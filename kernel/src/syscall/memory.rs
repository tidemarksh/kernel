//! Memory syscalls: brk, mmap, munmap, mremap, mprotect.
//!
//! VMA table and brk state are allocated in kernel Worker's WASM linear
//! memory via alloc.rs, per the data ownership model.
//!
//! Struct layout (RV64):
//!
//! struct Vma {                          // 40 bytes total
//!     start:  u64,                      // offset 0   — region start (page-aligned)
//!     end:    u64,                      // offset 8   — region end (exclusive)
//!     prot:   i32,                      // offset 16  — PROT_READ | PROT_WRITE | PROT_EXEC | PROT_NONE
//!     flags:  i32,                      // offset 20  — MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
//!     fd:     i32,                      // offset 24  — file-backed MemFS inode, -1 = anonymous
//!     _pad:   i32,                      // offset 28
//!     offset: u64,                      // offset 32  — file offset for file-backed mmap
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/linux/mm_types.h

use alloc_crate::{format, vec::Vec};

use crate::abi::*;
use crate::fs::{fd_table, memfs};
use crate::guest_mem;
use crate::types::{ThreadState, Vma};

const MIN_MMAP_BASE: u64 = 0x20_0000;
const MMAP_BASE_ALIGN: u64 = 0x10_0000;
const BRK_MMAP_GAP: u64 = 8 * 1024 * 1024;
const PROT_NONE_TOPDOWN_LIMIT: u64 = 0x8000_0000;
const PERMIT_CACHE_PROT_SLOTS: usize = 4;
const PERMIT_CACHE_WAYS: usize = 2;
const PERMIT_CACHE_SLOTS: usize = PERMIT_CACHE_PROT_SLOTS * PERMIT_CACHE_WAYS;
const PERMIT_OUTCOME_CACHE_HIT: u32 = 1;
const PERMIT_OUTCOME_COVER_HIT: u32 = 2;
const PERMIT_OUTCOME_DENIED: u32 = 3;

/// Address space state — shared by all threads of a process.
/// Allocated in kernel Worker linear memory via alloc.rs.
/// Separated for fork (new address space) and execve (reinit).
/// VMA table is a sorted Vec<Vma> (sorted by start address).
/// https://man7.org/linux/man-pages/man2/mmap.2.html
struct AddressSpaceState {
    vmas: Vec<Vma>,
    kernel_owned_guest_ranges: Vec<KernelGuestRange>,
    brk_base: u64,
    brk_current: u64,
    mmap_next: u64,
    has_prot_none: u32,
    permit_cache_start: [u64; PERMIT_CACHE_SLOTS],
    permit_cache_end: [u64; PERMIT_CACHE_SLOTS],
    permit_cache_prot: [i32; PERMIT_CACHE_SLOTS],
}

#[derive(Clone, Copy)]
struct KernelGuestRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Copy)]
struct DebugMemorySyscallEntry {
    nr: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    result: i64,
    pid: i32,
    process_ptr: u32,
}

const DEBUG_MEMORY_SYSCALL_TRACE_CAPACITY: usize = 256;
const FILE_MMAP_MATERIALIZE_TRACE_CAPACITY: usize = 64;
const CPU_WRITE_PERMIT_TRACE_CAPACITY: usize = 96;
const MPROTECT_TRANSITION_TRACE_CAPACITY: usize = 96;
const MMAP_EXEC_TRANSITION_TRACE_CAPACITY: usize = 96;

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct FileMmapMaterializeTraceEntry {
    pub vm_ptr: u32,
    pub ino: u32,
    pub start: u64,
    pub end: u64,
    pub prot: i32,
    pub flags: i32,
    pub offset: u64,
    pub source_proc_maps: u32,
    pub old_exec_overlap: u32,
    pub old_vma_start: u64,
    pub old_vma_end: u64,
    pub old_vma_fd: i32,
    pub old_vma_offset: u64,
    pub sample: u64,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct CpuWritePermitTraceEntry {
    pub vm_ptr: u32,
    pub tid: i32,
    pub pc: u64,
    pub addr: u64,
    pub len: u64,
    pub vma_start: u64,
    pub vma_end: u64,
    pub vma_prot: i32,
    pub vma_flags: i32,
    pub vma_fd: i32,
    pub vma_offset: u64,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct MprotectTransitionTraceEntry {
    pub vm_ptr: u32,
    pub tid: i32,
    pub request_start: u64,
    pub request_end: u64,
    pub segment_start: u64,
    pub segment_end: u64,
    pub old_prot: i32,
    pub new_prot: i32,
    pub old_flags: i32,
    pub old_fd: i32,
    pub old_offset: u64,
    pub gained_exec: u32,
    pub gained_write: u32,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct MmapExecTransitionTraceEntry {
    pub vm_ptr: u32,
    pub tid: i32,
    pub start: u64,
    pub end: u64,
    pub prot: i32,
    pub flags: i32,
    pub fd: i32,
    pub offset: u64,
    pub is_anon: u32,
    pub sparse_fixed_upgrade: u32,
    pub old_exec_overlap: u32,
    pub old_vma_start: u64,
    pub old_vma_end: u64,
    pub old_vma_fd: i32,
    pub old_vma_offset: u64,
    pub sample: u64,
}

static mut DEBUG_MEMORY_SYSCALL_TRACE: [DebugMemorySyscallEntry;
    DEBUG_MEMORY_SYSCALL_TRACE_CAPACITY] = [DebugMemorySyscallEntry {
    nr: 0,
    arg0: 0,
    arg1: 0,
    arg2: 0,
    arg3: 0,
    arg4: 0,
    arg5: 0,
    result: 0,
    pid: 0,
    process_ptr: 0,
}; DEBUG_MEMORY_SYSCALL_TRACE_CAPACITY];
static mut DEBUG_MEMORY_SYSCALL_TRACE_LEN: u32 = 0;
static mut DEBUG_MEMORY_SYSCALL_TRACE_NEXT: u32 = 0;
static mut FILE_MMAP_MATERIALIZE_TRACE: [FileMmapMaterializeTraceEntry;
    FILE_MMAP_MATERIALIZE_TRACE_CAPACITY] = [FileMmapMaterializeTraceEntry {
    vm_ptr: 0,
    ino: 0,
    start: 0,
    end: 0,
    prot: 0,
    flags: 0,
    offset: 0,
    source_proc_maps: 0,
    old_exec_overlap: 0,
    old_vma_start: 0,
    old_vma_end: 0,
    old_vma_fd: 0,
    old_vma_offset: 0,
    sample: 0,
}; FILE_MMAP_MATERIALIZE_TRACE_CAPACITY];
static mut FILE_MMAP_MATERIALIZE_TRACE_LEN: u32 = 0;
static mut FILE_MMAP_MATERIALIZE_TRACE_NEXT: u32 = 0;
static mut CPU_WRITE_PERMIT_TRACE: [CpuWritePermitTraceEntry; CPU_WRITE_PERMIT_TRACE_CAPACITY] =
    [CpuWritePermitTraceEntry {
        vm_ptr: 0,
        tid: 0,
        pc: 0,
        addr: 0,
        len: 0,
        vma_start: 0,
        vma_end: 0,
        vma_prot: 0,
        vma_flags: 0,
        vma_fd: 0,
        vma_offset: 0,
    }; CPU_WRITE_PERMIT_TRACE_CAPACITY];
static mut CPU_WRITE_PERMIT_TRACE_LEN: u32 = 0;
static mut CPU_WRITE_PERMIT_TRACE_NEXT: u32 = 0;
static mut MPROTECT_TRANSITION_TRACE: [MprotectTransitionTraceEntry;
    MPROTECT_TRANSITION_TRACE_CAPACITY] = [MprotectTransitionTraceEntry {
    vm_ptr: 0,
    tid: 0,
    request_start: 0,
    request_end: 0,
    segment_start: 0,
    segment_end: 0,
    old_prot: 0,
    new_prot: 0,
    old_flags: 0,
    old_fd: 0,
    old_offset: 0,
    gained_exec: 0,
    gained_write: 0,
}; MPROTECT_TRANSITION_TRACE_CAPACITY];
static mut MPROTECT_TRANSITION_TRACE_LEN: u32 = 0;
static mut MPROTECT_TRANSITION_TRACE_NEXT: u32 = 0;
static mut MMAP_EXEC_TRANSITION_TRACE: [MmapExecTransitionTraceEntry;
    MMAP_EXEC_TRANSITION_TRACE_CAPACITY] = [MmapExecTransitionTraceEntry {
    vm_ptr: 0,
    tid: 0,
    start: 0,
    end: 0,
    prot: 0,
    flags: 0,
    fd: 0,
    offset: 0,
    is_anon: 0,
    sparse_fixed_upgrade: 0,
    old_exec_overlap: 0,
    old_vma_start: 0,
    old_vma_end: 0,
    old_vma_fd: 0,
    old_vma_offset: 0,
    sample: 0,
}; MMAP_EXEC_TRANSITION_TRACE_CAPACITY];
static mut MMAP_EXEC_TRANSITION_TRACE_LEN: u32 = 0;
static mut MMAP_EXEC_TRANSITION_TRACE_NEXT: u32 = 0;

#[derive(Clone, Copy)]
enum ProcMapsLabel {
    None,
    Heap,
    Stack,
}

#[derive(Clone, Copy)]
struct ProcMapsEntry {
    start: u64,
    end: u64,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: u64,
    inode: u64,
    label: ProcMapsLabel,
}

/// Internal address-space image used by process handoff support.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct AddressSpaceStateImage {
    vmas: Vec<Vma>,
    kernel_owned_guest_ranges: Vec<KernelGuestRange>,
    brk_base: u64,
    brk_current: u64,
    mmap_next: u64,
    has_prot_none: u32,
}

impl AddressSpaceStateImage {
    #[allow(dead_code)]
    pub(crate) fn vmas(&self) -> &[Vma] {
        &self.vmas
    }

    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self {
            vmas: Vec::new(),
            kernel_owned_guest_ranges: Vec::new(),
            brk_base: 0,
            brk_current: 0,
            mmap_next: 0,
            has_prot_none: 0,
        }
    }

    #[cfg(any(test, feature = "harness"))]
    pub(crate) fn debug_vma_vec_meta(&self) -> (usize, usize, usize) {
        (
            self.vmas.len(),
            self.vmas.capacity(),
            self.vmas.as_ptr() as usize,
        )
    }
}

/// Pointer to AddressSpaceState in kernel Worker linear memory (allocated via alloc.rs).
static mut MEM_STATE: *mut AddressSpaceState = core::ptr::null_mut();

pub const DEFAULT_STACK_SIZE: u64 = 8 * 1024 * 1024;
const MIN_STACK_SIZE: u64 = 64 * 1024;
const INITIAL_STACK_HEADROOM: u64 = 64 * 1024 * 1024;

fn ms() -> &'static mut AddressSpaceState {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(MEM_STATE));
        &mut *p
    }
}

pub fn mem_state_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(MEM_STATE)) as u32 }
}

pub fn attach_mem_state_ptr(ptr: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(MEM_STATE),
            ptr as *mut AddressSpaceState,
        );
    }
}

pub(crate) fn record_debug_syscall(
    vm: &ThreadState,
    nr: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    result: i64,
) {
    unsafe {
        let next = DEBUG_MEMORY_SYSCALL_TRACE_NEXT as usize % DEBUG_MEMORY_SYSCALL_TRACE_CAPACITY;
        DEBUG_MEMORY_SYSCALL_TRACE[next] = DebugMemorySyscallEntry {
            nr,
            arg0,
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
            result,
            pid: vm.tid,
            process_ptr: vm.process_ptr,
        };
        DEBUG_MEMORY_SYSCALL_TRACE_NEXT =
            (DEBUG_MEMORY_SYSCALL_TRACE_NEXT + 1) % DEBUG_MEMORY_SYSCALL_TRACE_CAPACITY as u32;
        if DEBUG_MEMORY_SYSCALL_TRACE_LEN < DEBUG_MEMORY_SYSCALL_TRACE_CAPACITY as u32 {
            DEBUG_MEMORY_SYSCALL_TRACE_LEN += 1;
        }
    }
}

pub(crate) fn debug_syscall_trace_len() -> u32 {
    unsafe { DEBUG_MEMORY_SYSCALL_TRACE_LEN }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn debug_clear_syscall_trace() {
    unsafe {
        DEBUG_MEMORY_SYSCALL_TRACE_LEN = 0;
        DEBUG_MEMORY_SYSCALL_TRACE_NEXT = 0;
    }
}

fn debug_syscall_trace_entry(index: u32) -> DebugMemorySyscallEntry {
    unsafe {
        if index >= DEBUG_MEMORY_SYSCALL_TRACE_LEN {
            return DebugMemorySyscallEntry {
                nr: 0,
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
                result: 0,
                pid: 0,
                process_ptr: 0,
            };
        }
        let len = DEBUG_MEMORY_SYSCALL_TRACE_LEN as usize;
        let start = if len < DEBUG_MEMORY_SYSCALL_TRACE_CAPACITY {
            0
        } else {
            DEBUG_MEMORY_SYSCALL_TRACE_NEXT as usize
        };
        let ring_index = (start + index as usize) % DEBUG_MEMORY_SYSCALL_TRACE_CAPACITY;
        DEBUG_MEMORY_SYSCALL_TRACE[ring_index]
    }
}

fn is_proc_self_maps_inode(ino: u32) -> bool {
    let mut path = [0u8; 128];
    let len = memfs::write_path(ino, &mut path);
    &path[..len] == b"/proc/self/maps"
}

fn current_exec_overlap(s: &AddressSpaceState, start: u64, end: u64) -> (u32, u64, u64, i32, u64) {
    for vma in s.vmas.iter() {
        if (vma.prot & PROT_EXEC) == 0 {
            continue;
        }
        if start < vma.end && end > vma.start {
            return (1, vma.start, vma.end, vma.fd, vma.offset);
        }
    }
    (0, 0, 0, 0, 0)
}

#[allow(clippy::too_many_arguments)]
fn record_file_mmap_materialize(
    vm: &ThreadState,
    s: &AddressSpaceState,
    ino: u32,
    start: u64,
    end: u64,
    prot: i32,
    flags: i32,
    offset: u64,
    sample: u64,
) {
    let source_proc_maps = is_proc_self_maps_inode(ino) as u32;
    let (old_exec_overlap, old_vma_start, old_vma_end, old_vma_fd, old_vma_offset) =
        current_exec_overlap(s, start, end);
    if source_proc_maps == 0 && old_exec_overlap == 0 {
        return;
    }
    let entry = FileMmapMaterializeTraceEntry {
        vm_ptr: vm as *const ThreadState as u32,
        ino,
        start,
        end,
        prot,
        flags,
        offset,
        source_proc_maps,
        old_exec_overlap,
        old_vma_start,
        old_vma_end,
        old_vma_fd,
        old_vma_offset,
        sample,
    };
    unsafe {
        let index =
            FILE_MMAP_MATERIALIZE_TRACE_NEXT as usize % FILE_MMAP_MATERIALIZE_TRACE_CAPACITY;
        FILE_MMAP_MATERIALIZE_TRACE[index] = entry;
        FILE_MMAP_MATERIALIZE_TRACE_NEXT = FILE_MMAP_MATERIALIZE_TRACE_NEXT.wrapping_add(1);
        if FILE_MMAP_MATERIALIZE_TRACE_LEN < FILE_MMAP_MATERIALIZE_TRACE_CAPACITY as u32 {
            FILE_MMAP_MATERIALIZE_TRACE_LEN += 1;
        }
    }
}

fn push_cpu_write_permit_trace(entry: CpuWritePermitTraceEntry) {
    unsafe {
        let index = CPU_WRITE_PERMIT_TRACE_NEXT as usize % CPU_WRITE_PERMIT_TRACE_CAPACITY;
        CPU_WRITE_PERMIT_TRACE[index] = entry;
        CPU_WRITE_PERMIT_TRACE_NEXT = CPU_WRITE_PERMIT_TRACE_NEXT.wrapping_add(1);
        if CPU_WRITE_PERMIT_TRACE_LEN < CPU_WRITE_PERMIT_TRACE_CAPACITY as u32 {
            CPU_WRITE_PERMIT_TRACE_LEN += 1;
        }
    }
}

pub(crate) fn record_cpu_write_permit_trace(vm: &ThreadState, pc: u64, addr: u64, len: u64) {
    if len == 0 {
        return;
    }
    let Some(end) = addr.checked_add(len) else {
        return;
    };
    let s = ms();
    for vma in s.vmas.iter() {
        if addr >= vma.end || end <= vma.start {
            continue;
        }
        if (vma.prot & PROT_EXEC) == 0 && vma.fd < 0 {
            continue;
        }
        push_cpu_write_permit_trace(CpuWritePermitTraceEntry {
            vm_ptr: vm as *const ThreadState as u32,
            tid: vm.tid,
            pc,
            addr,
            len,
            vma_start: vma.start,
            vma_end: vma.end,
            vma_prot: vma.prot,
            vma_flags: vma.flags,
            vma_fd: vma.fd,
            vma_offset: vma.offset,
        });
    }
}

fn record_mprotect_transition(
    vm: &ThreadState,
    request_start: u64,
    request_end: u64,
    segment_start: u64,
    segment_end: u64,
    old_vma: &Vma,
    new_prot: i32,
) {
    let gained_exec = (old_vma.prot & PROT_EXEC) == 0 && (new_prot & PROT_EXEC) != 0;
    let gained_write = (old_vma.prot & PROT_WRITE) == 0 && (new_prot & PROT_WRITE) != 0;
    let file_backed_exec_or_write_relevant = old_vma.fd >= 0
        && ((old_vma.prot & (PROT_EXEC | PROT_WRITE)) != 0
            || (new_prot & (PROT_EXEC | PROT_WRITE)) != 0);
    if !gained_exec && !gained_write && !file_backed_exec_or_write_relevant {
        return;
    }
    let entry = MprotectTransitionTraceEntry {
        vm_ptr: vm as *const ThreadState as u32,
        tid: vm.tid,
        request_start,
        request_end,
        segment_start,
        segment_end,
        old_prot: old_vma.prot,
        new_prot,
        old_flags: old_vma.flags,
        old_fd: old_vma.fd,
        old_offset: old_vma.offset,
        gained_exec: gained_exec as u32,
        gained_write: gained_write as u32,
    };
    unsafe {
        let index = MPROTECT_TRANSITION_TRACE_NEXT as usize % MPROTECT_TRANSITION_TRACE_CAPACITY;
        MPROTECT_TRANSITION_TRACE[index] = entry;
        MPROTECT_TRANSITION_TRACE_NEXT = MPROTECT_TRANSITION_TRACE_NEXT.wrapping_add(1);
        if MPROTECT_TRANSITION_TRACE_LEN < MPROTECT_TRANSITION_TRACE_CAPACITY as u32 {
            MPROTECT_TRANSITION_TRACE_LEN += 1;
        }
    }
}

fn sample_guest_u64(base: u32, addr: u64) -> u64 {
    let memory_len = crate::wasm::memory_size_bytes();
    let absolute = base as u64 + addr;
    let Some(end) = absolute.checked_add(8) else {
        return 0;
    };
    if end > memory_len {
        return 0;
    }
    let mut bytes = [0u8; 8];
    unsafe {
        guest_mem::read_bytes(base, addr, &mut bytes);
    }
    u64::from_le_bytes(bytes)
}

#[allow(clippy::too_many_arguments)]
fn record_mmap_exec_transition(
    vm: &ThreadState,
    s: &AddressSpaceState,
    base: u32,
    start: u64,
    end: u64,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: u64,
    is_anon: bool,
    sparse_fixed_upgrade: bool,
) {
    let (old_exec_overlap, old_vma_start, old_vma_end, old_vma_fd, old_vma_offset) =
        current_exec_overlap(s, start, end);
    if (prot & PROT_EXEC) == 0 && old_exec_overlap == 0 {
        return;
    }
    let entry = MmapExecTransitionTraceEntry {
        vm_ptr: vm as *const ThreadState as u32,
        tid: vm.tid,
        start,
        end,
        prot,
        flags,
        fd,
        offset,
        is_anon: is_anon as u32,
        sparse_fixed_upgrade: sparse_fixed_upgrade as u32,
        old_exec_overlap,
        old_vma_start,
        old_vma_end,
        old_vma_fd,
        old_vma_offset,
        sample: sample_guest_u64(base, start),
    };
    unsafe {
        let index = MMAP_EXEC_TRANSITION_TRACE_NEXT as usize % MMAP_EXEC_TRANSITION_TRACE_CAPACITY;
        MMAP_EXEC_TRANSITION_TRACE[index] = entry;
        MMAP_EXEC_TRANSITION_TRACE_NEXT = MMAP_EXEC_TRANSITION_TRACE_NEXT.wrapping_add(1);
        if MMAP_EXEC_TRANSITION_TRACE_LEN < MMAP_EXEC_TRANSITION_TRACE_CAPACITY as u32 {
            MMAP_EXEC_TRANSITION_TRACE_LEN += 1;
        }
    }
}

#[allow(dead_code)]
pub(crate) fn file_mmap_materialize_trace_len() -> u32 {
    unsafe { FILE_MMAP_MATERIALIZE_TRACE_LEN }
}

#[allow(dead_code)]
pub(crate) fn file_mmap_materialize_trace_entry(index: u32) -> FileMmapMaterializeTraceEntry {
    unsafe {
        if FILE_MMAP_MATERIALIZE_TRACE_LEN == 0 {
            return FILE_MMAP_MATERIALIZE_TRACE[0];
        }
        let len = FILE_MMAP_MATERIALIZE_TRACE_LEN as usize;
        let start = if len < FILE_MMAP_MATERIALIZE_TRACE_CAPACITY {
            0
        } else {
            FILE_MMAP_MATERIALIZE_TRACE_NEXT as usize
        };
        let ring_index = (start + index as usize) % FILE_MMAP_MATERIALIZE_TRACE_CAPACITY;
        FILE_MMAP_MATERIALIZE_TRACE[ring_index]
    }
}

#[allow(dead_code)]
pub(crate) fn cpu_write_permit_trace_len() -> u32 {
    unsafe { CPU_WRITE_PERMIT_TRACE_LEN }
}

#[allow(dead_code)]
pub(crate) fn cpu_write_permit_trace_entry(index: u32) -> CpuWritePermitTraceEntry {
    unsafe {
        if CPU_WRITE_PERMIT_TRACE_LEN == 0 {
            return CPU_WRITE_PERMIT_TRACE[0];
        }
        let len = CPU_WRITE_PERMIT_TRACE_LEN as usize;
        let start = if len < CPU_WRITE_PERMIT_TRACE_CAPACITY {
            0
        } else {
            CPU_WRITE_PERMIT_TRACE_NEXT as usize
        };
        let ring_index = (start + index as usize) % CPU_WRITE_PERMIT_TRACE_CAPACITY;
        CPU_WRITE_PERMIT_TRACE[ring_index]
    }
}

#[allow(dead_code)]
pub(crate) fn mprotect_transition_trace_len() -> u32 {
    unsafe { MPROTECT_TRANSITION_TRACE_LEN }
}

#[allow(dead_code)]
pub(crate) fn mprotect_transition_trace_entry(index: u32) -> MprotectTransitionTraceEntry {
    unsafe {
        if MPROTECT_TRANSITION_TRACE_LEN == 0 {
            return MPROTECT_TRANSITION_TRACE[0];
        }
        let len = MPROTECT_TRANSITION_TRACE_LEN as usize;
        let start = if len < MPROTECT_TRANSITION_TRACE_CAPACITY {
            0
        } else {
            MPROTECT_TRANSITION_TRACE_NEXT as usize
        };
        let ring_index = (start + index as usize) % MPROTECT_TRANSITION_TRACE_CAPACITY;
        MPROTECT_TRANSITION_TRACE[ring_index]
    }
}

#[allow(dead_code)]
pub(crate) fn mmap_exec_transition_trace_len() -> u32 {
    unsafe { MMAP_EXEC_TRANSITION_TRACE_LEN }
}

#[allow(dead_code)]
pub(crate) fn mmap_exec_transition_trace_entry(index: u32) -> MmapExecTransitionTraceEntry {
    unsafe {
        if MMAP_EXEC_TRANSITION_TRACE_LEN == 0 {
            return MMAP_EXEC_TRANSITION_TRACE[0];
        }
        let len = MMAP_EXEC_TRANSITION_TRACE_LEN as usize;
        let start = if len < MMAP_EXEC_TRANSITION_TRACE_CAPACITY {
            0
        } else {
            MMAP_EXEC_TRANSITION_TRACE_NEXT as usize
        };
        let ring_index = (start + index as usize) % MMAP_EXEC_TRANSITION_TRACE_CAPACITY;
        MMAP_EXEC_TRANSITION_TRACE[ring_index]
    }
}

pub(crate) fn debug_syscall_trace_entry_nr(index: u32) -> u64 {
    debug_syscall_trace_entry(index).nr
}

pub(crate) fn debug_syscall_trace_entry_arg0(index: u32) -> u64 {
    debug_syscall_trace_entry(index).arg0
}

pub(crate) fn debug_syscall_trace_entry_arg1(index: u32) -> u64 {
    debug_syscall_trace_entry(index).arg1
}

pub(crate) fn debug_syscall_trace_entry_arg2(index: u32) -> u64 {
    debug_syscall_trace_entry(index).arg2
}

pub(crate) fn debug_syscall_trace_entry_arg3(index: u32) -> u64 {
    debug_syscall_trace_entry(index).arg3
}

pub(crate) fn debug_syscall_trace_entry_arg4(index: u32) -> u64 {
    debug_syscall_trace_entry(index).arg4
}

pub(crate) fn debug_syscall_trace_entry_arg5(index: u32) -> u64 {
    debug_syscall_trace_entry(index).arg5
}

pub(crate) fn debug_syscall_trace_entry_result(index: u32) -> i64 {
    debug_syscall_trace_entry(index).result
}

pub(crate) fn debug_syscall_trace_entry_pid(index: u32) -> i32 {
    debug_syscall_trace_entry(index).pid
}

pub(crate) fn debug_syscall_trace_entry_process_ptr(index: u32) -> u32 {
    debug_syscall_trace_entry(index).process_ptr
}

fn align_mmap_base(addr: u64) -> u64 {
    (addr.saturating_add(MMAP_BASE_ALIGN - 1)) & !(MMAP_BASE_ALIGN - 1)
}

fn default_mmap_start(brk_start: u64) -> u64 {
    align_mmap_base(brk_start.saturating_add(BRK_MMAP_GAP)).max(MIN_MMAP_BASE)
}

/// Initialize memory state. Allocates AddressSpaceState via alloc.rs.
pub fn init(brk_start: u64) {
    // Guest VMA placement must depend on the guest address space, not on the
    // kernel-worker bump allocator's host-side placement.
    let mmap_start = default_mmap_start(brk_start);
    unsafe {
        // Null the pointer so we always take the fresh allocation path.
        // Re-initialization intentionally leaks older test-only state so a
        // shared WASM test process never aliases prior allocations.
        core::ptr::write(core::ptr::addr_of_mut!(MEM_STATE), core::ptr::null_mut());

        let ptr = crate::alloc::alloc(
            core::mem::size_of::<AddressSpaceState>() as u32,
            core::mem::align_of::<AddressSpaceState>() as u32,
        );
        if ptr == 0 {
            crate::wasm::unreachable();
        }
        core::ptr::write(
            ptr as *mut AddressSpaceState,
            AddressSpaceState {
                vmas: Vec::new(),
                kernel_owned_guest_ranges: Vec::new(),
                brk_base: brk_start,
                brk_current: brk_start,
                mmap_next: mmap_start,
                has_prot_none: 0,
                permit_cache_start: [0; PERMIT_CACHE_SLOTS],
                permit_cache_end: [0; PERMIT_CACHE_SLOTS],
                permit_cache_prot: [0; PERMIT_CACHE_SLOTS],
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(MEM_STATE),
            ptr as *mut AddressSpaceState,
        );
    }
}

pub fn has_prot_none() -> bool {
    ms().has_prot_none != 0
}

fn invalidate_permit_cache(s: &mut AddressSpaceState) {
    s.permit_cache_start = [0; PERMIT_CACHE_SLOTS];
    s.permit_cache_end = [0; PERMIT_CACHE_SLOTS];
    s.permit_cache_prot = [0; PERMIT_CACHE_SLOTS];
}

#[inline(always)]
fn permit_cache_slot(prot: i32) -> usize {
    ((prot as usize) & (PERMIT_CACHE_PROT_SLOTS - 1)) * PERMIT_CACHE_WAYS
}

fn cache_permitted_range(
    s: &mut AddressSpaceState,
    start: u64,
    end: u64,
    cover_prot: i32,
    requested_prot: i32,
) {
    let slot = permit_cache_slot(requested_prot);
    if s.permit_cache_start[slot] == start
        && s.permit_cache_end[slot] == end
        && s.permit_cache_prot[slot] == cover_prot
    {
        return;
    }
    s.permit_cache_start[slot + 1] = s.permit_cache_start[slot];
    s.permit_cache_end[slot + 1] = s.permit_cache_end[slot];
    s.permit_cache_prot[slot + 1] = s.permit_cache_prot[slot];
    s.permit_cache_start[slot] = start;
    s.permit_cache_end[slot] = end;
    s.permit_cache_prot[slot] = cover_prot;
}

#[allow(dead_code)]
pub(crate) fn capture_state_image_into(image: &mut AddressSpaceStateImage) {
    let s = ms();
    validate_vma_vec_for_image(&s.vmas);
    let vmas = clone_vmas_for_state_image(&s.vmas);
    image.vmas = vmas;
    image
        .kernel_owned_guest_ranges
        .clone_from(&s.kernel_owned_guest_ranges);
    image.brk_base = s.brk_base;
    image.brk_current = s.brk_current;
    image.mmap_next = s.mmap_next;
    image.has_prot_none = s.has_prot_none;
}

#[inline(never)]
fn clone_vmas_for_state_image(vmas: &Vec<Vma>) -> Vec<Vma> {
    vmas.clone()
}

#[allow(dead_code)]
fn validate_vma_vec_for_image(vmas: &Vec<Vma>) {
    let len = vmas.len();
    let cap = vmas.capacity();
    let ptr = vmas.as_ptr() as usize;
    let elem = core::mem::size_of::<Vma>();
    let mem_size = crate::wasm::memory_size_bytes() as usize;
    if len > cap {
        panic!("address_space_state_image: len {} > cap {}", len, cap);
    }
    if cap == 0 {
        return;
    }
    if ptr == 0 {
        panic!(
            "address_space_state_image: non-empty vma vec with null ptr len={} cap={}",
            len, cap
        );
    }
    let bytes = cap.checked_mul(elem).unwrap_or_else(|| {
        panic!(
            "address_space_state_image: cap overflow cap={} elem={}",
            cap, elem
        )
    });
    let end = ptr.checked_add(bytes).unwrap_or_else(|| {
        panic!(
            "address_space_state_image: ptr overflow ptr=0x{:x} bytes={}",
            ptr, bytes
        )
    });
    if end > mem_size {
        panic!(
            "address_space_state_image: vma vec out of linear memory ptr=0x{:x} len={} cap={} bytes={} mem_size=0x{:x}",
            ptr, len, cap, bytes, mem_size
        );
    }
}

fn validate_state_image_for_restore(image: &AddressSpaceStateImage) {
    validate_vma_vec_for_image(&image.vmas);
}

#[allow(dead_code)]
pub(crate) fn restore_state_from_image(image: &AddressSpaceStateImage) {
    validate_state_image_for_restore(image);
    let s = ms();
    s.vmas.clone_from(&image.vmas);
    s.kernel_owned_guest_ranges
        .clone_from(&image.kernel_owned_guest_ranges);
    s.brk_base = image.brk_base;
    s.brk_current = image.brk_current;
    s.mmap_next = image.mmap_next;
    s.has_prot_none = image.has_prot_none;
    invalidate_permit_cache(s);
}

pub fn reset_for_execve_with_flush(base: u32, brk_start: u64, flush_shared: bool) {
    let mmap_start = default_mmap_start(brk_start);
    if flush_shared {
        flush_shared_mappings_in_range(base, 0, u64::MAX);
    }
    discard_execve_guest_address_space(base);
    let s = ms();
    s.vmas.clear();
    s.kernel_owned_guest_ranges.clear();
    s.brk_base = brk_start;
    s.brk_current = brk_start;
    s.mmap_next = mmap_start;
    s.has_prot_none = 0;
    invalidate_permit_cache(s);
}

pub fn reset_for_execve(base: u32, brk_start: u64) {
    reset_for_execve_with_flush(base, brk_start, true);
}

pub fn flush_shared_mappings(base: u32) {
    flush_shared_mappings_in_range(base, 0, u64::MAX);
}

fn discard_execve_guest_address_space(base: u32) {
    // execve(2) does not preserve the old memory mappings. Tidemark keeps the
    // same WebAssembly Memory for in-place exec, so clear the previously mapped
    // guest bytes before installing the new image. See:
    // https://man7.org/linux/man-pages/man2/execve.2.html
    let s = ms();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for vma in s.vmas.iter() {
        ranges.push((vma.start, vma.end));
    }
    if s.brk_current > s.brk_base {
        ranges.push((page_align_down(s.brk_base), page_align_up(s.brk_current)));
    }
    let backed_limit = current_linear_guest_limit(base);
    for (start, end) in ranges {
        let zero_end = end.min(backed_limit);
        if zero_end > start {
            crate::tracepoints::record_execve_stage(370, start, zero_end);
            unsafe {
                guest_mem::zero_mem(base, start, (zero_end - start) as usize);
            }
        }
    }
}

pub fn refresh_shared_file_mappings(base: u32, guest_limit: u64) {
    let s = ms();
    for vma in s.vmas.iter() {
        refresh_shared_file_vma(base, vma, guest_limit);
    }
}

pub fn is_prot_none(addr: u64) -> bool {
    let s = ms();
    for v in s.vmas.iter() {
        if addr >= v.start && addr < v.end && v.prot == PROT_NONE {
            return true;
        }
    }
    false
}

pub fn range_has_prot_none(start: u64, len: u64) -> bool {
    let Some(end) = start.checked_add(len) else {
        return true;
    };
    let s = ms();
    for v in s.vmas.iter() {
        if v.prot != PROT_NONE {
            continue;
        }
        if start < v.end && end > v.start {
            return true;
        }
    }
    false
}

pub fn guest_range_accessible(base: u32, start: u64, len: u64) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    let guest_limit = current_linear_guest_limit(base);
    if start > u32::MAX as u64 || end > guest_limit || end > u32::MAX as u64 {
        return false;
    }
    if range_overlaps_kernel_owned_guest_range(ms(), start, end) {
        return false;
    }
    !range_has_prot_none(start, len)
}

fn max_guest_addr_limit(base: u32) -> u64 {
    crate::abi::max_guest_window_for_base(base)
}

fn current_linear_guest_limit(base: u32) -> u64 {
    crate::wasm::memory_size_bytes()
        .saturating_sub(base as u64)
        .min(max_guest_addr_limit(base))
}

fn prot_none_reservation_limit() -> u64 {
    u32::MAX as u64 + 1
}

fn nonfixed_prot_none_reservation_limit(guest_limit: u64) -> u64 {
    guest_limit.min(PROT_NONE_TOPDOWN_LIMIT)
}

fn needs_sparse_linear_backing(base: u32, guest_end: u64) -> bool {
    match (base as u64).checked_add(guest_end) {
        Some(needed) => needed > 0x1_0000_0000,
        None => true,
    }
}

pub(crate) fn effective_guest_limit(vm: &ThreadState, base: u32) -> u64 {
    if vm.guest_memory_policy_limit != 0 {
        vm.guest_memory_policy_limit.min(max_guest_addr_limit(base))
    } else {
        current_linear_guest_limit(base)
    }
}

fn range_cover_with_prot(s: &AddressSpaceState, addr: u64, prot: i32) -> Option<(u64, u64, i32)> {
    if let Some(index) = find_vma_containing(s, addr) {
        let v = s.vmas[index];
        if v.prot != PROT_NONE && (v.prot & prot) == prot {
            return Some((v.start, v.end, v.prot));
        }
        return None;
    }

    if (prot & PROT_EXEC) == 0 && addr >= s.brk_base && addr < s.brk_current {
        return Some((s.brk_base, s.brk_current, PROT_READ | PROT_WRITE));
    }

    None
}

fn range_cover_end_with_sparse_anon_reservation(s: &AddressSpaceState, addr: u64) -> u64 {
    if let Some(index) = find_vma_containing(s, addr) {
        let v = s.vmas[index];
        if v.prot != PROT_NONE || v.fd >= 0 || (v.flags as u64 & MAP_ANONYMOUS) == 0 {
            return 0;
        }
        return v.end;
    }
    0
}

fn range_fully_covered_by_sparse_anon_reservation(
    s: &AddressSpaceState,
    start: u64,
    end: u64,
) -> bool {
    let mut cur = start;
    while cur < end {
        let cover_end = range_cover_end_with_sparse_anon_reservation(s, cur);
        if cover_end <= cur {
            return false;
        }
        cur = cover_end.min(end);
    }
    true
}

#[inline(always)]
pub fn guest_range_permitted(vm: &ThreadState, base: u32, start: u64, len: u64, prot: i32) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = start.checked_add(len) else {
        crate::tracepoints::record_guest_range_permit_check(prot as u32, PERMIT_OUTCOME_DENIED);
        return false;
    };
    let guest_limit = effective_guest_limit(vm, base);
    if start > u32::MAX as u64 || end > guest_limit || end > u32::MAX as u64 {
        crate::tracepoints::record_guest_range_permit_check(prot as u32, PERMIT_OUTCOME_DENIED);
        return false;
    }

    let s = ms();
    if range_overlaps_kernel_owned_guest_range(s, start, end) {
        crate::tracepoints::record_guest_range_permit_check(prot as u32, PERMIT_OUTCOME_DENIED);
        return false;
    }

    let slot = permit_cache_slot(prot);
    for i in slot..slot + PERMIT_CACHE_WAYS {
        if start >= s.permit_cache_start[i]
            && end <= s.permit_cache_end[i]
            && (s.permit_cache_prot[i] & prot) == prot
        {
            crate::tracepoints::record_guest_range_permit_check(
                prot as u32,
                PERMIT_OUTCOME_CACHE_HIT,
            );
            return true;
        }
    }
    let mut cur = start;
    while cur < end {
        let Some((cover_start, cover_end, cover_prot)) = range_cover_with_prot(s, cur, prot) else {
            crate::tracepoints::record_guest_range_permit_check(prot as u32, PERMIT_OUTCOME_DENIED);
            return false;
        };
        if cover_end <= cur {
            crate::tracepoints::record_guest_range_permit_check(prot as u32, PERMIT_OUTCOME_DENIED);
            return false;
        }
        if cur == start && end <= cover_end {
            cache_permitted_range(s, cover_start, cover_end, cover_prot, prot);
            crate::tracepoints::record_guest_range_permit_check(
                prot as u32,
                PERMIT_OUTCOME_COVER_HIT,
            );
            return true;
        }
        cur = cover_end.min(end);
    }
    crate::tracepoints::record_guest_range_permit_check(prot as u32, PERMIT_OUTCOME_COVER_HIT);
    true
}

pub fn register_kernel_owned_guest_range(start: u64, len: u64) {
    if len == 0 {
        return;
    }
    let Some(end) = start.checked_add(len) else {
        return;
    };
    if start >= end {
        return;
    }

    let s = ms();
    s.kernel_owned_guest_ranges
        .push(KernelGuestRange { start, end });
    invalidate_permit_cache(s);
}

pub fn debug_kernel_owned_guest_range_len() -> u32 {
    ms().kernel_owned_guest_ranges.len() as u32
}

pub fn debug_kernel_owned_guest_range_start(index: u32) -> u64 {
    ms().kernel_owned_guest_ranges
        .get(index as usize)
        .map(|range| range.start)
        .unwrap_or(0)
}

pub fn debug_kernel_owned_guest_range_end(index: u32) -> u64 {
    ms().kernel_owned_guest_ranges
        .get(index as usize)
        .map(|range| range.end)
        .unwrap_or(0)
}

pub fn register_elf_load_segment(start: u64, end: u64, prot: i32) {
    if start >= end {
        return;
    }
    let start = page_align_down(start);
    let end = page_align_up(end);
    let s = ms();
    s.vmas.push(Vma {
        start,
        end,
        prot,
        flags: (MAP_PRIVATE | MAP_FIXED) as i32,
        fd: -1,
        _pad: 0,
        offset: 0,
    });
    s.vmas.sort_by_key(|v| v.start);
    recompute_prot_none(s);
    invalidate_permit_cache(s);
}

// =========================================================================
// brk
// =========================================================================

/// Return current brk address (for ProcessState allocation in guest Memory).
pub fn current_brk() -> u64 {
    ms().brk_current
}

/// Hide a kernel-owned prefix that was carved out of the guest brk arena.
///
/// ProcessState lives in shared guest memory for cross-worker visibility, but
/// it must not remain part of the user-visible heap interval. After reserving
/// that prefix, move the public brk floor behind it so guest brk/malloc users
/// cannot overwrite kernel-owned process metadata.
pub fn user_brk_start_after_hidden_prefix(hidden_end: u64) -> u64 {
    page_align_up(hidden_end)
}

pub fn rebase_brk_after_hidden_prefix(hidden_end: u64) {
    let public_brk = user_brk_start_after_hidden_prefix(hidden_end);
    let s = ms();
    if s.brk_base < public_brk {
        s.brk_base = public_brk;
    }
    if s.brk_current < public_brk {
        s.brk_current = public_brk;
    }
    invalidate_permit_cache(s);
}

pub(crate) fn address_space_brk_base() -> u64 {
    ms().brk_base
}

pub(crate) fn address_space_mmap_next() -> u64 {
    ms().mmap_next
}

pub(crate) fn address_space_vma_len() -> u32 {
    ms().vmas.len() as u32
}

pub(crate) fn address_space_vma_start(index: u32) -> u64 {
    ms().vmas.get(index as usize).map(|v| v.start).unwrap_or(0)
}

pub(crate) fn address_space_vma_end(index: u32) -> u64 {
    ms().vmas.get(index as usize).map(|v| v.end).unwrap_or(0)
}

pub(crate) fn address_space_vma_prot(index: u32) -> i32 {
    ms().vmas.get(index as usize).map(|v| v.prot).unwrap_or(0)
}

pub(crate) fn address_space_vma_flags(index: u32) -> i32 {
    ms().vmas.get(index as usize).map(|v| v.flags).unwrap_or(0)
}

pub(crate) fn address_space_vma_fd(index: u32) -> i32 {
    ms().vmas.get(index as usize).map(|v| v.fd).unwrap_or(-1)
}

pub(crate) fn address_space_vma_offset(index: u32) -> u64 {
    ms().vmas.get(index as usize).map(|v| v.offset).unwrap_or(0)
}

pub(crate) fn address_space_vma_path_len(index: u32) -> u32 {
    let fd = address_space_vma_fd(index);
    if fd < 0 {
        return 0;
    }
    let mut buf = [0u8; 256];
    crate::fs::memfs::write_path(fd as u32, &mut buf) as u32
}

pub(crate) fn address_space_vma_path_byte(index: u32, offset: u32) -> u32 {
    let fd = address_space_vma_fd(index);
    if fd < 0 {
        return 0;
    }
    let mut buf = [0u8; 256];
    let len = crate::fs::memfs::write_path(fd as u32, &mut buf);
    buf.get(offset as usize)
        .copied()
        .filter(|_| (offset as usize) < len)
        .unwrap_or(0) as u32
}

pub(crate) fn address_space_vma_file_sample(index: u32, addr: u64) -> u64 {
    let Some(vma) = ms().vmas.get(index as usize).copied() else {
        return 0;
    };
    if vma.fd < 0 || addr < vma.start || addr >= vma.end {
        return 0;
    }
    let Some(file_offset) = vma.offset.checked_add(addr - vma.start) else {
        return 0;
    };
    let mut bytes = [0u8; 8];
    let n = crate::fs::memfs::read_file(vma.fd as u32, file_offset, &mut bytes);
    if n <= 0 {
        return 0;
    }
    u64::from_le_bytes(bytes)
}

pub(crate) fn address_space_vma_file_sample_len(index: u32, addr: u64) -> u32 {
    let Some(vma) = ms().vmas.get(index as usize).copied() else {
        return 0;
    };
    if vma.fd < 0 || addr < vma.start || addr >= vma.end {
        return 0;
    }
    let Some(file_offset) = vma.offset.checked_add(addr - vma.start) else {
        return 0;
    };
    let mut bytes = [0u8; 8];
    let n = crate::fs::memfs::read_file(vma.fd as u32, file_offset, &mut bytes);
    n.max(0) as u32
}

fn ensure_memory_capacity_for_guest_range(base: u32, guest_end: u64) -> bool {
    let Some(needed) = (base as u64).checked_add(guest_end) else {
        return false;
    };
    if needed > 0x1_0000_0000 {
        return false;
    }

    let mut mem_size = crate::wasm::memory_size_bytes();
    if needed <= mem_size {
        return true;
    }

    // Imported shared memories can reject a large single grow even when the
    // final size is otherwise reachable, so advance in 1 MiB chunks.
    const GROW_CHUNK_PAGES: u64 = 16;
    const WASM_PAGE_BYTES: u64 = 65536;
    while mem_size < needed {
        let remaining_pages = (needed - mem_size).div_ceil(WASM_PAGE_BYTES);
        let step_pages = remaining_pages.min(GROW_CHUNK_PAGES) as usize;
        if !crate::wasm::memory_grow_pages(step_pages) {
            return false;
        }
        mem_size = crate::wasm::memory_size_bytes();
    }
    true
}

pub fn ensure_guest_memory_capacity(base: u32, guest_end: u64) -> bool {
    ensure_memory_capacity_for_guest_range(base, guest_end)
}

fn page_align_up(len: u64) -> u64 {
    (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

fn page_align_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

fn is_stack_vma(vmas: &[Vma], index: usize) -> bool {
    let vma = vmas[index];
    if vma.fd >= 0
        || (vma.flags as u64 & MAP_ANONYMOUS) == 0
        || (vma.flags as u64 & MAP_PRIVATE) == 0
        || vma.prot != (PROT_READ | PROT_WRITE)
    {
        return false;
    }

    vmas.iter().any(|candidate| {
        candidate.end == vma.start
            && candidate.fd < 0
            && (candidate.flags as u64 & MAP_ANONYMOUS) != 0
            && (candidate.flags as u64 & MAP_PRIVATE) != 0
            && candidate.prot == PROT_NONE
    })
}

fn append_proc_maps_line(out: &mut Vec<u8>, entry: &ProcMapsEntry) {
    let perms = [
        if (entry.prot & PROT_READ) != 0 {
            b'r'
        } else {
            b'-'
        },
        if (entry.prot & PROT_WRITE) != 0 {
            b'w'
        } else {
            b'-'
        },
        if (entry.prot & PROT_EXEC) != 0 {
            b'x'
        } else {
            b'-'
        },
        if (entry.flags as u64 & MAP_SHARED) != 0 {
            b's'
        } else {
            b'p'
        },
    ];
    out.extend_from_slice(
        format!(
            "{:08x}-{:08x} {} {:08x} 00:00 {}",
            entry.start,
            entry.end,
            core::str::from_utf8(&perms).unwrap_or("---p"),
            entry.offset,
            entry.inode
        )
        .as_bytes(),
    );

    match entry.label {
        ProcMapsLabel::Heap => out.extend_from_slice(b" [heap]"),
        ProcMapsLabel::Stack => out.extend_from_slice(b" [stack]"),
        ProcMapsLabel::None if entry.fd >= 0 => {
            let mut path = [0u8; 4096];
            let len = memfs::write_path(entry.fd as u32, &mut path);
            if len != 0 {
                out.push(b' ');
                out.extend_from_slice(&path[..len]);
            }
        }
        ProcMapsLabel::None => {}
    }

    out.push(b'\n');
}

pub fn proc_self_maps_snapshot() -> Vec<u8> {
    let s = ms();
    let mut entries = Vec::with_capacity(s.vmas.len() + 1);

    let heap_start = page_align_down(s.brk_base);
    let heap_end = page_align_up(s.brk_current);
    if heap_end > heap_start {
        entries.push(ProcMapsEntry {
            start: heap_start,
            end: heap_end,
            prot: PROT_READ | PROT_WRITE,
            flags: (MAP_PRIVATE | MAP_ANONYMOUS) as i32,
            fd: -1,
            offset: 0,
            inode: 0,
            label: ProcMapsLabel::Heap,
        });
    }

    for (index, vma) in s.vmas.iter().enumerate() {
        entries.push(ProcMapsEntry {
            start: vma.start,
            end: vma.end,
            prot: vma.prot,
            flags: vma.flags,
            fd: vma.fd,
            offset: vma.offset,
            inode: if vma.fd >= 0 { vma.fd as u64 } else { 0 },
            label: if is_stack_vma(&s.vmas, index) {
                ProcMapsLabel::Stack
            } else {
                ProcMapsLabel::None
            },
        });
    }

    entries.sort_by_key(|entry| entry.start);

    let mut out = Vec::new();
    for entry in entries.iter() {
        append_proc_maps_line(&mut out, entry);
    }
    out
}

fn map_fixed_anonymous(base: u32, start: u64, length: u64, prot: i32, guest_limit: u64) -> i64 {
    if start & (PAGE_SIZE - 1) != 0 || length == 0 {
        return EINVAL;
    }
    let len = page_align_up(length);
    let Some(end) = start.checked_add(len) else {
        return ENOMEM;
    };
    if end > guest_limit {
        return ENOMEM;
    }

    let s = ms();
    remove_overlap(s, start, end);

    unsafe {
        if !ensure_memory_capacity_for_guest_range(base, end) {
            return ENOMEM;
        }
        guest_mem::zero_mem(base, start, len as usize);
    }

    s.vmas.push(Vma {
        start,
        end,
        prot,
        flags: (MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED) as i32,
        fd: -1,
        _pad: 0,
        offset: 0,
    });
    s.vmas.sort_by_key(|v| v.start);
    recompute_prot_none(s);
    invalidate_permit_cache(s);
    start as i64
}

/// Reserve the initial process stack and a guard page below it.
/// Returns the logical stack top used for argv/env/auxv placement.
pub fn map_initial_stack(base: u32, guest_limit: u64, stack_size: u64) -> i64 {
    let guest_limit = guest_limit.min(max_guest_addr_limit(base));
    let guest_limit = page_align_down(guest_limit);
    let usable = page_align_up(stack_size.max(MIN_STACK_SIZE));
    if guest_limit <= usable + PAGE_SIZE {
        return ENOMEM;
    }

    let s = ms();
    let mapped_high = s
        .vmas
        .iter()
        .fold(s.brk_current.max(s.brk_base), |high, vma| high.max(vma.end));
    let compact_top = page_align_up(
        mapped_high
            .saturating_add(INITIAL_STACK_HEADROOM)
            .saturating_add(PAGE_SIZE)
            .saturating_add(usable),
    );
    let stack_top = if compact_top <= guest_limit {
        compact_top
    } else {
        guest_limit
    };

    let stack_start = stack_top - usable;
    let guard_start = stack_start - PAGE_SIZE;

    let guard = map_fixed_anonymous(base, guard_start, PAGE_SIZE, PROT_NONE, guest_limit);
    if guard < 0 {
        return guard;
    }
    let stack = map_fixed_anonymous(
        base,
        stack_start,
        usable,
        PROT_READ | PROT_WRITE,
        guest_limit,
    );
    if stack < 0 {
        return stack;
    }

    (stack_top - PAGE_SIZE) as i64
}

/// Grow brk to `new_brk`, return new brk as i64. Used by process_create to
/// allocate ProcessState in guest Memory address space.
pub fn grow_brk(base: u32, new_brk: u64) -> i64 {
    let s = ms();
    if new_brk <= s.brk_current {
        return s.brk_current as i64;
    }
    if new_brk > max_guest_addr_limit(base) {
        return s.brk_current as i64;
    }
    if brk_growth_overlaps_vma(s, s.brk_current, new_brk) {
        return s.brk_current as i64;
    }
    unsafe {
        if !ensure_memory_capacity_for_guest_range(base, new_brk) {
            return s.brk_current as i64;
        }
        guest_mem::zero_mem(base, s.brk_current, (new_brk - s.brk_current) as usize);
    }
    s.brk_current = new_brk;
    invalidate_permit_cache(s);
    new_brk as i64
}

/// brk: adjust program break. addr=0 returns current break.
/// Grows WASM memory via memory.grow if needed, zero-fills new region.
pub fn sys_brk(vm: &mut ThreadState, base: u32, addr: u64) -> i64 {
    let s = ms();
    let guest_limit = effective_guest_limit(vm, base);
    if addr == 0 {
        return s.brk_current as i64;
    }
    if addr < s.brk_base {
        return s.brk_current as i64;
    }
    if addr > guest_limit {
        return s.brk_current as i64;
    }
    if brk_growth_overlaps_vma(s, s.brk_current, addr) {
        return s.brk_current as i64;
    }

    // Ensure WASM memory is large enough (§6.10: grow in 1MB units)
    unsafe {
        if !ensure_memory_capacity_for_guest_range(base, addr) {
            return s.brk_current as i64;
        }

        // Zero new region if growing
        if addr > s.brk_current {
            guest_mem::zero_mem(base, s.brk_current, (addr - s.brk_current) as usize);
        }
    }

    s.brk_current = addr;
    invalidate_permit_cache(s);
    addr as i64
}

// =========================================================================
// mmap
// =========================================================================

/// mmap: map pages into the guest address space.
/// Supports MAP_ANONYMOUS and MAP_PRIVATE file-backed (eager populate).
/// MAP_FIXED removes overlapping VMAs. WASM memory.grow on demand.
#[allow(clippy::too_many_arguments)]
pub fn sys_mmap(
    vm: &mut ThreadState,
    base: u32,
    addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    fd: i64,
    offset: u64,
) -> i64 {
    let s = ms();
    let guest_limit = effective_guest_limit(vm, base);
    if length == 0 {
        return EINVAL;
    }
    let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let is_fixed_noreplace = (flags & MAP_FIXED_NOREPLACE) != 0;
    let is_fixed = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;
    let is_anon = (flags & MAP_ANONYMOUS) != 0;
    let is_sparse_anon_reservation = is_anon && prot as i32 == PROT_NONE;

    // Validate fd for file-backed mmap
    // https://man7.org/linux/man-pages/man2/mmap.2.html
    let backing_ino = if is_anon {
        0
    } else if fd < 0 {
        return EBADF;
    } else {
        match fd_table::get_ofd(base, vm, fd as u64) {
            Some(ofd) => ofd.ino,
            None => return EBADF,
        }
    };

    let mut sparse_fixed_upgrade = false;
    let mut remove_fixed_overlap_after_validation = false;
    let nonfixed_limit = if is_sparse_anon_reservation {
        nonfixed_prot_none_reservation_limit(guest_limit)
    } else {
        guest_limit
    };
    let start = if is_fixed {
        if addr & (PAGE_SIZE - 1) != 0 {
            return EINVAL;
        }
        let Some(end) = addr.checked_add(len) else {
            return ENOMEM;
        };
        let sparse_fixed_upgrade_candidate = is_anon
            && prot as i32 != PROT_NONE
            && needs_sparse_linear_backing(base, end)
            && range_fully_covered_by_sparse_anon_reservation(s, addr, end);
        let fixed_limit = if is_sparse_anon_reservation || sparse_fixed_upgrade_candidate {
            prot_none_reservation_limit()
        } else {
            guest_limit
        };
        if end > fixed_limit {
            return ENOMEM;
        }
        if is_fixed_noreplace {
            if overlaps(s, addr, end) {
                return EEXIST;
            }
        } else {
            sparse_fixed_upgrade = sparse_fixed_upgrade_candidate;
            remove_fixed_overlap_after_validation = true;
        }
        addr
    } else if addr != 0
        && addr >= mmap_preferred_floor(s, len, nonfixed_limit)
        && addr
            .checked_add(len)
            .is_some_and(|end| end <= nonfixed_limit)
        && !overlaps(s, addr, addr + len)
    {
        addr
    } else if is_sparse_anon_reservation {
        let hole = find_high_hole(s, len, mmap_min_floor(s), nonfixed_limit);
        if hole == 0 {
            return ENOMEM;
        }
        hole
    } else if addr != 0 {
        let hole = find_hole(s, len, nonfixed_limit);
        if hole == 0 {
            return ENOMEM;
        }
        hole
    } else {
        let hole = find_hole(s, len, nonfixed_limit);
        if hole == 0 {
            return ENOMEM;
        }
        hole
    };
    let mapping_end = start + len;
    if range_overlaps_kernel_owned_guest_range(s, start, mapping_end) {
        return ENOMEM;
    }

    let needs_materialization = !is_anon || prot as i32 != PROT_NONE;
    if !is_anon && fd >= 0 && flags & (MAP_PRIVATE | MAP_SHARED) == 0 {
        return EINVAL;
    }
    if needs_materialization && !sparse_fixed_upgrade {
        // PROT_NONE reservations do not require backing linear-memory pages yet.
        if !ensure_memory_capacity_for_guest_range(base, start + len) {
            return ENOMEM;
        }
    }

    if !is_anon && fd >= 0 {
        let mut sample_bytes = [0u8; 8];
        let sample_len = memfs::read_file(backing_ino, offset, &mut sample_bytes);
        let sample = if sample_len > 0 {
            u64::from_le_bytes(sample_bytes)
        } else {
            0
        };
        record_file_mmap_materialize(
            vm,
            s,
            backing_ino,
            start,
            mapping_end,
            prot as i32,
            flags as i32,
            offset,
            sample,
        );
    }

    let mut fixed_overlap_removed = false;
    if remove_fixed_overlap_after_validation && needs_materialization && !sparse_fixed_upgrade {
        remove_overlap(s, start, mapping_end);
        fixed_overlap_removed = true;
    }

    if is_anon {
        if prot as i32 != PROT_NONE && !sparse_fixed_upgrade {
            unsafe {
                guest_mem::zero_mem(base, start, len as usize);
            }
        }
    } else if fd >= 0 {
        // File-backed mmap: eager-populate the mapping. For now MAP_PRIVATE and
        // MAP_SHARED use the same backing semantics inside a single guest
        // process; shared dirty-page writeback can be added later.
        // Eager populate from MemFS — zero-fill beyond EOF.
        // WASM has no page fault / demand paging, so populate eagerly.
        unsafe {
            guest_mem::zero_mem(base, start, len as usize);
        }
        if let Some(st) = memfs::stat(backing_ino) {
            let file_size = st.size;
            let copy_start = offset.min(file_size);
            let copy_end = (offset + len).min(file_size);
            if copy_end > copy_start {
                let copy_len = (copy_end - copy_start) as usize;
                let mut tmp = [0u8; 4096];
                let mut off = 0usize;
                while off < copy_len {
                    let chunk = (copy_len - off).min(tmp.len());
                    let n =
                        memfs::read_file(backing_ino, copy_start + off as u64, &mut tmp[..chunk]);
                    if n <= 0 {
                        break;
                    }
                    unsafe {
                        guest_mem::write_bytes(base, start + off as u64, &tmp[..n as usize]);
                    }
                    off += n as usize;
                }
            }
        }
    }

    record_mmap_exec_transition(
        vm,
        s,
        base,
        start,
        mapping_end,
        prot as i32,
        flags as i32,
        if is_anon { -1 } else { backing_ino as i32 },
        offset,
        is_anon,
        sparse_fixed_upgrade,
    );

    if remove_fixed_overlap_after_validation && !fixed_overlap_removed {
        remove_overlap(s, start, start + len);
    }

    s.vmas.push(Vma {
        start,
        end: mapping_end,
        prot: prot as i32,
        flags: flags as i32,
        fd: if is_anon { -1 } else { backing_ino as i32 },
        _pad: 0,
        offset,
    });
    s.vmas.sort_by_key(|v| v.start);

    if prot as i32 == PROT_NONE {
        s.has_prot_none = 1;
    }
    invalidate_permit_cache(s);

    start as i64
}

// =========================================================================
// munmap
// =========================================================================

/// munmap: unmap pages. Removes matching VMAs and recomputes PROT_NONE flag.
pub fn sys_munmap(_vm: &mut ThreadState, base: u32, addr: u64, length: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }
    let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let s = ms();
    flush_shared_mappings_in_range(base, addr, len);
    remove_overlap(s, addr, addr + len);
    recompute_prot_none(s);
    invalidate_permit_cache(s);
    0
}

/// msync: flush a mapped range to backing storage.
///
/// In the current eager-populated WASM memory model there is no separate host
/// page cache to flush for the mappings we expose to guests, so success is
/// equivalent for the cleanup paths that use msync() before munmap().
pub fn sys_msync(_vm: &mut ThreadState, _base: u32, _addr: u64, _length: u64, _flags: u64) -> i64 {
    flush_shared_mappings_in_range(_base, _addr, _length);
    0
}

// =========================================================================
// madvise
// =========================================================================

/// https://man7.org/linux/man-pages/man2/madvise.2.html
///
/// Minimal current support:
/// - `MADV_NORMAL`, `MADV_RANDOM`, `MADV_SEQUENTIAL`, `MADV_WILLNEED`: no-op success
/// - `MADV_DONTNEED`: preserve mapping shape and discard contents where our
///   memory model can represent that cheaply
/// - `MADV_FREE`: accepted for private anonymous memory and treated as an
///   immediate discard
/// - `MADV_DONTFORK`, `MADV_DOFORK`: accepted as advisory no-ops until the
///   current process model gains observable per-VMA fork inheritance semantics
pub fn sys_madvise(_vm: &mut ThreadState, base: u32, addr: u64, length: u64, advice: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }

    let advice = advice as i32;
    if !is_supported_madvise_advice(advice) {
        return EINVAL;
    }
    if length == 0 {
        return 0;
    }

    let len = page_align_up(length);
    let Some(end) = addr.checked_add(len) else {
        return ENOMEM;
    };

    let s = ms();
    if !range_fully_mapped(s, addr, end) {
        return ENOMEM;
    }
    if advice == MADV_FREE && !range_all_private_anonymous_or_brk(s, addr, end) {
        return EINVAL;
    }

    let brk_start = addr.max(s.brk_base);
    let brk_end = end.min(s.brk_current);
    if brk_start < brk_end {
        let ret = apply_madvise_to_brk_range(base, brk_start, brk_end, advice);
        if ret != 0 {
            return ret;
        }
    }

    for vma in s.vmas.iter() {
        let overlap_start = addr.max(vma.start);
        let overlap_end = end.min(vma.end);
        if overlap_start >= overlap_end {
            continue;
        }
        let ret = apply_madvise_to_vma_range(base, vma, overlap_start, overlap_end, advice);
        if ret != 0 {
            return ret;
        }
    }

    0
}

// =========================================================================
// mremap
// =========================================================================

/// mremap: resize or relocate an existing mapping.
/// Shrink in-place, grow in-place if adjacent space is free, or relocate.
pub fn sys_mremap(
    vm: &mut ThreadState,
    base: u32,
    old_addr: u64,
    old_size: u64,
    new_size: u64,
    _flags: u64,
    _new_addr: u64,
) -> i64 {
    let s = ms();
    let guest_limit = effective_guest_limit(vm, base);
    let old_len = (old_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let new_len = (new_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let idx = match find_vma_containing(s, old_addr) {
        Some(i) => i,
        None => return EINVAL,
    };

    if new_len <= old_len {
        s.vmas[idx].end = old_addr + new_len;
        invalidate_permit_cache(s);
        return old_addr as i64;
    }

    let grow_end = old_addr + new_len;
    if !overlaps_except(s, old_addr + old_len, grow_end, idx) {
        unsafe {
            if !ensure_memory_capacity_for_guest_range(base, grow_end) {
                return ENOMEM;
            }
            guest_mem::zero_mem(base, old_addr + old_len, (new_len - old_len) as usize);
        }
        s.vmas[idx].end = grow_end;
        invalidate_permit_cache(s);
        return old_addr as i64;
    }

    let new_start = find_hole(s, new_len, guest_limit);
    if new_start == 0 {
        return ENOMEM;
    }

    unsafe {
        if !ensure_memory_capacity_for_guest_range(base, new_start + new_len) {
            return ENOMEM;
        }
        let src = (base as u64 + old_addr) as u32 as *const u8;
        let dst = (base as u64 + new_start) as u32 as *mut u8;
        let src_start = old_addr;
        let src_end = old_addr + old_len;
        let dst_start = new_start;
        let dst_end = new_start + old_len;
        debug_assert!(
            !src.is_null(),
            "sys_mremap null src: old_addr=0x{old_addr:x} new_start=0x{new_start:x} len=0x{old_len:x}"
        );
        debug_assert!(
            !dst.is_null(),
            "sys_mremap null dst: old_addr=0x{old_addr:x} new_start=0x{new_start:x} len=0x{old_len:x}"
        );
        debug_assert!(
            dst_end <= src_start || src_end <= dst_start,
            "sys_mremap overlapping copy: src=[0x{src_start:x},0x{src_end:x}) dst=[0x{dst_start:x},0x{dst_end:x})"
        );
        core::ptr::copy_nonoverlapping(src, dst, old_len as usize);
        guest_mem::zero_mem(base, new_start + old_len, (new_len - old_len) as usize);
    }

    s.vmas[idx].start = new_start;
    s.vmas[idx].end = new_start + new_len;
    s.vmas.sort_by_key(|v| v.start);
    invalidate_permit_cache(s);
    new_start as i64
}

// =========================================================================
// mprotect
// =========================================================================

/// mprotect: change VMA protection flags. Splits VMAs at boundaries if needed.
/// Sets has_prot_none flag for SIGSEGV detection.
pub fn sys_mprotect(vm: &mut ThreadState, base: u32, addr: u64, length: u64, prot: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }
    if length == 0 {
        return 0;
    }
    let Some(len) = length
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
    else {
        return ENOMEM;
    };
    let Some(end) = addr.checked_add(len) else {
        return ENOMEM;
    };
    let s = ms();
    if !range_fully_mapped(s, addr, end) {
        return ENOMEM;
    }

    let original_vmas = s.vmas.clone();
    let mut rebuilt_vmas = Vec::with_capacity(original_vmas.len() + 2);

    for v in original_vmas {
        if v.end <= addr || v.start >= end {
            rebuilt_vmas.push(v);
            continue;
        }

        if v.start < addr {
            rebuilt_vmas.push(Vma {
                start: v.start,
                end: addr,
                ..v
            });
        }

        let segment = Vma {
            start: v.start.max(addr),
            end: v.end.min(end),
            prot: prot as i32,
            ..v
        };

        if segment.end > segment.start {
            record_mprotect_transition(vm, addr, end, segment.start, segment.end, &v, prot as i32);
            let was_prot_none = v.prot == PROT_NONE;
            if prot as i32 != PROT_NONE
                && was_prot_none
                && (segment.flags as u64 & MAP_ANONYMOUS) != 0
            {
                unsafe {
                    if !ensure_memory_capacity_for_guest_range(base, segment.end) {
                        return ENOMEM;
                    }
                    guest_mem::zero_mem(
                        base,
                        segment.start,
                        (segment.end - segment.start) as usize,
                    );
                }
            }
            rebuilt_vmas.push(segment);
        }

        if v.end > end {
            rebuilt_vmas.push(Vma {
                start: end,
                end: v.end,
                ..v
            });
        }
    }

    s.vmas = rebuilt_vmas;
    recompute_prot_none(s);
    invalidate_permit_cache(s);
    0
}

// =========================================================================
// VMA table helpers
// =========================================================================

fn mmap_min_floor(s: &AddressSpaceState) -> u64 {
    align_mmap_base(s.brk_current.max(s.brk_base).saturating_add(0x1F_FFFF)).max(MIN_MMAP_BASE)
}

fn mmap_preferred_floor(s: &AddressSpaceState, len: u64, guest_limit: u64) -> u64 {
    let min_floor = mmap_min_floor(s);
    let preferred = align_mmap_base(s.brk_current.max(s.brk_base).saturating_add(BRK_MMAP_GAP))
        .max(MIN_MMAP_BASE);
    if preferred
        .checked_add(len)
        .is_some_and(|end| end <= guest_limit)
    {
        preferred
    } else {
        min_floor
    }
}

fn find_hole(s: &mut AddressSpaceState, len: u64, guest_limit: u64) -> u64 {
    let floor = mmap_preferred_floor(s, len, guest_limit);
    let hole = find_hole_from(s, s.mmap_next.max(floor), len, guest_limit);
    if hole != 0 {
        s.mmap_next = hole + len;
        return hole;
    }

    let hole = find_hole_from(s, floor, len, guest_limit);
    if hole != 0 {
        s.mmap_next = hole + len;
        return hole;
    }

    let hole = find_hole_from(s, mmap_min_floor(s), len, guest_limit);
    if hole != 0 {
        s.mmap_next = hole + len;
    }
    hole
}

fn find_hole_from(s: &AddressSpaceState, start: u64, len: u64, guest_limit: u64) -> u64 {
    let mut candidate = (start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    loop {
        if candidate + len > guest_limit {
            return 0;
        }
        if !overlaps(s, candidate, candidate + len) {
            return candidate;
        }
        for v in s.vmas.iter() {
            if v.start < candidate + len && v.end > candidate {
                candidate = (v.end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                break;
            }
        }
    }
}

fn find_high_hole(s: &AddressSpaceState, len: u64, floor: u64, guest_limit: u64) -> u64 {
    if len == 0
        || floor
            .checked_add(len)
            .is_none_or(|min_end| min_end > guest_limit)
    {
        return 0;
    }

    let mut candidate = (guest_limit - len) & !(PAGE_SIZE - 1);
    loop {
        let end = candidate + len;
        let mut moved = false;
        for v in s.vmas.iter().rev() {
            if v.end <= candidate || v.start >= end {
                continue;
            }
            let Some(next) = v.start.checked_sub(len) else {
                return 0;
            };
            candidate = next & !(PAGE_SIZE - 1);
            if candidate < floor {
                return 0;
            }
            moved = true;
            break;
        }
        if !moved {
            return candidate;
        }
    }
}

fn overlaps(s: &AddressSpaceState, start: u64, end: u64) -> bool {
    for v in s.vmas.iter() {
        if v.start < end && v.end > start {
            return true;
        }
    }
    false
}

fn range_overlaps_kernel_owned_guest_range(s: &AddressSpaceState, start: u64, end: u64) -> bool {
    if start >= end {
        return false;
    }
    s.kernel_owned_guest_ranges
        .iter()
        .any(|range| start < range.end && end > range.start)
}

fn brk_growth_overlaps_vma(s: &AddressSpaceState, current_brk: u64, new_brk: u64) -> bool {
    if new_brk <= current_brk {
        return false;
    }
    let grow_start = page_align_up(current_brk);
    let grow_end = page_align_up(new_brk);
    grow_start < grow_end && overlaps(s, grow_start, grow_end)
}

fn range_cover_end_any_mapping(s: &AddressSpaceState, addr: u64) -> u64 {
    let mut cover_end = 0u64;

    if addr >= s.brk_base && addr < s.brk_current {
        cover_end = s.brk_current;
    }

    if let Some(index) = find_vma_containing(s, addr) {
        cover_end = cover_end.max(s.vmas[index].end);
    }

    cover_end
}

fn range_fully_mapped(s: &AddressSpaceState, start: u64, end: u64) -> bool {
    let mut cur = start;
    while cur < end {
        let cover_end = range_cover_end_any_mapping(s, cur);
        if cover_end <= cur {
            return false;
        }
        cur = cover_end.min(end);
    }
    true
}

fn range_all_private_anonymous_or_brk(s: &AddressSpaceState, start: u64, end: u64) -> bool {
    let mut cur = start;
    while cur < end {
        if cur >= s.brk_base && cur < s.brk_current {
            cur = s.brk_current.min(end);
            continue;
        }

        let mut covered = false;
        for v in s.vmas.iter() {
            if cur < v.start || cur >= v.end {
                continue;
            }
            if v.fd >= 0
                || (v.flags as u64 & MAP_ANONYMOUS) == 0
                || (v.flags as u64 & MAP_SHARED) != 0
            {
                return false;
            }
            cur = v.end.min(end);
            covered = true;
            break;
        }
        if !covered {
            return false;
        }
    }
    true
}

fn overlaps_except(s: &AddressSpaceState, start: u64, end: u64, except: usize) -> bool {
    for (i, v) in s.vmas.iter().enumerate() {
        if i == except {
            continue;
        }
        if v.start < end && v.end > start {
            return true;
        }
    }
    false
}

fn is_supported_madvise_advice(advice: i32) -> bool {
    matches!(
        advice,
        MADV_NORMAL
            | MADV_RANDOM
            | MADV_SEQUENTIAL
            | MADV_WILLNEED
            | MADV_DONTNEED
            | MADV_FREE
            | MADV_DONTFORK
            | MADV_DOFORK
    )
}

fn apply_madvise_to_brk_range(base: u32, start: u64, end: u64, advice: i32) -> i64 {
    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED | MADV_DONTFORK
        | MADV_DOFORK => 0,
        MADV_DONTNEED | MADV_FREE => {
            unsafe {
                guest_mem::zero_mem(base, start, (end - start) as usize);
            }
            0
        }
        _ => EINVAL,
    }
}

fn apply_madvise_to_vma_range(base: u32, vma: &Vma, start: u64, end: u64, advice: i32) -> i64 {
    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED | MADV_DONTFORK
        | MADV_DOFORK => 0,
        MADV_DONTNEED => {
            if vma.prot == PROT_NONE {
                return 0;
            }
            if vma.fd >= 0 {
                if (vma.flags as u64 & MAP_SHARED) != 0 {
                    flush_shared_vma_range(base, vma, start, end);
                }
                repopulate_file_vma_range(base, vma, start, end);
                return 0;
            }
            if (vma.flags as u64 & MAP_SHARED) != 0 {
                return 0;
            }
            unsafe {
                guest_mem::zero_mem(base, start, (end - start) as usize);
            }
            0
        }
        MADV_FREE => {
            if vma.prot == PROT_NONE {
                return 0;
            }
            if vma.fd >= 0
                || (vma.flags as u64 & MAP_ANONYMOUS) == 0
                || (vma.flags as u64 & MAP_SHARED) != 0
            {
                return EINVAL;
            }
            unsafe {
                guest_mem::zero_mem(base, start, (end - start) as usize);
            }
            0
        }
        _ => EINVAL,
    }
}

fn remove_overlap(s: &mut AddressSpaceState, start: u64, end: u64) {
    let mut i = 0;
    while i < s.vmas.len() {
        let v = s.vmas[i];
        if v.start >= end || v.end <= start {
            i += 1;
            continue;
        }

        if v.start >= start && v.end <= end {
            s.vmas.swap_remove(i);
            continue;
        }
        if v.start < start && v.end > end {
            s.vmas.push(Vma {
                start: end,
                end: v.end,
                ..v
            });
            s.vmas[i].end = start;
            i += 1;
            continue;
        }
        if v.start < start {
            s.vmas[i].end = start;
        } else {
            s.vmas[i].start = end;
        }
        i += 1;
    }
    s.vmas.sort_by_key(|v| v.start);
    invalidate_permit_cache(s);
}

fn find_vma_containing(s: &AddressSpaceState, addr: u64) -> Option<usize> {
    let mut lo = 0usize;
    let mut hi = s.vmas.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if s.vmas[mid].start <= addr {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let index = lo.checked_sub(1)?;
    if addr < s.vmas[index].end {
        Some(index)
    } else {
        None
    }
}

fn recompute_prot_none(s: &mut AddressSpaceState) {
    s.has_prot_none = 0;
    for v in s.vmas.iter() {
        if v.prot == PROT_NONE {
            s.has_prot_none = 1;
            return;
        }
    }
}

fn flush_shared_mappings_in_range(base: u32, start: u64, length: u64) {
    let end = start.saturating_add(length);
    let s = ms();
    for vma in s.vmas.iter() {
        let flush_start = start.max(vma.start);
        let flush_end = end.min(vma.end);
        if flush_start >= flush_end {
            continue;
        }
        flush_shared_vma_range(base, vma, flush_start, flush_end);
    }
}

pub(crate) fn flush_shared_mappings_for_guest_write(base: u32, start: u64, length: u64) -> bool {
    let end = start.saturating_add(length);
    let s = ms();
    let mut flushed = false;
    for vma in s.vmas.iter() {
        if (vma.flags as u64 & MAP_SHARED) == 0 || vma.fd < 0 {
            continue;
        }
        let flush_start = start.max(vma.start);
        let flush_end = end.min(vma.end);
        if flush_start >= flush_end {
            continue;
        }
        flush_shared_vma_range(base, vma, flush_start, flush_end);
        flushed = true;
    }
    flushed
}

fn flush_shared_vma_range(base: u32, vma: &Vma, flush_start: u64, flush_end: u64) {
    if (vma.flags as u64 & MAP_SHARED) == 0 || vma.fd < 0 {
        return;
    }

    let ino = vma.fd as u32;
    let mut guest_addr = flush_start;
    let mut file_offset = vma.offset + (flush_start - vma.start);
    let mut tmp = [0u8; 4096];

    while guest_addr < flush_end {
        let chunk = ((flush_end - guest_addr) as usize).min(tmp.len());
        unsafe {
            guest_mem::read_bytes(base, guest_addr, &mut tmp[..chunk]);
        }
        let written = memfs::write_file(ino, file_offset, &tmp[..chunk]);
        if written != chunk as i64 {
            return;
        }
        guest_addr += chunk as u64;
        file_offset += chunk as u64;
    }
}

fn repopulate_file_vma_range(base: u32, vma: &Vma, start: u64, end: u64) {
    unsafe {
        guest_mem::zero_mem(base, start, (end - start) as usize);
    }

    let ino = vma.fd as u32;
    let Some(st) = memfs::stat(ino) else {
        return;
    };
    let file_size = st.size;
    let copy_start = (vma.offset + (start - vma.start)).min(file_size);
    let copy_end = (vma.offset + (end - vma.start)).min(file_size);
    if copy_end <= copy_start {
        return;
    }

    let copy_len = (copy_end - copy_start) as usize;
    let mut tmp = [0u8; 4096];
    let mut off = 0usize;
    while off < copy_len {
        let chunk = (copy_len - off).min(tmp.len());
        let n = memfs::read_file(ino, copy_start + off as u64, &mut tmp[..chunk]);
        if n <= 0 {
            break;
        }
        unsafe {
            guest_mem::write_bytes(base, start + off as u64, &tmp[..n as usize]);
        }
        off += n as usize;
    }
}

fn refresh_shared_file_vma(base: u32, vma: &Vma, guest_limit: u64) {
    if (vma.flags as u64 & MAP_SHARED) == 0 || vma.fd < 0 {
        return;
    }

    let start = vma.start.min(guest_limit);
    let end = vma.end.min(guest_limit);
    if start >= end {
        return;
    }

    repopulate_file_vma_range(base, vma, start, end);
}
