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

/// Address space state — shared by all threads of a process.
/// Allocated in kernel Worker linear memory via alloc.rs.
/// Separated for fork (new address space) and execve (reinit).
/// VMA table is a sorted Vec<Vma> (sorted by start address).
/// https://man7.org/linux/man-pages/man2/mmap.2.html
struct AddressSpaceState {
    vmas: Vec<Vma>,
    brk_base: u64,
    brk_current: u64,
    mmap_next: u64,
    has_prot_none: u32,
}

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

/// Internal snapshot of address space state used by plain-fork handoff support.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct AddressSpaceSnapshot {
    vmas: Vec<Vma>,
    brk_base: u64,
    brk_current: u64,
    mmap_next: u64,
    has_prot_none: u32,
}

impl AddressSpaceSnapshot {
    #[allow(dead_code)]
    pub(crate) fn vmas(&self) -> &[Vma] {
        &self.vmas
    }
}

/// Pointer to AddressSpaceState in kernel Worker linear memory (allocated via alloc.rs).
static mut MEM_STATE: *mut AddressSpaceState = core::ptr::null_mut();

pub const DEFAULT_STACK_SIZE: u64 = 1024 * 1024;
const MIN_STACK_SIZE: u64 = 64 * 1024;

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

/// Initialize memory state. Allocates AddressSpaceState via alloc.rs.
pub fn init(brk_start: u64) {
    // Guest VMA placement must depend on the guest address space, not on the
    // kernel-worker bump allocator's host-side placement.
    let mmap_start = ((brk_start + 0x1F_FFFF) & !0xF_FFFF).max(0x20_0000);
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
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            ptr as *mut AddressSpaceState,
            AddressSpaceState {
                vmas: Vec::new(),
                brk_base: brk_start,
                brk_current: brk_start,
                mmap_next: mmap_start,
                has_prot_none: 0,
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

#[allow(dead_code)]
pub(crate) fn snapshot_for_plain_fork() -> AddressSpaceSnapshot {
    let s = ms();
    AddressSpaceSnapshot {
        // Plain-fork handoff snapshots only address-space metadata; kernel-owned
        // objects are reattached by the runtime from the canonical owner.
        vmas: s.vmas.clone(),
        brk_base: s.brk_base,
        brk_current: s.brk_current,
        mmap_next: s.mmap_next,
        has_prot_none: s.has_prot_none,
    }
}

#[allow(dead_code)]
pub(crate) fn restore_after_plain_fork(snapshot: &AddressSpaceSnapshot) {
    let s = ms();
    s.vmas = snapshot.vmas.clone();
    s.brk_base = snapshot.brk_base;
    s.brk_current = snapshot.brk_current;
    s.mmap_next = snapshot.mmap_next;
    s.has_prot_none = snapshot.has_prot_none;
}

pub fn reset_for_execve_with_flush(base: u32, brk_start: u64, flush_shared: bool) {
    let mmap_start = ((brk_start + 0x1F_FFFF) & !0xF_FFFF).max(0x20_0000);
    if flush_shared {
        flush_shared_mappings_in_range(base, 0, u64::MAX);
    }
    let s = ms();
    s.vmas.clear();
    s.brk_base = brk_start;
    s.brk_current = brk_start;
    s.mmap_next = mmap_start;
    s.has_prot_none = 0;
}

pub fn reset_for_execve(base: u32, brk_start: u64) {
    reset_for_execve_with_flush(base, brk_start, true);
}

pub fn flush_shared_mappings(base: u32) {
    flush_shared_mappings_in_range(base, 0, u64::MAX);
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
    let guest_limit = ((core::arch::wasm32::memory_size(0) as u64) * 65536)
        .saturating_sub(base as u64)
        .min(0x8000_0000);
    if start > u32::MAX as u64 || end > guest_limit || end > u32::MAX as u64 {
        return false;
    }
    !range_has_prot_none(start, len)
}

fn range_cover_end_with_prot(s: &AddressSpaceState, addr: u64, prot: i32) -> u64 {
    let mut cover_end = 0u64;

    if (prot & PROT_EXEC) == 0 && addr >= s.brk_base && addr < s.brk_current {
        cover_end = s.brk_current;
    }

    for v in s.vmas.iter() {
        if addr < v.start || addr >= v.end {
            continue;
        }
        if v.prot == PROT_NONE || (v.prot & prot) != prot {
            continue;
        }
        cover_end = cover_end.max(v.end);
    }

    cover_end
}

pub fn guest_range_permitted(start: u64, len: u64, prot: i32) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    if start > u32::MAX as u64 || end > 0x8000_0000 || end > u32::MAX as u64 {
        return false;
    }

    let s = ms();
    let mut cur = start;
    while cur < end {
        let cover_end = range_cover_end_with_prot(s, cur, prot);
        if cover_end <= cur {
            return false;
        }
        cur = cover_end.min(end);
    }
    true
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
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_brk_base() -> u64 {
    ms().brk_base
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_mmap_next() -> u64 {
    ms().mmap_next
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_vma_len() -> u32 {
    ms().vmas.len() as u32
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_vma_start(index: u32) -> u64 {
    ms().vmas.get(index as usize).map(|v| v.start).unwrap_or(0)
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_vma_end(index: u32) -> u64 {
    ms().vmas.get(index as usize).map(|v| v.end).unwrap_or(0)
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_vma_prot(index: u32) -> i32 {
    ms().vmas.get(index as usize).map(|v| v.prot).unwrap_or(0)
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_vma_flags(index: u32) -> i32 {
    ms().vmas.get(index as usize).map(|v| v.flags).unwrap_or(0)
}

fn ensure_memory_capacity_for_guest_range(base: u32, guest_end: u64) -> bool {
    let Some(needed) = (base as u64).checked_add(guest_end) else {
        return false;
    };
    if needed > 0x1_0000_0000 {
        return false;
    }

    let mem_size = (core::arch::wasm32::memory_size(0) as u64) * 65536;
    if needed <= mem_size {
        return true;
    }

    let deficit = needed - mem_size;
    let grow_unit = 16u64 * 65536; // 1 MB
    let grow_bytes = deficit.div_ceil(grow_unit) * grow_unit;
    let pages = (grow_bytes / 65536) as usize;
    core::arch::wasm32::memory_grow(0, pages) != usize::MAX
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

fn map_fixed_anonymous(base: u32, start: u64, length: u64, prot: i32) -> i64 {
    if start & (PAGE_SIZE - 1) != 0 || length == 0 {
        return EINVAL;
    }
    let len = page_align_up(length);
    let Some(end) = start.checked_add(len) else {
        return ENOMEM;
    };
    if end > 0x8000_0000 {
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
    start as i64
}

/// Reserve the initial process stack and a guard page below it.
/// Returns the logical stack top used for argv/env/auxv placement.
pub fn map_initial_stack(base: u32, guest_limit: u64, stack_size: u64) -> i64 {
    let guest_limit = guest_limit.min(0x8000_0000);
    let usable = page_align_up(stack_size.max(MIN_STACK_SIZE));
    if guest_limit <= usable + PAGE_SIZE {
        return ENOMEM;
    }

    let stack_start = guest_limit - usable;
    let guard_start = stack_start - PAGE_SIZE;

    let guard = map_fixed_anonymous(base, guard_start, PAGE_SIZE, PROT_NONE);
    if guard < 0 {
        return guard;
    }
    let stack = map_fixed_anonymous(base, stack_start, usable, PROT_READ | PROT_WRITE);
    if stack < 0 {
        return stack;
    }

    (guest_limit - PAGE_SIZE) as i64
}

/// Grow brk to `new_brk`, return new brk as i64. Used by process_create to
/// allocate ProcessState in guest Memory address space.
pub fn grow_brk(base: u32, new_brk: u64) -> i64 {
    let s = ms();
    if new_brk <= s.brk_current {
        return s.brk_current as i64;
    }
    if new_brk > 0x8000_0000 {
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
    new_brk as i64
}

/// brk: adjust program break. addr=0 returns current break.
/// Grows WASM memory via memory.grow if needed, zero-fills new region.
pub fn sys_brk(_vm: &mut ThreadState, base: u32, addr: u64) -> i64 {
    let s = ms();
    if addr == 0 {
        return s.brk_current as i64;
    }
    if addr < s.brk_base {
        return s.brk_current as i64;
    }
    // 2GB address space ceiling
    if addr > 0x8000_0000 {
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
    if length == 0 {
        return EINVAL;
    }
    let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let is_fixed = (flags & MAP_FIXED) != 0;
    let is_anon = (flags & MAP_ANONYMOUS) != 0;

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

    let start = if is_fixed {
        if addr & (PAGE_SIZE - 1) != 0 {
            return EINVAL;
        }
        // 2GB address space ceiling
        if addr + len > 0x8000_0000 {
            return ENOMEM;
        }
        remove_overlap(s, addr, addr + len);
        addr
    } else if addr != 0
        && addr >= mmap_floor(s)
        && addr + len <= 0x8000_0000
        && !overlaps(s, addr, addr + len)
    {
        addr
    } else if addr != 0 {
        let hole = find_hole_from(s, mmap_floor(s), len);
        if hole == 0 {
            return ENOMEM;
        }
        hole
    } else if is_anon && prot as i32 == PROT_NONE {
        let hole = find_hole_high(s, len);
        if hole == 0 {
            return ENOMEM;
        }
        hole
    } else {
        let hole = find_hole(s, len);
        if hole == 0 {
            return ENOMEM;
        }
        hole
    };

    let needs_materialization = !is_anon || prot as i32 != PROT_NONE;
    if needs_materialization {
        // PROT_NONE reservations do not require backing linear-memory pages yet.
        if !ensure_memory_capacity_for_guest_range(base, start + len) {
            return ENOMEM;
        }
    }

    if is_anon {
        if prot as i32 != PROT_NONE {
            unsafe {
                guest_mem::zero_mem(base, start, len as usize);
            }
        }
    } else if fd >= 0 {
        // File-backed mmap: eager-populate the mapping. For now MAP_PRIVATE and
        // MAP_SHARED use the same backing semantics inside a single guest
        // process; shared dirty-page writeback can be added later.
        if flags & (MAP_PRIVATE | MAP_SHARED) == 0 {
            return EINVAL;
        }
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

    s.vmas.push(Vma {
        start,
        end: start + len,
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
// mremap
// =========================================================================

/// mremap: resize or relocate an existing mapping.
/// Shrink in-place, grow in-place if adjacent space is free, or relocate.
pub fn sys_mremap(
    _vm: &mut ThreadState,
    base: u32,
    old_addr: u64,
    old_size: u64,
    new_size: u64,
    _flags: u64,
    _new_addr: u64,
) -> i64 {
    let s = ms();
    let old_len = (old_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let new_len = (new_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let idx = match find_vma_containing(s, old_addr) {
        Some(i) => i,
        None => return EINVAL,
    };

    if new_len <= old_len {
        s.vmas[idx].end = old_addr + new_len;
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
        return old_addr as i64;
    }

    let new_start = find_hole(s, new_len);
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
    new_start as i64
}

// =========================================================================
// mprotect
// =========================================================================

/// mprotect: change VMA protection flags. Splits VMAs at boundaries if needed.
/// Sets has_prot_none flag for SIGSEGV detection.
pub fn sys_mprotect(_vm: &mut ThreadState, base: u32, addr: u64, length: u64, prot: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 {
        return EINVAL;
    }
    let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end = addr + len;
    let s = ms();

    let mut i = 0;
    while i < s.vmas.len() {
        let v = s.vmas[i];
        if v.end <= addr || v.start >= end {
            i += 1;
            continue;
        }

        if v.start < addr {
            s.vmas.push(Vma {
                start: v.start,
                end: addr,
                ..v
            });
            s.vmas[i].start = addr;
        }
        if v.end > end {
            let cur = s.vmas[i];
            s.vmas.push(Vma {
                start: end,
                end: v.end,
                ..cur
            });
            s.vmas[i].end = end;
        }
        let was_prot_none = s.vmas[i].prot == PROT_NONE;
        let segment = s.vmas[i];
        if prot as i32 != PROT_NONE && was_prot_none && (segment.flags as u64 & MAP_ANONYMOUS) != 0
        {
            unsafe {
                if !ensure_memory_capacity_for_guest_range(base, segment.end) {
                    return ENOMEM;
                }
                guest_mem::zero_mem(base, segment.start, (segment.end - segment.start) as usize);
            }
        }
        s.vmas[i].prot = prot as i32;
        i += 1;
    }

    s.vmas.sort_by_key(|v| v.start);
    recompute_prot_none(s);
    0
}

// =========================================================================
// VMA table helpers
// =========================================================================

fn mmap_floor(s: &AddressSpaceState) -> u64 {
    ((s.brk_current.max(s.brk_base) + 0x1F_FFFF) & !0xF_FFFF).max(0x20_0000)
}

fn find_hole(s: &mut AddressSpaceState, len: u64) -> u64 {
    let floor = mmap_floor(s);
    let hole = find_hole_from(s, s.mmap_next.max(floor), len);
    if hole != 0 {
        s.mmap_next = hole + len;
        return hole;
    }

    let hole = find_hole_from(s, floor, len);
    if hole != 0 {
        s.mmap_next = hole + len;
    }
    hole
}

fn find_hole_from(s: &AddressSpaceState, start: u64, len: u64) -> u64 {
    let mut candidate = (start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    loop {
        if candidate + len > 0x8000_0000 {
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

fn find_hole_high(s: &AddressSpaceState, len: u64) -> u64 {
    let floor = mmap_floor(s);
    if len == 0 || len > 0x8000_0000 - floor {
        return 0;
    }

    let mut candidate = (0x8000_0000 - len) & !(PAGE_SIZE - 1);
    loop {
        if candidate < floor {
            return 0;
        }

        let mut overlap = None;
        for v in s.vmas.iter().rev() {
            if v.start < candidate + len && v.end > candidate {
                overlap = Some(v.start);
                break;
            }
        }

        match overlap {
            None => return candidate,
            Some(start) => {
                if start < len {
                    return 0;
                }
                candidate = (start - len) & !(PAGE_SIZE - 1);
            }
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

fn brk_growth_overlaps_vma(s: &AddressSpaceState, current_brk: u64, new_brk: u64) -> bool {
    if new_brk <= current_brk {
        return false;
    }
    let grow_start = page_align_up(current_brk);
    let grow_end = page_align_up(new_brk);
    grow_start < grow_end && overlaps(s, grow_start, grow_end)
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
}

fn find_vma_containing(s: &AddressSpaceState, addr: u64) -> Option<usize> {
    for (i, v) in s.vmas.iter().enumerate() {
        if addr >= v.start && addr < v.end {
            return Some(i);
        }
    }
    None
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

fn refresh_shared_file_vma(base: u32, vma: &Vma, guest_limit: u64) {
    if (vma.flags as u64 & MAP_SHARED) == 0 || vma.fd < 0 {
        return;
    }

    let start = vma.start.min(guest_limit);
    let end = vma.end.min(guest_limit);
    if start >= end {
        return;
    }

    unsafe {
        guest_mem::zero_mem(base, start, (end - start) as usize);
    }

    let ino = vma.fd as u32;
    let Some(st) = memfs::stat(ino) else {
        return;
    };
    let file_size = st.size;
    let copy_start = vma.offset.min(file_size);
    let copy_end = (vma.offset + (end - start)).min(file_size);
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
