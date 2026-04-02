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

use alloc_crate::vec::Vec;

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

/// Internal snapshot of address space state used by plain-fork handoff support.
#[derive(Clone)]
pub(crate) struct AddressSpaceSnapshot {
    vmas: Vec<Vma>,
    brk_base: u64,
    brk_current: u64,
    mmap_next: u64,
    has_prot_none: u32,
}

impl AddressSpaceSnapshot {
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
        core::ptr::write(core::ptr::addr_of_mut!(MEM_STATE), ptr as *mut AddressSpaceState);
    }
}

/// Initialize memory state. Allocates AddressSpaceState via alloc.rs.
pub fn init(brk_start: u64) {
    // Guest VMA placement must depend on the guest address space, not on the
    // kernel-worker bump allocator's host-side placement.
    let mmap_start = ((brk_start + 0x1F_FFFF) & !0xF_FFFF).max(0x20_0000);
    unsafe {
        // Null the pointer so we always take the fresh allocation path.
        // After alloc::reset() the old AddressSpaceState occupies bump-allocated memory
        // that will be reused by other subsystem inits. The old Vec<Vma>'s
        // system-allocator buffer (if any) is leaked; this is acceptable
        // because alloc::reset() reclaims the bump region anyway.
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
        core::ptr::write(core::ptr::addr_of_mut!(MEM_STATE), ptr as *mut AddressSpaceState);
    }
}

pub fn has_prot_none() -> bool {
    ms().has_prot_none != 0
}

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

// =========================================================================
// brk
// =========================================================================

/// Return current brk address (for ProcessState allocation in guest Memory).
pub fn current_brk() -> u64 {
    ms().brk_current
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
    let grow_bytes = ((deficit + grow_unit - 1) / grow_unit) * grow_unit;
    let pages = (grow_bytes / 65536) as usize;
    core::arch::wasm32::memory_grow(0, pages as usize) != usize::MAX
}

pub fn ensure_guest_memory_capacity(base: u32, guest_end: u64) -> bool {
    ensure_memory_capacity_for_guest_range(base, guest_end)
}

fn page_align_up(len: u64) -> u64 {
    (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
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
        unsafe {
            if !ensure_memory_capacity_for_guest_range(base, start + len) {
                return ENOMEM;
            }
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
        if let Some(st) = memfs::stat(backing_ino as u32) {
            let file_size = st.size;
            let copy_start = offset.min(file_size);
            let copy_end = (offset + len).min(file_size);
            if copy_end > copy_start {
                let copy_len = (copy_end - copy_start) as usize;
                let mut tmp = [0u8; 4096];
                let mut off = 0usize;
                while off < copy_len {
                    let chunk = (copy_len - off).min(tmp.len());
                    let n = memfs::read_file(
                        backing_ino as u32,
                        copy_start + off as u64,
                        &mut tmp[..chunk],
                    );
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
        if prot as i32 != PROT_NONE && was_prot_none && (segment.flags as u64 & MAP_ANONYMOUS) != 0 {
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

#[cfg(test)]
mod tests {
    use crate::abi::*;
    use crate::test_helpers::TestVm;

    #[test]
    fn memory_syscalls() {
        let mut t = TestVm::new();

        // brk: query current brk
        let cur = t.sys_brk(0);
        assert!(cur > 0);

        // brk: extend
        let new_brk = cur as u64 + 4096;
        let ret = t.sys_brk(new_brk);
        assert_eq!(ret, new_brk as i64);

        // mmap: anonymous
        let addr = t.sys_mmap(
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0,
        );
        assert!(
            addr > 0,
            "mmap should return positive address, got {}",
            addr
        );

        // Write and read back
        unsafe {
            crate::guest_mem::write_u64(t.base, addr as u64, 0xDEADBEEF);
            assert_eq!(crate::guest_mem::read_u64(t.base, addr as u64), 0xDEADBEEF);
        }

        // munmap
        let ret = t.sys_munmap(addr as u64, 4096);
        assert_eq!(ret, 0);

        // mprotect
        let addr2 = t.sys_mmap(
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0,
        );
        assert!(addr2 > 0);

        // Change to read-only
        let ret = t.sys_mprotect(addr2 as u64, 4096, PROT_READ);
        assert_eq!(ret, 0);

        // Change to PROT_NONE should set the flag
        let ret2 = t.sys_mprotect(addr2 as u64, 4096, PROT_NONE);
        assert_eq!(ret2, 0);
        assert!(super::has_prot_none());

        t.sys_munmap(addr2 as u64, 4096);
    }

    // https://man7.org/linux/man-pages/man2/mmap.2.html
    // https://man7.org/linux/man-pages/man2/brk.2.html
    // VMA management requirements from sorted Vec<Vma> design:

    #[test]
    fn vmas_are_sorted_after_multiple_mmaps() {
        let mut t = TestVm::new();
        let a1 = t.sys_mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        let a2 = t.sys_mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        let a3 = t.sys_mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        assert!(a1 > 0 && a2 > 0 && a3 > 0);
        // VMA table should be sorted by start address
        let s = super::ms();
        for i in 1..s.vmas.len() {
            assert!(
                s.vmas[i].start >= s.vmas[i - 1].start,
                "VMAs not sorted: [{}].start=0x{:x} < [{}].start=0x{:x}",
                i,
                s.vmas[i].start,
                i - 1,
                s.vmas[i - 1].start
            );
        }
        t.sys_munmap(a1 as u64, 4096);
        t.sys_munmap(a2 as u64, 4096);
        t.sys_munmap(a3 as u64, 4096);
    }

    #[test]
    fn map_fixed_replaces_existing_vma() {
        let mut t = TestVm::new();
        let a = t.sys_mmap(
            0,
            8192,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0,
        );
        assert!(a > 0);
        // MAP_FIXED over the same region with different prot
        let a2 = t.sys_mmap(
            a as u64,
            4096,
            PROT_READ,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
            -1,
            0,
        );
        assert_eq!(a2, a);
        t.sys_munmap(a as u64, 8192);
    }

    #[test]
    fn munmap_partial_splits_vma() {
        let mut t = TestVm::new();
        let a = t.sys_mmap(
            0,
            0x3000,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0,
        );
        assert!(a > 0);
        let count_before = super::ms().vmas.len();
        // Unmap the middle page — should split into 2 VMAs
        let ret = t.sys_munmap(a as u64 + 0x1000, 0x1000);
        assert_eq!(ret, 0);
        let count_after = super::ms().vmas.len();
        assert!(
            count_after >= count_before,
            "split should not reduce VMA count"
        );
        t.sys_munmap(a as u64, 0x1000);
        t.sys_munmap(a as u64 + 0x2000, 0x1000);
    }

    #[test]
    fn mprotect_split_on_boundary_mismatch() {
        let mut t = TestVm::new();
        let a = t.sys_mmap(
            0,
            0x2000,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0,
        );
        assert!(a > 0);
        // Protect only the first page — should split the VMA
        let ret = t.sys_mprotect(a as u64, 0x1000, PROT_READ);
        assert_eq!(ret, 0);
        t.sys_munmap(a as u64, 0x2000);
    }

    #[test]
    fn brk_refuses_above_2gb() {
        let mut t = TestVm::new();
        // Try to set brk above 2GB
        let cur = t.sys_brk(0);
        let ret = t.sys_brk(0x8000_0001);
        // Should refuse and return current brk
        assert_eq!(ret, cur, "brk should refuse addresses above 2GB");
    }

    #[test]
    fn mmap_rejects_invalid_fd_for_file_backed() {
        let mut t = TestVm::new();
        // Non-anonymous with fd=-1 should fail
        let ret = t.sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, -1, 0);
        assert_eq!(
            ret, EBADF as i64,
            "mmap with !MAP_ANONYMOUS and fd=-1 should return EBADF"
        );
    }

    #[test]
    fn prot_none_reservation_does_not_grow_linear_memory() {
        let mut t = TestVm::new();
        let before = core::arch::wasm32::memory_size(0);
        let addr = t.sys_mmap(0, 128 * 1024 * 1024, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        let after = core::arch::wasm32::memory_size(0);

        assert!(addr > 0);
        assert_eq!(before, after);
        assert!(super::has_prot_none());
    }

    #[test]
    fn prot_none_reservation_keeps_rw_mmaps_low() {
        let mut t = TestVm::new();

        let reserve =
            t.sys_mmap(0, 512 * 1024 * 1024, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        assert!(reserve > 0);

        let mapped = t.sys_mmap(
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0,
        );
        assert!(mapped > 0);
        assert!(
            (mapped as u64) < reserve as u64,
            "RW mapping should stay below high PROT_NONE reservation: reserve=0x{:x} mapped=0x{:x}",
            reserve,
            mapped,
        );
    }

    #[test]
    fn failed_hint_probe_reuses_low_hole_after_munmap() {
        let mut t = TestVm::new();
        let bad_hint = 0x9000_0000;
        let len = 64 * 1024 * 1024;

        let first = t.sys_mmap(bad_hint, len, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        assert!(first > 0);
        assert_eq!(t.sys_munmap(first as u64, len), 0);

        let second = t.sys_mmap(bad_hint, len, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        assert_eq!(second, first);
    }

    #[test]
    fn mmap_stays_above_expanded_brk_region() {
        let mut t = TestVm::new();
        let grown = t.sys_brk(0x40_0000);
        assert_eq!(grown, 0x40_0000);

        let mapped = t.sys_mmap(
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0,
        );
        assert!(mapped > 0);

        let floor = (((grown as u64) + 0x1F_FFFF) & !0x1F_FFFF).max(0x20_0000);
        assert!(
            (mapped as u64) >= floor,
            "mmap should stay above current brk floor: brk=0x{:x} floor=0x{:x} mapped=0x{:x}",
            grown,
            floor,
            mapped,
        );
    }

    #[test]
    fn initial_stack_maps_guard_and_writable_stack() {
        let t = TestVm::new();
        let guest_limit = 0x80_0000;
        let stack_top = super::map_initial_stack(t.base, guest_limit, 1024 * 1024);
        assert_eq!(stack_top, (guest_limit - PAGE_SIZE) as i64);

        let guard_addr = guest_limit - 1024 * 1024 - PAGE_SIZE / 2;
        let stack_addr = guest_limit - PAGE_SIZE - 64;
        assert!(super::is_prot_none(guard_addr));
        assert!(!super::is_prot_none(stack_addr));

        unsafe {
            crate::guest_mem::write_u64(t.base, stack_addr, 0xDEAD_BEEF_CAFE_BABEu64);
            assert_eq!(
                crate::guest_mem::read_u64(t.base, stack_addr),
                0xDEAD_BEEF_CAFE_BABEu64
            );
        }
    }
}
