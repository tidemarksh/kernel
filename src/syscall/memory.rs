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
//!     fd:     i32,                      // offset 24  — file-backed OFD id, -1 = anonymous
//!     _pad:   i32,                      // offset 28
//!     offset: u64,                      // offset 32  — file offset for file-backed mmap
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/linux/mm_types.h

use crate::abi::*;
use crate::alloc;
use crate::fs::{memfs, fd_table};
use crate::guest_mem;
use crate::types::{ThreadState, Vma};

const MAX_VMAS: usize = MAX_MMAP_REGIONS;

/// Memory management state, allocated in kernel Worker linear memory.
#[repr(C)]
struct MemState {
    vma_table: [Vma; MAX_VMAS],
    vma_count: u32,
    _pad0: u32,
    brk_base: u64,
    brk_current: u64,
    mmap_next: u64,
    has_prot_none: u32,
}

/// Pointer to MemState in WASM linear memory.
static mut MEM_STATE: *mut MemState = core::ptr::null_mut();

fn ms() -> &'static mut MemState {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(MEM_STATE));
        &mut *p
    }
}

/// Initialize memory state. Allocates MemState via alloc.rs.
pub fn init(brk_start: u64) {
    unsafe {
        let ptr = alloc::alloc_zeroed(
            core::mem::size_of::<MemState>() as u32,
            core::mem::align_of::<MemState>() as u32,
        );
        if ptr == 0 { core::arch::wasm32::unreachable(); }
        core::ptr::write(core::ptr::addr_of_mut!(MEM_STATE), ptr as *mut MemState);
    }
    let s = ms();
    s.brk_base = brk_start;
    s.brk_current = brk_start;
    s.mmap_next = 0x4000_0000;
    s.has_prot_none = 0;
    s.vma_count = 0;
}

pub fn has_prot_none() -> bool {
    ms().has_prot_none != 0
}

pub fn is_prot_none(addr: u64) -> bool {
    let s = ms();
    let count = s.vma_count as usize;
    for i in 0..count {
        let v = &s.vma_table[i];
        if addr >= v.start && addr < v.end && v.prot == PROT_NONE {
            return true;
        }
    }
    false
}

// =========================================================================
// brk
// =========================================================================

/// brk: adjust program break. addr=0 returns current break.
/// Grows WASM memory via memory.grow if needed, zero-fills new region.
pub fn sys_brk(_vm: &mut ThreadState, _base: u32, addr: u64) -> i64 {
    let s = ms();
    if addr == 0 {
        return s.brk_current as i64;
    }
    if addr < s.brk_base {
        return s.brk_current as i64;
    }

    // Ensure WASM memory is large enough
    unsafe {
        let needed = addr as u32;
        let mem_size = core::arch::wasm32::memory_size(0) as u32 * 65536;
        if needed > mem_size {
            let pages = ((needed - mem_size) + 65535) / 65536;
            if core::arch::wasm32::memory_grow(0, pages as usize) == usize::MAX {
                return s.brk_current as i64;
            }
        }

        // Zero new region if growing
        if addr > s.brk_current {
            guest_mem::zero_mem(0, s.brk_current, (addr - s.brk_current) as usize);
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
    _vm: &mut ThreadState, _base: u32,
    addr: u64, length: u64, prot: u64, flags: u64, fd: i64, offset: u64,
) -> i64 {
    let s = ms();
    if length == 0 { return EINVAL; }
    let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let is_fixed = (flags & MAP_FIXED) != 0;
    let is_anon = (flags & MAP_ANONYMOUS) != 0;

    let start = if is_fixed {
        if addr & (PAGE_SIZE - 1) != 0 { return EINVAL; }
        remove_overlap(s, addr, addr + len);
        addr
    } else if addr != 0 && !overlaps(s, addr, addr + len) {
        addr
    } else {
        let hole = find_hole(s, len);
        if hole == 0 { return ENOMEM; }
        hole
    };

    // Ensure WASM memory covers the mapped region
    unsafe {
        let needed = (start + len) as u32;
        let mem_size = core::arch::wasm32::memory_size(0) as u32 * 65536;
        if needed > mem_size {
            let pages = ((needed - mem_size) + 65535) / 65536;
            if core::arch::wasm32::memory_grow(0, pages as usize) == usize::MAX {
                return ENOMEM;
            }
        }
    }

    if is_anon {
        unsafe { guest_mem::zero_mem(0, start, len as usize); }
    } else if fd >= 0 {
        // File-backed mmap (MAP_PRIVATE): eager populate from MemFS.
        // Read file content into guest memory, zero-fill beyond EOF.
        // WASM has no page fault / demand paging, so populate eagerly.
        unsafe { guest_mem::zero_mem(0, start, len as usize); }
        let ofd = fd_table::get_ofd_by_id(fd as u32);
        if let Some(ofd) = ofd {
            let st = memfs::stat(ofd.ino as u32);
            if let Some(st) = st {
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
                            ofd.ino as u32,
                            copy_start + off as u64,
                            &mut tmp[..chunk],
                        );
                        if n <= 0 { break; }
                        unsafe { guest_mem::write_bytes(0, start + off as u64, &tmp[..n as usize]); }
                        off += n as usize;
                    }
                }
            }
        }
    }

    let count = s.vma_count as usize;
    if count >= MAX_VMAS { return ENOMEM; }
    s.vma_table[count] = Vma {
        start,
        end: start + len,
        prot: prot as i32,
        flags: flags as i32,
        fd: if is_anon { -1 } else { fd as i32 },
        _pad: 0,
        offset,
    };
    s.vma_count += 1;
    sort_vmas(s);

    if prot as i32 == PROT_NONE { s.has_prot_none = 1; }

    start as i64
}

// =========================================================================
// munmap
// =========================================================================

/// munmap: unmap pages. Removes matching VMAs and recomputes PROT_NONE flag.
pub fn sys_munmap(_vm: &mut ThreadState, _base: u32, addr: u64, length: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 { return EINVAL; }
    let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let s = ms();
    remove_overlap(s, addr, addr + len);
    recompute_prot_none(s);
    0
}

// =========================================================================
// mremap
// =========================================================================

/// mremap: resize or relocate an existing mapping.
/// Shrink in-place, grow in-place if adjacent space is free, or relocate.
pub fn sys_mremap(
    _vm: &mut ThreadState, _base: u32,
    old_addr: u64, old_size: u64, new_size: u64, _flags: u64, _new_addr: u64,
) -> i64 {
    let s = ms();
    let old_len = (old_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let new_len = (new_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let idx = match find_vma_containing(s, old_addr) {
        Some(i) => i,
        None => return EINVAL,
    };

    if new_len <= old_len {
        s.vma_table[idx].end = old_addr + new_len;
        return old_addr as i64;
    }

    let grow_end = old_addr + new_len;
    if !overlaps_except(s, old_addr + old_len, grow_end, idx) {
        unsafe {
            let needed = grow_end as u32;
            let mem_size = core::arch::wasm32::memory_size(0) as u32 * 65536;
            if needed > mem_size {
                let pages = ((needed - mem_size) + 65535) / 65536;
                if core::arch::wasm32::memory_grow(0, pages as usize) == usize::MAX {
                    return ENOMEM;
                }
            }
            guest_mem::zero_mem(0, old_addr + old_len, (new_len - old_len) as usize);
        }
        s.vma_table[idx].end = grow_end;
        return old_addr as i64;
    }

    let new_start = find_hole(s, new_len);
    if new_start == 0 { return ENOMEM; }

    unsafe {
        let needed = (new_start + new_len) as u32;
        let mem_size = core::arch::wasm32::memory_size(0) as u32 * 65536;
        if needed > mem_size {
            let pages = ((needed - mem_size) + 65535) / 65536;
            if core::arch::wasm32::memory_grow(0, pages as usize) == usize::MAX {
                return ENOMEM;
            }
        }
        let src = old_addr as u32 as *const u8;
        let dst = new_start as u32 as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, old_len as usize);
        guest_mem::zero_mem(0, new_start + old_len, (new_len - old_len) as usize);
    }

    s.vma_table[idx].start = new_start;
    s.vma_table[idx].end = new_start + new_len;
    sort_vmas(s);
    new_start as i64
}

// =========================================================================
// mprotect
// =========================================================================

/// mprotect: change VMA protection flags. Splits VMAs at boundaries if needed.
/// Sets has_prot_none flag for SIGSEGV detection.
pub fn sys_mprotect(_vm: &mut ThreadState, _base: u32, addr: u64, length: u64, prot: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 { return EINVAL; }
    let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end = addr + len;
    let s = ms();

    let mut i = 0;
    while i < s.vma_count as usize {
        let v = s.vma_table[i];
        if v.end <= addr || v.start >= end { i += 1; continue; }

        if v.start < addr {
            let count = s.vma_count as usize;
            if count >= MAX_VMAS { return ENOMEM; }
            s.vma_table[count] = Vma { start: v.start, end: addr, ..v };
            s.vma_count += 1;
            s.vma_table[i].start = addr;
        }
        if v.end > end {
            let count = s.vma_count as usize;
            if count >= MAX_VMAS { return ENOMEM; }
            s.vma_table[count] = Vma { start: end, end: v.end, ..s.vma_table[i] };
            s.vma_count += 1;
            s.vma_table[i].end = end;
        }
        s.vma_table[i].prot = prot as i32;
        i += 1;
    }

    sort_vmas(s);
    recompute_prot_none(s);
    0
}

// =========================================================================
// VMA table helpers
// =========================================================================

fn find_hole(s: &mut MemState, len: u64) -> u64 {
    let mut candidate = s.mmap_next;
    loop {
        if candidate + len > 0x8000_0000 { return 0; }
        if !overlaps(s, candidate, candidate + len) {
            s.mmap_next = candidate + len;
            return candidate;
        }
        let count = s.vma_count as usize;
        for i in 0..count {
            let v = &s.vma_table[i];
            if v.start < candidate + len && v.end > candidate {
                candidate = (v.end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                break;
            }
        }
    }
}

fn overlaps(s: &MemState, start: u64, end: u64) -> bool {
    let count = s.vma_count as usize;
    for i in 0..count {
        let v = &s.vma_table[i];
        if v.start < end && v.end > start { return true; }
    }
    false
}

fn overlaps_except(s: &MemState, start: u64, end: u64, except: usize) -> bool {
    let count = s.vma_count as usize;
    for i in 0..count {
        if i == except { continue; }
        let v = &s.vma_table[i];
        if v.start < end && v.end > start { return true; }
    }
    false
}

fn remove_overlap(s: &mut MemState, start: u64, end: u64) {
    let mut i = 0;
    while i < s.vma_count as usize {
        let v = s.vma_table[i];
        if v.start >= end || v.end <= start { i += 1; continue; }

        if v.start >= start && v.end <= end {
            let last = s.vma_count as usize - 1;
            s.vma_table[i] = s.vma_table[last];
            s.vma_count -= 1;
            continue;
        }
        if v.start < start && v.end > end {
            let count = s.vma_count as usize;
            if count < MAX_VMAS {
                s.vma_table[count] = Vma { start: end, end: v.end, ..v };
                s.vma_count += 1;
            }
            s.vma_table[i].end = start;
            i += 1;
            continue;
        }
        if v.start < start {
            s.vma_table[i].end = start;
        } else {
            s.vma_table[i].start = end;
        }
        i += 1;
    }
    sort_vmas(s);
}

fn find_vma_containing(s: &MemState, addr: u64) -> Option<usize> {
    let count = s.vma_count as usize;
    for i in 0..count {
        let v = &s.vma_table[i];
        if addr >= v.start && addr < v.end { return Some(i); }
    }
    None
}

fn sort_vmas(s: &mut MemState) {
    let count = s.vma_count as usize;
    for i in 1..count {
        let key = s.vma_table[i];
        let mut j = i;
        while j > 0 && s.vma_table[j - 1].start > key.start {
            s.vma_table[j] = s.vma_table[j - 1];
            j -= 1;
        }
        s.vma_table[j] = key;
    }
}

fn recompute_prot_none(s: &mut MemState) {
    s.has_prot_none = 0;
    let count = s.vma_count as usize;
    for i in 0..count {
        if s.vma_table[i].prot == PROT_NONE {
            s.has_prot_none = 1;
            return;
        }
    }
}
