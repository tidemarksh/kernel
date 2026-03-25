//! Memory syscalls: brk, mmap, munmap, mremap, mprotect.
//!
//! VMA table is a sorted array of Vma entries stored in kernel Worker memory.
//! For the current single-process model (single-process, no kernel Worker yet), we store VMA state in
//! static memory and operate directly.

use crate::abi::*;
use crate::guest_mem;
use crate::types::{ThreadState, Vma};

const MAX_VMAS: usize = MAX_MMAP_REGIONS;

/// Per-process VMA state. Static for the current single-process model (single process).
/// Will move to kernel Worker's linear memory in the kernel Worker model.
static mut VMA_TABLE: [Vma; MAX_VMAS] = [Vma {
    start: 0, end: 0, prot: 0, flags: 0, fd: -1, _pad: 0, offset: 0,
}; MAX_VMAS];
static mut VMA_COUNT: usize = 0;
static mut BRK_CURRENT: u64 = 0;
static mut BRK_BASE: u64 = 0;
static mut MMAP_NEXT: u64 = 0x4000_0000; // mmap region starts at 1GB
static mut HAS_PROT_NONE: bool = false;

/// Initialize memory state after ELF load.
pub fn init(brk_start: u64) {
    unsafe {
        BRK_BASE = brk_start;
        BRK_CURRENT = brk_start;
        VMA_COUNT = 0;
        MMAP_NEXT = 0x4000_0000;
        HAS_PROT_NONE = false;
    }
}

/// Check if any PROT_NONE VMA exists (for interpreter guard check).
pub fn has_prot_none() -> bool {
    unsafe { HAS_PROT_NONE }
}

/// Check if an address falls in a PROT_NONE region.
pub fn is_prot_none(addr: u64) -> bool {
    unsafe {
        for i in 0..VMA_COUNT {
            let v = &VMA_TABLE[i];
            if addr >= v.start && addr < v.end && v.prot == PROT_NONE {
                return true;
            }
        }
        false
    }
}

// =========================================================================
// brk
// =========================================================================

pub fn sys_brk(_vm: &mut ThreadState, _base: u32, addr: u64) -> i64 {
    unsafe {
        if addr == 0 {
            return BRK_CURRENT as i64;
        }
        if addr < BRK_BASE {
            return BRK_CURRENT as i64;
        }

        // Ensure WASM memory is large enough
        let needed = addr as u32;
        let mem_size = core::arch::wasm32::memory_size(0) as u32 * 65536;
        if needed > mem_size {
            let pages = ((needed - mem_size) + 65535) / 65536;
            let result = core::arch::wasm32::memory_grow(0, pages as usize);
            if result == usize::MAX {
                return BRK_CURRENT as i64; // OOM: return current brk
            }
        }

        // Zero new region if growing
        if addr > BRK_CURRENT {
            guest_mem::zero_mem(0, BRK_CURRENT, (addr - BRK_CURRENT) as usize);
        }

        BRK_CURRENT = addr;
        addr as i64
    }
}

// =========================================================================
// mmap
// =========================================================================

pub fn sys_mmap(
    _vm: &mut ThreadState, _base: u32,
    addr: u64, length: u64, prot: u64, flags: u64, fd: i64, offset: u64,
) -> i64 {
    unsafe {
        if length == 0 { return EINVAL; }
        let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1); // page-align

        let is_fixed = (flags & MAP_FIXED) != 0;
        let is_anon = (flags & MAP_ANONYMOUS) != 0;

        // Find or assign address
        let start = if is_fixed {
            if addr & (PAGE_SIZE - 1) != 0 { return EINVAL; }
            // Remove overlapping VMAs
            remove_overlap(addr, addr + len);
            addr
        } else if addr != 0 && !overlaps(addr, addr + len) {
            addr
        } else {
            let s = find_hole(len);
            if s == 0 { return ENOMEM; }
            s
        };

        // Ensure WASM memory covers the mapped region
        let needed = (start + len) as u32;
        let mem_size = core::arch::wasm32::memory_size(0) as u32 * 65536;
        if needed > mem_size {
            let pages = ((needed - mem_size) + 65535) / 65536;
            if core::arch::wasm32::memory_grow(0, pages as usize) == usize::MAX {
                return ENOMEM;
            }
        }

        // Zero anonymous mapping
        if is_anon {
            guest_mem::zero_mem(0, start, len as usize);
        }

        // Insert VMA
        if VMA_COUNT >= MAX_VMAS { return ENOMEM; }
        VMA_TABLE[VMA_COUNT] = Vma {
            start,
            end: start + len,
            prot: prot as i32,
            flags: flags as i32,
            fd: if is_anon { -1 } else { fd as i32 },
            _pad: 0,
            offset,
        };
        VMA_COUNT += 1;
        sort_vmas();

        if prot as i32 == PROT_NONE { HAS_PROT_NONE = true; }

        start as i64
    }
}

// =========================================================================
// munmap
// =========================================================================

pub fn sys_munmap(_vm: &mut ThreadState, _base: u32, addr: u64, length: u64) -> i64 {
    unsafe {
        if addr & (PAGE_SIZE - 1) != 0 { return EINVAL; }
        let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        remove_overlap(addr, addr + len);
        recompute_prot_none();
        0
    }
}

// =========================================================================
// mremap
// =========================================================================

pub fn sys_mremap(
    _vm: &mut ThreadState, _base: u32,
    old_addr: u64, old_size: u64, new_size: u64, _flags: u64, _new_addr: u64,
) -> i64 {
    unsafe {
        let old_len = (old_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let new_len = (new_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Find the VMA
        let idx = match find_vma_containing(old_addr) {
            Some(i) => i,
            None => return EINVAL,
        };

        if new_len <= old_len {
            // Shrink: just update end
            VMA_TABLE[idx].end = old_addr + new_len;
            return old_addr as i64;
        }

        // Grow: check if space after is free
        let grow_end = old_addr + new_len;
        if !overlaps_except(old_addr + old_len, grow_end, idx) {
            // Ensure memory
            let needed = grow_end as u32;
            let mem_size = core::arch::wasm32::memory_size(0) as u32 * 65536;
            if needed > mem_size {
                let pages = ((needed - mem_size) + 65535) / 65536;
                if core::arch::wasm32::memory_grow(0, pages as usize) == usize::MAX {
                    return ENOMEM;
                }
            }
            guest_mem::zero_mem(0, old_addr + old_len, (new_len - old_len) as usize);
            VMA_TABLE[idx].end = grow_end;
            return old_addr as i64;
        }

        // Need to move: allocate new region, copy, unmap old
        let new_start = find_hole(new_len);
        if new_start == 0 { return ENOMEM; }

        let needed = (new_start + new_len) as u32;
        let mem_size = core::arch::wasm32::memory_size(0) as u32 * 65536;
        if needed > mem_size {
            let pages = ((needed - mem_size) + 65535) / 65536;
            if core::arch::wasm32::memory_grow(0, pages as usize) == usize::MAX {
                return ENOMEM;
            }
        }

        // Copy old data
        let src = old_addr as u32 as *const u8;
        let dst = new_start as u32 as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, old_len as usize);
        guest_mem::zero_mem(0, new_start + old_len, (new_len - old_len) as usize);

        // Update VMA
        VMA_TABLE[idx].start = new_start;
        VMA_TABLE[idx].end = new_start + new_len;
        sort_vmas();

        new_start as i64
    }
}

// =========================================================================
// mprotect
// =========================================================================

pub fn sys_mprotect(_vm: &mut ThreadState, _base: u32, addr: u64, length: u64, prot: u64) -> i64 {
    unsafe {
        if addr & (PAGE_SIZE - 1) != 0 { return EINVAL; }
        let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let end = addr + len;

        // Update prot for all overlapping VMAs (split if needed)
        let mut i = 0;
        while i < VMA_COUNT {
            let v = VMA_TABLE[i];
            if v.end <= addr || v.start >= end { i += 1; continue; }

            if v.start < addr {
                // Split: left part keeps old prot
                if VMA_COUNT >= MAX_VMAS { return ENOMEM; }
                VMA_TABLE[VMA_COUNT] = Vma { start: v.start, end: addr, ..v };
                VMA_COUNT += 1;
                VMA_TABLE[i].start = addr;
            }
            if v.end > end {
                // Split: right part keeps old prot
                if VMA_COUNT >= MAX_VMAS { return ENOMEM; }
                VMA_TABLE[VMA_COUNT] = Vma { start: end, end: v.end, ..VMA_TABLE[i] };
                VMA_COUNT += 1;
                VMA_TABLE[i].end = end;
            }
            VMA_TABLE[i].prot = prot as i32;
            i += 1;
        }

        sort_vmas();
        recompute_prot_none();
        0
    }
}

// =========================================================================
// VMA table helpers
// =========================================================================

unsafe fn find_hole(len: u64) -> u64 {
    let mut candidate = MMAP_NEXT;
    // Simple linear scan for a gap
    loop {
        if candidate + len > 0x8000_0000 { return 0; } // 2GB limit
        if !overlaps(candidate, candidate + len) {
            MMAP_NEXT = candidate + len;
            return candidate;
        }
        // Skip past the overlapping VMA
        for i in 0..VMA_COUNT {
            let v = &VMA_TABLE[i];
            if v.start < candidate + len && v.end > candidate {
                candidate = (v.end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                break;
            }
        }
    }
}

unsafe fn overlaps(start: u64, end: u64) -> bool {
    for i in 0..VMA_COUNT {
        let v = &VMA_TABLE[i];
        if v.start < end && v.end > start { return true; }
    }
    false
}

unsafe fn overlaps_except(start: u64, end: u64, except: usize) -> bool {
    for i in 0..VMA_COUNT {
        if i == except { continue; }
        let v = &VMA_TABLE[i];
        if v.start < end && v.end > start { return true; }
    }
    false
}

unsafe fn remove_overlap(start: u64, end: u64) {
    let mut i = 0;
    while i < VMA_COUNT {
        let v = VMA_TABLE[i];
        if v.start >= end || v.end <= start { i += 1; continue; }

        if v.start >= start && v.end <= end {
            // Fully contained: remove
            VMA_TABLE[i] = VMA_TABLE[VMA_COUNT - 1];
            VMA_COUNT -= 1;
            continue; // don't increment, re-check swapped entry
        }
        if v.start < start && v.end > end {
            // Hole punch: split into two
            if VMA_COUNT < MAX_VMAS {
                VMA_TABLE[VMA_COUNT] = Vma { start: end, end: v.end, ..v };
                VMA_COUNT += 1;
            }
            VMA_TABLE[i].end = start;
            i += 1;
            continue;
        }
        if v.start < start {
            VMA_TABLE[i].end = start; // Trim right
        } else {
            VMA_TABLE[i].start = end; // Trim left
        }
        i += 1;
    }
    sort_vmas();
}

unsafe fn find_vma_containing(addr: u64) -> Option<usize> {
    for i in 0..VMA_COUNT {
        let v = &VMA_TABLE[i];
        if addr >= v.start && addr < v.end { return Some(i); }
    }
    None
}

unsafe fn sort_vmas() {
    // Insertion sort (small array, mostly sorted)
    for i in 1..VMA_COUNT {
        let key = VMA_TABLE[i];
        let mut j = i;
        while j > 0 && VMA_TABLE[j - 1].start > key.start {
            VMA_TABLE[j] = VMA_TABLE[j - 1];
            j -= 1;
        }
        VMA_TABLE[j] = key;
    }
}

unsafe fn recompute_prot_none() {
    HAS_PROT_NONE = false;
    for i in 0..VMA_COUNT {
        if VMA_TABLE[i].prot == PROT_NONE {
            HAS_PROT_NONE = true;
            return;
        }
    }
}
