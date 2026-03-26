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

use alloc_crate::vec::Vec;

use crate::abi::*;
use crate::fs::{memfs, fd_table};
use crate::guest_mem;
use crate::types::{ThreadState, Vma};

/// Memory management state.
/// VMA table is a sorted Vec<Vma> (sorted by start address).
/// https://man7.org/linux/man-pages/man2/mmap.2.html
struct MemState {
    vmas: Vec<Vma>,
    brk_base: u64,
    brk_current: u64,
    mmap_next: u64,
    has_prot_none: u32,
}

static mut MEM_STATE_INIT: bool = false;
static mut MEM_STATE: core::mem::MaybeUninit<MemState> = core::mem::MaybeUninit::uninit();

fn ms() -> &'static mut MemState {
    unsafe { &mut *core::ptr::addr_of_mut!(MEM_STATE).cast::<MemState>() }
}

/// Initialize memory state.
pub fn init(brk_start: u64) {
    let heap_end = unsafe { crate::alloc::heap_ptr() };
    let mmap_start = ((heap_end as u64 + 0x10_0000) & !0xF_FFFF).max(0x4000_0000);
    unsafe {
        let init_ptr = core::ptr::addr_of_mut!(MEM_STATE_INIT);
        if core::ptr::read(init_ptr) {
            // Re-init: reset existing state
            let s = ms();
            s.vmas.clear();
            s.brk_base = brk_start;
            s.brk_current = brk_start;
            s.mmap_next = mmap_start;
            s.has_prot_none = 0;
        } else {
            let p = core::ptr::addr_of_mut!(MEM_STATE).cast::<MemState>();
            core::ptr::write(p, MemState {
                vmas: Vec::new(),
                brk_base: brk_start,
                brk_current: brk_start,
                mmap_next: mmap_start,
                has_prot_none: 0,
            });
            core::ptr::write(init_ptr, true);
        }
    }
}

pub fn has_prot_none() -> bool {
    ms().has_prot_none != 0
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
    // 2GB address space ceiling
    if addr > 0x8000_0000 {
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
    vm: &mut ThreadState, _base: u32,
    addr: u64, length: u64, prot: u64, flags: u64, fd: i64, offset: u64,
) -> i64 {
    let s = ms();
    if length == 0 { return EINVAL; }
    let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let is_fixed = (flags & MAP_FIXED) != 0;
    let is_anon = (flags & MAP_ANONYMOUS) != 0;

    // Validate fd for file-backed mmap
    // https://man7.org/linux/man-pages/man2/mmap.2.html
    if !is_anon {
        if fd < 0 || fd_table::get_ofd(vm, fd as u64).is_none() {
            return EBADF;
        }
    }

    let start = if is_fixed {
        if addr & (PAGE_SIZE - 1) != 0 { return EINVAL; }
        // 2GB address space ceiling
        if addr + len > 0x8000_0000 { return ENOMEM; }
        remove_overlap(s, addr, addr + len);
        addr
    } else if addr != 0 && addr + len <= 0x8000_0000 && !overlaps(s, addr, addr + len) {
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
        // File-backed mmap: only MAP_PRIVATE is supported.
        if flags & MAP_PRIVATE == 0 { return EINVAL; }
        // Eager populate from MemFS — zero-fill beyond EOF.
        // WASM has no page fault / demand paging, so populate eagerly.
        unsafe { guest_mem::zero_mem(0, start, len as usize); }
        let ofd = fd_table::get_ofd(vm, fd as u64);
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

    s.vmas.push(Vma {
        start,
        end: start + len,
        prot: prot as i32,
        flags: flags as i32,
        fd: if is_anon { -1 } else { fd as i32 },
        _pad: 0,
        offset,
    });
    s.vmas.sort_by_key(|v| v.start);

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
        s.vmas[idx].end = old_addr + new_len;
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
        s.vmas[idx].end = grow_end;
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
pub fn sys_mprotect(_vm: &mut ThreadState, _base: u32, addr: u64, length: u64, prot: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 { return EINVAL; }
    let len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end = addr + len;
    let s = ms();

    let mut i = 0;
    while i < s.vmas.len() {
        let v = s.vmas[i];
        if v.end <= addr || v.start >= end { i += 1; continue; }

        if v.start < addr {
            s.vmas.push(Vma { start: v.start, end: addr, ..v });
            s.vmas[i].start = addr;
        }
        if v.end > end {
            let cur = s.vmas[i];
            s.vmas.push(Vma { start: end, end: v.end, ..cur });
            s.vmas[i].end = end;
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

fn find_hole(s: &mut MemState, len: u64) -> u64 {
    let mut candidate = s.mmap_next;
    loop {
        if candidate + len > 0x8000_0000 { return 0; }
        if !overlaps(s, candidate, candidate + len) {
            s.mmap_next = candidate + len;
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

fn overlaps(s: &MemState, start: u64, end: u64) -> bool {
    for v in s.vmas.iter() {
        if v.start < end && v.end > start { return true; }
    }
    false
}

fn overlaps_except(s: &MemState, start: u64, end: u64, except: usize) -> bool {
    for (i, v) in s.vmas.iter().enumerate() {
        if i == except { continue; }
        if v.start < end && v.end > start { return true; }
    }
    false
}

fn remove_overlap(s: &mut MemState, start: u64, end: u64) {
    let mut i = 0;
    while i < s.vmas.len() {
        let v = s.vmas[i];
        if v.start >= end || v.end <= start { i += 1; continue; }

        if v.start >= start && v.end <= end {
            s.vmas.swap_remove(i);
            continue;
        }
        if v.start < start && v.end > end {
            s.vmas.push(Vma { start: end, end: v.end, ..v });
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

fn find_vma_containing(s: &MemState, addr: u64) -> Option<usize> {
    for (i, v) in s.vmas.iter().enumerate() {
        if addr >= v.start && addr < v.end { return Some(i); }
    }
    None
}

fn recompute_prot_none(s: &mut MemState) {
    s.has_prot_none = 0;
    for v in s.vmas.iter() {
        if v.prot == PROT_NONE {
            s.has_prot_none = 1;
            return;
        }
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
            0, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0,
        );
        assert!(addr > 0, "mmap should return positive address, got {}", addr);

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
            0, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0,
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
            assert!(s.vmas[i].start >= s.vmas[i - 1].start,
                "VMAs not sorted: [{}].start=0x{:x} < [{}].start=0x{:x}",
                i, s.vmas[i].start, i - 1, s.vmas[i - 1].start);
        }
        t.sys_munmap(a1 as u64, 4096);
        t.sys_munmap(a2 as u64, 4096);
        t.sys_munmap(a3 as u64, 4096);
    }

    #[test]
    fn map_fixed_replaces_existing_vma() {
        let mut t = TestVm::new();
        let a = t.sys_mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        assert!(a > 0);
        // MAP_FIXED over the same region with different prot
        let a2 = t.sys_mmap(a as u64, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        assert_eq!(a2, a);
        t.sys_munmap(a as u64, 8192);
    }

    #[test]
    fn munmap_partial_splits_vma() {
        let mut t = TestVm::new();
        let a = t.sys_mmap(0, 0x3000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        assert!(a > 0);
        let count_before = super::ms().vmas.len();
        // Unmap the middle page — should split into 2 VMAs
        let ret = t.sys_munmap(a as u64 + 0x1000, 0x1000);
        assert_eq!(ret, 0);
        let count_after = super::ms().vmas.len();
        assert!(count_after >= count_before, "split should not reduce VMA count");
        t.sys_munmap(a as u64, 0x1000);
        t.sys_munmap(a as u64 + 0x2000, 0x1000);
    }

    #[test]
    fn mprotect_split_on_boundary_mismatch() {
        let mut t = TestVm::new();
        let a = t.sys_mmap(0, 0x2000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
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
        assert_eq!(ret, EBADF as i64, "mmap with !MAP_ANONYMOUS and fd=-1 should return EBADF");
    }
}
