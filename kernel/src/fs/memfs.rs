//! In-memory filesystem (MemFS).
//!
//! All data structures are allocated in kernel Worker's WASM linear memory
//! via alloc.rs. Designed for later migration to SAB page cache where
//! thread-workers can read without kernel Worker round-trip.
//!
//! Struct layout (RV64):
//!
//! struct stat {                         // 128 bytes total
//!     st_dev:       u64,                // offset 0
//!     st_ino:       u64,                // offset 8
//!     st_mode:      u32,                // offset 16
//!     st_nlink:     u32,                // offset 20
//!     st_uid:       u32,                // offset 24
//!     st_gid:       u32,                // offset 28
//!     st_rdev:      u64,                // offset 32
//!     __pad1:       u64,                // offset 40
//!     st_size:      i64,                // offset 48
//!     st_blksize:   i32,                // offset 56
//!     __pad2:       i32,                // offset 60
//!     st_blocks:    i64,                // offset 64
//!     st_atime:     i64,                // offset 72
//!     st_atime_nsec:u64,                // offset 80
//!     st_mtime:     i64,                // offset 88
//!     st_mtime_nsec:u64,                // offset 96
//!     st_ctime:     i64,                // offset 104
//!     st_ctime_nsec:u64,                // offset 112
//!     __unused4:    u32,                // offset 120
//!     __unused5:    u32,                // offset 124
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/stat.h

use crate::abi::*;
use crate::alloc;
#[cfg(all(
    not(all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        target_os = "unknown"
    )),
    any(test, feature = "harness")
))]
use alloc_crate::vec::Vec;

#[repr(C)]
struct PageCacheMeta {
    mode: u32,
    _pad: u32,
    size: u64,
}

#[cfg(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
))]
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn tidemark_page_cache_read(ino: u32, offset: u64, dst_ptr: usize, dst_len: u32) -> i64;
    fn tidemark_page_cache_stat(ino: u32, out_ptr: usize) -> i32;
    fn tidemark_page_cache_set_mode(ino: u32, mode: u32) -> i32;
    fn tidemark_page_cache_flush(ino: u32) -> i32;
    fn tidemark_page_cache_truncate(ino: u32, size: u64) -> i32;
    fn tidemark_page_cache_write(ino: u32, offset: u64, src_ptr: usize, src_len: u32) -> i64;
}

#[cfg(all(
    not(all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        target_os = "unknown"
    )),
    any(test, feature = "harness")
))]
struct HarnessPageCacheEntry {
    ino: u32,
    mode: u32,
    data: Vec<u8>,
}

#[cfg(all(
    not(all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        target_os = "unknown"
    )),
    any(test, feature = "harness")
))]
static mut HARNESS_PAGE_CACHE: Option<Vec<HarnessPageCacheEntry>> = None;

#[cfg(all(
    not(all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        target_os = "unknown"
    )),
    any(test, feature = "harness")
))]
static mut HARNESS_PAGE_CACHE_ENABLED: bool = false;

#[cfg(all(
    not(all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        target_os = "unknown"
    )),
    any(test, feature = "harness")
))]
pub fn enable_harness_page_cache() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(HARNESS_PAGE_CACHE_ENABLED), true);
        let entries = core::ptr::addr_of_mut!(HARNESS_PAGE_CACHE);
        if (*entries).is_none() {
            *entries = Some(Vec::new());
        }
        if let Some(entries) = (*entries).as_mut() {
            entries.clear();
        }
    }
}

#[cfg(all(
    not(all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        target_os = "unknown"
    )),
    any(test, feature = "harness")
))]
fn harness_page_cache_entries() -> Option<&'static mut Vec<HarnessPageCacheEntry>> {
    unsafe {
        if !core::ptr::read(core::ptr::addr_of!(HARNESS_PAGE_CACHE_ENABLED)) {
            return None;
        }
        let entries = core::ptr::addr_of_mut!(HARNESS_PAGE_CACHE);
        if (*entries).is_none() {
            *entries = Some(Vec::new());
        }
        (*entries).as_mut()
    }
}

#[cfg(all(
    not(all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        target_os = "unknown"
    )),
    any(test, feature = "harness")
))]
fn reset_harness_page_cache() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(HARNESS_PAGE_CACHE_ENABLED), false);
        let entries = core::ptr::addr_of_mut!(HARNESS_PAGE_CACHE);
        if let Some(entries) = (*entries).as_mut() {
            entries.clear();
        }
    }
}

#[cfg(not(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
)))]
unsafe fn tidemark_page_cache_read(ino: u32, offset: u64, dst_ptr: usize, dst_len: u32) -> i64 {
    #[cfg(any(test, feature = "harness"))]
    let Some(entries) = harness_page_cache_entries() else {
        return 0;
    };
    #[cfg(any(test, feature = "harness"))]
    {
        let Some(entry) = entries.iter_mut().find(|entry| entry.ino == ino) else {
            return 0;
        };
        let offset = offset as usize;
        if offset >= entry.data.len() {
            return 0;
        }
        let len = (dst_len as usize).min(entry.data.len() - offset);
        unsafe {
            core::ptr::copy_nonoverlapping(
                entry.data.as_ptr().add(offset),
                dst_ptr as *mut u8,
                len,
            );
        }
        len as i64
    }
    #[cfg(not(any(test, feature = "harness")))]
    {
        let _ = (ino, offset, dst_ptr, dst_len);
        0
    }
}

#[cfg(not(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
)))]
unsafe fn tidemark_page_cache_stat(ino: u32, out_ptr: usize) -> i32 {
    #[cfg(any(test, feature = "harness"))]
    let Some(entries) = harness_page_cache_entries() else {
        return 0;
    };
    #[cfg(any(test, feature = "harness"))]
    {
        let Some(entry) = entries.iter_mut().find(|entry| entry.ino == ino) else {
            return 0;
        };
        unsafe {
            let meta = &mut *(out_ptr as *mut PageCacheMeta);
            meta.mode = entry.mode;
            meta._pad = 0;
            meta.size = entry.data.len() as u64;
        }
        1
    }
    #[cfg(not(any(test, feature = "harness")))]
    {
        let _ = (ino, out_ptr);
        0
    }
}

#[cfg(not(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
)))]
unsafe fn tidemark_page_cache_set_mode(ino: u32, mode: u32) -> i32 {
    #[cfg(any(test, feature = "harness"))]
    let Some(entries) = harness_page_cache_entries() else {
        return 0;
    };
    #[cfg(any(test, feature = "harness"))]
    {
        let Some(entry) = entries.iter_mut().find(|entry| entry.ino == ino) else {
            return 0;
        };
        entry.mode = mode;
        1
    }
    #[cfg(not(any(test, feature = "harness")))]
    {
        let _ = (ino, mode);
        0
    }
}

#[cfg(not(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
)))]
unsafe fn tidemark_page_cache_write(ino: u32, offset: u64, src_ptr: usize, src_len: u32) -> i64 {
    #[cfg(not(any(test, feature = "harness")))]
    {
        let _ = (ino, offset, src_ptr, src_len);
        return EOPNOTSUPP;
    }
    #[cfg(any(test, feature = "harness"))]
    let Some(entries) = harness_page_cache_entries() else {
        return EOPNOTSUPP;
    };
    let Some(end) = (offset as usize).checked_add(src_len as usize) else {
        return ENOSPC;
    };
    if end > u32::MAX as usize {
        return ENOSPC;
    }

    let index = match entries.iter().position(|entry| entry.ino == ino) {
        Some(index) => index,
        None => {
            entries.push(HarnessPageCacheEntry {
                ino,
                mode: S_IFREG | 0o644,
                data: Vec::new(),
            });
            entries.len() - 1
        }
    };
    let entry = &mut entries[index];
    if entry.data.len() < end {
        if entry
            .data
            .try_reserve_exact(end - entry.data.len())
            .is_err()
        {
            return ENOSPC;
        }
        entry.data.resize(end, 0);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            src_ptr as *const u8,
            entry.data.as_mut_ptr().add(offset as usize),
            src_len as usize,
        );
    }
    src_len as i64
}

#[cfg(not(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
)))]
unsafe fn tidemark_page_cache_flush(ino: u32) -> i32 {
    #[cfg(not(any(test, feature = "harness")))]
    {
        let _ = ino;
        return EOPNOTSUPP as i32;
    }
    #[cfg(any(test, feature = "harness"))]
    let Some(entries) = harness_page_cache_entries() else {
        let _ = ino;
        return EOPNOTSUPP as i32;
    };
    #[cfg(any(test, feature = "harness"))]
    {
        let _ = entries.iter().find(|entry| entry.ino == ino);
    }
    0
}

#[cfg(not(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
)))]
unsafe fn tidemark_page_cache_truncate(ino: u32, size: u64) -> i32 {
    #[cfg(not(any(test, feature = "harness")))]
    {
        let _ = (ino, size);
        return EOPNOTSUPP as i32;
    }
    #[cfg(any(test, feature = "harness"))]
    let Some(entries) = harness_page_cache_entries() else {
        return EOPNOTSUPP as i32;
    };
    if size > u32::MAX as u64 {
        return ENOSPC as i32;
    }
    let index = match entries.iter().position(|entry| entry.ino == ino) {
        Some(index) => index,
        None => {
            entries.push(HarnessPageCacheEntry {
                ino,
                mode: S_IFREG | 0o644,
                data: Vec::new(),
            });
            entries.len() - 1
        }
    };
    let entry = &mut entries[index];
    let next_len = size as usize;
    if entry.data.len() < next_len
        && entry
            .data
            .try_reserve_exact(next_len - entry.data.len())
            .is_err()
    {
        return ENOSPC as i32;
    }
    entry.data.resize(next_len, 0);
    0
}

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFCHR: u32 = 0o020000;

const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_IXGRP: u32 = 0o0010;

const MAX_INODES: usize = 65536;
const MAX_NAME_LEN: usize = 255;
const MAX_SYMLINK_FOLLOWS: u32 = 40;
const INITIAL_DATA_SIZE: u32 = 256 * 1024;
const LOOKUP_CACHE_SIZE: usize = 4096;
const LOOKUP_CACHE_MASK: usize = LOOKUP_CACHE_SIZE - 1;
const LOOKUP_HASH_OFFSET: u64 = 0xcbf29ce484222325;
const LOOKUP_HASH_PRIME: u64 = 0x100000001b3;
#[repr(C)]
#[derive(Clone, Copy)]
struct Inode {
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    data_offset: u32,
    data_cap: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DirEntry {
    name: [u8; MAX_NAME_LEN + 1],
    name_len: u16,
    _pad: u16,
    ino: u32,
    next_sibling: u32,
}

#[derive(Clone, Copy)]
struct LookupCacheEntry {
    memfs_ptr: usize,
    parent_ino: u32,
    name_hash: u64,
    name_len: u16,
    generation: u32,
    is_negative: bool,
    dir_entry_idx: u32,
    ino: u32,
    parent_first_child: u32,
    previous_sibling: u32,
    next_sibling: u32,
    dir_entry_count: u32,
}

impl LookupCacheEntry {
    const EMPTY: Self = Self {
        memfs_ptr: 0,
        parent_ino: 0,
        name_hash: 0,
        name_len: 0,
        generation: 0,
        is_negative: false,
        dir_entry_idx: 0,
        ino: 0,
        parent_first_child: 0,
        previous_sibling: 0,
        next_sibling: 0,
        dir_entry_count: 0,
    };
}

/// MemFS state header, allocated in kernel Worker linear memory.
/// The inode table, dir entries, first_child array, and data pool are
/// allocated separately via alloc.rs and referenced by pointers.
#[repr(C)]
struct MemFsHeader {
    inode_count: u32,
    dir_entry_count: u32,
    data_used: u32,
    data_cap: u32,
    inodes: *mut Inode,
    first_child: *mut u32,
    dir_entries: *mut DirEntry,
    data: *mut u8,
}

static mut MEMFS_PTR: *mut MemFsHeader = core::ptr::null_mut();
static mut LOOKUP_CACHE: [LookupCacheEntry; LOOKUP_CACHE_SIZE] =
    [LookupCacheEntry::EMPTY; LOOKUP_CACHE_SIZE];
static mut LOOKUP_CACHE_GENERATION: u32 = 1;
static mut LOOKUP_CACHE_MEMFS_PTR: usize = 0;
static mut LAST_CREATE_SYMLINK_STAGE: u32 = 0;
static mut LAST_CREATE_SYMLINK_ARG0: u64 = 0;
static mut LAST_CREATE_SYMLINK_ARG1: u64 = 0;

fn fs() -> &'static mut MemFsHeader {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(MEMFS_PTR));
        &mut *p
    }
}

pub fn memfs_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(MEMFS_PTR)) as u32 }
}

pub fn memfs_header_bytes() -> u32 {
    core::mem::size_of::<MemFsHeader>() as u32
}

pub fn memfs_inodes_ptr() -> u32 {
    fs().inodes as u32
}

pub fn memfs_inodes_bytes() -> u32 {
    (MAX_INODES * core::mem::size_of::<Inode>()) as u32
}

pub fn memfs_first_child_ptr() -> u32 {
    fs().first_child as u32
}

pub fn memfs_first_child_bytes() -> u32 {
    (MAX_INODES * core::mem::size_of::<u32>()) as u32
}

pub fn memfs_dir_entries_ptr() -> u32 {
    fs().dir_entries as u32
}

pub fn memfs_dir_entries_bytes() -> u32 {
    (MAX_INODES * core::mem::size_of::<DirEntry>()) as u32
}

pub fn memfs_data_ptr() -> u32 {
    fs().data as u32
}

pub fn memfs_data_bytes() -> u32 {
    fs().data_cap
}

pub fn memfs_inode_count() -> u32 {
    fs().inode_count
}

pub fn memfs_dir_entry_count() -> u32 {
    fs().dir_entry_count
}

pub fn memfs_data_used() -> u32 {
    fs().data_used
}

pub fn memfs_data_cap() -> u32 {
    fs().data_cap
}

pub fn last_create_symlink_stage() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_CREATE_SYMLINK_STAGE)) }
}

pub fn last_create_symlink_arg0() -> u64 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_CREATE_SYMLINK_ARG0)) }
}

pub fn last_create_symlink_arg1() -> u64 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_CREATE_SYMLINK_ARG1)) }
}

fn record_create_symlink(stage: u32, arg0: u64, arg1: u64) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(LAST_CREATE_SYMLINK_STAGE), stage);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_CREATE_SYMLINK_ARG0), arg0);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_CREATE_SYMLINK_ARG1), arg1);
    }
}

fn current_memfs_ptr_usize() -> usize {
    unsafe { core::ptr::read(core::ptr::addr_of!(MEMFS_PTR)) as usize }
}

fn reset_lookup_cache_for_ptr(ptr: usize) {
    unsafe {
        let cache_ptr = core::ptr::addr_of_mut!(LOOKUP_CACHE) as *mut LookupCacheEntry;
        for idx in 0..LOOKUP_CACHE_SIZE {
            core::ptr::write(cache_ptr.add(idx), LookupCacheEntry::EMPTY);
        }
        core::ptr::write(core::ptr::addr_of_mut!(LOOKUP_CACHE_GENERATION), 1);
        core::ptr::write(core::ptr::addr_of_mut!(LOOKUP_CACHE_MEMFS_PTR), ptr);
    }
}

fn ensure_lookup_cache_context() -> usize {
    let ptr = current_memfs_ptr_usize();
    let cached_ptr = unsafe { core::ptr::read(core::ptr::addr_of!(LOOKUP_CACHE_MEMFS_PTR)) };
    if cached_ptr != ptr {
        reset_lookup_cache_for_ptr(ptr);
    }
    ptr
}

fn invalidate_lookup_cache() {
    ensure_lookup_cache_context();
    unsafe {
        let generation = core::ptr::read(core::ptr::addr_of!(LOOKUP_CACHE_GENERATION));
        if generation == u32::MAX {
            reset_lookup_cache_for_ptr(current_memfs_ptr_usize());
            return;
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(LOOKUP_CACHE_GENERATION),
            generation + 1,
        );
    }
}

fn lookup_hash(parent_ino: u32, name: &[u8]) -> u64 {
    let mut hash = LOOKUP_HASH_OFFSET;
    for byte in parent_ino.to_le_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(LOOKUP_HASH_PRIME);
    }
    for &byte in name {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(LOOKUP_HASH_PRIME);
    }
    hash
}

fn lookup_cache_slot(hash: u64) -> usize {
    (hash as usize) & LOOKUP_CACHE_MASK
}

fn lookup_cache_get(parent_ino: u32, name: &[u8], hash: u64) -> Option<u32> {
    let memfs_ptr = ensure_lookup_cache_context();
    if memfs_ptr == 0 {
        return None;
    }
    let slot = lookup_cache_slot(hash);
    let entry = unsafe {
        let cache_ptr = core::ptr::addr_of!(LOOKUP_CACHE) as *const LookupCacheEntry;
        core::ptr::read(cache_ptr.add(slot))
    };
    let generation = unsafe { core::ptr::read(core::ptr::addr_of!(LOOKUP_CACHE_GENERATION)) };
    if entry.memfs_ptr != memfs_ptr
        || entry.parent_ino != parent_ino
        || entry.name_hash != hash
        || entry.name_len as usize != name.len()
        || entry.generation != generation
    {
        return None;
    }

    let h = fs();
    if h.dir_entries.is_null() || h.first_child.is_null() {
        return None;
    }

    unsafe {
        let first_child = *h.first_child.add(parent_ino as usize);
        if first_child != entry.parent_first_child || entry.dir_entry_count != h.dir_entry_count {
            return None;
        }
        if entry.is_negative {
            return Some(0);
        }
        if entry.dir_entry_idx == 0 || entry.dir_entry_idx >= h.dir_entry_count {
            return None;
        }
        if entry.previous_sibling == 0 {
            if first_child != entry.dir_entry_idx {
                return None;
            }
        } else {
            if entry.previous_sibling >= h.dir_entry_count {
                return None;
            }
            let prev = &*h.dir_entries.add(entry.previous_sibling as usize);
            if prev.next_sibling != entry.dir_entry_idx {
                return None;
            }
        }

        let de = &*h.dir_entries.add(entry.dir_entry_idx as usize);
        if de.ino == entry.ino
            && de.next_sibling == entry.next_sibling
            && de.name_len as usize == name.len()
            && &de.name[..name.len()] == name
        {
            return Some(entry.ino);
        }
    }
    None
}

fn lookup_cache_put(
    parent_ino: u32,
    name: &[u8],
    hash: u64,
    dir_entry_idx: u32,
    previous_sibling: u32,
    de: &DirEntry,
) {
    let memfs_ptr = ensure_lookup_cache_context();
    if memfs_ptr == 0 || dir_entry_idx == 0 {
        return;
    }
    let h = fs();
    let parent_first_child = unsafe { *h.first_child.add(parent_ino as usize) };
    let generation = unsafe { core::ptr::read(core::ptr::addr_of!(LOOKUP_CACHE_GENERATION)) };
    let entry = LookupCacheEntry {
        memfs_ptr,
        parent_ino,
        name_hash: hash,
        name_len: name.len() as u16,
        generation,
        is_negative: false,
        dir_entry_idx,
        ino: de.ino,
        parent_first_child,
        previous_sibling,
        next_sibling: de.next_sibling,
        dir_entry_count: h.dir_entry_count,
    };
    unsafe {
        let cache_ptr = core::ptr::addr_of_mut!(LOOKUP_CACHE) as *mut LookupCacheEntry;
        core::ptr::write(cache_ptr.add(lookup_cache_slot(hash)), entry);
    }
}

fn lookup_cache_put_negative(parent_ino: u32, name: &[u8], hash: u64) {
    let memfs_ptr = ensure_lookup_cache_context();
    if memfs_ptr == 0 {
        return;
    }
    let h = fs();
    let parent_first_child = unsafe { *h.first_child.add(parent_ino as usize) };
    let generation = unsafe { core::ptr::read(core::ptr::addr_of!(LOOKUP_CACHE_GENERATION)) };
    let entry = LookupCacheEntry {
        memfs_ptr,
        parent_ino,
        name_hash: hash,
        name_len: name.len() as u16,
        generation,
        is_negative: true,
        dir_entry_idx: 0,
        ino: 0,
        parent_first_child,
        previous_sibling: 0,
        next_sibling: 0,
        dir_entry_count: h.dir_entry_count,
    };
    unsafe {
        let cache_ptr = core::ptr::addr_of_mut!(LOOKUP_CACHE) as *mut LookupCacheEntry;
        core::ptr::write(cache_ptr.add(lookup_cache_slot(hash)), entry);
    }
}

pub fn attach_memfs_ptr(ptr: u32) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(MEMFS_PTR), ptr as *mut MemFsHeader);
    }
    // Runtime state attachment may follow an out-of-band metadata table copy.
    // The pointer can stay stable while dentries change underneath the cache.
    reset_lookup_cache_for_ptr(ptr as usize);
}

fn inodes() -> &'static mut [Inode] {
    let h = fs();
    unsafe { core::slice::from_raw_parts_mut(h.inodes, MAX_INODES) }
}

fn first_child() -> &'static mut [u32] {
    let h = fs();
    unsafe { core::slice::from_raw_parts_mut(h.first_child, MAX_INODES) }
}

fn dir_entries() -> &'static mut [DirEntry] {
    let h = fs();
    unsafe { core::slice::from_raw_parts_mut(h.dir_entries, MAX_INODES) }
}

/// Initialize MemFS. Allocates all data structures via alloc.rs.
pub fn init() {
    #[cfg(all(
        not(all(
            any(target_arch = "wasm32", target_arch = "wasm64"),
            target_os = "unknown"
        )),
        any(test, feature = "harness")
    ))]
    reset_harness_page_cache();

    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(MEMFS_PTR), core::ptr::null_mut());

        let header_ptr = alloc::alloc_zeroed(
            core::mem::size_of::<MemFsHeader>() as u32,
            core::mem::align_of::<MemFsHeader>() as u32,
        );
        let inodes_ptr =
            alloc::alloc_zeroed((MAX_INODES * core::mem::size_of::<Inode>()) as u32, 8);
        let first_child_ptr = alloc::alloc_zeroed((MAX_INODES * 4) as u32, 4);
        let dir_entries_ptr =
            alloc::alloc_zeroed((MAX_INODES * core::mem::size_of::<DirEntry>()) as u32, 4);
        let data_ptr = alloc::alloc_zeroed(INITIAL_DATA_SIZE, 8);

        if header_ptr == 0
            || inodes_ptr == 0
            || first_child_ptr == 0
            || dir_entries_ptr == 0
            || data_ptr == 0
        {
            crate::wasm::unreachable();
        }

        let h = &mut *(header_ptr as *mut MemFsHeader);
        h.inode_count = 2; // 0=unused, 1=root
        h.dir_entry_count = 1; // 0=unused
        h.data_used = 8;
        h.data_cap = INITIAL_DATA_SIZE;
        h.inodes = inodes_ptr as *mut Inode;
        h.first_child = first_child_ptr as *mut u32;
        h.dir_entries = dir_entries_ptr as *mut DirEntry;
        h.data = data_ptr as *mut u8;

        // Root directory (ino=1)
        let root = &mut *h.inodes.add(1);
        root.mode = S_IFDIR | 0o755;
        root.nlink = 2;

        core::ptr::write(
            core::ptr::addr_of_mut!(MEMFS_PTR),
            header_ptr as *mut MemFsHeader,
        );
    }
    reset_lookup_cache_for_ptr(current_memfs_ptr_usize());
}

pub fn reset() {
    let ptr = memfs_ptr();
    if ptr == 0 {
        init();
        return;
    }

    let h = fs();
    unsafe {
        core::ptr::write_bytes(h.inodes, 0, MAX_INODES);
        core::ptr::write_bytes(h.first_child, 0, MAX_INODES);
        core::ptr::write_bytes(h.dir_entries, 0, MAX_INODES);
        core::ptr::write_bytes(h.data, 0, h.data_cap as usize);

        h.inode_count = 2; // 0=unused, 1=root
        h.dir_entry_count = 1; // 0=unused
        h.data_used = 8;

        let root = &mut *h.inodes.add(1);
        root.mode = S_IFDIR | 0o755;
        root.nlink = 2;
    }
    reset_lookup_cache_for_ptr(current_memfs_ptr_usize());
}

// =========================================================================
// Allocation helpers
// =========================================================================

fn alloc_inode(mode: u32) -> u32 {
    let h = fs();
    let ino = h.inode_count as usize;
    if ino >= MAX_INODES {
        return 0;
    }
    unsafe {
        core::ptr::write(
            h.inodes.add(ino),
            Inode {
                mode,
                nlink: 1,
                uid: 0,
                gid: 0,
                size: 0,
                data_offset: 0,
                data_cap: 0,
            },
        );
    }
    h.inode_count += 1;
    ino as u32
}

pub fn reserve_inode_until(target_ino: u32) -> i64 {
    let h = fs();
    if target_ino as usize >= MAX_INODES {
        return ENOSPC;
    }
    while h.inode_count < target_ino {
        unsafe {
            core::ptr::write(
                h.inodes.add(h.inode_count as usize),
                Inode {
                    mode: 0,
                    nlink: 0,
                    uid: 0,
                    gid: 0,
                    size: 0,
                    data_offset: 0,
                    data_cap: 0,
                },
            );
        }
        h.inode_count += 1;
    }
    0
}

fn alloc_data(size: u32) -> u32 {
    let aligned = (size + 7) & !7;
    let data_used = fs().data_used.max(referenced_data_high_watermark());
    let needed = match data_used.checked_add(aligned) {
        Some(needed) => needed,
        None => return u32::MAX,
    };
    if needed > fs().data_cap && !grow_data_pool(needed) {
        return u32::MAX;
    }
    let h = fs();
    let off = data_used;
    h.data_used = needed;
    off
}

fn referenced_data_high_watermark() -> u32 {
    let inode_count = fs().inode_count as usize;
    let mut high = fs().data_used;
    for inode in inodes().iter().take(inode_count).skip(1) {
        if inode.data_cap == 0 {
            continue;
        }
        let Some(end) = inode.data_offset.checked_add(inode.data_cap) else {
            return u32::MAX;
        };
        high = high.max(end);
    }
    high
}

fn grow_data_pool(needed: u32) -> bool {
    let data_cap = fs().data_cap;
    let data_used = fs().data_used;
    let old_data = fs().data;
    let mut new_cap = data_cap.max(4096);
    while new_cap < needed {
        let Some(doubled) = new_cap.checked_mul(2) else {
            return false;
        };
        new_cap = doubled;
    }

    // MemFS uses bump allocation, so growth installs a new backing store and
    // leaves the old one unreachable for the lifetime of the worker.
    let new_data = unsafe { alloc::alloc_zeroed(new_cap, 8) };
    if new_data == 0 {
        return false;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(old_data, new_data as *mut u8, data_used as usize);
    }
    let h = fs();
    h.data = new_data as *mut u8;
    h.data_cap = new_cap;
    true
}

// =========================================================================
// Directory operations
// =========================================================================

pub fn lookup(parent_ino: u32, name: &[u8]) -> u32 {
    if parent_ino as usize >= MAX_INODES || name.len() > MAX_NAME_LEN {
        return 0;
    }
    let ptr = memfs_ptr();
    if ptr == 0 {
        return 0;
    }
    let h = fs();
    if h.first_child.is_null() || h.dir_entries.is_null() {
        return 0;
    }
    let hash = lookup_hash(parent_ino, name);
    if let Some(ino) = lookup_cache_get(parent_ino, name, hash) {
        return ino;
    }
    unsafe {
        let mut idx = *h.first_child.add(parent_ino as usize);
        let mut previous_sibling = 0u32;
        while idx != 0 {
            let de = &*h.dir_entries.add(idx as usize);
            if de.name_len as usize == name.len() && &de.name[..name.len()] == name {
                lookup_cache_put(parent_ino, name, hash, idx, previous_sibling, de);
                return de.ino;
            }
            previous_sibling = idx;
            idx = de.next_sibling;
        }
        lookup_cache_put_negative(parent_ino, name, hash);
        0
    }
}

pub fn resolve_path(path: &[u8]) -> u32 {
    if path.is_empty() || path[0] != b'/' {
        return 0;
    }
    let mut ino = 1u32;
    for component in path[1..].split(|&b| b == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            ino = parent_ino(ino);
            continue;
        }
        ino = lookup(ino, component);
        if ino == 0 {
            return 0;
        }
    }
    ino
}

fn concat_symlink_target_and_rest<'a>(
    target: &[u8],
    rest: &[u8],
    buf: &'a mut [u8; 4096],
) -> Result<&'a [u8], i64> {
    let total = target.len().checked_add(rest.len()).ok_or(ENAMETOOLONG)?;
    if total > buf.len() {
        return Err(ENAMETOOLONG);
    }
    buf[..target.len()].copy_from_slice(target);
    buf[target.len()..total].copy_from_slice(rest);
    Ok(&buf[..total])
}

pub fn resolve_path_following_symlinks(path: &[u8]) -> u32 {
    resolve_path_following_symlinks_with_errno(path).unwrap_or(0)
}

pub fn resolve_path_following_symlinks_with_errno(path: &[u8]) -> Result<u32, i64> {
    resolve_path_following_symlinks_from_with_errno(1, path, MAX_SYMLINK_FOLLOWS)
}

fn resolve_path_following_symlinks_from_with_errno(
    start_ino: u32,
    path: &[u8],
    depth_left: u32,
) -> Result<u32, i64> {
    // execve(2) requires resolving script and ELF interpreters through normal
    // path lookup and reporting ELOOP/ENOENT for symlink loops or missing
    // interpreters: https://man7.org/linux/man-pages/man2/execve.2.html
    if depth_left == 0 {
        return Err(ELOOP);
    }
    if path.is_empty() {
        return Err(ENOENT);
    }

    let mut ino = start_ino;
    let mut cursor = 0usize;
    if path.first() == Some(&b'/') {
        ino = 1;
        cursor = 1;
    }

    while cursor < path.len() {
        while cursor < path.len() && path[cursor] == b'/' {
            cursor += 1;
        }
        if cursor >= path.len() {
            break;
        }

        let component_start = cursor;
        while cursor < path.len() && path[cursor] != b'/' {
            cursor += 1;
        }
        let component = &path[component_start..cursor];
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            ino = parent_ino(ino);
            continue;
        }

        let st = stat(ino).ok_or(ENOENT)?;
        if st.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }

        let next_ino = lookup(ino, component);
        if next_ino == 0 {
            return Err(ENOENT);
        }

        let next_st = stat(next_ino).ok_or(ENOENT)?;
        if next_st.mode & S_IFMT == S_IFLNK {
            let mut target_buf = [0u8; 4096];
            let target_len = read_link(next_ino, &mut target_buf);
            if target_len == 0 {
                return Err(ENOENT);
            }
            let target = &target_buf[..target_len];
            let rest = &path[cursor..];
            let mut combined = [0u8; 4096];
            let combined_path = concat_symlink_target_and_rest(target, rest, &mut combined)?;
            let restart_ino = if target.first() == Some(&b'/') {
                1
            } else {
                ino
            };
            return resolve_path_following_symlinks_from_with_errno(
                restart_ino,
                combined_path,
                depth_left - 1,
            );
        }

        ino = next_ino;
    }

    Ok(ino)
}

/// Resolve a relative path starting from a given directory inode.
/// The path must NOT start with '/'. Each component is looked up
/// via `lookup` starting from `start_ino`.
pub fn resolve_path_from(start_ino: u32, path: &[u8]) -> u32 {
    if path.is_empty() {
        return start_ino;
    }
    // Absolute paths should not be passed here
    if path[0] == b'/' {
        return 0;
    }
    let mut ino = start_ino;
    for component in path.split(|&b| b == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            ino = parent_ino(ino);
            continue;
        }
        ino = lookup(ino, component);
        if ino == 0 {
            return 0;
        }
    }
    ino
}

fn add_dir_entry(parent_ino: u32, name: &[u8], ino: u32) -> bool {
    let h = fs();
    let idx = h.dir_entry_count as usize;
    if idx >= MAX_INODES || name.len() > MAX_NAME_LEN {
        return false;
    }

    unsafe {
        let de = &mut *h.dir_entries.add(idx);
        de.name[..name.len()].copy_from_slice(name);
        de.name_len = name.len() as u16;
        de.ino = ino;
        let parent_first_child = h.first_child.add(parent_ino as usize);
        de.next_sibling = *parent_first_child;
        *parent_first_child = idx as u32;
    }
    h.dir_entry_count += 1;
    invalidate_lookup_cache();
    true
}

fn remove_dir_entry(parent_ino: u32, name: &[u8]) -> u32 {
    let fc = first_child();
    let des = dir_entries();
    let mut prev_idx = 0u32;
    let mut idx = fc[parent_ino as usize];
    let mut is_first = true;

    while idx != 0 {
        let de = &des[idx as usize];
        if de.name_len as usize == name.len() && &de.name[..name.len()] == name {
            let removed_ino = de.ino;
            let next = de.next_sibling;
            if is_first {
                fc[parent_ino as usize] = next;
            } else {
                des[prev_idx as usize].next_sibling = next;
            }
            invalidate_lookup_cache();
            return removed_ino;
        }
        prev_idx = idx;
        idx = de.next_sibling;
        is_first = false;
    }
    0
}

fn find_parent_name(child_ino: u32, name_buf: &mut [u8; MAX_NAME_LEN + 1]) -> Option<(u32, usize)> {
    let h = fs();
    let des = dir_entries();
    let fc = first_child();

    for parent_ino in 1..h.inode_count {
        let mut idx = fc[parent_ino as usize];
        while idx != 0 {
            let de = &des[idx as usize];
            if de.ino == child_ino {
                let name_len = de.name_len as usize;
                name_buf[..name_len].copy_from_slice(&de.name[..name_len]);
                return Some((parent_ino, name_len));
            }
            idx = de.next_sibling;
        }
    }

    None
}

pub fn parent_ino(ino: u32) -> u32 {
    if ino <= 1 {
        return 1;
    }
    let mut name_buf = [0u8; MAX_NAME_LEN + 1];
    find_parent_name(ino, &mut name_buf)
        .map(|(parent, _)| parent)
        .unwrap_or(1)
}

fn write_path_inner(ino: u32, buf: &mut [u8]) -> Option<usize> {
    if ino == 1 {
        if buf.is_empty() {
            return None;
        }
        buf[0] = b'/';
        return Some(1);
    }

    let mut name_buf = [0u8; MAX_NAME_LEN + 1];
    let (parent_ino, name_len) = find_parent_name(ino, &mut name_buf)?;
    let prefix_len = write_path_inner(parent_ino, buf)?;
    let sep_len = usize::from(prefix_len > 1);
    let total_len = prefix_len + sep_len + name_len;
    if total_len > buf.len() {
        return None;
    }
    if sep_len != 0 {
        buf[prefix_len] = b'/';
    }
    let name_start = prefix_len + sep_len;
    buf[name_start..name_start + name_len].copy_from_slice(&name_buf[..name_len]);
    Some(total_len)
}

pub fn write_path(ino: u32, buf: &mut [u8]) -> usize {
    write_path_inner(ino, buf).unwrap_or_default()
}

// =========================================================================
// Symlink operations
// =========================================================================

/// Create a symbolic link under `parent_ino` with `name` pointing to `target`.
/// Returns the new inode number, or 0 on failure.
/// https://man7.org/linux/man-pages/man2/symlinkat.2.html
pub fn create_symlink(parent_ino: u32, name: &[u8], target: &[u8]) -> u32 {
    record_create_symlink(801, parent_ino as u64, target.len() as u64);
    crate::tracepoints::record_execve_stage(801, parent_ino as u64, target.len() as u64);
    let existing = lookup(parent_ino, name);
    record_create_symlink(802, existing as u64, name.len() as u64);
    crate::tracepoints::record_execve_stage(802, existing as u64, name.len() as u64);
    if existing != 0 {
        return 0;
    } // already exists
    let ino = alloc_inode(S_IFLNK | 0o777);
    record_create_symlink(803, ino as u64, 0);
    crate::tracepoints::record_execve_stage(803, ino as u64, 0);
    if ino == 0 {
        return 0;
    }
    // Store target as the inode's data
    let off = alloc_data(target.len() as u32);
    record_create_symlink(804, off as u64, fs().data_cap as u64);
    crate::tracepoints::record_execve_stage(804, off as u64, fs().data_cap as u64);
    if off == u32::MAX {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(target.as_ptr(), fs().data.add(off as usize), target.len());
    }
    record_create_symlink(805, off as u64, target.len() as u64);
    crate::tracepoints::record_execve_stage(805, off as u64, target.len() as u64);
    inodes()[ino as usize].data_offset = off;
    inodes()[ino as usize].data_cap = target.len() as u32;
    inodes()[ino as usize].size = target.len() as u64;
    let added = add_dir_entry(parent_ino, name, ino);
    record_create_symlink(806, added as u64, ino as u64);
    crate::tracepoints::record_execve_stage(806, added as u64, ino as u64);
    if !added {
        return 0;
    }
    record_create_symlink(807, ino as u64, 0);
    crate::tracepoints::record_execve_stage(807, ino as u64, 0);
    ino
}

pub fn replace_symlink_target(ino: u32, target: &[u8]) -> i64 {
    let idx = ino as usize;
    if idx >= fs().inode_count as usize || inodes()[idx].mode & S_IFMT != S_IFLNK {
        return EINVAL;
    }
    let target_len = match u32::try_from(target.len()) {
        Ok(length) => length,
        Err(_) => return ENOSPC,
    };
    let current_cap = inodes()[idx].data_cap;
    let offset = if current_cap >= target_len {
        inodes()[idx].data_offset
    } else {
        let allocated = alloc_data(target_len);
        if allocated == u32::MAX {
            return ENOSPC;
        }
        allocated
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            target.as_ptr(),
            fs().data.add(offset as usize),
            target.len(),
        );
    }
    let inode = &mut inodes()[idx];
    inode.data_offset = offset;
    inode.data_cap = current_cap.max(target_len);
    inode.size = target.len() as u64;
    0
}

/// Read the target of a symbolic link. Returns bytes written to `buf`.
pub fn read_link(ino: u32, buf: &mut [u8]) -> usize {
    let ins = inodes();
    if ino as usize >= ins.len() {
        return 0;
    }
    let inode = &ins[ino as usize];
    if inode.mode & S_IFMT != S_IFLNK {
        return 0;
    }
    let len = inode.size as usize;
    let n = len.min(buf.len());
    let off = inode.data_offset as usize;
    unsafe {
        core::ptr::copy_nonoverlapping(fs().data.add(off), buf.as_mut_ptr(), n);
    }
    n
}

// =========================================================================
// File/directory CRUD
// =========================================================================

pub fn create_file(parent_ino: u32, name: &[u8], mode: u32) -> u32 {
    if lookup(parent_ino, name) != 0 {
        return 0;
    }
    let ino = alloc_inode(S_IFREG | (mode & 0o7777));
    if ino == 0 {
        return 0;
    }
    if !add_dir_entry(parent_ino, name, ino) {
        return 0;
    }
    ino
}

pub fn create_dir(parent_ino: u32, name: &[u8], mode: u32) -> u32 {
    if lookup(parent_ino, name) != 0 {
        return 0;
    }
    let ino = alloc_inode(S_IFDIR | (mode & 0o7777));
    if ino == 0 {
        return 0;
    }
    inodes()[ino as usize].nlink = 2;
    if !add_dir_entry(parent_ino, name, ino) {
        return 0;
    }
    inodes()[parent_ino as usize].nlink += 1;
    ino
}

pub fn unlink(parent_ino: u32, name: &[u8]) -> i64 {
    let ino = lookup(parent_ino, name);
    if ino == 0 {
        return ENOENT;
    }
    if inodes()[ino as usize].mode & S_IFMT == S_IFDIR {
        return EISDIR;
    }
    remove_dir_entry(parent_ino, name);
    inodes()[ino as usize].nlink -= 1;
    0
}

pub fn rmdir(parent_ino: u32, name: &[u8]) -> i64 {
    let ino = lookup(parent_ino, name);
    if ino == 0 {
        return ENOENT;
    }
    if inodes()[ino as usize].mode & S_IFMT != S_IFDIR {
        return ENOTDIR;
    }
    if first_child()[ino as usize] != 0 {
        return ENOTEMPTY;
    }
    remove_dir_entry(parent_ino, name);
    inodes()[ino as usize].nlink = 0;
    inodes()[parent_ino as usize].nlink -= 1;
    0
}

pub fn rename(old_parent_ino: u32, old_name: &[u8], new_parent_ino: u32, new_name: &[u8]) -> i64 {
    if old_name.is_empty() || new_name.is_empty() {
        return ENOENT;
    }

    let ino = lookup(old_parent_ino, old_name);
    if ino == 0 {
        return ENOENT;
    }

    if old_parent_ino == new_parent_ino && old_name == new_name {
        return 0;
    }

    let inode = inodes()[ino as usize];
    let file_type = inode.mode & S_IFMT;
    if old_name == b"." || old_name == b".." || new_name == b"." || new_name == b".." {
        return EINVAL;
    }

    if file_type == S_IFDIR {
        let mut ancestor = new_parent_ino;
        loop {
            if ancestor == ino {
                return EINVAL;
            }
            if ancestor <= 1 {
                break;
            }
            let next = parent_ino(ancestor);
            if next == ancestor {
                break;
            }
            ancestor = next;
        }
    }

    let existing_target = lookup(new_parent_ino, new_name);
    if existing_target != 0 && existing_target != ino {
        let target_mode = inodes()[existing_target as usize].mode & S_IFMT;
        if file_type == S_IFDIR {
            if target_mode != S_IFDIR {
                return ENOTDIR;
            }
            if first_child()[existing_target as usize] != 0 {
                return ENOTEMPTY;
            }
        } else if target_mode == S_IFDIR {
            return EISDIR;
        }
    }

    if existing_target != 0 && existing_target != ino {
        let target_mode = inodes()[existing_target as usize].mode & S_IFMT;
        remove_dir_entry(new_parent_ino, new_name);
        if target_mode == S_IFDIR {
            inodes()[existing_target as usize].nlink = 0;
            inodes()[new_parent_ino as usize].nlink -= 1;
        } else {
            inodes()[existing_target as usize].nlink =
                inodes()[existing_target as usize].nlink.saturating_sub(1);
        }
    }

    let removed = remove_dir_entry(old_parent_ino, old_name);
    if removed == 0 {
        return ENOENT;
    }
    if !add_dir_entry(new_parent_ino, new_name, ino) {
        let _ = add_dir_entry(old_parent_ino, old_name, ino);
        return ENOSPC;
    }

    if file_type == S_IFDIR && old_parent_ino != new_parent_ino {
        inodes()[old_parent_ino as usize].nlink =
            inodes()[old_parent_ino as usize].nlink.saturating_sub(1);
        inodes()[new_parent_ino as usize].nlink += 1;
    }

    0
}

// =========================================================================
// File I/O
// =========================================================================

pub fn write_file(ino: u32, offset: u64, data: &[u8]) -> i64 {
    let idx = ino as usize;
    if inodes()[idx].mode & S_IFMT != S_IFREG {
        return EBADF;
    }

    let Some(end_u64) = offset.checked_add(data.len() as u64) else {
        return ENOSPC;
    };
    if end_u64 > u32::MAX as u64 {
        return ENOSPC;
    }
    let discard_inline_data = inodes()[idx].data_cap != 0 && inodes()[idx].size > 0;
    if discard_inline_data && offset != 0 {
        return EOPNOTSUPP;
    }

    let written = unsafe {
        tidemark_page_cache_write(ino, offset, data.as_ptr() as usize, data.len() as u32)
    };
    if written != data.len() as i64 {
        return if written < 0 { written } else { EIO };
    }
    let inode = &mut inodes()[idx];
    inode.size = if discard_inline_data {
        end_u64
    } else {
        inode.size.max(end_u64)
    };
    inode.data_offset = 0;
    inode.data_cap = 0;
    written
}

pub fn read_file(ino: u32, offset: u64, buf: &mut [u8]) -> i64 {
    let inode = inodes()[ino as usize];
    if inode.mode & S_IFMT != S_IFREG {
        return EBADF;
    }
    if offset >= inode.size {
        return 0;
    }
    let avail = (inode.size - offset) as usize;
    if inode.data_cap == 0 {
        let n = buf.len().min(avail);
        return unsafe {
            tidemark_page_cache_read(ino, offset, buf.as_mut_ptr() as usize, n as u32)
        };
    }
    EOPNOTSUPP
}

pub fn can_read_file_to_ptr(ino: u32) -> bool {
    let ins = inodes();
    let idx = ino as usize;
    idx < ins.len() && ins[idx].mode & S_IFMT == S_IFREG && ins[idx].data_cap == 0
}

pub fn read_file_to_ptr(ino: u32, offset: u64, dst_ptr: usize, dst_len: u32) -> i64 {
    let inode = inodes()[ino as usize];
    if inode.mode & S_IFMT != S_IFREG {
        return EBADF;
    }
    if offset >= inode.size {
        return 0;
    }
    let avail = (inode.size - offset).min(dst_len as u64) as u32;
    if inode.data_cap == 0 {
        return unsafe { tidemark_page_cache_read(ino, offset, dst_ptr, avail) };
    }
    EOPNOTSUPP
}

pub fn file_data_ptr(ino: u32) -> Option<u32> {
    let _ = ino;
    None
}

pub fn debug_file_data_layout(ino: u32) -> u64 {
    let idx = ino as usize;
    let ins = inodes();
    if idx >= ins.len() || ino == 0 {
        return 0;
    }
    ((ins[idx].data_cap as u64) << 32) | ins[idx].data_offset as u64
}

pub fn truncate(ino: u32, size: u64) -> i64 {
    let idx = ino as usize;
    if inodes()[idx].mode & S_IFMT != S_IFREG {
        return EINVAL;
    }
    if inodes()[idx].data_cap != 0 && inodes()[idx].size > 0 && size != 0 {
        return EOPNOTSUPP;
    }
    let truncated = unsafe { tidemark_page_cache_truncate(ino, size) };
    if truncated < 0 {
        return truncated as i64;
    }
    let inode = &mut inodes()[idx];
    inode.size = size;
    inode.data_offset = 0;
    inode.data_cap = 0;
    0
}

pub fn fsync(ino: u32) -> i64 {
    let idx = ino as usize;
    if inodes()[idx].mode & S_IFMT != S_IFREG {
        return EINVAL;
    }
    let flushed = unsafe { tidemark_page_cache_flush(ino) };
    if flushed < 0 {
        return flushed as i64;
    }
    0
}

pub fn set_file_size_shallow(ino: u32, size: u64) -> i64 {
    let idx = ino as usize;
    if inodes()[idx].mode & S_IFMT != S_IFREG {
        return EINVAL;
    }
    if inodes()[idx].data_cap != 0 {
        return EINVAL;
    }

    let mut meta = PageCacheMeta {
        mode: 0,
        _pad: 0,
        size: 0,
    };
    let published =
        unsafe { tidemark_page_cache_stat(ino, (&mut meta as *mut PageCacheMeta) as usize) };
    if published != 0 {
        inodes()[idx].mode = meta.mode;
        inodes()[idx].size = meta.size;
        return 0;
    }

    inodes()[idx].size = size;
    0
}

pub fn set_file_external(ino: u32, size: u64) -> i64 {
    let idx = ino as usize;
    if inodes()[idx].mode & S_IFMT != S_IFREG {
        return EINVAL;
    }

    let inode = &mut inodes()[idx];
    inode.size = size;
    inode.data_offset = 0;
    inode.data_cap = 0;
    0
}

pub fn set_mode(ino: u32, mode: u32) -> i64 {
    let idx = ino as usize;
    let ins = inodes();
    if idx >= ins.len() || ino == 0 {
        return ENOENT;
    }
    let file_type = ins[idx].mode & S_IFMT;
    let next_mode = file_type | (mode & 0o7777);
    let published = unsafe { tidemark_page_cache_set_mode(ino, next_mode) };
    if published < 0 {
        return published as i64;
    }
    inodes()[idx].mode = next_mode;
    0
}

pub fn set_owner(ino: u32, uid: Option<u32>, gid: Option<u32>) -> i64 {
    let idx = ino as usize;
    let ins = inodes();
    if idx >= ins.len() || ino == 0 {
        return ENOENT;
    }
    let owner_update_requested = uid.is_some() || gid.is_some();

    if let Some(uid) = uid {
        inodes()[idx].uid = uid;
    }
    if let Some(gid) = gid {
        inodes()[idx].gid = gid;
    }
    if owner_update_requested && inodes()[idx].mode & S_IFMT == S_IFREG {
        inodes()[idx].mode &= !S_ISUID;
        if inodes()[idx].mode & S_IXGRP != 0 {
            inodes()[idx].mode &= !S_ISGID;
        }
    }
    0
}

/// Subset of inode metadata returned by stat.
pub struct InodeStat {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
}

pub fn stat(ino: u32) -> Option<InodeStat> {
    let h = fs();
    if ino == 0 || ino as usize >= h.inode_count as usize {
        return None;
    }
    let inode = &inodes()[ino as usize];
    Some(InodeStat {
        ino: ino as u64,
        mode: inode.mode,
        nlink: inode.nlink,
        uid: inode.uid,
        gid: inode.gid,
        size: inode.size,
    })
}

pub fn readdir<F: FnMut(&[u8], u32)>(dir_ino: u32, mut cb: F) -> i64 {
    if inodes()[dir_ino as usize].mode & S_IFMT != S_IFDIR {
        return ENOTDIR;
    }
    let fc = first_child();
    let des = dir_entries();
    let mut count = 0i64;
    let mut idx = fc[dir_ino as usize];
    while idx != 0 {
        let de = &des[idx as usize];
        cb(&de.name[..de.name_len as usize], de.ino);
        count += 1;
        idx = de.next_sibling;
    }
    count
}

pub fn create_file_with_data(parent_ino: u32, name: &[u8], data: &[u8]) -> u32 {
    let ino = create_file(parent_ino, name, 0o644);
    if ino == 0 {
        return 0;
    }
    write_file(ino, 0, data);
    ino
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::TestVm;

    #[test]
    fn alloc_data_does_not_reuse_referenced_file_ranges_after_stale_data_used() {
        let _t = TestVm::new();

        let first = create_file(1, b"first.bin", 0o644);
        assert!(first > 0);
        let first_data = [0x41u8; 4096];
        assert_eq!(write_file(first, 0, &first_data), first_data.len() as i64);

        // Runtime ownership can restore/copy MemFS metadata independently from
        // the bump header. The allocator must treat inode data ranges as live
        // even when the header's data_used value is stale.
        fs().data_used = 8;

        let second = create_file(1, b"second.bin", 0o644);
        assert!(second > 0);
        let second_data = [0x42u8; 4096];
        assert_eq!(
            write_file(second, 0, &second_data),
            second_data.len() as i64
        );

        let mut first_read = [0u8; 4096];
        assert_eq!(
            read_file(first, 0, &mut first_read),
            first_read.len() as i64
        );
        assert_eq!(first_read, first_data);

        let mut second_read = [0u8; 4096];
        assert_eq!(
            read_file(second, 0, &mut second_read),
            second_read.len() as i64
        );
        assert_eq!(second_read, second_data);
    }

    #[test]
    fn regular_inline_file_data_is_not_page_cache_fallback() {
        let _t = TestVm::new();

        let ino = create_file(1, b"legacy-inline.bin", 0o644);
        assert!(ino > 0);
        let inline = *b"old!";
        let off = alloc_data(inline.len() as u32);
        assert_ne!(off, u32::MAX);
        unsafe {
            core::ptr::copy_nonoverlapping(
                inline.as_ptr(),
                fs().data.add(off as usize),
                inline.len(),
            );
        }
        {
            let inode = &mut inodes()[ino as usize];
            inode.size = inline.len() as u64;
            inode.data_offset = off;
            inode.data_cap = inline.len() as u32;
        }

        let mut read_buf = [0u8; 4];
        assert_eq!(read_file(ino, 0, &mut read_buf), EOPNOTSUPP);
        assert_eq!(write_file(ino, 1, b"x"), EOPNOTSUPP);
        assert_eq!(truncate(ino, 2), EOPNOTSUPP);
        assert_eq!(write_file(ino, 0, b"new"), 3);
        assert!(file_data_ptr(ino).is_none());
        assert_eq!(debug_file_data_layout(ino) >> 32, 0);

        let mut replaced = [0u8; 3];
        assert_eq!(read_file(ino, 0, &mut replaced), 3);
        assert_eq!(&replaced, b"new");

        let truncate_ino = create_file(1, b"legacy-inline-zero.bin", 0o644);
        assert!(truncate_ino > 0);
        let truncate_off = alloc_data(inline.len() as u32);
        assert_ne!(truncate_off, u32::MAX);
        unsafe {
            core::ptr::copy_nonoverlapping(
                inline.as_ptr(),
                fs().data.add(truncate_off as usize),
                inline.len(),
            );
        }
        {
            let inode = &mut inodes()[truncate_ino as usize];
            inode.size = inline.len() as u64;
            inode.data_offset = truncate_off;
            inode.data_cap = inline.len() as u32;
        }
        assert_eq!(truncate(truncate_ino, 0), 0);
        assert_eq!(debug_file_data_layout(truncate_ino) >> 32, 0);
    }

    #[test]
    fn lookup_cache_invalidates_after_unlink_and_recreate() {
        let _t = TestVm::new();

        let dir = create_dir(1, b"cache-dir", 0o755);
        assert!(dir > 0);
        let first = create_file(dir, b"target.rb", 0o644);
        assert!(first > 0);

        assert_eq!(lookup(dir, b"target.rb"), first);
        assert_eq!(lookup(dir, b"target.rb"), first);
        assert_eq!(unlink(dir, b"target.rb"), 0);
        assert_eq!(lookup(dir, b"target.rb"), 0);

        let second = create_file(dir, b"target.rb", 0o644);
        assert!(second > first);
        assert_eq!(lookup(dir, b"target.rb"), second);
    }

    #[test]
    fn lookup_cache_invalidates_negative_entry_after_create() {
        let _t = TestVm::new();

        let dir = create_dir(1, b"negative-cache", 0o755);
        assert!(dir > 0);

        assert_eq!(lookup(dir, b"later.rb"), 0);
        assert_eq!(lookup(dir, b"later.rb"), 0);
        let ino = create_file(dir, b"later.rb", 0o644);
        assert!(ino > 0);
        assert_eq!(lookup(dir, b"later.rb"), ino);
    }

    #[test]
    fn lookup_cache_invalidates_when_same_memfs_state_is_reattached() {
        let _t = TestVm::new();

        let ino = create_dir(1, b"before", 0o755);
        assert!(ino > 0);
        assert_eq!(lookup(1, b"after"), 0);

        let entry = &mut dir_entries()[1];
        entry.name[..5].copy_from_slice(b"after");
        entry.name_len = 5;

        attach_memfs_ptr(memfs_ptr());
        assert_eq!(lookup(1, b"after"), ino);
    }

    #[test]
    fn lookup_cache_invalidates_after_rename_replace() {
        let _t = TestVm::new();

        let dir = create_dir(1, b"rename-cache", 0o755);
        assert!(dir > 0);
        let old = create_file(dir, b"old.rb", 0o644);
        let replacement = create_file(dir, b"replacement.rb", 0o644);
        assert!(old > 0);
        assert!(replacement > 0);

        assert_eq!(lookup(dir, b"old.rb"), old);
        assert_eq!(lookup(dir, b"replacement.rb"), replacement);
        assert_eq!(rename(dir, b"old.rb", dir, b"replacement.rb"), 0);

        assert_eq!(lookup(dir, b"old.rb"), 0);
        assert_eq!(lookup(dir, b"replacement.rb"), old);
    }
}
