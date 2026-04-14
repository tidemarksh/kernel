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

#[repr(C)]
struct PageCacheMeta {
    mode: u32,
    _pad: u32,
    size: u64,
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn tidemark_page_cache_read(ino: u32, offset: u64, dst_ptr: u32, dst_len: u32) -> i64;
    fn tidemark_page_cache_stat(ino: u32, out_ptr: u32) -> i32;
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
unsafe fn tidemark_page_cache_read(_ino: u32, _offset: u64, _dst_ptr: u32, _dst_len: u32) -> i64 {
    0
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
unsafe fn tidemark_page_cache_stat(_ino: u32, _out_ptr: u32) -> i32 {
    0
}

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFCHR: u32 = 0o020000;

const MAX_INODES: usize = 16384;
const MAX_NAME_LEN: usize = 255;
const INITIAL_DATA_SIZE: u32 = 256 * 1024;

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

pub fn attach_memfs_ptr(ptr: u32) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(MEMFS_PTR), ptr as *mut MemFsHeader);
    }
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
            core::arch::wasm32::unreachable();
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
    let data_used = fs().data_used;
    let needed = match data_used.checked_add(aligned) {
        Some(needed) => needed,
        None => return u32::MAX,
    };
    if needed > fs().data_cap && !grow_data_pool(needed) {
        return u32::MAX;
    }
    let h = fs();
    let off = h.data_used;
    h.data_used = needed;
    off
}

fn has_external_file_data(ino: u32) -> bool {
    let inode = inodes()[ino as usize];
    inode.mode & S_IFMT == S_IFREG && inode.size > 0 && inode.data_cap == 0
}

fn materialize_external_file_data(ino: u32) -> i64 {
    if !has_external_file_data(ino) {
        return 0;
    }

    let idx = ino as usize;
    let size = inodes()[idx].size as usize;
    let cap = (size as u32).max(4096);
    let off = alloc_data(cap);
    if off == u32::MAX {
        return ENOSPC;
    }

    let mut copied = 0usize;
    while copied < size {
        let chunk = (size - copied).min(4096);
        let dst_ptr = unsafe { fs().data.add(off as usize + copied) as u32 };
        let n = unsafe { tidemark_page_cache_read(ino, copied as u64, dst_ptr, chunk as u32) };
        if n < 0 {
            return n;
        }
        if n == 0 {
            return EIO;
        }
        copied += n as usize;
    }

    let inode = &mut inodes()[idx];
    inode.data_offset = off;
    inode.data_cap = cap;
    0
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
    let h = fs();
    unsafe {
        let mut idx = *h.first_child.add(parent_ino as usize);
        while idx != 0 {
            let de = &*h.dir_entries.add(idx as usize);
            if de.name_len as usize == name.len() && &de.name[..name.len()] == name {
                return de.ino;
            }
            idx = de.next_sibling;
        }
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
    crate::harness_hooks::record_execve_stage(801, parent_ino as u64, target.len() as u64);
    let existing = lookup(parent_ino, name);
    record_create_symlink(802, existing as u64, name.len() as u64);
    crate::harness_hooks::record_execve_stage(802, existing as u64, name.len() as u64);
    if existing != 0 {
        return 0;
    } // already exists
    let ino = alloc_inode(S_IFLNK | 0o777);
    record_create_symlink(803, ino as u64, 0);
    crate::harness_hooks::record_execve_stage(803, ino as u64, 0);
    if ino == 0 {
        return 0;
    }
    // Store target as the inode's data
    let off = alloc_data(target.len() as u32);
    record_create_symlink(804, off as u64, fs().data_cap as u64);
    crate::harness_hooks::record_execve_stage(804, off as u64, fs().data_cap as u64);
    if off == u32::MAX {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(target.as_ptr(), fs().data.add(off as usize), target.len());
    }
    record_create_symlink(805, off as u64, target.len() as u64);
    crate::harness_hooks::record_execve_stage(805, off as u64, target.len() as u64);
    inodes()[ino as usize].data_offset = off;
    inodes()[ino as usize].data_cap = target.len() as u32;
    inodes()[ino as usize].size = target.len() as u64;
    let added = add_dir_entry(parent_ino, name, ino);
    record_create_symlink(806, added as u64, ino as u64);
    crate::harness_hooks::record_execve_stage(806, added as u64, ino as u64);
    if !added {
        return 0;
    }
    record_create_symlink(807, ino as u64, 0);
    crate::harness_hooks::record_execve_stage(807, ino as u64, 0);
    ino
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
          inodes()[existing_target as usize].nlink = inodes()[existing_target as usize].nlink.saturating_sub(1);
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
        inodes()[old_parent_ino as usize].nlink = inodes()[old_parent_ino as usize].nlink.saturating_sub(1);
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

    let materialized = materialize_external_file_data(ino);
    if materialized < 0 {
        return materialized;
    }

    let end = offset as u32 + data.len() as u32;
    let data_cap = inodes()[idx].data_cap;

    if data_cap == 0 {
        let cap = end.max(4096);
        let off = alloc_data(cap);
        if off == u32::MAX {
            return ENOSPC;
        }
        let inode = &mut inodes()[idx];
        inode.data_offset = off;
        inode.data_cap = cap;
    } else if end > data_cap {
        let old_off = inodes()[idx].data_offset as usize;
        let old_size = inodes()[idx].size as usize;
        let new_cap = (end * 2).max(data_cap * 2);
        let new_off = alloc_data(new_cap);
        if new_off == u32::MAX {
            return ENOSPC;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                fs().data.add(old_off),
                fs().data.add(new_off as usize),
                old_size,
            );
        }
        let inode = &mut inodes()[idx];
        inode.data_offset = new_off;
        inode.data_cap = new_cap;
    }

    let base = inodes()[idx].data_offset as usize + offset as usize;
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), fs().data.add(base), data.len());
    }
    if end as u64 > inodes()[idx].size {
        inodes()[idx].size = end as u64;
    }
    data.len() as i64
}

pub fn read_file(ino: u32, offset: u64, buf: &mut [u8]) -> i64 {
    let inode = inodes()[ino as usize];
    if inode.mode & S_IFMT != S_IFREG {
        return EBADF;
    }
    if offset >= inode.size {
        return 0;
    }
    if inode.data_cap == 0 {
        return unsafe {
            tidemark_page_cache_read(ino, offset, buf.as_mut_ptr() as u32, buf.len() as u32)
        };
    }
    let avail = (inode.size - offset) as usize;
    let n = buf.len().min(avail);
    let base = inode.data_offset as usize + offset as usize;
    unsafe {
        core::ptr::copy_nonoverlapping(fs().data.add(base), buf.as_mut_ptr(), n);
    }
    n as i64
}

pub fn file_data_ptr(ino: u32) -> Option<u32> {
    let idx = ino as usize;
    let ins = inodes();
    if idx >= ins.len()
        || ins[idx].mode & S_IFMT != S_IFREG
        || ins[idx].size == 0
        || ins[idx].data_cap == 0
    {
        return None;
    }
    Some(fs().data as u32 + ins[idx].data_offset)
}

pub fn truncate(ino: u32, size: u64) -> i64 {
    let idx = ino as usize;
    if inodes()[idx].mode & S_IFMT != S_IFREG {
        return EINVAL;
    }
    let materialized = materialize_external_file_data(ino);
    if materialized < 0 {
        return materialized;
    }
    let old_size = inodes()[idx].size;
    let data_cap = inodes()[idx].data_cap as u64;

    if size > 0 && data_cap == 0 {
        let cap = (size as u32).max(4096);
        let off = alloc_data(cap);
        if off == u32::MAX {
            return ENOSPC;
        }
        let inode = &mut inodes()[idx];
        inode.data_offset = off;
        inode.data_cap = cap;
    } else if size > data_cap {
        let old_off = inodes()[idx].data_offset as usize;
        let new_cap = ((size as u32) * 2).max((data_cap as u32) * 2);
        let new_off = alloc_data(new_cap);
        if new_off == u32::MAX {
            return ENOSPC;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                fs().data.add(old_off),
                fs().data.add(new_off as usize),
                old_size as usize,
            );
        }
        let inode = &mut inodes()[idx];
        inode.data_offset = new_off;
        inode.data_cap = new_cap;
    }

    let data_offset = inodes()[idx].data_offset as usize;
    if size < old_size {
        let base = data_offset + size as usize;
        let len = old_size as usize - size as usize;
        unsafe {
            core::ptr::write_bytes(fs().data.add(base), 0, len);
        }
    } else if size > old_size {
        let base = data_offset + old_size as usize;
        let len = size as usize - old_size as usize;
        unsafe {
            core::ptr::write_bytes(fs().data.add(base), 0, len);
        }
    }
    inodes()[idx].size = size;
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
        unsafe { tidemark_page_cache_stat(ino, (&mut meta as *mut PageCacheMeta) as u32) };
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
    inodes()[idx].mode = file_type | (mode & 0o7777);
    0
}

pub fn set_owner(ino: u32, uid: Option<u32>, gid: Option<u32>) -> i64 {
    let idx = ino as usize;
    let ins = inodes();
    if idx >= ins.len() || ino == 0 {
        return ENOENT;
    }
    if let Some(uid) = uid {
        inodes()[idx].uid = uid;
    }
    if let Some(gid) = gid {
        inodes()[idx].gid = gid;
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
