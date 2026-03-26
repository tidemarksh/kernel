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

pub const S_IFMT: u32   = 0o170000;
pub const S_IFDIR: u32  = 0o040000;
pub const S_IFREG: u32  = 0o100000;
pub const S_IFLNK: u32  = 0o120000;
pub const S_IFCHR: u32  = 0o020000;

const MAX_INODES: usize = 4096;
const MAX_NAME_LEN: usize = 255;
const INITIAL_DATA_SIZE: u32 = 256 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
struct Inode {
    mode: u32,
    nlink: u32,
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

fn fs() -> &'static mut MemFsHeader {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(MEMFS_PTR));
        &mut *p
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

fn data_slice() -> &'static [u8] {
    let h = fs();
    unsafe { core::slice::from_raw_parts(h.data, h.data_cap as usize) }
}

fn data_slice_mut() -> &'static mut [u8] {
    let h = fs();
    unsafe { core::slice::from_raw_parts_mut(h.data, h.data_cap as usize) }
}

/// Initialize MemFS. Allocates all data structures via alloc.rs.
pub fn init() {
    unsafe {
        let header_ptr = alloc::alloc_zeroed(
            core::mem::size_of::<MemFsHeader>() as u32,
            core::mem::align_of::<MemFsHeader>() as u32,
        );
        let inodes_ptr = alloc::alloc_zeroed(
            (MAX_INODES * core::mem::size_of::<Inode>()) as u32, 8,
        );
        let first_child_ptr = alloc::alloc_zeroed(
            (MAX_INODES * 4) as u32, 4,
        );
        let dir_entries_ptr = alloc::alloc_zeroed(
            (MAX_INODES * core::mem::size_of::<DirEntry>()) as u32, 4,
        );
        let data_ptr = alloc::alloc_zeroed(INITIAL_DATA_SIZE, 8);

        if header_ptr == 0 || inodes_ptr == 0 || first_child_ptr == 0
            || dir_entries_ptr == 0 || data_ptr == 0 {
            core::arch::wasm32::unreachable();
        }

        let h = &mut *(header_ptr as *mut MemFsHeader);
        h.inode_count = 2; // 0=unused, 1=root
        h.dir_entry_count = 1; // 0=unused
        h.data_used = 0;
        h.data_cap = INITIAL_DATA_SIZE;
        h.inodes = inodes_ptr as *mut Inode;
        h.first_child = first_child_ptr as *mut u32;
        h.dir_entries = dir_entries_ptr as *mut DirEntry;
        h.data = data_ptr as *mut u8;

        // Root directory (ino=1)
        let root = &mut *h.inodes.add(1);
        root.mode = S_IFDIR | 0o755;
        root.nlink = 2;

        core::ptr::write(core::ptr::addr_of_mut!(MEMFS_PTR), header_ptr as *mut MemFsHeader);
    }
}

// =========================================================================
// Allocation helpers
// =========================================================================

fn alloc_inode(mode: u32) -> u32 {
    let h = fs();
    let ino = h.inode_count as usize;
    if ino >= MAX_INODES { return 0; }
    inodes()[ino] = Inode { mode, nlink: 1, size: 0, data_offset: 0, data_cap: 0 };
    h.inode_count += 1;
    ino as u32
}

fn alloc_data(size: u32) -> u32 {
    let h = fs();
    let aligned = (size + 7) & !7;
    if h.data_used + aligned > h.data_cap { return u32::MAX; }
    let off = h.data_used;
    h.data_used += aligned;
    off
}

// =========================================================================
// Directory operations
// =========================================================================

pub fn lookup(parent_ino: u32, name: &[u8]) -> u32 {
    let fc = first_child();
    let des = dir_entries();
    let mut idx = fc[parent_ino as usize];
    while idx != 0 {
        let de = &des[idx as usize];
        if de.name_len as usize == name.len() && &de.name[..name.len()] == name {
            return de.ino;
        }
        idx = de.next_sibling;
    }
    0
}

pub fn resolve_path(path: &[u8]) -> u32 {
    if path.is_empty() || path[0] != b'/' { return 0; }
    let mut ino = 1u32;
    for component in path[1..].split(|&b| b == b'/') {
        if component.is_empty() || component == b"." { continue; }
        ino = lookup(ino, component);
        if ino == 0 { return 0; }
    }
    ino
}

fn add_dir_entry(parent_ino: u32, name: &[u8], ino: u32) -> bool {
    let h = fs();
    let idx = h.dir_entry_count as usize;
    if idx >= MAX_INODES || name.len() > MAX_NAME_LEN { return false; }

    let des = dir_entries();
    des[idx].name[..name.len()].copy_from_slice(name);
    des[idx].name_len = name.len() as u16;
    des[idx].ino = ino;
    des[idx].next_sibling = first_child()[parent_ino as usize];
    first_child()[parent_ino as usize] = idx as u32;
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

// =========================================================================
// File/directory CRUD
// =========================================================================

pub fn create_file(parent_ino: u32, name: &[u8], mode: u32) -> u32 {
    if lookup(parent_ino, name) != 0 { return 0; }
    let ino = alloc_inode(S_IFREG | (mode & 0o7777));
    if ino == 0 { return 0; }
    if !add_dir_entry(parent_ino, name, ino) { return 0; }
    inodes()[parent_ino as usize].nlink += 1;
    ino
}

pub fn create_dir(parent_ino: u32, name: &[u8], mode: u32) -> u32 {
    if lookup(parent_ino, name) != 0 { return 0; }
    let ino = alloc_inode(S_IFDIR | (mode & 0o7777));
    if ino == 0 { return 0; }
    inodes()[ino as usize].nlink = 2;
    if !add_dir_entry(parent_ino, name, ino) { return 0; }
    inodes()[parent_ino as usize].nlink += 1;
    ino
}

pub fn unlink(parent_ino: u32, name: &[u8]) -> i64 {
    let ino = lookup(parent_ino, name);
    if ino == 0 { return ENOENT; }
    if inodes()[ino as usize].mode & S_IFMT == S_IFDIR { return EISDIR; }
    remove_dir_entry(parent_ino, name);
    inodes()[ino as usize].nlink -= 1;
    inodes()[parent_ino as usize].nlink -= 1;
    0
}

// =========================================================================
// File I/O
// =========================================================================

pub fn write_file(ino: u32, offset: u64, data: &[u8]) -> i64 {
    let idx = ino as usize;
    let ins = inodes();
    if ins[idx].mode & S_IFMT != S_IFREG { return EBADF; }

    let end = offset as u32 + data.len() as u32;

    if ins[idx].data_cap == 0 {
        let cap = end.max(4096);
        let off = alloc_data(cap);
        if off == u32::MAX { return ENOSPC; }
        inodes()[idx].data_offset = off;
        inodes()[idx].data_cap = cap;
    } else if end > ins[idx].data_cap {
        let old_off = ins[idx].data_offset as usize;
        let old_size = ins[idx].size as usize;
        let new_cap = (end * 2).max(ins[idx].data_cap * 2);
        let new_off = alloc_data(new_cap);
        if new_off == u32::MAX { return ENOSPC; }
        data_slice_mut().copy_within(old_off..old_off + old_size, new_off as usize);
        inodes()[idx].data_offset = new_off;
        inodes()[idx].data_cap = new_cap;
    }

    let base = inodes()[idx].data_offset as usize + offset as usize;
    data_slice_mut()[base..base + data.len()].copy_from_slice(data);
    if end as u64 > inodes()[idx].size {
        inodes()[idx].size = end as u64;
    }
    data.len() as i64
}

pub fn read_file(ino: u32, offset: u64, buf: &mut [u8]) -> i64 {
    let ins = inodes();
    let inode = &ins[ino as usize];
    if inode.mode & S_IFMT != S_IFREG { return EBADF; }
    if offset >= inode.size { return 0; }
    let avail = (inode.size - offset) as usize;
    let n = buf.len().min(avail);
    let base = inode.data_offset as usize + offset as usize;
    buf[..n].copy_from_slice(&data_slice()[base..base + n]);
    n as i64
}

pub fn truncate(ino: u32, size: u64) -> i64 {
    let idx = ino as usize;
    let ins = inodes();
    if ins[idx].mode & S_IFMT != S_IFREG { return EINVAL; }
    if size < ins[idx].size {
        let base = ins[idx].data_offset as usize + size as usize;
        let end = ins[idx].data_offset as usize + ins[idx].size as usize;
        data_slice_mut()[base..end].fill(0);
    }
    inodes()[idx].size = size;
    0
}

/// Subset of inode metadata returned by stat.
pub struct InodeStat {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub size: u64,
}

pub fn stat(ino: u32) -> Option<InodeStat> {
    let h = fs();
    if ino == 0 || ino as usize >= h.inode_count as usize { return None; }
    let inode = &inodes()[ino as usize];
    Some(InodeStat { ino: ino as u64, mode: inode.mode, nlink: inode.nlink, size: inode.size })
}

pub fn readdir<F: FnMut(&[u8], u32)>(dir_ino: u32, mut cb: F) -> i64 {
    if inodes()[dir_ino as usize].mode & S_IFMT != S_IFDIR { return ENOTDIR; }
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
    if ino == 0 { return 0; }
    write_file(ino, 0, data);
    ino
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::TestVm;

    #[test]
    fn create_and_read() {
        let _ = TestVm::new();
        let ino = create_file(1, b"hello.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(write_file(ino, 0, b"Hello, world!"), 13);

        let mut buf = [0u8; 32];
        let n = read_file(ino, 0, &mut buf);
        assert_eq!(n, 13);
        assert_eq!(&buf[..13], b"Hello, world!");
    }

    #[test]
    fn directory_tree() {
        let _ = TestVm::new();
        let dir = create_dir(1, b"src", 0o755);
        assert!(dir > 0);
        let file = create_file(dir, b"main.rs", 0o644);
        assert!(file > 0);

        assert_eq!(resolve_path(b"/src/main.rs"), file);
        assert_eq!(resolve_path(b"/src"), dir);
        assert_eq!(resolve_path(b"/nonexistent"), 0);
    }

    #[test]
    fn unlink_file() {
        let _ = TestVm::new();
        let ino = create_file(1, b"tmp.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(resolve_path(b"/tmp.txt"), ino);
        assert_eq!(unlink(1, b"tmp.txt"), 0);
        assert_eq!(resolve_path(b"/tmp.txt"), 0);
    }

    #[test]
    fn stat_file() {
        let _ = TestVm::new();
        let ino = create_file(1, b"data.bin", 0o644);
        write_file(ino, 0, &[0u8; 1024]);
        let st = stat(ino).unwrap();
        assert_eq!(st.size, 1024);
        assert_eq!(st.mode & S_IFREG, S_IFREG);
    }

    #[test]
    fn readdir_entries() {
        let _ = TestVm::new();
        create_file(1, b"a.txt", 0o644);
        create_file(1, b"b.txt", 0o644);
        create_dir(1, b"sub", 0o755);
        let mut count = 0;
        readdir(1, |_name, _ino| { count += 1; });
        assert_eq!(count, 3);
    }

    #[test]
    fn truncate_file() {
        let _ = TestVm::new();
        let ino = create_file(1, b"f.txt", 0o644);
        write_file(ino, 0, b"Hello, world!");
        assert_eq!(stat(ino).unwrap().size, 13);
        truncate(ino, 5);
        assert_eq!(stat(ino).unwrap().size, 5);
        let mut buf = [0u8; 16];
        let n = read_file(ino, 0, &mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"Hello");
    }

    #[test]
    fn write_at_offset() {
        let _ = TestVm::new();
        let ino = create_file(1, b"sparse.bin", 0o644);
        write_file(ino, 100, b"data");
        assert_eq!(stat(ino).unwrap().size, 104);
        let mut buf = [0u8; 4];
        read_file(ino, 100, &mut buf);
        assert_eq!(&buf, b"data");
    }
}
