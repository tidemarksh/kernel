//! In-memory filesystem (MemFS).
//!
//! Stores inode metadata, directory tree, and file data in the kernel
//! Worker's linear memory. Designed for later migration to SAB page cache
//! where thread-workers can read without kernel Worker round-trip.
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

// File mode bits (from Linux stat.h)
pub const S_IFMT: u32   = 0o170000;
pub const S_IFDIR: u32  = 0o040000;
pub const S_IFREG: u32  = 0o100000;
pub const S_IFLNK: u32  = 0o120000;
pub const S_IFCHR: u32  = 0o020000;

const MAX_INODES: usize = 256;
const INITIAL_DATA_SIZE: usize = 256 * 1024; // 256 KB initial, grows as needed
const MAX_NAME_LEN: usize = 255;

#[derive(Clone)]
struct Inode {
    mode: u32,
    nlink: u32,
    size: u64,
    data_offset: u32, // offset into data pool
    data_cap: u32,    // allocated capacity in data pool
    // directory: first_child, next_sibling, parent are stored separately
}

#[derive(Clone)]
struct DirEntry {
    name: [u8; MAX_NAME_LEN + 1],
    name_len: u16,
    ino: u32,
    next_sibling: u32, // 0 = none
}

/// In-memory filesystem state.
/// Data pool is a raw pointer + capacity to avoid stack allocation.
pub struct MemFs {
    inodes: [Inode; MAX_INODES],
    inode_count: u32,

    first_child: [u32; MAX_INODES],
    dir_entries: [DirEntry; MAX_INODES],
    dir_entry_count: u32,

    data_ptr: *mut u8,
    data_cap: u32,
    data_used: u32,
}

impl MemFs {
    /// Create a new empty filesystem with root directory (ino=1).
    /// `data_ptr` is a pre-allocated zeroed buffer of `data_cap` bytes.
    pub fn with_data(data_ptr: *mut u8, data_cap: u32) -> Self {
        let mut fs = Self {
            inodes: core::array::from_fn(|_| Inode {
                mode: 0, nlink: 0, size: 0, data_offset: 0, data_cap: 0,
            }),
            inode_count: 2,
            first_child: [0; MAX_INODES],
            dir_entries: core::array::from_fn(|_| DirEntry {
                name: [0; MAX_NAME_LEN + 1], name_len: 0, ino: 0, next_sibling: 0,
            }),
            dir_entry_count: 1,
            data_ptr,
            data_cap,
            data_used: 0,
        };
        fs.inodes[1] = Inode {
            mode: S_IFDIR | 0o755,
            nlink: 2,
            size: 0,
            data_offset: 0,
            data_cap: 0,
        };
        fs
    }

    /// Allocate a new inode. Returns inode number, or 0 on failure.
    fn alloc_inode(&mut self, mode: u32) -> u32 {
        let ino = self.inode_count as usize;
        if ino >= MAX_INODES { return 0; }
        self.inodes[ino] = Inode { mode, nlink: 1, size: 0, data_offset: 0, data_cap: 0 };
        self.inode_count += 1;
        ino as u32
    }

    fn data_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data_ptr, self.data_cap as usize) }
    }

    fn data_slice_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.data_ptr, self.data_cap as usize) }
    }

    fn alloc_data(&mut self, size: u32) -> u32 {
        let aligned = (size + 7) & !7;
        if self.data_used + aligned > self.data_cap { return u32::MAX; }
        let off = self.data_used;
        self.data_used += aligned;
        off
    }

    /// Look up a name in a directory. Returns inode number, or 0 if not found.
    pub fn lookup(&self, parent_ino: u32, name: &[u8]) -> u32 {
        let mut idx = self.first_child[parent_ino as usize];
        while idx != 0 {
            let de = &self.dir_entries[idx as usize];
            if de.name_len as usize == name.len()
                && &de.name[..name.len()] == name
            {
                return de.ino;
            }
            idx = de.next_sibling;
        }
        0
    }

    /// Resolve a path to an inode number. Handles absolute paths only.
    pub fn resolve_path(&self, path: &[u8]) -> u32 {
        if path.is_empty() || path[0] != b'/' { return 0; }
        let mut ino = 1u32; // root
        for component in path[1..].split(|&b| b == b'/') {
            if component.is_empty() { continue; }
            if component == b"." { continue; }
            if component == b".." {
                // TODO: parent tracking
                continue;
            }
            ino = self.lookup(ino, component);
            if ino == 0 { return 0; }
        }
        ino
    }

    /// Add a directory entry linking name → ino under parent_ino.
    fn add_dir_entry(&mut self, parent_ino: u32, name: &[u8], ino: u32) -> bool {
        let idx = self.dir_entry_count as usize;
        if idx >= MAX_INODES || name.len() > MAX_NAME_LEN { return false; }

        let de = &mut self.dir_entries[idx];
        de.name[..name.len()].copy_from_slice(name);
        de.name_len = name.len() as u16;
        de.ino = ino;
        de.next_sibling = self.first_child[parent_ino as usize];
        self.first_child[parent_ino as usize] = idx as u32;
        self.dir_entry_count += 1;
        true
    }

    /// Remove a directory entry by name from parent_ino. Returns the removed ino, or 0.
    fn remove_dir_entry(&mut self, parent_ino: u32, name: &[u8]) -> u32 {
        let mut prev_idx = 0u32;
        let mut idx = self.first_child[parent_ino as usize];
        let mut is_first = true;

        while idx != 0 {
            let de = &self.dir_entries[idx as usize];
            if de.name_len as usize == name.len() && &de.name[..name.len()] == name {
                let removed_ino = de.ino;
                let next = de.next_sibling;
                if is_first {
                    self.first_child[parent_ino as usize] = next;
                } else {
                    self.dir_entries[prev_idx as usize].next_sibling = next;
                }
                return removed_ino;
            }
            prev_idx = idx;
            idx = de.next_sibling;
            is_first = false;
        }
        0
    }

    /// Create a regular file. Returns inode number, or 0 on failure.
    pub fn create_file(&mut self, parent_ino: u32, name: &[u8], mode: u32) -> u32 {
        if self.lookup(parent_ino, name) != 0 { return 0; } // exists
        let ino = self.alloc_inode(S_IFREG | (mode & 0o7777));
        if ino == 0 { return 0; }
        if !self.add_dir_entry(parent_ino, name, ino) { return 0; }
        self.inodes[parent_ino as usize].nlink += 1;
        ino
    }

    /// Create a directory. Returns inode number, or 0 on failure.
    pub fn create_dir(&mut self, parent_ino: u32, name: &[u8], mode: u32) -> u32 {
        if self.lookup(parent_ino, name) != 0 { return 0; }
        let ino = self.alloc_inode(S_IFDIR | (mode & 0o7777));
        if ino == 0 { return 0; }
        self.inodes[ino as usize].nlink = 2; // . and parent link
        if !self.add_dir_entry(parent_ino, name, ino) { return 0; }
        self.inodes[parent_ino as usize].nlink += 1;
        ino
    }

    /// Remove a file (not directory). Returns 0 on success, or negative error.
    pub fn unlink(&mut self, parent_ino: u32, name: &[u8]) -> i64 {
        let ino = self.lookup(parent_ino, name);
        if ino == 0 { return ENOENT; }
        if self.inodes[ino as usize].mode & S_IFMT == S_IFDIR { return EISDIR; }
        self.remove_dir_entry(parent_ino, name);
        self.inodes[ino as usize].nlink -= 1;
        self.inodes[parent_ino as usize].nlink -= 1;
        0
    }

    /// Write data to a file. Grows the file if needed.
    pub fn write_file(&mut self, ino: u32, offset: u64, data: &[u8]) -> i64 {
        let idx = ino as usize;
        if self.inodes[idx].mode & S_IFMT != S_IFREG { return EBADF; }

        let end = offset as u32 + data.len() as u32;

        // Allocate or grow data
        if self.inodes[idx].data_cap == 0 {
            let cap = end.max(4096);
            let off = self.alloc_data(cap);
            if off == u32::MAX { return ENOSPC; }
            self.inodes[idx].data_offset = off;
            self.inodes[idx].data_cap = cap;
        } else if end > self.inodes[idx].data_cap {
            let old_off = self.inodes[idx].data_offset as usize;
            let old_size = self.inodes[idx].size as usize;
            let new_cap = (end * 2).max(self.inodes[idx].data_cap * 2);
            let new_off = self.alloc_data(new_cap);
            if new_off == u32::MAX { return ENOSPC; }
            self.data_slice_mut().copy_within(old_off..old_off + old_size, new_off as usize);
            self.inodes[idx].data_offset = new_off;
            self.inodes[idx].data_cap = new_cap;
        }

        let base = self.inodes[idx].data_offset as usize + offset as usize;
        self.data_slice_mut()[base..base + data.len()].copy_from_slice(data);
        if end as u64 > self.inodes[idx].size {
            self.inodes[idx].size = end as u64;
        }
        data.len() as i64
    }

    /// Read data from a file.
    pub fn read_file(&self, ino: u32, offset: u64, buf: &mut [u8]) -> i64 {
        let inode = &self.inodes[ino as usize];
        if inode.mode & S_IFMT != S_IFREG { return EBADF; }

        if offset >= inode.size { return 0; }
        let avail = (inode.size - offset) as usize;
        let n = buf.len().min(avail);
        let base = inode.data_offset as usize + offset as usize;
        buf[..n].copy_from_slice(&self.data_slice()[base..base + n]);
        n as i64
    }

    /// Truncate a file to the given size.
    pub fn truncate(&mut self, ino: u32, size: u64) -> i64 {
        let idx = ino as usize;
        if self.inodes[idx].mode & S_IFMT != S_IFREG { return EINVAL; }
        if size < self.inodes[idx].size {
            let base = self.inodes[idx].data_offset as usize + size as usize;
            let end = self.inodes[idx].data_offset as usize + self.inodes[idx].size as usize;
            self.data_slice_mut()[base..end].fill(0);
        }
        self.inodes[idx].size = size;
        0
    }

    /// Get inode metadata.
    pub fn stat(&self, ino: u32) -> Option<InodeStat> {
        if ino == 0 || ino as usize >= self.inode_count as usize { return None; }
        let inode = &self.inodes[ino as usize];
        Some(InodeStat {
            ino: ino as u64,
            mode: inode.mode,
            nlink: inode.nlink,
            size: inode.size,
        })
    }

    /// Iterate directory entries. Calls `cb` for each entry with (name, ino).
    /// Returns number of entries visited.
    pub fn readdir<F: FnMut(&[u8], u32)>(&self, dir_ino: u32, mut cb: F) -> i64 {
        let inode = &self.inodes[dir_ino as usize];
        if inode.mode & S_IFMT != S_IFDIR { return ENOTDIR; }

        let mut count = 0i64;
        let mut idx = self.first_child[dir_ino as usize];
        while idx != 0 {
            let de = &self.dir_entries[idx as usize];
            cb(&de.name[..de.name_len as usize], de.ino);
            count += 1;
            idx = de.next_sibling;
        }
        count
    }

    /// Convenience: create a file with initial content.
    pub fn create_file_with_data(&mut self, parent_ino: u32, name: &[u8], data: &[u8]) -> u32 {
        let ino = self.create_file(parent_ino, name, 0o644);
        if ino == 0 { return 0; }
        self.write_file(ino, 0, data);
        ino
    }
}

/// Subset of inode metadata returned by stat.
pub struct InodeStat {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub size: u64,
}

/// Global MemFS instance. Will move to kernel Worker allocation later.
static mut MEMFS: Option<MemFs> = None;

/// Initialize MemFS with a data pool at the given pointer.
/// In production, this is allocated via kernel Worker memory.grow.
pub fn init_with_data(data_ptr: *mut u8, data_cap: u32) {
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(MEMFS), Some(MemFs::with_data(data_ptr, data_cap))); }
}

pub fn get() -> &'static mut MemFs {
    unsafe { (*core::ptr::addr_of_mut!(MEMFS)).as_mut().expect("MemFS not initialized") }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_fs() -> (Vec<u8>, Box<MemFs>) {
        let mut data = vec![0u8; INITIAL_DATA_SIZE];
        let ptr = data.as_mut_ptr();
        let fs = Box::new(MemFs::with_data(ptr, INITIAL_DATA_SIZE as u32));
        (data, fs) // data must outlive fs
    }

    #[test]
    fn create_and_read() {
        let (_data, mut fs) = new_fs();
        let ino = fs.create_file(1, b"hello.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(fs.write_file(ino, 0, b"Hello, world!"), 13);

        let mut buf = [0u8; 32];
        let n = fs.read_file(ino, 0, &mut buf);
        assert_eq!(n, 13);
        assert_eq!(&buf[..13], b"Hello, world!");
    }

    #[test]
    fn directory_tree() {
        let (_data, mut fs) = new_fs();
        let dir = fs.create_dir(1, b"src", 0o755);
        assert!(dir > 0);
        let file = fs.create_file(dir, b"main.rs", 0o644);
        assert!(file > 0);

        assert_eq!(fs.resolve_path(b"/src/main.rs"), file);
        assert_eq!(fs.resolve_path(b"/src"), dir);
        assert_eq!(fs.resolve_path(b"/nonexistent"), 0);
    }

    #[test]
    fn unlink_file() {
        let (_data, mut fs) = new_fs();
        let ino = fs.create_file(1, b"tmp.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(fs.resolve_path(b"/tmp.txt"), ino);
        assert_eq!(fs.unlink(1, b"tmp.txt"), 0);
        assert_eq!(fs.resolve_path(b"/tmp.txt"), 0);
    }

    #[test]
    fn stat_file() {
        let (_data, mut fs) = new_fs();
        let ino = fs.create_file(1, b"data.bin", 0o644);
        fs.write_file(ino, 0, &[0u8; 1024]);

        let st = fs.stat(ino).unwrap();
        assert_eq!(st.size, 1024);
        assert_eq!(st.mode & S_IFREG, S_IFREG);
    }

    #[test]
    fn readdir_entries() {
        let (_data, mut fs) = new_fs();
        fs.create_file(1, b"a.txt", 0o644);
        fs.create_file(1, b"b.txt", 0o644);
        fs.create_dir(1, b"sub", 0o755);

        let mut count = 0;
        fs.readdir(1, |_name, _ino| { count += 1; });
        assert_eq!(count, 3);
    }

    #[test]
    fn truncate_file() {
        let (_data, mut fs) = new_fs();
        let ino = fs.create_file(1, b"f.txt", 0o644);
        fs.write_file(ino, 0, b"Hello, world!");
        assert_eq!(fs.stat(ino).unwrap().size, 13);

        fs.truncate(ino, 5);
        assert_eq!(fs.stat(ino).unwrap().size, 5);

        let mut buf = [0u8; 16];
        let n = fs.read_file(ino, 0, &mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"Hello");
    }

    #[test]
    fn write_at_offset() {
        let (_data, mut fs) = new_fs();
        let ino = fs.create_file(1, b"sparse.bin", 0o644);
        fs.write_file(ino, 100, b"data");
        assert_eq!(fs.stat(ino).unwrap().size, 104);

        let mut buf = [0u8; 4];
        fs.read_file(ino, 100, &mut buf);
        assert_eq!(&buf, b"data");
    }
}
