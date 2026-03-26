//! FS syscalls: openat, read, write, stat, mkdir, unlink, rename, getdents64.
//!
//! Struct layouts (RV64):
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
//!
//! struct linux_dirent64 {               // variable size
//!     d_ino:    u64,                    // offset 0
//!     d_off:    i64,                    // offset 8
//!     d_reclen: u16,                    // offset 16
//!     d_type:   u8,                     // offset 18
//!     d_name:   [u8],                   // offset 19 (null-terminated)
//! };
//! https://man7.org/linux/man-pages/man2/getdents.2.html

use crate::abi::*;
use crate::fs::{memfs, fd_table};
use crate::guest_mem;
use crate::syscall::signal;
use crate::types::ThreadState;

const AT_FDCWD: i32 = -100;
const DT_UNKNOWN: u8 = 0;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;

// =========================================================================
// Path resolution helper
// =========================================================================

fn resolve_at(dirfd: u64, path_addr: u64, base: u32) -> u32 {
    let mut path_buf = [0u8; 512];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf) };
    let path = &path_buf[..len];

    if path.is_empty() { return 0; }

    if path[0] == b'/' {
        memfs::resolve_path(path)
    } else if dirfd as i32 == AT_FDCWD {
        // Relative to CWD — resolve from root for now (CWD tracking is later)
        let mut full = [0u8; 513];
        full[0] = b'/';
        full[1..1 + len].copy_from_slice(path);
        memfs::resolve_path(&full[..1 + len])
    } else {
        0 // dirfd-relative: not yet supported
    }
}

// =========================================================================
// openat
// =========================================================================

/// openat: open or create a file. Supports O_CREAT, O_TRUNC.
/// Path resolution via MemFS (absolute or AT_FDCWD-relative).
pub fn sys_openat(vm: &mut ThreadState, base: u32, dirfd: u64, path_addr: u64, flags: u64, mode: u64) -> i64 {
    let oflags = flags as i32;
    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let path = &path_buf[1..1 + len];

    if path.is_empty() { return ENOENT; }

    // Make absolute
    let (abs_path, abs_len) = if path[0] == b'/' {
        (&path_buf[1..1 + len], len)
    } else if dirfd as i32 == AT_FDCWD {
        path_buf[0] = b'/';
        (&path_buf[..1 + len], 1 + len)
    } else {
        return EINVAL;
    };

    let (parent_ino, name) = split_parent_name(&abs_path[..abs_len]);

    if parent_ino == 0 && name.is_empty() {
        return fd_table::open_file(vm, base, 1, oflags);
    }
    if parent_ino == 0 { return ENOENT; }

    let mut ino = memfs::lookup(parent_ino, name);

    if ino == 0 {
        if oflags & O_CREAT != 0 {
            ino = memfs::create_file(parent_ino, name, mode as u32 & 0o7777);
            if ino == 0 { return ENOSPC; }
        } else {
            return ENOENT;
        }
    }

    if oflags & O_TRUNC != 0 {
        memfs::truncate(ino, 0);
    }

    fd_table::open_file(vm, base, ino, oflags)
}

fn split_parent_name(path: &[u8]) -> (u32, &[u8]) {
    if path == b"/" { return (0, &[]); }

    // Find last '/'
    let mut last_slash = 0;
    for i in (0..path.len()).rev() {
        if path[i] == b'/' { last_slash = i; break; }
    }

    let parent_path = if last_slash == 0 { b"/" as &[u8] } else { &path[..last_slash] };
    let name = &path[last_slash + 1..];

    let parent_ino = memfs::resolve_path(parent_path);
    (parent_ino, name)
}

// =========================================================================
// read / pread64
// =========================================================================

/// read: read from file or pipe FD. Advances OFD offset for files.
pub fn sys_read(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64) -> i64 {
    if fd <= 2 { return 0; }

    let ofd = match fd_table::get_ofd(vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_PIPE {
        let mut tmp = [0u8; 4096];
        let to_read = (count as usize).min(tmp.len());
        let n = super::pipe::pipe_read(ofd.ino, &mut tmp[..to_read]);
        if n > 0 {
            unsafe { guest_mem::write_bytes(base, buf, &tmp[..n as usize]); }
        }
        return n;
    }

    let mut tmp = [0u8; 4096];
    let to_read = (count as usize).min(tmp.len());
    let n = memfs::read_file(ofd.ino as u32, ofd.offset as u64, &mut tmp[..to_read]);
    if n > 0 {
        unsafe { guest_mem::write_bytes(base, buf, &tmp[..n as usize]); }
        fd_table::advance_offset(vm, fd, n as u64);
    }
    n
}

/// pread64: read at specified offset without changing OFD offset.
pub fn sys_pread64(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64, offset: u64) -> i64 {
    let ofd = match fd_table::get_ofd(vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let mut tmp = [0u8; 4096];
    let to_read = (count as usize).min(tmp.len());
    let n = memfs::read_file(ofd.ino as u32, offset, &mut tmp[..to_read]);
    if n > 0 {
        unsafe { guest_mem::write_bytes(base, buf, &tmp[..n as usize]); }
    }
    n
}

// =========================================================================
// pwrite64
// =========================================================================

/// pwrite64: write at specified offset without changing OFD offset.
pub fn sys_pwrite64(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64, offset: u64) -> i64 {
    let ofd = match fd_table::get_ofd(vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let mut tmp = [0u8; 4096];
    let to_write = (count as usize).min(tmp.len());
    unsafe { guest_mem::read_bytes(base, buf, &mut tmp[..to_write]); }
    memfs::write_file(ofd.ino as u32, offset, &tmp[..to_write])
}

// =========================================================================
// write / writev
// =========================================================================

/// write: write to file or pipe FD. Sends SIGPIPE on broken pipe.
/// Also handles writev (dispatched by nr == SYS_WRITEV).
pub fn sys_write(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64, nr: u64) -> i64 {
    if nr == SYS_WRITEV { return sys_writev(vm, base, fd, buf, count); }
    if fd == 1 || fd == 2 { return count as i64; }

    let ofd = match fd_table::get_ofd(vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_PIPE {
        let mut tmp = [0u8; 4096];
        let to_write = (count as usize).min(tmp.len());
        unsafe { guest_mem::read_bytes(base, buf, &mut tmp[..to_write]); }
        let n = super::pipe::pipe_write(ofd.ino, &tmp[..to_write]);
        if n == EPIPE {
            signal::send_signal(vm, SIGPIPE);
        }
        return n;
    }

    let mut tmp = [0u8; 4096];
    let to_write = (count as usize).min(tmp.len());
    unsafe { guest_mem::read_bytes(base, buf, &mut tmp[..to_write]); }
    let n = memfs::write_file(ofd.ino as u32, ofd.offset as u64, &tmp[..to_write]);
    if n > 0 {
        fd_table::advance_offset(vm, fd, n as u64);
    }
    n
}

fn sys_writev(vm: &mut ThreadState, base: u32, fd: u64, iov_addr: u64, iovcnt: u64) -> i64 {
    if fd == 1 || fd == 2 {
        let mut total = 0u64;
        for i in 0..iovcnt {
            let len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
            total += len;
        }
        return total as i64;
    }

    let ofd = match fd_table::get_ofd(vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let mut total = 0i64;
    for i in 0..iovcnt {
        let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * 16) };
        let iov_len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
        if iov_len == 0 { continue; }

        if ofd.fd_type == FD_TYPE_PIPE {
            let mut tmp = [0u8; 4096];
            let to_write = (iov_len as usize).min(tmp.len());
            unsafe { guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]); }
            let n = super::pipe::pipe_write(ofd.ino, &tmp[..to_write]);
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                if total == 0 { return EPIPE; }
                return total;
            }
            if n < 0 {
                if total > 0 { return total; }
                return n;
            }
            total += n;
        } else {
            let mut tmp = [0u8; 4096];
            let to_write = (iov_len as usize).min(tmp.len());
            unsafe { guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]); }
            let current_offset = fd_table::get_offset(vm, fd);
            let n = memfs::write_file(ofd.ino as u32, current_offset, &tmp[..to_write]);
            if n > 0 {
                fd_table::advance_offset(vm, fd, n as u64);
            }
            if n < 0 {
                if total > 0 { return total; }
                return n;
            }
            total += n;
        }
    }
    total
}

// =========================================================================
// fstat / newfstatat
// =========================================================================

/// fstat: get file status by FD. Writes 128-byte struct stat to guest memory.
pub fn sys_fstat(vm: &mut ThreadState, base: u32, fd: u64, stat_buf: u64) -> i64 {
    let ofd = match fd_table::get_ofd(vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    write_stat(base, stat_buf, ofd.ino as u32)
}

/// newfstatat: get file status by path. Writes 128-byte struct stat to guest memory.
pub fn sys_newfstatat(_vm: &mut ThreadState, base: u32, dirfd: u64, path_addr: u64, stat_buf: u64, _flags: u64) -> i64 {
    let ino = resolve_at(dirfd, path_addr, base);
    if ino == 0 { return ENOENT; }
    write_stat(base, stat_buf, ino)
}

fn write_stat(base: u32, stat_buf: u64, ino: u32) -> i64 {
    let st = match memfs::stat(ino) {
        Some(s) => s,
        None => return ENOENT,
    };
    unsafe {
        guest_mem::zero_mem(base, stat_buf, 128);
        guest_mem::write_u64(base, stat_buf + 0, 1);              // st_dev
        guest_mem::write_u64(base, stat_buf + 8, st.ino);         // st_ino
        guest_mem::write_u32(base, stat_buf + 16, st.mode);       // st_mode
        guest_mem::write_u32(base, stat_buf + 20, st.nlink);      // st_nlink
        guest_mem::write_u32(base, stat_buf + 24, 0);             // st_uid
        guest_mem::write_u32(base, stat_buf + 28, 0);             // st_gid
        guest_mem::write_u64(base, stat_buf + 48, st.size);       // st_size
        guest_mem::write_u32(base, stat_buf + 56, 4096u32);       // st_blksize
        let blocks = (st.size + 511) / 512;
        guest_mem::write_u64(base, stat_buf + 64, blocks);        // st_blocks
    }
    0
}

// =========================================================================
// mkdir / unlink / rename
// =========================================================================

/// mkdirat: create a directory.
pub fn sys_mkdirat(_vm: &mut ThreadState, base: u32, dirfd: u64, path_addr: u64, mode: u64) -> i64 {
    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let path = &path_buf[1..1 + len];
    if path.is_empty() { return ENOENT; }

    let abs_path = if path[0] == b'/' {
        &path_buf[1..1 + len]
    } else if dirfd as i32 == AT_FDCWD {
        path_buf[0] = b'/';
        &path_buf[..1 + len]
    } else {
        return EINVAL;
    };
    let (parent_ino, name) = split_parent_name(abs_path);
    if parent_ino == 0 { return ENOENT; }
    let ino = memfs::create_dir(parent_ino, name, mode as u32 & 0o7777);
    if ino == 0 { return EEXIST; }
    0
}

/// unlinkat: remove a file entry from its parent directory.
pub fn sys_unlinkat(_vm: &mut ThreadState, base: u32, dirfd: u64, path_addr: u64, _flags: u64) -> i64 {
    let ino = resolve_at(dirfd, path_addr, base);
    if ino == 0 { return ENOENT; }

    let mut path_buf = [0u8; 512];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf) };
    let path = &path_buf[..len];
    let (parent_ino, name) = split_parent_name(if path[0] == b'/' { path } else { return EINVAL; });
    if parent_ino == 0 { return ENOENT; }
    memfs::unlink(parent_ino, name)
}

// =========================================================================
// getdents64
// =========================================================================

/// getdents64: read directory entries into guest buffer.
/// Writes linux_dirent64 records (variable-size, 8-byte aligned).
pub fn sys_getdents64(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, buf_size: u64) -> i64 {
    let ofd = match fd_table::get_ofd(vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let dir_ino = ofd.ino as u32;
    let mut offset = 0u64;
    let max = buf_size;

    memfs::readdir(dir_ino, |name, ino| {
        // d_reclen = 19 + name_len + 1 (null) + padding to 8-byte align
        let reclen = ((19 + name.len() + 1) + 7) & !7;
        if offset + reclen as u64 > max { return; }

        let entry_addr = buf + offset;
        unsafe {
            guest_mem::write_u64(base, entry_addr, ino as u64);     // d_ino
            guest_mem::write_u64(base, entry_addr + 8, offset + reclen as u64); // d_off
            guest_mem::write_u16(base, entry_addr + 16, reclen as u16); // d_reclen

            let st = memfs::stat(ino);
            let d_type = match st {
                Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFDIR => DT_DIR,
                Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFREG => DT_REG,
                _ => DT_UNKNOWN,
            };
            guest_mem::write_u8(base, entry_addr + 18, d_type);    // d_type
            guest_mem::write_bytes(base, entry_addr + 19, name);   // d_name
            guest_mem::write_u8(base, entry_addr + 19 + name.len() as u64, 0); // null terminator
        }
        offset += reclen as u64;
    });

    offset as i64
}

// =========================================================================
// lseek
// =========================================================================

/// lseek: reposition OFD offset. Supports SEEK_SET (0), SEEK_CUR (1), SEEK_END (2).
pub fn sys_lseek(vm: &mut ThreadState, _base: u32, fd: u64, offset: i64, whence: u64) -> i64 {
    let ofd = match fd_table::get_ofd(vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let new_offset = match whence {
        0 => offset as u64,                              // SEEK_SET
        1 => (ofd.offset as i64 + offset) as u64,        // SEEK_CUR
        2 => {                                            // SEEK_END
            let st = memfs::stat(ofd.ino as u32);
            match st {
                Some(s) => (s.size as i64 + offset) as u64,
                None => return EINVAL,
            }
        }
        _ => return EINVAL,
    };

    fd_table::set_offset(vm, fd, new_offset);
    new_offset as i64
}

// =========================================================================
// faccessat / readlinkat / ftruncate
// =========================================================================

/// faccessat: check file accessibility (existence check only).
pub fn sys_faccessat(_vm: &mut ThreadState, base: u32, dirfd: u64, path_addr: u64, _mode: u64) -> i64 {
    let ino = resolve_at(dirfd, path_addr, base);
    if ino == 0 { ENOENT } else { 0 }
}

/// readlinkat: read symbolic link. Handles /proc/self/exe for Go runtime.
/// No general symlink support in MemFS yet.
pub fn sys_readlinkat(_vm: &mut ThreadState, base: u32, _dirfd: u64, path_addr: u64, buf: u64, bufsiz: u64) -> i64 {
    let mut path_buf = [0u8; 512];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf) };
    let path = &path_buf[..len];

    // Handle /proc/self/exe — Go runtime reads this to find its own binary.
    if path == b"/proc/self/exe" {
        let result = b"/init";
        let n = (result.len()).min(bufsiz as usize);
        unsafe { guest_mem::write_bytes(base, buf, &result[..n]); }
        return n as i64;
    }

    EINVAL // no symlinks in memfs
}

/// ftruncate: truncate file to specified length.
pub fn sys_ftruncate(vm: &mut ThreadState, _base: u32, fd: u64, length: u64) -> i64 {
    let ofd = match fd_table::get_ofd(vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    memfs::truncate(ofd.ino as u32, length)
}

#[cfg(test)]
mod tests {
    use crate::abi::*;
    use crate::test_helpers::TestVm;

    #[test]
    fn fs_syscalls() {
        let mut t = TestVm::new();

        // --- openat / read / write ---

        // openat with O_CREAT | O_RDWR
        let fd = t.sys_openat(b"/test.txt", O_CREAT | O_RDWR);
        assert!(fd >= 3, "openat should return fd >= 3, got {}", fd);

        // write
        let written = t.sys_write_data(fd, b"Hello FS!");
        assert_eq!(written, 9);

        // lseek to beginning
        let pos = t.sys_lseek(fd, 0, 0);
        assert_eq!(pos, 0);

        // read
        let mut buf = [0u8; 16];
        let nread = t.sys_read(fd, &mut buf);
        assert_eq!(nread, 9);
        assert_eq!(&buf[..9], b"Hello FS!");

        // fstat
        let stat_addr = t.scratch + 0x3000;
        let ret = t.sys_fstat(fd, stat_addr);
        assert_eq!(ret, 0);
        let size = unsafe { crate::guest_mem::read_u64(t.base, stat_addr + 48) };
        assert_eq!(size, 9);

        // close
        let ret2 = t.sys_close(fd);
        assert_eq!(ret2, 0);

        // --- mkdir / getdents ---

        // Create /mydir
        let ret = t.sys_mkdirat(b"/mydir");
        assert_eq!(ret, 0);

        // Create files in /mydir
        let fd_a = t.sys_openat(b"/mydir/a.txt", O_CREAT | O_RDWR);
        assert!(fd_a >= 3);
        t.sys_close(fd_a);

        let fd_b = t.sys_openat(b"/mydir/b.txt", O_CREAT | O_RDWR);
        assert!(fd_b >= 3);
        t.sys_close(fd_b);

        // Open /mydir as directory
        let dir_fd = t.sys_openat(b"/mydir", O_RDONLY);
        assert!(dir_fd >= 3);

        // getdents64
        let dents_buf = t.scratch + 0x4000;
        let n = t.sys_getdents64(dir_fd, dents_buf, 4096);
        assert!(n > 0, "getdents64 should return > 0 bytes, got {}", n);
    }
}
