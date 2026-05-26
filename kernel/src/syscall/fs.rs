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
use crate::fs::{fd_table, memfs};
use crate::guest_mem;
use crate::types::ThreadState;

mod meta;
mod mutation;
mod open;
mod path;
mod pending;
mod read_write;
mod state;

const AT_FDCWD: i32 = -100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const PENDING_FS_PATH_MAX: usize = 4096;
const DT_UNKNOWN: u8 = 0;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;
const MAX_PATH_SYMLINK_FOLLOWS: u32 = 40;
pub const FS_EFFECT_MEMFS_MUTATION: u32 = 1 << 0;
pub const FS_EFFECT_SHARED_OFD_STATE: u32 = 1 << 1;
pub const FS_EFFECT_MEMFS_FILE_DATA: u32 = 1 << 2;
pub use meta::{
    sys_faccessat, sys_fchmod, sys_fchmodat, sys_fchown, sys_fchownat, sys_fstat, sys_ftruncate,
    sys_newfstatat, sys_readlinkat, sys_statfs, sys_truncate, sys_utimensat,
};
pub use mutation::{sys_mkdirat, sys_renameat, sys_renameat2, sys_unlinkat};
pub use open::sys_openat;
use path::resolve_at;
pub use pending::{
    dispatch_fstat, dispatch_ftruncate, dispatch_getdents64, dispatch_lseek, dispatch_mkdirat,
    dispatch_openat, dispatch_pwrite64, dispatch_renameat2, dispatch_truncate, dispatch_unlinkat,
    dispatch_write, pending_request_absolute_path, pending_request_effects, pending_request_opcode,
    pending_request_path_len, pending_request_path_ptr, pending_request_secondary_absolute_path,
    pending_request_target_ino, process_pending_requests, resume_from_fs,
};
pub(crate) use read_write::PIPE_READ_EOF_SYNC_RETRY_MARKER;
use read_write::mark_fork_shared_ofd_sync_effect;
pub use read_write::{sys_pread64, sys_pwrite64, sys_read, sys_readv, sys_write};
pub(crate) use state::sys_umask;
use state::{current_dir_ino, set_current_dir_ino};

// =========================================================================
// Path resolution helper
// =========================================================================

pub fn sys_getcwd(vm: &ThreadState, base: u32, buf: u64, size: u64) -> i64 {
    let mut path = [0u8; 512];
    let len = memfs::write_path(current_dir_ino(base, vm), &mut path);
    if len == 0 {
        return ENOENT;
    }
    if len as u64 + 1 > size {
        return ERANGE;
    }
    unsafe {
        guest_mem::write_bytes(base, buf, &path[..len]);
        guest_mem::write_u8(base, buf + len as u64, 0);
    }
    (len as i64) + 1
}

pub fn sys_chdir(vm: &mut ThreadState, base: u32, path_addr: u64) -> i64 {
    let ino = match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(ino) => ino,
        Err(errno) => return errno,
    };
    let st = match memfs::stat(ino) {
        Some(st) => st,
        None => return ENOENT,
    };
    if st.mode & memfs::S_IFMT != memfs::S_IFDIR {
        return ENOTDIR;
    }
    set_current_dir_ino(base, vm, ino);
    0
}

/// chroot(2) changes the process root directory.
/// https://man7.org/linux/man-pages/man2/chroot.2.html
///
/// Tidemark does not currently track per-process root directories. Returning
/// success would lie about path resolution semantics, so expose the syscall as
/// unavailable after normal path/type validation.
pub fn sys_chroot(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
    let ino = match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(ino) => ino,
        Err(errno) => return errno,
    };
    let st = match memfs::stat(ino) {
        Some(st) => st,
        None => return ENOENT,
    };
    if st.mode & memfs::S_IFMT != memfs::S_IFDIR {
        return ENOTDIR;
    }
    ENOSYS
}

/// umount2(2) unmounts a mount point.
/// https://man7.org/linux/man-pages/man2/umount.2.html
///
/// Tidemark has no guest mount table yet. Existing paths are therefore not
/// mount points; Linux reports EINVAL for a target that is not mounted.
pub fn sys_umount2(vm: &ThreadState, base: u32, path_addr: u64, _flags: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => EINVAL,
        Err(errno) => errno,
    }
}

/// mount(2) mounts a filesystem.
/// https://man7.org/linux/man-pages/man2/mount.2.html
///
/// Tidemark has no guest mount table or CAP_SYS_ADMIN model. Linux rejects
/// unprivileged mount attempts with EPERM, which lets feature probes continue
/// without pretending the syscall number is absent.
pub fn sys_mount(
    _vm: &ThreadState,
    _base: u32,
    _source_addr: u64,
    _target_addr: u64,
    _filesystemtype_addr: u64,
    _mountflags: u64,
    _data_addr: u64,
) -> i64 {
    EPERM
}

/// xattr syscalls.
/// https://man7.org/linux/man-pages/man7/xattr.7.html
/// https://man7.org/linux/man-pages/man2/setxattr.2.html
/// https://man7.org/linux/man-pages/man2/getxattr.2.html
/// https://man7.org/linux/man-pages/man2/listxattr.2.html
/// https://man7.org/linux/man-pages/man2/removexattr.2.html
///
/// MemFS does not store extended attributes. Existing objects behave like a
/// filesystem without xattr support: setting is not supported, getting/removing
/// a missing attribute reports ENODATA, and listing returns an empty list.
pub fn sys_setxattr(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => EOPNOTSUPP,
        Err(errno) => errno,
    }
}

pub fn sys_fsetxattr(vm: &ThreadState, base: u32, fd: u64) -> i64 {
    if fd_table::get_ofd(base, vm, fd).is_none() {
        return EBADF;
    }
    EOPNOTSUPP
}

pub fn sys_getxattr(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => ENODATA,
        Err(errno) => errno,
    }
}

pub fn sys_fgetxattr(vm: &ThreadState, base: u32, fd: u64) -> i64 {
    if fd_table::get_ofd(base, vm, fd).is_none() {
        return EBADF;
    }
    ENODATA
}

pub fn sys_listxattr(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => 0,
        Err(errno) => errno,
    }
}

pub fn sys_flistxattr(vm: &ThreadState, base: u32, fd: u64) -> i64 {
    if fd_table::get_ofd(base, vm, fd).is_none() {
        return EBADF;
    }
    0
}

pub fn sys_removexattr(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => ENODATA,
        Err(errno) => errno,
    }
}

pub fn sys_fremovexattr(vm: &ThreadState, base: u32, fd: u64) -> i64 {
    if fd_table::get_ofd(base, vm, fd).is_none() {
        return EBADF;
    }
    ENODATA
}

// =========================================================================
// getdents64
// =========================================================================

fn write_dirent64(
    base: u32,
    buf: u64,
    offset: u64,
    max: u64,
    ino: u64,
    d_type: u8,
    name: &[u8],
) -> Option<u64> {
    // d_reclen = 19 + name_len + 1 (NUL) + padding to 8-byte alignment.
    let reclen = ((19 + name.len() + 1) + 7) & !7;
    if offset + reclen as u64 > max {
        return None;
    }

    let entry_addr = buf + offset;
    unsafe {
        guest_mem::zero_mem(base, entry_addr, reclen);
        guest_mem::write_u64(base, entry_addr, ino);
        guest_mem::write_u64(base, entry_addr + 8, offset + reclen as u64);
        guest_mem::write_u16(base, entry_addr + 16, reclen as u16);
        guest_mem::write_u8(base, entry_addr + 18, d_type);
        guest_mem::write_bytes(base, entry_addr + 19, name);
        guest_mem::write_u8(base, entry_addr + 19 + name.len() as u64, 0);
    }
    Some(reclen as u64)
}

fn proc_self_fd_dir_ino() -> u32 {
    memfs::resolve_path(b"/proc/self/fd")
}

fn u32_decimal_bytes(value: u32, out: &mut [u8; 10]) -> &[u8] {
    if value == 0 {
        out[9] = b'0';
        return &out[9..10];
    }

    let mut value = value;
    let mut cursor = out.len();
    while value > 0 {
        cursor -= 1;
        out[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    &out[cursor..]
}

fn sys_getdents64_proc_self_fd(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    start_index: u64,
    buf: u64,
    buf_size: u64,
) -> i64 {
    let mut offset = 0u64;
    let mut entry_index = 0u64;

    for proc_fd in 0..MAX_FDS {
        let entry = fd_table::load_process_fd_entry(base, vm.process_ptr, proc_fd);
        if entry.ofd_id == 0 {
            continue;
        }
        if entry_index < start_index {
            entry_index += 1;
            continue;
        }

        let mut name_buf = [0u8; 10];
        let name = u32_decimal_bytes(proc_fd as u32, &mut name_buf);
        match write_dirent64(base, buf, offset, buf_size, proc_fd as u64, DT_LNK, name) {
            Some(written) => {
                offset += written;
                entry_index += 1;
            }
            None => {
                break;
            }
        }
    }

    fd_table::set_offset(base, vm, fd, entry_index);
    offset as i64
}

/// getdents64: read directory entries into guest buffer.
/// Writes linux_dirent64 records (variable-size, 8-byte aligned).
pub fn sys_getdents64(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, buf_size: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let dir_ino = ofd.ino;
    let start_index = ofd.offset.max(0) as u64;
    if dir_ino == proc_self_fd_dir_ino() {
        return sys_getdents64_proc_self_fd(vm, base, fd, start_index, buf, buf_size);
    }

    let mut offset = 0u64;
    let max = buf_size;
    let mut entry_index = 0u64;
    let mut buffer_full = false;

    let readdir_result = memfs::readdir(dir_ino, |name, ino| {
        if buffer_full {
            return;
        }
        if entry_index < start_index {
            entry_index += 1;
            return;
        }

        let st = memfs::stat(ino);
        let d_type = match st {
            Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFDIR => DT_DIR,
            Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFREG => DT_REG,
            Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFLNK => DT_LNK,
            _ => DT_UNKNOWN,
        };
        match write_dirent64(base, buf, offset, max, ino as u64, d_type, name) {
            Some(written) => {
                offset += written;
                entry_index += 1;
            }
            None => {
                buffer_full = true;
            }
        }
    });
    if readdir_result < 0 {
        return readdir_result;
    }

    fd_table::set_offset(base, vm, fd, entry_index);
    offset as i64
}

// =========================================================================
// lseek
// =========================================================================

/// lseek: reposition OFD offset. Supports SEEK_SET (0), SEEK_CUR (1), SEEK_END (2).
pub fn sys_lseek(vm: &mut ThreadState, base: u32, fd: u64, offset: i64, whence: u64) -> i64 {
    let ofd_id = match fd_table::get_ofd_id(base, vm, fd) {
        Some(id) => id,
        None => return EBADF,
    };
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if fd_table::is_nonseekable_fd_type(ofd.fd_type) {
        return ESPIPE;
    }
    let current_offset = if ofd.fd_type == FD_TYPE_FILE {
        (ofd.offset as u64).max(fd_table::get_offset_floor_by_id(ofd_id))
    } else {
        ofd.offset as u64
    };

    let new_offset_i64 = match whence {
        0 => offset,                         // SEEK_SET
        1 => current_offset as i64 + offset, // SEEK_CUR
        2 => {
            // SEEK_END
            let st = memfs::stat(ofd.ino);
            match st {
                Some(s) => s.size as i64 + offset,
                None => return EINVAL,
            }
        }
        _ => return EINVAL,
    };
    if new_offset_i64 < 0 {
        return EINVAL;
    }
    let new_offset = new_offset_i64 as u64;

    fd_table::set_offset(base, vm, fd, new_offset);
    mark_fork_shared_ofd_sync_effect(vm);
    new_offset as i64
}
