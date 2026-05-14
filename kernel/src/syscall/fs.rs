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
use crate::syscall::signal;
use crate::types::OpenFileDesc;
use crate::types::ThreadState;

mod meta;
mod mutation;
mod open;
mod path;
mod pending;
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
const EVENTFD_COUNTER_MAX: u64 = u64::MAX - 1;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;
const MAX_PATH_SYMLINK_FOLLOWS: u32 = 40;
const SYNC_EFFECT_PIPE_STATE: u32 = 1 << 0;
const SYNC_EFFECT_SOCKET_STATE: u32 = 1 << 1;
const SYNC_EFFECT_EPOLL_STATE: u32 = 1 << 2;
const SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE: u32 = 1 << 3;
const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;
const SYNC_EFFECT_PROCESS_MEMFS: u32 = 1 << 7;
pub(crate) const PIPE_READ_EOF_SYNC_RETRY_MARKER: u64 = 0x7069_7065_454f_4652;
const PIPE_EPIPE_SYNC_RETRY_MARKER: u64 = 0x7069_7065_4550_4950;
pub const FS_EFFECT_MEMFS_MUTATION: u32 = 1 << 0;
pub const FS_EFFECT_SHARED_OFD_STATE: u32 = 1 << 1;
pub const FS_EFFECT_MEMFS_FILE_DATA: u32 = 1 << 2;
pub use meta::{
    sys_faccessat, sys_fchmod, sys_fchmodat, sys_fchownat, sys_fstat, sys_ftruncate,
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
// read / pread64
// =========================================================================

/// read: read from file or pipe FD. Advances OFD offset for files.
pub fn sys_read(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return 0;
    }

    if ofd.fd_type == FD_TYPE_PTY_SLAVE || ofd.fd_type == FD_TYPE_PTY_MASTER {
        let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
        if access_mode == O_WRONLY {
            return EBADF;
        }
        let mut tmp = [0u8; 4096];
        let to_read = (count as usize).min(tmp.len());
        let n = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
            crate::syscall::pty::slave_read(ofd.ino, &mut tmp[..to_read])
        } else {
            crate::syscall::pty::master_read(ofd.ino, &mut tmp[..to_read])
        };
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        if n > 0 {
            let pipe_slot = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
                crate::syscall::pty::input_pipe_slot(ofd.ino)
            } else {
                crate::syscall::pty::output_pipe_slot(ofd.ino)
            };
            mark_pipe_sync_effect(vm, pipe_slot, false);
            if !crate::syscall::memory::guest_range_accessible(base, buf, n as u64) {
                return EFAULT;
            }
            unsafe {
                guest_mem::write_bytes(base, buf, &tmp[..n as usize]);
            }
            flush_shared_guest_write(vm, base, buf, n as u64);
            vm.completed_pipe_read_guest_ptr = buf;
            vm.completed_pipe_read_len = n as u32;
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_PIPE {
        if !fd_table::is_pipe_read(&ofd) {
            return EBADF;
        }
        let mut tmp = [0u8; super::pipe::PIPE_BUF_SIZE];
        let to_read = (count as usize).min(tmp.len());
        let n = super::pipe::pipe_read(ofd.ino, &mut tmp[..to_read]);
        if n == 0 && count > 0 {
            if vm.fault_addr != PIPE_READ_EOF_SYNC_RETRY_MARKER || vm.fault_pc != fd {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.fault_addr = PIPE_READ_EOF_SYNC_RETRY_MARKER;
                vm.fault_pc = fd;
                vm.status = STATUS_PIPE_WAIT;
                return 0;
            }
            vm.fault_addr = 0;
            vm.fault_pc = 0;
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        if n > 0 {
            mark_pipe_sync_effect(vm, ofd.ino, false);
            vm.fault_addr = 0;
            vm.fault_pc = 0;
            if !crate::syscall::memory::guest_range_accessible(base, buf, n as u64) {
                return EFAULT;
            }
            unsafe {
                guest_mem::write_bytes(base, buf, &tmp[..n as usize]);
            }
            flush_shared_guest_write(vm, base, buf, n as u64);
            vm.completed_pipe_read_guest_ptr = buf;
            vm.completed_pipe_read_len = n as u32;
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_EVENTFD {
        if count < 8 {
            return EINVAL;
        }
        let counter = fd_table::get_offset(base, vm, fd);
        if counter == 0 {
            if ofd.status_flags & O_NONBLOCK != 0 {
                return EAGAIN;
            }
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }

        let value = if ofd.host_fd != 0 { 1 } else { counter };
        let next = if ofd.host_fd != 0 { counter - 1 } else { 0 };
        if !crate::syscall::memory::guest_range_accessible(base, buf, 8) {
            return EFAULT;
        }
        unsafe {
            guest_mem::write_u64(base, buf, value);
        }
        flush_shared_guest_write(vm, base, buf, 8);
        fd_table::set_offset(base, vm, fd, next);
        return 8;
    }

    if ofd.fd_type == FD_TYPE_TIMERFD {
        let n = crate::syscall::time::timerfd_read(base, buf, count, ofd.ino);
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_SIGNALFD {
        let n = crate::syscall::signal::signalfd_read(vm, base, buf, count, ofd.ino);
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_SOCKET {
        let n = super::socket::socket_read(vm, base, fd, buf, count);
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.socket_timeout_ms = super::socket::socket_recv_timeout_ms_for_fd(base, vm, fd);
            vm.status = STATUS_SOCKET_RECV;
            return 0;
        }
        if n >= 0 {
            mark_socket_sync_effect(vm);
        }
        if n > 0 {
            flush_shared_guest_write(vm, base, buf, n as u64);
        }
        return n;
    }

    read_regular_file_to_guest(vm, base, fd, buf, count, None)
}

/// readv: scatter read into multiple guest buffers.
pub fn sys_readv(vm: &mut ThreadState, base: u32, fd: u64, iov_addr: u64, iovcnt: u64) -> i64 {
    let mut total = 0i64;

    for i in 0..iovcnt {
        let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * 16) };
        let iov_len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
        if iov_len == 0 {
            continue;
        }

        let n = sys_read(vm, base, fd, iov_base, iov_len);
        if vm.status == STATUS_PIPE_WAIT || vm.status == STATUS_SOCKET_RECV {
            if total > 0 {
                fd_table::clear_blocked_ofd_pin(vm);
                vm.socket_timeout_ms = -1;
                vm.status = STATUS_OK;
                return total;
            }
            return 0;
        }
        if n < 0 {
            return if total > 0 { total } else { n };
        }
        if n == 0 {
            break;
        }

        total += n;
        if (n as u64) < iov_len {
            break;
        }
    }

    total
}

/// pread64: read at specified offset without changing OFD offset.
pub fn sys_pread64(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    count: u64,
    offset: u64,
) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return 0;
    }

    read_regular_file_to_guest(vm, base, fd, buf, count, Some(offset))
}

fn read_regular_file_to_guest(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    guest_buf: u64,
    count: u64,
    offset: Option<u64>,
) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if let Some(st) = memfs::stat(ofd.ino) {
        if st.mode & memfs::S_IFMT == memfs::S_IFDIR {
            return EISDIR;
        }
    }
    if count == 0 {
        return 0;
    }

    let start_offset = offset.unwrap_or(ofd.offset as u64);
    let mut tmp = [0u8; 4096];
    let mut total = 0u64;

    while total < count {
        let to_read = ((count - total) as usize).min(tmp.len());
        let n = memfs::read_file(ofd.ino, start_offset + total, &mut tmp[..to_read]);
        if n < 0 {
            return if total > 0 { total as i64 } else { n };
        }
        if n == 0 {
            break;
        }
        if !crate::syscall::memory::guest_range_accessible(base, guest_buf + total, n as u64) {
            return if total > 0 { total as i64 } else { EFAULT };
        }
        unsafe {
            guest_mem::write_bytes(base, guest_buf + total, &tmp[..n as usize]);
        }
        flush_shared_guest_write(vm, base, guest_buf + total, n as u64);
        total += n as u64;
        if (n as usize) < to_read {
            break;
        }
    }

    if total > 0 && offset.is_none() {
        fd_table::advance_offset(base, vm, fd, total);
        mark_fork_shared_ofd_sync_effect(vm);
    }
    total as i64
}

// =========================================================================
// pwrite64
// =========================================================================

/// pwrite64: write at specified offset without changing OFD offset.
pub fn sys_pwrite64(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    count: u64,
    offset: u64,
) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return count as i64;
    }

    let n = write_regular_file_from_guest(base, buf, count, ofd.ino, offset);
    if n > 0 {
        mark_process_memfs_sync_effect(vm);
    }
    n
}

fn write_regular_file_from_guest(
    base: u32,
    guest_addr: u64,
    len: u64,
    ino: u32,
    start_offset: u64,
) -> i64 {
    let mut tmp = [0u8; 4096];
    let mut total = 0u64;
    while total < len {
        let to_write = ((len - total) as usize).min(tmp.len());
        unsafe {
            guest_mem::read_bytes(base, guest_addr + total, &mut tmp[..to_write]);
        }
        let n = memfs::write_file(ino, start_offset + total, &tmp[..to_write]);
        if n < 0 {
            return if total > 0 { total as i64 } else { n };
        }
        if n == 0 {
            break;
        }
        total += n as u64;
        if (n as usize) < to_write {
            break;
        }
    }
    total as i64
}

// =========================================================================
// write / writev
// =========================================================================

/// write: write to file or pipe FD. Sends SIGPIPE on broken pipe.
/// Also handles writev (dispatched by nr == SYS_WRITEV).
#[allow(clippy::too_many_arguments)]
fn trace_write_attempt(
    fd: u64,
    nr: u64,
    buf_addr: u64,
    count: u64,
    result: i64,
    ofd_id: u32,
    ofd_type: i32,
    ofd_ino: u32,
    status_flags: i32,
    pipe_read_open: i32,
    pipe_write_open: i32,
    bytes: Option<&[u8]>,
) -> i64 {
    crate::tracepoints::record_write_attempt(
        fd,
        nr,
        buf_addr,
        count,
        result,
        ofd_id,
        ofd_type,
        ofd_ino,
        status_flags,
        pipe_read_open,
        pipe_write_open,
        bytes,
    );
    result
}

fn trace_pipe_open_state(ofd: &OpenFileDesc) -> (i32, i32) {
    if ofd.fd_type == FD_TYPE_PIPE {
        (
            super::pipe::debug_read_open(ofd.ino),
            super::pipe::debug_write_open(ofd.ino),
        )
    } else {
        (0, 0)
    }
}

fn mark_process_memfs_sync_effect(vm: &mut ThreadState) {
    vm.completed_sync_effects |= SYNC_EFFECT_PROCESS_MEMFS;
}

fn flush_shared_guest_write(vm: &mut ThreadState, base: u32, guest_addr: u64, len: u64) {
    if len == 0 {
        return;
    }
    if crate::syscall::memory::flush_shared_mappings_for_guest_write(base, guest_addr, len) {
        mark_process_memfs_sync_effect(vm);
    }
}

fn mark_fork_shared_ofd_sync_effect(vm: &mut ThreadState) {
    vm.completed_sync_effects |= SYNC_EFFECT_FORK_SHARED_OFD_STATE;
}

fn mark_socket_sync_effect(vm: &mut ThreadState) {
    vm.completed_sync_effects |=
        SYNC_EFFECT_SOCKET_STATE | SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE;
}

fn mark_pipe_sync_effect(vm: &mut ThreadState, pipe_slot: u32, write_effect: bool) {
    vm.completed_sync_effects |= SYNC_EFFECT_PIPE_STATE;
    if pipe_slot > 0 && pipe_slot < 64 {
        vm.completed_pipe_sync_slots |= 1u64 << pipe_slot;
        if write_effect {
            vm.completed_pipe_sync_write_slots |= 1u64 << pipe_slot;
        } else {
            vm.completed_pipe_sync_read_slots |= 1u64 << pipe_slot;
        }
    }
}

pub fn sys_write(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64, nr: u64) -> i64 {
    if nr == SYS_WRITEV {
        return sys_writev(vm, base, fd, buf, count);
    }

    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                0,
                FD_TYPE_NONE,
                0,
                0,
                0,
                0,
                None,
            );
        }
    };
    let ofd_id = fd_table::get_ofd_id(base, vm, fd).unwrap_or(0);
    let (pipe_read_open, pipe_write_open) = trace_pipe_open_state(&ofd);

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            count as i64,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_STDOUT || ofd.fd_type == FD_TYPE_STDERR {
        #[cfg(target_os = "wasi")]
        {
            let mut tmp = [0u8; 4096];
            let to_write = (count as usize).min(tmp.len());
            unsafe {
                guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
            }
            if let Ok(s) = core::str::from_utf8(&tmp[..to_write]) {
                eprint!("{s}");
            } else {
                eprintln!("guest-fd{} {:?}", fd, &tmp[..to_write]);
            }
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                to_write as i64,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                Some(&tmp[..to_write]),
            );
        }
    }

    if ofd.fd_type == FD_TYPE_PTY_SLAVE || ofd.fd_type == FD_TYPE_PTY_MASTER {
        let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
        if access_mode == O_RDONLY {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        let mut tmp = [0u8; 4096];
        let to_write = (count as usize).min(tmp.len());
        unsafe {
            guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
        }
        let n = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
            crate::syscall::pty::slave_write(ofd.ino, &tmp[..to_write])
        } else {
            crate::syscall::pty::master_write_from_thread(ofd.ino, &tmp[..to_write], vm, base)
        };
        if n == EPIPE {
            signal::send_signal(vm, SIGPIPE);
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                Some(&tmp[..to_write]),
            );
        }
        if n > 0 {
            let pipe_slot = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
                crate::syscall::pty::output_pipe_slot(ofd.ino)
            } else {
                crate::syscall::pty::input_pipe_slot(ofd.ino)
            };
            mark_pipe_sync_effect(vm, pipe_slot, true);
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            n,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            Some(&tmp[..to_write]),
        );
    }

    if ofd.fd_type == FD_TYPE_PIPE {
        if !fd_table::is_pipe_write(&ofd) {
            let mut tmp = [0u8; 64];
            let to_trace = (count as usize).min(tmp.len());
            if to_trace > 0
                && crate::syscall::memory::guest_range_accessible(base, buf, to_trace as u64)
            {
                unsafe {
                    guest_mem::read_bytes(base, buf, &mut tmp[..to_trace]);
                }
                return trace_write_attempt(
                    fd,
                    nr,
                    buf,
                    count,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    Some(&tmp[..to_trace]),
                );
            }
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                pipe_read_open,
                pipe_write_open,
                None,
            );
        }
        let mut tmp = [0u8; super::pipe::PIPE_BUF_SIZE];
        let to_write = (count as usize).min(tmp.len());
        unsafe {
            guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
        }
        let n = super::pipe::pipe_write(ofd.ino, &tmp[..to_write]);
        if n == EPIPE {
            if !fd_table::pipe_epipe_synced(ofd_id)
                && (vm.fault_addr != PIPE_EPIPE_SYNC_RETRY_MARKER || vm.fault_pc != fd)
            {
                fd_table::pin_blocked_fd(base, vm, fd);
                fd_table::set_pipe_epipe_synced(ofd_id, true);
                vm.fault_addr = PIPE_EPIPE_SYNC_RETRY_MARKER;
                vm.fault_pc = fd;
                vm.status = STATUS_PIPE_WAIT;
                return trace_write_attempt(
                    fd,
                    nr,
                    buf,
                    count,
                    0,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    Some(&tmp[..to_write]),
                );
            }
            vm.fault_addr = 0;
            vm.fault_pc = 0;
            signal::send_signal(vm, SIGPIPE);
        }
        if n >= 0 {
            vm.fault_addr = 0;
            vm.fault_pc = 0;
            fd_table::set_pipe_epipe_synced(ofd_id, false);
        }
        if n == EAGAIN {
            fd_table::set_pipe_epipe_synced(ofd_id, false);
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                pipe_read_open,
                pipe_write_open,
                Some(&tmp[..to_write]),
            );
        }
        if n > 0 {
            mark_pipe_sync_effect(vm, ofd.ino, true);
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            n,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            pipe_read_open,
            pipe_write_open,
            Some(&tmp[..to_write]),
        );
    }

    if ofd.fd_type == FD_TYPE_EVENTFD {
        if count < 8 {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EINVAL,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        let value = unsafe { guest_mem::read_u64(base, buf) };
        if value == u64::MAX {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EINVAL,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }

        let counter = fd_table::get_offset(base, vm, fd);
        if counter > EVENTFD_COUNTER_MAX.saturating_sub(value) {
            if ofd.status_flags & O_NONBLOCK != 0 {
                return trace_write_attempt(
                    fd,
                    nr,
                    buf,
                    count,
                    EAGAIN,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }

        fd_table::set_offset(base, vm, fd, counter + value);
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            8,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_TIMERFD {
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            EINVAL,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_SIGNALFD {
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            EINVAL,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_SOCKET {
        let n = super::socket::socket_write(vm, base, fd, buf, count);
        if n == EPIPE {
            signal::send_signal(vm, SIGPIPE);
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.socket_timeout_ms = super::socket::socket_send_timeout_ms_for_fd(base, vm, fd);
            vm.status = STATUS_SOCKET_SEND;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        if n >= 0 || n == EPIPE {
            mark_socket_sync_effect(vm);
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            n,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    let mut trace = [0u8; 64];
    let to_trace = (count as usize).min(trace.len());
    if to_trace > 0 {
        unsafe {
            guest_mem::read_bytes(base, buf, &mut trace[..to_trace]);
        }
    }
    let current_offset = fd_table::get_offset_by_id(ofd_id)
        .max(fd_table::get_offset_floor_by_id(ofd_id))
        .max(ofd.offset as u64);
    let n = write_regular_file_from_guest(base, buf, count, ofd.ino, current_offset);
    if n > 0 {
        let next_offset = current_offset.saturating_add(n as u64);
        fd_table::set_offset_by_id(ofd_id, next_offset.max(fd_table::get_offset_by_id(ofd_id)));
        mark_fork_shared_ofd_sync_effect(vm);
        mark_process_memfs_sync_effect(vm);
    }
    trace_write_attempt(
        fd,
        nr,
        buf,
        count,
        n,
        ofd_id,
        ofd.fd_type,
        ofd.ino,
        ofd.status_flags,
        0,
        0,
        Some(&trace[..to_trace]),
    )
}

fn sys_writev(vm: &mut ThreadState, base: u32, fd: u64, iov_addr: u64, iovcnt: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => {
            return trace_write_attempt(
                fd,
                SYS_WRITEV,
                iov_addr,
                iovcnt,
                EBADF,
                0,
                FD_TYPE_NONE,
                0,
                0,
                0,
                0,
                None,
            );
        }
    };
    let ofd_id = fd_table::get_ofd_id(base, vm, fd).unwrap_or(0);
    let (pipe_read_open, pipe_write_open) = trace_pipe_open_state(&ofd);

    if ofd.fd_type == FD_TYPE_DEVNULL {
        let mut total = 0u64;
        for i in 0..iovcnt {
            total += unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
        }
        return trace_write_attempt(
            fd,
            SYS_WRITEV,
            iov_addr,
            iovcnt,
            total as i64,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_STDOUT || ofd.fd_type == FD_TYPE_STDERR {
        let mut total = 0u64;
        for i in 0..iovcnt {
            #[cfg(target_os = "wasi")]
            {
                let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * 16) };
                let len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
                let mut tmp = [0u8; 4096];
                let to_write = (len as usize).min(tmp.len());
                unsafe {
                    guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]);
                }
                if let Ok(s) = core::str::from_utf8(&tmp[..to_write]) {
                    eprint!("{s}");
                } else {
                    eprintln!("guest-fd{} {:?}", fd, &tmp[..to_write]);
                }
            }
            let len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
            total += len;
        }
        return trace_write_attempt(
            fd,
            SYS_WRITEV,
            iov_addr,
            iovcnt,
            total as i64,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    let mut total = 0i64;
    for i in 0..iovcnt {
        let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * 16) };
        let iov_len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
        if iov_len == 0 {
            continue;
        }

        if ofd.fd_type == FD_TYPE_PTY_SLAVE || ofd.fd_type == FD_TYPE_PTY_MASTER {
            let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
            if access_mode == O_RDONLY {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            let mut tmp = [0u8; 4096];
            let to_write = (iov_len as usize).min(tmp.len());
            unsafe {
                guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]);
            }
            let n = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
                crate::syscall::pty::slave_write(ofd.ino, &tmp[..to_write])
            } else {
                crate::syscall::pty::master_write_from_thread(ofd.ino, &tmp[..to_write], vm, base)
            };
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                if total == 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        EPIPE,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        0,
                        0,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.status = STATUS_PIPE_WAIT;
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { 0 },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n < 0 {
                if total > 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        total,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        0,
                        0,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    n,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n > 0 {
                mark_pipe_sync_effect(vm, ofd.ino, true);
            }
            total += n;
            if (n as usize) < to_write {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
        } else if ofd.fd_type == FD_TYPE_PIPE {
            if !fd_table::is_pipe_write(&ofd) {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            let mut tmp = [0u8; super::pipe::PIPE_BUF_SIZE];
            let to_write = (iov_len as usize).min(tmp.len());
            unsafe {
                guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]);
            }
            let n = super::pipe::pipe_write(ofd.ino, &tmp[..to_write]);
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                if total == 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        EPIPE,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        pipe_read_open,
                        pipe_write_open,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.status = STATUS_PIPE_WAIT;
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { 0 },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            if n < 0 {
                if total > 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        total,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        pipe_read_open,
                        pipe_write_open,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    n,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            if n > 0 {
                mark_pipe_sync_effect(vm, ofd.ino, true);
            }
            total += n;
            if (n as usize) < to_write {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
        } else if ofd.fd_type == FD_TYPE_SOCKET {
            let n = super::socket::socket_write(vm, base, fd, iov_base, iov_len);
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { EPIPE },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.socket_timeout_ms = super::socket::socket_send_timeout_ms_for_fd(base, vm, fd);
                vm.status = STATUS_SOCKET_SEND;
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { 0 },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n < 0 {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { n },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            total += n;
            if (n as u64) < iov_len {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
        } else {
            let current_offset = fd_table::get_offset(base, vm, fd)
                .max(fd_table::get_offset_by_id(ofd_id))
                .max(fd_table::get_offset_floor_by_id(ofd_id))
                .max(ofd.offset as u64);
            let n = write_regular_file_from_guest(base, iov_base, iov_len, ofd.ino, current_offset);
            if n > 0 {
                let next_offset = current_offset.saturating_add(n as u64);
                fd_table::set_offset_by_id(
                    ofd_id,
                    next_offset.max(fd_table::get_offset_by_id(ofd_id)),
                );
                mark_fork_shared_ofd_sync_effect(vm);
                mark_process_memfs_sync_effect(vm);
            }
            if n < 0 {
                if total > 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        total,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        0,
                        0,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    n,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            total += n;
        }
    }
    trace_write_attempt(
        fd,
        SYS_WRITEV,
        iov_addr,
        iovcnt,
        total,
        ofd_id,
        ofd.fd_type,
        ofd.ino,
        ofd.status_flags,
        0,
        0,
        None,
    )
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

    memfs::readdir(dir_ino, |name, ino| {
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
    let current_offset = if ofd.fd_type == FD_TYPE_FILE {
        (ofd.offset as u64).max(fd_table::get_offset_floor_by_id(ofd_id))
    } else {
        ofd.offset as u64
    };

    let new_offset = match whence {
        0 => offset as u64,                           // SEEK_SET
        1 => (current_offset as i64 + offset) as u64, // SEEK_CUR
        2 => {
            // SEEK_END
            let st = memfs::stat(ofd.ino);
            match st {
                Some(s) => (s.size as i64 + offset) as u64,
                None => return EINVAL,
            }
        }
        _ => return EINVAL,
    };

    fd_table::set_offset(base, vm, fd, new_offset);
    mark_fork_shared_ofd_sync_effect(vm);
    new_offset as i64
}
