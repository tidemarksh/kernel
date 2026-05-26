//! FD table and OFD (Open File Description) table management.
//!
//! Two-layer design:
//!
//! FD table lives in guest Memory (ProcessState.fd_table) — dup/close(same-process alias)/
//! fcntl operate without kernel Worker.
//!
//! OFD table lives in kernel Worker linear memory (alloc.rs) — shared by FDs via
//! refcount. Last close triggers OFD cleanup via kernel Worker.
//!
//! Struct layouts (RV64):
//!
//! struct FdEntry {                      // 8 bytes total
//!     ofd_id:   u32,                    // offset 0  — index into kernel Worker OFD table (0=unused)
//!     fd_flags: u32,                    // offset 4  — FD_CLOEXEC
//! };
//!
//! struct OpenFileDesc {                 // 32 bytes total
//!     fd_type:      i32,               // offset 0  — FD_TYPE_FILE, FD_TYPE_PIPE, etc.
//!     host_fd:      i32,               // offset 4  — pipe: idx or -(idx+1)
//!     status_flags: i32,               // offset 8  — O_ACCMODE, O_APPEND, O_NONBLOCK
//!     refcount:     i32,               // offset 12 — process-level holds (fork increments,
//!                                      //             last close in a process decrements)
//!     offset:       i64,               // offset 16 — current file offset
//!     ino:          u32,               // offset 24 — inode number (MemFS)
//!     flock_state:  u32,               // offset 28 — LOCK_SH/LOCK_EX advisory lock
//! };
//!
//! fcntl commands (https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/fcntl.h):
//!   F_DUPFD         = 0     dup to >= arg
//!   F_GETFD         = 1     get close_on_exec
//!   F_SETFD         = 2     set close_on_exec
//!   F_GETFL         = 3     get file status flags
//!   F_SETFL         = 4     set file status flags
//!   F_GETLK         = 5     query POSIX record lock
//!   F_SETLK         = 6     set POSIX record lock
//!   F_SETLKW        = 7     blocking POSIX record lock
//!   F_OFD_GETLK     = 36    query open-file-description lock
//!   F_OFD_SETLK     = 37    set open-file-description lock
//!   F_OFD_SETLKW    = 38    blocking open-file-description lock
//!   F_DUPFD_CLOEXEC = 1030  dup with CLOEXEC
//!   FD_CLOEXEC      = 1

use crate::abi::*;
use crate::types::{FdEntry, OpenFileDesc, ThreadState};
const OFD_PIPE_EPIPE_SYNCED: u32 = 1 << 31;
pub(crate) const OPEN_ACCESS_MODE_MASK: i32 = 0x3;

pub const FD_CLOEXEC: u32 = 1;
const EFD_SEMAPHORE: i32 = 0x1;

pub use super::fd::backend_cleanup::BackendCleanup;
pub use super::fd::close::{
    close_all_for_process, close_all_for_process_without_backend_cleanup, release_ofd_id,
    release_ofd_id_deferred, sys_close, sys_close_range,
};
pub use super::fd::dup::{sys_dup, sys_dup3};
use super::fd::entry::{
    find_free_fd, get_fd_entry, get_process_state, load_fd_entry_ptr, store_fd_entry_ptr,
};
pub use super::fd::entry::{load_process_fd_entry, store_process_fd_entry};
pub use super::fd::fcntl::{sys_fcntl, sys_flock};
use super::fd::ofd::{alloc as alloc_ofd, table as ofd_table};
pub use super::fd::ofd::{
    attach_ofd_table_ptr, get_ofd_by_id, get_offset_by_id, get_offset_floor_by_id, init,
    is_ofd_reserved, ofd_reserved_bytes, ofd_reserved_ptr, ofd_table_bytes, ofd_table_ptr,
    reserve_ofd_id, set_offset_by_id, set_offset_floor_by_id, unreserve_ofd_id,
};

pub fn run_backend_cleanup(cleanup: BackendCleanup) {
    super::fd::backend_cleanup::run(cleanup);
}

/// Increment the OFD refcount for an additional file descriptor reference.
/// Linux dup/fork create another fd referring to the same open file
/// description: https://man7.org/linux/man-pages/man2/dup.2.html
pub fn retain_ofd_id(ofd_id: u32) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    let slot = ofd_id as usize;
    let ofd = &mut ofd_table()[slot];
    if ofd.refcount > 0 || (ofd.refcount == 0 && is_ofd_reserved(ofd_id) && ofd.fd_type != 0) {
        ofd.refcount += 1;
    }
}

pub fn blocked_status_uses_ofd_pin(status: i32) -> bool {
    matches!(
        status,
        STATUS_PIPE_WAIT
            | STATUS_EPOLL_WAIT
            | STATUS_CONNECT
            | STATUS_SOCKET_RECV
            | STATUS_SOCKET_SEND
            | STATUS_FLOCK_WAIT
    )
}

pub fn clear_blocked_ofd_pin(vm: &mut ThreadState) {
    let ofd_id = vm.blocked_ofd_id;
    vm.blocked_fd = 0;
    vm.blocked_ofd_id = 0;
    vm.blocked_syscall_nr = 0;
    vm.blocked_syscall_args = [0; 6];
    if ofd_id != 0 {
        release_ofd_id(ofd_id);
    }
}

pub fn pin_blocked_fd(base: u32, vm: &mut ThreadState, fd: u64) {
    let Some(ofd_id) = get_ofd_id(base, vm, fd) else {
        clear_blocked_ofd_pin(vm);
        return;
    };
    let blocked_fd = fd as u32;
    if vm.blocked_ofd_id == ofd_id && vm.blocked_fd == blocked_fd {
        return;
    }
    clear_blocked_ofd_pin(vm);
    retain_ofd_id(ofd_id);
    vm.blocked_fd = blocked_fd;
    vm.blocked_ofd_id = ofd_id;
}

pub fn patch_blocked_fd_entry_for_resume(base: u32, vm: &ThreadState) -> Option<(u32, FdEntry)> {
    unsafe {
        let ofd_id = vm.blocked_ofd_id;
        let fd = vm.blocked_fd as usize;
        if ofd_id == 0 || fd >= MAX_FDS {
            return None;
        }

        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return None;
        }

        let entry = core::ptr::addr_of_mut!((*ps).fd_table[fd]);
        let saved = load_fd_entry_ptr(entry);
        if saved.ofd_id != ofd_id {
            store_fd_entry_ptr(
                entry,
                FdEntry {
                    ofd_id,
                    fd_flags: saved.fd_flags,
                },
            );
        }
        Some((fd as u32, saved))
    }
}

pub fn restore_blocked_fd_entry(base: u32, vm: &ThreadState, saved: Option<(u32, FdEntry)>) {
    unsafe {
        let Some((fd, saved)) = saved else {
            return;
        };
        let fd = fd as usize;
        if fd >= MAX_FDS {
            return;
        }

        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return;
        }

        store_fd_entry_ptr(core::ptr::addr_of_mut!((*ps).fd_table[fd]), saved);
    }
}

pub fn inode_has_write_open(ino: u32) -> bool {
    ofd_table().iter().any(|ofd| {
        ofd.refcount > 0
            && ofd.fd_type == FD_TYPE_FILE
            && ofd.ino == ino
            && (ofd.status_flags & OPEN_ACCESS_MODE_MASK) != O_RDONLY
    })
}

// =========================================================================
// Pipe FD creation
// =========================================================================

/// Open a pipe FD. `is_read_end` determines if this is the read or write end.
/// pipe_idx is the index into the pipe table.
pub fn open_pipe(
    vm: &mut ThreadState,
    base: u32,
    pipe_idx: u32,
    is_read_end: bool,
    flags: i32,
) -> i64 {
    unsafe {
        let fd_type = FD_TYPE_PIPE;
        let access_mode = if is_read_end { O_RDONLY } else { O_WRONLY };
        // Encode pipe_idx and read/write flag in host_fd field
        let host_fd = if is_read_end {
            pipe_idx as i32
        } else {
            -(pipe_idx as i32) - 1
        };
        let ofd_id = alloc_ofd(fd_type, access_mode | (flags & O_NONBLOCK));
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].host_fd = host_fd;
        ofd_table()[ofd_id as usize].ino = pipe_idx;
        ofd_table()[ofd_id as usize].offset =
            crate::syscall::pipe::pipe_generation(pipe_idx) as i64;

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

/// Check if an OFD is a pipe read-end (host_fd >= 0 and fd_type == PIPE).
pub fn is_pipe_read(ofd: &OpenFileDesc) -> bool {
    ofd.fd_type == FD_TYPE_PIPE
        && ofd.host_fd >= 0
        && crate::syscall::pipe::pipe_generation_matches(ofd.ino, ofd.offset as u32)
}

/// Check if an OFD is a pipe write-end (host_fd < 0 and fd_type == PIPE).
pub fn is_pipe_write(ofd: &OpenFileDesc) -> bool {
    ofd.fd_type == FD_TYPE_PIPE
        && ofd.host_fd < 0
        && crate::syscall::pipe::pipe_generation_matches(ofd.ino, ofd.offset as u32)
}

// =========================================================================
// Socket FD creation
// =========================================================================

/// Open a socket FD. `socket_idx` is the index into the socket table.
pub fn open_socket(vm: &mut ThreadState, base: u32, socket_idx: u32, flags: i32) -> i64 {
    unsafe {
        let ofd_id = alloc_ofd(FD_TYPE_SOCKET, O_RDWR | (flags & O_NONBLOCK));
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].ino = socket_idx;

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

// =========================================================================
// Epoll FD creation
// =========================================================================

/// Open an epoll FD. epoll_idx is the index into the epoll instance table.
pub fn open_epoll(vm: &mut ThreadState, base: u32, epoll_idx: u32, flags: i32) -> i64 {
    unsafe {
        let ofd_id = alloc_ofd(FD_TYPE_EPOLL, O_RDWR);
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].ino = epoll_idx;

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

/// Open an eventfd FD backed by the OFD table. The counter lives in `offset`
/// so dup/fork continue to share the same eventfd object.
pub fn open_eventfd(vm: &mut ThreadState, base: u32, initval: u64, flags: i32) -> i64 {
    unsafe {
        let ofd_id = alloc_ofd(FD_TYPE_EVENTFD, O_RDWR | (flags & O_NONBLOCK));
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].host_fd = if flags & EFD_SEMAPHORE != 0 { 1 } else { 0 };
        ofd_table()[ofd_id as usize].offset = initval as i64;

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

/// Open a timerfd FD backed by the shared timerfd table.
pub fn open_timerfd(vm: &mut ThreadState, base: u32, timerfd_idx: u32, flags: i32) -> i64 {
    unsafe {
        let ofd_id = alloc_ofd(FD_TYPE_TIMERFD, O_RDONLY | (flags & O_NONBLOCK));
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].ino = timerfd_idx;

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

/// Open a signalfd FD backed by the shared signalfd table.
pub fn open_signalfd(vm: &mut ThreadState, base: u32, signalfd_idx: u32, flags: i32) -> i64 {
    unsafe {
        let ofd_id = alloc_ofd(FD_TYPE_SIGNALFD, O_RDONLY | (flags & O_NONBLOCK));
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].ino = signalfd_idx;

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

/// Open `/dev/null` as a synthetic character device.
pub fn open_devnull(vm: &mut ThreadState, base: u32, flags: i32) -> i64 {
    unsafe {
        let ofd_id = alloc_ofd(
            FD_TYPE_DEVNULL,
            flags & (OPEN_ACCESS_MODE_MASK | O_APPEND | O_NONBLOCK),
        );
        if ofd_id == 0 {
            return EMFILE;
        }

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

pub fn open_pty_slave(vm: &mut ThreadState, base: u32, pty_idx: u32, flags: i32) -> i64 {
    unsafe {
        let access_mode = flags & OPEN_ACCESS_MODE_MASK;
        if access_mode != O_RDONLY && access_mode != O_WRONLY && access_mode != O_RDWR {
            return EINVAL;
        }
        let ofd_id = alloc_ofd(
            FD_TYPE_PTY_SLAVE,
            flags & (OPEN_ACCESS_MODE_MASK | O_APPEND | O_NONBLOCK),
        );
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].host_fd = 0;
        ofd_table()[ofd_id as usize].ino = pty_idx;
        crate::syscall::pty::retain_slave(pty_idx);

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => {
                release_ofd_id(ofd_id);
                return EMFILE;
            }
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

pub fn open_pty_master(vm: &mut ThreadState, base: u32, pty_idx: u32, flags: i32) -> i64 {
    unsafe {
        let access_mode = flags & OPEN_ACCESS_MODE_MASK;
        if access_mode != O_RDONLY && access_mode != O_WRONLY && access_mode != O_RDWR {
            return EINVAL;
        }
        let ofd_id = alloc_ofd(
            FD_TYPE_PTY_MASTER,
            flags & (OPEN_ACCESS_MODE_MASK | O_APPEND | O_NONBLOCK),
        );
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].host_fd = 1;
        ofd_table()[ofd_id as usize].ino = pty_idx;
        crate::syscall::pty::retain_master(pty_idx);

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => {
                release_ofd_id(ofd_id);
                return EMFILE;
            }
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

// =========================================================================
// FS integration: open_file, get_ofd, advance_offset, set_offset
// =========================================================================

/// Open a file by inode number. Allocates OFD and FD. Returns FD or error.
pub fn open_file(vm: &mut ThreadState, base: u32, ino: u32, flags: i32) -> i64 {
    unsafe {
        let fd_type = FD_TYPE_FILE;
        let ofd_id = alloc_ofd(
            fd_type,
            flags & (OPEN_ACCESS_MODE_MASK | O_APPEND | O_NONBLOCK),
        );
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].ino = ino;

        let cloexec = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

/// Get OFD for a file descriptor (read-only snapshot).
pub fn get_ofd(base: u32, vm: &ThreadState, fd: u64) -> Option<OpenFileDesc> {
    let entry = unsafe { get_fd_entry(base, vm, fd)? };
    let ofd = &ofd_table()[entry.ofd_id as usize];
    Some(*ofd)
}

/// Get the internal OFD id for a file descriptor.
pub fn get_ofd_id(base: u32, vm: &ThreadState, fd: u64) -> Option<u32> {
    unsafe { Some(get_fd_entry(base, vm, fd)?.ofd_id) }
}

pub fn pipe_epipe_synced(ofd_id: u32) -> bool {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return false;
    }
    let ofd = &ofd_table()[ofd_id as usize];
    ofd.fd_type == FD_TYPE_PIPE && ofd.host_fd < 0 && (ofd.flock_state & OFD_PIPE_EPIPE_SYNCED) != 0
}

pub fn set_pipe_epipe_synced(ofd_id: u32, synced: bool) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    let ofd = &mut ofd_table()[ofd_id as usize];
    if ofd.fd_type != FD_TYPE_PIPE || ofd.host_fd >= 0 {
        return;
    }
    if synced {
        ofd.flock_state |= OFD_PIPE_EPIPE_SYNCED;
    } else {
        ofd.flock_state &= !OFD_PIPE_EPIPE_SYNCED;
    }
}

pub fn set_fd_nonblock(base: u32, vm: &ThreadState, fd: u64, enabled: bool) -> i64 {
    unsafe {
        let entry = match get_fd_entry(base, vm, fd) {
            Some(entry) => entry,
            None => return EBADF,
        };
        let ofd = &mut ofd_table()[entry.ofd_id as usize];
        if enabled {
            ofd.status_flags |= O_NONBLOCK;
        } else {
            ofd.status_flags &= !O_NONBLOCK;
        }
        0
    }
}

/// Increment OFD refcounts for every fd held by the process.
///
/// Used when emulating fork(): the child receives a copy of the parent's
/// FD table, and each copied fd holds a reference to its open file
/// description. See https://man7.org/linux/man-pages/man2/fork.2.html
pub fn retain_fds_for_fork(base: u32, vm: &ThreadState) {
    unsafe {
        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return;
        }

        for index in 0..MAX_FDS {
            let entry = load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[index]));
            if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS {
                continue;
            }
            retain_ofd_id(entry.ofd_id);
        }
    }
}

/// Get the current offset of the OFD associated with fd.
pub fn get_offset(base: u32, vm: &ThreadState, fd: u64) -> u64 {
    unsafe {
        get_fd_entry(base, vm, fd)
            .map_or(0, |entry| ofd_table()[entry.ofd_id as usize].offset as u64)
    }
}

/// Advance the offset of the OFD associated with fd.
pub fn advance_offset(base: u32, vm: &ThreadState, fd: u64, delta: u64) {
    unsafe {
        if let Some(entry) = get_fd_entry(base, vm, fd) {
            ofd_table()[entry.ofd_id as usize].offset += delta as i64;
            set_offset_floor_by_id(
                entry.ofd_id,
                ofd_table()[entry.ofd_id as usize].offset as u64,
            );
        }
    }
}

/// Set the offset of the OFD associated with fd.
pub fn set_offset(base: u32, vm: &ThreadState, fd: u64, offset: u64) {
    unsafe {
        if let Some(entry) = get_fd_entry(base, vm, fd) {
            ofd_table()[entry.ofd_id as usize].offset = offset as i64;
            set_offset_floor_by_id(entry.ofd_id, offset);
        }
    }
}

/// Initialize stdin/stdout/stderr bridges for a new process.
///
/// Runtime owns the hidden peer ends:
/// - stdin: runtime writes, guest reads
/// - stdout/stderr: guest writes, runtime reads
///
/// # Safety
/// `base` and `vm.process_ptr` must describe a valid writable guest `ProcessState`.
pub unsafe fn init_stdio(base: u32, vm: &mut ThreadState) {
    let ps = get_process_state(base, vm);
    if ps.is_null() {
        return;
    }

    let Some(stdio_pty) = crate::syscall::pty::alloc_stdio_pty(vm, base) else {
        return;
    };

    let fd0 = open_pty_slave(vm, base, stdio_pty.pty_idx, O_RDONLY);
    let fd1 = open_pty_slave(vm, base, stdio_pty.pty_idx, O_WRONLY);
    let fd2 = open_pty_slave(vm, base, stdio_pty.pty_idx, O_WRONLY);
    if fd0 != 0 || fd1 != 1 || fd2 != 2 {
        if fd0 >= 0 {
            let _ = sys_close(vm, base, fd0 as u64);
        }
        if fd1 >= 0 {
            let _ = sys_close(vm, base, fd1 as u64);
        }
        if fd2 >= 0 {
            let _ = sys_close(vm, base, fd2 as u64);
        }
        crate::syscall::pty::release_host_attachment(vm, base);
        return;
    }

    unsafe {
        (*ps).stdin_pipe_slot = stdio_pty.stdin_pipe;
        (*ps).stdout_pipe_slot = stdio_pty.stdout_pipe;
        (*ps).stderr_pipe_slot = stdio_pty.stdout_pipe;
    }
}

/// Replace the default host-facing PTY stdio with plain pipes.
///
/// Non-interactive processes use byte streams; PTY echo/canonical handling is
/// only correct for terminal sessions. Runtime keeps the hidden peer ends:
/// - stdin: runtime writes, guest reads fd 0
/// - stdout/stderr: guest writes fd 1/2, runtime reads
pub unsafe fn use_pipe_stdio(base: u32, vm: &mut ThreadState) -> bool {
    crate::syscall::pty::release_host_attachment(vm, base);
    let _ = sys_close(vm, base, 0);
    let _ = sys_close(vm, base, 1);
    let _ = sys_close(vm, base, 2);

    let Some(stdin_pipe) = crate::syscall::pipe::alloc_pipe_slot() else {
        return false;
    };
    let Some(stdout_pipe) = crate::syscall::pipe::alloc_pipe_slot() else {
        crate::syscall::pipe::pipe_close(stdin_pipe, true);
        crate::syscall::pipe::pipe_close(stdin_pipe, false);
        return false;
    };
    let Some(stderr_pipe) = crate::syscall::pipe::alloc_pipe_slot() else {
        crate::syscall::pipe::pipe_close(stdin_pipe, true);
        crate::syscall::pipe::pipe_close(stdin_pipe, false);
        crate::syscall::pipe::pipe_close(stdout_pipe, true);
        crate::syscall::pipe::pipe_close(stdout_pipe, false);
        return false;
    };

    let fd0 = open_pipe(vm, base, stdin_pipe, true, 0);
    let fd1 = open_pipe(vm, base, stdout_pipe, false, 0);
    let fd2 = open_pipe(vm, base, stderr_pipe, false, 0);
    if fd0 != 0 || fd1 != 1 || fd2 != 2 {
        if fd0 >= 0 {
            let _ = sys_close(vm, base, fd0 as u64);
        }
        if fd1 >= 0 {
            let _ = sys_close(vm, base, fd1 as u64);
        }
        if fd2 >= 0 {
            let _ = sys_close(vm, base, fd2 as u64);
        }
        crate::syscall::pipe::pipe_close(stdin_pipe, true);
        crate::syscall::pipe::pipe_close(stdin_pipe, false);
        crate::syscall::pipe::pipe_close(stdout_pipe, true);
        crate::syscall::pipe::pipe_close(stdout_pipe, false);
        crate::syscall::pipe::pipe_close(stderr_pipe, true);
        crate::syscall::pipe::pipe_close(stderr_pipe, false);
        return false;
    }

    let ps = get_process_state(base, vm);
    if ps.is_null() {
        return false;
    }
    unsafe {
        (*ps).stdin_pipe_slot = stdin_pipe;
        (*ps).stdout_pipe_slot = stdout_pipe;
        (*ps).stderr_pipe_slot = stderr_pipe;
        (*ps).tty_pty_slot = 0;
    }
    true
}
