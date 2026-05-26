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

pub const FD_CLOEXEC: u32 = 1;

pub(crate) use super::fd::alloc::OPEN_ACCESS_MODE_MASK;
pub use super::fd::alloc::{
    open_devnull, open_epoll, open_eventfd, open_file, open_pipe, open_pty_master, open_pty_slave,
    open_signalfd, open_socket, open_timerfd,
};
pub use super::fd::backend_cleanup::BackendCleanup;
pub use super::fd::close::{
    close_all_for_process, close_all_for_process_without_backend_cleanup, release_ofd_id,
    release_ofd_id_deferred, sys_close, sys_close_range,
};
pub use super::fd::dup::{sys_dup, sys_dup3};
use super::fd::entry::{get_fd_entry, get_process_state, load_fd_entry_ptr, store_fd_entry_ptr};
pub use super::fd::entry::{load_process_fd_entry, store_process_fd_entry};
pub use super::fd::fcntl::{sys_fcntl, sys_flock};
use super::fd::ofd::table as ofd_table;
pub use super::fd::ofd::{
    attach_ofd_table_ptr, get_ofd_by_id, get_offset_by_id, get_offset_floor_by_id, init,
    is_ofd_reserved, ofd_reserved_bytes, ofd_reserved_ptr, ofd_table_bytes, ofd_table_ptr,
    reserve_ofd_id, set_offset_by_id, set_offset_floor_by_id, unreserve_ofd_id,
};
pub use super::fd::stdio::{init_stdio, use_pipe_stdio};

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
