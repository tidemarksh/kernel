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

pub const FD_CLOEXEC: u32 = 1;

pub(crate) use super::fd::alloc::OPEN_ACCESS_MODE_MASK;
pub use super::fd::alloc::{
    open_devnull, open_epoll, open_eventfd, open_file, open_pipe, open_pty_master, open_pty_slave,
    open_signalfd, open_socket, open_timerfd,
};
pub use super::fd::backend_cleanup::{BackendCleanup, run as run_backend_cleanup};
pub use super::fd::close::{
    close_all_for_process, close_all_for_process_without_backend_cleanup, release_ofd_id,
    release_ofd_id_deferred, sys_close, sys_close_range,
};
pub use super::fd::dup::{sys_dup, sys_dup3};
pub use super::fd::entry::{load_process_fd_entry, store_process_fd_entry};
pub use super::fd::fcntl::{sys_fcntl, sys_flock};
pub use super::fd::nonseekable::is_nonseekable_fd_type;
pub use super::fd::ofd::{
    advance_offset, attach_ofd_state_ptr, blocked_status_uses_ofd_pin, clear_blocked_ofd_pin,
    get_ofd, get_ofd_by_id, get_ofd_id, get_offset, get_offset_by_id, get_offset_floor_by_id, init,
    inode_has_write_open, is_ofd_reserved, is_pipe_read, is_pipe_write, ofd_offset_floor_bytes,
    ofd_offset_floor_ptr, ofd_reserved_bytes, ofd_reserved_ptr, ofd_state_bytes, ofd_state_ptr,
    ofd_table_bytes, ofd_table_ptr, patch_blocked_fd_entry_for_resume, pin_blocked_fd,
    pipe_epipe_synced, reserve_ofd_id, restore_blocked_fd_entry, retain_fds_for_fork,
    retain_ofd_id, set_fd_nonblock, set_offset, set_offset_by_id, set_offset_floor_by_id,
    set_pipe_epipe_synced, unreserve_ofd_id,
};
pub use super::fd::stdio::{init_stdio, use_pipe_stdio};
