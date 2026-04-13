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
//!   F_DUPFD_CLOEXEC = 1030  dup with CLOEXEC
//!   FD_CLOEXEC      = 1

use crate::abi::*;
use crate::types::{FdEntry, OpenFileDesc, ProcessState, ThreadState};
use core::sync::atomic::{AtomicU32, Ordering};

// fcntl commands
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;
pub(crate) const OPEN_ACCESS_MODE_MASK: i32 = 0x3;
const LOCK_SH: u32 = 0x1;
const LOCK_EX: u32 = 0x2;
const LOCK_NB: u32 = 0x4;
const LOCK_UN: u32 = 0x8;

pub const FD_CLOEXEC: u32 = 1;
const EFD_SEMAPHORE: i32 = 0x1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendCleanup {
    Pipe {
        pipe_idx: u32,
        is_read_end: bool,
        ofd_id: u32,
    },
    Epoll {
        epoll_idx: u32,
    },
    Socket {
        socket_idx: u32,
    },
    Pty {
        pty_idx: u32,
        is_master: bool,
    },
}

/// Pointer to OFD table in kernel Worker linear memory.
static mut OFD_TABLE_PTR: *mut [OpenFileDesc; MAX_FDS] = core::ptr::null_mut();

fn ofd_table() -> &'static mut [OpenFileDesc; MAX_FDS] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(OFD_TABLE_PTR));
        &mut *p
    }
}

pub fn ofd_table_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(OFD_TABLE_PTR)) as u32 }
}

pub fn ofd_table_bytes() -> u32 {
    core::mem::size_of::<[OpenFileDesc; MAX_FDS]>() as u32
}

pub fn attach_ofd_table_ptr(ptr: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(OFD_TABLE_PTR),
            ptr as *mut [OpenFileDesc; MAX_FDS],
        );
    }
}

/// Initialize OFD table. Allocates via alloc.rs.
pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(OFD_TABLE_PTR),
            core::ptr::null_mut(),
        );

        let size = core::mem::size_of::<[OpenFileDesc; MAX_FDS]>() as u32;
        let align = core::mem::align_of::<OpenFileDesc>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(OFD_TABLE_PTR),
            ptr as *mut [OpenFileDesc; MAX_FDS],
        );
    }
}

/// Get the ProcessState from guest memory.
fn get_process_state(base: u32, vm: &ThreadState) -> *mut ProcessState {
    (base as u64 + vm.process_ptr as u64) as *mut ProcessState
}

#[inline(always)]
unsafe fn load_fd_entry_ptr(entry: *const FdEntry) -> FdEntry {
    unsafe {
        let ofd_id =
            (&*(core::ptr::addr_of!((*entry).ofd_id) as *const AtomicU32)).load(Ordering::Acquire);
        let fd_flags = (&*(core::ptr::addr_of!((*entry).fd_flags) as *const AtomicU32))
            .load(Ordering::Relaxed);
        FdEntry { ofd_id, fd_flags }
    }
}

#[inline(always)]
unsafe fn store_fd_entry_ptr(entry: *mut FdEntry, value: FdEntry) {
    unsafe {
        (&*(core::ptr::addr_of!((*entry).fd_flags) as *const AtomicU32))
            .store(value.fd_flags, Ordering::Relaxed);
        (&*(core::ptr::addr_of!((*entry).ofd_id) as *const AtomicU32))
            .store(value.ofd_id, Ordering::Release);
    }
}

#[inline(always)]
unsafe fn clear_fd_entry_ptr(entry: *mut FdEntry) {
    unsafe {
        (&*(core::ptr::addr_of!((*entry).ofd_id) as *const AtomicU32)).store(0, Ordering::Release);
        (&*(core::ptr::addr_of!((*entry).fd_flags) as *const AtomicU32))
            .store(0, Ordering::Relaxed);
    }
}

/// Get FD entry from ProcessState. Returns None if out of range or unused.
unsafe fn get_fd_entry(base: u32, vm: &ThreadState, fd: u64) -> Option<FdEntry> {
    if fd as usize >= MAX_FDS {
        return None;
    }
    let ps = get_process_state(base, vm);
    if ps.is_null() {
        return None;
    }
    unsafe {
        let entry = load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[fd as usize]));
        if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS {
            return None;
        }
        Some(entry)
    }
}

/// Find the lowest available FD >= min_fd.
unsafe fn find_free_fd(base: u32, vm: &ThreadState, min_fd: usize) -> Option<usize> {
    let ps = get_process_state(base, vm);
    if ps.is_null() {
        return None;
    }
    unsafe {
        for i in min_fd..MAX_FDS {
            if load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[i])).ofd_id == 0 {
                return Some(i);
            }
        }
    }
    None
}

unsafe fn process_has_ofd(ps: *const ProcessState, ofd_id: u32) -> bool {
    if ps.is_null() || ofd_id == 0 {
        return false;
    }
    unsafe {
        for index in 0..MAX_FDS {
            let entry = load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[index]));
            if entry.ofd_id == ofd_id {
                return true;
            }
        }
    }
    false
}

/// Allocate a new OFD slot. Returns ofd_id (1-based), or 0 on failure.
unsafe fn alloc_ofd(fd_type: i32, status_flags: i32) -> u32 {
    for i in 1..MAX_FDS {
        if ofd_table()[i].refcount == 0 {
            ofd_table()[i] = OpenFileDesc {
                fd_type,
                host_fd: -1,
                status_flags,
                refcount: 1,
                offset: 0,
                ino: 0,
                flock_state: 0,
            };
            return i as u32;
        }
    }
    0
}

fn backend_cleanup_for_ofd(ofd_id: u32, ofd: &OpenFileDesc) -> Option<BackendCleanup> {
    if ofd.fd_type == FD_TYPE_PIPE {
        Some(BackendCleanup::Pipe {
            pipe_idx: ofd.ino,
            is_read_end: ofd.host_fd >= 0,
            ofd_id,
        })
    } else if ofd.fd_type == FD_TYPE_EPOLL {
        Some(BackendCleanup::Epoll { epoll_idx: ofd.ino })
    } else if ofd.fd_type == FD_TYPE_SOCKET {
        Some(BackendCleanup::Socket {
            socket_idx: ofd.ino,
        })
    } else if ofd.fd_type == FD_TYPE_PTY_MASTER {
        Some(BackendCleanup::Pty {
            pty_idx: ofd.ino,
            is_master: true,
        })
    } else if ofd.fd_type == FD_TYPE_PTY_SLAVE {
        Some(BackendCleanup::Pty {
            pty_idx: ofd.ino,
            is_master: false,
        })
    } else {
        None
    }
}

fn clear_ofd(ofd: &mut OpenFileDesc) {
    ofd.fd_type = 0;
    ofd.host_fd = -1;
    ofd.status_flags = 0;
    ofd.refcount = 0;
    ofd.offset = 0;
    ofd.ino = 0;
    ofd.flock_state = 0;
}

pub fn run_backend_cleanup(cleanup: BackendCleanup) {
    match cleanup {
        BackendCleanup::Pipe {
            pipe_idx,
            is_read_end,
            ofd_id,
        } => {
            let outcome = crate::syscall::pipe::pipe_close_outcome(pipe_idx, is_read_end);
            crate::harness_hooks::record_pipe_close_event(
                pipe_idx,
                is_read_end,
                ofd_id,
                outcome.read_open,
                outcome.write_open,
            );
        }
        BackendCleanup::Epoll { epoll_idx } => {
            crate::syscall::epoll::close_epoll(epoll_idx);
        }
        BackendCleanup::Socket { socket_idx } => {
            crate::syscall::socket::socket_close(socket_idx);
        }
        BackendCleanup::Pty { pty_idx, is_master } => {
            crate::syscall::pty::pty_close(pty_idx, is_master);
        }
    }
}

/// Increment the OFD refcount for an additional process holding this OFD.
pub fn retain_ofd_id(ofd_id: u32) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    let ofd = &mut ofd_table()[ofd_id as usize];
    if ofd.refcount > 0 {
        ofd.refcount += 1;
    }
}

pub fn blocked_status_uses_ofd_pin(status: i32) -> bool {
    matches!(
        status,
        STATUS_PIPE_WAIT
            | STATUS_EPOLL_WAIT
            | STATUS_SOCKET_RECV
            | STATUS_SOCKET_SEND
            | STATUS_FLOCK_WAIT
    )
}

pub fn clear_blocked_ofd_pin(vm: &mut ThreadState) {
    let ofd_id = vm.blocked_ofd_id;
    vm.blocked_fd = 0;
    vm.blocked_ofd_id = 0;
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

pub fn patch_blocked_fd_entry_for_resume(base: u32, vm: &ThreadState) -> Option<FdEntry> {
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
        Some(saved)
    }
}

pub fn restore_blocked_fd_entry(base: u32, vm: &ThreadState, saved: Option<FdEntry>) {
    unsafe {
        let Some(saved) = saved else {
            return;
        };
        let fd = vm.blocked_fd as usize;
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

/// Drop one process-level reference to an OFD and report the backend cleanup
/// that must run when this was the final process hold.
///
/// The OFD slot itself is cleared immediately; callers may run the returned
/// backend cleanup locally today or defer it to the canonical owner kernel.
pub fn release_ofd_id_deferred(ofd_id: u32) -> Option<BackendCleanup> {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return None;
    }
    let slot = ofd_id as usize;
    let ofd = &mut ofd_table()[slot];
    if ofd.refcount <= 0 {
        return None;
    }
    ofd.refcount -= 1;
    if ofd.refcount > 0 {
        return None;
    }

    crate::syscall::epoll::release_interest_for_ofd(ofd_id);
    let cleanup = backend_cleanup_for_ofd(ofd_id, ofd);
    clear_ofd(ofd);
    cleanup
}

/// Drop one process-level reference to an OFD and run backend cleanup on last close.
pub fn release_ofd_id(ofd_id: u32) {
    if let Some(cleanup) = release_ofd_id_deferred(ofd_id) {
        run_backend_cleanup(cleanup);
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
    ofd.fd_type == FD_TYPE_PIPE && ofd.host_fd >= 0
}

/// Check if an OFD is a pipe write-end (host_fd < 0 and fd_type == PIPE).
pub fn is_pipe_write(ofd: &OpenFileDesc) -> bool {
    ofd.fd_type == FD_TYPE_PIPE && ofd.host_fd < 0
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

#[derive(Clone, Copy)]
struct FlockRequest {
    mode: u32,
    nonblocking: bool,
}

fn parse_flock_request(operation: u64) -> Option<FlockRequest> {
    let op = operation as u32;
    if op & !(LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN) != 0 {
        return None;
    }
    let mode = op & (LOCK_SH | LOCK_EX | LOCK_UN);
    if mode.count_ones() != 1 {
        return None;
    }
    Some(FlockRequest {
        mode,
        nonblocking: op & LOCK_NB != 0,
    })
}

fn flock_conflicts(held_mode: u32, requested_mode: u32) -> bool {
    match requested_mode {
        LOCK_SH => held_mode == LOCK_EX,
        LOCK_EX => held_mode == LOCK_SH || held_mode == LOCK_EX,
        _ => false,
    }
}

// =========================================================================
// syscall implementations
// =========================================================================

/// dup(oldfd) → newfd
/// Duplicating an FD inside the same process does not change OFD process refcount.
pub fn sys_dup(vm: &mut ThreadState, base: u32, oldfd: u64) -> i64 {
    unsafe {
        let entry = match get_fd_entry(base, vm, oldfd) {
            Some(entry) => entry,
            None => return EBADF,
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
            FdEntry {
                ofd_id: entry.ofd_id,
                fd_flags: 0, // dup clears FD_CLOEXEC
            },
        );
        newfd as i64
    }
}

/// dup3(oldfd, newfd, flags) → newfd
pub fn sys_dup3(vm: &mut ThreadState, base: u32, oldfd: u64, newfd: u64, flags: u64) -> i64 {
    unsafe {
        if oldfd == newfd {
            return EINVAL;
        }
        if newfd as usize >= MAX_FDS {
            return EBADF;
        }

        let entry = match get_fd_entry(base, vm, oldfd) {
            Some(entry) => entry,
            None => return EBADF,
        };

        let ps = get_process_state(base, vm);

        // POSIX dup3: silently close newfd if it's already open.
        // Releasing the OFD is only required when this was the process's last
        // FD alias to that OFD.
        let old_new_ptr = core::ptr::addr_of_mut!((*ps).fd_table[newfd as usize]);
        let old_new = load_fd_entry_ptr(old_new_ptr);
        if old_new.ofd_id != 0 {
            let old_ofd_id = old_new.ofd_id;
            clear_fd_entry_ptr(old_new_ptr);
            if !process_has_ofd(ps, old_ofd_id) {
                release_ofd_id(old_ofd_id);
            }
        }

        let cloexec = if (flags as i32 & O_CLOEXEC) != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        store_fd_entry_ptr(
            core::ptr::addr_of_mut!((*ps).fd_table[newfd as usize]),
            FdEntry {
                ofd_id: entry.ofd_id,
                fd_flags: cloexec,
            },
        );
        newfd as i64
    }
}

/// fcntl(fd, cmd, arg)
pub fn sys_fcntl(vm: &mut ThreadState, base: u32, fd: u64, cmd: u64, arg: u64) -> i64 {
    unsafe {
        match cmd {
            F_DUPFD => {
                let entry = match get_fd_entry(base, vm, fd) {
                    Some(entry) => entry,
                    None => return EBADF,
                };
                let newfd = match find_free_fd(base, vm, arg as usize) {
                    Some(fd) => fd,
                    None => return EMFILE,
                };
                let ps = get_process_state(base, vm);
                store_fd_entry_ptr(
                    core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
                    FdEntry {
                        ofd_id: entry.ofd_id,
                        fd_flags: 0,
                    },
                );
                newfd as i64
            }
            F_DUPFD_CLOEXEC => {
                let entry = match get_fd_entry(base, vm, fd) {
                    Some(entry) => entry,
                    None => return EBADF,
                };
                let newfd = match find_free_fd(base, vm, arg as usize) {
                    Some(fd) => fd,
                    None => return EMFILE,
                };
                let ps = get_process_state(base, vm);
                store_fd_entry_ptr(
                    core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
                    FdEntry {
                        ofd_id: entry.ofd_id,
                        fd_flags: FD_CLOEXEC,
                    },
                );
                newfd as i64
            }
            F_GETFD => match get_fd_entry(base, vm, fd) {
                Some(entry) => entry.fd_flags as i64,
                None => EBADF,
            },
            F_SETFD => match get_fd_entry(base, vm, fd) {
                Some(entry) => {
                    let ps = get_process_state(base, vm);
                    store_fd_entry_ptr(
                        core::ptr::addr_of_mut!((*ps).fd_table[fd as usize]),
                        FdEntry {
                            ofd_id: entry.ofd_id,
                            fd_flags: arg as u32 & FD_CLOEXEC,
                        },
                    );
                    0
                }
                None => EBADF,
            },
            F_GETFL => {
                let entry = match get_fd_entry(base, vm, fd) {
                    Some(entry) => entry,
                    None => return EBADF,
                };
                ofd_table()[entry.ofd_id as usize].status_flags as i64
            }
            F_SETFL => {
                let entry = match get_fd_entry(base, vm, fd) {
                    Some(entry) => entry,
                    None => return EBADF,
                };
                // Only O_APPEND, O_NONBLOCK, O_DSYNC, O_ASYNC can be changed
                let changeable = O_APPEND | O_NONBLOCK;
                let ofd = &mut ofd_table()[entry.ofd_id as usize];
                ofd.status_flags = (ofd.status_flags & !changeable) | (arg as i32 & changeable);
                0
            }
            _ => EINVAL,
        }
    }
}

/// flock(fd, operation)
///
/// BSD advisory locks are associated with the open file description, so dup()
/// and fork() share the same lock state.
pub fn sys_flock(vm: &mut ThreadState, base: u32, fd: u64, operation: u64) -> i64 {
    unsafe {
        let entry = match get_fd_entry(base, vm, fd) {
            Some(entry) => entry,
            None => return EBADF,
        };
        let request = match parse_flock_request(operation) {
            Some(req) => req,
            None => return EINVAL,
        };

        let ofd_id = entry.ofd_id as usize;
        let ofd = ofd_table()[ofd_id];
        if ofd.fd_type != FD_TYPE_FILE {
            return EBADF;
        }

        if request.mode == LOCK_UN {
            ofd_table()[ofd_id].flock_state = 0;
            return 0;
        }

        let mut conflict = false;
        for idx in 1..MAX_FDS {
            if idx == ofd_id {
                continue;
            }
            let other = ofd_table()[idx];
            if other.refcount <= 0 || other.fd_type != FD_TYPE_FILE || other.ino != ofd.ino {
                continue;
            }
            if flock_conflicts(other.flock_state, request.mode) {
                conflict = true;
                break;
            }
        }

        if conflict {
            if request.nonblocking {
                return EAGAIN;
            }
            vm.status = STATUS_FLOCK_WAIT;
            return 0;
        }

        ofd_table()[ofd_id].flock_state = request.mode;
        0
    }
}

/// close(fd)
/// Only the last FD alias in the current process drops the OFD process refcount.
pub fn sys_close(vm: &mut ThreadState, base: u32, fd: u64) -> i64 {
    unsafe {
        if fd as usize >= MAX_FDS {
            return EBADF;
        }

        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return EBADF;
        }

        let entry_ptr = core::ptr::addr_of_mut!((*ps).fd_table[fd as usize]);
        let entry = load_fd_entry_ptr(entry_ptr);
        if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS {
            return EBADF;
        }

        let ofd_id = entry.ofd_id;
        clear_fd_entry_ptr(entry_ptr);
        if !process_has_ofd(ps, ofd_id) {
            release_ofd_id(ofd_id);
        }

        0
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

/// Get OFD by internal OFD id (for mmap file-backed without FD context).
pub fn get_ofd_by_id(ofd_id: u32) -> Option<OpenFileDesc> {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return None;
    }
    let ofd = &ofd_table()[ofd_id as usize];
    if ofd.fd_type == FD_TYPE_NONE {
        return None;
    }
    Some(*ofd)
}

/// Increment OFD refcounts for every distinct OFD held by the process.
///
/// Used when emulating fork(): the child receives a copy of the parent's
/// FD table, and both processes must hold a process-level reference to the
/// shared OFDs.
pub fn retain_fds_for_fork(base: u32, vm: &ThreadState) {
    unsafe {
        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return;
        }

        let mut retained = [false; MAX_FDS];
        for index in 0..MAX_FDS {
            let entry = load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[index]));
            if entry.ofd_id == 0 || retained[entry.ofd_id as usize] {
                continue;
            }
            retained[entry.ofd_id as usize] = true;
            retain_ofd_id(entry.ofd_id);
        }
    }
}

/// Drop this process's reference to every distinct OFD it still holds.
pub fn close_all_for_process(base: u32, vm: &ThreadState) {
    unsafe {
        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return;
        }

        let mut released = [false; MAX_FDS];
        for index in 0..MAX_FDS {
            let entry_ptr = core::ptr::addr_of_mut!((*ps).fd_table[index]);
            let entry = load_fd_entry_ptr(entry_ptr);
            let ofd_id = entry.ofd_id;
            clear_fd_entry_ptr(entry_ptr);
            let ofd_idx = ofd_id as usize;
            if ofd_id == 0 || ofd_idx >= MAX_FDS || released[ofd_idx] {
                continue;
            }
            released[ofd_idx] = true;
            release_ofd_id(ofd_id);
        }
    }
}

/// Drop this process's reference to every distinct OFD it still holds without
/// mutating backend control planes. Used by runtime-owned vfork restore paths:
/// the canonical owner kernel already accounts for pipe/epoll/socket cleanup,
/// but the local kernel must still forget the transient child process holds so
/// later parent-local close semantics do not retain stale process references.
pub fn close_all_for_process_without_backend_cleanup(base: u32, vm: &ThreadState) {
    unsafe {
        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return;
        }

        let mut released = [false; MAX_FDS];
        for index in 0..MAX_FDS {
            let entry_ptr = core::ptr::addr_of_mut!((*ps).fd_table[index]);
            let entry = load_fd_entry_ptr(entry_ptr);
            let ofd_id = entry.ofd_id;
            clear_fd_entry_ptr(entry_ptr);
            let ofd_idx = ofd_id as usize;
            if ofd_id == 0 || ofd_idx >= MAX_FDS || released[ofd_idx] {
                continue;
            }
            released[ofd_idx] = true;
            let _ = release_ofd_id_deferred(ofd_id);
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
        }
    }
}

/// Set the offset of the OFD associated with fd.
pub fn set_offset(base: u32, vm: &ThreadState, fd: u64, offset: u64) {
    unsafe {
        if let Some(entry) = get_fd_entry(base, vm, fd) {
            ofd_table()[entry.ofd_id as usize].offset = offset as i64;
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
