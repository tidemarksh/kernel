use super::close::release_ofd_id;
use super::entry::{find_free_fd, get_process_state, store_process_fd_entry_ptr};
use super::ofd::{alloc as alloc_ofd, table as ofd_table};
use crate::abi::*;
use crate::fs::fd_table::FD_CLOEXEC;
use crate::types::{FdEntry, ThreadState};

pub(crate) const OPEN_ACCESS_MODE_MASK: i32 = 0x3;

const EFD_SEMAPHORE: i32 = 0x1;

fn cloexec_flag(flags: i32) -> u32 {
    if flags & O_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    }
}

unsafe fn install_fd(vm: &ThreadState, base: u32, ofd_id: u32, flags: i32) -> Option<usize> {
    let newfd = find_free_fd(base, vm, 0)?;
    let ps = get_process_state(base, vm);
    unsafe {
        store_process_fd_entry_ptr(
            ps,
            newfd,
            FdEntry {
                ofd_id,
                fd_flags: cloexec_flag(flags),
            },
        );
    }
    Some(newfd)
}

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

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => EMFILE,
        }
    }
}

/// Open a socket FD. `socket_idx` is the index into the socket table.
pub fn open_socket(vm: &mut ThreadState, base: u32, socket_idx: u32, flags: i32) -> i64 {
    unsafe {
        let ofd_id = alloc_ofd(FD_TYPE_SOCKET, O_RDWR | (flags & O_NONBLOCK));
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].ino = socket_idx;

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => EMFILE,
        }
    }
}

/// Open an epoll FD. epoll_idx is the index into the epoll instance table.
pub fn open_epoll(vm: &mut ThreadState, base: u32, epoll_idx: u32, flags: i32) -> i64 {
    unsafe {
        let ofd_id = alloc_ofd(FD_TYPE_EPOLL, O_RDWR);
        if ofd_id == 0 {
            return EMFILE;
        }
        ofd_table()[ofd_id as usize].ino = epoll_idx;

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => EMFILE,
        }
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

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => EMFILE,
        }
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

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => EMFILE,
        }
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

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => EMFILE,
        }
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

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => EMFILE,
        }
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

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => {
                release_ofd_id(ofd_id);
                EMFILE
            }
        }
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

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => {
                release_ofd_id(ofd_id);
                EMFILE
            }
        }
    }
}

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

        match install_fd(vm, base, ofd_id, flags) {
            Some(fd) => fd as i64,
            None => EMFILE,
        }
    }
}
