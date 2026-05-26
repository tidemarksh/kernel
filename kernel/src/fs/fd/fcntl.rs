use super::entry::{find_free_fd, get_fd_entry, get_process_state, store_fd_entry_ptr};
use super::ofd::table as ofd_table;
use crate::abi::*;
use crate::guest_mem;
use crate::types::{FdEntry, ThreadState};

// fcntl commands
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_GETLK: u64 = 5;
const F_SETLK: u64 = 6;
const F_SETLKW: u64 = 7;
const F_OFD_GETLK: u64 = 36;
const F_OFD_SETLK: u64 = 37;
const F_OFD_SETLKW: u64 = 38;
const F_DUPFD_CLOEXEC: u64 = 1030;
const F_RDLCK: u16 = 0;
const F_WRLCK: u16 = 1;
const F_UNLCK: u16 = 2;
const LOCK_SH: u32 = 0x1;
const LOCK_EX: u32 = 0x2;
const LOCK_NB: u32 = 0x4;
const LOCK_UN: u32 = 0x8;

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
                crate::fs::fd_table::retain_ofd_id(entry.ofd_id);
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
                crate::fs::fd_table::retain_ofd_id(entry.ofd_id);
                store_fd_entry_ptr(
                    core::ptr::addr_of_mut!((*ps).fd_table[newfd]),
                    FdEntry {
                        ofd_id: entry.ofd_id,
                        fd_flags: crate::fs::fd_table::FD_CLOEXEC,
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
                            fd_flags: arg as u32 & crate::fs::fd_table::FD_CLOEXEC,
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
                // Only O_APPEND, O_NONBLOCK, O_DSYNC, O_ASYNC can be changed.
                let changeable = O_APPEND | O_NONBLOCK;
                let ofd = &mut ofd_table()[entry.ofd_id as usize];
                ofd.status_flags = (ofd.status_flags & !changeable) | (arg as i32 & changeable);
                0
            }
            F_GETLK | F_OFD_GETLK => fcntl_getlk(base, vm, fd, arg),
            F_SETLK | F_SETLKW | F_OFD_SETLK | F_OFD_SETLKW => fcntl_setlk(base, vm, fd, arg),
            _ => EINVAL,
        }
    }
}

fn fcntl_getlk(base: u32, vm: &ThreadState, fd: u64, flock_addr: u64) -> i64 {
    if unsafe { get_fd_entry(base, vm, fd) }.is_none() {
        return EBADF;
    }
    if flock_addr == 0 {
        return EFAULT;
    }
    unsafe {
        guest_mem::write_u16(base, flock_addr, F_UNLCK);
    }
    0
}

fn fcntl_setlk(base: u32, vm: &ThreadState, fd: u64, flock_addr: u64) -> i64 {
    let Some(entry) = (unsafe { get_fd_entry(base, vm, fd) }) else {
        return EBADF;
    };
    if flock_addr == 0 {
        return EFAULT;
    }
    let lock_type = unsafe { guest_mem::read_u16(base, flock_addr) };
    let access_mode = ofd_table()[entry.ofd_id as usize].status_flags
        & crate::fs::fd_table::OPEN_ACCESS_MODE_MASK;
    match lock_type {
        F_RDLCK if access_mode == O_WRONLY => EBADF,
        F_WRLCK if access_mode == O_RDONLY => EBADF,
        F_RDLCK | F_WRLCK | F_UNLCK => 0,
        _ => EINVAL,
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
