//! poll/ppoll readiness checks.
//!
//! Semantics: https://pubs.opengroup.org/onlinepubs/9799919799/functions/poll.html
//!            https://man7.org/linux/man-pages/man2/ppoll.2.html

use crate::abi::*;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::ThreadState;

const POLLFD_SIZE: u64 = 8;
const POLLFD_FD_OFF: u64 = 0;
const POLLFD_EVENTS_OFF: u64 = 4;
const POLLFD_REVENTS_OFF: u64 = 6;
const POLLERR: u16 = 0x008;
const POLLHUP: u16 = 0x010;
const POLLNVAL: u16 = 0x020;
const MAX_POLL_FDS: u64 = MAX_FDS as u64;
const PPOLL_HUP_SYNC_RETRY_MARKER: u64 = 0x7070_6f6c_6c48_5550;
const NSEC_PER_SEC: u64 = 1_000_000_000;
const NSEC_PER_MSEC: u64 = 1_000_000;
const PSELECT_READ_INTEREST: u32 = 0x001;
const PSELECT_WRITE_INTEREST: u32 = 0x004;

fn timeout_is_zero(base: u32, timeout_addr: u64) -> bool {
    if timeout_addr == 0 {
        return false;
    }
    if !crate::syscall::memory::guest_range_accessible(base, timeout_addr, 16) {
        return true;
    }
    let sec = unsafe { guest_mem::read_u64(base, timeout_addr) };
    let nsec = unsafe { guest_mem::read_u64(base, timeout_addr + 8) };
    sec == 0 && nsec == 0
}

fn timeout_ms(base: u32, timeout_addr: u64) -> Result<i64, i64> {
    if timeout_addr == 0 {
        return Ok(-1);
    }
    if !crate::syscall::memory::guest_range_accessible(base, timeout_addr, 16) {
        return Err(EFAULT);
    }
    let sec = unsafe { guest_mem::read_u64(base, timeout_addr) };
    let nsec = unsafe { guest_mem::read_u64(base, timeout_addr + 8) };
    if nsec >= NSEC_PER_SEC {
        return Err(EINVAL);
    }
    let sec_ms = sec.saturating_mul(1000);
    let nsec_ms = nsec.saturating_add(NSEC_PER_MSEC - 1) / NSEC_PER_MSEC;
    let ms = sec_ms.saturating_add(nsec_ms);
    Ok(ms.min(i64::MAX as u64) as i64)
}

fn pollfd_addr(fds_addr: u64, index: u64) -> Option<u64> {
    index
        .checked_mul(POLLFD_SIZE)
        .and_then(|offset| fds_addr.checked_add(offset))
}

fn write_revents(base: u32, entry_addr: u64, revents: u16) {
    unsafe {
        guest_mem::write_u16(base, entry_addr + POLLFD_REVENTS_OFF, revents);
    }
}

fn fd_set_bytes(nfds: u64) -> Option<u64> {
    nfds.checked_add(63).map(|bits| (bits / 64) * 8)
}

fn fd_set_has(base: u32, set_addr: u64, fd: u64) -> bool {
    if set_addr == 0 {
        return false;
    }
    let word_addr = set_addr + (fd / 64) * 8;
    let bit = fd % 64;
    let word = unsafe { guest_mem::read_u64(base, word_addr) };
    (word & (1u64 << bit)) != 0
}

fn fd_set_write_bit(base: u32, set_addr: u64, fd: u64, ready: bool) {
    if set_addr == 0 {
        return;
    }
    let word_addr = set_addr + (fd / 64) * 8;
    let bit = fd % 64;
    let mut word = unsafe { guest_mem::read_u64(base, word_addr) };
    if ready {
        word |= 1u64 << bit;
    } else {
        word &= !(1u64 << bit);
    }
    unsafe {
        guest_mem::write_u64(base, word_addr, word);
    }
}

fn validate_fd_set(base: u32, set_addr: u64, bytes: u64) -> bool {
    set_addr == 0
        || bytes == 0
        || crate::syscall::memory::guest_range_accessible(base, set_addr, bytes)
}

pub fn wait_set_has_socket(vm: &ThreadState, base: u32) -> bool {
    match vm.x[17] {
        SYS_PPOLL => {
            let fds_addr = vm.x[10];
            let nfds = vm.x[11].min(MAX_POLL_FDS);
            for index in 0..nfds {
                let Some(entry_addr) = pollfd_addr(fds_addr, index) else {
                    return false;
                };
                if !crate::syscall::memory::guest_range_accessible(base, entry_addr, POLLFD_SIZE) {
                    return false;
                }
                let fd = unsafe { guest_mem::read_i32(base, entry_addr + POLLFD_FD_OFF) };
                let events = unsafe { guest_mem::read_u16(base, entry_addr + POLLFD_EVENTS_OFF) };
                if fd < 0 || events == 0 {
                    continue;
                }
                if fd_table::get_ofd(base, vm, fd as u64)
                    .is_some_and(|ofd| ofd.fd_type == FD_TYPE_SOCKET)
                {
                    return true;
                }
            }
            false
        }
        SYS_PSELECT6 => {
            let nfds = vm.x[10].min(MAX_POLL_FDS);
            let readfds = vm.x[11];
            let writefds = vm.x[12];
            let exceptfds = vm.x[13];
            for fd in 0..nfds {
                if !fd_set_has(base, readfds, fd)
                    && !fd_set_has(base, writefds, fd)
                    && !fd_set_has(base, exceptfds, fd)
                {
                    continue;
                }
                if fd_table::get_ofd(base, vm, fd).is_some_and(|ofd| ofd.fd_type == FD_TYPE_SOCKET)
                {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

pub fn wait_set_ready_count(vm: &ThreadState, base: u32) -> i32 {
    match vm.x[17] {
        SYS_PPOLL => {
            let fds_addr = vm.x[10];
            let nfds = vm.x[11].min(MAX_POLL_FDS);
            let mut ready = 0i32;
            for index in 0..nfds {
                let Some(entry_addr) = pollfd_addr(fds_addr, index) else {
                    return EINVAL as i32;
                };
                if !crate::syscall::memory::guest_range_accessible(base, entry_addr, POLLFD_SIZE) {
                    return EFAULT as i32;
                }
                let fd = unsafe { guest_mem::read_i32(base, entry_addr + POLLFD_FD_OFF) };
                let events = unsafe { guest_mem::read_u16(base, entry_addr + POLLFD_EVENTS_OFF) };
                if fd < 0 {
                    continue;
                }
                let revents = match fd_table::get_ofd(base, vm, fd as u64) {
                    Some(ofd) => {
                        crate::syscall::epoll::poll_ofd(vm, base, &ofd, events as u32) as u16
                    }
                    None => POLLNVAL,
                };
                if revents != 0 {
                    ready += 1;
                }
            }
            ready
        }
        SYS_PSELECT6 => {
            let nfds = vm.x[10].min(MAX_POLL_FDS);
            let readfds = vm.x[11];
            let writefds = vm.x[12];
            let exceptfds = vm.x[13];
            let Some(set_bytes) = fd_set_bytes(nfds) else {
                return EINVAL as i32;
            };
            if !validate_fd_set(base, readfds, set_bytes)
                || !validate_fd_set(base, writefds, set_bytes)
                || !validate_fd_set(base, exceptfds, set_bytes)
            {
                return EFAULT as i32;
            }

            let mut ready = 0i32;
            for fd in 0..nfds {
                let wants_read = fd_set_has(base, readfds, fd);
                let wants_write = fd_set_has(base, writefds, fd);
                let wants_except = fd_set_has(base, exceptfds, fd);
                if !wants_read && !wants_write && !wants_except {
                    continue;
                }
                let Some(ofd) = fd_table::get_ofd(base, vm, fd) else {
                    return EBADF as i32;
                };
                let mut interest = 0u32;
                if wants_read {
                    interest |= PSELECT_READ_INTEREST;
                }
                if wants_write {
                    interest |= PSELECT_WRITE_INTEREST;
                }
                let revents = crate::syscall::epoll::poll_ofd(vm, base, &ofd, interest);
                let error_ready = revents & ((POLLERR | POLLHUP | POLLNVAL) as u32) != 0;
                if (wants_read && (revents & (PSELECT_READ_INTEREST | POLLHUP as u32)) != 0)
                    || (wants_write && ((revents & PSELECT_WRITE_INTEREST) != 0 || error_ready))
                    || (wants_except && (revents & ((POLLERR | POLLHUP) as u32)) != 0)
                {
                    ready += 1;
                }
            }
            ready
        }
        _ => 0,
    }
}

pub fn wait_set_first_socket_revents(vm: &ThreadState, base: u32) -> u32 {
    match vm.x[17] {
        SYS_PPOLL => {
            let fds_addr = vm.x[10];
            let nfds = vm.x[11].min(MAX_POLL_FDS);
            for index in 0..nfds {
                let Some(entry_addr) = pollfd_addr(fds_addr, index) else {
                    return 0;
                };
                if !crate::syscall::memory::guest_range_accessible(base, entry_addr, POLLFD_SIZE) {
                    return 0;
                }
                let fd = unsafe { guest_mem::read_i32(base, entry_addr + POLLFD_FD_OFF) };
                let events = unsafe { guest_mem::read_u16(base, entry_addr + POLLFD_EVENTS_OFF) };
                if fd < 0 || events == 0 {
                    continue;
                }
                let Some(ofd) = fd_table::get_ofd(base, vm, fd as u64) else {
                    continue;
                };
                if ofd.fd_type == FD_TYPE_SOCKET {
                    let revents =
                        crate::syscall::epoll::poll_ofd(vm, base, &ofd, events as u32) as u16;
                    return ((fd as u32) & 0xff)
                        | ((events as u32) << 8)
                        | ((revents as u32) << 24);
                }
            }
            0
        }
        SYS_PSELECT6 => {
            let nfds = vm.x[10].min(MAX_POLL_FDS);
            let readfds = vm.x[11];
            let writefds = vm.x[12];
            let exceptfds = vm.x[13];
            for fd in 0..nfds {
                let wants_read = fd_set_has(base, readfds, fd);
                let wants_write = fd_set_has(base, writefds, fd);
                let wants_except = fd_set_has(base, exceptfds, fd);
                if !wants_read && !wants_write && !wants_except {
                    continue;
                }
                let Some(ofd) = fd_table::get_ofd(base, vm, fd) else {
                    continue;
                };
                if ofd.fd_type != FD_TYPE_SOCKET {
                    continue;
                }
                let mut interest = 0u32;
                if wants_read {
                    interest |= PSELECT_READ_INTEREST;
                }
                if wants_write {
                    interest |= PSELECT_WRITE_INTEREST;
                }
                let revents = crate::syscall::epoll::poll_ofd(vm, base, &ofd, interest);
                return ((fd as u32) & 0xff)
                    | ((interest & 0xffff) << 8)
                    | ((revents & 0xff) << 24);
            }
            0
        }
        _ => 0,
    }
}

pub fn wait_set_first_pipe_revents(vm: &ThreadState, base: u32) -> u32 {
    match vm.x[17] {
        SYS_PPOLL => {
            let fds_addr = vm.x[10];
            let nfds = vm.x[11].min(MAX_POLL_FDS);
            for index in 0..nfds {
                let Some(entry_addr) = pollfd_addr(fds_addr, index) else {
                    return 0;
                };
                if !crate::syscall::memory::guest_range_accessible(base, entry_addr, POLLFD_SIZE) {
                    return 0;
                }
                let fd = unsafe { guest_mem::read_i32(base, entry_addr + POLLFD_FD_OFF) };
                let events = unsafe { guest_mem::read_u16(base, entry_addr + POLLFD_EVENTS_OFF) };
                if fd < 0 || events == 0 {
                    continue;
                }
                let Some(ofd) = fd_table::get_ofd(base, vm, fd as u64) else {
                    continue;
                };
                if ofd.fd_type == FD_TYPE_PIPE {
                    let revents =
                        crate::syscall::epoll::poll_ofd(vm, base, &ofd, events as u32) as u16;
                    return ((fd as u32) & 0xff)
                        | ((events as u32) << 8)
                        | ((revents as u32) << 24);
                }
            }
            0
        }
        SYS_PSELECT6 => {
            let nfds = vm.x[10].min(MAX_POLL_FDS);
            let readfds = vm.x[11];
            let writefds = vm.x[12];
            let exceptfds = vm.x[13];
            for fd in 0..nfds {
                let wants_read = fd_set_has(base, readfds, fd);
                let wants_write = fd_set_has(base, writefds, fd);
                let wants_except = fd_set_has(base, exceptfds, fd);
                if !wants_read && !wants_write && !wants_except {
                    continue;
                }
                let Some(ofd) = fd_table::get_ofd(base, vm, fd) else {
                    continue;
                };
                if ofd.fd_type != FD_TYPE_PIPE {
                    continue;
                }
                let mut interest = 0u32;
                if wants_read {
                    interest |= PSELECT_READ_INTEREST;
                }
                if wants_write {
                    interest |= PSELECT_WRITE_INTEREST;
                }
                let revents = crate::syscall::epoll::poll_ofd(vm, base, &ofd, interest);
                return ((fd as u32) & 0xff)
                    | ((interest & 0xffff) << 8)
                    | ((revents & 0xff) << 24);
            }
            0
        }
        _ => 0,
    }
}

/// ppoll: check readiness for a pollfd array.
///
/// Blocking ppoll waits are represented with STATUS_PIPE_WAIT and re-dispatch
/// the syscall after any shared pipe/socket readiness wake. The signal mask is
/// intentionally not applied yet; signal delivery is still handled at normal
/// syscall boundaries by the existing signal machinery.
pub fn sys_ppoll(
    vm: &mut ThreadState,
    base: u32,
    fds_addr: u64,
    nfds: u64,
    timeout_addr: u64,
    _sigmask_addr: u64,
    _sigsetsize: u64,
) -> i64 {
    let wait_timeout_ms = match timeout_ms(base, timeout_addr) {
        Ok(ms) => ms,
        Err(errno) => return errno,
    };
    if nfds > MAX_POLL_FDS {
        return EINVAL;
    }
    let Some(total_bytes) = nfds.checked_mul(POLLFD_SIZE) else {
        return EINVAL;
    };
    if nfds > 0 && !crate::syscall::memory::guest_range_accessible(base, fds_addr, total_bytes) {
        return EFAULT;
    }

    let mut ready = 0i64;
    let mut saw_pipe_hup = false;
    for index in 0..nfds {
        let Some(entry_addr) = pollfd_addr(fds_addr, index) else {
            return EINVAL;
        };
        let fd = unsafe { guest_mem::read_i32(base, entry_addr + POLLFD_FD_OFF) };
        let events = unsafe { guest_mem::read_u16(base, entry_addr + POLLFD_EVENTS_OFF) };
        let revents = if fd < 0 {
            0
        } else {
            match fd_table::get_ofd(base, vm, fd as u64) {
                Some(ofd) => {
                    let interest = events as u32;
                    let revents = crate::syscall::epoll::poll_ofd(vm, base, &ofd, interest) as u16;
                    if ofd.fd_type == FD_TYPE_PIPE
                        && fd_table::is_pipe_read(&ofd)
                        && (revents & POLLHUP) != 0
                    {
                        saw_pipe_hup = true;
                    }
                    revents
                }
                None => POLLNVAL,
            }
        };
        write_revents(base, entry_addr, revents);
        if revents != 0 {
            ready += 1;
        }
    }

    if ready > 0 || timeout_is_zero(base, timeout_addr) {
        if saw_pipe_hup && vm.fault_addr != PPOLL_HUP_SYNC_RETRY_MARKER {
            vm.fault_addr = PPOLL_HUP_SYNC_RETRY_MARKER;
            vm.fault_pc = fds_addr;
            vm.epoll_timeout_ms = wait_timeout_ms;
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        vm.fault_addr = 0;
        vm.fault_pc = 0;
        vm.epoll_timeout_ms = 0;
        fd_table::clear_blocked_ofd_pin(vm);
        vm.status = STATUS_OK;
        return ready;
    }

    fd_table::clear_blocked_ofd_pin(vm);
    vm.epoll_timeout_ms = wait_timeout_ms;
    vm.status = STATUS_PIPE_WAIT;
    0
}

/// pselect6: fd_set based readiness check.
///
/// This shares the same readiness backend as ppoll. Signal-mask swapping is not
/// implemented yet; signal delivery still occurs at normal syscall boundaries.
pub fn sys_pselect6(
    vm: &mut ThreadState,
    base: u32,
    nfds: u64,
    readfds: u64,
    writefds: u64,
    exceptfds: u64,
    timeout_addr: u64,
    _sigmask_arg: u64,
) -> i64 {
    let wait_timeout_ms = match timeout_ms(base, timeout_addr) {
        Ok(ms) => ms,
        Err(errno) => return errno,
    };
    if nfds > MAX_POLL_FDS {
        return EINVAL;
    }
    let Some(set_bytes) = fd_set_bytes(nfds) else {
        return EINVAL;
    };
    if !validate_fd_set(base, readfds, set_bytes)
        || !validate_fd_set(base, writefds, set_bytes)
        || !validate_fd_set(base, exceptfds, set_bytes)
    {
        return EFAULT;
    }

    let mut ready_read = [false; MAX_FDS];
    let mut ready_write = [false; MAX_FDS];
    let mut ready_except = [false; MAX_FDS];
    let mut ready = 0i64;
    let mut saw_pipe_hup = false;

    for fd in 0..nfds {
        let wants_read = fd_set_has(base, readfds, fd);
        let wants_write = fd_set_has(base, writefds, fd);
        let wants_except = fd_set_has(base, exceptfds, fd);
        if !wants_read && !wants_write && !wants_except {
            continue;
        }
        let Some(ofd) = fd_table::get_ofd(base, vm, fd) else {
            return EBADF;
        };
        let mut interest = 0u32;
        if wants_read {
            interest |= PSELECT_READ_INTEREST;
        }
        if wants_write {
            interest |= PSELECT_WRITE_INTEREST;
        }
        let revents = crate::syscall::epoll::poll_ofd(vm, base, &ofd, interest);
        let fd_usize = fd as usize;
        let error_ready = revents & ((POLLERR | POLLHUP | POLLNVAL) as u32) != 0;
        if wants_read && (revents & (PSELECT_READ_INTEREST | POLLHUP as u32)) != 0 {
            ready_read[fd_usize] = true;
        }
        if wants_write && ((revents & PSELECT_WRITE_INTEREST) != 0 || error_ready) {
            ready_write[fd_usize] = true;
        }
        if wants_except && (revents & ((POLLERR | POLLHUP) as u32)) != 0 {
            ready_except[fd_usize] = true;
        }
        if ofd.fd_type == FD_TYPE_PIPE
            && fd_table::is_pipe_read(&ofd)
            && (revents & POLLHUP as u32) != 0
        {
            saw_pipe_hup = true;
        }
        if ready_read[fd_usize] || ready_write[fd_usize] || ready_except[fd_usize] {
            ready += 1;
        }
    }

    if ready == 0 && !timeout_is_zero(base, timeout_addr) {
        fd_table::clear_blocked_ofd_pin(vm);
        vm.epoll_timeout_ms = wait_timeout_ms;
        vm.status = STATUS_PIPE_WAIT;
        return 0;
    }

    if saw_pipe_hup && vm.fault_addr != PPOLL_HUP_SYNC_RETRY_MARKER {
        vm.fault_addr = PPOLL_HUP_SYNC_RETRY_MARKER;
        vm.fault_pc = readfds;
        vm.epoll_timeout_ms = wait_timeout_ms;
        vm.status = STATUS_PIPE_WAIT;
        return 0;
    }

    for fd in 0..nfds {
        fd_set_write_bit(base, readfds, fd, ready_read[fd as usize]);
        fd_set_write_bit(base, writefds, fd, ready_write[fd as usize]);
        fd_set_write_bit(base, exceptfds, fd, ready_except[fd as usize]);
    }
    vm.fault_addr = 0;
    vm.fault_pc = 0;
    vm.epoll_timeout_ms = 0;
    fd_table::clear_blocked_ofd_pin(vm);
    vm.status = STATUS_OK;
    ready
}

pub fn resume_poll_timeout(vm: &mut ThreadState, base: u32) {
    match vm.x[17] {
        SYS_PPOLL => {
            let fds_addr = vm.x[10];
            let nfds = vm.x[11].min(MAX_POLL_FDS);
            for index in 0..nfds {
                if let Some(entry_addr) = pollfd_addr(fds_addr, index) {
                    if crate::syscall::memory::guest_range_accessible(base, entry_addr, POLLFD_SIZE)
                    {
                        write_revents(base, entry_addr, 0);
                    }
                }
            }
        }
        SYS_PSELECT6 => {
            let nfds = vm.x[10].min(MAX_POLL_FDS);
            let readfds = vm.x[11];
            let writefds = vm.x[12];
            let exceptfds = vm.x[13];
            for fd in 0..nfds {
                fd_set_write_bit(base, readfds, fd, false);
                fd_set_write_bit(base, writefds, fd, false);
                fd_set_write_bit(base, exceptfds, fd, false);
            }
        }
        _ => {}
    }
    fd_table::clear_blocked_ofd_pin(vm);
    vm.fault_addr = 0;
    vm.fault_pc = 0;
    vm.epoll_timeout_ms = 0;
    vm.x[10] = 0;
    vm.status = STATUS_OK;
}
