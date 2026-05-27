use super::{
    SHUT_RD_MASK, SHUT_WR_MASK, SOCK_STATE_BOUND, SOCK_STATE_CONNECTED, SOCK_STATE_IDLE,
    SOCK_STATE_SHUTDOWN, SOCKADDR_STORAGE_LEN, ensure_external_peer_for_connected_socket,
    get_socket_idx, is_slot_used, record_socket_read_debug, socket_has_successful_read,
    socket_recv_timeout_ms_for_fd, socket_recv_timeout_ms_for_slot, socket_send_timeout_ms_for_fd,
    socket_send_timeout_ms_for_slot, socket_table,
};
use crate::abi::*;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::ThreadState;

const MSGHDR_SIZE: u64 = 56;
const MSGHDR_NAME_OFF: u64 = 0;
const MSGHDR_NAMELEN_OFF: u64 = 8;
const MSGHDR_IOV_OFF: u64 = 16;
const MSGHDR_IOVLEN_OFF: u64 = 24;
const MSGHDR_FLAGS_OFF: u64 = 48;
const IOVEC_SIZE: u64 = 16;
const MAX_MSG_IOV: u64 = 1024;
const MSG_NOSIGNAL: u64 = 0x4000;

pub(super) fn socket_recv_available(idx: usize) -> usize {
    let slot = &socket_table()[idx];
    if slot.recv_buf_idx < 0 {
        return 0;
    }
    crate::net::ring_buffer::available(slot.recv_buf_idx as u32)
}

pub(super) fn socket_send_space(idx: usize) -> usize {
    let mut peer_idx = socket_table()[idx].peer_idx;
    if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
        if ensure_external_peer_for_connected_socket(idx).is_err() {
            return 0;
        }
        peer_idx = socket_table()[idx].peer_idx;
    }
    if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
        return 0;
    }
    let peer = &socket_table()[peer_idx as usize];
    if peer.recv_buf_idx < 0 {
        return 0;
    }
    crate::net::ring_buffer::space(peer.recv_buf_idx as u32)
}

pub(super) fn slot_peer_is_closed(idx: usize) -> bool {
    let slot = &socket_table()[idx];
    if slot.external_peer != 0 && slot.state == SOCK_STATE_CONNECTED {
        return false;
    }
    let mut peer_idx = socket_table()[idx].peer_idx;
    if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
        if ensure_external_peer_for_connected_socket(idx).is_err() {
            return true;
        }
        peer_idx = socket_table()[idx].peer_idx;
        if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
            return true;
        }
    }
    let peer = &socket_table()[peer_idx as usize];
    peer.state == SOCK_STATE_SHUTDOWN || peer.state == SOCK_STATE_IDLE
}

pub fn read_external_connection_data(conn_id: i32, dst: &mut [u8]) -> i32 {
    if conn_id < 0 || conn_id as usize >= MAX_SOCKETS || !is_slot_used(conn_id as u32) {
        return -1;
    }
    let idx = conn_id as usize;
    let slot = &socket_table()[idx];
    if slot.recv_buf_idx < 0 {
        return -1;
    }

    let n = crate::net::ring_buffer::read(slot.recv_buf_idx as u32, dst);
    if n > 0 {
        return n as i32;
    }

    if slot_peer_is_closed(idx) { -1 } else { 0 }
}

/// sendto(fd, buf, len, flags, dest_addr, addrlen) -> STATUS_SOCKET_SEND
#[allow(clippy::too_many_arguments)]
pub fn sys_sendto(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    len: u64,
    _flags: u64,
    dest_addr: u64,
    dest_addrlen: u64,
) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };

    let slot = &socket_table()[idx as usize];

    if slot.sock_type == SOCK_STREAM {
        if slot.state != SOCK_STATE_CONNECTED {
            return ENOTCONN;
        }
    } else if slot.state != SOCK_STATE_CONNECTED && dest_addr == 0 {
        return EDESTADDRREQ;
    }

    if dest_addr != 0 && dest_addrlen > 0 {
        let len = (dest_addrlen as usize).min(SOCKADDR_STORAGE_LEN);
        if len >= 2 {
            let slot_mut = &mut socket_table()[idx as usize];
            let mut buf = [0u8; SOCKADDR_STORAGE_LEN];
            unsafe {
                guest_mem::read_bytes(base, dest_addr, &mut buf[..len]);
            }
            slot_mut.peer_addr[..len].copy_from_slice(&buf[..len]);
            slot_mut.peer_len = len as u32;
        }
    }

    let n = socket_write(vm, base, fd, buf, len);
    if n == EAGAIN {
        fd_table::pin_blocked_fd(base, vm, fd);
        vm.socket_timeout_ms = socket_send_timeout_ms_for_slot(slot);
        vm.status = STATUS_SOCKET_SEND;
        return 0;
    }
    n
}

/// sendmsg(2): https://man7.org/linux/man-pages/man2/sendmsg.2.html
///
/// Minimal stream/datagram data-path support. Control messages are ignored;
/// payload is sent from msg_iov just like writev.
pub fn sys_sendmsg(vm: &mut ThreadState, base: u32, fd: u64, msg: u64, flags: u64) -> i64 {
    if !crate::syscall::memory::guest_range_accessible(base, msg, MSGHDR_SIZE) {
        return EFAULT;
    }
    let name = unsafe { guest_mem::read_u64(base, msg + MSGHDR_NAME_OFF) };
    let namelen = unsafe { guest_mem::read_u32(base, msg + MSGHDR_NAMELEN_OFF) } as u64;
    let iov = unsafe { guest_mem::read_u64(base, msg + MSGHDR_IOV_OFF) };
    let iovlen = unsafe { guest_mem::read_u64(base, msg + MSGHDR_IOVLEN_OFF) };
    if iovlen > MAX_MSG_IOV {
        return EINVAL;
    }
    let Some(iov_bytes) = iovlen.checked_mul(IOVEC_SIZE) else {
        return EINVAL;
    };
    if iovlen > 0 && !crate::syscall::memory::guest_range_accessible(base, iov, iov_bytes) {
        return EFAULT;
    }

    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };
    if socket_table()[idx as usize].sock_type != SOCK_STREAM
        && socket_table()[idx as usize].state != SOCK_STATE_CONNECTED
        && name == 0
    {
        return EDESTADDRREQ;
    }
    if name != 0 && namelen > 0 && socket_table()[idx as usize].sock_type != SOCK_STREAM {
        let len = (namelen as usize).min(SOCKADDR_STORAGE_LEN);
        if !crate::syscall::memory::guest_range_accessible(base, name, len as u64) {
            return EFAULT;
        }
        let mut addr = [0u8; SOCKADDR_STORAGE_LEN];
        unsafe {
            guest_mem::read_bytes(base, name, &mut addr[..len]);
        }
        let slot = &mut socket_table()[idx as usize];
        slot.peer_addr[..len].copy_from_slice(&addr[..len]);
        slot.peer_len = len as u32;
    }

    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(value) => value,
        None => return EBADF,
    };
    let mut total = 0i64;
    for index in 0..iovlen {
        let iov_base = unsafe { guest_mem::read_u64(base, iov + index * IOVEC_SIZE) };
        let iov_len = unsafe { guest_mem::read_u64(base, iov + index * IOVEC_SIZE + 8) };
        if iov_len == 0 {
            continue;
        }
        let n = socket_write(vm, base, fd, iov_base, iov_len);
        if n == EPIPE {
            if flags & MSG_NOSIGNAL == 0 {
                crate::syscall::signal::send_signal(vm, SIGPIPE);
            }
            return if total > 0 { total } else { EPIPE };
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.socket_timeout_ms = socket_send_timeout_ms_for_fd(base, vm, fd);
            vm.status = STATUS_SOCKET_SEND;
            return if total > 0 { total } else { 0 };
        }
        if n < 0 {
            return if total > 0 { total } else { n };
        }
        total += n;
        if (n as u64) < iov_len {
            return total;
        }
    }
    total
}

/// recvfrom(fd, buf, len, flags, src_addr, addrlen) -> EAGAIN or STATUS_SOCKET_RECV
#[allow(clippy::too_many_arguments)]
pub fn sys_recvfrom(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    len: u64,
    _flags: u64,
    src_addr: u64,
    addrlen_ptr: u64,
) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };

    let slot = &socket_table()[idx as usize];

    if slot.sock_type == SOCK_STREAM
        && slot.state != SOCK_STATE_CONNECTED
        && slot.state != SOCK_STATE_SHUTDOWN
    {
        return ENOTCONN;
    }

    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let n = socket_read(vm, base, fd, buf, len);
    if n == EAGAIN {
        if ofd.status_flags & O_NONBLOCK != 0 {
            return EAGAIN;
        }
        fd_table::pin_blocked_fd(base, vm, fd);
        vm.socket_timeout_ms = socket_recv_timeout_ms_for_slot(slot);
        vm.status = STATUS_SOCKET_RECV;
        return 0;
    }

    if n > 0 && src_addr != 0 && addrlen_ptr != 0 {
        let slot = &socket_table()[idx as usize];
        let out_len = slot.peer_len.min(SOCKADDR_STORAGE_LEN as u32) as usize;
        unsafe {
            guest_mem::write_bytes(base, src_addr, &slot.peer_addr[..out_len]);
            guest_mem::write_u32(base, addrlen_ptr, out_len as u32);
        }
    }

    n
}

/// recvmsg(2): https://man7.org/linux/man-pages/man2/recvmsg.2.html
///
/// Minimal scatter receive support. Address/control metadata is omitted for
/// connected stream sockets, which is sufficient for the current network path.
pub fn sys_recvmsg(vm: &mut ThreadState, base: u32, fd: u64, msg: u64, _flags: u64) -> i64 {
    if !crate::syscall::memory::guest_range_accessible(base, msg, MSGHDR_SIZE) {
        return EFAULT;
    }
    let iov = unsafe { guest_mem::read_u64(base, msg + MSGHDR_IOV_OFF) };
    let iovlen = unsafe { guest_mem::read_u64(base, msg + MSGHDR_IOVLEN_OFF) };
    if iovlen > MAX_MSG_IOV {
        return EINVAL;
    }
    let Some(iov_bytes) = iovlen.checked_mul(IOVEC_SIZE) else {
        return EINVAL;
    };
    if iovlen > 0 && !crate::syscall::memory::guest_range_accessible(base, iov, iov_bytes) {
        return EFAULT;
    }

    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };
    if socket_table()[idx as usize].sock_type == SOCK_STREAM
        && socket_table()[idx as usize].state != SOCK_STATE_CONNECTED
        && socket_table()[idx as usize].state != SOCK_STATE_SHUTDOWN
    {
        return ENOTCONN;
    }
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(value) => value,
        None => return EBADF,
    };
    let mut total = 0i64;
    for index in 0..iovlen {
        let iov_base = unsafe { guest_mem::read_u64(base, iov + index * IOVEC_SIZE) };
        let iov_len = unsafe { guest_mem::read_u64(base, iov + index * IOVEC_SIZE + 8) };
        if iov_len == 0 {
            continue;
        }
        let n = socket_read(vm, base, fd, iov_base, iov_len);
        if n == EAGAIN {
            if total > 0 {
                break;
            }
            if ofd.status_flags & O_NONBLOCK != 0 {
                return EAGAIN;
            }
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.socket_timeout_ms = socket_recv_timeout_ms_for_fd(base, vm, fd);
            vm.status = STATUS_SOCKET_RECV;
            return 0;
        }
        if n < 0 {
            return if total > 0 { total } else { n };
        }
        total += n;
        if (n as u64) < iov_len {
            break;
        }
    }
    unsafe {
        guest_mem::write_u32(base, msg + MSGHDR_FLAGS_OFF, 0);
    }
    total
}

pub fn sys_shutdown(vm: &mut ThreadState, base: u32, fd: u64, how: u64) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i as usize,
        None => return ENOTSOCK,
    };
    let slot = &mut socket_table()[idx];
    if slot.state != SOCK_STATE_CONNECTED && slot.state != SOCK_STATE_SHUTDOWN {
        return ENOTCONN;
    }
    let bits = match how as i32 {
        SHUT_RD => SHUT_RD_MASK,
        SHUT_WR => SHUT_WR_MASK,
        SHUT_RDWR => SHUT_RD_MASK | SHUT_WR_MASK,
        _ => return EINVAL,
    };
    slot.shutdown_mask |= bits;
    0
}

pub fn socket_read(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, len: u64) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i as usize,
        None => return ENOTSOCK,
    };
    let slot_state = socket_table()[idx].state;
    let allow_dgram_bound =
        socket_table()[idx].sock_type == SOCK_DGRAM && slot_state == SOCK_STATE_BOUND;
    let before = socket_recv_available(idx);
    if !allow_dgram_bound
        && slot_state != SOCK_STATE_CONNECTED
        && slot_state != SOCK_STATE_SHUTDOWN
        && before == 0
    {
        if socket_table()[idx].sock_type == 0
            && socket_table()[idx].external_peer == 0
            && socket_table()[idx].recv_buf_idx >= 0
            && socket_has_successful_read(idx)
        {
            record_socket_read_debug(idx, fd, before, 0, socket_recv_available(idx));
            return 0;
        }
        return ENOTCONN;
    }
    if socket_table()[idx].recv_buf_idx < 0 {
        let result = if slot_peer_is_closed(idx) { 0 } else { EAGAIN };
        record_socket_read_debug(idx, fd, before, result, socket_recv_available(idx));
        return result;
    }

    let recv_buf_idx = socket_table()[idx].recv_buf_idx;
    let available = crate::net::ring_buffer::available(recv_buf_idx as u32);
    let to_read = (len as usize).min(available);
    if to_read > 0 {
        if !crate::syscall::memory::guest_range_accessible(base, buf, to_read as u64) {
            record_socket_read_debug(idx, fd, before, EFAULT, socket_recv_available(idx));
            return EFAULT;
        }
        let n = unsafe {
            guest_mem::with_write_slice(base, buf, to_read, |dst| {
                crate::net::ring_buffer::read(recv_buf_idx as u32, dst)
            })
        };
        record_socket_read_debug(idx, fd, before, n as i64, socket_recv_available(idx));
        return n as i64;
    }
    let result = if slot_peer_is_closed(idx) { 0 } else { EAGAIN };
    record_socket_read_debug(idx, fd, before, result, socket_recv_available(idx));
    result
}

pub fn socket_write(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, len: u64) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i as usize,
        None => return ENOTSOCK,
    };
    let slot = &socket_table()[idx];
    if slot.state != SOCK_STATE_CONNECTED {
        return ENOTCONN;
    }
    let mut peer_idx = slot.peer_idx;
    if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
        if ensure_external_peer_for_connected_socket(idx).is_err() {
            return EPIPE;
        }
        peer_idx = socket_table()[idx].peer_idx;
        if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
            return EPIPE;
        }
    }

    let peer = &socket_table()[peer_idx as usize];
    if peer.recv_buf_idx < 0 {
        return EPIPE;
    }

    let mut tmp = [0u8; 4096];
    let to_write = (len as usize).min(tmp.len());
    unsafe {
        guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
    }
    let written = crate::net::ring_buffer::write(peer.recv_buf_idx as u32, &tmp[..to_write]);
    if written > 0 {
        written as i64
    } else if peer.state == SOCK_STATE_SHUTDOWN || peer.state == SOCK_STATE_IDLE {
        EPIPE
    } else {
        EAGAIN
    }
}
