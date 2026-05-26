use super::{
    ACCEPT_QUEUE_SIZE, DEFAULT_SOCKET_BUFFER, INVALID_BUF_IDX, INVALID_PEER_IDX, SOCK_STATE_BOUND,
    SOCK_STATE_CONNECTED, SOCK_STATE_CONNECTING, SOCK_STATE_IDLE, SOCK_STATE_LISTENING,
    SOCKADDR_STORAGE_LEN, SocketSlot, alloc_socket_cookie, alloc_socket_recv_buffer,
    alloc_socket_slot, ensure_external_peer, ensure_socket_recv_buffer,
    free_recv_buffer_if_unreferenced, free_socket_slot, get_socket_idx, is_slot_used,
    socket_recv_timeout_ms_for_slot, socket_send_timeout_ms_for_slot, socket_table,
    thread_connect_target_fd,
};
use crate::abi::*;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::ThreadState;

pub(super) fn accept_queue_len(slot: &SocketSlot) -> usize {
    slot.accept_tail.wrapping_sub(slot.accept_head) as usize
}

fn accept_queue_pop(slot: &mut SocketSlot) -> Option<u32> {
    if accept_queue_len(slot) == 0 {
        return None;
    }
    let idx = (slot.accept_head as usize) % ACCEPT_QUEUE_SIZE;
    let value = slot.accept_queue[idx];
    slot.accept_queue[idx] = -1;
    slot.accept_head = slot.accept_head.wrapping_add(1);
    (value >= 0).then_some(value as u32)
}

pub(super) fn accept_queue_push(slot: &mut SocketSlot, value: u32) -> bool {
    if accept_queue_len(slot) >= ACCEPT_QUEUE_SIZE {
        return false;
    }
    let idx = (slot.accept_tail as usize) % ACCEPT_QUEUE_SIZE;
    slot.accept_queue[idx] = value as i32;
    slot.accept_tail = slot.accept_tail.wrapping_add(1);
    true
}

fn accept_queue_remove(slot: &mut SocketSlot, value: u32) -> bool {
    let len = accept_queue_len(slot);
    if len == 0 {
        return false;
    }

    let target = value as i32;
    let mut retained = [-1; ACCEPT_QUEUE_SIZE];
    let mut retained_len = 0usize;
    let mut removed = false;
    for offset in 0..len {
        let idx = (slot.accept_head as usize + offset) % ACCEPT_QUEUE_SIZE;
        let queued = slot.accept_queue[idx];
        if queued == target {
            removed = true;
            continue;
        }
        retained[retained_len] = queued;
        retained_len += 1;
    }

    if !removed {
        return false;
    }

    slot.accept_head = 0;
    slot.accept_tail = retained_len as u32;
    slot.accept_queue = [-1; ACCEPT_QUEUE_SIZE];
    for (idx, queued) in retained.into_iter().take(retained_len).enumerate() {
        slot.accept_queue[idx] = queued;
    }
    true
}

pub(super) fn remove_socket_from_accept_queues(socket_idx: u32) {
    for listener_idx in 0..MAX_SOCKETS {
        if !is_slot_used(listener_idx as u32) {
            continue;
        }
        let listener = &mut socket_table()[listener_idx];
        if listener.state != SOCK_STATE_LISTENING {
            continue;
        }
        let _ = accept_queue_remove(listener, socket_idx);
    }
}

fn unix_addr_eq(slot: &SocketSlot, addr: &[u8], len: usize) -> bool {
    slot.domain == AF_UNIX
        && slot.local_len as usize == len
        && slot.local_addr[..len] == addr[..len]
}

fn find_unix_socket_by_addr(addr: &[u8], len: usize) -> Option<usize> {
    socket_table()
        .iter()
        .enumerate()
        .find(|(idx, slot)| is_slot_used(*idx as u32) && unix_addr_eq(slot, addr, len))
        .map(|(idx, _)| idx)
}

fn unix_connect_stream(idx: usize, addr: &[u8], len: usize) -> i64 {
    let Some(listener_idx) = find_unix_socket_by_addr(addr, len) else {
        return ENOENT;
    };
    if listener_idx == idx {
        return ECONNREFUSED;
    }
    let listener = &socket_table()[listener_idx];
    if listener.sock_type != SOCK_STREAM {
        return EPROTOTYPE;
    }
    if listener.state != SOCK_STATE_LISTENING {
        return ECONNREFUSED;
    }
    if accept_queue_len(listener) >= ACCEPT_QUEUE_SIZE {
        return EAGAIN;
    }

    let Some(accepted_idx) = alloc_socket_slot().map(|value| value as usize) else {
        return ENOMEM;
    };
    if ensure_socket_recv_buffer(idx).is_err() {
        free_socket_slot(accepted_idx as u32);
        return ENOMEM;
    }
    let Some(accepted_recv) = alloc_socket_recv_buffer() else {
        free_socket_slot(accepted_idx as u32);
        return ENOMEM;
    };

    let client_owner_pid = socket_table()[idx].owner_pid;
    let client_owner_uid = socket_table()[idx].owner_uid;
    let client_owner_gid = socket_table()[idx].owner_gid;
    let listener_owner_pid = listener.owner_pid;
    let listener_owner_uid = listener.owner_uid;
    let listener_owner_gid = listener.owner_gid;
    let listener_local_addr = listener.local_addr;
    let listener_local_len = listener.local_len;
    let protocol = listener.protocol;

    socket_table()[accepted_idx] = SocketSlot {
        domain: AF_UNIX,
        sock_type: SOCK_STREAM,
        protocol,
        state: SOCK_STATE_CONNECTED,
        owner_pid: listener_owner_pid,
        owner_uid: listener_owner_uid,
        owner_gid: listener_owner_gid,
        local_addr: listener_local_addr,
        local_len: listener_local_len,
        peer_addr: socket_table()[idx].local_addr,
        peer_len: socket_table()[idx].local_len,
        peer_idx: idx as i32,
        peer_pid: client_owner_pid,
        peer_uid: client_owner_uid,
        peer_gid: client_owner_gid,
        external_peer: 0,
        recv_buf_idx: accepted_recv,
        last_error: 0,
        so_cookie: alloc_socket_cookie(),
        so_reuseaddr: 0,
        so_reuseport: 0,
        so_keepalive: 0,
        so_oobinline: 0,
        so_nocheck: 0,
        so_bsdcompat: 0,
        so_broadcast: 0,
        so_sndbuf: DEFAULT_SOCKET_BUFFER,
        so_rcvbuf: DEFAULT_SOCKET_BUFFER,
        so_rcvlowat: 1,
        so_rcvtimeo_sec: 0,
        so_rcvtimeo_usec: 0,
        so_sndtimeo_sec: 0,
        so_sndtimeo_usec: 0,
        tcp_nodelay: 0,
        shutdown_mask: 0,
        accept_head: 0,
        accept_tail: 0,
        accept_queue: [-1; ACCEPT_QUEUE_SIZE],
    };

    {
        let client = &mut socket_table()[idx];
        client.peer_addr[..len].copy_from_slice(&addr[..len]);
        client.peer_len = len as u32;
        client.peer_idx = accepted_idx as i32;
        client.peer_pid = listener_owner_pid;
        client.peer_uid = listener_owner_uid;
        client.peer_gid = listener_owner_gid;
        client.state = SOCK_STATE_CONNECTED;
    }

    if !accept_queue_push(&mut socket_table()[listener_idx], accepted_idx as u32) {
        super::shutdown_slot(accepted_idx);
        let client = &mut socket_table()[idx];
        client.peer_idx = INVALID_PEER_IDX;
        client.peer_pid = 0;
        client.peer_uid = 0;
        client.peer_gid = 0;
        client.state = if client.local_len > 0 {
            SOCK_STATE_BOUND
        } else {
            SOCK_STATE_IDLE
        };
        return EAGAIN;
    }
    0
}

fn unix_connect_dgram(idx: usize, addr: &[u8], len: usize) -> i64 {
    let Some(peer_idx) = find_unix_socket_by_addr(addr, len) else {
        return ENOENT;
    };
    if peer_idx == idx {
        return EISCONN;
    }
    let peer = &socket_table()[peer_idx];
    if peer.sock_type != SOCK_DGRAM {
        return EPROTOTYPE;
    }
    if ensure_socket_recv_buffer(idx).is_err() || ensure_socket_recv_buffer(peer_idx).is_err() {
        return ENOMEM;
    }
    let peer_owner_pid = peer.owner_pid;
    let peer_owner_uid = peer.owner_uid;
    let peer_owner_gid = peer.owner_gid;
    let slot = &mut socket_table()[idx];
    slot.peer_addr[..len].copy_from_slice(&addr[..len]);
    slot.peer_len = len as u32;
    slot.peer_idx = peer_idx as i32;
    slot.peer_pid = peer_owner_pid;
    slot.peer_uid = peer_owner_uid;
    slot.peer_gid = peer_owner_gid;
    slot.state = SOCK_STATE_CONNECTED;
    0
}

/// bind(fd, addr, addrlen) -> 0 or error
pub fn sys_bind(vm: &mut ThreadState, base: u32, fd: u64, addr: u64, addrlen: u64) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };

    let len = addrlen as usize;
    if !(2..=SOCKADDR_STORAGE_LEN).contains(&len) {
        return EINVAL;
    }

    let slot = &mut socket_table()[idx as usize];
    if slot.state != SOCK_STATE_IDLE {
        return EINVAL;
    }

    let mut buf = [0u8; SOCKADDR_STORAGE_LEN];
    unsafe {
        guest_mem::read_bytes(base, addr, &mut buf[..len]);
    }

    let sa_family = u16::from_le_bytes([buf[0], buf[1]]);
    if sa_family as u32 != slot.domain {
        return EINVAL;
    }

    if slot.domain == AF_UNIX && find_unix_socket_by_addr(&buf, len).is_some() {
        return EADDRINUSE;
    }

    slot.local_addr[..len].copy_from_slice(&buf[..len]);
    slot.local_len = len as u32;
    slot.state = SOCK_STATE_BOUND;
    0
}

/// listen(fd, backlog) -> 0 or error
pub fn sys_listen(vm: &mut ThreadState, base: u32, fd: u64, _backlog: u64) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };

    let slot = &mut socket_table()[idx as usize];
    if slot.domain == AF_UNIX && slot.sock_type != SOCK_STREAM {
        return EOPNOTSUPP;
    }
    if slot.state != SOCK_STATE_BOUND {
        return EINVAL;
    }

    slot.state = SOCK_STATE_LISTENING;
    0
}

/// connect(fd, addr, addrlen) -> STATUS_CONNECT (async to host runtime)
pub fn sys_connect(vm: &mut ThreadState, base: u32, fd: u64, addr: u64, addrlen: u64) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };

    let len = addrlen as usize;
    if !(2..=SOCKADDR_STORAGE_LEN).contains(&len) {
        return EINVAL;
    }

    let slot = &mut socket_table()[idx as usize];
    if slot.state == SOCK_STATE_CONNECTED {
        return EISCONN;
    }
    if slot.state == SOCK_STATE_LISTENING {
        return EINVAL;
    }

    let mut buf = [0u8; SOCKADDR_STORAGE_LEN];
    unsafe {
        guest_mem::read_bytes(base, addr, &mut buf[..len]);
    }

    if slot.domain == AF_UNIX {
        return match slot.sock_type {
            SOCK_STREAM => unix_connect_stream(idx as usize, &buf, len),
            SOCK_DGRAM => unix_connect_dgram(idx as usize, &buf, len),
            _ => EPROTOTYPE,
        };
    }

    slot.peer_addr[..len].copy_from_slice(&buf[..len]);
    slot.peer_len = len as u32;
    slot.state = SOCK_STATE_CONNECTING;
    vm.socket_timeout_ms = socket_send_timeout_ms_for_slot(slot);
    fd_table::pin_blocked_fd(base, vm, fd);

    vm.status = STATUS_CONNECT;
    0
}

pub fn resume_connect_result_for_fd(vm: &mut ThreadState, base: u32, fd: u64, result: i64) {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        vm.x[10] = ENOTSOCK as u64;
        vm.status = STATUS_OK;
        fd_table::clear_blocked_ofd_pin(vm);
        crate::syscall::signal::check_pending(vm, base);
        return;
    };
    let nonblocking =
        fd_table::get_ofd(base, vm, fd).is_some_and(|ofd| ofd.status_flags & O_NONBLOCK != 0);

    if socket_table()[idx].state == SOCK_STATE_CONNECTING {
        if result == 0 {
            let current_recv = socket_table()[idx].recv_buf_idx;
            let allocated_recv_for_connect = current_recv == INVALID_BUF_IDX;
            let recv_buf_idx = if allocated_recv_for_connect {
                alloc_socket_recv_buffer().unwrap_or(INVALID_BUF_IDX)
            } else {
                current_recv
            };
            socket_table()[idx].recv_buf_idx = recv_buf_idx;
            socket_table()[idx].state = SOCK_STATE_CONNECTED;
            if recv_buf_idx == INVALID_BUF_IDX || ensure_external_peer(idx).is_err() {
                if allocated_recv_for_connect && recv_buf_idx >= 0 {
                    free_recv_buffer_if_unreferenced(recv_buf_idx, idx);
                    socket_table()[idx].recv_buf_idx = INVALID_BUF_IDX;
                }
                socket_table()[idx].external_peer = 0;
                socket_table()[idx].peer_idx = INVALID_PEER_IDX;
                socket_table()[idx].last_error = (-ENOMEM) as i32;
                socket_table()[idx].state = SOCK_STATE_IDLE;
                vm.x[10] = ENOMEM as u64;
                vm.status = STATUS_OK;
                fd_table::clear_blocked_ofd_pin(vm);
                crate::syscall::signal::check_pending(vm, base);
                return;
            } else if nonblocking {
                socket_table()[idx].last_error = 0;
            }
        } else {
            let slot = &mut socket_table()[idx];
            slot.last_error = (-result) as i32;
            slot.state = if slot.local_len > 0 {
                SOCK_STATE_BOUND
            } else {
                SOCK_STATE_IDLE
            };
        }
    }

    vm.socket_timeout_ms = -1;
    vm.x[10] = result as u64;
    vm.status = STATUS_OK;
    fd_table::clear_blocked_ofd_pin(vm);
    crate::syscall::signal::check_pending(vm, base);
}

pub fn resume_connect_result(vm: &mut ThreadState, base: u32, result: i64) {
    resume_connect_result_for_fd(vm, base, thread_connect_target_fd(vm), result);
}

/// accept4(fd, addr, addrlen, flags) -> new fd or STATUS_SOCKET_RECV
pub fn sys_accept4(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    addr: u64,
    addrlen_ptr: u64,
    flags: u64,
) -> i64 {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) as u64 != 0 {
        return EINVAL;
    }

    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };
    let listener = &mut socket_table()[idx as usize];
    if listener.state != SOCK_STATE_LISTENING {
        return EINVAL;
    }

    let accepted_idx = match accept_queue_pop(listener) {
        Some(value) => value,
        None => {
            let ofd = match fd_table::get_ofd(base, vm, fd) {
                Some(o) => o,
                None => return EBADF,
            };
            if ofd.status_flags & O_NONBLOCK != 0 {
                return EAGAIN;
            }
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.socket_timeout_ms = socket_recv_timeout_ms_for_slot(listener);
            vm.status = STATUS_SOCKET_RECV;
            return 0;
        }
    };

    let mut fd_flags = 0;
    if (flags as u32) & SOCK_NONBLOCK != 0 {
        fd_flags |= O_NONBLOCK;
    }
    if (flags as u32) & SOCK_CLOEXEC != 0 {
        fd_flags |= O_CLOEXEC;
    }
    let new_fd = fd_table::open_socket(vm, base, accepted_idx, fd_flags);
    if new_fd < 0 {
        return new_fd;
    }

    let accepted = &socket_table()[accepted_idx as usize];
    if addr != 0 && addrlen_ptr != 0 {
        let len = accepted.peer_len.min(SOCKADDR_STORAGE_LEN as u32) as usize;
        unsafe {
            guest_mem::write_bytes(base, addr, &accepted.peer_addr[..len]);
            guest_mem::write_u32(base, addrlen_ptr, len as u32);
        }
    }

    new_fd
}
