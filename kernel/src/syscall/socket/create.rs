use super::{
    ACCEPT_QUEUE_SIZE, DEFAULT_SOCKET_BUFFER, IPPROTO_TCP, IPPROTO_UDP, NETLINK_ROUTE,
    SOCK_STATE_CONNECTED, SOCK_STATE_IDLE, SOCKADDR_STORAGE_LEN, SocketSlot, alloc_socket_cookie,
    alloc_socket_recv_buffer, alloc_socket_slot, free_socket_slot, shutdown_slot, socket_table,
};
use crate::abi::*;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::ThreadState;

fn socket_fd_flags(flags: u32) -> i32 {
    let mut fd_flags: i32 = 0;
    if flags & SOCK_NONBLOCK != 0 {
        fd_flags |= O_NONBLOCK;
    }
    if flags & SOCK_CLOEXEC != 0 {
        fd_flags |= O_CLOEXEC;
    }
    fd_flags
}

/// socket(domain, type, protocol) -> fd
pub fn sys_socket(vm: &mut ThreadState, base: u32, domain: u64, stype: u64, protocol: u64) -> i64 {
    let domain_val = domain as u32;
    let raw_type = stype as u32;

    // Extract flags from type
    let type_val = raw_type & 0xFF;
    let flags = raw_type & !0xFF;

    // Validate domain
    if domain_val != AF_INET
        && domain_val != AF_INET6
        && domain_val != AF_UNIX
        && domain_val != AF_NETLINK
    {
        return EAFNOSUPPORT;
    }

    // Validate type
    if type_val != SOCK_STREAM
        && type_val != SOCK_DGRAM
        && !(domain_val == AF_NETLINK && type_val == SOCK_RAW)
    {
        return EINVAL;
    }

    let protocol_val = if protocol == 0 {
        match (domain_val, type_val) {
            (AF_INET | AF_INET6, SOCK_STREAM) => IPPROTO_TCP,
            (AF_INET | AF_INET6, SOCK_DGRAM) => IPPROTO_UDP,
            (AF_NETLINK, SOCK_RAW) => NETLINK_ROUTE,
            _ => 0,
        }
    } else {
        protocol as u32
    };

    let idx = match alloc_socket_slot() {
        Some(i) => i,
        None => return ENOMEM,
    };

    {
        let slot = &mut socket_table()[idx as usize];
        slot.domain = domain_val;
        slot.sock_type = type_val;
        slot.protocol = protocol_val;
        slot.state = SOCK_STATE_IDLE;
        slot.owner_pid = crate::syscall::process::current_process_pid(vm, base);
        slot.owner_uid = vm.euid;
        slot.owner_gid = vm.egid;
    }

    let fd = fd_table::open_socket(vm, base, idx, socket_fd_flags(flags));
    if fd < 0 {
        free_socket_slot(idx);
        return fd;
    }
    fd
}

/// socketpair(domain, type, protocol, sv) -> 0 or error
pub fn sys_socketpair(
    vm: &mut ThreadState,
    base: u32,
    domain: u64,
    stype: u64,
    protocol: u64,
    sv: u64,
) -> i64 {
    if sv == 0 || !crate::syscall::memory::guest_range_accessible(base, sv, 8) {
        return EFAULT;
    }

    let domain_val = domain as u32;
    if domain_val != AF_UNIX {
        return EAFNOSUPPORT;
    }

    let raw_type = stype as u32;
    let type_val = raw_type & 0xFF;
    let flags = raw_type & !0xFF;
    if type_val != SOCK_STREAM && type_val != SOCK_DGRAM {
        return EINVAL;
    }

    let protocol_val = protocol as u32;
    let Some(left_idx) = alloc_socket_slot().map(|idx| idx as usize) else {
        return ENOMEM;
    };
    let Some(right_idx) = alloc_socket_slot().map(|idx| idx as usize) else {
        free_socket_slot(left_idx as u32);
        return ENOMEM;
    };
    let Some(left_recv) = alloc_socket_recv_buffer() else {
        free_socket_slot(left_idx as u32);
        free_socket_slot(right_idx as u32);
        return ENOMEM;
    };
    let Some(right_recv) = alloc_socket_recv_buffer() else {
        crate::net::ring_buffer::free_buffer(left_recv as u32);
        free_socket_slot(left_idx as u32);
        free_socket_slot(right_idx as u32);
        return ENOMEM;
    };

    let pid = crate::syscall::process::current_process_pid(vm, base);
    let uid = vm.euid;
    let gid = vm.egid;
    socket_table()[left_idx] = SocketSlot {
        domain: domain_val,
        sock_type: type_val,
        protocol: protocol_val,
        state: SOCK_STATE_CONNECTED,
        owner_pid: pid,
        owner_uid: uid,
        owner_gid: gid,
        local_addr: [0; SOCKADDR_STORAGE_LEN],
        local_len: 0,
        peer_addr: [0; SOCKADDR_STORAGE_LEN],
        peer_len: 0,
        peer_idx: right_idx as i32,
        peer_pid: pid,
        peer_uid: uid,
        peer_gid: gid,
        external_peer: 0,
        recv_buf_idx: left_recv,
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
    socket_table()[right_idx] = SocketSlot {
        domain: domain_val,
        sock_type: type_val,
        protocol: protocol_val,
        state: SOCK_STATE_CONNECTED,
        owner_pid: pid,
        owner_uid: uid,
        owner_gid: gid,
        local_addr: [0; SOCKADDR_STORAGE_LEN],
        local_len: 0,
        peer_addr: [0; SOCKADDR_STORAGE_LEN],
        peer_len: 0,
        peer_idx: left_idx as i32,
        peer_pid: pid,
        peer_uid: uid,
        peer_gid: gid,
        external_peer: 0,
        recv_buf_idx: right_recv,
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

    let fd_flags = socket_fd_flags(flags);
    let left_fd = fd_table::open_socket(vm, base, left_idx as u32, fd_flags);
    if left_fd < 0 {
        shutdown_slot(left_idx);
        shutdown_slot(right_idx);
        return left_fd;
    }
    let right_fd = fd_table::open_socket(vm, base, right_idx as u32, fd_flags);
    if right_fd < 0 {
        let _ = fd_table::sys_close(vm, base, left_fd as u64);
        shutdown_slot(left_idx);
        shutdown_slot(right_idx);
        return right_fd;
    }

    unsafe {
        guest_mem::write_u32(base, sv, left_fd as u32);
        guest_mem::write_u32(base, sv + 4, right_fd as u32);
    }
    0
}
