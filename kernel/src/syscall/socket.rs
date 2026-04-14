//! Socket syscalls: socket, bind, connect, accept4, sendto, recvfrom,
//! setsockopt, getsockopt, getsockname, getpeername.
//!
//! Semantics: https://man7.org/linux/man-pages/man2/socket.2.html
//!            https://man7.org/linux/man-pages/man7/socket.7.html
//!
//! Socket state is kernel Worker managed (allocated via alloc.rs).
//! For HTTP preview, the runtime can inject a virtual client connection into a
//! listening socket. Data then moves through the shared net ring buffers.
//!
use crate::abi::*;
use crate::alloc;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::{OpenFileDesc, ThreadState};

// Socket states
const SOCK_STATE_IDLE: u32 = 0;
const SOCK_STATE_BOUND: u32 = 1;
const SOCK_STATE_LISTENING: u32 = 2;
const SOCK_STATE_CONNECTED: u32 = 3;
const SOCK_STATE_CONNECTING: u32 = 4;
const SOCK_STATE_SHUTDOWN: u32 = 5;

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;
const SHUT_RD_MASK: u32 = 1 << 0;
const SHUT_WR_MASK: u32 = 1 << 1;

// Max sockaddr size we store (covers sockaddr_in and sockaddr_in6)
const SOCKADDR_STORAGE_LEN: usize = 28;
const ACCEPT_QUEUE_SIZE: usize = 16;
const INVALID_BUF_IDX: i32 = -1;
const INVALID_PEER_IDX: i32 = -1;
const SOL_SOCKET: u32 = 1;
const SO_REUSEADDR: u32 = 2;
const SO_TYPE: u32 = 3;
const SO_ERROR: u32 = 4;
const SO_BROADCAST: u32 = 6;
const SO_SNDBUF: u32 = 7;
const SO_RCVBUF: u32 = 8;
const SO_KEEPALIVE: u32 = 9;
const SO_REUSEPORT: u32 = 15;
const SO_ACCEPTCONN: u32 = 30;
const IPPROTO_TCP: u32 = 6;
const TCP_NODELAY: u32 = 1;
const DEFAULT_SOCKET_BUFFER: u32 = 8192;

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketSlot {
    domain: u32,
    sock_type: u32,
    protocol: u32,
    state: u32,
    local_addr: [u8; SOCKADDR_STORAGE_LEN],
    local_len: u32,
    peer_addr: [u8; SOCKADDR_STORAGE_LEN],
    peer_len: u32,
    peer_idx: i32,
    recv_buf_idx: i32,
    last_error: i32,
    so_reuseaddr: u32,
    so_reuseport: u32,
    so_keepalive: u32,
    so_broadcast: u32,
    so_sndbuf: u32,
    so_rcvbuf: u32,
    tcp_nodelay: u32,
    shutdown_mask: u32,
    accept_head: u32,
    accept_tail: u32,
    accept_queue: [i32; ACCEPT_QUEUE_SIZE],
}

/// Pointer to socket table in kernel Worker linear memory.
static mut SOCKET_TABLE_PTR: *mut [SocketSlot; MAX_SOCKETS] = core::ptr::null_mut();

/// Socket slot allocation bitmap (1 = in use).
static mut SOCKET_USED: u32 = 0;

fn socket_table() -> &'static mut [SocketSlot; MAX_SOCKETS] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(SOCKET_TABLE_PTR));
        &mut *p
    }
}

pub fn socket_table_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(SOCKET_TABLE_PTR)) as u32 }
}

pub fn socket_used() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(SOCKET_USED)) }
}

pub fn socket_table_bytes() -> u32 {
    core::mem::size_of::<[SocketSlot; MAX_SOCKETS]>() as u32
}

pub fn attach_socket_state(table_ptr: u32, used: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_TABLE_PTR),
            table_ptr as *mut [SocketSlot; MAX_SOCKETS],
        );
        core::ptr::write(core::ptr::addr_of_mut!(SOCKET_USED), used);
    }
}

/// Initialize socket subsystem. Allocates socket table via alloc.rs.
pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_TABLE_PTR),
            core::ptr::null_mut(),
        );
        core::ptr::write(core::ptr::addr_of_mut!(SOCKET_USED), 0);

        let size = core::mem::size_of::<[SocketSlot; MAX_SOCKETS]>() as u32;
        let align = core::mem::align_of::<SocketSlot>() as u32;
        let ptr = alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_TABLE_PTR),
            ptr as *mut [SocketSlot; MAX_SOCKETS],
        );
    }
}

fn alloc_socket_slot() -> Option<u32> {
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(SOCKET_USED));
        for i in 0..MAX_SOCKETS {
            if used & (1u32 << i) == 0 {
                core::ptr::write(core::ptr::addr_of_mut!(SOCKET_USED), used | (1u32 << i));
                socket_table()[i] = SocketSlot {
                    domain: 0,
                    sock_type: 0,
                    protocol: 0,
                    state: SOCK_STATE_IDLE,
                    local_addr: [0; SOCKADDR_STORAGE_LEN],
                    local_len: 0,
                    peer_addr: [0; SOCKADDR_STORAGE_LEN],
                    peer_len: 0,
                    peer_idx: INVALID_PEER_IDX,
                    recv_buf_idx: INVALID_BUF_IDX,
                    last_error: 0,
                    so_reuseaddr: 0,
                    so_reuseport: 0,
                    so_keepalive: 0,
                    so_broadcast: 0,
                    so_sndbuf: DEFAULT_SOCKET_BUFFER,
                    so_rcvbuf: DEFAULT_SOCKET_BUFFER,
                    tcp_nodelay: 0,
                    shutdown_mask: 0,
                    accept_head: 0,
                    accept_tail: 0,
                    accept_queue: [-1; ACCEPT_QUEUE_SIZE],
                };
                return Some(i as u32);
            }
        }
        None
    }
}

fn free_socket_slot(idx: u32) {
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(SOCKET_USED));
        core::ptr::write(core::ptr::addr_of_mut!(SOCKET_USED), used & !(1u32 << idx));
    }
}

/// Check if a socket slot is allocated.
pub fn is_slot_used(idx: u32) -> bool {
    if idx >= MAX_SOCKETS as u32 {
        return false;
    }
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(SOCKET_USED));
        used & (1u32 << idx) != 0
    }
}

/// Free a socket slot. Called from fd_table on last close.
pub fn socket_close(socket_idx: u32) {
    if socket_idx < MAX_SOCKETS as u32 {
        shutdown_slot(socket_idx as usize);
    }
}

/// Look up the socket index for an FD. Returns None if the FD is not a socket.
fn get_socket_idx(base: u32, vm: &ThreadState, fd: u64) -> Option<u32> {
    let ofd = fd_table::get_ofd(base, vm, fd)?;
    if ofd.fd_type != FD_TYPE_SOCKET {
        return None;
    }
    Some(ofd.ino)
}

fn port_from_sockaddr(addr: &[u8], len: u32) -> u16 {
    if len < 4 {
        return 0;
    }
    u16::from_be_bytes([addr[2], addr[3]])
}

fn accept_queue_len(slot: &SocketSlot) -> usize {
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

fn accept_queue_push(slot: &mut SocketSlot, value: u32) -> bool {
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

fn remove_socket_from_accept_queues(socket_idx: u32) {
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

fn socket_recv_available(idx: usize) -> usize {
    let slot = &socket_table()[idx];
    if slot.recv_buf_idx < 0 {
        return 0;
    }
    crate::net::ring_buffer::available(slot.recv_buf_idx as u32)
}

fn socket_send_space(idx: usize) -> usize {
    let peer_idx = socket_table()[idx].peer_idx;
    if peer_idx < 0 {
        return 0;
    }
    let peer = &socket_table()[peer_idx as usize];
    if peer.recv_buf_idx < 0 {
        return 0;
    }
    crate::net::ring_buffer::space(peer.recv_buf_idx as u32)
}

fn slot_peer_is_closed(idx: usize) -> bool {
    let peer_idx = socket_table()[idx].peer_idx;
    if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
        return true;
    }
    let peer = &socket_table()[peer_idx as usize];
    peer.state == SOCK_STATE_SHUTDOWN || peer.state == SOCK_STATE_IDLE
}

fn shutdown_slot(idx: usize) {
    if idx >= MAX_SOCKETS || !is_slot_used(idx as u32) {
        return;
    }

    let mut pending_accepts = [u32::MAX; ACCEPT_QUEUE_SIZE];
    let mut pending_accept_count = 0usize;
    {
        let slot = &socket_table()[idx];
        if slot.state == SOCK_STATE_LISTENING {
            let pending = accept_queue_len(slot);
            for offset in 0..pending {
                let queue_idx = (slot.accept_head as usize + offset) % ACCEPT_QUEUE_SIZE;
                let accepted_idx = slot.accept_queue[queue_idx];
                if accepted_idx >= 0 {
                    pending_accepts[pending_accept_count] = accepted_idx as u32;
                    pending_accept_count += 1;
                }
            }
        }
    }
    remove_socket_from_accept_queues(idx as u32);

    let peer_idx = socket_table()[idx].peer_idx;
    let recv_buf_idx = socket_table()[idx].recv_buf_idx;

    if recv_buf_idx >= 0 {
        crate::net::ring_buffer::free_buffer(recv_buf_idx as u32);
    }

    {
        let slot = &mut socket_table()[idx];
        slot.state = SOCK_STATE_SHUTDOWN;
        slot.recv_buf_idx = INVALID_BUF_IDX;
        slot.peer_idx = INVALID_PEER_IDX;
        slot.accept_head = 0;
        slot.accept_tail = 0;
        slot.accept_queue = [-1; ACCEPT_QUEUE_SIZE];
        slot.shutdown_mask = SHUT_RD_MASK | SHUT_WR_MASK;
    }

    if peer_idx >= 0 && (peer_idx as usize) < MAX_SOCKETS && is_slot_used(peer_idx as u32) {
        let peer = &mut socket_table()[peer_idx as usize];
        if peer.peer_idx == idx as i32 {
            peer.peer_idx = INVALID_PEER_IDX;
            if peer.state == SOCK_STATE_CONNECTED {
                peer.state = SOCK_STATE_SHUTDOWN;
            }
        }
    }

    free_socket_slot(idx as u32);

    for accepted_idx in pending_accepts.into_iter().take(pending_accept_count) {
        if !is_slot_used(accepted_idx) {
            continue;
        }
        let accepted_peer_idx = socket_table()[accepted_idx as usize].peer_idx;
        shutdown_slot(accepted_idx as usize);
        if accepted_peer_idx >= 0 && is_slot_used(accepted_peer_idx as u32) {
            shutdown_slot(accepted_peer_idx as usize);
        }
    }
}

// =========================================================================
// socket(2)
// =========================================================================

/// socket(domain, type, protocol) -> fd
pub fn sys_socket(vm: &mut ThreadState, base: u32, domain: u64, stype: u64, protocol: u64) -> i64 {
    let domain_val = domain as u32;
    let raw_type = stype as u32;

    // Extract flags from type
    let type_val = raw_type & 0xFF;
    let flags = raw_type & !0xFF;

    // Validate domain
    if domain_val != AF_INET && domain_val != AF_INET6 && domain_val != AF_UNIX {
        return EAFNOSUPPORT;
    }

    // Validate type
    if type_val != SOCK_STREAM && type_val != SOCK_DGRAM {
        return EINVAL;
    }

    let idx = match alloc_socket_slot() {
        Some(i) => i,
        None => return ENOMEM,
    };

    {
        let slot = &mut socket_table()[idx as usize];
        slot.domain = domain_val;
        slot.sock_type = type_val;
        slot.protocol = protocol as u32;
        slot.state = SOCK_STATE_IDLE;
    }

    // Translate SOCK_NONBLOCK/SOCK_CLOEXEC to O_NONBLOCK/O_CLOEXEC
    let mut fd_flags: i32 = 0;
    if flags & SOCK_NONBLOCK != 0 {
        fd_flags |= O_NONBLOCK;
    }
    if flags & SOCK_CLOEXEC != 0 {
        fd_flags |= O_CLOEXEC;
    }

    let fd = fd_table::open_socket(vm, base, idx, fd_flags);
    if fd < 0 {
        free_socket_slot(idx);
        return fd;
    }
    fd
}

// =========================================================================
// bind(2)
// =========================================================================

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

    // Copy address from guest memory
    let mut buf = [0u8; SOCKADDR_STORAGE_LEN];
    unsafe {
        guest_mem::read_bytes(base, addr, &mut buf[..len]);
    }

    // Validate that the address family matches the socket domain
    let sa_family = u16::from_le_bytes([buf[0], buf[1]]);
    if sa_family as u32 != slot.domain {
        return EINVAL;
    }

    slot.local_addr[..len].copy_from_slice(&buf[..len]);
    slot.local_len = len as u32;
    slot.state = SOCK_STATE_BOUND;
    0
}

// =========================================================================
// listen(2)
// =========================================================================

/// listen(fd, backlog) -> 0 or error
pub fn sys_listen(vm: &mut ThreadState, base: u32, fd: u64, _backlog: u64) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };

    let slot = &mut socket_table()[idx as usize];
    if slot.state != SOCK_STATE_BOUND {
        return EINVAL;
    }

    slot.state = SOCK_STATE_LISTENING;
    0
}

// =========================================================================
// connect(2)
// =========================================================================

/// connect(fd, addr, addrlen) -> STATUS_CONNECT (async to TS runtime)
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

    // Copy peer address from guest memory
    let mut buf = [0u8; SOCKADDR_STORAGE_LEN];
    unsafe {
        guest_mem::read_bytes(base, addr, &mut buf[..len]);
    }

    slot.peer_addr[..len].copy_from_slice(&buf[..len]);
    slot.peer_len = len as u32;
    slot.state = SOCK_STATE_CONNECTING;

    // Signal TS runtime to perform the actual connect
    vm.status = STATUS_CONNECT;
    0
}

pub fn resume_connect_result(vm: &mut ThreadState, base: u32, result: i64) {
    let fd = vm.x[10];
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        vm.x[10] = ENOTSOCK as u64;
        vm.status = STATUS_OK;
        crate::syscall::signal::check_pending(vm, base);
        return;
    };

    let slot = &mut socket_table()[idx];
    if slot.state == SOCK_STATE_CONNECTING {
        if result == 0 {
            slot.state = SOCK_STATE_CONNECTED;
            if slot.recv_buf_idx == INVALID_BUF_IDX {
                slot.recv_buf_idx = crate::net::ring_buffer::alloc_buffer()
                    .map(|value| value as i32)
                    .unwrap_or(INVALID_BUF_IDX);
            }
        } else {
            slot.last_error = (-result) as i32;
            slot.state = if slot.local_len > 0 {
                SOCK_STATE_BOUND
            } else {
                SOCK_STATE_IDLE
            };
        }
    }

    vm.x[10] = result as u64;
    vm.status = STATUS_OK;
    crate::syscall::signal::check_pending(vm, base);
}

// =========================================================================
// accept4(2)
// =========================================================================

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

// =========================================================================
// sendto(2)
// =========================================================================

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

    // For connected sockets (SOCK_STREAM), dest_addr must be NULL/0
    // For unconnected SOCK_DGRAM, dest_addr is required unless connected
    if slot.sock_type == SOCK_STREAM {
        if slot.state != SOCK_STATE_CONNECTED {
            return ENOTCONN;
        }
    } else if slot.state != SOCK_STATE_CONNECTED && dest_addr == 0 {
        return EDESTADDRREQ;
    }

    // If dest_addr is provided for DGRAM, record it temporarily as peer
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
        vm.status = STATUS_SOCKET_SEND;
        return 0;
    }
    n
}

// =========================================================================
// recvfrom(2)
// =========================================================================

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

    // For SOCK_STREAM, must be connected
    if slot.sock_type == SOCK_STREAM && slot.state != SOCK_STATE_CONNECTED {
        return ENOTCONN;
    }

    // Check if socket is non-blocking via OFD status_flags
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
    let slot = &socket_table()[idx];
    if slot.state != SOCK_STATE_CONNECTED && slot.state != SOCK_STATE_SHUTDOWN {
        return ENOTCONN;
    }
    if slot.recv_buf_idx < 0 {
        return if slot_peer_is_closed(idx) { 0 } else { EAGAIN };
    }

    let mut tmp = [0u8; 4096];
    let to_read = (len as usize).min(tmp.len());
    let n = crate::net::ring_buffer::read(slot.recv_buf_idx as u32, &mut tmp[..to_read]);
    if n > 0 {
        if !crate::syscall::memory::guest_range_accessible(base, buf, n as u64) {
            return EFAULT;
        }
        unsafe {
            guest_mem::write_bytes(base, buf, &tmp[..n]);
        }
        return n as i64;
    }
    if slot_peer_is_closed(idx) { 0 } else { EAGAIN }
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
    let peer_idx = slot.peer_idx;
    if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
        return EPIPE;
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

pub fn poll_revents(base: u32, vm: &ThreadState, fd: u64, interest: u32) -> u32 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(ofd) => ofd,
        None => return EPOLLERR,
    };
    poll_revents_ofd(&ofd, interest)
}

pub fn poll_revents_ofd(ofd: &OpenFileDesc, interest: u32) -> u32 {
    if ofd.fd_type != FD_TYPE_SOCKET {
        return EPOLLERR;
    }
    let idx = ofd.ino as usize;
    if idx >= MAX_SOCKETS {
        return EPOLLERR;
    }
    let slot = &socket_table()[idx];
    let mut revents = 0u32;

    if slot.state == SOCK_STATE_LISTENING {
        if accept_queue_len(slot) > 0 {
            revents |= EPOLLIN;
        }
    } else if slot.state == SOCK_STATE_CONNECTED || slot.state == SOCK_STATE_SHUTDOWN {
        if slot.shutdown_mask & SHUT_RD_MASK != 0 {
            revents |= EPOLLRDHUP;
        }
        if socket_recv_available(idx) > 0 {
            revents |= EPOLLIN;
        } else if slot_peer_is_closed(idx) {
            revents |= EPOLLHUP;
        }

        if socket_send_space(idx) > 0 {
            revents |= EPOLLOUT;
        } else if slot_peer_is_closed(idx) {
            revents |= EPOLLERR;
        }
    }

    revents & (interest | EPOLLERR | EPOLLHUP)
}

pub fn inject_http_connection(vm_ptr: u32, port: u16, request: &[u8]) -> i32 {
    let _ = vm_ptr;

    let listener_idx = socket_table()
        .iter()
        .enumerate()
        .find(|(_, slot)| {
            slot.state == SOCK_STATE_LISTENING
                && port_from_sockaddr(&slot.local_addr, slot.local_len) == port
        })
        .map(|(idx, _)| idx);

    let Some(listener_idx) = listener_idx else {
        return -1;
    };

    let Some(server_idx) = alloc_socket_slot().map(|idx| idx as usize) else {
        return -2;
    };
    let Some(client_idx) = alloc_socket_slot().map(|idx| idx as usize) else {
        shutdown_slot(server_idx);
        return -2;
    };
    let Some(server_recv) = crate::net::ring_buffer::alloc_buffer().map(|idx| idx as i32) else {
        shutdown_slot(server_idx);
        shutdown_slot(client_idx);
        return -2;
    };
    let Some(client_recv) = crate::net::ring_buffer::alloc_buffer().map(|idx| idx as i32) else {
        crate::net::ring_buffer::free_buffer(server_recv as u32);
        shutdown_slot(server_idx);
        shutdown_slot(client_idx);
        return -2;
    };

    let listener_local_addr = socket_table()[listener_idx].local_addr;
    let listener_local_len = socket_table()[listener_idx].local_len;
    let listener_domain = socket_table()[listener_idx].domain;
    let listener_type = socket_table()[listener_idx].sock_type;
    let listener_protocol = socket_table()[listener_idx].protocol;

    socket_table()[server_idx] = SocketSlot {
        domain: listener_domain,
        sock_type: listener_type,
        protocol: listener_protocol,
        state: SOCK_STATE_CONNECTED,
        local_addr: listener_local_addr,
        local_len: listener_local_len,
        peer_addr: [0; SOCKADDR_STORAGE_LEN],
        peer_len: 0,
        peer_idx: client_idx as i32,
        recv_buf_idx: server_recv,
        last_error: 0,
        so_reuseaddr: 0,
        so_reuseport: 0,
        so_keepalive: 0,
        so_broadcast: 0,
        so_sndbuf: DEFAULT_SOCKET_BUFFER,
        so_rcvbuf: DEFAULT_SOCKET_BUFFER,
        tcp_nodelay: 0,
        shutdown_mask: 0,
        accept_head: 0,
        accept_tail: 0,
        accept_queue: [-1; ACCEPT_QUEUE_SIZE],
    };
    socket_table()[client_idx] = SocketSlot {
        domain: listener_domain,
        sock_type: listener_type,
        protocol: listener_protocol,
        state: SOCK_STATE_CONNECTED,
        local_addr: [0; SOCKADDR_STORAGE_LEN],
        local_len: 0,
        peer_addr: listener_local_addr,
        peer_len: listener_local_len,
        peer_idx: server_idx as i32,
        recv_buf_idx: client_recv,
        last_error: 0,
        so_reuseaddr: 0,
        so_reuseport: 0,
        so_keepalive: 0,
        so_broadcast: 0,
        so_sndbuf: DEFAULT_SOCKET_BUFFER,
        so_rcvbuf: DEFAULT_SOCKET_BUFFER,
        tcp_nodelay: 0,
        shutdown_mask: 0,
        accept_head: 0,
        accept_tail: 0,
        accept_queue: [-1; ACCEPT_QUEUE_SIZE],
    };

    if !request.is_empty() {
        let _ = crate::net::ring_buffer::write(server_recv as u32, request);
    }

    if !accept_queue_push(&mut socket_table()[listener_idx], server_idx as u32) {
        shutdown_slot(server_idx);
        shutdown_slot(client_idx);
        return -3;
    }

    client_idx as i32
}

pub fn read_http_response(_vm_ptr: u32, conn_id: i32, dst: &mut [u8]) -> i32 {
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

pub fn close_http_connection(_vm_ptr: u32, conn_id: i32) {
    if conn_id < 0 || conn_id as usize >= MAX_SOCKETS || !is_slot_used(conn_id as u32) {
        return;
    }
    shutdown_slot(conn_id as usize);
}

// =========================================================================
// setsockopt(2) / getsockopt(2)
// =========================================================================

fn read_opt_i32(base: u32, optval: u64, optlen: u64) -> Result<i32, i64> {
    if optval == 0 || optlen < 4 {
        return Err(EINVAL);
    }
    Ok(unsafe { guest_mem::read_i32(base, optval) })
}

fn write_opt_u32(base: u32, optval: u64, optlen_ptr: u64, value: u32) -> i64 {
    if optval == 0 || optlen_ptr == 0 {
        return EFAULT;
    }

    let user_len = unsafe { guest_mem::read_u32(base, optlen_ptr) } as usize;
    let bytes = value.to_le_bytes();
    let copy_len = user_len.min(bytes.len());
    unsafe {
        guest_mem::write_bytes(base, optval, &bytes[..copy_len]);
        guest_mem::write_u32(base, optlen_ptr, bytes.len() as u32);
    }
    0
}

/// setsockopt(fd, level, optname, optval, optlen)
pub fn sys_setsockopt(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    level: u64,
    optname: u64,
    optval: u64,
    optlen: u64,
) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(idx) => idx as usize,
        None => return ENOTSOCK,
    };
    let slot = &mut socket_table()[idx];

    match (level as u32, optname as u32) {
        (SOL_SOCKET, SO_REUSEADDR) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_reuseaddr = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_REUSEPORT) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_reuseport = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_KEEPALIVE) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_keepalive = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_BROADCAST) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_broadcast = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_SNDBUF) => match read_opt_i32(base, optval, optlen) {
            Ok(value) if value > 0 => {
                slot.so_sndbuf = value.max(256) as u32;
                0
            }
            Ok(_) => EINVAL,
            Err(err) => err,
        },
        (SOL_SOCKET, SO_RCVBUF) => match read_opt_i32(base, optval, optlen) {
            Ok(value) if value > 0 => {
                slot.so_rcvbuf = value.max(256) as u32;
                0
            }
            Ok(_) => EINVAL,
            Err(err) => err,
        },
        (IPPROTO_TCP, TCP_NODELAY) => {
            if slot.sock_type != SOCK_STREAM {
                return ENOPROTOOPT;
            }
            match read_opt_i32(base, optval, optlen) {
                Ok(value) => {
                    slot.tcp_nodelay = u32::from(value != 0);
                    0
                }
                Err(err) => err,
            }
        }
        (SOL_SOCKET, SO_TYPE | SO_ERROR | SO_ACCEPTCONN) => ENOPROTOOPT,
        _ => ENOPROTOOPT,
    }
}

/// getsockopt(fd, level, optname, optval, optlen)
pub fn sys_getsockopt(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    level: u64,
    optname: u64,
    optval: u64,
    optlen: u64,
) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(idx) => idx as usize,
        None => return ENOTSOCK,
    };
    let slot = &mut socket_table()[idx];

    match (level as u32, optname as u32) {
        (SOL_SOCKET, SO_TYPE) => write_opt_u32(base, optval, optlen, slot.sock_type),
        (SOL_SOCKET, SO_ERROR) => {
            let error = slot.last_error as u32;
            slot.last_error = 0;
            write_opt_u32(base, optval, optlen, error)
        }
        (SOL_SOCKET, SO_REUSEADDR) => write_opt_u32(base, optval, optlen, slot.so_reuseaddr),
        (SOL_SOCKET, SO_REUSEPORT) => write_opt_u32(base, optval, optlen, slot.so_reuseport),
        (SOL_SOCKET, SO_KEEPALIVE) => write_opt_u32(base, optval, optlen, slot.so_keepalive),
        (SOL_SOCKET, SO_BROADCAST) => write_opt_u32(base, optval, optlen, slot.so_broadcast),
        (SOL_SOCKET, SO_SNDBUF) => write_opt_u32(base, optval, optlen, slot.so_sndbuf),
        (SOL_SOCKET, SO_RCVBUF) => write_opt_u32(base, optval, optlen, slot.so_rcvbuf),
        (SOL_SOCKET, SO_ACCEPTCONN) => write_opt_u32(
            base,
            optval,
            optlen,
            u32::from(slot.state == SOCK_STATE_LISTENING),
        ),
        (IPPROTO_TCP, TCP_NODELAY) => {
            if slot.sock_type != SOCK_STREAM {
                return ENOPROTOOPT;
            }
            write_opt_u32(base, optval, optlen, slot.tcp_nodelay)
        }
        _ => ENOPROTOOPT,
    }
}

// =========================================================================
// getsockname(2) / getpeername(2)
// =========================================================================

/// getsockname(fd, addr, addrlen) -> 0 or error
pub fn sys_getsockname(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    addr: u64,
    addrlen_ptr: u64,
) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };

    let slot = &socket_table()[idx as usize];

    if slot.local_len == 0 {
        // No address bound; return a zeroed sockaddr with the right family
        // struct sockaddr { u16 sa_family; ... }
        let family_bytes = (slot.domain as u16).to_le_bytes();
        unsafe {
            guest_mem::write_bytes(base, addr, &family_bytes);
            // Zero out the rest up to the addrlen the caller provided
            let caller_len = guest_mem::read_u32(base, addrlen_ptr);
            if caller_len > 2 {
                let zero_len = (caller_len as usize - 2).min(SOCKADDR_STORAGE_LEN - 2);
                let zeros = [0u8; SOCKADDR_STORAGE_LEN];
                guest_mem::write_bytes(base, addr + 2, &zeros[..zero_len]);
            }
            // Write actual length (2 for just the family)
            guest_mem::write_u32(base, addrlen_ptr, 2);
        }
        return 0;
    }

    let len = slot.local_len as usize;
    unsafe {
        guest_mem::write_bytes(base, addr, &slot.local_addr[..len]);
        guest_mem::write_u32(base, addrlen_ptr, len as u32);
    }
    0
}

/// getpeername(fd, addr, addrlen) -> 0 or error
pub fn sys_getpeername(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    addr: u64,
    addrlen_ptr: u64,
) -> i64 {
    let idx = match get_socket_idx(base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };

    let slot = &socket_table()[idx as usize];
    if slot.peer_len == 0 {
        return ENOTCONN;
    }

    let len = slot.peer_len as usize;
    unsafe {
        guest_mem::write_bytes(base, addr, &slot.peer_addr[..len]);
        guest_mem::write_u32(base, addrlen_ptr, len as u32);
    }
    0
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::TestVm;

    #[test]
    fn listener_close_drains_pending_accepts_and_peers() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x50, 0x00, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let bind_addr = t.scratch + 0x700;
        t.write_mem(bind_addr, &sockaddr);
        assert_eq!(sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16), 0);
        assert_eq!(sys_listen(&mut t.vm, t.base, fd as u64, 8), 0);

        let listener_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("listener OFD should exist")
            .ino;
        let client_idx = inject_http_connection(0, 0x5000, b"GET / HTTP/1.0\r\n\r\n");
        assert!(client_idx >= 0);

        let listener = &socket_table()[listener_idx as usize];
        assert_eq!(accept_queue_len(listener), 1);
        let server_idx = listener.accept_queue[listener.accept_head as usize] as u32;
        assert!(is_slot_used(server_idx));
        assert!(is_slot_used(client_idx as u32));

        assert_eq!(t.sys_close(fd), 0);
        assert!(!is_slot_used(listener_idx));
        assert!(!is_slot_used(server_idx));
        assert!(!is_slot_used(client_idx as u32));
        assert_eq!(crate::net::ring_buffer::net_buffer_state().1, 0);
    }

    #[test]
    fn closing_queued_accept_removes_stale_listener_entry() {
        let mut t = TestVm::new();
        let fd = sys_socket(
            &mut t.vm,
            t.base,
            AF_INET as u64,
            (SOCK_STREAM | SOCK_NONBLOCK) as u64,
            0,
        );
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x50, 0x00, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let bind_addr = t.scratch + 0x800;
        t.write_mem(bind_addr, &sockaddr);
        assert_eq!(sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16), 0);
        assert_eq!(sys_listen(&mut t.vm, t.base, fd as u64, 8), 0);

        let listener_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("listener OFD should exist")
            .ino;
        let client_idx = inject_http_connection(0, 0x5000, b"GET / HTTP/1.0\r\n\r\n");
        assert!(client_idx >= 0);

        let listener = &socket_table()[listener_idx as usize];
        assert_eq!(accept_queue_len(listener), 1);
        let server_idx = listener.accept_queue[listener.accept_head as usize] as u32;

        socket_close(server_idx);
        assert!(!is_slot_used(server_idx));
        assert_eq!(accept_queue_len(&socket_table()[listener_idx as usize]), 0);

        let ret = sys_accept4(&mut t.vm, t.base, fd as u64, 0, 0, 0);
        assert_eq!(ret, EAGAIN);
    }
}
