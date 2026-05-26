//! Socket syscalls: socket, bind, connect, accept4, sendto, recvfrom,
//! setsockopt, getsockopt, getsockname, getpeername.
//!
//! Semantics: https://man7.org/linux/man-pages/man2/socket.2.html
//!            https://man7.org/linux/man-pages/man7/socket.7.html
//!            https://man7.org/linux/man-pages/man7/unix.7.html
//!
//! Socket state is kernel Worker managed (allocated via alloc.rs).
//! For HTTP preview, the runtime can inject a virtual client connection into a
//! listening socket. Data then moves through the shared net ring buffers.
//!
mod address;

use crate::abi::*;
use crate::alloc;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::{OpenFileDesc, ThreadState};

use address::port_from_sockaddr;
pub use address::{connect_peer_addr, connect_peer_addr_for_fd, sys_getpeername, sys_getsockname};

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

// Covers sockaddr_in, sockaddr_in6, and Linux sockaddr_un (sun_path[108]).
pub(super) const SOCKADDR_STORAGE_LEN: usize = 128;
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
const SO_SNDBUFFORCE: u32 = 32;
const SO_RCVBUFFORCE: u32 = 33;
const SO_KEEPALIVE: u32 = 9;
const SO_OOBINLINE: u32 = 10;
const SO_NO_CHECK: u32 = 11;
const SO_BSDCOMPAT: u32 = 14;
const SO_REUSEPORT: u32 = 15;
const SO_RCVLOWAT: u32 = 18;
const SO_SNDLOWAT: u32 = 19;
const SO_RCVTIMEO_OLD: u32 = 20;
const SO_SNDTIMEO_OLD: u32 = 21;
const SO_ACCEPTCONN: u32 = 30;
const SO_PROTOCOL: u32 = 38;
const SO_DOMAIN: u32 = 39;
const SO_INCOMING_CPU: u32 = 49;
const SO_COOKIE: u32 = 57;
const SO_RCVTIMEO_NEW: u32 = 66;
const SO_SNDTIMEO_NEW: u32 = 67;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const NETLINK_ROUTE: u32 = 0;
const TCP_NODELAY: u32 = 1;
const DEFAULT_SOCKET_BUFFER: u32 = 256 * 1024;
const MSGHDR_SIZE: u64 = 56;
const MSGHDR_NAME_OFF: u64 = 0;
const MSGHDR_NAMELEN_OFF: u64 = 8;
const MSGHDR_IOV_OFF: u64 = 16;
const MSGHDR_IOVLEN_OFF: u64 = 24;
const MSGHDR_FLAGS_OFF: u64 = 48;
const IOVEC_SIZE: u64 = 16;
const MAX_MSG_IOV: u64 = 1024;
const MSG_NOSIGNAL: u64 = 0x4000;

fn timeout_to_millis(sec: u64, usec: u64) -> i64 {
    if sec == 0 && usec == 0 {
        return -1;
    }
    let millis = sec
        .saturating_mul(1000)
        .saturating_add(usec.saturating_add(999) / 1000);
    millis.min(i64::MAX as u64) as i64
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketSlot {
    domain: u32,
    sock_type: u32,
    protocol: u32,
    state: u32,
    owner_pid: i32,
    owner_uid: u32,
    owner_gid: u32,
    local_addr: [u8; SOCKADDR_STORAGE_LEN],
    local_len: u32,
    peer_addr: [u8; SOCKADDR_STORAGE_LEN],
    peer_len: u32,
    peer_idx: i32,
    peer_pid: i32,
    peer_uid: u32,
    peer_gid: u32,
    external_peer: u32,
    recv_buf_idx: i32,
    last_error: i32,
    so_cookie: u64,
    so_reuseaddr: u32,
    so_reuseport: u32,
    so_keepalive: u32,
    so_oobinline: u32,
    so_nocheck: u32,
    so_bsdcompat: u32,
    so_broadcast: u32,
    so_sndbuf: u32,
    so_rcvbuf: u32,
    so_rcvlowat: u32,
    so_rcvtimeo_sec: u64,
    so_rcvtimeo_usec: u64,
    so_sndtimeo_sec: u64,
    so_sndtimeo_usec: u64,
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
static mut NEXT_SOCKET_COOKIE: u64 = 1;
static mut SOCKET_READ_COUNT: [u32; MAX_SOCKETS] = [0; MAX_SOCKETS];
static mut SOCKET_READ_BYTES: [u64; MAX_SOCKETS] = [0; MAX_SOCKETS];
static mut SOCKET_READ_LAST_FD: [u32; MAX_SOCKETS] = [0; MAX_SOCKETS];
static mut SOCKET_READ_LAST_RESULT: [i64; MAX_SOCKETS] = [0; MAX_SOCKETS];
static mut SOCKET_READ_LAST_BEFORE: [u32; MAX_SOCKETS] = [0; MAX_SOCKETS];
static mut SOCKET_READ_LAST_AFTER: [u32; MAX_SOCKETS] = [0; MAX_SOCKETS];

pub(super) fn socket_table() -> &'static mut [SocketSlot; MAX_SOCKETS] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(SOCKET_TABLE_PTR));
        &mut *p
    }
}

fn alloc_socket_cookie() -> u64 {
    unsafe {
        let cookie = core::ptr::read(core::ptr::addr_of!(NEXT_SOCKET_COOKIE));
        let next = cookie.saturating_add(1).max(1);
        core::ptr::write(core::ptr::addr_of_mut!(NEXT_SOCKET_COOKIE), next);
        cookie
    }
}

fn empty_socket_slot() -> SocketSlot {
    SocketSlot {
        domain: 0,
        sock_type: 0,
        protocol: 0,
        state: SOCK_STATE_IDLE,
        owner_pid: 0,
        owner_uid: 0,
        owner_gid: 0,
        local_addr: [0; SOCKADDR_STORAGE_LEN],
        local_len: 0,
        peer_addr: [0; SOCKADDR_STORAGE_LEN],
        peer_len: 0,
        peer_idx: INVALID_PEER_IDX,
        peer_pid: 0,
        peer_uid: 0,
        peer_gid: 0,
        external_peer: 0,
        recv_buf_idx: INVALID_BUF_IDX,
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
        core::ptr::write(core::ptr::addr_of_mut!(SOCKET_READ_COUNT), [0; MAX_SOCKETS]);
        core::ptr::write(core::ptr::addr_of_mut!(SOCKET_READ_BYTES), [0; MAX_SOCKETS]);
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_READ_LAST_FD),
            [0; MAX_SOCKETS],
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_READ_LAST_RESULT),
            [0; MAX_SOCKETS],
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_READ_LAST_BEFORE),
            [0; MAX_SOCKETS],
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_READ_LAST_AFTER),
            [0; MAX_SOCKETS],
        );

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
    reap_shutdown_socket_slots(u32::MAX);
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(SOCKET_USED));
        for i in 0..MAX_SOCKETS {
            if used & (1u32 << i) == 0 {
                core::ptr::write(core::ptr::addr_of_mut!(SOCKET_USED), used | (1u32 << i));
                socket_table()[i] = empty_socket_slot();
                return Some(i as u32);
            }
        }
        None
    }
}

fn reap_shutdown_socket_slots(excluded_idx: u32) {
    let mut stale = [u32::MAX; MAX_SOCKETS];
    let mut stale_count = 0usize;
    for idx in 0..MAX_SOCKETS {
        if idx as u32 == excluded_idx || !is_slot_used(idx as u32) {
            continue;
        }
        if external_peer_slot_has_live_owner(idx as u32) {
            continue;
        }
        if !socket_slot_has_ofd_ref(idx as u32) || socket_table()[idx].state == SOCK_STATE_SHUTDOWN
        {
            stale[stale_count] = idx as u32;
            stale_count += 1;
        }
    }
    for idx in stale.into_iter().take(stale_count) {
        if idx != excluded_idx && is_slot_used(idx) {
            shutdown_slot(idx as usize);
        }
    }
}

fn external_peer_slot_has_live_owner(socket_idx: u32) -> bool {
    if socket_idx >= MAX_SOCKETS as u32 {
        return false;
    }
    let slot = &socket_table()[socket_idx as usize];
    if slot.external_peer == 0 || slot.peer_idx < 0 {
        return false;
    }
    let owner_idx = slot.peer_idx as u32;
    if owner_idx >= MAX_SOCKETS as u32 || !is_slot_used(owner_idx) {
        return false;
    }
    socket_table()[owner_idx as usize].peer_idx == socket_idx as i32
}

fn socket_slot_has_ofd_ref(socket_idx: u32) -> bool {
    for ofd_id in 1..crate::abi::MAX_FDS {
        if let Some(ofd) = fd_table::get_ofd_by_id(ofd_id as u32) {
            if ofd.fd_type == FD_TYPE_SOCKET && ofd.ino == socket_idx {
                return true;
            }
        }
    }
    false
}

fn mark_socket_slot_used(idx: u32) {
    if idx >= MAX_SOCKETS as u32 {
        return;
    }
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(SOCKET_USED));
        core::ptr::write(core::ptr::addr_of_mut!(SOCKET_USED), used | (1u32 << idx));
    }
}

fn alloc_socket_slot_excluding(excluded_idx: u32) -> Option<u32> {
    reap_shutdown_socket_slots(excluded_idx);
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(SOCKET_USED)) | (1u32 << excluded_idx);
        for i in 0..MAX_SOCKETS {
            if used & (1u32 << i) == 0 {
                core::ptr::write(core::ptr::addr_of_mut!(SOCKET_USED), used | (1u32 << i));
                socket_table()[i] = empty_socket_slot();
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

fn mark_referenced_recv_buffers_used() {
    for idx in 0..MAX_SOCKETS {
        if !is_slot_used(idx as u32) {
            continue;
        }
        let recv_buf_idx = socket_table()[idx].recv_buf_idx;
        if recv_buf_idx >= 0 {
            crate::net::ring_buffer::mark_buffer_used(recv_buf_idx as u32);
        }
    }
}

fn sync_referenced_recv_buffers_used() {
    let (net_buf_base, _) = crate::net::ring_buffer::net_buffer_state();
    let mut used = 0u64;
    for idx in 0..MAX_SOCKETS {
        if !is_slot_used(idx as u32) {
            continue;
        }
        let recv_buf_idx = socket_table()[idx].recv_buf_idx;
        if recv_buf_idx >= 0 {
            used |= 1u64 << recv_buf_idx;
        }
    }
    crate::net::ring_buffer::attach_net_buffer_state(net_buf_base, used);
}

fn alloc_socket_recv_buffer() -> Option<i32> {
    mark_referenced_recv_buffers_used();
    crate::net::ring_buffer::alloc_buffer().map(|idx| idx as i32)
}

fn recv_buffer_referenced_elsewhere(recv_buf_idx: i32, owner_idx: usize) -> bool {
    if recv_buf_idx < 0 {
        return false;
    }
    for idx in 0..MAX_SOCKETS {
        if idx == owner_idx || !is_slot_used(idx as u32) {
            continue;
        }
        if socket_table()[idx].recv_buf_idx == recv_buf_idx {
            return true;
        }
    }
    false
}

fn free_recv_buffer_if_unreferenced(recv_buf_idx: i32, owner_idx: usize) {
    if recv_buf_idx >= 0 && !recv_buffer_referenced_elsewhere(recv_buf_idx, owner_idx) {
        crate::net::ring_buffer::free_buffer(recv_buf_idx as u32);
    }
}

/// Free a socket slot. Called from fd_table on last close.
pub fn socket_close(socket_idx: u32) {
    if socket_idx < MAX_SOCKETS as u32 {
        shutdown_slot(socket_idx as usize);
    }
}

fn socket_recv_timeout_ms_for_slot(slot: &SocketSlot) -> i64 {
    timeout_to_millis(slot.so_rcvtimeo_sec, slot.so_rcvtimeo_usec)
}

fn socket_send_timeout_ms_for_slot(slot: &SocketSlot) -> i64 {
    timeout_to_millis(slot.so_sndtimeo_sec, slot.so_sndtimeo_usec)
}

pub fn socket_recv_timeout_ms_for_fd(base: u32, vm: &ThreadState, fd: u64) -> i64 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return -1;
    };
    socket_recv_timeout_ms_for_slot(&socket_table()[idx])
}

pub fn socket_send_timeout_ms_for_fd(base: u32, vm: &ThreadState, fd: u64) -> i64 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return -1;
    };
    socket_send_timeout_ms_for_slot(&socket_table()[idx])
}

/// Look up the socket index for an FD. Returns None if the FD is not a socket.
pub(super) fn get_socket_idx(base: u32, vm: &ThreadState, fd: u64) -> Option<u32> {
    let ofd = fd_table::get_ofd(base, vm, fd)?;
    if ofd.fd_type != FD_TYPE_SOCKET {
        return None;
    }
    Some(ofd.ino)
}

pub(super) fn thread_connect_target_fd(vm: &ThreadState) -> u64 {
    if vm.blocked_ofd_id != 0 {
        vm.blocked_fd as u64
    } else {
        vm.x[10]
    }
}

pub fn thread_connect_fd(vm: &ThreadState) -> i32 {
    thread_connect_target_fd(vm) as i32
}

fn ensure_external_peer(idx: usize) -> Result<(), i64> {
    if external_peer_is_usable_for_socket(idx) {
        socket_table()[idx].external_peer = 1;
        return Ok(());
    }
    if let Some(peer_idx) = find_external_peer_for_socket(idx) {
        socket_table()[idx].peer_idx = peer_idx as i32;
        socket_table()[idx].external_peer = 1;
        socket_table()[peer_idx].state = SOCK_STATE_CONNECTED;
        socket_table()[peer_idx].shutdown_mask = 0;
        return Ok(());
    }
    reap_detached_external_peers();
    let stale_peer_idx = socket_table()[idx].peer_idx;
    if stale_peer_idx >= 0
        && (stale_peer_idx as usize) < MAX_SOCKETS
        && is_slot_used(stale_peer_idx as u32)
    {
        shutdown_slot(stale_peer_idx as usize);
    }
    socket_table()[idx].peer_idx = INVALID_PEER_IDX;
    mark_socket_slot_used(idx as u32);
    let Some(peer_idx) = alloc_socket_slot_excluding(idx as u32).map(|value| value as usize) else {
        return Err(ENOMEM);
    };
    let Some(peer_recv) = alloc_socket_recv_buffer() else {
        shutdown_slot(peer_idx);
        return Err(ENOMEM);
    };
    let domain = socket_table()[idx].domain;
    let sock_type = socket_table()[idx].sock_type;
    let protocol = socket_table()[idx].protocol;
    let peer_addr = socket_table()[idx].peer_addr;
    let peer_len = socket_table()[idx].peer_len;
    socket_table()[peer_idx] = SocketSlot {
        domain,
        sock_type,
        protocol,
        state: SOCK_STATE_CONNECTED,
        external_peer: 1,
        local_addr: peer_addr,
        local_len: peer_len,
        peer_idx: idx as i32,
        recv_buf_idx: peer_recv,
        ..empty_socket_slot()
    };
    socket_table()[idx].peer_idx = peer_idx as i32;
    socket_table()[idx].external_peer = 1;
    Ok(())
}

fn external_peer_is_usable_for_socket(idx: usize) -> bool {
    let peer_idx = socket_table()[idx].peer_idx;
    if peer_idx < 0 || (peer_idx as usize) >= MAX_SOCKETS || !is_slot_used(peer_idx as u32) {
        return false;
    }
    let peer = &socket_table()[peer_idx as usize];
    peer.external_peer != 0
        && peer.peer_idx == idx as i32
        && peer.state == SOCK_STATE_CONNECTED
        && peer.recv_buf_idx >= 0
}

fn find_external_peer_for_socket(idx: usize) -> Option<usize> {
    socket_table()
        .iter()
        .enumerate()
        .find(|(peer_idx, slot)| {
            *peer_idx != idx
                && is_slot_used(*peer_idx as u32)
                && slot.external_peer != 0
                && slot.peer_idx == idx as i32
                && slot.state == SOCK_STATE_CONNECTED
                && slot.recv_buf_idx >= 0
        })
        .map(|(peer_idx, _)| peer_idx)
}

fn reap_detached_external_peers() {
    let mut stale = [u32::MAX; MAX_SOCKETS];
    let mut stale_count = 0usize;
    for (idx, slot) in socket_table().iter().enumerate() {
        if !is_slot_used(idx as u32) || slot.external_peer == 0 {
            continue;
        }
        if slot.state == SOCK_STATE_SHUTDOWN || slot.state == SOCK_STATE_IDLE || slot.peer_idx < 0 {
            stale[stale_count] = idx as u32;
            stale_count += 1;
            continue;
        }
        let owner_idx = slot.peer_idx as usize;
        let owner_missing = owner_idx >= MAX_SOCKETS || !is_slot_used(owner_idx as u32);
        let owner_detached = !owner_missing && socket_table()[owner_idx].peer_idx != idx as i32;
        if owner_missing || owner_detached {
            stale[stale_count] = idx as u32;
            stale_count += 1;
        }
    }
    for idx in stale.into_iter().take(stale_count) {
        if is_slot_used(idx) {
            shutdown_slot(idx as usize);
        }
    }
}

fn ensure_external_peer_for_connected_socket(idx: usize) -> Result<(), i64> {
    if socket_table()[idx].external_peer != 0 && socket_table()[idx].state == SOCK_STATE_SHUTDOWN {
        socket_table()[idx].state = SOCK_STATE_CONNECTED;
        socket_table()[idx].shutdown_mask = 0;
    }
    if socket_table()[idx].state != SOCK_STATE_CONNECTED {
        return Err(ENOTCONN);
    }
    ensure_socket_recv_buffer(idx)?;
    ensure_external_peer(idx)
}

pub fn drain_external_outbound_for_fd(base: u32, vm: &ThreadState, fd: u64, dst: &mut [u8]) -> i32 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return ENOTSOCK as i32;
    };
    if socket_table()[idx].state != SOCK_STATE_CONNECTED || socket_table()[idx].recv_buf_idx < 0 {
        return 0;
    }
    let mut peer_idx = socket_table()[idx].peer_idx;
    if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
        if ensure_external_peer_for_connected_socket(idx).is_err() {
            return ENOTCONN as i32;
        }
        peer_idx = socket_table()[idx].peer_idx;
        if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
            return ENOTCONN as i32;
        }
    }
    let peer = &socket_table()[peer_idx as usize];
    if peer.recv_buf_idx < 0 {
        return 0;
    }
    if peer.recv_buf_idx == socket_table()[idx].recv_buf_idx {
        return 0;
    }
    crate::net::ring_buffer::read(peer.recv_buf_idx as u32, dst) as i32
}

pub fn close_external_peer_for_fd(base: u32, vm: &ThreadState, fd: u64) -> i32 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return ENOTSOCK as i32;
    };
    let was_external = socket_table()[idx].external_peer != 0;
    let peer_idx = if socket_table()[idx].peer_idx >= 0 {
        socket_table()[idx].peer_idx
    } else {
        find_external_peer_for_socket(idx)
            .map(|value| value as i32)
            .unwrap_or(-1)
    };
    let has_external_peer = peer_idx >= 0
        && is_slot_used(peer_idx as u32)
        && socket_table()[peer_idx as usize].external_peer != 0
        && socket_table()[peer_idx as usize].peer_idx == idx as i32;
    if !was_external && !has_external_peer {
        if socket_table()[idx].state == SOCK_STATE_CONNECTED
            || (socket_table()[idx].sock_type == SOCK_STREAM
                && socket_table()[idx].recv_buf_idx >= 0)
        {
            socket_table()[idx].state = SOCK_STATE_SHUTDOWN;
            socket_table()[idx].shutdown_mask = SHUT_RD_MASK | SHUT_WR_MASK;
        }
        socket_table()[idx].external_peer = 0;
        return 0;
    }
    socket_table()[idx].external_peer = 0;
    if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
        if socket_table()[idx].state == SOCK_STATE_CONNECTED
            || (socket_table()[idx].sock_type == SOCK_STREAM
                && socket_table()[idx].recv_buf_idx >= 0)
        {
            socket_table()[idx].state = SOCK_STATE_SHUTDOWN;
            socket_table()[idx].shutdown_mask = SHUT_RD_MASK | SHUT_WR_MASK;
        }
        return 0;
    }
    let peer_idx = peer_idx as usize;
    if has_external_peer {
        let peer_recv_buf_idx = socket_table()[peer_idx].recv_buf_idx;
        free_recv_buffer_if_unreferenced(peer_recv_buf_idx, peer_idx);
        socket_table()[peer_idx].state = SOCK_STATE_SHUTDOWN;
        socket_table()[peer_idx].recv_buf_idx = INVALID_BUF_IDX;
        socket_table()[peer_idx].shutdown_mask = SHUT_RD_MASK | SHUT_WR_MASK;
    } else {
        shutdown_slot(peer_idx);
    }
    socket_table()[idx].external_peer = 0;
    if socket_table()[idx].state == SOCK_STATE_CONNECTED
        || (socket_table()[idx].sock_type == SOCK_STREAM && socket_table()[idx].recv_buf_idx >= 0)
    {
        socket_table()[idx].state = SOCK_STATE_SHUTDOWN;
        socket_table()[idx].shutdown_mask = SHUT_RD_MASK | SHUT_WR_MASK;
    }
    0
}

pub fn force_shutdown_for_fd(base: u32, vm: &ThreadState, fd: u64) -> i32 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return ENOTSOCK as i32;
    };
    let peer_idx = socket_table()[idx].peer_idx;
    socket_table()[idx].external_peer = 0;
    socket_table()[idx].state = SOCK_STATE_SHUTDOWN;
    socket_table()[idx].shutdown_mask = SHUT_RD_MASK | SHUT_WR_MASK;

    if peer_idx >= 0 && (peer_idx as usize) < MAX_SOCKETS && is_slot_used(peer_idx as u32) {
        let peer_idx = peer_idx as usize;
        let peer_is_external = socket_table()[peer_idx].external_peer != 0
            && socket_table()[peer_idx].peer_idx == idx as i32;
        if peer_is_external {
            let peer_recv_buf_idx = socket_table()[peer_idx].recv_buf_idx;
            free_recv_buffer_if_unreferenced(peer_recv_buf_idx, peer_idx);
            socket_table()[peer_idx].recv_buf_idx = INVALID_BUF_IDX;
        }
        socket_table()[peer_idx].external_peer = 0;
        socket_table()[peer_idx].state = SOCK_STATE_SHUTDOWN;
        socket_table()[peer_idx].shutdown_mask = SHUT_RD_MASK | SHUT_WR_MASK;
    }

    0
}

pub fn mark_external_peer_for_fd(base: u32, vm: &ThreadState, fd: u64) -> i32 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return ENOTSOCK as i32;
    };
    if socket_table()[idx].state == SOCK_STATE_CONNECTING
        || (socket_table()[idx].state == SOCK_STATE_SHUTDOWN
            && socket_table()[idx].external_peer != 0)
    {
        socket_table()[idx].state = SOCK_STATE_CONNECTED;
        socket_table()[idx].shutdown_mask = 0;
    }
    if socket_table()[idx].state != SOCK_STATE_CONNECTED {
        return ENOTCONN as i32;
    }
    if let Err(errno) = ensure_socket_recv_buffer(idx) {
        return errno as i32;
    }
    match ensure_external_peer(idx) {
        Ok(()) => 0,
        Err(errno) => errno as i32,
    }
}

pub fn commit_external_connect_for_fd(base: u32, vm: &ThreadState, fd: u64) -> i32 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return ENOTSOCK as i32;
    };
    if socket_table()[idx].state == SOCK_STATE_SHUTDOWN {
        return ENOTCONN as i32;
    }
    socket_table()[idx].state = SOCK_STATE_CONNECTED;
    socket_table()[idx].shutdown_mask = 0;
    if let Err(errno) = ensure_socket_recv_buffer(idx) {
        return errno as i32;
    }
    match ensure_external_peer(idx) {
        Ok(()) => 0,
        Err(errno) => errno as i32,
    }
}

pub fn debug_external_outbound_available_for_fd(base: u32, vm: &ThreadState, fd: u64) -> i32 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return ENOTSOCK as i32;
    };
    if socket_table()[idx].state != SOCK_STATE_CONNECTED || socket_table()[idx].recv_buf_idx < 0 {
        return 0;
    }
    let mut peer_idx = socket_table()[idx].peer_idx;
    if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
        if ensure_external_peer_for_connected_socket(idx).is_err() {
            return ENOTCONN as i32;
        }
        peer_idx = socket_table()[idx].peer_idx;
        if peer_idx < 0 || !is_slot_used(peer_idx as u32) {
            return ENOTCONN as i32;
        }
    }
    let peer = &socket_table()[peer_idx as usize];
    if peer.recv_buf_idx < 0 {
        return 0;
    }
    if peer.recv_buf_idx == socket_table()[idx].recv_buf_idx {
        return 0;
    }
    crate::net::ring_buffer::available(peer.recv_buf_idx as u32) as i32
}

pub fn debug_socket_idx_for_fd(base: u32, vm: &ThreadState, fd: u64) -> i32 {
    get_socket_idx(base, vm, fd)
        .map(|value| value as i32)
        .unwrap_or(ENOTSOCK as i32)
}

pub fn debug_socket_peer_idx(idx: u32) -> i32 {
    if (idx as usize) >= MAX_SOCKETS || !is_slot_used(idx) {
        return ENOTSOCK as i32;
    }
    socket_table()[idx as usize].peer_idx
}

pub fn debug_socket_state(idx: u32) -> i32 {
    if (idx as usize) >= MAX_SOCKETS || !is_slot_used(idx) {
        return ENOTSOCK as i32;
    }
    socket_table()[idx as usize].state as i32
}

pub fn debug_socket_type(idx: u32) -> i32 {
    if (idx as usize) >= MAX_SOCKETS || !is_slot_used(idx) {
        return ENOTSOCK as i32;
    }
    socket_table()[idx as usize].sock_type as i32
}

pub fn debug_socket_external_peer(idx: u32) -> i32 {
    if (idx as usize) >= MAX_SOCKETS || !is_slot_used(idx) {
        return ENOTSOCK as i32;
    }
    socket_table()[idx as usize].external_peer as i32
}

pub fn debug_socket_recv_buf_idx(idx: u32) -> i32 {
    if (idx as usize) >= MAX_SOCKETS || !is_slot_used(idx) {
        return ENOTSOCK as i32;
    }
    socket_table()[idx as usize].recv_buf_idx
}

pub fn debug_socket_recv_available(idx: u32) -> i32 {
    if (idx as usize) >= MAX_SOCKETS || !is_slot_used(idx) {
        return ENOTSOCK as i32;
    }
    let recv_buf_idx = socket_table()[idx as usize].recv_buf_idx;
    if recv_buf_idx < 0 {
        return 0;
    }
    crate::net::ring_buffer::available(recv_buf_idx as u32) as i32
}

pub fn debug_socket_read_count(idx: u32) -> u32 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    unsafe { SOCKET_READ_COUNT[idx as usize] }
}

pub fn debug_socket_read_bytes(idx: u32) -> u64 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    unsafe { SOCKET_READ_BYTES[idx as usize] }
}

pub fn debug_socket_read_last_fd(idx: u32) -> u32 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    unsafe { SOCKET_READ_LAST_FD[idx as usize] }
}

pub fn debug_socket_read_last_result(idx: u32) -> i64 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    unsafe { SOCKET_READ_LAST_RESULT[idx as usize] }
}

pub fn debug_socket_read_last_before(idx: u32) -> u32 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    unsafe { SOCKET_READ_LAST_BEFORE[idx as usize] }
}

pub fn debug_socket_read_last_after(idx: u32) -> u32 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    unsafe { SOCKET_READ_LAST_AFTER[idx as usize] }
}

pub fn inject_external_inbound_for_fd(base: u32, vm: &ThreadState, fd: u64, src: &[u8]) -> i32 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return ENOTSOCK as i32;
    };
    if socket_table()[idx].state != SOCK_STATE_CONNECTED {
        return ENOTCONN as i32;
    }
    if ensure_socket_recv_buffer(idx).is_err() {
        return ENOMEM as i32;
    }
    crate::net::ring_buffer::write(socket_table()[idx].recv_buf_idx as u32, src) as i32
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

fn record_socket_read_debug(idx: usize, fd: u64, before: usize, result: i64, after: usize) {
    if idx >= MAX_SOCKETS {
        return;
    }
    unsafe {
        SOCKET_READ_LAST_FD[idx] = fd as u32;
        SOCKET_READ_LAST_RESULT[idx] = result;
        SOCKET_READ_LAST_BEFORE[idx] = before.min(u32::MAX as usize) as u32;
        SOCKET_READ_LAST_AFTER[idx] = after.min(u32::MAX as usize) as u32;
        if result > 0 {
            SOCKET_READ_COUNT[idx] = SOCKET_READ_COUNT[idx].saturating_add(1);
            SOCKET_READ_BYTES[idx] = SOCKET_READ_BYTES[idx].saturating_add(result as u64);
        }
    }
}

fn socket_send_space(idx: usize) -> usize {
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

fn slot_peer_is_closed(idx: usize) -> bool {
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

    free_recv_buffer_if_unreferenced(recv_buf_idx, idx);

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
        let peer_is_external = socket_table()[peer_idx as usize].external_peer != 0
            && socket_table()[peer_idx as usize].peer_idx == idx as i32;
        if peer_is_external {
            shutdown_slot(peer_idx as usize);
        } else {
            let peer = &mut socket_table()[peer_idx as usize];
            if peer.peer_idx == idx as i32 {
                peer.peer_idx = INVALID_PEER_IDX;
                if peer.state == SOCK_STATE_CONNECTED {
                    peer.state = SOCK_STATE_SHUTDOWN;
                }
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
    sync_referenced_recv_buffers_used();
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

    let mut fd_flags: i32 = 0;
    if flags & SOCK_NONBLOCK != 0 {
        fd_flags |= O_NONBLOCK;
    }
    if flags & SOCK_CLOEXEC != 0 {
        fd_flags |= O_CLOEXEC;
    }

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

fn ensure_socket_recv_buffer(idx: usize) -> Result<(), i64> {
    if socket_table()[idx].recv_buf_idx >= 0 {
        return Ok(());
    }
    let Some(buf_idx) = alloc_socket_recv_buffer() else {
        return Err(ENOMEM);
    };
    socket_table()[idx].recv_buf_idx = buf_idx;
    Ok(())
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
        shutdown_slot(accepted_idx);
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

    if slot.domain == AF_UNIX {
        if find_unix_socket_by_addr(&buf, len).is_some() {
            return EADDRINUSE;
        }
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
    if slot.domain == AF_UNIX && slot.sock_type != SOCK_STREAM {
        return EOPNOTSUPP;
    }
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

    // Signal TS runtime to perform the actual connect
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

    // Cache the explicit DGRAM destination so recvfrom/getpeername can
    // surface the last peer address until a different destination is used.
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
/// Minimal stream/datagram data-path support for browser-networked guests.
/// Control messages are ignored; payload is sent from msg_iov just like writev.
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

    // For SOCK_STREAM, reads after peer shutdown must still drain queued bytes
    // and then report EOF. Linux does not turn that final recv into ENOTCONN.
    if slot.sock_type == SOCK_STREAM
        && slot.state != SOCK_STATE_CONNECTED
        && slot.state != SOCK_STATE_SHUTDOWN
    {
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
            && unsafe { SOCKET_READ_COUNT[idx] } > 0
            && unsafe { SOCKET_READ_BYTES[idx] } > 0
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
    } else {
        if socket_recv_available(idx) > 0 {
            revents |= EPOLLIN;
        }
    }

    if slot.state == SOCK_STATE_CONNECTED || slot.state == SOCK_STATE_SHUTDOWN {
        if slot.shutdown_mask & SHUT_RD_MASK != 0 {
            revents |= EPOLLRDHUP;
        }
        if slot_peer_is_closed(idx) {
            revents |= EPOLLHUP;
        }

        if socket_send_space(idx) > 0 {
            revents |= EPOLLOUT;
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
    let Some(server_recv) = alloc_socket_recv_buffer() else {
        shutdown_slot(server_idx);
        shutdown_slot(client_idx);
        return -2;
    };
    let Some(client_recv) = alloc_socket_recv_buffer() else {
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
        owner_pid: 0,
        owner_uid: 0,
        owner_gid: 0,
        local_addr: listener_local_addr,
        local_len: listener_local_len,
        peer_addr: [0; SOCKADDR_STORAGE_LEN],
        peer_len: 0,
        peer_idx: client_idx as i32,
        peer_pid: 0,
        peer_uid: 0,
        peer_gid: 0,
        external_peer: 0,
        recv_buf_idx: server_recv,
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
    socket_table()[client_idx] = SocketSlot {
        domain: listener_domain,
        sock_type: listener_type,
        protocol: listener_protocol,
        state: SOCK_STATE_CONNECTED,
        owner_pid: 0,
        owner_uid: 0,
        owner_gid: 0,
        local_addr: [0; SOCKADDR_STORAGE_LEN],
        local_len: 0,
        peer_addr: listener_local_addr,
        peer_len: listener_local_len,
        peer_idx: server_idx as i32,
        peer_pid: 0,
        peer_uid: 0,
        peer_gid: 0,
        external_peer: 0,
        recv_buf_idx: client_recv,
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

fn read_opt_timeval(base: u32, optval: u64, optlen: u64) -> Result<(u64, u64), i64> {
    if optval == 0 || optlen < 16 {
        return Err(EINVAL);
    }
    let sec = unsafe { guest_mem::read_i64(base, optval) };
    let usec = unsafe { guest_mem::read_i64(base, optval + 8) };
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return Err(EINVAL);
    }
    Ok((sec as u64, usec as u64))
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

fn write_opt_bytes(base: u32, optval: u64, optlen_ptr: u64, bytes: &[u8]) -> i64 {
    if optval == 0 || optlen_ptr == 0 {
        return EFAULT;
    }

    let user_len = unsafe { guest_mem::read_u32(base, optlen_ptr) } as usize;
    let copy_len = user_len.min(bytes.len());
    unsafe {
        guest_mem::write_bytes(base, optval, &bytes[..copy_len]);
        guest_mem::write_u32(base, optlen_ptr, bytes.len() as u32);
    }
    0
}

fn write_opt_timeval(base: u32, optval: u64, optlen_ptr: u64, sec: u64, usec: u64) -> i64 {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&(sec as i64).to_le_bytes());
    bytes[8..].copy_from_slice(&(usec as i64).to_le_bytes());
    write_opt_bytes(base, optval, optlen_ptr, &bytes)
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
        (SOL_SOCKET, SO_OOBINLINE) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_oobinline = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_NO_CHECK) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_nocheck = u32::from(value != 0);
                0
            }
            Err(err) => err,
        },
        (SOL_SOCKET, SO_BSDCOMPAT) => match read_opt_i32(base, optval, optlen) {
            Ok(value) => {
                slot.so_bsdcompat = u32::from(value != 0);
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
        (SOL_SOCKET, SO_RCVLOWAT) => match read_opt_i32(base, optval, optlen) {
            Ok(value) if value > 0 => {
                slot.so_rcvlowat = value as u32;
                0
            }
            Ok(_) => EINVAL,
            Err(err) => err,
        },
        (SOL_SOCKET, SO_SNDLOWAT) => ENOPROTOOPT,
        (SOL_SOCKET, SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW) => {
            match read_opt_timeval(base, optval, optlen) {
                Ok((sec, usec)) => {
                    slot.so_rcvtimeo_sec = sec;
                    slot.so_rcvtimeo_usec = usec;
                    0
                }
                Err(err) => err,
            }
        }
        (SOL_SOCKET, SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW) => {
            match read_opt_timeval(base, optval, optlen) {
                Ok((sec, usec)) => {
                    slot.so_sndtimeo_sec = sec;
                    slot.so_sndtimeo_usec = usec;
                    0
                }
                Err(err) => err,
            }
        }
        (SOL_SOCKET, SO_SNDBUF | SO_SNDBUFFORCE) => match read_opt_i32(base, optval, optlen) {
            Ok(value) if value > 0 => {
                slot.so_sndbuf = value.max(256) as u32;
                0
            }
            Ok(_) => EINVAL,
            Err(err) => err,
        },
        (SOL_SOCKET, SO_RCVBUF | SO_RCVBUFFORCE) => match read_opt_i32(base, optval, optlen) {
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
        (SOL_SOCKET, SO_TYPE | SO_ERROR | SO_ACCEPTCONN | SO_PROTOCOL | SO_DOMAIN) => ENOPROTOOPT,
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
        (SOL_SOCKET, SO_OOBINLINE) => write_opt_u32(base, optval, optlen, slot.so_oobinline),
        (SOL_SOCKET, SO_NO_CHECK) => write_opt_u32(base, optval, optlen, slot.so_nocheck),
        (SOL_SOCKET, SO_BSDCOMPAT) => write_opt_u32(base, optval, optlen, slot.so_bsdcompat),
        (SOL_SOCKET, SO_BROADCAST) => write_opt_u32(base, optval, optlen, slot.so_broadcast),
        (SOL_SOCKET, SO_SNDBUF) => write_opt_u32(base, optval, optlen, slot.so_sndbuf),
        (SOL_SOCKET, SO_RCVBUF) => write_opt_u32(base, optval, optlen, slot.so_rcvbuf),
        (SOL_SOCKET, SO_INCOMING_CPU) => write_opt_u32(base, optval, optlen, 0),
        (SOL_SOCKET, SO_COOKIE) => {
            write_opt_bytes(base, optval, optlen, &slot.so_cookie.to_le_bytes())
        }
        (SOL_SOCKET, SO_RCVLOWAT) => write_opt_u32(base, optval, optlen, slot.so_rcvlowat),
        (SOL_SOCKET, SO_SNDLOWAT) => write_opt_u32(base, optval, optlen, 1),
        (SOL_SOCKET, SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW) => write_opt_timeval(
            base,
            optval,
            optlen,
            slot.so_rcvtimeo_sec,
            slot.so_rcvtimeo_usec,
        ),
        (SOL_SOCKET, SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW) => write_opt_timeval(
            base,
            optval,
            optlen,
            slot.so_sndtimeo_sec,
            slot.so_sndtimeo_usec,
        ),
        (SOL_SOCKET, SO_ACCEPTCONN) => write_opt_u32(
            base,
            optval,
            optlen,
            u32::from(slot.state == SOCK_STATE_LISTENING),
        ),
        (SOL_SOCKET, SO_PROTOCOL) => write_opt_u32(base, optval, optlen, slot.protocol),
        (SOL_SOCKET, SO_DOMAIN) => write_opt_u32(base, optval, optlen, slot.domain),
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

    #[test]
    fn external_peer_allocation_never_reuses_current_socket_when_bitmap_is_stale() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);
        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;

        unsafe {
            let used = core::ptr::read(core::ptr::addr_of!(SOCKET_USED));
            core::ptr::write(
                core::ptr::addr_of_mut!(SOCKET_USED),
                used & !(1u32 << socket_idx),
            );
        }

        assert!(ensure_external_peer(socket_idx).is_ok());
        let peer_idx = socket_table()[socket_idx].peer_idx;
        assert!(peer_idx >= 0);
        assert_ne!(peer_idx as usize, socket_idx);
        assert!(is_slot_used(socket_idx as u32));
        assert!(is_slot_used(peer_idx as u32));
    }

    #[test]
    fn pending_connect_exports_use_pinned_fd_over_a0() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x880;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        assert_eq!(t.vm.status, STATUS_CONNECT);

        t.vm.x[10] = 99;
        let mut peer = [0u8; 16];
        assert_eq!(thread_connect_fd(&t.vm), fd as i32);
        assert_eq!(connect_peer_addr(&t.vm, &mut peer), 16);
        assert_eq!(&peer, &sockaddr);

        resume_connect_result(&mut t.vm, t.base, 0);
        assert_eq!(t.vm.status, STATUS_OK);
    }

    #[test]
    fn closing_external_peer_preserves_pending_inbound_until_read() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x900;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;
        let peer_idx = socket_table()[socket_idx].peer_idx;
        assert!(peer_idx >= 0);
        assert_eq!(
            inject_external_inbound_for_fd(t.base, &t.vm, fd as u64, b"hello"),
            5,
        );

        assert_eq!(close_external_peer_for_fd(t.base, &t.vm, fd as u64), 0);
        assert!(is_slot_used(socket_idx as u32));
        assert!(is_slot_used(peer_idx as u32));

        let mut buf = [0u8; 8];
        assert_eq!(t.sys_read(fd, &mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(t.sys_read(fd, &mut buf), 0);
    }

    #[test]
    fn closing_external_peer_marks_stale_stream_socket_eof() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x910;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;
        socket_table()[socket_idx].state = SOCK_STATE_IDLE;
        assert_eq!(close_external_peer_for_fd(t.base, &t.vm, fd as u64), 0);

        let mut buf = [0u8; 8];
        assert_eq!(t.sys_read(fd, &mut buf), 0);
    }

    #[test]
    fn socket_read_drains_queued_data_before_enotconn_on_stale_state() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x920;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        assert_eq!(
            inject_external_inbound_for_fd(t.base, &t.vm, fd as u64, b"hello"),
            5,
        );
        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;
        socket_table()[socket_idx].state = SOCK_STATE_IDLE;
        let ofd = fd_table::get_ofd(t.base, &t.vm, fd as u64).expect("socket OFD should exist");
        assert_ne!(poll_revents_ofd(&ofd, EPOLLIN) & EPOLLIN, 0);

        let mut buf = [0u8; 8];
        assert_eq!(t.sys_read(fd, &mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(t.sys_read(fd, &mut buf), ENOTCONN);
    }

    #[test]
    fn socket_poll_reports_write_ready_when_recv_data_pending() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x930;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        assert_eq!(
            inject_external_inbound_for_fd(t.base, &t.vm, fd as u64, b"hello"),
            5,
        );
        let ofd = fd_table::get_ofd(t.base, &t.vm, fd as u64).expect("socket OFD should exist");

        let write_only = poll_revents_ofd(&ofd, EPOLLOUT);
        assert_ne!(write_only & EPOLLOUT, 0);

        let read_write = poll_revents_ofd(&ofd, EPOLLIN | EPOLLOUT);
        assert_ne!(read_write & EPOLLIN, 0);
        assert_ne!(read_write & EPOLLOUT, 0);
    }

    #[test]
    fn socket_read_returns_available_stream_bytes_beyond_page_size() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x950;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        let mut payload = [0u8; 16 * 1024];
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_mul(17).wrapping_add(23);
        }
        assert_eq!(
            inject_external_inbound_for_fd(t.base, &t.vm, fd as u64, &payload),
            payload.len() as i32,
        );

        let mut buf = [0u8; 16 * 1024];
        assert_eq!(t.sys_read(fd, &mut buf), payload.len() as i64);
        assert_eq!(buf, payload);
    }

    #[test]
    fn mark_external_peer_does_not_reuse_existing_recv_buffer_when_bitmap_is_stale() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x940;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;
        let recv_buf_idx = socket_table()[socket_idx].recv_buf_idx;
        assert!(recv_buf_idx >= 0);
        let peer_idx = socket_table()[socket_idx].peer_idx;
        assert!(peer_idx >= 0);

        let peer_idx = peer_idx as usize;
        let peer_recv_buf_idx = socket_table()[peer_idx].recv_buf_idx;
        free_recv_buffer_if_unreferenced(peer_recv_buf_idx, peer_idx);
        socket_table()[peer_idx].recv_buf_idx = INVALID_BUF_IDX;
        socket_table()[socket_idx].peer_idx = INVALID_PEER_IDX;
        socket_table()[socket_idx].external_peer = 0;
        free_socket_slot(peer_idx as u32);

        let (net_buf_base, _) = crate::net::ring_buffer::net_buffer_state();
        crate::net::ring_buffer::attach_net_buffer_state(net_buf_base, 0);

        assert_eq!(mark_external_peer_for_fd(t.base, &t.vm, fd as u64), 0);
        let new_peer_idx = socket_table()[socket_idx].peer_idx;
        assert!(new_peer_idx >= 0);
        assert_ne!(
            socket_table()[new_peer_idx as usize].recv_buf_idx,
            recv_buf_idx,
        );
    }

    #[test]
    fn closing_external_peer_does_not_free_aliased_recv_buffer() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x980;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;
        let peer_idx = socket_table()[socket_idx].peer_idx;
        assert!(peer_idx >= 0);
        let recv_buf_idx = socket_table()[socket_idx].recv_buf_idx;
        assert!(recv_buf_idx >= 0);
        socket_table()[peer_idx as usize].recv_buf_idx = recv_buf_idx;

        assert_eq!(
            inject_external_inbound_for_fd(t.base, &t.vm, fd as u64, b"hello"),
            5,
        );
        assert_eq!(close_external_peer_for_fd(t.base, &t.vm, fd as u64), 0);

        let mut buf = [0u8; 8];
        assert_eq!(t.sys_read(fd, &mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(t.sys_read(fd, &mut buf), 0);
    }

    #[test]
    fn closing_external_peer_uses_peer_slot_when_owner_flag_is_stale() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x900;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;
        let peer_idx = socket_table()[socket_idx].peer_idx;
        assert!(peer_idx >= 0);
        socket_table()[socket_idx].external_peer = 0;

        assert_eq!(close_external_peer_for_fd(t.base, &t.vm, fd as u64), 0);
        assert_eq!(socket_table()[socket_idx].state, SOCK_STATE_SHUTDOWN);
        assert_eq!(socket_table()[peer_idx as usize].state, SOCK_STATE_SHUTDOWN);

        let mut buf = [0u8; 8];
        assert_eq!(t.sys_read(fd, &mut buf), 0);
    }

    #[test]
    fn aliased_external_peer_recv_buffer_is_not_outbound() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x9a0;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;
        let peer_idx = socket_table()[socket_idx].peer_idx;
        assert!(peer_idx >= 0);
        let recv_buf_idx = socket_table()[socket_idx].recv_buf_idx;
        assert!(recv_buf_idx >= 0);
        socket_table()[peer_idx as usize].recv_buf_idx = recv_buf_idx;

        assert_eq!(
            inject_external_inbound_for_fd(t.base, &t.vm, fd as u64, b"hello"),
            5,
        );
        assert_eq!(
            debug_external_outbound_available_for_fd(t.base, &t.vm, fd as u64),
            0,
        );
        let mut outbound = [0u8; 8];
        assert_eq!(
            drain_external_outbound_for_fd(t.base, &t.vm, fd as u64, &mut outbound),
            0,
        );

        let mut buf = [0u8; 8];
        assert_eq!(t.sys_read(fd, &mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn shutdown_socket_peer_recv_buffer_is_not_outbound() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x9c0;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;
        let peer_idx = socket_table()[socket_idx].peer_idx;
        assert!(peer_idx >= 0);
        let peer_recv_buf_idx = socket_table()[peer_idx as usize].recv_buf_idx;
        assert!(peer_recv_buf_idx >= 0);
        assert_eq!(
            crate::net::ring_buffer::write(peer_recv_buf_idx as u32, b"stale"),
            5,
        );

        socket_table()[socket_idx].state = SOCK_STATE_SHUTDOWN;
        socket_table()[socket_idx].recv_buf_idx = INVALID_BUF_IDX;

        assert_eq!(
            debug_external_outbound_available_for_fd(t.base, &t.vm, fd as u64),
            0,
        );
        let mut outbound = [0u8; 8];
        assert_eq!(
            drain_external_outbound_for_fd(t.base, &t.vm, fd as u64, &mut outbound),
            0,
        );
    }

    #[test]
    fn mark_external_peer_does_not_resurrect_forced_shutdown_socket() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x900;
        t.write_mem(addr, &sockaddr);
        assert_eq!(sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
        resume_connect_result(&mut t.vm, t.base, 0);

        let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
            .expect("socket OFD should exist")
            .ino as usize;
        assert_eq!(force_shutdown_for_fd(t.base, &t.vm, fd as u64), 0);
        assert_eq!(socket_table()[socket_idx].state, SOCK_STATE_SHUTDOWN);
        assert_eq!(socket_table()[socket_idx].external_peer, 0);

        assert_eq!(
            mark_external_peer_for_fd(t.base, &t.vm, fd as u64),
            ENOTCONN as i32
        );
        assert_eq!(socket_table()[socket_idx].state, SOCK_STATE_SHUTDOWN);
        assert_eq!(socket_table()[socket_idx].external_peer, 0);
    }
}
