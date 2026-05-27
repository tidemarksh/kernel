use super::connect::{accept_queue_len, remove_socket_from_accept_queues};
use crate::abi::*;
use crate::alloc;
use crate::fs::fd_table;
use crate::types::ThreadState;

// Socket states
pub(super) const SOCK_STATE_IDLE: u32 = 0;
pub(super) const SOCK_STATE_BOUND: u32 = 1;
pub(super) const SOCK_STATE_LISTENING: u32 = 2;
pub(super) const SOCK_STATE_CONNECTED: u32 = 3;
pub(super) const SOCK_STATE_CONNECTING: u32 = 4;
pub(super) const SOCK_STATE_SHUTDOWN: u32 = 5;

pub(super) const SHUT_RD_MASK: u32 = 1 << 0;
pub(super) const SHUT_WR_MASK: u32 = 1 << 1;

// Covers sockaddr_in, sockaddr_in6, and Linux sockaddr_un (sun_path[108]).
pub(super) const SOCKADDR_STORAGE_LEN: usize = 128;
pub(super) const ACCEPT_QUEUE_SIZE: usize = 16;
pub(super) const INVALID_BUF_IDX: i32 = -1;
pub(super) const INVALID_PEER_IDX: i32 = -1;
pub(super) const IPPROTO_TCP: u32 = 6;
pub(super) const IPPROTO_UDP: u32 = 17;
pub(super) const NETLINK_ROUTE: u32 = 0;
pub(super) const DEFAULT_SOCKET_BUFFER: u32 = 256 * 1024;
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SocketSlot {
    pub(super) domain: u32,
    pub(super) sock_type: u32,
    pub(super) protocol: u32,
    pub(super) state: u32,
    pub(super) owner_pid: i32,
    pub(super) owner_uid: u32,
    pub(super) owner_gid: u32,
    pub(super) local_addr: [u8; SOCKADDR_STORAGE_LEN],
    pub(super) local_len: u32,
    pub(super) peer_addr: [u8; SOCKADDR_STORAGE_LEN],
    pub(super) peer_len: u32,
    pub(super) peer_idx: i32,
    pub(super) peer_pid: i32,
    pub(super) peer_uid: u32,
    pub(super) peer_gid: u32,
    pub(super) external_peer: u32,
    pub(super) recv_buf_idx: i32,
    pub(super) last_error: i32,
    pub(super) so_cookie: u64,
    pub(super) so_reuseaddr: u32,
    pub(super) so_reuseport: u32,
    pub(super) so_keepalive: u32,
    pub(super) so_oobinline: u32,
    pub(super) so_nocheck: u32,
    pub(super) so_bsdcompat: u32,
    pub(super) so_broadcast: u32,
    pub(super) so_sndbuf: u32,
    pub(super) so_rcvbuf: u32,
    pub(super) so_rcvlowat: u32,
    pub(super) so_rcvtimeo_sec: u64,
    pub(super) so_rcvtimeo_usec: u64,
    pub(super) so_sndtimeo_sec: u64,
    pub(super) so_sndtimeo_usec: u64,
    pub(super) tcp_nodelay: u32,
    pub(super) shutdown_mask: u32,
    pub(super) accept_head: u32,
    pub(super) accept_tail: u32,
    pub(super) accept_queue: [i32; ACCEPT_QUEUE_SIZE],
}

#[repr(C)]
struct SocketReadDebugState {
    count: [u32; MAX_SOCKETS],
    bytes: [u64; MAX_SOCKETS],
    last_fd: [u32; MAX_SOCKETS],
    last_result: [i64; MAX_SOCKETS],
    last_before: [u32; MAX_SOCKETS],
    last_after: [u32; MAX_SOCKETS],
}

#[repr(C)]
struct SocketState {
    table: [SocketSlot; MAX_SOCKETS],
    used: u32,
    next_cookie: u64,
    read_debug: SocketReadDebugState,
}

/// Pointer to socket state in kernel Worker linear memory.
static mut SOCKET_STATE_PTR: *mut SocketState = core::ptr::null_mut();

fn state() -> &'static mut SocketState {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(SOCKET_STATE_PTR));
        &mut *p
    }
}

pub(super) fn socket_table() -> &'static mut [SocketSlot; MAX_SOCKETS] {
    &mut state().table
}

pub(super) fn alloc_socket_cookie() -> u64 {
    let socket_state = state();
    let cookie = socket_state.next_cookie;
    socket_state.next_cookie = cookie.saturating_add(1).max(1);
    cookie
}

pub(super) fn empty_socket_slot() -> SocketSlot {
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
    core::ptr::addr_of_mut!(state().table) as u32
}

pub fn socket_used() -> u32 {
    state().used
}

pub fn socket_table_bytes() -> u32 {
    core::mem::size_of::<[SocketSlot; MAX_SOCKETS]>() as u32
}

pub fn socket_state_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(SOCKET_STATE_PTR)) as u32 }
}

pub fn socket_state_bytes() -> u32 {
    core::mem::size_of::<SocketState>() as u32
}

pub fn attach_socket_state(state_ptr: u32, used: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_STATE_PTR),
            state_ptr as *mut SocketState,
        );
    }
    state().used = used;
}

/// Initialize socket subsystem. Allocates socket state via alloc.rs.
pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_STATE_PTR),
            core::ptr::null_mut(),
        );

        let size = core::mem::size_of::<SocketState>() as u32;
        let align = core::mem::align_of::<SocketState>() as u32;
        let ptr = alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(SOCKET_STATE_PTR),
            ptr as *mut SocketState,
        );
    }
    state().next_cookie = 1;
}

pub(super) fn alloc_socket_slot() -> Option<u32> {
    reap_shutdown_socket_slots(u32::MAX);
    let used = state().used;
    for i in 0..MAX_SOCKETS {
        if used & (1u32 << i) == 0 {
            state().used = used | (1u32 << i);
            socket_table()[i] = empty_socket_slot();
            return Some(i as u32);
        }
    }
    None
}

pub(super) fn reap_shutdown_socket_slots(excluded_idx: u32) {
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

pub(super) fn external_peer_slot_has_live_owner(socket_idx: u32) -> bool {
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

pub(super) fn socket_slot_has_ofd_ref(socket_idx: u32) -> bool {
    for ofd_id in 1..crate::abi::MAX_FDS {
        if let Some(ofd) = fd_table::get_ofd_by_id(ofd_id as u32) {
            if ofd.fd_type == FD_TYPE_SOCKET && ofd.ino == socket_idx {
                return true;
            }
        }
    }
    false
}

pub(super) fn mark_socket_slot_used(idx: u32) {
    if idx >= MAX_SOCKETS as u32 {
        return;
    }
    state().used |= 1u32 << idx;
}

pub(super) fn alloc_socket_slot_excluding(excluded_idx: u32) -> Option<u32> {
    reap_shutdown_socket_slots(excluded_idx);
    let used = state().used | (1u32 << excluded_idx);
    for i in 0..MAX_SOCKETS {
        if used & (1u32 << i) == 0 {
            state().used = used | (1u32 << i);
            socket_table()[i] = empty_socket_slot();
            return Some(i as u32);
        }
    }
    None
}

pub(super) fn free_socket_slot(idx: u32) {
    state().used &= !(1u32 << idx);
}

/// Check if a socket slot is allocated.
pub fn is_slot_used(idx: u32) -> bool {
    if idx >= MAX_SOCKETS as u32 {
        return false;
    }
    state().used & (1u32 << idx) != 0
}

pub(super) fn mark_referenced_recv_buffers_used() {
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

pub(super) fn sync_referenced_recv_buffers_used() {
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

pub(super) fn alloc_socket_recv_buffer() -> Option<i32> {
    mark_referenced_recv_buffers_used();
    crate::net::ring_buffer::alloc_buffer().map(|idx| idx as i32)
}

pub(super) fn recv_buffer_referenced_elsewhere(recv_buf_idx: i32, owner_idx: usize) -> bool {
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

pub(super) fn free_recv_buffer_if_unreferenced(recv_buf_idx: i32, owner_idx: usize) {
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

pub(super) fn ensure_external_peer(idx: usize) -> Result<(), i64> {
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

pub(super) fn external_peer_is_usable_for_socket(idx: usize) -> bool {
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

pub(super) fn find_external_peer_for_socket(idx: usize) -> Option<usize> {
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

pub(super) fn reap_detached_external_peers() {
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

pub(super) fn ensure_external_peer_for_connected_socket(idx: usize) -> Result<(), i64> {
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
    state().read_debug.count[idx as usize]
}

pub fn debug_socket_read_bytes(idx: u32) -> u64 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    state().read_debug.bytes[idx as usize]
}

pub fn debug_socket_read_last_fd(idx: u32) -> u32 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    state().read_debug.last_fd[idx as usize]
}

pub fn debug_socket_read_last_result(idx: u32) -> i64 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    state().read_debug.last_result[idx as usize]
}

pub fn debug_socket_read_last_before(idx: u32) -> u32 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    state().read_debug.last_before[idx as usize]
}

pub fn debug_socket_read_last_after(idx: u32) -> u32 {
    if (idx as usize) >= MAX_SOCKETS {
        return 0;
    }
    state().read_debug.last_after[idx as usize]
}

pub(super) fn record_socket_read_debug(
    idx: usize,
    fd: u64,
    before: usize,
    result: i64,
    after: usize,
) {
    if idx >= MAX_SOCKETS {
        return;
    }
    let debug = &mut state().read_debug;
    debug.last_fd[idx] = fd as u32;
    debug.last_result[idx] = result;
    debug.last_before[idx] = before.min(u32::MAX as usize) as u32;
    debug.last_after[idx] = after.min(u32::MAX as usize) as u32;
    if result > 0 {
        debug.count[idx] = debug.count[idx].saturating_add(1);
        debug.bytes[idx] = debug.bytes[idx].saturating_add(result as u64);
    }
}

pub(super) fn socket_has_successful_read(idx: usize) -> bool {
    if idx >= MAX_SOCKETS {
        return false;
    }
    let debug = &state().read_debug;
    debug.count[idx] > 0 && debug.bytes[idx] > 0
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

pub(super) fn shutdown_slot(idx: usize) {
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

pub(super) fn ensure_socket_recv_buffer(idx: usize) -> Result<(), i64> {
    if socket_table()[idx].recv_buf_idx >= 0 {
        return Ok(());
    }
    let Some(buf_idx) = alloc_socket_recv_buffer() else {
        return Err(ENOMEM);
    };
    socket_table()[idx].recv_buf_idx = buf_idx;
    Ok(())
}

pub fn close_connection_slot(conn_id: i32) {
    if conn_id < 0 || conn_id as usize >= MAX_SOCKETS || !is_slot_used(conn_id as u32) {
        return;
    }
    shutdown_slot(conn_id as usize);
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::super::poll::{EPOLLIN, EPOLLOUT};
    use super::super::{
        connect_peer_addr, inject_external_connection_by_port, poll_revents_ofd,
        resume_connect_result, sys_accept4, sys_bind, sys_connect, sys_listen, sys_socket,
    };
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
        let client_idx = inject_external_connection_by_port(0x5000, b"request");
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
        let client_idx = inject_external_connection_by_port(0x5000, b"request");
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

        state().used &= !(1u32 << socket_idx);

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
