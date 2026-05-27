//! Socket syscalls: socket, bind, connect, accept4, sendto, recvfrom,
//! setsockopt, getsockopt, getsockname, getpeername.
//!
//! Semantics: https://man7.org/linux/man-pages/man2/socket.2.html
//!            https://man7.org/linux/man-pages/man7/socket.7.html
//!            https://man7.org/linux/man-pages/man7/unix.7.html
//!
//! Socket state is kernel Worker managed (allocated via alloc.rs). External
//! endpoints use generic external-peer hooks rather than endpoint-named socket
//! semantics.
//!
mod address;
mod connect;
mod create;
mod options;
mod poll;
mod send_recv;
mod state;

pub use address::{connect_peer_addr, connect_peer_addr_for_fd, sys_getpeername, sys_getsockname};
pub use connect::{
    inject_external_connection_by_port, resume_connect_result, resume_connect_result_for_fd,
    sys_accept4, sys_bind, sys_connect, sys_listen,
};
pub use create::{sys_socket, sys_socketpair};
pub use options::{sys_getsockopt, sys_setsockopt};
pub use poll::{
    poll_revents, poll_revents_ofd, socket_recv_timeout_ms_for_fd, socket_send_timeout_ms_for_fd,
};
use poll::{socket_recv_timeout_ms_for_slot, socket_send_timeout_ms_for_slot};
pub use send_recv::{
    read_external_connection_data, socket_read, socket_write, sys_recvfrom, sys_recvmsg,
    sys_sendmsg, sys_sendto, sys_shutdown,
};

use state::{
    ACCEPT_QUEUE_SIZE, DEFAULT_SOCKET_BUFFER, INVALID_BUF_IDX, INVALID_PEER_IDX, IPPROTO_TCP,
    IPPROTO_UDP, NETLINK_ROUTE, SHUT_RD_MASK, SHUT_WR_MASK, SOCK_STATE_BOUND, SOCK_STATE_CONNECTED,
    SOCK_STATE_CONNECTING, SOCK_STATE_IDLE, SOCK_STATE_LISTENING, SOCK_STATE_SHUTDOWN,
    SOCKADDR_STORAGE_LEN, SocketSlot, alloc_socket_cookie, alloc_socket_recv_buffer,
    alloc_socket_slot, ensure_external_peer, ensure_external_peer_for_connected_socket,
    ensure_socket_recv_buffer, free_recv_buffer_if_unreferenced, free_socket_slot, get_socket_idx,
    record_socket_read_debug, shutdown_slot, socket_has_successful_read, socket_table,
    thread_connect_target_fd,
};
pub use state::{
    attach_socket_state, close_connection_slot, close_external_peer_for_fd,
    commit_external_connect_for_fd, debug_external_outbound_available_for_fd,
    debug_socket_external_peer, debug_socket_idx_for_fd, debug_socket_peer_idx,
    debug_socket_read_bytes, debug_socket_read_count, debug_socket_read_last_after,
    debug_socket_read_last_before, debug_socket_read_last_fd, debug_socket_read_last_result,
    debug_socket_recv_available, debug_socket_recv_buf_idx, debug_socket_state, debug_socket_type,
    drain_external_outbound_for_fd, force_shutdown_for_fd, init, inject_external_inbound_for_fd,
    is_slot_used, mark_external_peer_for_fd, socket_close, socket_state_bytes, socket_state_ptr,
    socket_table_bytes, socket_table_ptr, socket_used, thread_connect_fd,
};
