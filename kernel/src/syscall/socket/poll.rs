use super::{
    SOCK_STATE_CONNECTED, SOCK_STATE_LISTENING, SOCK_STATE_SHUTDOWN,
    connect::accept_queue_len,
    get_socket_idx,
    is_slot_used,
    send_recv::{slot_peer_is_closed, socket_recv_available, socket_send_space},
    socket_table,
};
use crate::abi::*;
use crate::fs::fd_table;
use crate::types::{OpenFileDesc, ThreadState};

pub(super) const EPOLLIN: u32 = 0x001;
pub(super) const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;
const SHUT_RD_MASK: u32 = 1 << 0;

fn timeout_to_millis(sec: u64, usec: u64) -> i64 {
    if sec == 0 && usec == 0 {
        return -1;
    }
    let millis = sec
        .saturating_mul(1000)
        .saturating_add(usec.saturating_add(999) / 1000);
    millis.min(i64::MAX as u64) as i64
}

pub(super) fn socket_recv_timeout_ms_for_slot(slot: &super::SocketSlot) -> i64 {
    timeout_to_millis(slot.so_rcvtimeo_sec, slot.so_rcvtimeo_usec)
}

pub(super) fn socket_send_timeout_ms_for_slot(slot: &super::SocketSlot) -> i64 {
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
    if idx >= MAX_SOCKETS || !is_slot_used(idx as u32) {
        return EPOLLERR | EPOLLHUP;
    }
    let slot = &socket_table()[idx];
    let mut revents = 0u32;

    if slot.state == SOCK_STATE_LISTENING {
        if accept_queue_len(slot) > 0 {
            revents |= EPOLLIN;
        }
    } else if socket_recv_available(idx) > 0 {
        revents |= EPOLLIN;
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
