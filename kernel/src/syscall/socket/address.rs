use super::{SOCK_STATE_CONNECTING, SOCKADDR_STORAGE_LEN, get_socket_idx, socket_table};
use crate::abi::*;
use crate::guest_mem;
use crate::types::ThreadState;

pub(super) fn port_from_sockaddr(addr: &[u8], len: u32) -> u16 {
    if len < 4 {
        return 0;
    }
    u16::from_be_bytes([addr[2], addr[3]])
}

pub fn connect_peer_addr_for_fd(base: u32, vm: &ThreadState, fd: u64, dst: &mut [u8]) -> i32 {
    let Some(idx) = get_socket_idx(base, vm, fd).map(|value| value as usize) else {
        return ENOTSOCK as i32;
    };
    let slot = &socket_table()[idx];
    if slot.state != SOCK_STATE_CONNECTING {
        return EINVAL as i32;
    }
    let len = (slot.peer_len as usize)
        .min(dst.len())
        .min(SOCKADDR_STORAGE_LEN);
    dst[..len].copy_from_slice(&slot.peer_addr[..len]);
    len as i32
}

pub fn connect_peer_addr(vm: &ThreadState, dst: &mut [u8]) -> i32 {
    connect_peer_addr_for_fd(vm.guest_base, vm, super::thread_connect_target_fd(vm), dst)
}

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
        // No address bound; return a zeroed sockaddr with the right family.
        let family_bytes = (slot.domain as u16).to_le_bytes();
        unsafe {
            guest_mem::write_bytes(base, addr, &family_bytes);
            let caller_len = guest_mem::read_u32(base, addrlen_ptr);
            if caller_len > 2 {
                let zero_len = (caller_len as usize - 2).min(SOCKADDR_STORAGE_LEN - 2);
                let zeros = [0u8; SOCKADDR_STORAGE_LEN];
                guest_mem::write_bytes(base, addr + 2, &zeros[..zero_len]);
            }
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
