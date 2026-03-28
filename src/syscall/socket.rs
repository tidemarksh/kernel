//! Socket syscalls: socket, bind, connect, accept4, sendto, recvfrom,
//! setsockopt, getsockopt, getsockname, getpeername.
//!
//! Semantics: https://man7.org/linux/man-pages/man2/socket.2.html
//!            https://man7.org/linux/man-pages/man7/socket.7.html
//!
//! Socket state is kernel Worker managed (allocated via alloc.rs).
//! Data plane (send/recv) is delegated to the TS runtime via status codes.
//!
//! Struct layout (RV64):
//!
//! struct SocketSlot {                    // 80 bytes total
//!     domain:     u32,                   // offset 0   — AF_INET, AF_UNIX, AF_INET6
//!     sock_type:  u32,                   // offset 4   — SOCK_STREAM, SOCK_DGRAM
//!     protocol:   u32,                   // offset 8   — protocol number
//!     state:      u32,                   // offset 12  — SOCK_STATE_*
//!     local_addr: [u8; 28],             // offset 16  — sockaddr storage (local)
//!     local_len:  u32,                   // offset 44  — actual length of local_addr
//!     peer_addr:  [u8; 28],             // offset 48  — sockaddr storage (peer)
//!     peer_len:   u32,                   // offset 76  — actual length of peer_addr
//! };

use crate::abi::*;
use crate::alloc;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::ThreadState;

// Socket states
const SOCK_STATE_IDLE: u32 = 0;
const SOCK_STATE_BOUND: u32 = 1;
const SOCK_STATE_LISTENING: u32 = 2;
const SOCK_STATE_CONNECTED: u32 = 3;
const SOCK_STATE_CONNECTING: u32 = 4;

// Max sockaddr size we store (covers sockaddr_in and sockaddr_in6)
const SOCKADDR_STORAGE_LEN: usize = 28;

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
        free_socket_slot(socket_idx);
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
    if len < 2 || len > SOCKADDR_STORAGE_LEN {
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
    if len < 2 || len > SOCKADDR_STORAGE_LEN {
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

// =========================================================================
// accept4(2)
// =========================================================================

/// accept4(fd, addr, addrlen, flags) -> ENOSYS (stub)
pub fn sys_accept4(
    _vm: &mut ThreadState,
    _base: u32,
    _fd: u64,
    _addr: u64,
    _addrlen: u64,
    _flags: u64,
) -> i64 {
    ENOSYS
}

// =========================================================================
// sendto(2)
// =========================================================================

/// sendto(fd, buf, len, flags, dest_addr, addrlen) -> STATUS_SOCKET_SEND
pub fn sys_sendto(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    _buf: u64,
    _len: u64,
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

    // Signal TS runtime to perform the actual send
    vm.status = STATUS_SOCKET_SEND;
    0
}

// =========================================================================
// recvfrom(2)
// =========================================================================

/// recvfrom(fd, buf, len, flags, src_addr, addrlen) -> EAGAIN or STATUS_SOCKET_RECV
pub fn sys_recvfrom(
    vm: &mut ThreadState,
    _base: u32,
    fd: u64,
    _buf: u64,
    _len: u64,
    _flags: u64,
    _src_addr: u64,
    _addrlen: u64,
) -> i64 {
    let idx = match get_socket_idx(_base, vm, fd) {
        Some(i) => i,
        None => return ENOTSOCK,
    };

    let slot = &socket_table()[idx as usize];

    // For SOCK_STREAM, must be connected
    if slot.sock_type == SOCK_STREAM && slot.state != SOCK_STATE_CONNECTED {
        return ENOTCONN;
    }

    // Check if socket is non-blocking via OFD status_flags
    let ofd = match fd_table::get_ofd(_base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.status_flags & O_NONBLOCK != 0 {
        return EAGAIN;
    }

    // Blocking: signal TS runtime to perform the actual recv
    vm.status = STATUS_SOCKET_RECV;
    0
}

// =========================================================================
// setsockopt(2) / getsockopt(2)
// =========================================================================

/// setsockopt(fd, level, optname, optval, optlen) -> 0 (stub success)
pub fn sys_setsockopt(
    vm: &mut ThreadState,
    _base: u32,
    fd: u64,
    _level: u64,
    _optname: u64,
    _optval: u64,
    _optlen: u64,
) -> i64 {
    match get_socket_idx(_base, vm, fd) {
        Some(_) => 0, // stub: accept all options silently
        None => ENOTSOCK,
    }
}

/// getsockopt(fd, level, optname, optval, optlen) -> 0 (stub success)
///
/// Writes a zero u32 to optval and sets *optlen = 4 as a safe default.
pub fn sys_getsockopt(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    _level: u64,
    _optname: u64,
    optval: u64,
    optlen: u64,
) -> i64 {
    match get_socket_idx(base, vm, fd) {
        Some(_) => {
            // Return a 4-byte zero as the option value
            if optval != 0 && optlen != 0 {
                unsafe {
                    guest_mem::write_u32(base, optval, 0);
                    guest_mem::write_u32(base, optlen, 4);
                }
            }
            0
        }
        None => ENOTSOCK,
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
    use crate::abi::*;
    use crate::test_helpers::TestVm;

    /// Tests: socket creation, type validation, close frees slot, unsupported domain.
    #[test]
    fn socket_create_close_and_errors() {
        let mut t = TestVm::new();

        // Unsupported domain (AF_NETLINK = 16)
        let bad = sys_socket(&mut t.vm, t.base, 16, SOCK_STREAM as u64, 0);
        assert_eq!(bad, EAFNOSUPPORT);

        // Create a TCP socket
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 3, "socket fd should be >= 3, got {}", fd);

        let ofd = fd_table::get_ofd(t.base, &t.vm, fd as u64).unwrap();
        assert_eq!(ofd.fd_type, FD_TYPE_SOCKET);

        // Close frees the slot
        let socket_idx = ofd.ino;
        assert!(is_slot_used(socket_idx));
        let ret = t.sys_close(fd);
        assert_eq!(ret, 0);
        assert!(!is_slot_used(socket_idx));
    }

    /// Tests: bind, getsockname (unbound and bound).
    #[test]
    fn socket_bind_and_getsockname() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        // getsockname on unbound socket: returns family only
        let addr_buf = t.scratch + 0x300;
        let addrlen_ptr = t.scratch + 0x380;
        unsafe {
            guest_mem::write_u32(t.base, addrlen_ptr, 16);
        }
        let ret = sys_getsockname(&mut t.vm, t.base, fd as u64, addr_buf, addrlen_ptr);
        assert_eq!(ret, 0);
        let family = unsafe { guest_mem::read_u16(t.base, addr_buf) };
        assert_eq!(family, AF_INET as u16);
        let actual_len = unsafe { guest_mem::read_u32(t.base, addrlen_ptr) };
        assert_eq!(actual_len, 2);

        // Bind
        let sockaddr: [u8; 16] = [2, 0, 0x50, 0x00, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let bind_addr = t.scratch + 0x100;
        t.write_mem(bind_addr, &sockaddr);
        let ret = sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16);
        assert_eq!(ret, 0);

        let ofd = fd_table::get_ofd(t.base, &t.vm, fd as u64).unwrap();
        let slot = &socket_table()[ofd.ino as usize];
        assert_eq!(slot.state, SOCK_STATE_BOUND);
        assert_eq!(slot.local_len, 16);

        // getsockname on bound socket: returns bound address
        let out_addr = t.scratch + 0x400;
        unsafe {
            guest_mem::write_u32(t.base, addrlen_ptr, 16);
        }
        let ret2 = sys_getsockname(&mut t.vm, t.base, fd as u64, out_addr, addrlen_ptr);
        assert_eq!(ret2, 0);
        let bound_len = unsafe { guest_mem::read_u32(t.base, addrlen_ptr) };
        assert_eq!(bound_len, 16);
        let returned = t.guest_mem(out_addr, 16);
        assert_eq!(&returned, &sockaddr);
    }

    /// Tests: setsockopt, ENOTSOCK on non-socket FD.
    #[test]
    fn socket_setsockopt_and_enotsock() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        let val_addr = t.scratch + 0x200;
        unsafe {
            guest_mem::write_u32(t.base, val_addr, 1);
        }
        let ret = sys_setsockopt(&mut t.vm, t.base, fd as u64, 1, 2, val_addr, 4);
        assert_eq!(ret, 0);

        // Not a socket -> ENOTSOCK
        let ret2 = sys_setsockopt(&mut t.vm, t.base, 1, 1, 2, val_addr, 4);
        assert_eq!(ret2, ENOTSOCK);
    }

    /// Tests: connect returns STATUS_CONNECT, getpeername before connect returns ENOTCONN.
    #[test]
    fn socket_connect_and_getpeername() {
        let mut t = TestVm::new();
        let fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0);

        // getpeername before connect -> ENOTCONN
        let out_addr = t.scratch + 0x600;
        let addrlen_ptr = t.scratch + 0x680;
        unsafe {
            guest_mem::write_u32(t.base, addrlen_ptr, 16);
        }
        let ret = sys_getpeername(&mut t.vm, t.base, fd as u64, out_addr, addrlen_ptr);
        assert_eq!(ret, ENOTCONN);

        // connect -> STATUS_CONNECT
        let sockaddr: [u8; 16] = [2, 0, 0x00, 0x50, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = t.scratch + 0x500;
        t.write_mem(addr, &sockaddr);
        let ret = sys_connect(&mut t.vm, t.base, fd as u64, addr, 16);
        assert_eq!(ret, 0);
        assert_eq!(t.vm.status, STATUS_CONNECT);
    }

    /// Tests: slot exhaustion and reuse after close.
    #[test]
    fn socket_slot_exhaustion_and_reuse() {
        let mut t = TestVm::new();
        let mut fds = [0i64; MAX_SOCKETS];
        for i in 0..MAX_SOCKETS {
            fds[i] = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
            assert!(fds[i] >= 0, "socket {} failed: {}", i, fds[i]);
        }

        // Table full
        let extra = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert_eq!(extra, ENOMEM);

        // Close one, then create succeeds
        let ret = t.sys_close(fds[0]);
        assert_eq!(ret, 0);
        let new_fd = sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(new_fd >= 0);
    }
}
