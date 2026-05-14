use tidemark_kernel::abi::*;
use tidemark_kernel::fs::fd_table;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::net::ring_buffer;
use tidemark_kernel::syscall::socket;

const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_OOBINLINE: u64 = 10;
const SO_NO_CHECK: u64 = 11;
const SO_BSDCOMPAT: u64 = 14;
const SO_RCVLOWAT: u64 = 18;
const SO_SNDLOWAT: u64 = 19;
const SO_RCVTIMEO_OLD: u64 = 20;
const SO_SNDTIMEO_OLD: u64 = 21;
const SO_ACCEPTCONN: u64 = 30;
const SO_SNDBUFFORCE: u64 = 32;
const SO_RCVBUFFORCE: u64 = 33;
const SO_INCOMING_CPU: u64 = 49;
const SO_COOKIE: u64 = 57;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;
const TCP_NODELAY: u64 = 1;
const F_GETFD: u64 = 1;

#[test]
fn socket_create_close_and_errors() {
    let mut t = TestVm::new();

    let bad = socket::sys_socket(&mut t.vm, t.base, 9999, SOCK_STREAM as u64, 0);
    assert_eq!(bad, EAFNOSUPPORT);

    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 3, "socket fd should be >= 3, got {}", fd);

    let ofd = fd_table::get_ofd(t.base, &t.vm, fd as u64).unwrap();
    assert_eq!(ofd.fd_type, FD_TYPE_SOCKET);

    assert_eq!(t.sys_close(fd), 0);
    assert!(fd_table::get_ofd(t.base, &t.vm, fd as u64).is_none());
}

#[test]
fn socketpair_unix_stream_roundtrip() {
    let mut t = TestVm::new();
    let sv_addr = t.scratch + 0x80;
    assert_eq!(
        socket::sys_socketpair(
            &mut t.vm,
            t.base,
            AF_UNIX as u64,
            SOCK_STREAM as u64,
            0,
            sv_addr
        ),
        0
    );

    let left_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, sv_addr) } as i64;
    let right_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, sv_addr + 4) } as i64;
    assert!(left_fd >= 3);
    assert!(right_fd >= 3);
    assert_ne!(left_fd, right_fd);

    let msg_addr = t.scratch + 0x100;
    t.write_mem(msg_addr, b"ping");
    assert_eq!(
        socket::sys_sendto(&mut t.vm, t.base, left_fd as u64, msg_addr, 4, 0, 0, 0),
        4
    );

    let read_addr = t.scratch + 0x140;
    assert_eq!(
        socket::sys_recvfrom(&mut t.vm, t.base, right_fd as u64, read_addr, 4, 0, 0, 0),
        4
    );
    let mut actual = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, read_addr, &mut actual);
    }
    assert_eq!(&actual, b"ping");
}

#[test]
fn socketpair_unix_dgram_honors_type_flags() {
    let mut t = TestVm::new();
    let sv_addr = t.scratch + 0x200;
    assert_eq!(
        socket::sys_socketpair(
            &mut t.vm,
            t.base,
            AF_UNIX as u64,
            (SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC) as u64,
            0,
            sv_addr,
        ),
        0
    );

    let left_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, sv_addr) } as u64;
    let right_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, sv_addr + 4) } as u64;
    let left_ofd = fd_table::get_ofd(t.base, &t.vm, left_fd).unwrap();
    let right_ofd = fd_table::get_ofd(t.base, &t.vm, right_fd).unwrap();
    assert_ne!(left_ofd.status_flags & O_NONBLOCK, 0);
    assert_ne!(right_ofd.status_flags & O_NONBLOCK, 0);
    assert_ne!(
        fd_table::sys_fcntl(&mut t.vm, t.base, left_fd, F_GETFD, 0),
        0
    );
    assert_ne!(
        fd_table::sys_fcntl(&mut t.vm, t.base, right_fd, F_GETFD, 0),
        0
    );
}

#[test]
fn unix_stream_bind_listen_connect_accept_roundtrip() {
    let mut t = TestVm::new();
    let listener_fd = socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_STREAM as u64, 0);
    assert!(listener_fd >= 0);
    let client_fd = socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_STREAM as u64, 0);
    assert!(client_fd >= 0);

    let path = b"/tmp/tidemark-unix\0";
    let addr = t.scratch + 0x240;
    let mut sockaddr = [0u8; 2 + 108];
    sockaddr[0..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    sockaddr[2..2 + path.len()].copy_from_slice(path);
    t.write_mem(addr, &sockaddr[..2 + path.len()]);

    assert_eq!(
        socket::sys_bind(
            &mut t.vm,
            t.base,
            listener_fd as u64,
            addr,
            (2 + path.len()) as u64
        ),
        0
    );
    assert_eq!(
        socket::sys_listen(&mut t.vm, t.base, listener_fd as u64, 8),
        0
    );
    assert_eq!(
        socket::sys_connect(
            &mut t.vm,
            t.base,
            client_fd as u64,
            addr,
            (2 + path.len()) as u64
        ),
        0
    );

    let accepted_fd = socket::sys_accept4(&mut t.vm, t.base, listener_fd as u64, 0, 0, 0);
    assert!(accepted_fd >= 0);

    let msg_addr = t.scratch + 0x340;
    t.write_mem(msg_addr, b"unix");
    assert_eq!(
        socket::sys_sendto(&mut t.vm, t.base, client_fd as u64, msg_addr, 4, 0, 0, 0),
        4
    );
    let read_addr = t.scratch + 0x360;
    assert_eq!(
        socket::sys_recvfrom(&mut t.vm, t.base, accepted_fd as u64, read_addr, 4, 0, 0, 0),
        4
    );
    let mut actual = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, read_addr, &mut actual);
    }
    assert_eq!(&actual, b"unix");

    let peer_addr = t.scratch + 0x380;
    let peer_len = t.scratch + 0x3f0;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, peer_len, 2 + path.len() as u32);
    }
    assert_eq!(
        socket::sys_getpeername(&mut t.vm, t.base, client_fd as u64, peer_addr, peer_len),
        0
    );
    let actual_len = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, peer_len) } as usize;
    let mut actual_peer = vec![0u8; actual_len];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, peer_addr, &mut actual_peer);
    }
    assert_eq!(&actual_peer[..], &sockaddr[..actual_len]);
}

#[test]
fn unix_dgram_connect_routes_to_bound_peer() {
    let mut t = TestVm::new();
    let server_fd = socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_DGRAM as u64, 0);
    assert!(server_fd >= 0);
    let client_fd = socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_DGRAM as u64, 0);
    assert!(client_fd >= 0);

    let path = b"\0tdm-dgram";
    let addr = t.scratch + 0x480;
    let mut sockaddr = [0u8; 2 + 108];
    sockaddr[0..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    sockaddr[2..2 + path.len()].copy_from_slice(path);
    t.write_mem(addr, &sockaddr[..2 + path.len()]);

    assert_eq!(
        socket::sys_bind(
            &mut t.vm,
            t.base,
            server_fd as u64,
            addr,
            (2 + path.len()) as u64
        ),
        0
    );
    assert_eq!(
        socket::sys_connect(
            &mut t.vm,
            t.base,
            client_fd as u64,
            addr,
            (2 + path.len()) as u64
        ),
        0
    );

    let msg_addr = t.scratch + 0x540;
    t.write_mem(msg_addr, b"dg");
    assert_eq!(
        socket::sys_sendto(&mut t.vm, t.base, client_fd as u64, msg_addr, 2, 0, 0, 0),
        2
    );
    let read_addr = t.scratch + 0x560;
    assert_eq!(
        socket::sys_recvfrom(&mut t.vm, t.base, server_fd as u64, read_addr, 2, 0, 0, 0),
        2
    );
    let mut actual = [0u8; 2];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, read_addr, &mut actual);
    }
    assert_eq!(&actual, b"dg");
}

#[test]
fn socket_bind_and_getsockname() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let addr_buf = t.scratch + 0x300;
    let addrlen_ptr = t.scratch + 0x380;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addrlen_ptr, 16);
    }
    let ret = socket::sys_getsockname(&mut t.vm, t.base, fd as u64, addr_buf, addrlen_ptr);
    assert_eq!(ret, 0);
    let family = unsafe { tidemark_kernel::guest_mem::read_u16(t.base, addr_buf) };
    assert_eq!(family, AF_INET as u16);
    let actual_len = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, addrlen_ptr) };
    assert_eq!(actual_len, 2);

    let sockaddr: [u8; 16] = [2, 0, 0x50, 0x00, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let bind_addr = t.scratch + 0x100;
    t.write_mem(bind_addr, &sockaddr);
    assert_eq!(
        socket::sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16),
        0
    );

    let out_addr = t.scratch + 0x400;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addrlen_ptr, 16);
    }
    let ret2 = socket::sys_getsockname(&mut t.vm, t.base, fd as u64, out_addr, addrlen_ptr);
    assert_eq!(ret2, 0);
    let bound_len = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, addrlen_ptr) };
    assert_eq!(bound_len, 16);
    let returned = t.guest_mem(out_addr, 16);
    assert_eq!(&returned, &sockaddr);
}

#[test]
fn socket_sockopt_roundtrip_and_enotsock() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let val_addr = t.scratch + 0x200;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, val_addr, 1);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_REUSEADDR as u64,
            val_addr,
            4,
        ),
        0
    );
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_NO_CHECK as u64,
            val_addr,
            4,
        ),
        0
    );
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_BSDCOMPAT as u64,
            val_addr,
            4,
        ),
        0
    );
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            IPPROTO_TCP as u64,
            TCP_NODELAY as u64,
            val_addr,
            4,
        ),
        0
    );
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, val_addr, 4096);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_SNDBUFFORCE as u64,
            val_addr,
            4,
        ),
        0
    );
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, val_addr, 6144);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_RCVBUFFORCE as u64,
            val_addr,
            4,
        ),
        0
    );

    let out_addr = t.scratch + 0x240;
    let out_len = t.scratch + 0x248;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_REUSEADDR as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        1
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_NO_CHECK as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        1
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_SNDBUF as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        4096
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_RCVBUF as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        6144
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_INCOMING_CPU as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        0
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 8);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_COOKIE as u64,
            out_addr,
            out_len,
        ),
        0
    );
    let cookie = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr) };
    assert_ne!(cookie, 0);

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_TYPE as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        SOCK_STREAM
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_PROTOCOL as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        IPPROTO_TCP as u32
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_DOMAIN as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        AF_INET as u32
    );

    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            1,
            SOL_SOCKET as u64,
            SO_REUSEADDR as u64,
            val_addr,
            4,
        ),
        ENOTSOCK
    );
}

#[test]
fn socket_protocol_default_for_datagram_is_udp() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_DGRAM as u64, 0);
    assert!(fd >= 0);

    let out_addr = t.scratch + 0x240;
    let out_len = t.scratch + 0x248;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_PROTOCOL as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        IPPROTO_UDP as u32
    );
}

#[test]
fn socket_sockopt_validation_and_acceptconn() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_KEEPALIVE as u64,
            t.scratch + 0x300,
            1,
        ),
        EINVAL
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, t.scratch + 0x308, 4);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_RCVLOWAT as u64,
            t.scratch + 0x308,
            4,
        ),
        0
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, t.scratch + 0x30c, 1);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_OOBINLINE as u64,
            t.scratch + 0x30c,
            4,
        ),
        0
    );

    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_SNDLOWAT as u64,
            t.scratch + 0x30c,
            4,
        ),
        ENOPROTOOPT
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, t.scratch + 0x304, 0);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_SNDBUF as u64,
            t.scratch + 0x304,
            4,
        ),
        EINVAL
    );

    let sockaddr: [u8; 16] = [2, 0, 0x50, 0x00, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let bind_addr = t.scratch + 0x340;
    t.write_mem(bind_addr, &sockaddr);
    assert_eq!(
        socket::sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16),
        0
    );
    assert_eq!(socket::sys_listen(&mut t.vm, t.base, fd as u64, 8), 0);

    let out_addr = t.scratch + 0x380;
    let out_len = t.scratch + 0x388;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_ACCEPTCONN as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        1
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_RCVLOWAT as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        4
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_OOBINLINE as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        1
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_SNDLOWAT as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        1
    );
}

#[test]
fn socket_timeout_validation() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let tv_addr = t.scratch + 0x7a0;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr + 8, 1_000_000);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_RCVTIMEO_OLD,
            tv_addr,
            16,
        ),
        EINVAL
    );
}

#[test]
fn socket_accept_block_captures_rcv_timeout_ms() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let tv_addr = t.scratch + 0x7c0;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr + 8, 1500);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_RCVTIMEO_OLD,
            tv_addr,
            16,
        ),
        0
    );

    let sockaddr: [u8; 16] = [2, 0, 0x50, 0x00, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let bind_addr = t.scratch + 0x7e0;
    t.write_mem(bind_addr, &sockaddr);
    assert_eq!(
        socket::sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16),
        0
    );
    assert_eq!(socket::sys_listen(&mut t.vm, t.base, fd as u64, 1), 0);

    let ret = socket::sys_accept4(&mut t.vm, t.base, fd as u64, 0, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_SOCKET_RECV);
    assert_eq!(t.vm.socket_timeout_ms, 2);
}

#[test]
fn socket_connect_block_captures_snd_timeout_ms() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let tv_addr = t.scratch + 0x800;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr + 8, 1500);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_SNDTIMEO_OLD,
            tv_addr,
            16,
        ),
        0
    );

    let sockaddr: [u8; 16] = [2, 0, 0x00, 0x50, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0];
    let addr = t.scratch + 0x820;
    t.write_mem(addr, &sockaddr);
    t.vm.x[10] = fd as u64;
    t.vm.x[17] = SYS_CONNECT;
    assert_eq!(
        socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16),
        0
    );
    assert_eq!(t.vm.status, STATUS_CONNECT);
    assert_eq!(t.vm.socket_timeout_ms, 2);
}

#[test]
fn socket_connect_timeout_returns_etimedout() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let tv_addr = t.scratch + 0x840;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr + 8, 0);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_SNDTIMEO_OLD,
            tv_addr,
            16,
        ),
        0
    );

    let sockaddr: [u8; 16] = [2, 0, 0x00, 0x50, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0];
    let addr = t.scratch + 0x860;
    t.write_mem(addr, &sockaddr);
    t.vm.x[10] = fd as u64;
    t.vm.x[17] = SYS_CONNECT;
    assert_eq!(
        socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16),
        0
    );
    assert_eq!(t.vm.status, STATUS_CONNECT);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    thread_resume_socket_wait_timeout(vm_ptr);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10] as i64, ETIMEDOUT);
    assert_eq!(t.vm.socket_timeout_ms, -1);
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, t.scratch + 0x908, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_ERROR,
            t.scratch + 0x900,
            t.scratch + 0x908,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, t.scratch + 0x900) } as i64,
        -ETIMEDOUT
    );
}

#[test]
fn socket_connect_and_getpeername() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let out_addr = t.scratch + 0x600;
    let addrlen_ptr = t.scratch + 0x680;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addrlen_ptr, 16);
    }
    assert_eq!(
        socket::sys_getpeername(&mut t.vm, t.base, fd as u64, out_addr, addrlen_ptr),
        ENOTCONN
    );

    let sockaddr: [u8; 16] = [2, 0, 0x00, 0x50, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0];
    let addr = t.scratch + 0x500;
    t.write_mem(addr, &sockaddr);
    t.vm.x[10] = fd as u64;
    assert_eq!(
        socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16),
        0
    );
    assert_eq!(t.vm.status, STATUS_CONNECT);

    socket::resume_connect_result(&mut t.vm, t.base, ECONNREFUSED);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10] as i64, ECONNREFUSED);
}

#[test]
fn socket_slot_exhaustion_and_reuse() {
    let mut t = TestVm::new();
    let mut fds = [0i64; MAX_SOCKETS];
    for (i, slot) in fds.iter_mut().enumerate() {
        *slot = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(*slot >= 0, "socket {} failed: {}", i, *slot);
    }

    let extra = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert_eq!(extra, ENOMEM);

    assert_eq!(t.sys_close(fds[0]), 0);
    let new_fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(new_fd >= 0);
}

#[test]
fn socket_connect_force_shutdown_close_reuses_slots() {
    let mut t = TestVm::new();
    let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let addr = t.scratch + 0x500;
    t.write_mem(addr, &sockaddr);

    for i in 0..(MAX_SOCKETS * 2) {
        let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(fd >= 0, "socket allocation failed on iteration {i}: {fd}");
        t.vm.x[10] = fd as u64;
        assert_eq!(
            socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16),
            0
        );
        socket::resume_connect_result(&mut t.vm, t.base, 0);

        if i == 0 {
            assert_eq!(
                socket::inject_external_inbound_for_fd(t.base, &t.vm, fd as u64, b"hello"),
                5
            );
            assert_eq!(socket::force_shutdown_for_fd(t.base, &t.vm, fd as u64), 0);
            let read_addr = t.scratch + 0x700;
            assert_eq!(
                socket::sys_recvfrom(&mut t.vm, t.base, fd as u64, read_addr, 8, 0, 0, 0),
                5
            );
            let mut actual = [0u8; 5];
            unsafe {
                tidemark_kernel::guest_mem::read_bytes(t.base, read_addr, &mut actual);
            }
            assert_eq!(&actual, b"hello");
            assert_eq!(
                socket::sys_recvfrom(&mut t.vm, t.base, fd as u64, read_addr, 8, 0, 0, 0),
                0
            );
        } else if i == 1 {
            assert_eq!(
                socket::inject_external_inbound_for_fd(t.base, &t.vm, fd as u64, b"world"),
                5
            );
            assert_eq!(socket::force_shutdown_for_fd(t.base, &t.vm, fd as u64), 0);
            let read_addr = t.scratch + 0x700;
            let iov_addr = t.scratch + 0x740;
            let msg_addr = t.scratch + 0x780;
            unsafe {
                tidemark_kernel::guest_mem::write_u64(t.base, iov_addr, read_addr);
                tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 8, 8);
                tidemark_kernel::guest_mem::write_u64(t.base, msg_addr + 16, iov_addr);
                tidemark_kernel::guest_mem::write_u64(t.base, msg_addr + 24, 1);
            }
            assert_eq!(
                socket::sys_recvmsg(&mut t.vm, t.base, fd as u64, msg_addr, 0),
                5
            );
            let mut actual = [0u8; 5];
            unsafe {
                tidemark_kernel::guest_mem::read_bytes(t.base, read_addr, &mut actual);
            }
            assert_eq!(&actual, b"world");
            assert_eq!(
                socket::sys_recvmsg(&mut t.vm, t.base, fd as u64, msg_addr, 0),
                0
            );
        } else {
            assert_eq!(socket::force_shutdown_for_fd(t.base, &t.vm, fd as u64), 0);
        }
        assert_eq!(t.sys_close(fd), 0);
    }
}

#[test]
fn socket_failed_external_peer_connect_releases_recv_buffer() {
    let mut t = TestVm::new();
    let sockaddr: [u8; 16] = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let addr = t.scratch + 0x500;
    t.write_mem(addr, &sockaddr);

    let mut fds = [0i64; MAX_SOCKETS];
    for slot in fds.iter_mut() {
        *slot = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
        assert!(*slot >= 0);
    }

    let fd = fds[MAX_SOCKETS - 1];
    t.vm.x[10] = fd as u64;
    assert_eq!(
        socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16),
        0
    );
    socket::resume_connect_result(&mut t.vm, t.base, 0);
    assert_eq!(t.vm.x[10] as i64, ENOMEM);
    assert_eq!(ring_buffer::net_buffer_state().1, 0);

    for fd in fds {
        assert_eq!(t.sys_close(fd), 0);
    }
}

#[test]
fn shutdown_reports_linux_shaped_error_cases() {
    let mut t = TestVm::new();
    assert_eq!(
        socket::sys_shutdown(&mut t.vm, t.base, 1, SHUT_RD as u64),
        ENOTSOCK
    );

    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);
    assert_eq!(
        socket::sys_shutdown(&mut t.vm, t.base, fd as u64, SHUT_RD as u64),
        ENOTCONN
    );

    let sockaddr: [u8; 16] = [2, 0, 0x00, 0x50, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0];
    let addr = t.scratch + 0x500;
    t.write_mem(addr, &sockaddr);
    t.vm.x[10] = fd as u64;
    assert_eq!(
        socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16),
        0
    );
    socket::resume_connect_result(&mut t.vm, t.base, 0);
    assert_eq!(
        socket::sys_shutdown(&mut t.vm, t.base, fd as u64, 99),
        EINVAL
    );
    assert_eq!(
        socket::sys_shutdown(&mut t.vm, t.base, fd as u64, SHUT_RD as u64),
        0
    );
    assert_eq!(
        socket::sys_shutdown(&mut t.vm, t.base, fd as u64, SHUT_RDWR as u64),
        0
    );
}
