use tidemark_kernel::abi::*;
use tidemark_kernel::fs::fd_table;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::socket;

const SOL_SOCKET: u64 = 1;
const SO_DEBUG: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_DONTROUTE: u64 = 5;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_OOBINLINE: u64 = 10;
const SO_NO_CHECK: u64 = 11;
const SO_PRIORITY: u64 = 12;
const SO_LINGER: u64 = 13;
const SO_BSDCOMPAT: u64 = 14;
const SO_PASSCRED: u64 = 16;
const SO_PEERCRED: u64 = 17;
const SO_RCVLOWAT: u64 = 18;
const SO_SNDLOWAT: u64 = 19;
const SO_RCVTIMEO_OLD: u64 = 20;
const SO_SNDTIMEO_OLD: u64 = 21;
const SO_ACCEPTCONN: u64 = 30;
const SO_SNDBUFFORCE: u64 = 32;
const SO_RCVBUFFORCE: u64 = 33;
const SO_PASSSEC: u64 = 34;
const SO_MARK: u64 = 36;
const SO_INCOMING_CPU: u64 = 49;
const SO_COOKIE: u64 = 57;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;
const TCP_NODELAY: u64 = 1;
const SO_RCVTIMEO_NEW: u64 = 66;
const SO_SNDTIMEO_NEW: u64 = 67;
const F_GETFD: u64 = 1;

#[test]
fn socket_create_close_and_errors() {
    let mut t = TestVm::new();

    let bad = socket::sys_socket(&mut t.vm, t.base, 16, SOCK_STREAM as u64, 0);
    assert_eq!(bad, EAFNOSUPPORT);

    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 3, "socket fd should be >= 3, got {}", fd);

    let ofd = fd_table::get_ofd(t.base, &t.vm, fd as u64).unwrap();
    assert_eq!(ofd.fd_type, FD_TYPE_SOCKET);

    assert_eq!(t.sys_close(fd), 0);
    assert!(fd_table::get_ofd(t.base, &t.vm, fd as u64).is_none());
}

#[test]
fn socketpair_unix_stream_roundtrip_and_peercred() {
    let mut t = TestVm::new();
    let sv_addr = t.scratch + 0x80;
    assert_eq!(
        socket::sys_socketpair(&mut t.vm, t.base, AF_UNIX as u64, SOCK_STREAM as u64, 0, sv_addr),
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

    let cred_addr = t.scratch + 0x180;
    let cred_len = t.scratch + 0x1a0;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, cred_len, 12);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            left_fd as u64,
            SOL_SOCKET,
            SO_PEERCRED,
            cred_addr,
            cred_len,
        ),
        0
    );
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_i32(t.base, cred_addr) }, 42);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u32(t.base, cred_addr + 4) }, 0);
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u32(t.base, cred_addr + 8) }, 0);
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
    assert_ne!(fd_table::sys_fcntl(&mut t.vm, t.base, left_fd, F_GETFD, 0), 0);
    assert_ne!(fd_table::sys_fcntl(&mut t.vm, t.base, right_fd, F_GETFD, 0), 0);
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
            SO_DEBUG as u64,
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
            SOL_SOCKET as u64,
            SO_DONTROUTE as u64,
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
        tidemark_kernel::guest_mem::write_u32(t.base, val_addr, 7);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_PRIORITY as u64,
            val_addr,
            4,
        ),
        0
    );
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, val_addr, 42);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET as u64,
            SO_MARK as u64,
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
            SO_DEBUG as u64,
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
            SO_PRIORITY as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        7
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
            SO_MARK as u64,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        42
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
            SO_BSDCOMPAT as u64,
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
            SO_DONTROUTE as u64,
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
fn unix_sockopts_passcred_and_passsec_are_unix_only() {
    let mut t = TestVm::new();
    let unix_fd = socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_DGRAM as u64, 0);
    assert!(unix_fd >= 0);
    let inet_fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_DGRAM as u64, 0);
    assert!(inet_fd >= 0);

    let val_addr = t.scratch + 0x340;
    let out_addr = t.scratch + 0x344;
    let out_len = t.scratch + 0x348;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, val_addr, 1);
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }

    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            unix_fd as u64,
            SOL_SOCKET,
            SO_PASSCRED,
            val_addr,
            4,
        ),
        0
    );
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            unix_fd as u64,
            SOL_SOCKET,
            SO_PASSSEC,
            val_addr,
            4,
        ),
        0
    );
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            unix_fd as u64,
            SOL_SOCKET,
            SO_PASSCRED,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) }, 1);
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 4);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            unix_fd as u64,
            SOL_SOCKET,
            SO_PASSSEC,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) }, 1);

    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            inet_fd as u64,
            SOL_SOCKET,
            SO_PASSCRED,
            val_addr,
            4,
        ),
        ENOPROTOOPT
    );
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            inet_fd as u64,
            SOL_SOCKET,
            SO_PASSSEC,
            val_addr,
            4,
        ),
        ENOPROTOOPT
    );
}

#[test]
fn socket_linger_and_timeouts_roundtrip() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let linger_addr = t.scratch + 0x700;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, linger_addr, 1);
        tidemark_kernel::guest_mem::write_u32(t.base, linger_addr + 4, 7);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_LINGER,
            linger_addr,
            8,
        ),
        0
    );

    let tv_addr = t.scratch + 0x720;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, tv_addr + 8, 250_000);
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
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_SNDTIMEO_NEW,
            tv_addr,
            16,
        ),
        0
    );

    let out_addr = t.scratch + 0x760;
    let out_len = t.scratch + 0x770;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 8);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_LINGER,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr + 4) },
        7
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 16);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_RCVTIMEO_NEW,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr) },
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        250_000
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, out_len, 16);
    }
    assert_eq!(
        socket::sys_getsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_SNDTIMEO_OLD,
            out_addr,
            out_len,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr) },
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        250_000
    );
}

#[test]
fn socket_timeout_and_linger_validation() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let linger_addr = t.scratch + 0x780;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, linger_addr, 1);
        tidemark_kernel::guest_mem::write_u32(t.base, linger_addr + 4, (-1i32) as u32);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            fd as u64,
            SOL_SOCKET,
            SO_LINGER,
            linger_addr,
            8,
        ),
        EINVAL
    );

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
    assert_eq!(socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
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
    assert_eq!(socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16), 0);
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
    assert_eq!(unsafe { tidemark_kernel::guest_mem::read_u32(t.base, t.scratch + 0x900) } as i64, -ETIMEDOUT);
}

#[test]
fn socket_linger_close_blocks_until_peer_buffer_drains() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let sockaddr: [u8; 16] = [2, 0, 0x50, 0x01, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let bind_addr = t.scratch + 0x820;
    t.write_mem(bind_addr, &sockaddr);
    assert_eq!(socket::sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16), 0);
    assert_eq!(socket::sys_listen(&mut t.vm, t.base, fd as u64, 1), 0);

    let client_idx = socket::inject_http_connection(0, 0x5001, &[]);
    assert!(client_idx >= 0);
    let accepted_fd = socket::sys_accept4(&mut t.vm, t.base, fd as u64, 0, 0, 0);
    assert!(accepted_fd >= 0);

    let linger_addr = t.scratch + 0x840;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, linger_addr, 1);
        tidemark_kernel::guest_mem::write_u32(t.base, linger_addr + 4, 1);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            accepted_fd as u64,
            SOL_SOCKET,
            SO_LINGER,
            linger_addr,
            8,
        ),
        0
    );

    let send_buf = t.scratch + 0x860;
    t.write_mem(send_buf, b"hello");
    assert_eq!(
        socket::sys_sendto(&mut t.vm, t.base, accepted_fd as u64, send_buf, 5, 0, 0, 0),
        5
    );

    t.vm.x[17] = SYS_CLOSE;
    t.vm.x[10] = accepted_fd as u64;
    assert_eq!(t.sys_close(accepted_fd), 0);
    assert_eq!(t.vm.status, STATUS_SOCKET_SEND);
    assert_eq!(t.vm.socket_timeout_ms, 1000);

    let mut drained = [0u8; 16];
    assert_eq!(socket::read_http_response(0, client_idx, &mut drained), 5);
    assert_eq!(&drained[..5], b"hello");

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert!(fd_table::get_ofd(t.base, &t.vm, accepted_fd as u64).is_none());
}

#[test]
fn socket_linger_close_timeout_forces_close() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let sockaddr: [u8; 16] = [2, 0, 0x50, 0x02, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let bind_addr = t.scratch + 0x880;
    t.write_mem(bind_addr, &sockaddr);
    assert_eq!(socket::sys_bind(&mut t.vm, t.base, fd as u64, bind_addr, 16), 0);
    assert_eq!(socket::sys_listen(&mut t.vm, t.base, fd as u64, 1), 0);

    let _client_idx = socket::inject_http_connection(0, 0x5002, &[]);
    let accepted_fd = socket::sys_accept4(&mut t.vm, t.base, fd as u64, 0, 0, 0);
    assert!(accepted_fd >= 0);

    let linger_addr = t.scratch + 0x8a0;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, linger_addr, 1);
        tidemark_kernel::guest_mem::write_u32(t.base, linger_addr + 4, 1);
    }
    assert_eq!(
        socket::sys_setsockopt(
            &mut t.vm,
            t.base,
            accepted_fd as u64,
            SOL_SOCKET,
            SO_LINGER,
            linger_addr,
            8,
        ),
        0
    );

    let send_buf = t.scratch + 0x8c0;
    t.write_mem(send_buf, b"bye");
    assert_eq!(
        socket::sys_sendto(&mut t.vm, t.base, accepted_fd as u64, send_buf, 3, 0, 0, 0),
        3
    );

    t.vm.x[17] = SYS_CLOSE;
    t.vm.x[10] = accepted_fd as u64;
    assert_eq!(t.sys_close(accepted_fd), 0);
    assert_eq!(t.vm.status, STATUS_SOCKET_SEND);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    thread_resume_socket_wait_timeout(vm_ptr);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], 0);
    assert!(fd_table::get_ofd(t.base, &t.vm, accepted_fd as u64).is_none());
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
