use super::support::*;

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
