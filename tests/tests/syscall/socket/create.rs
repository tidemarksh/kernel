use super::support::*;

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
