use super::support::*;

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
