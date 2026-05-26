use super::support::*;

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
