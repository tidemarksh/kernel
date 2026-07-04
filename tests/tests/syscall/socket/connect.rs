use super::support::*;

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
fn supervisor_fd_control_records_socket_bind_listen_connect_accept() {
    let mut t = TestVm::new();
    let listener_fd = socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_STREAM as u64, 0);
    assert!(listener_fd >= 0);
    let client_fd = socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_STREAM as u64, 0);
    assert!(client_fd >= 0);

    let listener_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, listener_fd as u64).expect("listener OFD should exist");
    let client_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, client_fd as u64).expect("client OFD should exist");
    let listener_idx = fd_table::get_ofd(t.base, &t.vm, listener_fd as u64)
        .expect("listener OFD should exist")
        .ino;
    let client_idx = fd_table::get_ofd(t.base, &t.vm, client_fd as u64)
        .expect("client OFD should exist")
        .ino;

    let path = b"/tmp/tidemark-supervisor-lifecycle\0";
    let addr = t.scratch + 0x240;
    let mut sockaddr = [0u8; 2 + 108];
    sockaddr[0..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    sockaddr[2..2 + path.len()].copy_from_slice(path);
    t.write_mem(addr, &sockaddr[..2 + path.len()]);
    let addrlen = (2 + path.len()) as u64;
    let read_record = || {
        let mut record = vec![0u8; supervisor_fd_control_record_bytes() as usize];
        assert_eq!(
            supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
            supervisor_fd_control_record_bytes() as i32
        );
        record
    };

    supervisor_reset_shadow_log();
    assert_eq!(
        socket::sys_bind(&mut t.vm, t.base, listener_fd as u64, addr, addrlen),
        0
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let record = read_record();
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_socket_bound()
    );
    assert_eq!(read_u32_le(&record, 36), listener_fd as u32);
    assert_eq!(read_u32_le(&record, 44), listener_ofd);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_SOCKET as u32);
    assert_eq!(read_u32_le(&record, 56), listener_idx);
    assert_eq!(read_u32_le(&record, 60), 0);
    assert_eq!(read_u64_le(&record, 64), 0);
    assert_eq!(read_u64_le(&record, 72), addrlen);
    assert_eq!(
        read_u64_le(&record, 80),
        socket_identity_detail(AF_UNIX, SOCK_STREAM, 0)
    );
    assert_eq!(
        read_u64_le(&record, 88),
        socket_state_transition_detail(SOCK_STATE_IDLE, SOCK_STATE_BOUND)
    );

    supervisor_reset_shadow_log();
    assert_eq!(
        socket::sys_listen(&mut t.vm, t.base, listener_fd as u64, 8),
        0
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let record = read_record();
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_socket_listening()
    );
    assert_eq!(read_u32_le(&record, 36), listener_fd as u32);
    assert_eq!(read_u32_le(&record, 44), listener_ofd);
    assert_eq!(read_u32_le(&record, 56), listener_idx);
    assert_eq!(read_u64_le(&record, 64), 0);
    assert_eq!(read_u64_le(&record, 72), 8);
    assert_eq!(
        read_u64_le(&record, 88),
        socket_state_transition_detail(SOCK_STATE_BOUND, SOCK_STATE_LISTENING)
    );

    supervisor_reset_shadow_log();
    assert_eq!(
        socket::sys_connect(&mut t.vm, t.base, client_fd as u64, addr, addrlen),
        0
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let record = read_record();
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_socket_connected()
    );
    let accepted_idx = read_u32_le(&record, 60);
    assert_ne!(accepted_idx, u32::MAX);
    assert_eq!(read_u32_le(&record, 36), client_fd as u32);
    assert_eq!(read_u32_le(&record, 44), client_ofd);
    assert_eq!(read_u32_le(&record, 56), client_idx);
    assert_eq!(read_u64_le(&record, 64), 0);
    assert_eq!(read_u64_le(&record, 72), addrlen);
    assert_eq!(
        read_u64_le(&record, 88),
        socket_state_transition_detail(SOCK_STATE_IDLE, SOCK_STATE_CONNECTED)
    );

    supervisor_reset_shadow_log();
    let accepted_fd = socket::sys_accept4(
        &mut t.vm,
        t.base,
        listener_fd as u64,
        0,
        0,
        SOCK_NONBLOCK as u64,
    );
    assert!(accepted_fd >= 0);
    let accepted_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, accepted_fd as u64).expect("accepted OFD should exist");
    let accepted_fd_idx = fd_table::get_ofd(t.base, &t.vm, accepted_fd as u64)
        .expect("accepted OFD should exist")
        .ino;
    assert_eq!(accepted_fd_idx, accepted_idx);

    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let record = read_record();
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_socket_accepted()
    );
    assert_eq!(read_u32_le(&record, 36), accepted_fd as u32);
    assert_eq!(read_u32_le(&record, 40), listener_fd as u32);
    assert_eq!(read_u32_le(&record, 44), accepted_ofd);
    assert_eq!(read_u32_le(&record, 48), listener_ofd);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_SOCKET as u32);
    assert_eq!(read_u32_le(&record, 56), accepted_idx);
    assert_eq!(read_u32_le(&record, 60), listener_idx);
    assert_eq!(read_u64_le(&record, 64), accepted_fd as u64);
    assert_eq!(read_u64_le(&record, 72), SOCK_NONBLOCK as u64);
    assert_eq!(
        read_u64_le(&record, 80),
        socket_identity_detail(AF_UNIX, SOCK_STREAM, 0)
    );
    assert_eq!(
        read_u64_le(&record, 88),
        socket_state_transition_detail(SOCK_STATE_CONNECTED, SOCK_STATE_CONNECTED)
    );
}

#[test]
fn supervisor_fd_control_records_socket_connect_start_and_failure() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);
    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, fd as u64).expect("socket OFD should exist");
    let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
        .expect("socket OFD should exist")
        .ino;

    let sockaddr: [u8; 16] = [2, 0, 0x00, 0x50, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0];
    let addr = t.scratch + 0x500;
    t.write_mem(addr, &sockaddr);
    let read_record = || {
        let mut record = vec![0u8; supervisor_fd_control_record_bytes() as usize];
        assert_eq!(
            supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
            supervisor_fd_control_record_bytes() as i32
        );
        record
    };

    supervisor_reset_shadow_log();
    assert_eq!(
        socket::sys_connect(&mut t.vm, t.base, fd as u64, addr, 16),
        0
    );
    assert_eq!(t.vm.status, STATUS_CONNECT);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let mut supervisor_peer = [0u8; 28];
    assert_eq!(supervisor_socket_connect_fd(vm_ptr), fd as i32);
    assert_eq!(
        supervisor_socket_connect_peer_addr(
            vm_ptr,
            supervisor_peer.as_mut_ptr() as u32,
            supervisor_peer.len() as u32
        ),
        16
    );
    assert_eq!(&supervisor_peer[..16], &sockaddr);
    supervisor_peer.fill(0);
    assert_eq!(
        supervisor_socket_connect_peer_addr_for_fd(
            vm_ptr,
            fd as u32,
            supervisor_peer.as_mut_ptr() as u32,
            supervisor_peer.len() as u32
        ),
        16
    );
    assert_eq!(&supervisor_peer[..16], &sockaddr);
    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let record = read_record();
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_socket_connect_started()
    );
    assert_eq!(read_u32_le(&record, 36), fd as u32);
    assert_eq!(read_u32_le(&record, 44), ofd_id);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_SOCKET as u32);
    assert_eq!(read_u32_le(&record, 56), socket_idx);
    assert_eq!(read_u32_le(&record, 60), u32::MAX);
    assert_eq!(read_u64_le(&record, 64), 0);
    assert_eq!(read_u64_le(&record, 72), 16);
    assert_eq!(
        read_u64_le(&record, 80),
        socket_identity_detail(AF_INET, SOCK_STREAM, IPPROTO_TCP as u32)
    );
    assert_eq!(
        read_u64_le(&record, 88),
        socket_state_transition_detail(SOCK_STATE_IDLE, SOCK_STATE_CONNECTING)
    );

    supervisor_reset_shadow_log();
    socket::resume_connect_result(&mut t.vm, t.base, ECONNREFUSED);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10] as i64, ECONNREFUSED);
    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let record = read_record();
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_socket_connect_failed()
    );
    assert_eq!(read_u32_le(&record, 36), fd as u32);
    assert_eq!(read_u32_le(&record, 44), ofd_id);
    assert_eq!(read_u32_le(&record, 56), socket_idx);
    assert_eq!(read_u64_le(&record, 64) as i64, ECONNREFUSED);
    assert_eq!(
        read_u64_le(&record, 88),
        socket_state_transition_detail(SOCK_STATE_CONNECTING, SOCK_STATE_IDLE)
    );
}

#[test]
fn supervisor_socket_bridge_ofd_queries_follow_fd_table_aliases() {
    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);
    let dup_fd = t.sys_dup(fd as u64);
    assert!(dup_fd >= 0);
    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, fd as u64).expect("socket OFD should exist");
    let vm_ptr = &mut t.vm as *mut _ as u32;

    assert_eq!(supervisor_socket_ofd_is_socket(ofd_id), 1);
    assert_eq!(
        supervisor_process_socket_ofd_for_fd(vm_ptr, fd as u32),
        ofd_id
    );
    assert_eq!(
        supervisor_process_socket_ofd_for_fd(vm_ptr, dup_fd as u32),
        ofd_id
    );
    assert_eq!(
        supervisor_process_socket_drain_fd(vm_ptr, fd as u32, 0),
        fd as i32
    );
    assert_eq!(
        supervisor_process_socket_drain_fd(vm_ptr, fd as u32, 1),
        dup_fd as i32
    );
    assert_eq!(
        supervisor_process_socket_drain_fd(vm_ptr, dup_fd as u32, 0),
        dup_fd as i32
    );
    assert_eq!(
        supervisor_process_socket_drain_fd(vm_ptr, dup_fd as u32, 1),
        fd as i32
    );
    assert_eq!(
        supervisor_process_socket_drain_fd(vm_ptr, fd as u32, 2),
        ENOENT as i32
    );
}

#[test]
fn accept4_sets_requested_fd_and_status_flags() {
    let cases = [
        (0_u64, false, false),
        (SOCK_CLOEXEC as u64, true, false),
        (SOCK_NONBLOCK as u64, false, true),
        ((SOCK_CLOEXEC | SOCK_NONBLOCK) as u64, true, true),
    ];

    for (case_idx, (flags, expect_cloexec, expect_nonblock)) in cases.into_iter().enumerate() {
        let mut t = TestVm::new();
        let listener_fd =
            socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_STREAM as u64, 0);
        assert!(listener_fd >= 0);
        let client_fd =
            socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_STREAM as u64, 0);
        assert!(client_fd >= 0);

        let path = format!("/tmp/tidemark-accept4-{case_idx}\0");
        let addr = t.scratch + 0x240;
        let mut sockaddr = [0u8; 2 + 108];
        sockaddr[0..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
        sockaddr[2..2 + path.len()].copy_from_slice(path.as_bytes());
        t.write_mem(addr, &sockaddr[..2 + path.len()]);

        assert_eq!(
            socket::sys_bind(
                &mut t.vm,
                t.base,
                listener_fd as u64,
                addr,
                (2 + path.len()) as u64,
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
                (2 + path.len()) as u64,
            ),
            0
        );

        let accepted_fd = socket::sys_accept4(&mut t.vm, t.base, listener_fd as u64, 0, 0, flags);
        assert!(accepted_fd >= 0);

        let fd_flags = fd_table::sys_fcntl(&mut t.vm, t.base, accepted_fd as u64, F_GETFD, 0);
        assert_eq!(fd_flags != 0, expect_cloexec);
        let status_flags = fd_table::sys_fcntl(&mut t.vm, t.base, accepted_fd as u64, F_GETFL, 0);
        assert_eq!(status_flags & O_NONBLOCK as i64 != 0, expect_nonblock);
    }
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
