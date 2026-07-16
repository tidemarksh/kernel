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
fn supervisor_fd_control_records_socket_create_and_socketpair() {
    let mut t = TestVm::new();
    supervisor_reset_shadow_log();

    let fd = socket::sys_socket(
        &mut t.vm,
        t.base,
        AF_INET as u64,
        (SOCK_STREAM | SOCK_NONBLOCK) as u64,
        0,
    );
    assert!(fd >= 3);
    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, fd as u64).expect("socket OFD should exist");
    let socket_idx = fd_table::get_ofd(t.base, &t.vm, fd as u64)
        .expect("socket OFD should exist")
        .ino;

    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let mut record = vec![0u8; supervisor_fd_control_record_bytes() as usize];
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_socket_created()
    );
    assert_eq!(read_u32_le(&record, 36), fd as u32);
    assert_eq!(read_u32_le(&record, 44), ofd_id);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_SOCKET as u32);
    assert_eq!(read_u32_le(&record, 56), socket_idx);
    assert_eq!(read_u64_le(&record, 64), fd as u64);
    assert_eq!(read_u64_le(&record, 72), SOCK_NONBLOCK as u64);
    assert_eq!(
        read_u64_le(&record, 80),
        socket_identity_detail(AF_INET, SOCK_STREAM, IPPROTO_TCP as u32)
    );

    supervisor_reset_shadow_log();
    let sv_addr = t.scratch + 0x180;
    assert_eq!(
        socket::sys_socketpair(
            &mut t.vm,
            t.base,
            AF_UNIX as u64,
            (SOCK_DGRAM | SOCK_CLOEXEC) as u64,
            0,
            sv_addr,
        ),
        0
    );
    let left_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, sv_addr) } as u64;
    let right_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, sv_addr + 4) } as u64;
    let left_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, left_fd).expect("left socket OFD should exist");
    let right_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, right_fd).expect("right socket OFD should exist");
    let left_idx = fd_table::get_ofd(t.base, &t.vm, left_fd)
        .expect("left socket OFD should exist")
        .ino;
    let right_idx = fd_table::get_ofd(t.base, &t.vm, right_fd)
        .expect("right socket OFD should exist")
        .ino;

    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_socketpair_created()
    );
    assert_eq!(read_u32_le(&record, 36), left_fd as u32);
    assert_eq!(read_u32_le(&record, 40), right_fd as u32);
    assert_eq!(read_u32_le(&record, 44), left_ofd);
    assert_eq!(read_u32_le(&record, 48), right_ofd);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_SOCKET as u32);
    assert_eq!(read_u32_le(&record, 56), left_idx);
    assert_eq!(read_u32_le(&record, 60), right_idx);
    assert_eq!(read_u64_le(&record, 64), 0);
    assert_eq!(read_u64_le(&record, 72), SOCK_CLOEXEC as u64);
    assert_eq!(
        read_u64_le(&record, 80),
        socket_identity_detail(AF_UNIX, SOCK_DGRAM, 0)
    );
}

#[test]
fn supervisor_process_socket_query_reports_unique_held_ofds() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 3);
    let dup_fd = t.sys_dup(fd as u64);
    assert!(dup_fd >= 0);
    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, fd as u64).expect("socket OFD should exist");

    assert_eq!(supervisor_process_socket_held_ofd(vm_ptr, 0), ofd_id);
    assert_eq!(supervisor_process_socket_held_ofd(vm_ptr, 1), 0);
}

#[test]
fn supervisor_socket_bridge_active_fd_resolves_expected_ofd_alias() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 3);
    let dup_fd = t.sys_dup(fd as u64);
    assert!(dup_fd >= 0);
    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, fd as u64).expect("socket OFD should exist");

    assert_eq!(
        supervisor_socket_bridge_active_fd(vm_ptr, fd as u32, ofd_id, 0),
        fd as i32
    );

    let resolved = supervisor_socket_bridge_active_fd(vm_ptr, abi_max_fds() as u32 - 1, ofd_id, 0);
    assert!(resolved == fd as i32 || resolved == dup_fd as i32);
    assert_eq!(
        fd_table::get_ofd_id(t.base, &t.vm, resolved as u64),
        Some(ofd_id)
    );
    assert_eq!(
        supervisor_socket_bridge_active_fd(vm_ptr, fd as u32, 0, 1),
        ENOENT as i32
    );
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
fn socketpair_unix_seqpacket_preserves_packet_boundaries_and_flags() {
    let mut t = TestVm::new();
    let sv_addr = t.scratch + 0x280;
    assert_eq!(
        socket::sys_socketpair(
            &mut t.vm,
            t.base,
            AF_UNIX as u64,
            (SOCK_SEQPACKET | SOCK_CLOEXEC) as u64,
            0,
            sv_addr,
        ),
        0
    );

    let left_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, sv_addr) } as u64;
    let right_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, sv_addr + 4) } as u64;
    assert_ne!(
        fd_table::sys_fcntl(&mut t.vm, t.base, left_fd, F_GETFD, 0),
        0
    );

    let write_addr = t.scratch + 0x300;
    t.write_mem(write_addr, b"firstsecond");
    assert_eq!(
        socket::socket_write(&mut t.vm, t.base, left_fd, write_addr, 5),
        5
    );
    assert_eq!(
        socket::socket_write(&mut t.vm, t.base, left_fd, write_addr + 5, 6),
        6
    );

    let read_addr = t.scratch + 0x380;
    assert_eq!(
        socket::socket_read(&mut t.vm, t.base, right_fd, read_addr, 3),
        3
    );
    assert_eq!(
        socket::socket_read(&mut t.vm, t.base, right_fd, read_addr + 3, 8),
        6
    );
    let mut actual = [0u8; 9];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, read_addr, &mut actual);
    }
    assert_eq!(&actual, b"firsecond");

    assert_eq!(fd_table::sys_close(&mut t.vm, t.base, left_fd), 0);
    assert_eq!(
        socket::socket_read(&mut t.vm, t.base, right_fd, read_addr, 1),
        0
    );

    let replacement_fd =
        socket::sys_socket(&mut t.vm, t.base, AF_UNIX as u64, SOCK_STREAM as u64, 0);
    assert!(replacement_fd >= 0);
    assert_ne!(
        socket::debug_socket_idx_for_fd(t.base, &t.vm, replacement_fd as u64),
        socket::debug_socket_idx_for_fd(t.base, &t.vm, right_fd),
    );
    assert_eq!(
        socket::socket_read(&mut t.vm, t.base, right_fd, read_addr, 1),
        0
    );
}
