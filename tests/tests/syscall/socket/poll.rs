use super::support::*;

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
fn supervisor_socket_connect_timeout_host_op_resumes_and_publishes_runnable() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let tv_addr = t.scratch + 0x940;
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
    let addr = t.scratch + 0x960;
    t.write_mem(addr, &sockaddr);
    t.vm.x[10] = fd as u64;
    t.vm.x[11] = addr;
    t.vm.x[12] = 16;
    t.vm.x[17] = SYS_CONNECT;

    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_CONNECT
    );
    assert_eq!(t.vm.status, STATUS_CONNECT);

    let mut host_op = vec![0u8; supervisor_host_op_record_bytes() as usize];
    assert_eq!(
        supervisor_next_host_op(host_op.as_mut_ptr() as u32, host_op.len() as u32),
        supervisor_host_op_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&host_op, 0), 0x4f48_5354);
    assert_eq!(read_u32_le(&host_op, 4), supervisor_abi_version());
    assert_eq!(read_u32_le(&host_op, 8), supervisor_host_op_record_bytes());
    assert_eq!(
        read_u32_le(&host_op, 12),
        supervisor_host_op_kind_arm_host_timer()
    );
    assert_eq!(
        read_u32_le(&host_op, 24),
        &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32
    );
    assert_eq!(read_u32_le(&host_op, 32), t.vm.tid as u32);
    assert_eq!(read_u32_le(&host_op, 36), t.vm.process_ptr);
    assert_eq!(read_u32_le(&host_op, 40), STATUS_CONNECT as u32);
    assert_eq!(read_u64_le(&host_op, 48), 1000);
    assert_eq!(read_u64_le(&host_op, 56), 0);

    let mut completion = [0u8; 64];
    write_u32_le(&mut completion, 0, 0x4348_5354);
    write_u32_le(&mut completion, 4, supervisor_abi_version());
    write_u32_le(&mut completion, 8, 64);
    write_u32_le(&mut completion, 12, read_u32_le(&host_op, 12));
    write_u64_le(&mut completion, 16, read_u64_le(&host_op, 16));
    write_u32_le(&mut completion, 24, read_u32_le(&host_op, 24));
    write_u32_le(&mut completion, 28, read_u32_le(&host_op, 28));
    write_u32_le(&mut completion, 32, read_u32_le(&host_op, 32));
    write_u32_le(&mut completion, 36, 1);
    write_u32_le(&mut completion, 40, 0);
    write_u64_le(&mut completion, 48, read_u64_le(&host_op, 48));
    write_u64_le(&mut completion, 56, read_u64_le(&host_op, 56));

    assert_eq!(
        supervisor_complete_host_op(completion.as_ptr() as u32, completion.len() as u32),
        STATUS_OK
    );
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10] as i64, ETIMEDOUT);
    assert_eq!(t.vm.socket_timeout_ms, -1);

    let mut resume = vec![0u8; supervisor_resume_record_bytes() as usize];
    assert_eq!(
        supervisor_next_resume(resume.as_mut_ptr() as u32, resume.len() as u32),
        supervisor_resume_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&resume, 12),
        supervisor_resume_kind_runnable_thread()
    );
    assert_eq!(
        read_u32_le(&resume, 24),
        &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32
    );
    assert_eq!(read_u32_le(&resume, 28), t.vm.tid as u32);
    assert_eq!(read_u32_le(&resume, 32), t.vm.process_ptr);
    assert_eq!(read_u32_le(&resume, 36), STATUS_OK as u32);
}

#[test]
fn pselect_readfds_reports_stale_socket_slot_as_ready() {
    const EPOLLIN: u32 = 0x001;
    const EPOLLERR: u32 = 0x008;
    const EPOLLHUP: u32 = 0x010;

    let mut t = TestVm::new();
    let fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(fd >= 0);

    let ofd = fd_table::get_ofd(t.base, &t.vm, fd as u64).expect("socket OFD should exist");
    let socket_idx = ofd.ino;
    assert!(socket::is_slot_used(socket_idx));

    socket::socket_close(socket_idx);
    assert_eq!(socket::debug_socket_state(socket_idx), ENOTSOCK as i32);

    let revents = socket::poll_revents_ofd(&ofd, EPOLLIN);
    assert_ne!(revents & EPOLLERR, 0);
    assert_ne!(revents & EPOLLHUP, 0);

    let readfds = t.scratch + 0x980;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, readfds, 1u64 << fd);
    }

    let result = tidemark_kernel::syscall::poll::sys_pselect6(
        &mut t.vm,
        t.base,
        fd as u64 + 1,
        readfds,
        0,
        0,
        0,
        0,
    );

    assert_eq!(result, 1);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, readfds) } & (1u64 << fd),
        1u64 << fd
    );
}
