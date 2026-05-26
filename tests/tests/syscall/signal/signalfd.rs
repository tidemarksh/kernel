use super::support::*;

#[test]
fn signalfd4_reads_matching_pending_signal_and_consumes_it() {
    let mut t = TestVm::new();
    let mask_addr = t.scratch + 0x800;
    let buf_addr = t.scratch + 0x900;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, mask_addr, 1u64 << (SIGALRM - 1));
    }

    let fd = signal::sys_signalfd4(&mut t.vm, t.base, -1, mask_addr, 8, O_NONBLOCK as u64);
    assert!(fd >= 3);

    signal::send_signal_with_code(&mut t.vm, SIGALRM, SI_TKILL);
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 128),
        128
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, buf_addr) },
        SIGALRM as u32
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, buf_addr + 8) } as i32,
        SI_TKILL
    );
    assert_eq!(t.vm.sig_pending & (1u64 << (SIGALRM - 1)), 0);
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 128),
        abi::EAGAIN
    );
}

#[test]
fn signalfd4_dispatch_creates_fd_and_updates_existing_mask() {
    let mut t = TestVm::new();
    let first_mask = t.scratch + 0xa00;
    let second_mask = t.scratch + 0xa08;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, first_mask, 1u64 << (SIGALRM - 1));
        tidemark_kernel::guest_mem::write_u64(t.base, second_mask, 1u64 << (SIGURG - 1));
    }

    t.vm.x[10] = u64::MAX;
    t.vm.x[11] = first_mask;
    t.vm.x[12] = 8;
    t.vm.x[13] = O_NONBLOCK as u64;
    t.vm.x[17] = SYS_SIGNALFD4;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    let fd = t.vm.x[10] as i64;
    assert!(fd >= 3);

    t.vm.x[10] = fd as u64;
    t.vm.x[11] = second_mask;
    t.vm.x[12] = 8;
    t.vm.x[13] = 0;
    t.vm.x[17] = SYS_SIGNALFD4;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, fd);

    signal::send_signal(&mut t.vm, SIGALRM);
    let buf_addr = t.scratch + 0xa80;
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 128),
        abi::EAGAIN
    );
    signal::send_signal(&mut t.vm, SIGURG);
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 128),
        128
    );
}

#[test]
fn epoll_pwait_reports_ready_signalfd() {
    let mut t = TestVm::new();
    let mask_addr = t.scratch + 0xb00;
    let event_addr = t.scratch + 0xb20;
    let out_addr = t.scratch + 0xb40;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, mask_addr, 1u64 << (SIGALRM - 1));
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0xbeef);
    }

    let sfd = signal::sys_signalfd4(&mut t.vm, t.base, -1, mask_addr, 8, O_NONBLOCK as u64);
    assert!(sfd >= 3);
    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            sfd as u64,
            event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );

    signal::send_signal(&mut t.vm, SIGALRM);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        EPOLLIN
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0xbeef
    );
}
