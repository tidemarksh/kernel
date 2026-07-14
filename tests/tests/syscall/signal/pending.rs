use super::support::*;

#[test]
fn pending_signal_delivery() {
    let mut t = TestVm::new();
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    signal::send_signal(&mut t.vm, abi::SIGTERM);
    assert_ne!(t.vm.sig_pending & (1u64 << (abi::SIGTERM - 1)), 0);

    let delivered = signal::check_pending(&mut t.vm, t.base);
    assert!(delivered);
    assert_eq!(t.vm.status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 128 + abi::SIGTERM);
    assert_eq!(t.vm.term_signal, abi::SIGTERM);
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        0
    );
    assert_eq!(ps.threads[0].state, THREAD_NONE);
    assert_eq!(t.vm.sig_pending & (1u64 << (abi::SIGTERM - 1)), 0);

    let mut t2 = TestVm::new();
    let caught_addr = t2.scratch + 0x100;
    let ign_addr = t2.scratch + 0x180;
    let old_addr = t2.scratch + 0x200;
    write_sigaction(t2.base, caught_addr, 0x12345, 0, 0);
    write_sigaction(t2.base, ign_addr, SIG_IGN, 0, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t2.vm, t2.base, 10, caught_addr, 0, 8),
        0
    );
    assert_eq!(
        signal::sys_rt_sigaction(&mut t2.vm, t2.base, 15, ign_addr, 0, 8),
        0
    );

    signal::reset_on_execve(42);

    assert_eq!(
        signal::sys_rt_sigaction(&mut t2.vm, t2.base, 10, 0, old_addr, 8),
        0
    );
    assert_eq!(read_sigaction(t2.base, old_addr).handler, SIG_DFL);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t2.vm, t2.base, 15, 0, old_addr, 8),
        0
    );
    assert_eq!(read_sigaction(t2.base, old_addr).handler, SIG_IGN);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t2.vm, t2.base, 2, 0, old_addr, 8),
        0
    );
    assert_eq!(read_sigaction(t2.base, old_addr).handler, SIG_DFL);
}

#[test]
fn rt_sigaction_with_invalid_current_pid_returns_esrch_instead_of_panicking() {
    let mut t = TestVm::new();
    let act_addr = t.scratch + 0x200;
    write_sigaction(t.base, act_addr, 0x12345, 0, 0);

    let pid_offset = core::mem::offset_of!(ProcessState, pid) as u64;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, t.vm.process_ptr as u64 + pid_offset, 0);
    }

    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGURG as u64, act_addr, 0, 8),
        abi::ESRCH
    );
}

#[test]
fn check_pending_with_invalid_current_pid_uses_default_disposition() {
    let mut t = TestVm::new();

    let pid_offset = core::mem::offset_of!(ProcessState, pid) as u64;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, t.vm.process_ptr as u64 + pid_offset, 0);
    }

    signal::send_signal(&mut t.vm, abi::SIGTERM);
    assert!(signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 128 + abi::SIGTERM);
    assert_eq!(t.vm.term_signal, abi::SIGTERM);
}

#[test]
fn send_signal_to_pid_queues_process_pending_signal() {
    let mut t = TestVm::new();
    let ign_addr = t.scratch + 0x100;
    write_sigaction(t.base, ign_addr, SIG_IGN, 0, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGALRM as u64, ign_addr, 0, 8),
        0
    );

    assert_eq!(
        signal::send_signal_to_pid(&mut t.vm, t.base, 42, SIGALRM),
        0
    );
    assert_eq!(t.vm.sig_pending, 0);

    let delivered = signal::check_pending(&mut t.vm, t.base);
    assert!(delivered);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.sig_pending & (1u64 << (SIGALRM - 1)), 0);
}

#[test]
fn supervisor_transport_moves_process_pending_bits_without_losing_target_bits() {
    let _t = TestVm::new();
    signal::queue_process_signal(42, SIGALRM);

    let transported = signal::take_process_pending_for_transport(42);
    assert_eq!(transported, 1u64 << (SIGALRM - 1));
    assert_eq!(signal::take_process_pending_for_transport(42), 0);

    signal::queue_process_signal(42, SIGURG);
    assert_eq!(
        signal::merge_process_pending_from_transport(42, transported),
        0
    );
    assert_eq!(
        signal::take_process_pending_for_transport(42),
        (1u64 << (SIGALRM - 1)) | (1u64 << (SIGURG - 1))
    );
}

#[test]
fn blocked_process_pending_signal_stays_process_pending_until_unblocked_thread_delivers() {
    let mut t = TestVm::new();
    let sigchld_bit = 1u64 << (SIGCHLD - 1);
    let act_addr = t.scratch + 0x100;
    let pending_addr = t.scratch + 0x180;
    write_sigaction(t.base, act_addr, 0x12345, 0, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGCHLD as u64, act_addr, 0, 8),
        0
    );

    t.vm.sig_mask = sigchld_bit;
    t.vm.pc = 0x4000;
    t.vm.x[2] = t.scratch + 0x4000;
    signal::queue_process_signal(42, SIGCHLD);

    assert!(!signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.sig_pending & sigchld_bit, 0);
    assert_eq!(signal::sys_rt_sigpending(&t.vm, t.base, pending_addr, 8), 0);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, pending_addr) } & sigchld_bit,
        sigchld_bit
    );

    t.vm.sig_mask = 0;
    assert!(signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.sig_pending & sigchld_bit, 0);
    assert_eq!(signal::sys_rt_sigpending(&t.vm, t.base, pending_addr, 8), 0);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, pending_addr) } & sigchld_bit,
        0
    );
}

#[test]
fn caught_signal_interrupts_epoll_wait_even_with_sa_restart() {
    const SA_RESTART: u64 = 0x10000000;

    let mut t = TestVm::new();
    let act_addr = t.scratch + 0x100;
    write_sigaction(t.base, act_addr, 0x12345, SA_RESTART, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGCHLD as u64, act_addr, 0, 8),
        0
    );

    signal::queue_process_signal(42, SIGCHLD);
    t.vm.status = abi::STATUS_PIPE_WAIT;
    assert!(!signal::pending_signal_interrupts_blocked_syscall(
        &t.vm, t.base
    ));

    t.vm.status = abi::STATUS_EPOLL_WAIT;
    assert!(signal::pending_signal_interrupts_blocked_syscall(
        &t.vm, t.base
    ));
}

#[test]
fn kill_sig_zero_for_current_pid_checks_without_queuing_signal() {
    let mut t = TestVm::new();
    let pid = signal::pid_from_vm(&t.vm, t.base);

    assert_eq!(signal::send_signal_to_pid(&mut t.vm, t.base, pid, 0), 0);
    assert_eq!(t.vm.sig_pending, 0);
    assert!(!signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn kill_pid_zero_targets_current_process_group() {
    let mut t = TestVm::new();
    let ign_addr = t.scratch + 0x100;
    write_sigaction(t.base, ign_addr, SIG_IGN, 0, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGALRM as u64, ign_addr, 0, 8),
        0
    );

    assert_eq!(signal::send_signal_to_pid(&mut t.vm, t.base, 0, SIGALRM), 0);
    assert_eq!(t.vm.sig_pending, 0);

    let delivered = signal::check_pending(&mut t.vm, t.base);
    assert!(delivered);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.sig_pending & (1u64 << (SIGALRM - 1)), 0);
}
