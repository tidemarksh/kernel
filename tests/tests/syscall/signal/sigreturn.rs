use super::support::*;

#[test]
fn rt_sigreturn_dispatch_preserves_restored_registers() {
    let mut t = TestVm::new();

    let original_pc = 0x1234_5000;
    let original_ra = 0xdead_beef;
    let original_sp = 0x9fff0;
    let original_a0 = 0x1122_3344_5566_7788;
    let original_a1 = 0x2233_4455_6677_8899;
    let original_a2 = 0x3344_5566_7788_99aa;
    let original_a7 = 0x4455_6677_8899_aabb;
    let original_sig_mask = 1u64 << (SIGALRM - 1);

    t.vm.pc = original_pc;
    t.vm.x[1] = original_ra;
    t.vm.x[2] = original_sp;
    t.vm.x[10] = original_a0;
    t.vm.x[11] = original_a1;
    t.vm.x[12] = original_a2;
    t.vm.x[17] = original_a7;
    t.vm.sig_mask = original_sig_mask;

    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, 0x88_000, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGURG as u64, act_addr, 0, 8),
        0
    );

    signal::send_signal(&mut t.vm, SIGURG);
    assert!(signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.pc, 0x88_000);
    assert_ne!(t.vm.x[2], original_sp);

    t.vm.x[17] = SYS_RT_SIGRETURN;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_OK);
    assert_eq!(t.vm.pc, original_pc);
    assert_eq!(t.vm.x[1], original_ra);
    assert_eq!(t.vm.x[2], original_sp);
    assert_eq!(t.vm.x[10], original_a0);
    assert_eq!(t.vm.x[11], original_a1);
    assert_eq!(t.vm.x[12], original_a2);
    assert_eq!(t.vm.x[17], original_a7);
    assert_eq!(t.vm.sig_mask, original_sig_mask);
}

#[test]
fn signal_trampoline_step_restores_context_without_executable_stack() {
    let mut t = TestVm::new();

    let original_pc = 0x1234_5000;
    let original_ra = 0xdead_beef;
    let original_sp = 0x9fff0;
    let original_a0 = 0x1122_3344_5566_7788;
    let original_sig_mask = 1u64 << (SIGALRM - 1);

    t.vm.pc = original_pc;
    t.vm.x[1] = original_ra;
    t.vm.x[2] = original_sp;
    t.vm.x[10] = original_a0;
    t.vm.sig_mask = original_sig_mask;

    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, 0x88_000, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGURG as u64, act_addr, 0, 8),
        0
    );

    signal::send_signal(&mut t.vm, SIGURG);
    assert!(signal::check_pending(&mut t.vm, t.base));

    let trampoline_pc = t.vm.x[1];
    let frame_base = t.vm.x[2];
    assert_eq!(trampoline_pc, frame_base + SIGFRAME_OFF_TRAMPOLINE);

    // Simulate a handler that immediately returns with `ret`.
    t.vm.pc = trampoline_pc;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 1);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, original_pc);
    assert_eq!(t.vm.x[1], original_ra);
    assert_eq!(t.vm.x[2], original_sp);
    assert_eq!(t.vm.x[10], original_a0);
    assert_eq!(t.vm.sig_mask, original_sig_mask);
}

#[test]
fn patch_current_signal_frame_a0_updates_rt_sigreturn_result() {
    let mut t = TestVm::new();

    t.vm.pc = 0x1234_5000;
    t.vm.x[1] = 0xdead_beef;
    t.vm.x[2] = 0x9fff0;
    t.vm.x[10] = 5;

    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, 0x88_000, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGURG as u64, act_addr, 0, 8),
        0
    );

    signal::send_signal(&mut t.vm, SIGURG);
    assert!(signal::check_pending(&mut t.vm, t.base));
    assert!(signal::patch_current_signal_frame_a0(&t.vm, t.base, EINTR));

    t.vm.x[17] = SYS_RT_SIGRETURN;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_OK);
    assert_eq!(t.vm.x[10], EINTR as u64);
}
