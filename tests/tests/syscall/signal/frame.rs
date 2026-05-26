use super::support::*;

#[test]
fn signal_delivery_populates_riscv_arg_home_slots() {
    let mut t = TestVm::new();
    t.vm.x[2] = 0x9fff0;

    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, 0x88_000, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGURG as u64, act_addr, 0, 8),
        0
    );

    signal::send_signal(&mut t.vm, SIGURG);
    assert!(signal::check_pending(&mut t.vm, t.base));

    let frame_base = t.vm.x[2];
    unsafe {
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, frame_base + SIGFRAME_OFF_ABI_SIGNO),
            SIGURG as u32
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(t.base, frame_base + SIGFRAME_OFF_ABI_SIGINFO_PTR),
            frame_base + SIGFRAME_OFF_SIGINFO
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(
                t.base,
                frame_base + SIGFRAME_OFF_ABI_UCONTEXT_PTR
            ),
            frame_base + SIGFRAME_OFF_UCONTEXT
        );
    }
}

#[test]
fn nested_sa_onstack_signal_keeps_current_stack() {
    let mut t = TestVm::new();
    let original_sp = 0x9fff0;
    t.vm.x[2] = original_sp;
    t.vm.sigaltstack_sp = 0x50000;
    t.vm.sigaltstack_size = 8192;
    t.vm.sigaltstack_flags = SS_ONSTACK;

    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, 0x88_000, SA_SIGINFO | SA_ONSTACK, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGURG as u64, act_addr, 0, 8),
        0
    );

    signal::send_signal(&mut t.vm, SIGURG);
    assert!(signal::check_pending(&mut t.vm, t.base));

    let expected_frame_base = (original_sp - SIGFRAME_SIZE) & !15;
    let altstack_frame_base = ((t.vm.sigaltstack_sp + t.vm.sigaltstack_size) - SIGFRAME_SIZE) & !15;
    assert_eq!(t.vm.x[2], expected_frame_base);
    assert_ne!(t.vm.x[2], altstack_frame_base);
}
