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

#[test]
fn synchronous_sigill_frame_records_siginfo_and_ucontext_pc() {
    const ILL_ILLOPC: u32 = 1;

    let mut t = TestVm::new();
    let code_addr = t.sys_mmap(
        0,
        4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
        abi::MAP_ANONYMOUS | abi::MAP_PRIVATE,
        -1,
        0,
    ) as u64;
    assert!(code_addr > 0);

    let handler = code_addr + 0x100;
    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, abi::SIGILL as u64, act_addr, 0, 8),
        0
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr, 0x0000_007f);
    }
    t.vm.pc = code_addr;
    t.vm.x[1] = 0x1234_5678;
    t.vm.x[2] = code_addr + 0x1000;
    t.vm.x[10] = 0xaaaa_bbbb_cccc_dddd;
    t.vm.x[11] = 0xbbbb_cccc_dddd_eeee;
    t.vm.x[12] = 0xcccc_dddd_eeee_ffff;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 1);

    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, handler);

    let frame_base = t.vm.x[2];
    let siginfo_base = frame_base + SIGFRAME_OFF_SIGINFO;
    let ucontext_base = frame_base + SIGFRAME_OFF_UCONTEXT;
    let regs_base = ucontext_base + UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_REGS;

    assert_eq!(t.vm.x[10], abi::SIGILL as u64);
    assert_eq!(t.vm.x[11], siginfo_base);
    assert_eq!(t.vm.x[12], ucontext_base);

    unsafe {
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, siginfo_base + SIGINFO_OFF_SIGNO),
            abi::SIGILL as u32
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, siginfo_base + SIGINFO_OFF_ERRNO),
            0
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, siginfo_base + SIGINFO_OFF_CODE),
            ILL_ILLOPC
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(t.base, siginfo_base + SIGINFO_OFF_ADDR),
            code_addr
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(t.base, regs_base),
            code_addr
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(t.base, regs_base + 8),
            0x1234_5678
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(t.base, regs_base + 10 * 8),
            0xaaaa_bbbb_cccc_dddd
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(t.base, regs_base + 11 * 8),
            0xbbbb_cccc_dddd_eeee
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(t.base, regs_base + 12 * 8),
            0xcccc_dddd_eeee_ffff
        );
    }
}
