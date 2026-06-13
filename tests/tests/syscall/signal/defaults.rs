use super::support::*;

#[test]
fn synchronous_sigsegv_ignores_signal_mask() {
    let mut t = TestVm::new();
    let handler = 0x88_000;
    let act_addr = t.scratch;
    t.vm.x[2] = 0x9fff0;

    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, abi::SIGSEGV as u64, act_addr, 0, 8),
        0
    );

    t.vm.sig_mask = 1u64 << (abi::SIGSEGV - 1);
    signal::queue_sigsegv(&mut t.vm, 0x1234, 0x5678, false);

    assert!(signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.pc, handler);
    assert_eq!(t.vm.fault_pc, 0x1234);
    assert_eq!(t.vm.fault_addr, 0x5678);
    assert_eq!(t.vm.sig_pending & (1u64 << (abi::SIGSEGV - 1)), 0);
}

#[test]
fn synchronous_sigsegv_handler_entry_preserves_s11() {
    let mut t = TestVm::new();
    let handler = 0x88_000;
    let act_addr = t.scratch;
    t.vm.pc = 0x1234;
    t.vm.x[1] = 0x4567;
    t.vm.x[2] = 0x9fff0;
    t.vm.x[27] = 0x7788_9900;

    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, abi::SIGSEGV as u64, act_addr, 0, 8),
        0
    );

    let orig_s11 = t.vm.x[27];
    signal::queue_sigsegv(&mut t.vm, 0x1234, 0x5678, false);

    assert!(signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.pc, handler);
    assert_eq!(t.vm.x[27], orig_s11);
    assert_eq!(signal_harness::last_signal_delivery().7, orig_s11);
}

#[test]
fn synchronous_sigsegv_handler_entry_passes_signal_arguments() {
    let mut t = TestVm::new();
    let handler = 0x88_000;
    let act_addr = t.scratch;
    t.vm.pc = 0x1234;
    t.vm.x[1] = 0x4567;
    t.vm.x[2] = 0x9fff0;

    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, abi::SIGSEGV as u64, act_addr, 0, 8),
        0
    );

    signal::queue_sigsegv(&mut t.vm, 0x1234, 0x5678, false);

    assert!(signal::check_pending(&mut t.vm, t.base));
    let frame_base = t.vm.x[2];
    assert_eq!(t.vm.pc, handler);
    assert_eq!(t.vm.x[10], abi::SIGSEGV as u64);
    assert_eq!(t.vm.x[11], frame_base + SIGFRAME_OFF_SIGINFO);
    assert_eq!(t.vm.x[12], frame_base + SIGFRAME_OFF_UCONTEXT);
    assert_eq!(
        unsafe {
            tidemark_kernel::guest_mem::read_u32(t.base, frame_base + SIGFRAME_OFF_SIGINFO + 0)
        },
        abi::SIGSEGV as u32
    );
}

#[test]
fn synchronous_sigsegv_with_handler_and_empty_stack_terminates_instead_of_panicking() {
    let mut t = TestVm::new();
    let handler = 0x88_000;
    let act_addr = t.scratch;
    t.vm.pc = 0x1234;
    t.vm.x[2] = 0;

    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, abi::SIGSEGV as u64, act_addr, 0, 8),
        0
    );

    signal::queue_sigsegv(&mut t.vm, 0x1234, 0x5678, false);

    assert!(signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 128 + abi::SIGSEGV);
    assert_eq!(t.vm.term_signal, abi::SIGSEGV);
}

#[test]
fn synchronous_sigsegv_default_action_records_pre_terminate_fault_state() {
    let mut t = TestVm::new();
    t.vm.pc = 0x1234;
    t.vm.x[1] = 0x4567;
    t.vm.x[2] = 0x89ab;
    t.vm.x[3] = 0xcdef;
    t.vm.x[4] = 0x2468;
    t.vm.x[27] = 0x1357;

    signal::queue_sigsegv(&mut t.vm, 0xdead_beef, 0xcafe_babe, false);

    assert!(signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.status, STATUS_FAULT);
    assert_eq!(
        signal_harness::last_default_signal(),
        (
            abi::SIGSEGV as u32,
            1,
            0x1234,
            0x4567,
            0x89ab,
            0xcdef,
            0x2468,
            0x1357,
            0xdead_beef,
            0xcafe_babe,
        )
    );
}

#[test]
fn thread_step_sync_fault_handler_entry_preserves_s11() {
    let mut t = TestVm::new();
    let handler = 0x88_000;
    let act_addr = t.scratch;
    t.vm.pc = 0x2;
    t.vm.x[1] = 0x4567;
    t.vm.x[2] = 0x9fff0;
    t.vm.x[27] = 0x7788_9900;

    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, abi::SIGSEGV as u64, act_addr, 0, 8),
        0
    );

    let orig_s11 = t.vm.x[27];
    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 1);

    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, handler);
    assert_eq!(t.vm.x[27], orig_s11);
    assert_eq!(signal_harness::last_signal_delivery().2, 0x2);
    assert_eq!(signal_harness::last_signal_delivery().7, orig_s11);
}

#[test]
fn thread_step_caught_sigill_enters_handler_without_advancing_pc() {
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
    t.vm.x[2] = code_addr + 0x1000;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 0;

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 1);

    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, handler);
    assert_eq!(t.vm.x[10], abi::SIGILL as u64);
}
