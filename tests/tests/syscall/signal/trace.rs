use super::support::*;

#[test]
fn clear_debug_trace_resets_last_signal_delivery_and_sigreturn_state() {
    let mut t = TestVm::new();
    let act_addr = t.scratch + 0x100;
    write_sigaction(t.base, act_addr, 0x12345, 0, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGURG as u64, act_addr, 0, 8),
        0
    );

    t.vm.pc = 0x4000;
    t.vm.x[1] = 0x4100;
    t.vm.x[2] = t.scratch + 0x1800;
    t.vm.x[27] = 0x4200;
    signal::send_signal(&mut t.vm, SIGURG);
    assert!(signal::check_pending(&mut t.vm, t.base));
    signal::sys_rt_sigreturn(&mut t.vm, t.base);

    assert_ne!(signal_harness::last_signal_delivery().0, 0);
    assert_ne!(signal_harness::last_sigreturn().2, 0);
    signal::queue_sigsegv(&mut t.vm, 0x7777, 0x8888, false);
    assert!(signal::check_pending(&mut t.vm, t.base));
    assert_ne!(signal_harness::last_default_signal().0, 0);

    signal_harness::clear_debug_trace();

    assert_eq!(
        signal_harness::last_signal_delivery(),
        (0, 0, 0, 0, 0, 0, 0, 0)
    );
    assert_eq!(signal_harness::last_sigreturn(), (0, 0, 0, 0, 0, 0, 0, 0));
    assert_eq!(
        signal_harness::last_default_signal(),
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    );
    assert_eq!(signal_harness::last_trampoline_hit(), (0, 0, 0));
}
