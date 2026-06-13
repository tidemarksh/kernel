use super::support::*;

#[test]
fn send_signal_to_tid_targets_requested_thread() {
    let mut t = TestVm::new();
    t.vm.tid = 1;

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0x88000, 0, 0, 0) as i32;
    assert!(child_tid > 0);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    assert_eq!(
        signal::send_signal_to_tid(&mut t.vm, t.base, child_tid, SIGURG),
        0
    );
    assert_eq!(t.vm.sig_pending, 0);
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let record = &ps.threads[(child_tid - 1) as usize];
    assert_ne!(record.pending_sigset & (1u64 << (SIGURG - 1)), 0);
    assert_eq!(record.pending_siginfo_code, SI_TKILL);

    let child = unsafe { &mut *(child_ptr as *mut ThreadState) };
    assert_eq!(child.sig_pending, 0);
    assert!(signal::check_pending(child, t.base));
    assert_eq!(child.sig_pending & (1u64 << (SIGURG - 1)), 0);
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let record = &ps.threads[(child_tid - 1) as usize];
    assert_eq!(record.pending_sigset, 0);
    assert_eq!(record.pending_siginfo_code, 0);
}

#[test]
fn tgkill_masked_signal_does_not_wake_blocked_futex_thread() {
    let mut t = TestVm::new();
    t.vm.tid = 1;

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0x88000, 0, 0, 0) as i32;
    assert!(child_tid > 0);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let futex_addr = t.scratch + 0x200;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    let record = &mut ps.threads[(child_tid - 1) as usize];
    record.state = THREAD_BLOCKED_FUTEX;
    record.blocked_addr = futex_addr;
    record.thread_ptr = child_ptr;

    let child = unsafe { &mut *(child_ptr as *mut ThreadState) };
    child.sig_mask = 1u64 << (SIGURG - 1);
    child.sig_pending = 0;

    assert_eq!(
        signal::send_signal_to_tid(&mut t.vm, t.base, child_tid, SIGURG),
        0
    );

    assert_eq!(child.sig_pending, 0);
    assert_ne!(record.pending_sigset & (1u64 << (SIGURG - 1)), 0);
    assert_eq!(record.pending_siginfo_code, SI_TKILL);
    assert_eq!(
        thread_impl::thread_record_blocked_addr(child, t.base),
        futex_addr
    );
}

#[test]
fn tgkill_masked_sigsegv_respects_signal_mask() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    t.vm.sig_mask = 1u64 << (SIGSEGV - 1);
    let tid = t.vm.tid;

    assert_eq!(
        signal::send_signal_to_tid(&mut t.vm, t.base, tid, SIGSEGV),
        0
    );

    assert_eq!(t.vm.sig_info_code, SI_TKILL);
    assert_ne!(t.vm.sig_pending & (1u64 << (SIGSEGV - 1)), 0);
    assert!(!signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.term_signal, 0);
    assert_ne!(t.vm.sig_pending & (1u64 << (SIGSEGV - 1)), 0);
}

#[test]
fn tgkill_unmasked_signal_delivers_default_action_for_blocked_futex_thread() {
    let mut t = TestVm::new();
    t.vm.tid = 1;

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0x88000, 0, 0, 0) as i32;
    assert!(child_tid > 0);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let futex_addr = t.scratch + 0x200;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    let record = &mut ps.threads[(child_tid - 1) as usize];
    record.state = THREAD_BLOCKED_FUTEX;
    record.blocked_addr = futex_addr;
    record.thread_ptr = child_ptr;

    let child = unsafe { &mut *(child_ptr as *mut ThreadState) };
    child.sig_mask = 0;
    child.sig_pending = 0;

    assert_eq!(
        signal::send_signal_to_tid(&mut t.vm, t.base, child_tid, SIGABRT),
        0
    );

    assert_eq!(child.sig_pending, 0);
    assert_ne!(record.pending_sigset & (1u64 << (SIGABRT - 1)), 0);
    assert_eq!(record.pending_siginfo_code, SI_TKILL);
    assert_eq!(
        thread_impl::thread_record_blocked_addr(child, t.base),
        futex_addr
    );

    assert!(signal::check_pending(child, t.base));
    assert_eq!(child.status, STATUS_FAULT);
    assert_eq!(child.exit_code, 128 + SIGABRT);
    assert_eq!(child.term_signal, SIGABRT);
    assert_eq!(child.sig_pending & (1u64 << (SIGABRT - 1)), 0);
    assert_eq!(record.pending_sigset, 0);
    assert_eq!(record.pending_siginfo_code, 0);
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        0
    );
    assert_eq!(ps.threads[(child_tid - 1) as usize].state, THREAD_NONE);
}

#[test]
fn tgkill_self_with_default_sigabrt_stops_at_syscall_boundary() {
    let mut t = TestVm::new();
    let pid = signal::pid_from_vm(&t.vm, t.base) as u64;
    let tid = t.vm.tid as u64;

    t.vm.x[10] = pid;
    t.vm.x[11] = tid;
    t.vm.x[12] = SIGABRT as u64;
    t.vm.x[17] = SYS_TGKILL;

    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(t.vm.status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 128 + SIGABRT);
    assert_eq!(t.vm.term_signal, SIGABRT);
    assert_eq!(t.vm.x[10], 0);
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        0
    );
}

#[test]
fn tgkill_reports_linux_shaped_error_cases_for_invalid_and_defunct_threads() {
    let mut t = TestVm::new();
    let pid = signal::pid_from_vm(&t.vm, t.base) as u64;

    t.vm.x[10] = u64::MAX;
    t.vm.x[11] = t.vm.tid as u64;
    t.vm.x[12] = SIGURG as u64;
    t.vm.x[17] = SYS_TGKILL;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, tidemark_kernel::abi::EINVAL);

    t.vm.status = STATUS_OK;
    t.vm.x[10] = pid + 1;
    t.vm.x[11] = t.vm.tid as u64;
    t.vm.x[12] = SIGURG as u64;
    t.vm.x[17] = SYS_TGKILL;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, tidemark_kernel::abi::ESRCH);

    t.vm.status = STATUS_OK;
    t.vm.x[10] = pid;
    t.vm.x[11] = u64::MAX;
    t.vm.x[12] = SIGURG as u64;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, tidemark_kernel::abi::EINVAL);

    t.vm.status = STATUS_OK;
    t.vm.x[10] = pid;
    t.vm.x[11] = t.vm.tid as u64;
    t.vm.x[12] = u64::MAX;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, tidemark_kernel::abi::EINVAL);

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0x88000, 0, 0, 0) as i32;
    assert!(child_tid > 0);
    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[(child_tid - 1) as usize].state = THREAD_DEAD;

    t.vm.status = STATUS_OK;
    t.vm.x[10] = pid;
    t.vm.x[11] = child_tid as u64;
    t.vm.x[12] = SIGURG as u64;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, tidemark_kernel::abi::ESRCH);
}
