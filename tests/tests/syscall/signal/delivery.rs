use super::support::*;

const SIGUSR1: i32 = 10;
const SUPERVISOR_SIGNAL_CONTROL_MAGIC: u32 = 0x4753_5354;

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

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
fn tgkill_caught_handler_delivery_enters_target_thread() {
    let mut t = TestVm::new();
    t.vm.tid = 1;

    let handler = 0x88_000;
    let child_start_pc = 0x77_000;
    let child_start_sp = 0x9fff0;
    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGUSR1 as u64, act_addr, 0, 8),
        0
    );

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let child_tid =
        thread_impl::sys_clone(&mut t.vm, t.base, flags, child_start_sp, 0, 0, 0) as i32;
    assert!(child_tid > 0);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let parent_pc = t.vm.pc;
    let child = unsafe { &mut *(child_ptr as *mut ThreadState) };
    child.pc = child_start_pc;
    child.x[2] = child_start_sp;
    child.sig_mask = 0;
    child.sig_pending = 0;

    assert_eq!(
        signal::send_signal_to_tid(&mut t.vm, t.base, child_tid, SIGUSR1),
        0
    );
    assert_eq!(t.vm.pc, parent_pc);
    assert_eq!(t.vm.sig_pending, 0);
    assert_eq!(child.pc, child_start_pc);
    assert_eq!(child.sig_pending, 0);

    assert!(signal::check_pending(child, t.base));
    assert_eq!(child.pc, handler);
    assert_eq!(child.x[10], SIGUSR1 as u64);

    let frame_base = child.x[2];
    let siginfo_base = frame_base + SIGFRAME_OFF_SIGINFO;
    let ucontext_base = frame_base + SIGFRAME_OFF_UCONTEXT;
    assert_eq!(child.x[11], siginfo_base);
    assert_eq!(child.x[12], ucontext_base);
    unsafe {
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, siginfo_base + SIGINFO_OFF_SIGNO),
            SIGUSR1 as u32
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, siginfo_base + SIGINFO_OFF_CODE),
            SI_TKILL as u32
        );
        assert_eq!(
            tidemark_kernel::guest_mem::read_u64(
                t.base,
                ucontext_base + UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_REGS
            ),
            child_start_pc
        );
    }

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let record = &ps.threads[(child_tid - 1) as usize];
    assert_eq!(record.pending_sigset, 0);
    assert_eq!(record.pending_siginfo_code, 0);
}

#[test]
fn supervisor_signal_control_records_delivery_boundary() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let handler = 0x91_000;
    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGUSR1 as u64, act_addr, 0, 8),
        0
    );
    t.vm.pc = 0x77_000;
    t.vm.x[2] = 0x9fff0;
    t.vm.sig_mask = 0;
    signal::send_signal(&mut t.vm, SIGUSR1);

    assert!(signal::check_pending(&mut t.vm, t.base));
    assert_eq!(t.vm.pc, handler);
    assert_eq!(supervisor_shadow_signal_control_count(), 2);

    let bytes_len = supervisor_signal_control_record_bytes() as usize;
    let mut bytes = vec![0u8; bytes_len];
    assert_eq!(
        supervisor_signal_control_record(bytes.as_mut_ptr() as u32, bytes_len as u32),
        bytes_len as i32
    );
    assert_eq!(read_u32_le(&bytes, 0), SUPERVISOR_SIGNAL_CONTROL_MAGIC);
    assert_eq!(read_u32_le(&bytes, 8), bytes_len as u32);
    assert_eq!(
        read_u32_le(&bytes, 12),
        supervisor_signal_control_kind_signal_delivered()
    );
    assert_eq!(read_u32_le(&bytes, 40), SIGUSR1 as u32);
    assert_eq!(read_u32_le(&bytes, 44), STATUS_OK as u32);
    assert_eq!(read_u32_le(&bytes, 52), 1);
    assert_ne!(read_u64_le(&bytes, 80) & (1u64 << (SIGUSR1 - 1)), 0);
    assert_eq!(read_u64_le(&bytes, 96), handler);
    assert_eq!(read_u64_le(&bytes, 104), handler);
}

#[test]
fn supervisor_signal_boundary_check_delivers_pending_signal() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let handler = 0x92_000;
    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGUSR1 as u64, act_addr, 0, 8),
        0
    );
    t.vm.pc = 0x78_000;
    t.vm.x[2] = 0x9fff0;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    signal::send_signal(&mut t.vm, SIGUSR1);
    let vm_ptr = &mut t.vm as *mut ThreadState as u32;

    assert_eq!(supervisor_signal_boundary_check(vm_ptr), 1);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, handler);
    assert_eq!(supervisor_shadow_signal_control_count(), 2);

    let bytes_len = supervisor_signal_control_record_bytes() as usize;
    let mut bytes = vec![0u8; bytes_len];
    assert_eq!(
        supervisor_signal_control_record(bytes.as_mut_ptr() as u32, bytes_len as u32),
        bytes_len as i32
    );
    assert_eq!(
        read_u32_le(&bytes, 12),
        supervisor_signal_control_kind_signal_delivered()
    );
    assert_eq!(read_u32_le(&bytes, 40), SIGUSR1 as u32);
    assert_eq!(read_u32_le(&bytes, 52), supervisor_signal_boundary_step());
}

#[test]
fn thread_step_budget_boundary_records_step_signal_boundary() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let handler = 0x93_000;
    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGUSR1 as u64, act_addr, 0, 8),
        0
    );
    t.vm.pc = 0x79_000;
    t.vm.x[2] = 0x9fff0;
    t.vm.status = STATUS_OK;
    t.vm.sig_mask = 0;
    signal::send_signal(&mut t.vm, SIGUSR1);

    assert_eq!(
        tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 0),
        0
    );
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, handler);
    assert_eq!(supervisor_shadow_signal_control_count(), 2);

    let bytes_len = supervisor_signal_control_record_bytes() as usize;
    let mut bytes = vec![0u8; bytes_len];
    assert_eq!(
        supervisor_signal_control_record(bytes.as_mut_ptr() as u32, bytes_len as u32),
        bytes_len as i32
    );
    assert_eq!(
        read_u32_le(&bytes, 12),
        supervisor_signal_control_kind_signal_delivered()
    );
    assert_eq!(read_u32_le(&bytes, 40), SIGUSR1 as u32);
    assert_eq!(read_u32_le(&bytes, 52), supervisor_signal_boundary_step());
}

#[test]
fn tgkill_caught_handler_resumes_blocked_futex_target_thread() {
    let mut t = TestVm::new();
    t.vm.tid = 1;

    let handler = 0x98_000;
    let child_start_pc = 0x78_000;
    let child_start_sp = 0x9fff0;
    let act_addr = t.scratch;
    write_sigaction(t.base, act_addr, handler, SA_SIGINFO, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGUSR1 as u64, act_addr, 0, 8),
        0
    );

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let child_tid =
        thread_impl::sys_clone(&mut t.vm, t.base, flags, child_start_sp, 0, 0, 0) as i32;
    assert!(child_tid > 0);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let futex_addr = t.scratch + 0x300;
    {
        let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
        let record = &mut ps.threads[(child_tid - 1) as usize];
        record.state = THREAD_BLOCKED_FUTEX;
        record.blocked_addr = futex_addr;
        record.thread_ptr = child_ptr;
    }

    let child = unsafe { &mut *(child_ptr as *mut ThreadState) };
    child.pc = child_start_pc;
    child.x[2] = child_start_sp;
    child.status = tidemark_kernel::abi::STATUS_FUTEX_WAIT;
    child.futex_wait_addr = futex_addr;
    child.sig_mask = 0;
    child.sig_pending = 0;

    assert_eq!(
        signal::send_signal_to_tid(&mut t.vm, t.base, child_tid, SIGUSR1),
        0
    );
    assert_eq!(child.pc, child_start_pc);
    assert_eq!(
        thread_impl::thread_record_blocked_addr(child, t.base),
        futex_addr
    );
    {
        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        let record = &ps.threads[(child_tid - 1) as usize];
        assert_ne!(record.pending_sigset & (1u64 << (SIGUSR1 - 1)), 0);
        assert_eq!(record.pending_siginfo_code, SI_TKILL);
    }

    thread_impl::resume_futex_wait(child, t.base);

    assert_eq!(child.status, STATUS_OK);
    assert_eq!(child.futex_wait_addr, 0);
    assert_eq!(child.pc, handler);
    assert_eq!(child.x[10], SIGUSR1 as u64);
    let frame_base = child.x[2];
    let siginfo_base = frame_base + SIGFRAME_OFF_SIGINFO;
    unsafe {
        assert_eq!(
            tidemark_kernel::guest_mem::read_u32(t.base, siginfo_base + SIGINFO_OFF_CODE),
            SI_TKILL as u32
        );
    }
    assert_eq!(thread_impl::thread_record_blocked_addr(child, t.base), 0);
    {
        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        let record = &ps.threads[(child_tid - 1) as usize];
        assert_eq!(record.pending_sigset, 0);
        assert_eq!(record.pending_siginfo_code, 0);
    }
}

#[test]
fn supervisor_signal_control_records_blocked_futex_signal_decision() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let futex_addr = t.scratch + 0x500;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, 7);
    }
    t.vm.tid = 1;
    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[0] = ThreadRecord::new(t.vm.tid, THREAD_RUNNING, vm_ptr, 0, 0);
        ps.thread_count
            .store(1, core::sync::atomic::Ordering::Release);
    }

    assert_eq!(
        thread_impl::sys_futex(
            &mut t.vm,
            t.base,
            futex_addr as u64,
            FUTEX_WAIT as u64,
            7,
            0,
            0,
            0,
        ),
        0
    );
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);
    t.vm.sig_mask = 1u64 << (SIGURG - 1);
    signal::send_signal(&mut t.vm, SIGURG);

    assert_eq!(supervisor_signal_pending_for_blocked_wait(vm_ptr), 1);
    assert_eq!(
        supervisor_complete_futex_wait(vm_ptr, supervisor_futex_wait_completion_signal_check()),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, EINTR);
    assert_eq!(supervisor_shadow_signal_control_count(), 1);

    let bytes_len = supervisor_signal_control_record_bytes() as usize;
    let mut bytes = vec![0u8; bytes_len];
    assert_eq!(
        supervisor_signal_control_record(bytes.as_mut_ptr() as u32, bytes_len as u32),
        bytes_len as i32
    );
    assert_eq!(read_u32_le(&bytes, 0), SUPERVISOR_SIGNAL_CONTROL_MAGIC);
    assert_eq!(
        read_u32_le(&bytes, 12),
        supervisor_signal_control_kind_blocked_wait_interrupted()
    );
    assert_eq!(read_u32_le(&bytes, 40), SIGURG as u32);
    assert_eq!(read_u32_le(&bytes, 44), STATUS_FUTEX_WAIT as u32);
    assert_eq!(read_u32_le(&bytes, 52), 2);
    assert_ne!(read_u64_le(&bytes, 56) & (1u64 << (SIGURG - 1)), 0);
    assert_eq!(read_u64_le(&bytes, 80), 0);
    assert_ne!(read_u64_le(&bytes, 88) & (1u64 << (SIGURG - 1)), 0);
    assert_eq!(
        read_u64_le(&bytes, 104),
        supervisor_futex_wait_completion_signal_check() as u64
    );
    assert_eq!(read_u64_le(&bytes, 112), futex_addr as u64);
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
