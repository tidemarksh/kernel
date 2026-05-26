use tidemark_kernel::abi::{
    self, CLONE_FS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VM, EINTR, O_NONBLOCK, SIGABRT, SIGALRM,
    SIGCHLD, SIGURG, STATUS_FAULT, STATUS_OK, SYS_RT_SIGRETURN, SYS_SIGNALFD4, SYS_TGKILL,
};
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::harness::signal as signal_harness;
use tidemark_kernel::syscall::epoll;
use tidemark_kernel::syscall::signal;
use tidemark_kernel::syscall::thread as thread_impl;
use tidemark_kernel::types::{
    ProcessState, SIG_DFL, SIG_IGN, SigAction, THREAD_BLOCKED_FUTEX, THREAD_DEAD, THREAD_NONE,
    ThreadState,
};

const SA_SIGINFO: u64 = 0x00000004;
const SA_ONSTACK: u64 = 0x08000000;
const SS_ONSTACK: i32 = 1;
const SI_TKILL: i32 = -6;
const SIGFRAME_SIZE: u64 = 1136;
const SIGFRAME_OFF_TRAMPOLINE: u64 = SIGFRAME_SIZE - 8;
const SIGFRAME_OFF_ABI_SIGNO: u64 = 8;
const SIGFRAME_OFF_ABI_SIGINFO_PTR: u64 = 16;
const SIGFRAME_OFF_ABI_UCONTEXT_PTR: u64 = 24;
const SIGFRAME_OFF_SIGINFO: u64 = 32;
const SIGFRAME_OFF_UCONTEXT: u64 = 160;
const EPOLL_CTL_ADD: u64 = 1;
const EPOLLIN: u32 = 0x001;

fn write_sigaction(base: u32, addr: u64, handler: u64, flags: u64, mask: u64) {
    unsafe {
        tidemark_kernel::guest_mem::write_u64(base, addr, handler);
        tidemark_kernel::guest_mem::write_u64(base, addr + 8, flags);
        tidemark_kernel::guest_mem::write_u64(base, addr + 16, mask);
    }
}

fn read_sigaction(base: u32, addr: u64) -> SigAction {
    SigAction {
        handler: unsafe { tidemark_kernel::guest_mem::read_u64(base, addr) },
        flags: unsafe { tidemark_kernel::guest_mem::read_u64(base, addr + 8) },
        mask: unsafe { tidemark_kernel::guest_mem::read_u64(base, addr + 16) },
    }
}

#[test]
fn signal_syscalls() {
    let mut t = TestVm::new();

    let set_addr = t.scratch;
    let oldset_addr = t.scratch + 0x100;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, set_addr, 1 << 9);
    }
    let ret = signal::sys_rt_sigprocmask(&mut t.vm, t.base, 0, set_addr, oldset_addr, 8);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.sig_mask & (1 << 9), 1 << 9);
    t.vm.sig_pending = 1 << 9;
    let pending_addr = t.scratch + 0x80;
    let pending_ret = signal::sys_rt_sigpending(&t.vm, t.base, pending_addr, 8);
    assert_eq!(pending_ret, 0);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, pending_addr) },
        1 << 9
    );

    let act_addr = t.scratch + 0x200;
    let oldact_addr = t.scratch + 0x300;
    write_sigaction(t.base, act_addr, 0x12345, 0, 0);
    let ret2 = signal::sys_rt_sigaction(&mut t.vm, t.base, 10, act_addr, oldact_addr, 8);
    assert_eq!(ret2, 0);

    let ss_addr = t.scratch + 0x400;
    let old_ss_addr = t.scratch + 0x500;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, ss_addr, 0x50000);
        tidemark_kernel::guest_mem::write_u32(t.base, ss_addr + 8, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, ss_addr + 16, 8192);
    }
    let ret3 = signal::sys_sigaltstack(&mut t.vm, t.base, ss_addr, old_ss_addr);
    assert_eq!(ret3, 0);
    assert_eq!(t.vm.sigaltstack_sp, 0x50000);
    assert_eq!(t.vm.sigaltstack_size, 8192);

    let old_default_addr = t.scratch + 0x540;
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, 1, 0, old_default_addr, 8),
        0
    );
    assert_eq!(read_sigaction(t.base, old_default_addr).handler, SIG_DFL);

    let act_addr2 = t.scratch + 0x600;
    let oldact_addr2 = t.scratch + 0x680;
    write_sigaction(t.base, act_addr2, 0xABCD, 0, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, 14, act_addr2, 0, 8),
        0
    );
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, 14, 0, oldact_addr2, 8),
        0
    );
    assert_eq!(read_sigaction(t.base, oldact_addr2).handler, 0xABCD);
}

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
    record.blocked_addr = futex_addr as u32;
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
        futex_addr as u32
    );
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
    record.blocked_addr = futex_addr as u32;
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
        futex_addr as u32
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
