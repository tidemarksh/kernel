use tidemark_kernel::abi::{
    self, CLONE_FS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VM, EINTR, SIGABRT, SIGALRM, SIGURG,
    STATUS_FAULT, STATUS_OK, SYS_RT_SIGRETURN, SYS_TGKILL,
};
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::signal;
use tidemark_kernel::syscall::thread as thread_impl;
use tidemark_kernel::types::{ProcessState, SIG_DFL, SIG_IGN, SigAction, THREAD_NONE, ThreadState};

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

    let child = unsafe { &*(child_ptr as *const ThreadState) };
    assert_ne!(child.sig_pending & (1u64 << (SIGURG - 1)), 0);
    assert_eq!(child.sig_info_code, SI_TKILL);
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

    let remaining =
        tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 1);
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
