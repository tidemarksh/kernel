pub(super) use tidemark_kernel::abi::{
    self, CLONE_FS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VM, EINTR, O_NONBLOCK, SIGABRT, SIGALRM,
    SIGCHLD, SIGURG, STATUS_FAULT, STATUS_OK, SYS_RT_SIGRETURN, SYS_SIGNALFD4, SYS_TGKILL,
};
pub(super) use tidemark_kernel::harness::TestVm;
pub(super) use tidemark_kernel::harness::signal as signal_harness;
pub(super) use tidemark_kernel::syscall::epoll;
pub(super) use tidemark_kernel::syscall::signal;
pub(super) use tidemark_kernel::syscall::thread as thread_impl;
pub(super) use tidemark_kernel::types::{
    ProcessState, SIG_DFL, SIG_IGN, SigAction, THREAD_BLOCKED_FUTEX, THREAD_DEAD, THREAD_NONE,
    ThreadState,
};

pub(super) const SA_SIGINFO: u64 = 0x00000004;
pub(super) const SA_ONSTACK: u64 = 0x08000000;
pub(super) const SS_ONSTACK: i32 = 1;
pub(super) const SI_TKILL: i32 = -6;
pub(super) const SIGFRAME_SIZE: u64 = 1136;
pub(super) const SIGFRAME_OFF_TRAMPOLINE: u64 = SIGFRAME_SIZE - 8;
pub(super) const SIGFRAME_OFF_ABI_SIGNO: u64 = 8;
pub(super) const SIGFRAME_OFF_ABI_SIGINFO_PTR: u64 = 16;
pub(super) const SIGFRAME_OFF_ABI_UCONTEXT_PTR: u64 = 24;
pub(super) const SIGFRAME_OFF_SIGINFO: u64 = 32;
pub(super) const SIGFRAME_OFF_UCONTEXT: u64 = 160;
pub(super) const EPOLL_CTL_ADD: u64 = 1;
pub(super) const EPOLLIN: u32 = 0x001;

pub(super) fn write_sigaction(base: u32, addr: u64, handler: u64, flags: u64, mask: u64) {
    unsafe {
        tidemark_kernel::guest_mem::write_u64(base, addr, handler);
        tidemark_kernel::guest_mem::write_u64(base, addr + 8, flags);
        tidemark_kernel::guest_mem::write_u64(base, addr + 16, mask);
    }
}

pub(super) fn read_sigaction(base: u32, addr: u64) -> SigAction {
    SigAction {
        handler: unsafe { tidemark_kernel::guest_mem::read_u64(base, addr) },
        flags: unsafe { tidemark_kernel::guest_mem::read_u64(base, addr + 8) },
        mask: unsafe { tidemark_kernel::guest_mem::read_u64(base, addr + 16) },
    }
}
