pub(super) use tidemark_kernel::abi::*;
pub(super) use tidemark_kernel::harness::TestVm;
pub(super) use tidemark_kernel::syscall::signal;
pub(super) use tidemark_kernel::syscall::thread as thread_impl;
pub(super) use tidemark_kernel::types::{
    ProcessState, THREAD_BLOCKED_FUTEX, THREAD_DEAD, THREAD_NONE, THREAD_RUNNING, ThreadRecord,
    ThreadState,
};

pub(super) const FUTEX_WAITERS: u32 = 0x8000_0000;
pub(super) const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub(super) const SS_DISABLE: i32 = 2;
pub(super) const SIGFRAME_SIZE: u64 = 1136;
pub(super) const SIGFRAME_OFF_TRAMPOLINE: u64 = SIGFRAME_SIZE - 8;
pub(super) fn write_sigaction(base: u32, addr: u64, handler: u64, flags: u64, mask: u64) {
    unsafe {
        tidemark_kernel::guest_mem::write_u64(base, addr, handler);
        tidemark_kernel::guest_mem::write_u64(base, addr + 8, flags);
        tidemark_kernel::guest_mem::write_u64(base, addr + 16, mask);
    }
}

pub(super) fn install_current_thread_record(t: &mut TestVm) {
    let vm_ptr = (&mut t.vm as *mut ThreadState) as u32;
    let tid = t.vm.tid;
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[(tid - 1) as usize] = ThreadRecord::new(tid, THREAD_RUNNING, vm_ptr, 0, 0);
        ps.thread_count
            .store(1, std::sync::atomic::Ordering::Release);
    }
}
