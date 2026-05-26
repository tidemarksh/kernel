use super::support::*;

#[test]
fn contract_reset_process_lifecycle_reinitializes_thread_registry() {
    let mut t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(3, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
    ps.threads[2] = ThreadRecord::new(3, THREAD_RUNNING, 0xCAFE_BABEu32, 0, 0);

    process_impl::reset_process_lifecycle(&mut t.vm, t.base, 7, 1, 8, 7, 7, true);

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps.pid, 7);
    assert_eq!(ps.ppid, 1);
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(ps.threads[0].tid, t.vm.tid);
    assert_eq!(ps.threads[0].state, THREAD_RUNNING);
    assert_eq!(ps.threads[0].thread_ptr, &t.vm as *const _ as u32);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
    assert_eq!(ps.threads[2].state, THREAD_NONE);
}
