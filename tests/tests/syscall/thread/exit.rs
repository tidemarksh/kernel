use super::support::*;

#[test]
fn contract_exit_decrements_thread_count() {
    let mut t = TestVm::new();
    let ps_ptr = t.vm.process_ptr as u64;
    let tc_off = core::mem::offset_of!(ProcessState, thread_count) as u64;
    unsafe { tidemark_kernel::guest_mem::write_u32(t.base, ps_ptr + tc_off, 2) };

    let status = thread_impl::sys_exit(&mut t.vm, t.base, 42);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 42);

    let tc = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, ps_ptr + tc_off) };
    assert_eq!(tc, 1);
}

#[test]
fn contract_exit_group_marks_process_dead() {
    let mut t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xCAFE_BABEu32, 0, 0);

    let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 9);
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        0
    );
    assert_eq!(ps.threads[0].state, THREAD_NONE);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}

#[test]
fn contract_exit_group_terminates_sibling_thread_state_and_blocks_future_steps() {
    let mut t = TestVm::new();
    let child_ptr = unsafe {
        tidemark_kernel::alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        )
    };
    assert_ne!(child_ptr, 0);
    let child = unsafe { &mut *(child_ptr as *mut ThreadState) };
    child.tid = 2;
    child.guest_base = t.base;
    child.guest_memory_policy_limit = t.vm.guest_memory_policy_limit;
    child.process_ptr = t.vm.process_ptr;
    child.pc = t.vm.pc;
    child.x[2] = t.vm.x[2];

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, child_ptr, 0, 0);

    let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(child.exit_code, 9);
    assert_eq!(child.term_signal, 0);
    assert_eq!(child.status, STATUS_FAULT);

    let remaining = tidemark_kernel::abi::thread_step(child_ptr, 1);
    assert_eq!(remaining, 1);
    assert_eq!(child.status, STATUS_FAULT);
    assert_eq!(child.exit_code, 9);
    assert_eq!(child.term_signal, 0);
}

#[test]
fn contract_init_main_thread_records_running_slot() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    thread_impl::init_main_thread(vm_ptr, t.base);

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(ps.threads[0].tid, 1);
    assert_eq!(ps.threads[0].state, THREAD_RUNNING);
    assert_eq!(ps.threads[0].thread_ptr, vm_ptr);
}

#[test]
fn contract_discard_exec_ignores_invalid_stale_slots() {
    let t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(0, THREAD_RUNNING, 0, 0x6e69_622f, 0);

    let discarded = thread_impl::discard_other_threads_for_exec(&t.vm, t.base);
    assert_eq!(discarded, 1);
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}

#[test]
fn contract_discard_exec_ignores_stale_thread_state_from_other_process() {
    let t = TestVm::new();
    let stale_ptr = unsafe {
        tidemark_kernel::alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        )
    };
    assert_ne!(stale_ptr, 0);
    let stale = unsafe { &mut *(stale_ptr as *mut ThreadState) };
    stale.tid = 2;
    stale.guest_base = t.base;
    stale.process_ptr = t.vm.process_ptr + 0x1000;
    stale.blocked_ofd_id = 17;

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, stale_ptr, 0x4000, 0);

    let discarded = thread_impl::discard_other_threads_for_exec(&t.vm, t.base);
    assert_eq!(discarded, 1);
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(ps.threads[1].state, THREAD_NONE);
    assert_eq!(stale.blocked_ofd_id, 17);
}
