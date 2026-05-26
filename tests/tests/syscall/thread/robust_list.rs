use super::*;

#[test]
fn contract_get_robust_list_reports_current_registration() {
    let mut t = TestVm::new();
    let head = t.scratch + 0x200;
    let head_ptr = t.scratch + 0x240;
    let len_ptr = t.scratch + 0x248;

    assert_eq!(thread_impl::sys_set_robust_list(&mut t.vm, head, 24), 0);
    assert_eq!(
        thread_impl::sys_get_robust_list(&t.vm, t.base, 0, head_ptr, len_ptr),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, head_ptr) },
        head
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, len_ptr) },
        24
    );
}

#[test]
fn contract_get_robust_list_reports_esrch_for_missing_tid() {
    let t = TestVm::new();
    assert_eq!(
        thread_impl::sys_get_robust_list(&t.vm, t.base, 99, t.scratch, t.scratch + 8),
        ESRCH
    );
}

#[test]
fn contract_get_robust_list_reports_eperm_for_other_live_thread() {
    let t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0x1000, 0, 0);

    assert_eq!(
        thread_impl::sys_get_robust_list(&t.vm, t.base, 2, t.scratch, t.scratch + 8),
        EPERM
    );
}

#[test]
fn contract_get_robust_list_reports_efault_for_invalid_output_ptrs() {
    let t = TestVm::new();
    assert_eq!(
        thread_impl::sys_get_robust_list(&t.vm, t.base, 0, 0, t.scratch),
        EFAULT
    );
    assert_eq!(
        thread_impl::sys_get_robust_list(&t.vm, t.base, 0, t.scratch, 0),
        EFAULT
    );
}

#[test]
fn contract_exit_marks_owned_robust_futex_owner_died_and_wakes_waiters() {
    let mut t = TestVm::new();
    let head = t.scratch + 0x600;
    let node = head + 0x40;
    let futex_addr = node + 8;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, head, node);
        tidemark_kernel::guest_mem::write_u64(t.base, head + 8, 8);
        tidemark_kernel::guest_mem::write_u64(t.base, head + 16, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, node, head);
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, FUTEX_WAITERS | t.vm.tid as u32);
    }
    t.vm.robust_list_head = head;
    t.vm.robust_list_len = 24;

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(
        2,
        THREAD_BLOCKED_FUTEX,
        0xDEAD_BEEFu32,
        0,
        futex_addr as u32,
    );
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    let status = thread_impl::sys_exit(&mut t.vm, t.base, 7);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, futex_addr) },
        FUTEX_WAITERS | FUTEX_OWNER_DIED
    );
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].blocked_addr, 0);
}

#[test]
fn contract_exit_group_cleans_up_other_thread_robust_futexes() {
    let mut t = TestVm::new();
    let head = t.scratch + 0x700;
    let node = head + 0x40;
    let futex_addr = node + 8;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, head, node);
        tidemark_kernel::guest_mem::write_u64(t.base, head + 8, 8);
        tidemark_kernel::guest_mem::write_u64(t.base, head + 16, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, node, head);
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, FUTEX_WAITERS | 2);
    }

    let child_ptr = unsafe {
        tidemark_kernel::alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        )
    };
    assert_ne!(child_ptr, 0);
    let child = unsafe { &mut *(child_ptr as *mut ThreadState) };
    child.tid = 2;
    child.process_ptr = t.vm.process_ptr;
    child.robust_list_head = head;
    child.robust_list_len = 24;

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, child_ptr, 0, 0);
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, futex_addr) },
        FUTEX_WAITERS | FUTEX_OWNER_DIED
    );
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        0
    );
    assert_eq!(ps.threads[0].state, THREAD_NONE);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}
