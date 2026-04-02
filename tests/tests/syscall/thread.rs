use tidemark_kernel::abi::*;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::thread as thread_impl;
use tidemark_kernel::types::{ProcessState, ThreadRecord, ThreadState, THREAD_BLOCKED_FUTEX, THREAD_NONE, THREAD_RUNNING};

const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;

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
fn contract_clone_thread_returns_status_clone_spawn() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    let ps_ptr = t.vm.process_ptr as u64;
    let tc_off = core::mem::offset_of!(ProcessState, thread_count) as u64;

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let child_stack = 0x80000u64;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, 0, 0);

    assert!(ret > 0);
    assert_eq!(t.vm.status, STATUS_CLONE_SPAWN);

    let tc = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, ps_ptr + tc_off) };
    assert_eq!(tc, 2);
}

#[test]
fn contract_spawn_from_clone_initializes_child_thread_state() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    t.vm.sig_mask = 0x55;
    t.vm.sig_pending = 0xAA;
    t.vm.sigaltstack_sp = 0x9000;
    t.vm.sigaltstack_size = 4096;
    t.vm.sigaltstack_flags = 1;

    let ps_ptr = t.vm.process_ptr as u64;

    let child_tidptr = t.scratch + 0x280;
    let flags = (CLONE_VM
        | CLONE_THREAD
        | CLONE_SIGHAND
        | CLONE_FS
        | CLONE_SETTLS
        | CLONE_CHILD_SETTID
        | CLONE_CHILD_CLEARTID) as u64;
    let child_stack = 0x88000u64;
    let tls = 0x1234_5000u64;

    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, tls, child_tidptr);
    assert!(ret > 0);
    assert_eq!(t.vm.clone_pending, 1);
    assert_eq!(t.vm.clone_child_tid, ret as i32);
    assert_eq!(t.vm.clone_child_stack, child_stack);
    assert_eq!(t.vm.clone_tls, tls);
    assert_eq!(t.vm.clone_child_tidptr, child_tidptr);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let child = unsafe { &*(child_ptr as *const ThreadState) };
    assert_eq!(child.tid, ret as i32);
    assert_eq!(child.x[10], 0);
    assert_eq!(child.x[2], child_stack);
    assert_eq!(child.x[4], tls);
    assert_eq!(child.tls_base, tls);
    assert_eq!(child.clear_child_tid, child_tidptr);
    assert_eq!(child.sig_mask, 0x55);
    assert_eq!(child.sig_pending, 0);
    assert_eq!(child.sigaltstack_sp, 0);
    assert_eq!(child.sigaltstack_size, 0);
    assert_eq!(child.sigaltstack_flags, 0);

    let written_tid = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, child_tidptr) };
    assert_eq!(written_tid, ret as u32);

    let threads_off = core::mem::offset_of!(ProcessState, threads) as u64;
    let record_size = core::mem::size_of::<ThreadRecord>() as u64;
    let record_off = ps_ptr + threads_off + ((ret as u64) - 1) * record_size;
    let state = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, record_off) };
    let thread_ptr = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, record_off + 8) };
    assert_eq!(state as i32, THREAD_RUNNING);
    assert_eq!(thread_ptr, child_ptr);

    assert_eq!(t.vm.clone_pending, 0);
    assert_eq!(t.vm.clone_child_tid, 0);
    assert_eq!(t.vm.clone_child_stack, 0);
    assert_eq!(t.vm.clone_tls, 0);
    assert_eq!(t.vm.clone_child_tidptr, 0);
}

#[test]
fn contract_futex_wake_unblocks_waiting_thread_record() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x500;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0xDEAD_BEEFu32, 0, addr as u32);
    ps.thread_count.store(2, core::sync::atomic::Ordering::Release);

    let ret = thread_impl::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
    assert_eq!(ret, 1);
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].blocked_addr, 0);
}

#[test]
fn contract_futex_cmp_requeue_moves_remaining_waiters() {
    let mut t = TestVm::new();
    let from_addr = t.scratch + 0x520;
    let to_addr = t.scratch + 0x524;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, from_addr, 7);
    }
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count.store(3, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0x1000, 0, from_addr as u32);
    ps.threads[2] = ThreadRecord::new(3, THREAD_BLOCKED_FUTEX, 0x2000, 0, from_addr as u32);

    let ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        from_addr,
        FUTEX_CMP_REQUEUE as u64,
        1,
        1,
        to_addr,
        7,
    );

    assert_eq!(ret, 2);
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].blocked_addr, 0);
    assert_eq!(ps.threads[2].state, THREAD_BLOCKED_FUTEX);
    assert_eq!(ps.threads[2].blocked_addr, to_addr as u32);
}

#[test]
fn contract_futex_cmp_requeue_validates_counts_and_compare_value() {
    let mut t = TestVm::new();
    let from_addr = t.scratch + 0x600;
    let to_addr = t.scratch + 0x604;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, from_addr, 11);
    }

    let invalid_wake = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        from_addr,
        FUTEX_CMP_REQUEUE as u64,
        u64::MAX,
        1,
        to_addr,
        11,
    );
    assert_eq!(invalid_wake, EINVAL);

    let invalid_requeue = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        from_addr,
        FUTEX_CMP_REQUEUE as u64,
        1,
        u64::MAX,
        to_addr,
        11,
    );
    assert_eq!(invalid_requeue, EINVAL);

    let mismatched = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        from_addr,
        FUTEX_CMP_REQUEUE as u64,
        1,
        1,
        to_addr,
        12,
    );
    assert_eq!(mismatched, EAGAIN);
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
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0xDEAD_BEEFu32, 0, futex_addr as u32);
    ps.thread_count.store(2, core::sync::atomic::Ordering::Release);

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
    ps.thread_count.store(2, core::sync::atomic::Ordering::Release);

    let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, futex_addr) },
        FUTEX_WAITERS | FUTEX_OWNER_DIED
    );
    assert_eq!(ps.thread_count.load(core::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(ps.threads[0].state, THREAD_NONE);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}

#[test]
fn contract_exit_group_marks_process_dead() {
    let mut t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count.store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xCAFE_BABEu32, 0, 0);

    let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(t.vm.exit_code, 9);
    assert_eq!(ps.thread_count.load(core::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(ps.threads[0].state, THREAD_NONE);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}

#[test]
fn contract_init_main_thread_records_running_slot() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    thread_impl::init_main_thread(vm_ptr, t.base);

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps.thread_count.load(core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(ps.threads[0].tid, 1);
    assert_eq!(ps.threads[0].state, THREAD_RUNNING);
    assert_eq!(ps.threads[0].thread_ptr, vm_ptr);
}

#[test]
fn contract_discard_exec_ignores_invalid_stale_slots() {
    let mut t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count.store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(0, THREAD_RUNNING, 0, 0x6e69_622f, 0);

    let discarded = thread_impl::discard_other_threads_for_exec(&t.vm, t.base);
    assert_eq!(discarded, 1);
    assert_eq!(ps.thread_count.load(core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}
