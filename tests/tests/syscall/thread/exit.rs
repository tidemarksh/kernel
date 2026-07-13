use super::support::*;
use core::sync::atomic::Ordering;

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_i32_le(bytes: &[u8], offset: usize) -> i32 {
    read_u32_le(bytes, offset) as i32
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn submit_faulted_thread_event(vm_ptr: u32, pid: u32, tid: u32, status: u32) {
    let mut event = [0u8; 80];
    write_u32_le(&mut event, 0, 0x5645_5354);
    write_u32_le(&mut event, 4, supervisor_abi_version());
    write_u32_le(&mut event, 8, supervisor_thread_event_record_bytes());
    write_u32_le(&mut event, 12, supervisor_thread_event_kind_faulted());
    write_u64_le(&mut event, 16, 1);
    write_u64_le(&mut event, 24, vm_ptr as u64);
    write_u32_le(&mut event, 32, pid);
    write_u32_le(&mut event, 36, tid);
    write_u32_le(&mut event, 40, status);
    assert_eq!(
        supervisor_submit_thread_event(event.as_ptr() as u32, event.len() as u32),
        0
    );
}

fn submit_blocked_thread_event(vm_ptr: u32, pid: u32, tid: u32, status: u32, detail: u64) {
    let mut event = [0u8; 80];
    write_u32_le(&mut event, 0, 0x5645_5354);
    write_u32_le(&mut event, 4, supervisor_abi_version());
    write_u32_le(&mut event, 8, supervisor_thread_event_record_bytes());
    write_u32_le(&mut event, 12, supervisor_thread_event_kind_blocked());
    write_u64_le(&mut event, 16, 1);
    write_u64_le(&mut event, 24, vm_ptr as u64);
    write_u32_le(&mut event, 32, pid);
    write_u32_le(&mut event, 36, tid);
    write_u32_le(&mut event, 40, status);
    write_u64_le(&mut event, 72, detail);
    assert_eq!(
        supervisor_submit_thread_event(event.as_ptr() as u32, event.len() as u32),
        0
    );
}

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
fn supervisor_exit_publication_updates_only_matching_thread_incarnation() {
    let mut t = TestVm::new();
    install_current_thread_record(&mut t);
    let exited_vm_ptr = 0x1234_5000;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, exited_vm_ptr, 0x8000, 0x9000);
    ps.thread_count.store(2, Ordering::Release);

    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    assert_eq!(
        supervisor_apply_exited_thread_publication(vm_ptr, exited_vm_ptr, 2),
        0
    );
    assert_eq!(ps.thread_count.load(Ordering::Acquire), 1);
    assert_eq!(ps.threads[1].state, THREAD_DEAD);
    assert_eq!(ps.threads[1].thread_ptr, 0);
    ps.thread_count.store(2, Ordering::Release);
    assert_eq!(
        supervisor_apply_exited_thread_publication(vm_ptr, exited_vm_ptr, 2),
        0
    );
    assert_eq!(ps.thread_count.load(Ordering::Acquire), 1);

    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0x5678_9000, 0, 0);
    ps.thread_count.store(2, Ordering::Release);
    assert_eq!(
        supervisor_apply_exited_thread_publication(vm_ptr, exited_vm_ptr, 2),
        0
    );
    assert_eq!(ps.thread_count.load(Ordering::Acquire), 2);
    assert_eq!(ps.threads[1].thread_ptr, 0x5678_9000);
}

#[test]
fn supervisor_fault_exit_decision_keeps_process_alive_with_one_remaining_thread() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);
    let current_vm_ptr = &mut t.vm as *mut ThreadState as u32;
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
    child.process_ptr = t.vm.process_ptr;
    child.status = STATUS_OK;

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, child_ptr, 0, 0);

    let status = thread_impl::sys_exit(&mut t.vm, t.base, 42);
    assert_eq!(status, STATUS_FAULT);

    let mut record = [0u8; 88];
    assert_eq!(
        supervisor_fault_exit_decision(
            current_vm_ptr,
            record.as_mut_ptr() as u32,
            record.len() as u32,
        ),
        supervisor_fault_exit_decision_bytes() as i32
    );
    assert_eq!(read_u32_le(&record, 0), 0x5846_5354);
    assert_eq!(
        read_u32_le(&record, 8),
        supervisor_fault_exit_decision_bytes()
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fault_exit_kind_thread_exit()
    );
    assert_eq!(read_u32_le(&record, 24), current_vm_ptr);
    assert_eq!(read_u32_le(&record, 28), current_vm_ptr);
    assert_eq!(read_u32_le(&record, 40), 1);
    assert_eq!(read_u32_le(&record, 44), 1);
    assert_eq!(read_i32_le(&record, 48), 42);
    assert_eq!(read_u32_le(&record, 56), STATUS_FAULT as u32);
}

#[test]
fn supervisor_fault_exit_decision_reports_process_exit_when_no_threads_remain() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);
    let current_vm_ptr = &mut t.vm as *mut ThreadState as u32;

    let status = thread_impl::sys_exit(&mut t.vm, t.base, 7);
    assert_eq!(status, STATUS_FAULT);

    let mut record = [0u8; 88];
    assert_eq!(
        supervisor_fault_exit_decision(
            current_vm_ptr,
            record.as_mut_ptr() as u32,
            record.len() as u32,
        ),
        supervisor_fault_exit_decision_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fault_exit_kind_process_exit()
    );
    assert_eq!(read_u32_le(&record, 24), current_vm_ptr);
    assert_eq!(read_u32_le(&record, 28), current_vm_ptr);
    assert_eq!(read_u32_le(&record, 40), 0);
    assert_eq!(read_u32_le(&record, 44), 0);
    assert_eq!(read_i32_le(&record, 48), 7);
}

#[test]
fn supervisor_fault_exit_decision_preserves_thread_group_exit_source() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);
    let observer_vm_ptr = &mut t.vm as *mut ThreadState as u32;
    let source_ptr = unsafe {
        tidemark_kernel::alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        )
    };
    assert_ne!(source_ptr, 0);
    let source = unsafe { &mut *(source_ptr as *mut ThreadState) };
    source.tid = 2;
    source.guest_base = t.base;
    source.process_ptr = t.vm.process_ptr;
    source.status = STATUS_OK;

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count.store(2, Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, source_ptr, 0, 0);

    assert_eq!(
        thread_impl::terminate_process(source, t.base, 139, 11),
        STATUS_FAULT,
    );

    let mut record = [0u8; 88];
    assert_eq!(
        supervisor_fault_exit_decision(
            observer_vm_ptr,
            record.as_mut_ptr() as u32,
            record.len() as u32,
        ),
        supervisor_fault_exit_decision_bytes() as i32
    );
    assert_eq!(read_u32_le(&record, 28), source_ptr);
    assert_eq!(read_u32_le(&record, 32), 2);
    assert_eq!(read_i32_le(&record, 48), 139);
    assert_eq!(read_i32_le(&record, 52), 11);
}

#[test]
fn supervisor_fault_exit_decision_reports_process_exit_when_tidless_runtime_fault_event_is_only_live_thread()
 {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);
    t.vm.status = STATUS_FAULT;
    t.vm.exit_code = 0;
    t.vm.term_signal = 0;
    let current_vm_ptr = &mut t.vm as *mut ThreadState as u32;

    submit_faulted_thread_event(current_vm_ptr, 1, 0, STATUS_FAULT as u32);

    let mut record = [0u8; 88];
    assert_eq!(
        supervisor_fault_exit_decision(
            current_vm_ptr,
            record.as_mut_ptr() as u32,
            record.len() as u32,
        ),
        supervisor_fault_exit_decision_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fault_exit_kind_process_exit()
    );
    assert_eq!(read_u32_le(&record, 24), current_vm_ptr);
    assert_eq!(read_u32_le(&record, 28), current_vm_ptr);
    assert_eq!(read_u32_le(&record, 40), 1);
    assert_eq!(read_u32_le(&record, 44), 0);
    assert_eq!(read_i32_le(&record, 48), 0);
}

#[test]
fn supervisor_fault_exit_decision_ignores_stale_blocked_event_for_faulted_thread() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);
    t.vm.status = STATUS_FAULT;
    t.vm.exit_code = 0;
    t.vm.term_signal = 0;
    let current_vm_ptr = &mut t.vm as *mut ThreadState as u32;

    let sibling_ptr = unsafe {
        tidemark_kernel::alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        )
    };
    assert_ne!(sibling_ptr, 0);
    let sibling = unsafe { &mut *(sibling_ptr as *mut ThreadState) };
    sibling.tid = 2;
    sibling.guest_base = t.base;
    sibling.process_ptr = t.vm.process_ptr;
    sibling.status = STATUS_FAULT;

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, sibling_ptr, 0, 0x37d4_c960);

    submit_blocked_thread_event(sibling_ptr, 1, 2, STATUS_FUTEX_WAIT as u32, 0x37d4_c960);

    let mut record = [0u8; 88];
    assert_eq!(
        supervisor_fault_exit_decision(
            current_vm_ptr,
            record.as_mut_ptr() as u32,
            record.len() as u32,
        ),
        supervisor_fault_exit_decision_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fault_exit_kind_process_exit()
    );
    assert_eq!(read_u32_le(&record, 40), 2);
    assert_eq!(read_u32_le(&record, 44), 0);
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
fn contract_set_tid_address_updates_supervisor_thread_record() {
    let mut t = TestVm::new();
    let clear_child_tid = t.scratch + 0x480;

    assert_eq!(
        thread_impl::sys_set_tid_address(&mut t.vm, clear_child_tid),
        t.vm.tid as i64
    );
    assert_eq!(t.vm.clear_child_tid, clear_child_tid);

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(
        ps.threads[(t.vm.tid - 1) as usize].clear_child_tid,
        clear_child_tid
    );
}

#[test]
fn contract_exit_group_clears_updated_sibling_clear_child_tid() {
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

    let stale_clear_child_tid = t.scratch + 0x500;
    let updated_clear_child_tid = t.scratch + 0x504;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, stale_clear_child_tid, child.tid as u32);
        tidemark_kernel::guest_mem::write_u32(t.base, updated_clear_child_tid, child.tid as u32);
    }

    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, child_ptr, stale_clear_child_tid, 0);

    assert_eq!(
        thread_impl::sys_set_tid_address(child, updated_clear_child_tid),
        child.tid as i64
    );
    assert_eq!(child.clear_child_tid, updated_clear_child_tid);
    assert_eq!(ps.threads[1].clear_child_tid, updated_clear_child_tid);

    let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
    assert_eq!(status, STATUS_FAULT);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, updated_clear_child_tid) },
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, stale_clear_child_tid) },
        child.tid as u32
    );
    assert_eq!(child.clear_child_tid, 0);
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
