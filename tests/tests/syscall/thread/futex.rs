use super::support::*;

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

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_thread_event_record(
    bytes: &mut [u8; 80],
    event_kind: u32,
    sequence: u64,
    vm_ptr: u32,
    tid: u32,
    status: u32,
) {
    write_u32_le(bytes, 0, 0x5645_5354);
    write_u32_le(bytes, 4, supervisor_abi_version());
    write_u32_le(bytes, 8, supervisor_thread_event_record_bytes());
    write_u32_le(bytes, 12, event_kind);
    write_u64_le(bytes, 16, sequence);
    write_u64_le(bytes, 24, vm_ptr as u64);
    write_u32_le(bytes, 32, 0);
    write_u32_le(bytes, 36, tid);
    write_u32_le(bytes, 40, status);
}

#[test]
fn supervisor_futex_completion_resumes_only_kernel_selected_waiter() {
    let mut t = TestVm::new();
    let futex_addr = t.scratch + 0x100;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, 7);
    }
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let wait = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        futex_addr as u64,
        FUTEX_WAIT as u64,
        7,
        0,
        0,
        0,
    );
    assert_eq!(wait, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);
    assert_eq!(
        thread_impl::thread_record_blocked_addr(&t.vm, t.base),
        futex_addr as u64
    );

    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    assert_eq!(
        supervisor_complete_futex_wait(vm_ptr, supervisor_futex_wait_completion_woken()),
        STATUS_FUTEX_WAIT
    );
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);
    assert_eq!(
        thread_impl::thread_record_blocked_addr(&t.vm, t.base),
        futex_addr as u64
    );

    let wake = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        futex_addr as u64,
        FUTEX_WAKE as u64,
        1,
        0,
        0,
        0,
    );
    assert_eq!(wake, 1);
    assert_eq!(thread_impl::thread_record_blocked_addr(&t.vm, t.base), 0);

    assert_eq!(
        supervisor_complete_futex_wait(vm_ptr, supervisor_futex_wait_completion_woken()),
        STATUS_OK
    );
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], 0);
}

#[test]
fn supervisor_futex_completion_clears_stale_resolved_record_without_rewriting_result() {
    let mut t = TestVm::new();
    let futex_addr = t.scratch + 0x110;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, 7);
    }
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let wait = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        futex_addr as u64,
        FUTEX_WAIT as u64,
        7,
        0,
        0,
        0,
    );
    assert_eq!(wait, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);
    assert_eq!(
        thread_impl::thread_record_blocked_addr(&t.vm, t.base),
        futex_addr as u64
    );

    t.vm.status = STATUS_OK;
    t.vm.futex_wait_addr = 0;
    t.vm.x[10] = EAGAIN as u64;

    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    assert_eq!(
        supervisor_complete_futex_wait(vm_ptr, supervisor_futex_wait_completion_woken()),
        STATUS_OK
    );
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10] as i64, EAGAIN);
    assert_eq!(thread_impl::thread_record_blocked_addr(&t.vm, t.base), 0);
}

#[test]
fn supervisor_next_resume_publishes_kernel_selected_futex_wake() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let futex_addr = t.scratch + 0x120;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, 11);
    }
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let wait = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        futex_addr as u64,
        FUTEX_WAIT as u64,
        11,
        0,
        0,
        0,
    );
    assert_eq!(wait, 0);
    assert_eq!(supervisor_next_resume(0, 0), 0);

    let wake = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        futex_addr as u64,
        FUTEX_WAKE as u64,
        1,
        0,
        0,
        0,
    );
    assert_eq!(wake, 1);
    assert_eq!(supervisor_shadow_resume_enqueue_count(), 1);
    assert_eq!(
        supervisor_next_resume(0, 0),
        supervisor_resume_record_bytes() as i32
    );

    let mut too_small = [0u8; 47];
    assert_eq!(
        supervisor_next_resume(too_small.as_mut_ptr() as u32, too_small.len() as u32),
        ENOSPC as i32
    );

    let mut record = [0u8; 48];
    assert_eq!(
        supervisor_next_resume(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_resume_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&record, 0), 0x5255_5354);
    assert_eq!(read_u32_le(&record, 4), supervisor_abi_version());
    assert_eq!(read_u32_le(&record, 8), supervisor_resume_record_bytes());
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_resume_kind_futex_wake()
    );
    assert_eq!(read_u64_le(&record, 16), 1);
    assert_eq!(
        read_u32_le(&record, 24),
        (&mut t.vm as *mut ThreadState) as u32
    );
    assert_eq!(read_u32_le(&record, 28), t.vm.tid as u32);
    assert_eq!(read_u32_le(&record, 32), t.vm.process_ptr);
    assert_eq!(read_u32_le(&record, 36), STATUS_OK as u32);
    assert_eq!(read_u64_le(&record, 40), futex_addr as u64);
    assert_eq!(supervisor_next_resume(0, 0), 0);
}

#[test]
fn supervisor_thread_state_snapshot_reports_process_thread_states() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let vm_ptr = (&mut t.vm as *mut ThreadState) as u32;
    let blocked_addr = t.scratch + 0x180;
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0, 0, blocked_addr as u64);
        ps.threads[1].pending_sigset = 0x55aa;
        ps.threads[2] = ThreadRecord::new(3, THREAD_DEAD, 0, 0, 0);
        ps.thread_count
            .store(3, std::sync::atomic::Ordering::Release);
    }

    let snapshot_bytes = supervisor_thread_state_snapshot_bytes();
    assert_eq!(snapshot_bytes, 32 + abi_max_threads() as u32 * 32);
    assert_eq!(
        supervisor_thread_state_snapshot(0, 0, 0),
        snapshot_bytes as i32
    );

    let mut too_small = vec![0u8; snapshot_bytes as usize - 1];
    assert_eq!(
        supervisor_thread_state_snapshot(
            vm_ptr,
            too_small.as_mut_ptr() as u32,
            too_small.len() as u32
        ),
        ENOSPC as i32
    );

    let mut snapshot = vec![0u8; snapshot_bytes as usize];
    assert_eq!(
        supervisor_thread_state_snapshot(
            vm_ptr,
            snapshot.as_mut_ptr() as u32,
            snapshot.len() as u32
        ),
        snapshot_bytes as i32
    );

    assert_eq!(read_u32_le(&snapshot, 0), 0x4854_5354);
    assert_eq!(read_u32_le(&snapshot, 4), supervisor_abi_version());
    assert_eq!(read_u32_le(&snapshot, 8), snapshot_bytes);
    assert_eq!(read_u32_le(&snapshot, 12), abi_max_threads() as u32);
    assert_eq!(read_u32_le(&snapshot, 16), t.vm.process_ptr);
    assert_eq!(read_u32_le(&snapshot, 20), vm_ptr);
    assert_eq!(read_u32_le(&snapshot, 24), 32);

    let slot0 = 32;
    assert_eq!(read_u32_le(&snapshot, slot0), 1);
    assert_eq!(read_u32_le(&snapshot, slot0 + 4), THREAD_RUNNING as u32);
    assert_eq!(read_u32_le(&snapshot, slot0 + 8), vm_ptr);
    assert_eq!(read_u32_le(&snapshot, slot0 + 12), STATUS_OK as u32);
    assert_eq!(read_u64_le(&snapshot, slot0 + 16), 0);

    let slot1 = 32 + 32;
    assert_eq!(read_u32_le(&snapshot, slot1), 2);
    assert_eq!(
        read_u32_le(&snapshot, slot1 + 4),
        THREAD_BLOCKED_FUTEX as u32
    );
    assert_eq!(read_u32_le(&snapshot, slot1 + 8), 0);
    assert_eq!(read_u32_le(&snapshot, slot1 + 12), 0);
    assert_eq!(read_u64_le(&snapshot, slot1 + 16), blocked_addr as u64);
    assert_eq!(read_u64_le(&snapshot, slot1 + 24), 0x55aa);

    let slot2 = 32 + 32 * 2;
    assert_eq!(read_u32_le(&snapshot, slot2), 3);
    assert_eq!(read_u32_le(&snapshot, slot2 + 4), THREAD_DEAD as u32);
}

#[test]
fn supervisor_select_runnable_uses_kernel_thread_order_not_candidate_order() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let mut thread2: ThreadState = unsafe { std::mem::zeroed() };
    thread2.guest_base = t.base;
    thread2.process_ptr = t.vm.process_ptr;
    thread2.tid = 2;
    thread2.status = STATUS_OK;
    let thread2_ptr = (&mut thread2 as *mut ThreadState) as u32;

    let mut thread3: ThreadState = unsafe { std::mem::zeroed() };
    thread3.guest_base = t.base;
    thread3.process_ptr = t.vm.process_ptr;
    thread3.tid = 3;
    thread3.status = STATUS_OK;
    let thread3_ptr = (&mut thread3 as *mut ThreadState) as u32;

    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, thread2_ptr, 0, 0);
        ps.threads[2] = ThreadRecord::new(3, THREAD_RUNNING, thread3_ptr, 0, 0);
        ps.thread_count
            .store(3, std::sync::atomic::Ordering::Release);
    }

    let vm_ptr = (&mut t.vm as *mut ThreadState) as u32;
    let candidates = [thread3_ptr, thread2_ptr];
    let mut too_small = [0u8; 47];
    assert_eq!(
        supervisor_select_runnable(
            vm_ptr,
            candidates.as_ptr() as u32,
            candidates.len() as u32,
            too_small.as_mut_ptr() as u32,
            too_small.len() as u32,
        ),
        ENOSPC as i32
    );

    let mut selection = [0u8; 48];
    assert_eq!(
        supervisor_select_runnable(
            vm_ptr,
            candidates.as_ptr() as u32,
            candidates.len() as u32,
            selection.as_mut_ptr() as u32,
            selection.len() as u32,
        ),
        supervisor_runnable_selection_bytes() as i32
    );
    assert_eq!(read_u32_le(&selection, 0), 0x4e52_5354);
    assert_eq!(read_u32_le(&selection, 4), supervisor_abi_version());
    assert_eq!(
        read_u32_le(&selection, 8),
        supervisor_runnable_selection_bytes()
    );
    assert_eq!(read_u64_le(&selection, 16), 1);
    assert_eq!(read_u32_le(&selection, 24), thread2_ptr);
    assert_eq!(read_u32_le(&selection, 28), 2);
    assert_eq!(read_u32_le(&selection, 32), t.vm.process_ptr);
    assert_eq!(read_u32_le(&selection, 36), THREAD_RUNNING as u32);
    assert_eq!(read_u32_le(&selection, 40), STATUS_OK as u32);
    assert_eq!(read_u32_le(&selection, 44), 1);

    selection.fill(0);
    assert_eq!(
        supervisor_select_runnable(
            vm_ptr,
            candidates.as_ptr() as u32,
            candidates.len() as u32,
            selection.as_mut_ptr() as u32,
            selection.len() as u32,
        ),
        supervisor_runnable_selection_bytes() as i32
    );
    assert_eq!(read_u64_le(&selection, 16), 2);
    assert_eq!(read_u32_le(&selection, 24), thread3_ptr);
    assert_eq!(read_u32_le(&selection, 28), 3);
    assert_eq!(read_u32_le(&selection, 44), 2);

    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[1].state = THREAD_BLOCKED_FUTEX;
        ps.threads[2].state = THREAD_BLOCKED_FUTEX;
    }
    assert_eq!(
        supervisor_select_runnable(
            vm_ptr,
            candidates.as_ptr() as u32,
            candidates.len() as u32,
            selection.as_mut_ptr() as u32,
            selection.len() as u32,
        ),
        0
    );
}

#[test]
fn supervisor_select_runnable_without_runtime_candidates_uses_kernel_thread_state() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let mut thread2: ThreadState = unsafe { std::mem::zeroed() };
    thread2.guest_base = t.base;
    thread2.process_ptr = t.vm.process_ptr;
    thread2.tid = 2;
    thread2.status = STATUS_OK;
    let thread2_ptr = (&mut thread2 as *mut ThreadState) as u32;

    let mut thread3: ThreadState = unsafe { std::mem::zeroed() };
    thread3.guest_base = t.base;
    thread3.process_ptr = t.vm.process_ptr;
    thread3.tid = 3;
    thread3.status = STATUS_OK;
    let thread3_ptr = (&mut thread3 as *mut ThreadState) as u32;

    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[0].state = THREAD_BLOCKED_FUTEX;
        ps.threads[0].blocked_addr = 0x6000;
        ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, thread2_ptr, 0, 0);
        ps.threads[2] = ThreadRecord::new(3, THREAD_BLOCKED_FUTEX, thread3_ptr, 0, 0x7000);
        ps.thread_count
            .store(3, std::sync::atomic::Ordering::Release);
    }

    let vm_ptr = (&mut t.vm as *mut ThreadState) as u32;
    let mut selection = [0u8; 48];
    assert_eq!(
        supervisor_select_runnable(
            vm_ptr,
            0,
            0,
            selection.as_mut_ptr() as u32,
            selection.len() as u32,
        ),
        supervisor_runnable_selection_bytes() as i32
    );
    assert_eq!(read_u32_le(&selection, 0), 0x4e52_5354);
    assert_eq!(read_u64_le(&selection, 16), 1);
    assert_eq!(read_u32_le(&selection, 24), thread2_ptr);
    assert_eq!(read_u32_le(&selection, 28), 2);
    assert_eq!(read_u32_le(&selection, 32), t.vm.process_ptr);
    assert_eq!(read_u32_le(&selection, 36), THREAD_RUNNING as u32);
    assert_eq!(read_u32_le(&selection, 40), STATUS_OK as u32);
    assert_eq!(read_u32_le(&selection, 44), 1);

    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[1].state = THREAD_BLOCKED_FUTEX;
    }
    assert_eq!(
        supervisor_select_runnable(
            vm_ptr,
            0,
            0,
            selection.as_mut_ptr() as u32,
            selection.len() as u32,
        ),
        0
    );
}

#[test]
fn supervisor_select_runnable_honors_latest_thread_event_blocked_state() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let mut thread2: ThreadState = unsafe { std::mem::zeroed() };
    thread2.guest_base = t.base;
    thread2.process_ptr = t.vm.process_ptr;
    thread2.tid = 2;
    thread2.status = STATUS_OK;
    let thread2_ptr = (&mut thread2 as *mut ThreadState) as u32;

    let mut thread3: ThreadState = unsafe { std::mem::zeroed() };
    thread3.guest_base = t.base;
    thread3.process_ptr = t.vm.process_ptr;
    thread3.tid = 3;
    thread3.status = STATUS_OK;
    let thread3_ptr = (&mut thread3 as *mut ThreadState) as u32;

    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[0].state = THREAD_BLOCKED_FUTEX;
        ps.threads[0].blocked_addr = 0x6100;
        ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, thread2_ptr, 0, 0);
        ps.threads[2] = ThreadRecord::new(3, THREAD_RUNNING, thread3_ptr, 0, 0);
        ps.thread_count
            .store(3, std::sync::atomic::Ordering::Release);
    }

    let mut event = [0u8; 80];
    write_thread_event_record(
        &mut event,
        supervisor_thread_event_kind_blocked(),
        41,
        thread2_ptr,
        2,
        STATUS_FUTEX_WAIT as u32,
    );
    assert_eq!(
        supervisor_submit_thread_event(event.as_ptr() as u32, event.len() as u32),
        0
    );

    let vm_ptr = (&mut t.vm as *mut ThreadState) as u32;
    let mut selection = [0u8; 48];
    assert_eq!(
        supervisor_select_runnable(
            vm_ptr,
            0,
            0,
            selection.as_mut_ptr() as u32,
            selection.len() as u32,
        ),
        supervisor_runnable_selection_bytes() as i32
    );
    assert_eq!(read_u32_le(&selection, 24), thread3_ptr);
    assert_eq!(read_u32_le(&selection, 28), 3);

    event.fill(0);
    write_thread_event_record(
        &mut event,
        supervisor_thread_event_kind_ready(),
        42,
        thread2_ptr,
        2,
        STATUS_OK as u32,
    );
    assert_eq!(
        supervisor_submit_thread_event(event.as_ptr() as u32, event.len() as u32),
        0
    );

    selection.fill(0);
    assert_eq!(
        supervisor_select_runnable(
            vm_ptr,
            0,
            0,
            selection.as_mut_ptr() as u32,
            selection.len() as u32,
        ),
        supervisor_runnable_selection_bytes() as i32
    );
    assert_eq!(read_u32_le(&selection, 24), thread2_ptr);
    assert_eq!(read_u32_le(&selection, 28), 2);
    assert_eq!(supervisor_shadow_thread_event_count(), 2);
}

#[test]
fn supervisor_futex_completion_owns_timeout_result() {
    let mut t = TestVm::new();
    let futex_addr = t.scratch + 0x140;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, 9);
    }
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let wait = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        futex_addr as u64,
        FUTEX_WAIT as u64,
        9,
        0,
        0,
        0,
    );
    assert_eq!(wait, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    assert_eq!(
        supervisor_complete_futex_wait(vm_ptr, supervisor_futex_wait_completion_timed_out()),
        STATUS_OK
    );
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10] as i64, ETIMEDOUT);
    assert_eq!(thread_impl::thread_record_blocked_addr(&t.vm, t.base), 0);

    let mut resume = [0u8; 48];
    assert_eq!(
        supervisor_next_resume(resume.as_mut_ptr() as u32, resume.len() as u32),
        48
    );
    assert_eq!(read_u32_le(&resume, 0), 0x5255_5354);
    assert_eq!(read_u32_le(&resume, 24), vm_ptr);
    assert_eq!(read_u32_le(&resume, 28), t.vm.tid as u32);
    assert_eq!(read_u32_le(&resume, 32), t.vm.process_ptr);
    assert_eq!(read_u32_le(&resume, 36), STATUS_OK as u32);
}

#[test]
fn supervisor_futex_wait_timeout_publishes_arm_host_timer_host_op() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let futex_addr = t.scratch + 0x150;
    let timeout = t.scratch + 0x170;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, futex_addr, 9);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout + 8, 2_000_000);
    }
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let wait = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        futex_addr as u64,
        FUTEX_WAIT as u64,
        9,
        timeout,
        0,
        0,
    );
    assert_eq!(wait, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

    let mut record = [0u8; 64];
    assert_eq!(
        supervisor_next_host_op(record.as_mut_ptr() as u32, record.len() as u32),
        64
    );
    assert_eq!(read_u32_le(&record, 0), 0x4f48_5354);
    assert_eq!(read_u32_le(&record, 8), 64);
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_host_op_kind_arm_host_timer()
    );
    assert_eq!(
        read_u32_le(&record, 24),
        &mut t.vm as *mut ThreadState as u32
    );
    assert_eq!(read_u32_le(&record, 28), 0);
    assert_eq!(read_u32_le(&record, 32), t.vm.tid as u32);
    assert_eq!(read_u32_le(&record, 36), t.vm.process_ptr);
    assert_eq!(read_u32_le(&record, 40), STATUS_FUTEX_WAIT as u32);
    assert_eq!(read_u64_le(&record, 48), 2);
    assert_eq!(read_u64_le(&record, 56), 200_000);
    assert_eq!(supervisor_next_host_op(0, 0), 0);
}

#[test]
fn contract_futex_wait_return_path_preserves_thread_context() {
    let mut t = TestVm::new();
    let notesleep_page = t.sys_mmap(
        0x2a000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(notesleep_page, 0x2a000);
    let futexsleep_page = t.sys_mmap(
        0x4d000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futexsleep_page, 0x4d000);
    let futex_page = t.sys_mmap(
        0x83000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futex_page, 0x83000);
    let wake_check_page = t.sys_mmap(
        0xbdc000,
        0x1000,
        PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(wake_check_page, 0xbdc000);
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x2a000,
        0x2b000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x4d000,
        0x4e000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x83000,
        0x84000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );

    unsafe {
        // Synthetic caller tail around the futex wait call and loop.
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a482, 0x72a2); // ld t0,40(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a484, 0x0302_b383); // ld t2,48(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a488, 0x1003_8aa3); // sb zero,277(t2)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a48c, 0x7302); // ld t1,32(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a48e, 0x7562); // ld a0,56(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a490, 0x1405_23af); // lr.w.aq t2,(a0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a494, 0x1382); // slli t2,t2,0x20
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a496, 0x0203_d393); // srli t2,t2,0x20
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a49a, 0x0203_9963); // bnez t2,2a4cc
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a49e, 0x0302_b283); // ld t0,48(t0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4a2, 0x4385); // li t2,1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4a4, 0x1072_8aa3); // sb t2,277(t0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4a8, 0x4581); // li a1,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4aa, 0x861a); // mv a2,t1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4ac, 0x18c2_30ef); // jal futex_wait
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b0, 0x00bb_2297); // auipc t0,...
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b4, 0x6282_b283); // ld t0,1576(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b8, 0x0002_b283); // ld t0,0(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4bc, 0xfc02_83e3); // beqz t0,2a482
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c0, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c2, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c4, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c6, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c8, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4ca, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4cc, 0x6082); // ld ra,0(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4ce, 0x6145); // addi sp,sp,48
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4d0, 0x0000_8067); // ret

        // Synthetic futex wait fast path.
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d638, 0xfc11_3023); // sd ra,-64(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d63c, 0x7139); // addi sp,sp,-64
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d63e, 0xe006); // sd ra,0(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d640, 0x0006_5e63); // bgez a2,4d65c
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d644, 0x862e); // mv a2,a1
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d646, 0x4681); // li a3,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d648, 0x4701); // li a4,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d64a, 0x4781); // li a5,0
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d64c, 0x0800_0593); // li a1,128
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d650, 0x4b13_50ef); // jal futex syscall wrapper
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d654, 0x6082); // ld ra,0(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d656, 0x6121); // addi sp,sp,64
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d658, 0x0000_8067); // ret

        // Synthetic futex syscall wrapper.
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83300, 0x0620_0893); // li a7,98
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83304, 0x0000_0073); // ecall
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83308, 0x0000_8067); // ret

        // The wake-check function pointer is null, so the caller loops back.
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcad8, 0xbdcb00);
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcb00, 0);
    }
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_riscv_flush_icache(
            &mut t.vm, t.base, 0x2a000, 0x84000, 0,
        ),
        0
    );

    let futexsleep_sp = t.scratch + 0x7000;
    let notesleep_sp = futexsleep_sp + 64;
    let note_addr = t.scratch + 0x7200;
    let note_state = t.scratch + 0x7300;
    let g = t.scratch + 0x7800;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, note_addr, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, note_state + 48, g);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 32, u64::MAX);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 40, note_state);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 56, note_addr);
        tidemark_kernel::guest_mem::write_u64(t.base, futexsleep_sp, 0x2a4b0);
    }

    t.vm.tid = 3;
    t.vm.status = STATUS_OK;
    t.vm.guest_base = t.base;
    t.vm.pc = 0x83308;
    t.vm.x[1] = 0x4d654;
    t.vm.x[2] = futexsleep_sp;
    t.vm.x[27] = g;
    install_current_thread_record(&mut t);
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.thread_count
            .store(2, std::sync::atomic::Ordering::Release);
    }
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83308, 0x0000_8067);
    }
    assert!(
        tidemark_kernel::syscall::memory::guest_range_permitted(
            &t.vm, t.base, 0x83308, 4, PROT_EXEC,
        ),
        "synthetic futex return page must be executable"
    );

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 64);
    assert!(remaining >= 0);
    assert_eq!(
        t.vm.status, STATUS_FUTEX_WAIT,
        "status={} pc=0x{:x} ra=0x{:x} sp=0x{:x} exit={} fault_pc=0x{:x} fault_addr=0x{:x}",
        t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2], t.vm.exit_code, t.vm.fault_pc, t.vm.fault_addr,
    );
    assert_eq!(
        t.vm.pc, 0x83308,
        "status={} pc=0x{:x} ra=0x{:x} sp=0x{:x} exit={} fault_pc=0x{:x} fault_addr=0x{:x}",
        t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2], t.vm.exit_code, t.vm.fault_pc, t.vm.fault_addr,
    );
    assert_eq!(t.vm.x[27], g);
    assert_eq!(t.vm.x[2], futexsleep_sp);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, futexsleep_sp) },
        0x2a4b0
    );
}

#[test]
fn contract_futex_wake_return_path_preserves_thread_context() {
    let mut t = TestVm::new();
    let notesleep_page = t.sys_mmap(
        0x2a000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(notesleep_page, 0x2a000);
    let futexsleep_page = t.sys_mmap(
        0x4d000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futexsleep_page, 0x4d000);
    let futex_page = t.sys_mmap(
        0x83000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(futex_page, 0x83000);
    let wake_check_page = t.sys_mmap(
        0xbdc000,
        0x1000,
        PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(wake_check_page, 0xbdc000);
    let caller_page = t.sys_mmap(
        0x2b000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(caller_page, 0x2b000);
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x2a000,
        0x2c000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x4d000,
        0x4e000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );
    tidemark_kernel::syscall::memory::register_elf_load_segment(
        0x83000,
        0x84000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    );

    unsafe {
        // Synthetic caller tail around the futex wait call and wake check.
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a482, 0x72a2); // ld t0,40(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a484, 0x0302_b383); // ld t2,48(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a488, 0x1003_8aa3); // sb zero,277(t2)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a48c, 0x7302); // ld t1,32(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a48e, 0x7562); // ld a0,56(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a490, 0x1405_23af); // lr.w.aq t2,(a0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a494, 0x1382); // slli t2,t2,0x20
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a496, 0x0203_d393); // srli t2,t2,0x20
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a49a, 0x0203_9963); // bnez t2,2a4cc
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a49e, 0x0302_b283); // ld t0,48(t0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4a2, 0x4385); // li t2,1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4a4, 0x1072_8aa3); // sb t2,277(t0)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4a8, 0x4581); // li a1,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4aa, 0x861a); // mv a2,t1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4ac, 0x18c2_30ef); // jal futex_wait
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b0, 0x00bb_2297); // auipc t0,...
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b4, 0x6282_b283); // ld t0,1576(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4b8, 0x0002_b283); // ld t0,0(t0)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4bc, 0xfc02_83e3); // beqz t0,2a482
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c0, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c2, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c4, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c6, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4c8, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4ca, 0x0001); // c.nop
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4cc, 0x6082); // ld ra,0(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x2a4ce, 0x6145); // addi sp,sp,48
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2a4d0, 0x0000_8067); // ret

        // Synthetic futex wait fast path.
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d638, 0xfc11_3023); // sd ra,-64(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d63c, 0x7139); // addi sp,sp,-64
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d63e, 0xe006); // sd ra,0(sp)
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d640, 0x0006_5e63); // bgez a2,4d65c
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d644, 0x862e); // mv a2,a1
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d646, 0x4681); // li a3,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d648, 0x4701); // li a4,0
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d64a, 0x4781); // li a5,0
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d64c, 0x0800_0593); // li a1,128
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d650, 0x4b13_50ef); // jal futex syscall wrapper
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d654, 0x6082); // ld ra,0(sp)
        tidemark_kernel::guest_mem::write_u16(t.base, 0x4d656, 0x6121); // addi sp,sp,64
        tidemark_kernel::guest_mem::write_u32(t.base, 0x4d658, 0x0000_8067); // ret

        // Synthetic futex syscall wrapper.
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83300, 0x0620_0893); // li a7,98
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83304, 0x0000_0073); // ecall
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83308, 0x0000_8067); // ret

        // The wake-check function pointer is non-zero, so the caller exits after wake.
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcad8, 0xbdcb00);
        tidemark_kernel::guest_mem::write_u64(t.base, 0xbdcb00, 1);

        // Caller target after notesleep returns.
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2b000, 0x0010_0513); // li a0,1
        tidemark_kernel::guest_mem::write_u32(t.base, 0x2b004, 0x0000_8067); // ret
    }
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_riscv_flush_icache(
            &mut t.vm, t.base, 0x2a000, 0x84000, 0,
        ),
        0
    );

    let futexsleep_sp = t.scratch + 0x7000;
    let notesleep_sp = futexsleep_sp + 64;
    let note_addr = t.scratch + 0x7200;
    let note_state = t.scratch + 0x7300;
    let g = t.scratch + 0x7800;
    unsafe {
        // Wake condition already satisfied.
        tidemark_kernel::guest_mem::write_u32(t.base, note_addr, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, note_state + 48, g);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 32, u64::MAX);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 40, note_state);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp + 56, note_addr);
        tidemark_kernel::guest_mem::write_u64(t.base, futexsleep_sp, 0x2a4b0);
        tidemark_kernel::guest_mem::write_u64(t.base, notesleep_sp, 0x2b000);
    }

    t.vm.tid = 3;
    t.vm.status = STATUS_OK;
    t.vm.guest_base = t.base;
    t.vm.pc = 0x83308;
    t.vm.x[1] = 0x4d654;
    t.vm.x[2] = futexsleep_sp;
    t.vm.x[27] = g;
    install_current_thread_record(&mut t);
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.thread_count
            .store(2, std::sync::atomic::Ordering::Release);
        tidemark_kernel::guest_mem::write_u32(t.base, 0x83308, 0x0000_8067);
    }

    let remaining = tidemark_kernel::abi::thread_step(&mut t.vm as *mut ThreadState as u32, 64);
    assert!(remaining >= 0);
    assert_eq!(
        t.vm.status, STATUS_OK,
        "status={} pc=0x{:x} ra=0x{:x} sp=0x{:x} exit={} fault_pc=0x{:x} fault_addr=0x{:x}",
        t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2], t.vm.exit_code, t.vm.fault_pc, t.vm.fault_addr,
    );
    assert_eq!(
        t.vm.pc, 0x2b004,
        "status={} pc=0x{:x} ra=0x{:x} sp=0x{:x} exit={} fault_pc=0x{:x} fault_addr=0x{:x}",
        t.vm.status, t.vm.pc, t.vm.x[1], t.vm.x[2], t.vm.exit_code, t.vm.fault_pc, t.vm.fault_addr,
    );
    assert_eq!(t.vm.x[2], notesleep_sp + 48);
    assert_eq!(t.vm.x[27], g);
}

#[test]
fn contract_futex_wake_unblocks_waiting_thread_record() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x500;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0xDEAD_BEEFu32, 0, addr);
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    let ret = thread_impl::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
    assert_eq!(ret, 1);
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].blocked_addr, 0);
}

#[test]
fn contract_futex_wake_does_not_truncate_memory64_blocked_thread_record_address() {
    let mut t = TestVm::new();
    let low_addr = t.scratch + 0x400;
    let high_addr = low_addr + (1u64 << 32);
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, low_addr, 0);
    }
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0xDEAD_BEEFu32, 0, high_addr);
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);

    let ret = thread_impl::sys_futex(&mut t.vm, t.base, low_addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(ps.threads[1].state, THREAD_BLOCKED_FUTEX);
    assert_eq!(ps.threads[1].blocked_addr, high_addr);
}

#[test]
fn contract_futex_wake_bitset_only_wakes_matching_waiters() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x510;
    let waiter_ptr = unsafe {
        tidemark_kernel::alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        )
    };
    assert_ne!(waiter_ptr, 0);
    let waiter = unsafe { &mut *(waiter_ptr as *mut ThreadState) };
    waiter.process_ptr = t.vm.process_ptr;
    waiter.futex_wait_bitset = 0x2;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, waiter_ptr, 0, addr);

    let mismatch = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAKE_BITSET as u64,
        1,
        0,
        0,
        0x1,
    );
    assert_eq!(mismatch, 0);
    assert_eq!(ps.threads[1].state, THREAD_BLOCKED_FUTEX);
    assert_eq!(ps.threads[1].blocked_addr, addr);

    let matched = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAKE_BITSET as u64,
        1,
        0,
        0,
        0x2,
    );
    assert_eq!(matched, 1);
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].blocked_addr, 0);
}

#[test]
fn contract_futex_wait_replaces_stale_running_record_address() {
    let mut t = TestVm::new();
    let stale_addr = t.scratch + 0x510;
    let next_addr = t.scratch + 0x514;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, next_addr, 0);
    }

    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[(t.vm.tid - 1) as usize] = ThreadRecord::new(
            t.vm.tid,
            THREAD_RUNNING,
            &mut t.vm as *mut ThreadState as u32,
            0,
            stale_addr,
        );
    }

    assert_eq!(thread_impl::thread_record_blocked_addr(&t.vm, t.base), 0);

    let wait_ret =
        thread_impl::sys_futex(&mut t.vm, t.base, next_addr, FUTEX_WAIT as u64, 0, 0, 0, 0);

    assert_eq!(wait_ret, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        assert_eq!(
            ps.threads[(t.vm.tid - 1) as usize].state,
            THREAD_BLOCKED_FUTEX
        );
        assert_eq!(ps.threads[(t.vm.tid - 1) as usize].blocked_addr, next_addr);
    }
    assert_eq!(
        thread_impl::thread_record_blocked_addr(&t.vm, t.base),
        next_addr
    );
}

#[test]
fn contract_futex_bitset_rejects_zero_mask() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x514;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 3);
    }

    let wait_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAIT_BITSET as u64,
        3,
        0,
        0,
        0,
    );
    assert_eq!(wait_ret, EINVAL);

    let wake_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        FUTEX_WAKE_BITSET as u64,
        1,
        0,
        0,
        0,
    );
    assert_eq!(wake_ret, EINVAL);
}

#[test]
fn contract_futex_wait_bad_uaddr_returns_efault() {
    let mut t = TestVm::new();
    let bad_addr = 0x9;

    let wait_ret =
        thread_impl::sys_futex(&mut t.vm, t.base, bad_addr, FUTEX_WAIT as u64, 0, 0, 0, 0);
    assert_eq!(wait_ret, EFAULT);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.fault_addr, 0);

    let bitset_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        bad_addr,
        FUTEX_WAIT_BITSET as u64,
        0,
        0,
        0,
        FUTEX_BITSET_MATCH_ANY as u64,
    );
    assert_eq!(bitset_ret, EFAULT);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.fault_addr, 0);
}

#[test]
fn contract_futex_wake_bad_uaddr_returns_efault() {
    let mut t = TestVm::new();
    let bad_addr = 0x9;

    let wake_ret =
        thread_impl::sys_futex(&mut t.vm, t.base, bad_addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
    assert_eq!(wake_ret, EFAULT);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.fault_addr, 0);

    let bitset_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        bad_addr,
        FUTEX_WAKE_BITSET as u64,
        1,
        0,
        0,
        FUTEX_BITSET_MATCH_ANY as u64,
    );
    assert_eq!(bitset_ret, EFAULT);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.fault_addr, 0);
}

#[test]
fn contract_futex_wait_bitset_captures_realtime_flag_and_clears_on_resume() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x518;
    let timeout = t.scratch + 0x540;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 3);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout + 8, 0);
    }

    let wait_ret = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        addr,
        (FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME) as u64,
        3,
        timeout,
        0,
        FUTEX_BITSET_MATCH_ANY as u64,
    );
    assert_eq!(wait_ret, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);
    assert_eq!(t.vm.futex_wait_timeout, timeout);
    assert_eq!(t.vm.futex_wait_absolute, 1);
    assert_eq!(t.vm.futex_wait_flags, FUTEX_CLOCK_REALTIME);

    thread_impl::resume_futex_wait_result(&mut t.vm, t.base, ETIMEDOUT);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.futex_wait_timeout, 0);
    assert_eq!(t.vm.futex_wait_absolute, 0);
    assert_eq!(t.vm.futex_wait_flags, 0);
    assert_eq!(t.vm.x[10] as i64, ETIMEDOUT);
}

#[test]
fn contract_resume_timed_futex_wait_without_pending_signal_preserves_context() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x580;
    let timeout = t.scratch + 0x5a0;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 7);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout + 8, 0);
    }

    let wait_ret =
        thread_impl::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAIT as u64, 7, timeout, 0, 0);
    assert_eq!(wait_ret, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

    t.vm.pc = 0x4455_6677;
    t.vm.x[1] = 0x5566_7788;
    t.vm.x[2] = t.scratch + 0x1800;
    t.vm.x[27] = 0x7788_9900;
    t.vm.sig_pending = 0;
    t.vm.sig_info_code = 0;

    let record = unsafe {
        &mut (*((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState)).threads
            [(t.vm.tid - 1) as usize]
    };
    record.state = THREAD_BLOCKED_FUTEX;
    record.blocked_addr = addr;

    thread_impl::resume_futex_wait_result(&mut t.vm, t.base, ETIMEDOUT);

    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.futex_wait_addr, 0);
    assert_eq!(t.vm.futex_wait_timeout, 0);
    assert_eq!(t.vm.futex_wait_expected, 0);
    assert_eq!(t.vm.futex_wait_bitset, 0);
    assert_eq!(t.vm.futex_wait_absolute, 0);
    assert_eq!(t.vm.futex_wait_flags, 0);
    assert_eq!(t.vm.x[10] as i64, ETIMEDOUT);
    assert_eq!(t.vm.pc, 0x4455_6677);
    assert_eq!(t.vm.x[1], 0x5566_7788);
    assert_eq!(t.vm.x[2], t.scratch + 0x1800);
    assert_eq!(t.vm.x[27], 0x7788_9900);
    assert_eq!(t.vm.sig_pending, 0);
    assert_eq!(t.vm.sig_info_code, 0);
    assert_eq!(record.state, THREAD_RUNNING);
    assert_eq!(record.blocked_addr, 0);
}

#[test]
fn contract_resume_timed_futex_wait_delivers_pending_signal_and_restores_timeout_result() {
    let mut t = TestVm::new();
    let addr = t.scratch + 0x5c0;
    let timeout = t.scratch + 0x5e0;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, addr, 9);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, timeout + 8, 0);
    }

    let wait_ret =
        thread_impl::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAIT as u64, 9, timeout, 0, 0);
    assert_eq!(wait_ret, 0);
    assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

    let handler = 0x12345;
    let act_addr = t.scratch + 0x640;
    write_sigaction(t.base, act_addr, handler, 0, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGURG as u64, act_addr, 0, 8),
        0
    );

    t.vm.pc = 0x4455_6677;
    t.vm.x[1] = 0x5566_7788;
    t.vm.x[2] = t.scratch + 0x2000;
    t.vm.x[27] = 0x7788_9900;
    t.vm.sig_mask = 0;
    t.vm.sig_pending = 1u64 << (SIGURG - 1);
    t.vm.sig_info_code = 0;

    let orig_pc = t.vm.pc;
    let orig_ra = t.vm.x[1];
    let orig_sp = t.vm.x[2];
    let orig_s11 = t.vm.x[27];

    let record = unsafe {
        &mut (*((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState)).threads
            [(t.vm.tid - 1) as usize]
    };
    record.state = THREAD_BLOCKED_FUTEX;
    record.blocked_addr = addr;

    thread_impl::resume_futex_wait_result(&mut t.vm, t.base, ETIMEDOUT);

    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, handler);
    assert_eq!(t.vm.x[10], SIGURG as u64);
    assert_eq!(t.vm.x[1], t.vm.x[2] + SIGFRAME_OFF_TRAMPOLINE);
    assert_eq!(t.vm.x[27], orig_s11);
    assert_eq!(t.vm.sig_pending & (1u64 << (SIGURG - 1)), 0);
    assert_eq!(record.state, THREAD_RUNNING);
    assert_eq!(record.blocked_addr, 0);

    signal::sys_rt_sigreturn(&mut t.vm, t.base);
    assert_eq!(t.vm.pc, orig_pc);
    assert_eq!(t.vm.x[1], orig_ra);
    assert_eq!(t.vm.x[2], orig_sp);
    assert_eq!(t.vm.x[10] as i64, ETIMEDOUT);
    assert_eq!(t.vm.x[27], orig_s11);
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
    ps.thread_count
        .store(3, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0, 0, from_addr);
    ps.threads[2] = ThreadRecord::new(3, THREAD_BLOCKED_FUTEX, 0, 0, from_addr);

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
    assert_eq!(ps.threads[2].blocked_addr, to_addr);
}

#[test]
fn contract_futex_cmp_requeue_bad_uaddr_returns_efault() {
    let mut t = TestVm::new();
    let bad_addr = 0x9;
    let from_addr = t.scratch + 0x610;
    let to_addr = t.scratch + 0x614;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, from_addr, 13);
    }

    let bad_from = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        bad_addr,
        FUTEX_CMP_REQUEUE as u64,
        1,
        1,
        to_addr,
        13,
    );
    assert_eq!(bad_from, EFAULT);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.fault_addr, 0);

    let bad_to = thread_impl::sys_futex(
        &mut t.vm,
        t.base,
        from_addr,
        FUTEX_CMP_REQUEUE as u64,
        1,
        1,
        bad_addr,
        13,
    );
    assert_eq!(bad_to, EFAULT);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.fault_addr, 0);
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
