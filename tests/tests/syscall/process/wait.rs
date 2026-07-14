use super::support::*;
use tidemark_kernel::fs::fd_table;
use tidemark_kernel::syscall::pipe;

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

fn submit_wait4_blocked_event(vm_ptr: u32, tid: u32) {
    let mut event = [0u8; 80];
    write_u32_le(&mut event, 0, supervisor_thread_event_record_magic());
    write_u32_le(&mut event, 4, supervisor_abi_version());
    write_u32_le(&mut event, 8, supervisor_thread_event_record_bytes());
    write_u32_le(&mut event, 12, supervisor_thread_event_kind_blocked());
    write_u64_le(&mut event, 16, 1);
    write_u64_le(&mut event, 24, vm_ptr as u64);
    write_u32_le(&mut event, 36, tid);
    write_u32_le(&mut event, 40, STATUS_WAIT4 as u32);
    assert_eq!(
        supervisor_submit_thread_event(event.as_ptr() as u32, event.len() as u32),
        0
    );
}

fn install_current_thread_record(t: &mut TestVm) {
    let vm_ptr = (&mut t.vm as *mut ThreadState) as u32;
    let tid = t.vm.tid;
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[(tid - 1) as usize] = ThreadRecord::new(tid, THREAD_RUNNING, vm_ptr, 0, 0);
        ps.thread_count
            .store(1, std::sync::atomic::Ordering::Release);
    }
}

#[test]
fn semantics_waitid_wnowait_reports_without_reaping() {
    let mut t = TestVm::new();
    let info_addr = t.scratch + 0x1000;

    let child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child > 0);
    t.vm.status = STATUS_OK;
    process_impl::record_child_exit(child, 9 << 8);

    let ret = process_impl::sys_waitid(
        &mut t.vm,
        t.base,
        P_PID,
        child as i64,
        info_addr,
        WEXITED | WNOWAIT,
        0,
    );
    assert_eq!(ret, 0);
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_PID) },
        child as u32
    );
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_STATUS) },
        9
    );

    let ret = process_impl::sys_waitid(
        &mut t.vm,
        t.base,
        P_PID,
        child as i64,
        info_addr,
        WEXITED,
        0,
    );
    assert_eq!(ret, 0);

    let ret = process_impl::sys_waitid(
        &mut t.vm,
        t.base,
        P_PID,
        child as i64,
        info_addr,
        WEXITED | WNOHANG,
        0,
    );
    assert_eq!(ret, ECHILD);
}

#[test]
fn resume_wait4_clears_stale_blocked_supervisor_event() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    install_current_thread_record(&mut t);
    let vm_ptr = (&mut t.vm as *mut ThreadState) as u32;
    let child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child > 0);
    t.vm.status = STATUS_OK;

    assert_eq!(
        process_impl::sys_wait4(&mut t.vm, t.base, child as i64, 0, 0, 0),
        0
    );
    assert_eq!(t.vm.status, STATUS_WAIT4);
    submit_wait4_blocked_event(vm_ptr, t.vm.tid as u32);
    process_impl::record_child_exit(child, 0);

    assert_eq!(process_impl::resume_wait4(vm_ptr, t.base), child as i64);
    assert_eq!(t.vm.status, STATUS_OK);

    let mut snapshot = vec![0u8; supervisor_thread_state_snapshot_bytes() as usize];
    assert_eq!(
        supervisor_thread_state_snapshot(
            vm_ptr,
            snapshot.as_mut_ptr() as u32,
            snapshot.len() as u32,
        ),
        supervisor_thread_state_snapshot_bytes() as i32
    );
    assert_eq!(read_u32_le(&snapshot, 32 + 4), THREAD_RUNNING as u32);
    assert_eq!(read_u32_le(&snapshot, 32 + 12), STATUS_OK as u32);
}

#[test]
fn semantics_waitid_reports_signal_killed_children() {
    let mut t = TestVm::new();
    let info_addr = t.scratch + 0x1000;

    let child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child > 0);
    t.vm.status = STATUS_OK;
    process_impl::record_child_exit(child, SIGKILL);

    let ret = process_impl::sys_waitid(&mut t.vm, t.base, P_ALL, 0, info_addr, WEXITED, 0);
    assert_eq!(ret, 0);
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_PID) },
        child as u32
    );
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_STATUS) },
        SIGKILL as u32
    );
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_SIGNO) },
        SIGCHLD as u32
    );
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_CODE) },
        CLD_KILLED
    );
}

#[test]
fn semantics_wait4_accepts_common_waitpid_flags_when_reaping_exited_child() {
    let mut t = TestVm::new();
    let wstatus_addr = t.scratch + 0x1200;

    let child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child > 0);
    t.vm.status = STATUS_OK;
    process_impl::record_child_exit(child, 7 << 8);

    let ret = process_impl::sys_wait4(
        &mut t.vm,
        t.base,
        child as i64,
        wstatus_addr,
        WUNTRACED | WCONTINUED,
        0,
    );
    assert_eq!(ret, child as i64);
    assert_eq!(unsafe { guest_mem::read_u32(t.base, wstatus_addr) }, 7 << 8);
}

#[test]
fn supervisor_process_has_active_child_tracks_kernel_child_table() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    let parent_pid = process_impl::current_process_pid(&t.vm, t.base);

    assert_eq!(
        tidemark_kernel::abi::process_has_active_child(parent_pid),
        0
    );
    assert_eq!(
        tidemark_kernel::abi::process_active_child_pid(parent_pid),
        0
    );
    let child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child > 0);
    assert_eq!(
        tidemark_kernel::abi::process_has_active_child(parent_pid),
        1
    );
    assert_eq!(
        tidemark_kernel::abi::process_active_child_pid(parent_pid),
        child
    );
    t.vm.status = STATUS_WAIT4;
    assert_eq!(t.vm.status, STATUS_WAIT4);
    assert_eq!(supervisor_blocked_wait_active_child_pid(vm_ptr), child);
    assert_eq!(
        supervisor_blocked_wait_retry_reason(vm_ptr, 0),
        supervisor_blocked_wait_retry_reason_active_child() as i32
    );
    assert_eq!(
        supervisor_blocked_retry_action(vm_ptr, 0),
        supervisor_blocked_retry_action_park_active_child() as i32
    );
    t.vm.status = STATUS_PIPE_WAIT;
    t.vm.epoll_timeout_ms = -1;
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.epoll_timeout_ms, -1);
    assert_eq!(supervisor_blocked_wait_active_child_pid(vm_ptr), child);
    assert_eq!(
        supervisor_blocked_retry_action(vm_ptr, 0),
        supervisor_blocked_retry_action_park_active_child() as i32
    );
    t.vm.epoll_timeout_ms = 1;
    assert_eq!(t.vm.epoll_timeout_ms, 1);
    t.vm.x[17] = SYS_PSELECT6;
    assert_eq!(supervisor_blocked_wait_active_child_pid(vm_ptr), 0);
    assert_eq!(
        supervisor_blocked_retry_action(vm_ptr, 0),
        supervisor_blocked_retry_action_arm_wait_timer() as i32
    );
    t.vm.x[17] = SYS_READ;
    assert_eq!(supervisor_blocked_wait_active_child_pid(vm_ptr), child);
    assert_eq!(
        supervisor_blocked_retry_action(vm_ptr, 0),
        supervisor_blocked_retry_action_park_active_child() as i32
    );

    let pipefd_addr = t.scratch + 0x1300;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { guest_mem::read_u32(t.base, pipefd_addr + 4) } as u64;
    let buf_addr = t.scratch + 0x1400;

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_PIPE_WAIT
    );
    let write_ofd = fd_table::get_ofd(t.base, &t.vm, write_fd).expect("pipe writer OFD");
    assert_eq!(pipe::pipe_write(write_ofd.ino, b"x"), 1);
    assert_eq!(thread_blocked_pipe_read_ready(vm_ptr), 1);
    assert_eq!(supervisor_blocked_wait_active_child_pid(vm_ptr), 0);
    assert_ne!(
        supervisor_blocked_retry_action(vm_ptr, 0),
        supervisor_blocked_retry_action_park_active_child() as i32
    );

    process_impl::record_child_exit(child, 7 << 8);
    assert_eq!(
        tidemark_kernel::abi::process_has_active_child(parent_pid),
        0
    );
    assert_eq!(
        tidemark_kernel::abi::process_active_child_pid(parent_pid),
        0
    );
    t.vm.status = STATUS_WAIT4;
    assert_eq!(t.vm.status, STATUS_WAIT4);
    assert_eq!(
        supervisor_blocked_retry_action(vm_ptr, 0),
        supervisor_blocked_retry_action_resume_wait4() as i32
    );
    assert_eq!(
        supervisor_blocked_retry_action(
            vm_ptr,
            supervisor_blocked_retry_action_flag_kernel_worker_available()
        ),
        supervisor_blocked_retry_action_resume_wait4_kernel_worker() as i32
    );
}

#[test]
fn supervisor_wait4_reaps_matching_exited_child_before_parking_for_an_active_child() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut ThreadState as u32;

    let exited_child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(exited_child > 0);
    t.vm.status = STATUS_OK;
    let active_child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(active_child > 0);
    t.vm.status = STATUS_OK;

    assert_eq!(process_impl::sys_wait4(&mut t.vm, t.base, -1, 0, 0, 0), 0);
    assert_eq!(t.vm.status, STATUS_WAIT4);

    process_impl::record_child_exit(exited_child, 7 << 8);
    assert_eq!(
        tidemark_kernel::abi::process_active_child_pid(process_impl::current_process_pid(
            &t.vm, t.base
        )),
        active_child
    );
    assert_eq!(supervisor_blocked_wait_active_child_pid(vm_ptr), 0);
    assert_eq!(
        supervisor_blocked_retry_action(vm_ptr, 0),
        supervisor_blocked_retry_action_resume_wait4() as i32
    );
    assert_eq!(thread_resume_wait4(vm_ptr), exited_child as i64);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn supervisor_process_lifecycle_records_child_exit_before_wait4_completion() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    let wstatus_addr = t.scratch + 0x1280;
    let parent_pid = process_impl::current_process_pid(&t.vm, t.base);

    let child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child > 0);
    t.vm.status = STATUS_OK;

    process_impl::record_child_exit_for_parent(parent_pid, child, 7 << 8);
    assert_eq!(supervisor_shadow_process_lifecycle_count(), 1);

    let mut record = [0u8; 96];
    assert_eq!(
        supervisor_process_lifecycle_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_process_lifecycle_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&record, 0), 0x4350_5354);
    assert_eq!(
        read_u32_le(&record, 8),
        supervisor_process_lifecycle_record_bytes()
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_process_lifecycle_kind_child_exit_published()
    );
    assert_eq!(read_u64_le(&record, 16), 1);
    assert_eq!(read_u32_le(&record, 24), 0);
    assert_eq!(read_u32_le(&record, 28), parent_pid as u32);
    assert_eq!(read_u32_le(&record, 32), child as u32);
    assert_eq!(read_u32_le(&record, 36), (7 << 8) as u32);

    let ret = process_impl::sys_wait4(&mut t.vm, t.base, child as i64, wstatus_addr, 0, 0);
    assert_eq!(ret, child as i64);
    assert_eq!(unsafe { guest_mem::read_u32(t.base, wstatus_addr) }, 7 << 8);
    assert_eq!(supervisor_shadow_process_lifecycle_count(), 2);

    assert_eq!(
        supervisor_process_lifecycle_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_process_lifecycle_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_process_lifecycle_kind_wait4_completed()
    );
    assert_eq!(read_u64_le(&record, 16), 2);
    assert_eq!(read_u32_le(&record, 24), vm_ptr);
    assert_eq!(read_u32_le(&record, 28), parent_pid as u32);
    assert_eq!(read_u32_le(&record, 32), child as u32);
    assert_eq!(read_u32_le(&record, 36), (7 << 8) as u32);
    assert_eq!(read_u32_le(&record, 40), 1);
    assert_eq!(read_u32_le(&record, 44), STATUS_OK as u32);
    assert_eq!(read_u64_le(&record, 48), child as u64);
    assert_eq!(read_u64_le(&record, 56), child as u64);
    assert_eq!(read_u64_le(&record, 64), 0);
    assert_eq!(read_u64_le(&record, 72), wstatus_addr);
    assert_eq!(read_u64_le(&record, 80), 0);
    assert_eq!(read_u64_le(&record, 88), 1);
}

#[test]
fn semantics_wait4_wnohang_accepts_common_waitpid_flags_for_running_child() {
    let mut t = TestVm::new();

    let child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child > 0);
    t.vm.status = STATUS_OK;

    let ret = process_impl::sys_wait4(
        &mut t.vm,
        t.base,
        child as i64,
        0,
        WNOHANG | WUNTRACED | WCONTINUED,
        0,
    );
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn semantics_wait4_reaps_late_exit_record_seeded_with_explicit_parent_pid() {
    let mut t = TestVm::new();
    let wstatus_addr = t.scratch + 0x1300;

    write_process_ids(&t, 2, 1);
    signal::init_for_process(2);
    process_impl::record_child_exit_for_parent(2, 7, 5 << 8);

    let ret = process_impl::sys_wait4(&mut t.vm, t.base, 7, wstatus_addr, 0, 0);
    assert_eq!(ret, 7);
    assert_eq!(unsafe { guest_mem::read_u32(t.base, wstatus_addr) }, 5 << 8);
}

#[test]
fn semantics_wait4_zero_reaps_exited_child_after_process_entry_removed() {
    let mut t = TestVm::new();
    let wstatus_addr = t.scratch + 0x1380;

    let child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child > 0);
    t.vm.status = STATUS_OK;
    process_impl::record_child_exit(child, 6 << 8);
    process_impl::remove_process_entry(child);

    let ret = process_impl::sys_wait4(&mut t.vm, t.base, 0, wstatus_addr, 0, 0);
    assert_eq!(ret, child as i64);
    assert_eq!(unsafe { guest_mem::read_u32(t.base, wstatus_addr) }, 6 << 8);
}

#[test]
fn semantics_wait4_zero_reaps_late_exit_record_with_active_sibling() {
    let mut t = TestVm::new();
    let wstatus_addr = t.scratch + 0x13c0;
    let parent_pid = process_impl::current_process_pid(&t.vm, t.base);

    let exited_child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(exited_child > 0);
    t.vm.status = STATUS_OK;
    process_impl::remove_process_entry(exited_child);
    process_impl::record_child_exit_for_parent(parent_pid, exited_child, 6 << 8);

    let active_child = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(active_child > 0);
    assert_ne!(active_child, exited_child);
    t.vm.status = STATUS_OK;

    let ret = process_impl::sys_wait4(&mut t.vm, t.base, 0, wstatus_addr, 0, 0);
    assert_eq!(ret, exited_child as i64);
    assert_eq!(unsafe { guest_mem::read_u32(t.base, wstatus_addr) }, 6 << 8);
}

#[test]
fn semantics_wait4_reap_discards_pending_sigchld_when_no_other_child_status_is_available() {
    let mut t = TestVm::new();
    let wstatus_addr = t.scratch + 0x1400;
    let pending_addr = t.scratch + 0x1410;
    let sigchld_bit = 1u64 << (SIGCHLD - 1);

    write_process_ids(&t, 2, 1);
    signal::init_for_process(2);
    t.vm.sig_mask = sigchld_bit;
    process_impl::record_child_exit_for_parent(2, 7, 5 << 8);

    assert_eq!(signal::sys_rt_sigpending(&t.vm, t.base, pending_addr, 8), 0);
    assert_eq!(
        unsafe { guest_mem::read_u64(t.base, pending_addr) } & sigchld_bit,
        sigchld_bit
    );

    let ret = process_impl::sys_wait4(&mut t.vm, t.base, 7, wstatus_addr, 0, 0);

    assert_eq!(ret, 7);
    assert_eq!(unsafe { guest_mem::read_u32(t.base, wstatus_addr) }, 5 << 8);
    assert_eq!(signal::sys_rt_sigpending(&t.vm, t.base, pending_addr, 8), 0);
    assert_eq!(
        unsafe { guest_mem::read_u64(t.base, pending_addr) } & sigchld_bit,
        0
    );
}
