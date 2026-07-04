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
    assert_eq!(supervisor_blocked_wait_active_child_pid(vm_ptr), 0);

    process_impl::record_child_exit(child, 7 << 8);
    assert_eq!(
        tidemark_kernel::abi::process_has_active_child(parent_pid),
        0
    );
    assert_eq!(
        tidemark_kernel::abi::process_active_child_pid(parent_pid),
        0
    );
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
