use super::support::*;

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
