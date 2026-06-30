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
fn contract_fork_returns_status_execve_spawn() {
    let mut t = TestVm::new();
    let ret = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0);
    assert!(ret > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_FORK);
    assert_eq!(t.vm.spawn_child_pid, ret as i32);
    assert_eq!(t.vm.spawn_path, 0);
}

#[test]
fn supervisor_process_host_op_records_fork_spawn_handoff() {
    supervisor_reset_shadow_log();
    let mut t = TestVm::new();
    t.vm.guest_memory_policy_limit = 5 * 1024 * 1024;
    t.vm.process_max_memory_pages = 96;
    let vm_ptr = &mut t.vm as *mut _ as u32;

    let ret = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0);
    assert!(ret > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    let mut record = vec![0u8; supervisor_process_host_op_record_bytes() as usize];
    assert_eq!(
        supervisor_process_host_op(vm_ptr, record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_process_host_op_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&record, 0), 0x4850_5354);
    assert_eq!(read_u32_le(&record, 4), supervisor_abi_version());
    assert_eq!(
        read_u32_le(&record, 8),
        supervisor_process_host_op_record_bytes()
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_process_host_op_kind_spawn_process_worker()
    );
    assert_eq!(read_u64_le(&record, 16), 1);
    assert_eq!(read_u32_le(&record, 24), vm_ptr);
    assert_eq!(read_u32_le(&record, 28), SPAWN_KIND_FORK);
    assert_eq!(read_u32_le(&record, 32), ret as u32);
    assert_eq!(read_u32_le(&record, 36), t.vm.process_ptr);
    assert_eq!(read_u32_le(&record, 40), STATUS_EXECVE_SPAWN as u32);
    assert_eq!(read_u32_le(&record, 44), t.vm.spawn_address_profile);
    assert_eq!(
        read_u64_le(&record, 48),
        t.vm.spawn_guest_memory_policy_limit
    );
    assert_eq!(
        read_u32_le(&record, 56),
        t.vm.spawn_process_max_memory_pages
    );
    assert_eq!(read_u64_le(&record, 64), 0);
    assert_eq!(read_u64_le(&record, 72), 0);
    assert_eq!(read_u64_le(&record, 80), 0);
}

#[test]
fn contract_prepare_fork_child_sets_child_return_value_and_main_thread_state() {
    let mut t = TestVm::new();
    let child_tidptr = t.scratch + 0x120;
    let child_stack = t.scratch + 0x4000;
    let child_tls = 0x445566;
    let flags = CLONE_SETTLS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    let child_pid = process_impl::sys_fork(
        &mut t.vm,
        t.base,
        flags,
        child_stack,
        0,
        child_tls,
        child_tidptr,
    ) as i32;

    assert!(child_pid > 0);
    process_impl::reset_process_lifecycle(
        &mut t.vm,
        t.base,
        child_pid,
        1,
        child_pid + 1,
        1,
        1,
        false,
    );
    process_impl::prepare_fork_child_after_handoff(&mut t.vm, t.base, child_pid);

    assert_eq!(t.vm.tid, 1);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.x[2], child_stack);
    assert_eq!(t.vm.x[4], child_tls);
    assert_eq!(t.vm.tls_base, child_tls);
    assert_eq!(t.vm.clear_child_tid, child_tidptr);
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, child_tidptr) },
        child_pid as u32
    );
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.clone_flags, 0);
    assert_eq!(t.vm.clone_child_tid, 0);
    assert_eq!(t.vm.blocked_fd, 0);
    assert_eq!(t.vm.blocked_ofd_id, 0);
}

#[test]
fn contract_prepare_fork_child_resets_runtime_reservation_state() {
    let mut t = TestVm::new();
    let child_pid = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child_pid > 0);

    process_impl::reset_process_lifecycle(
        &mut t.vm,
        t.base,
        child_pid,
        1,
        child_pid + 1,
        1,
        1,
        false,
    );

    let ps = unsafe { &mut *((t.base + t.vm.process_ptr) as *mut ProcessState) };
    ps.reservation_lock[3].store(1, Ordering::Release);
    ps.reservation_lock[17].store(1, Ordering::Release);
    ps.reservation_gen[3].store(5, Ordering::Release);
    ps.reservation_gen[17].store(9, Ordering::Release);
    t.vm.lr_addr = 0x1234;
    t.vm.lr_val = 0x5678;
    t.vm.lr_gen = 5;
    t.vm.lr_gen_end = 9;

    process_impl::prepare_fork_child_after_handoff(&mut t.vm, t.base, child_pid);

    let ps = unsafe { &*((t.base + t.vm.process_ptr) as *const ProcessState) };
    assert!(
        ps.reservation_lock
            .iter()
            .all(|lock| lock.load(Ordering::Acquire) == 0)
    );
    assert!(
        ps.reservation_gen
            .iter()
            .all(|generation| generation.load(Ordering::Acquire) == 0)
    );
    assert_eq!(t.vm.lr_addr, u64::MAX);
    assert_eq!(t.vm.lr_val, 0);
    assert_eq!(t.vm.lr_gen, 0);
    assert_eq!(t.vm.lr_gen_end, 0);
}

#[test]
fn semantics_fork_inherits_signal_dispositions_and_clears_process_pending() {
    let mut t = TestVm::new();
    let sigmask_addr = t.scratch + 0x200;
    let sigaction_addr = t.scratch + 0x220;
    let old_sigaction_addr = t.scratch + 0x260;
    let pending_addr = t.scratch + 0x280;

    unsafe {
        guest_mem::write_u64(t.base, sigmask_addr, 1 << (SIGALRM - 1));
        guest_mem::write_u64(t.base, sigaction_addr, 0x12345);
        guest_mem::write_u64(t.base, sigaction_addr + 8, 0);
        guest_mem::write_u64(t.base, sigaction_addr + 16, 0);
    }

    assert_eq!(
        signal::sys_rt_sigprocmask(&mut t.vm, t.base, 0, sigmask_addr, 0, 8),
        0
    );
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGALRM as u64, sigaction_addr, 0, 8,),
        0
    );
    assert_eq!(
        signal::send_signal_to_pid(&mut t.vm, t.base, 42, SIGALRM),
        0
    );

    let child_pid = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child_pid > 0);
    t.vm.status = STATUS_OK;

    write_process_ids(&t, child_pid, 42);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGALRM as u64, 0, old_sigaction_addr, 8,),
        0
    );
    assert_eq!(
        unsafe { guest_mem::read_u64(t.base, old_sigaction_addr) },
        0x12345
    );

    assert_eq!(signal::sys_rt_sigpending(&t.vm, t.base, pending_addr, 8), 0);
    assert_eq!(unsafe { guest_mem::read_u64(t.base, pending_addr) }, 0);
}

#[test]
fn semantics_fork_inherits_resource_limits() {
    let mut t = TestVm::new();
    let new_limit_addr = t.scratch;
    let old_limit_addr = t.scratch + 0x20;
    const RLIMIT_STACK: u64 = 3;

    unsafe {
        guest_mem::write_u64(t.base, new_limit_addr, 512 * 1024);
        guest_mem::write_u64(t.base, new_limit_addr + 8, 1024 * 1024);
    }
    assert_eq!(
        tidemark_kernel::syscall::resource::sys_prlimit64(
            &t.vm,
            t.base,
            0,
            RLIMIT_STACK,
            new_limit_addr,
            0,
        ),
        0
    );

    let child_pid = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child_pid > 0);
    t.vm.status = STATUS_OK;

    write_process_ids(&t, child_pid, 42);
    assert_eq!(
        tidemark_kernel::syscall::resource::sys_prlimit64(
            &t.vm,
            t.base,
            0,
            RLIMIT_STACK,
            0,
            old_limit_addr,
        ),
        0
    );
    assert_eq!(
        unsafe { guest_mem::read_u64(t.base, old_limit_addr) },
        512 * 1024
    );
    assert_eq!(
        unsafe { guest_mem::read_u64(t.base, old_limit_addr + 8) },
        1024 * 1024
    );
}
