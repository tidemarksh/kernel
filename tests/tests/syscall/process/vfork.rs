use super::support::*;

#[test]
fn contract_vfork_snapshots_and_suspends_parent() {
    let mut t = TestVm::new();
    t.vm.x[1] = 0xDEAD;
    t.vm.pc = 0x1000;

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_VFORK_WAIT);
    assert!(process_impl::vfork_child_pid() > 0);
}

#[test]
fn contract_clone_vfork_applies_raw_clone_child_args_without_polluting_parent() {
    let mut t = TestVm::new();
    t.vm.x[2] = 0x41000;
    t.vm.x[4] = 0x12000;
    t.vm.clear_child_tid = 0x7770;
    let parent_tidptr = 0x3000;
    let child_tidptr = 0x3008;
    let child_stack = 0x88000;
    let child_tls = 0x99000;
    let flags = CLONE_VFORK
        | CLONE_VM
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_SETTID
        | CLONE_CHILD_CLEARTID;

    let status = process_impl::sys_clone_vfork(
        &mut t.vm,
        t.base,
        flags,
        child_stack,
        parent_tidptr,
        child_tls,
        child_tidptr,
    );
    let child_pid = process_impl::vfork_child_pid();
    assert_eq!(status, STATUS_VFORK_WAIT);
    assert!(child_pid > 0);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.x[2], child_stack);
    assert_eq!(t.vm.x[4], child_tls);
    assert_eq!(t.vm.tls_base, child_tls);
    assert_eq!(t.vm.clear_child_tid, child_tidptr);
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, parent_tidptr) },
        child_pid as u32
    );
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, child_tidptr) },
        child_pid as u32
    );

    process_impl::vfork_parent_resume(&mut t.vm, child_pid);
    assert_eq!(t.vm.x[2], 0x41000);
    assert_eq!(t.vm.x[4], 0x12000);
    assert_eq!(t.vm.clear_child_tid, 0x7770);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn contract_vfork_parent_resume_restores_state() {
    let mut t = TestVm::new();
    t.vm.x[1] = 0xBEEF;
    t.vm.pc = 0x2000;
    t.vm.sig_pending = 1 << (SIGTERM - 1);
    t.vm.fault_pc = 0x4444;
    t.vm.fault_addr = 0x5555;
    t.vm.blocked_fd = 17;
    t.vm.blocked_ofd_id = 23;
    t.vm.epoll_timeout_ms = 99;
    t.vm.clone_pending = 1;
    t.vm.clone_child_tid = 77;

    process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(t.vm.sig_pending, 0);

    t.vm.x[1] = 0xFFFF;
    t.vm.pc = 0x9999;
    t.vm.fault_pc = 0xAAAA;
    t.vm.fault_addr = 0xBBBB;
    t.vm.blocked_fd = 0;
    t.vm.blocked_ofd_id = 0;
    t.vm.epoll_timeout_ms = -1;
    t.vm.clone_pending = 0;
    t.vm.clone_child_tid = 0;

    process_impl::vfork_parent_resume(&mut t.vm, 42);
    assert_eq!(t.vm.x[1], 0xBEEF);
    assert_eq!(t.vm.pc, 0x2000);
    assert_eq!(t.vm.x[10], 42);
    assert_eq!(t.vm.sig_pending, 1 << (SIGTERM - 1));
    assert_eq!(t.vm.fault_pc, 0x4444);
    assert_eq!(t.vm.fault_addr, 0x5555);
    assert_eq!(t.vm.blocked_fd, 17);
    assert_eq!(t.vm.blocked_ofd_id, 23);
    assert_eq!(t.vm.epoll_timeout_ms, 99);
    assert_eq!(t.vm.clone_pending, 1);
    assert_eq!(t.vm.clone_child_tid, 77);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn contract_vfork_exit_preserves_parent_thread_state() {
    let mut t = TestVm::new();
    let thread_count_off = core::mem::offset_of!(ProcessState, thread_count) as u64;

    process_impl::sys_vfork(&mut t.vm, t.base);
    let child_pid = process_impl::vfork_child_pid();
    assert!(child_pid > 0);

    let status = thread_impl::sys_exit(&mut t.vm, t.base, 7);
    assert_eq!(status, STATUS_FAULT);

    let thread_count =
        unsafe { guest_mem::read_u32(t.base, t.vm.process_ptr as u64 + thread_count_off) };
    assert_eq!(thread_count, 1);

    process_impl::record_child_exit(child_pid, ((t.vm.exit_code as u32) << 8) as i32);
    process_impl::vfork_parent_resume(&mut t.vm, child_pid);
    assert_eq!(t.vm.x[10], child_pid as u64);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn contract_vfork_from_secondary_thread_detaches_parent_thread_record_until_resume() {
    let mut t = TestVm::new();
    t.vm.tid = 3;
    let caller_ptr = &t.vm as *const _ as u32;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(3, core::sync::atomic::Ordering::Release);
    ps.threads[0] = ThreadRecord::new(1, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xCAFE_BABEu32, 0, 0);
    ps.threads[2] = ThreadRecord::new(3, THREAD_RUNNING, caller_ptr, 0, 0);

    let parent_process_ptr = t.vm.process_ptr;
    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    let parent_ps =
        unsafe { &*((t.base as u64 + parent_process_ptr as u64) as *const ProcessState) };
    assert_eq!(
        parent_ps
            .thread_count
            .load(core::sync::atomic::Ordering::Acquire),
        2
    );
    assert_eq!(parent_ps.threads[2].state, THREAD_NONE);
    assert_eq!(parent_ps.threads[2].thread_ptr, 0);

    let child_pid = process_impl::vfork_child_pid();
    process_impl::vfork_parent_resume(&mut t.vm, child_pid);

    let parent_ps =
        unsafe { &*((t.base as u64 + parent_process_ptr as u64) as *const ProcessState) };
    assert_eq!(
        parent_ps
            .thread_count
            .load(core::sync::atomic::Ordering::Acquire),
        3
    );
    assert_eq!(parent_ps.threads[2].tid, 3);
    assert_eq!(parent_ps.threads[2].state, THREAD_RUNNING);
    assert_eq!(parent_ps.threads[2].thread_ptr, caller_ptr);
}

#[test]
fn contract_vfork_parent_resume_clears_spawn_handoff() {
    let mut t = TestVm::new();
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);

    process_impl::sys_vfork(&mut t.vm, t.base);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_EXECVE);

    process_impl::vfork_parent_resume(&mut t.vm, child_pid as i32);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.spawn_child_pid, 0);
    assert_eq!(t.vm.x[10], child_pid as u64);
}

#[test]
fn contract_vfork_execve_failure_does_not_publish_spawn_handoff() {
    let mut t = TestVm::new();
    let path_addr = install_exec_file(&t, b"bad", b"not-an-elf");

    process_impl::sys_vfork(&mut t.vm, t.base);
    let child_pid = process_impl::vfork_child_pid();
    let child_process_ptr = t.vm.process_ptr;
    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, ENOEXEC);
    assert_eq!(t.vm.status, STATUS_VFORK_WAIT);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.spawn_child_pid, 0);
    assert_eq!(t.vm.process_ptr, child_process_ptr);
    assert_eq!(signal::pid_from_vm(&t.vm, t.base), child_pid);
}

#[test]
fn contract_vfork_rebases_brk_after_child_process_state() {
    let mut t = TestVm::new();

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    let child_process_ptr = t.vm.process_ptr as u64;
    let ps_size = core::mem::size_of::<ProcessState>() as u64;
    let public_brk = (child_process_ptr + ps_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    assert_eq!(status, STATUS_VFORK_WAIT);
    assert!(process_impl::vfork_child_pid() > 0);
    assert!(
        tidemark_kernel::harness::memory::debug_brk_base() >= public_brk,
        "vfork child ProcessState must not remain inside the user brk floor"
    );
    assert!(
        tidemark_kernel::harness::memory::current_brk() >= public_brk,
        "vfork child ProcessState must not remain inside the user brk interval"
    );
}

#[test]
fn semantics_vfork_execve_preserves_stdio_fds() {
    let mut t = TestVm::new();
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let old_fd0 = ps.fd_table[0].ofd_id;
    let old_fd1 = ps.fd_table[1].ofd_id;
    let old_fd2 = ps.fd_table[2].ofd_id;
    assert!(old_fd0 != 0 && old_fd1 != 0 && old_fd2 != 0);

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    process_impl::clear_vfork_runtime_state();
    let ret = process_impl::complete_execve_in_place_from_handoff(
        &mut t.vm,
        t.base,
        process_impl::max_execve_guest_memory_limit(t.base),
    );
    assert_eq!(ret, 0);

    let new_ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(new_ps.fd_table[0].ofd_id, old_fd0);
    assert_eq!(new_ps.fd_table[1].ofd_id, old_fd1);
    assert_eq!(new_ps.fd_table[2].ofd_id, old_fd2);
}

#[test]
fn semantics_vfork_execve_preserves_distinct_capture_pipe_ofds() {
    let mut t = TestVm::new();
    let stdout_pipefd_addr = t.scratch + 0x1800;
    let stderr_pipefd_addr = t.scratch + 0x1810;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, stdout_pipefd_addr, 0),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, stderr_pipefd_addr, 0),
        0
    );

    let stdout_read_fd = unsafe { guest_mem::read_u32(t.base, stdout_pipefd_addr) };
    let stdout_write_fd = unsafe { guest_mem::read_u32(t.base, stdout_pipefd_addr + 4) };
    let stderr_read_fd = unsafe { guest_mem::read_u32(t.base, stderr_pipefd_addr) };
    let stderr_write_fd = unsafe { guest_mem::read_u32(t.base, stderr_pipefd_addr + 4) };

    assert_eq!(t.sys_dup3(stdout_write_fd as u64, 1, 0), 1);
    assert_eq!(t.sys_dup3(stderr_write_fd as u64, 2, 0), 2);
    assert_eq!(t.sys_close(stdout_write_fd as i64), 0);
    assert_eq!(t.sys_close(stderr_write_fd as i64), 0);
    assert_eq!(t.sys_close(stdout_read_fd as i64), 0);
    assert_eq!(t.sys_close(stderr_read_fd as i64), 0);

    let ps_before = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let stdout_ofd_before = ps_before.fd_table[1].ofd_id;
    let stderr_ofd_before = ps_before.fd_table[2].ofd_id;
    assert_ne!(stdout_ofd_before, 0);
    assert_ne!(stderr_ofd_before, 0);
    assert_ne!(stdout_ofd_before, stderr_ofd_before);

    let stdout_pipe_before = tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd_before)
        .expect("stdout pipe OFD should exist before vfork+execve");
    let stderr_pipe_before = tidemark_kernel::fs::fd_table::get_ofd_by_id(stderr_ofd_before)
        .expect("stderr pipe OFD should exist before vfork+execve");
    assert_ne!(stdout_pipe_before.ino, stderr_pipe_before.ino);

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    process_impl::clear_vfork_runtime_state();
    let ret = process_impl::complete_execve_in_place_from_handoff(
        &mut t.vm,
        t.base,
        process_impl::max_execve_guest_memory_limit(t.base),
    );
    assert_eq!(ret, 0);

    let ps_after = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let stdout_ofd_after = ps_after.fd_table[1].ofd_id;
    let stderr_ofd_after = ps_after.fd_table[2].ofd_id;
    assert_eq!(stdout_ofd_after, stdout_ofd_before);
    assert_eq!(stderr_ofd_after, stderr_ofd_before);

    let stdout_pipe_after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd_after)
        .expect("stdout pipe OFD should survive execve");
    let stderr_pipe_after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stderr_ofd_after)
        .expect("stderr pipe OFD should survive execve");
    assert_ne!(stdout_pipe_after.ino, stderr_pipe_after.ino);
}

#[test]
fn semantics_vfork_parent_restore_without_cleanup_preserves_parent_epoll() {
    let mut t = TestVm::new();
    t.memfs.create_file(b"stdin.txt", b"");

    let output_pipefd_addr = t.scratch + 0x1820;
    let status_pipefd_addr = t.scratch + 0x1830;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(
            &mut t.vm,
            t.base,
            output_pipefd_addr,
            O_CLOEXEC as u64
        ),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(
            &mut t.vm,
            t.base,
            status_pipefd_addr,
            O_CLOEXEC as u64
        ),
        0
    );

    let output_read_fd = unsafe { guest_mem::read_u32(t.base, output_pipefd_addr) } as u64;
    let output_write_fd = unsafe { guest_mem::read_u32(t.base, output_pipefd_addr + 4) } as u64;
    let status_read_fd = unsafe { guest_mem::read_u32(t.base, status_pipefd_addr) } as u64;
    let status_write_fd = unsafe { guest_mem::read_u32(t.base, status_pipefd_addr + 4) } as u64;
    let stdin_fd = t.sys_openat(b"/stdin.txt", O_RDONLY | O_CLOEXEC);
    assert!(stdin_fd >= 3);

    let epfd =
        tidemark_kernel::syscall::epoll::sys_epoll_create1(&mut t.vm, t.base, O_CLOEXEC as u64);
    assert!(epfd >= 3);

    let event_addr = t.scratch + 0x2000;
    let out_addr = t.scratch + 0x2100;
    unsafe {
        guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        guest_mem::write_u64(t.base, event_addr + 8, 0x1111);
    }
    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            output_read_fd,
            event_addr
        ),
        0
    );
    unsafe {
        guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        guest_mem::write_u64(t.base, event_addr + 8, 0x2222);
    }
    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            status_read_fd,
            event_addr
        ),
        0
    );

    let epoll_ofd_id = unsafe {
        let ps = &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState);
        ps.fd_table[epfd as usize].ofd_id
    };
    let epoll_idx = tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
        .expect("epoll OFD should exist before vfork")
        .ino;
    assert_eq!(
        tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
            .expect("epoll OFD should be readable before vfork")
            .refcount,
        1
    );

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);
    assert_eq!(
        tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
            .expect("epoll OFD should be retained for the vfork child")
            .refcount,
        2
    );

    assert_eq!(t.sys_dup3(stdin_fd as u64, 0, 0), 0);
    assert_eq!(t.sys_dup3(output_write_fd, 1, 0), 1);
    assert_eq!(t.sys_dup3(output_write_fd, 2, 0), 2);
    assert_eq!(t.sys_close(output_read_fd as i64), 0);
    assert_eq!(t.sys_close(status_read_fd as i64), 0);
    assert!(tidemark_kernel::syscall::epoll::epoll_slot_allocated(
        epoll_idx
    ));
    assert_eq!(
        tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
            .expect("epoll OFD should survive child pipe setup")
            .refcount,
        2
    );

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    process_impl::vfork_parent_restore_without_cleanup(&mut t.vm, child_pid as i32);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], child_pid as u64);
    assert!(tidemark_kernel::syscall::epoll::epoll_slot_allocated(
        epoll_idx
    ));
    assert_eq!(
        tidemark_kernel::fs::fd_table::get_ofd_by_id(epoll_ofd_id)
            .expect("epoll OFD should survive parent restore")
            .refcount,
        1
    );

    assert_eq!(t.sys_close(stdin_fd), 0);
    assert_eq!(t.sys_close(output_write_fd as i64), 0);
    assert_eq!(t.sys_close(status_write_fd as i64), 0);
    assert!(tidemark_kernel::syscall::epoll::epoll_slot_allocated(
        epoll_idx
    ));

    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_DEL,
            output_read_fd,
            event_addr
        ),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_DEL,
            status_read_fd,
            event_addr
        ),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::epoll::sys_epoll_pwait(
            &mut t.vm,
            t.base,
            epfd as u64,
            out_addr,
            1,
            0,
            0
        ),
        0
    );
}

#[test]
fn semantics_vfork_parent_restore_without_cleanup_preserves_distinct_capture_pipe_ofds() {
    let mut t = TestVm::new();

    let stdout_pipefd_addr = t.scratch + 0x1800;
    let stderr_pipefd_addr = t.scratch + 0x1810;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, stdout_pipefd_addr, 0),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, stderr_pipefd_addr, 0),
        0
    );

    let stdout_read_fd = unsafe { guest_mem::read_u32(t.base, stdout_pipefd_addr) };
    let stdout_write_fd = unsafe { guest_mem::read_u32(t.base, stdout_pipefd_addr + 4) };
    let stderr_read_fd = unsafe { guest_mem::read_u32(t.base, stderr_pipefd_addr) };
    let stderr_write_fd = unsafe { guest_mem::read_u32(t.base, stderr_pipefd_addr + 4) };

    assert_eq!(t.sys_dup3(stdout_write_fd as u64, 1, 0), 1);
    assert_eq!(t.sys_dup3(stderr_write_fd as u64, 2, 0), 2);
    assert_eq!(t.sys_close(stdout_write_fd as i64), 0);
    assert_eq!(t.sys_close(stderr_write_fd as i64), 0);
    assert_eq!(t.sys_close(stdout_read_fd as i64), 0);
    assert_eq!(t.sys_close(stderr_read_fd as i64), 0);

    let ps_before = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let stdout_ofd_before = ps_before.fd_table[1].ofd_id;
    let stderr_ofd_before = ps_before.fd_table[2].ofd_id;
    assert_ne!(stdout_ofd_before, 0);
    assert_ne!(stderr_ofd_before, 0);
    assert_ne!(stdout_ofd_before, stderr_ofd_before);

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    process_impl::vfork_parent_restore_without_cleanup(&mut t.vm, child_pid as i32);
    assert_eq!(t.vm.status, STATUS_OK);

    let ps_after = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps_after.fd_table[1].ofd_id, stdout_ofd_before);
    assert_eq!(ps_after.fd_table[2].ofd_id, stderr_ofd_before);

    let eventfd = tidemark_kernel::syscall::pipe::sys_eventfd2(&mut t.vm, t.base, 0, 0);
    assert!(eventfd >= 3);

    let ps_after_eventfd =
        unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps_after_eventfd.fd_table[1].ofd_id, stdout_ofd_before);
    assert_eq!(ps_after_eventfd.fd_table[2].ofd_id, stderr_ofd_before);

    let stdout_pipe_after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd_before)
        .expect("stdout pipe OFD should survive restore_without_cleanup");
    let stderr_pipe_after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stderr_ofd_before)
        .expect("stderr pipe OFD should survive restore_without_cleanup");
    assert_eq!(stdout_pipe_after.fd_type, FD_TYPE_PIPE);
    assert_eq!(stderr_pipe_after.fd_type, FD_TYPE_PIPE);
    assert_ne!(stdout_pipe_after.ino, stderr_pipe_after.ino);
}

#[test]
fn semantics_vfork_from_secondary_thread_preserves_memfs_paths_before_execve() {
    let mut t = TestVm::new();
    t.vm.tid = 3;
    let caller_ptr = &t.vm as *const _ as u32;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(3, core::sync::atomic::Ordering::Release);
    ps.threads[0] = ThreadRecord::new(1, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xCAFE_BABEu32, 0, 0);
    ps.threads[2] = ThreadRecord::new(3, THREAD_RUNNING, caller_ptr, 0, 0);

    let tool_path = b"/usr/local/bin/tool";
    let tool_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let tool_path_addr = install_exec_file_at(&t, tool_path, &tool_elf);
    assert_eq!(read_file_bytes(tool_path), tool_elf);

    let status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(status, STATUS_VFORK_WAIT);

    assert_eq!(read_file_bytes(tool_path), tool_elf);
    assert_ne!(memfs::resolve_path(tool_path), 0);
    assert_ne!(process_impl::vfork_child_pid(), 0);

    let child_ret = process_impl::sys_execve(&mut t.vm, t.base, tool_path_addr, 0, 0);
    assert!(child_ret > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
}
