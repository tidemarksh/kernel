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
fn contract_execve_completes_in_place_without_spawn() {
    let mut t = TestVm::new();
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    assert_ne!(memfs::resolve_path(b"/bin/test"), 0);
    assert_eq!(t.guest_mem(path_addr, 10), b"/bin/test\0");

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.spawn_child_pid, 0);
    assert_eq!(t.vm.pc, 0x1000);
}

#[test]
fn syscall_dispatch_routes_execve_through_fs_ring() {
    let mut t = TestVm::new();
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let vm_ptr = &mut t.vm as *mut _ as u32;

    t.vm.x[17] = SYS_EXECVE;
    t.vm.x[10] = path_addr;
    t.vm.x[11] = 0;
    t.vm.x[12] = 0;

    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_FS);
    assert_eq!(t.vm.status, STATUS_FS);

    tidemark_kernel::syscall::fs::process_pending_requests(vm_ptr, t.base);
    let ret = tidemark_kernel::syscall::fs::resume_from_fs(vm_ptr, t.base);

    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.pc, 0x1000);
}

#[test]
fn syscall_dispatch_preserves_vfork_execve_spawn_after_fs_ring() {
    let mut t = TestVm::new();
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let vfork_status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(vfork_status, STATUS_VFORK_WAIT);

    t.vm.x[17] = SYS_EXECVE;
    t.vm.x[10] = path_addr;
    t.vm.x[11] = 0;
    t.vm.x[12] = 0;

    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_FS);
    assert_eq!(t.vm.status, STATUS_FS);

    tidemark_kernel::syscall::fs::process_pending_requests(vm_ptr, t.base);
    let child_pid = tidemark_kernel::syscall::fs::resume_from_fs(vm_ptr, t.base);

    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_EXECVE);
    assert_eq!(t.vm.spawn_child_pid, child_pid as i32);
}

#[test]
fn supervisor_process_host_op_records_vfork_execve_spawn_handoff() {
    supervisor_reset_shadow_log();
    let mut t = TestVm::new();
    t.vm.guest_memory_policy_limit = 7 * 1024 * 1024;
    t.vm.process_max_memory_pages = 128;
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"supervisor_handoff", &elf);
    let argv_addr = write_strvec(&t, 0x400, &[b"/bin/supervisor_handoff", b"arg1"]);
    let envp_addr = write_strvec(&t, 0x800, &[b"KEY=VALUE"]);
    let vm_ptr = &mut t.vm as *mut _ as u32;

    let vfork_status = process_impl::sys_vfork(&mut t.vm, t.base);
    assert_eq!(vfork_status, STATUS_VFORK_WAIT);
    let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, argv_addr, envp_addr);

    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_EXECVE);

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
    assert_eq!(read_u32_le(&record, 24), vm_ptr);
    assert_eq!(read_u32_le(&record, 28), SPAWN_KIND_EXECVE);
    assert_eq!(read_u32_le(&record, 32), child_pid as u32);
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
    assert_eq!(read_u64_le(&record, 64), path_addr);
    assert_eq!(read_u64_le(&record, 72), argv_addr);
    assert_eq!(read_u64_le(&record, 80), envp_addr);
}

#[test]
fn syscall_dispatch_preserves_vfork_execve_fault_after_fs_ring() {
    let mut t = TestVm::new();
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let vfork_status = process_impl::sys_vfork(&mut t.vm, t.base);
    let child_pid = process_impl::vfork_child_pid();
    let child_process_ptr = t.vm.process_ptr;
    let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;
    let child_fs_ring_base =
        unsafe { guest_mem::read_u32(t.base, child_process_ptr as u64 + fs_ring_off) };
    let child_ps = unsafe { &*((t.base as u64 + child_process_ptr as u64) as *const ProcessState) };
    let child_fd0 = child_ps.fd_table[0].ofd_id;
    let child_fd1 = child_ps.fd_table[1].ofd_id;
    let child_fd2 = child_ps.fd_table[2].ofd_id;
    let invalid_argv = tidemark_kernel::wasm::memory_size_bytes().saturating_sub(t.base as u64);

    assert_eq!(vfork_status, STATUS_VFORK_WAIT);
    assert!(child_pid > 0);
    assert_ne!(child_fs_ring_base, 0);

    t.vm.x[17] = SYS_EXECVE;
    t.vm.x[10] = path_addr;
    t.vm.x[11] = invalid_argv;
    t.vm.x[12] = 0;

    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_FS);
    assert_eq!(t.vm.status, STATUS_FS);

    tidemark_kernel::syscall::fs::process_pending_requests(vm_ptr, t.base);
    let ret = tidemark_kernel::syscall::fs::resume_from_fs(vm_ptr, t.base);

    assert_eq!(ret, EFAULT);
    assert_eq!(t.vm.x[10] as i64, EFAULT);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
    assert_eq!(t.vm.spawn_child_pid, 0);
    assert_eq!(t.vm.process_ptr, child_process_ptr);
    assert_eq!(signal::pid_from_vm(&t.vm, t.base), child_pid);
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, child_process_ptr as u64 + fs_ring_off) },
        child_fs_ring_base
    );
    let child_ps = unsafe { &*((t.base as u64 + child_process_ptr as u64) as *const ProcessState) };
    assert_eq!(child_ps.fd_table[0].ofd_id, child_fd0);
    assert_eq!(child_ps.fd_table[1].ofd_id, child_fd1);
    assert_eq!(child_ps.fd_table[2].ofd_id, child_fd2);
}

#[test]
fn syscall_dispatch_preserves_vfork_execve_state_after_valid_large_image_fs_ring() {
    let mut t = TestVm::new();
    let mut code = vec![0x13, 0x05, 0x70, 0x00];
    code.resize(3_600_000, 0);
    let elf = build_test_elf(&code);
    let path_addr = install_exec_file(&t, b"test_large", &elf);
    let argv_addr = write_strvec(&t, 0x400, &[b"/bin/test_large", b"arg1"]);
    let envp_addr = write_strvec(&t, 0x800, &[b"KEY=VALUE"]);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let vfork_status = process_impl::sys_vfork(&mut t.vm, t.base);
    let child_pid = process_impl::vfork_child_pid();
    let child_process_ptr = t.vm.process_ptr;
    let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;
    let child_fs_ring_base =
        unsafe { guest_mem::read_u32(t.base, child_process_ptr as u64 + fs_ring_off) };
    let child_ps = unsafe { &*((t.base as u64 + child_process_ptr as u64) as *const ProcessState) };
    let child_fd0_ofd = child_ps.fd_table[0].ofd_id;
    let child_fd0_flags = child_ps.fd_table[0].fd_flags;
    let child_fd1_ofd = child_ps.fd_table[1].ofd_id;
    let child_fd1_flags = child_ps.fd_table[1].fd_flags;
    let child_fd2_ofd = child_ps.fd_table[2].ofd_id;
    let child_fd2_flags = child_ps.fd_table[2].fd_flags;

    assert_eq!(vfork_status, STATUS_VFORK_WAIT);
    assert!(child_pid > 0);
    assert_ne!(child_fs_ring_base, 0);

    t.vm.x[17] = SYS_EXECVE;
    t.vm.x[10] = path_addr;
    t.vm.x[11] = argv_addr;
    t.vm.x[12] = envp_addr;

    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_FS);
    assert_eq!(t.vm.status, STATUS_FS);

    tidemark_kernel::syscall::fs::process_pending_requests(vm_ptr, t.base);

    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.process_ptr, child_process_ptr);
    assert_eq!(signal::pid_from_vm(&t.vm, t.base), child_pid);
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, child_process_ptr as u64 + fs_ring_off) },
        child_fs_ring_base
    );
    let child_ps = unsafe { &*((t.base as u64 + child_process_ptr as u64) as *const ProcessState) };
    assert_eq!(child_ps.fd_table[0].ofd_id, child_fd0_ofd);
    assert_eq!(child_ps.fd_table[0].fd_flags, child_fd0_flags);
    assert_eq!(child_ps.fd_table[1].ofd_id, child_fd1_ofd);
    assert_eq!(child_ps.fd_table[1].fd_flags, child_fd1_flags);
    assert_eq!(child_ps.fd_table[2].ofd_id, child_fd2_ofd);
    assert_eq!(child_ps.fd_table[2].fd_flags, child_fd2_flags);

    let ret = tidemark_kernel::syscall::fs::resume_from_fs(vm_ptr, t.base);

    assert_eq!(ret, child_pid as i64);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_EXECVE);
    assert_eq!(t.vm.spawn_child_pid, child_pid);
}

#[test]
fn syscall_dispatch_keeps_vfork_execve_preflight_from_copying_large_image() {
    let mut t = TestVm::new();
    let mut code = vec![0x13, 0x05, 0x70, 0x00];
    code.resize(3_600_000, 0);
    let elf = build_test_elf(&code);
    let path_addr = install_exec_file(&t, b"test_large_preflight", &elf);
    let argv_addr = write_strvec(&t, 0x400, &[b"/bin/test_large_preflight", b"arg1"]);
    let envp_addr = write_strvec(&t, 0x800, &[b"KEY=VALUE"]);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let vfork_status = process_impl::sys_vfork(&mut t.vm, t.base);
    let child_pid = process_impl::vfork_child_pid();
    let child_process_ptr = t.vm.process_ptr;
    let ps_size = core::mem::size_of::<ProcessState>();
    let process_before = t.guest_mem(child_process_ptr as u64, ps_size);
    let argv_before = t.guest_mem(argv_addr, 128);
    let heap_before = tidemark_kernel::alloc::heap_ptr();

    assert_eq!(vfork_status, STATUS_VFORK_WAIT);
    assert!(child_pid > 0);

    t.vm.x[17] = SYS_EXECVE;
    t.vm.x[10] = path_addr;
    t.vm.x[11] = argv_addr;
    t.vm.x[12] = envp_addr;

    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_FS);
    assert_eq!(t.vm.status, STATUS_FS);

    tidemark_kernel::syscall::fs::process_pending_requests(vm_ptr, t.base);

    let heap_after = tidemark_kernel::alloc::heap_ptr();
    assert!(
        heap_after.saturating_sub(heap_before) < 512 * 1024,
        "vfork execve preflight must not copy the whole executable into kernel heap"
    );
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.process_ptr, child_process_ptr);
    assert_eq!(signal::pid_from_vm(&t.vm, t.base), child_pid);
    assert_eq!(
        t.guest_mem(child_process_ptr as u64, ps_size),
        process_before
    );
    assert_eq!(t.guest_mem(argv_addr, 128), argv_before);
}

#[test]
fn syscall_dispatch_completes_vfork_execve_handoff_with_large_image_argv() {
    let mut t = TestVm::new();
    let mut code = vec![0x13, 0x05, 0x70, 0x00];
    code.resize(3_600_000, 0);
    let elf = build_test_elf(&code);
    let path_addr = install_exec_file(&t, b"test_large_complete", &elf);
    let argv_addr = write_strvec(&t, 0x400, &[b"/bin/test_large_complete", b"arg1"]);
    let envp_addr = write_strvec(&t, 0x800, &[b"KEY=VALUE"]);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let vfork_status = process_impl::sys_vfork(&mut t.vm, t.base);
    let child_pid = process_impl::vfork_child_pid();

    assert_eq!(vfork_status, STATUS_VFORK_WAIT);
    assert!(child_pid > 0);

    t.vm.x[17] = SYS_EXECVE;
    t.vm.x[10] = path_addr;
    t.vm.x[11] = argv_addr;
    t.vm.x[12] = envp_addr;

    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_FS);
    assert_eq!(t.vm.status, STATUS_FS);

    tidemark_kernel::syscall::fs::process_pending_requests(vm_ptr, t.base);
    let ret = tidemark_kernel::syscall::fs::resume_from_fs(vm_ptr, t.base);

    assert_eq!(ret, child_pid as i64);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    assert_eq!(t.vm.spawn_kind, SPAWN_KIND_EXECVE);
    assert_eq!(t.vm.spawn_child_pid, child_pid);

    process_impl::clear_vfork_runtime_state();
    let ret = process_impl::complete_execve_in_place_from_handoff(
        &mut t.vm,
        t.base,
        process_impl::max_execve_guest_memory_limit(t.base),
    );

    assert_eq!(ret, 0);
    assert_eq!(t.vm.pc, 0x1000);
    let argc = unsafe { guest_mem::read_u64(t.base, t.vm.x[2]) };
    assert_eq!(argc, 2);
    let argv0 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 8) };
    let argv1 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 16) };
    let env0 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 32) };
    let mut buf = [0u8; 64];
    let len0 = unsafe { guest_mem::read_cstr(t.base, argv0, &mut buf) };
    assert_eq!(&buf[..len0], b"/bin/test_large_complete");
    let len1 = unsafe { guest_mem::read_cstr(t.base, argv1, &mut buf) };
    assert_eq!(&buf[..len1], b"arg1");
    let env_len = unsafe { guest_mem::read_cstr(t.base, env0, &mut buf) };
    assert_eq!(&buf[..env_len], b"KEY=VALUE");
}

#[test]
fn contract_execve_initializes_tp_from_pt_tls() {
    let mut t = TestVm::new();
    let elf = build_test_elf_with_tls(&[0x13, 0x05, 0x70, 0x00], &[0x41, 0x42, 0x43, 0x44], 0x20);
    let path_addr = install_exec_file(&t, b"test_tls", &elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.tls_base, 0x3000);
    assert_eq!(t.vm.x[4], 0x3000);
}

#[test]
fn contract_execve_preserves_host_stdio_slots() {
    let mut t = TestVm::new();
    let ps_addr = t.vm.process_ptr as u64;
    let stdin_pipe_off = core::mem::offset_of!(ProcessState, stdin_pipe_slot) as u64;
    let stdout_pipe_off = core::mem::offset_of!(ProcessState, stdout_pipe_slot) as u64;
    let stderr_pipe_off = core::mem::offset_of!(ProcessState, stderr_pipe_slot) as u64;
    let old_stdin = unsafe { guest_mem::read_u32(t.base, ps_addr + stdin_pipe_off) };
    let old_stdout = unsafe { guest_mem::read_u32(t.base, ps_addr + stdout_pipe_off) };
    let old_stderr = unsafe { guest_mem::read_u32(t.base, ps_addr + stderr_pipe_off) };
    assert!(old_stdin != 0 && old_stdout != 0 && old_stderr != 0);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);

    let new_ps_addr = t.vm.process_ptr as u64;
    let new_stdin = unsafe { guest_mem::read_u32(t.base, new_ps_addr + stdin_pipe_off) };
    let new_stdout = unsafe { guest_mem::read_u32(t.base, new_ps_addr + stdout_pipe_off) };
    let new_stderr = unsafe { guest_mem::read_u32(t.base, new_ps_addr + stderr_pipe_off) };
    assert_eq!(new_stdin, old_stdin);
    assert_eq!(new_stdout, old_stdout);
    assert_eq!(new_stderr, old_stderr);
}

#[test]
fn semantics_execve_discards_other_threads_on_success() {
    let mut t = TestVm::new();
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(ps.threads[0].state, THREAD_RUNNING);
    assert_eq!(ps.threads[1].state, THREAD_NONE);
}

#[test]
fn semantics_execve_clears_alt_stack() {
    let mut t = TestVm::new();
    t.vm.sigaltstack_sp = 0x5000;
    t.vm.sigaltstack_size = 8192;

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

    assert_eq!(t.vm.sigaltstack_sp, 0);
    assert_eq!(t.vm.sigaltstack_size, 0);
    assert_eq!(t.vm.sigaltstack_flags, SS_DISABLE);
}

#[test]
fn semantics_execve_preserves_signal_mask_and_pending() {
    let mut t = TestVm::new();
    t.vm.sig_mask = (1u64 << (SIGALRM - 1)) | (1u64 << (SIGTERM - 1));
    t.vm.sig_pending = 1u64 << (SIGCHLD - 1);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

    assert_eq!(
        t.vm.sig_mask,
        (1u64 << (SIGALRM - 1)) | (1u64 << (SIGTERM - 1))
    );
    assert_eq!(t.vm.sig_pending, 1u64 << (SIGCHLD - 1));
}

#[test]
fn contract_execve_with_pt_interp_enters_interpreter_and_sets_auxv() {
    let mut t = TestVm::new();
    t.vm.sig_mask = 1u64 << (SIGTERM - 1);
    t.vm.sig_pending = 1u64 << (SIGCHLD - 1);
    let main_elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_interp", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x3000);
    assert_eq!(t.vm.sig_mask, 1u64 << (SIGTERM - 1));
    assert_eq!(t.vm.sig_pending, 1u64 << (SIGCHLD - 1));
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );
    assert!(find_auxv_value(&t, tidemark_kernel::elf::AT_PHDR).is_some());
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_HWCAP),
        Some(0x112D)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_CLKTCK),
        Some(100)
    );
}

#[test]
fn contract_execve_with_pt_interp_follows_symlink_path() {
    let mut t = TestVm::new();
    let main_elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/usr/lib/ld-test.so", &interp_elf);
    assert_ne!(memfs::create_symlink(1, b"lib", b"usr/lib"), 0);
    let path_addr = install_exec_file_at(&t, b"/bin/test_interp_symlink", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.pc, 0x3000);
}

#[test]
fn contract_execve_with_pt_interp_preserves_executable_tls_base() {
    let mut t = TestVm::new();
    let main_elf = build_test_elf_with_interp_and_tls(
        &[0x13, 0x05, 0x70, 0x00],
        b"/lib/ld-test.so",
        &[0x41, 0x42, 0x43, 0x44],
        0x20,
    );
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_interp_tls", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x5000);
    assert_eq!(t.vm.tls_base, 0x3000);
    assert_eq!(t.vm.x[4], 0x3000);
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_ENTRY),
        Some(0x1300)
    );
}

#[test]
fn contract_execve_with_pt_interp_preserves_biased_dynamic_tls_base() {
    let mut t = TestVm::new();
    let main_elf = build_test_elf_dyn_with_interp_and_tls(
        &[0x13, 0x05, 0x70, 0x00],
        b"/lib/ld-test.so",
        &[0x41, 0x42, 0x43, 0x44],
        0x20,
    );
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_dyn_interp_tls", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x6000);
    assert_eq!(t.vm.tls_base, 0x4000);
    assert_eq!(t.vm.x[4], 0x4000);
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_ENTRY),
        Some(0x2300)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_BASE),
        Some(0x5000)
    );
}

#[test]
fn contract_execve_accepts_et_dyn_main_binary() {
    let mut t = TestVm::new();
    let path_addr = install_exec_file(
        &t,
        b"test-dyn",
        &build_test_elf_dyn(&[0x13, 0x05, 0x70, 0x00]),
    );

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(
        ret,
        0,
        "execve trace: {}",
        tidemark_kernel::harness::support::describe_execve_stage_trace()
    );
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x1000);
}

#[test]
fn contract_execve_with_pt_interp_accepts_et_dyn_interpreter() {
    let mut t = TestVm::new();
    let main_elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp_elf = build_test_elf_dyn(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_dyn_interp", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x3000);
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );
    let mut code = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, t.vm.pc, &mut code);
    }
    assert_eq!(code, [0x13, 0x05, 0x70, 0x00]);
}

#[test]
fn contract_execve_with_pt_interp_accepts_et_dyn_two_load_interpreter() {
    let mut t = TestVm::new();
    let main_elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp_elf =
        build_test_elf_dyn_two_loads(&[0x13, 0x05, 0x70, 0x00], &[0xaa, 0xbb, 0xcc, 0xdd]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_dyn_two_load_interp", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x3000);
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );
}

#[test]
fn contract_execve_interpreter_script_enters_interpreter_and_rewrites_argv() {
    let mut t = TestVm::new();
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/bin/interp", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/script", b"#!/bin/interp\nexit 0\n");
    let argv_addr = write_strvec(&t, 0x400, &[b"/bin/script", b"arg1"]);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, argv_addr, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x1000);

    let argc = unsafe { guest_mem::read_u64(t.base, t.vm.x[2]) };
    assert_eq!(argc, 3);
    let argv0 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 8) };
    let argv1 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 16) };
    let argv2 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 24) };
    let mut buf = [0u8; 32];
    let len0 = unsafe { guest_mem::read_cstr(t.base, argv0, &mut buf) };
    assert_eq!(&buf[..len0], b"/bin/interp");
    let len1 = unsafe { guest_mem::read_cstr(t.base, argv1, &mut buf) };
    assert_eq!(&buf[..len1], b"/bin/script");
    let len2 = unsafe { guest_mem::read_cstr(t.base, argv2, &mut buf) };
    assert_eq!(&buf[..len2], b"arg1");
}

#[test]
fn contract_execve_recursive_interpreter_script_rewrites_argv() {
    let mut t = TestVm::new();
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/bin/sh", &interp_elf);
    install_exec_file_at(&t, b"/bin/bash", b"#!/bin/sh\n");
    let path_addr = install_exec_file_at(&t, b"/bin/script", b"#!/bin/bash -x\nexit 0\n");
    let argv_addr = write_strvec(&t, 0x400, &[b"/bin/script", b"arg1"]);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, argv_addr, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x1000);

    let argc = unsafe { guest_mem::read_u64(t.base, t.vm.x[2]) };
    assert_eq!(argc, 5);
    let mut buf = [0u8; 32];
    let expected: [&[u8]; 5] = [b"/bin/sh", b"/bin/bash", b"-x", b"/bin/script", b"arg1"];
    for (idx, expected_arg) in expected.iter().enumerate() {
        let ptr = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 8 + (idx as u64 * 8)) };
        let len = unsafe { guest_mem::read_cstr(t.base, ptr, &mut buf) };
        assert_eq!(&buf[..len], *expected_arg);
    }
}

#[test]
fn contract_execve_recursive_interpreter_script_limit_returns_eloop() {
    let mut t = TestVm::new();
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/bin/final", &interp_elf);
    install_exec_file_at(&t, b"/bin/script4", b"#!/bin/final\n");
    install_exec_file_at(&t, b"/bin/script3", b"#!/bin/script4\n");
    install_exec_file_at(&t, b"/bin/script2", b"#!/bin/script3\n");
    install_exec_file_at(&t, b"/bin/script1", b"#!/bin/script2\n");
    let path_addr = install_exec_file_at(&t, b"/bin/script0", b"#!/bin/script1\n");

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, ELOOP);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn contract_execve_with_pt_interp_biases_et_dyn_main_executable() {
    let mut t = TestVm::new();
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_elf = build_test_elf_dyn_with_interp(&main_code, b"/lib/ld-test.so");
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_dyn_main_interp", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x4000);
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_ENTRY),
        Some(0x2200)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_PHDR),
        Some(0x2040)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_BASE),
        Some(0x3000)
    );

    let mut interp = [0u8; 32];
    let interp_len = unsafe { tidemark_kernel::guest_mem::read_cstr(t.base, 0x2100, &mut interp) };
    assert_eq!(&interp[..interp_len], b"/lib/ld-test.so");

    let mut code = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, 0x2200, &mut code);
    }
    assert_eq!(code, main_code);
}

#[test]
fn contract_execve_with_pt_interp_biases_et_dyn_two_load_main_executable() {
    let mut t = TestVm::new();
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_data = [0xaa, 0xbb, 0xcc, 0xdd];
    let main_elf =
        build_test_elf_dyn_with_interp_two_loads(&main_code, &main_data, b"/lib/ld-test.so");
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_dyn_two_load_main_interp", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x6000);
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_ENTRY),
        Some(0x2200)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_PHDR),
        Some(0x2040)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_BASE),
        Some(0x5000)
    );

    let mut data = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, 0x4000, &mut data);
    }
    assert_eq!(data, main_data);
}

#[test]
fn contract_execve_with_pt_interp_preserves_biased_main_dynamic_section() {
    let mut t = TestVm::new();
    let main_elf = build_test_elf_dyn_with_interp_dynamic(
        &[0x13, 0x05, 0x70, 0x00],
        &[0xaa, 0xbb, 0xcc, 0xdd],
        b"/lib/ld-test.so",
    );
    let interp_elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_dyn_dynamic_interp", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x6000);
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_ENTRY),
        Some(0x2200)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_PHDR),
        Some(0x2040)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_BASE),
        Some(0x5000)
    );

    let dyn_base = 0x4020u64;
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, dyn_base) },
        7
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, dyn_base + 8) },
        0x3300
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, dyn_base + 16) },
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, dyn_base + 24) },
        24
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, dyn_base + 32) },
        0x6fff_ffff
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, dyn_base + 40) },
        5
    );
}

#[test]
fn contract_execve_with_pt_interp_zero_fills_interpreter_brk_padding() {
    let mut t = TestVm::new();
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_elf = build_test_elf_with_interp(&main_code, b"/lib/ld-test.so");
    let interp_elf = build_test_elf_dyn_low(&[0x13, 0x06, 0x80, 0x00]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_pad", &main_elf);

    unsafe {
        tidemark_kernel::guest_mem::write_bytes(t.base, 0x2ff0, &[0xa5; 16]);
    }

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);

    let mut padding = [0u8; 16];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, 0x2ff0, &mut padding);
    }
    assert_eq!(padding, [0u8; 16]);
}

#[test]
fn contract_execve_discards_old_guest_address_space_bytes() {
    let mut t = TestVm::new();
    let old_brk = t.sys_brk(0x126000);
    assert_eq!(old_brk, 0x126000);
    let anon_map = t.sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert!(anon_map > 0);
    unsafe {
        guest_mem::write_bytes(t.base, 0x125000, &[0xa5; 16]);
        guest_mem::write_bytes(t.base, anon_map as u64, &[0x5a; 16]);
    }

    let code = [0x13, 0x05, 0x70, 0x00];
    let elf = build_test_elf(&code);
    let path_addr = install_exec_file_at(&t, b"/bin/test_exec_clear", &elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);

    let mut old_brk_bytes = [0u8; 16];
    let mut old_map_bytes = [0u8; 16];
    unsafe {
        guest_mem::read_bytes(t.base, 0x125000, &mut old_brk_bytes);
        guest_mem::read_bytes(t.base, anon_map as u64, &mut old_map_bytes);
    }
    assert_eq!(old_brk_bytes, [0u8; 16]);
    assert_eq!(old_map_bytes, [0u8; 16]);
}

#[test]
fn contract_execve_with_pt_interp_maps_main_executable_image() {
    let mut t = TestVm::new();
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_elf = build_test_elf_with_interp(&main_code, b"/lib/ld-test.so");
    let interp_elf = build_test_elf_dyn_low(&[0x13, 0x06, 0x80, 0x00]);
    install_exec_file_at(&t, b"/lib/ld-test.so", &interp_elf);
    let path_addr = install_exec_file_at(&t, b"/bin/test_main_mapped", &main_elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x2040);
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(&t, tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );

    let mut interp = [0u8; 32];
    let interp_len = unsafe { tidemark_kernel::guest_mem::read_cstr(t.base, 0x1100, &mut interp) };
    assert_eq!(&interp[..interp_len], b"/lib/ld-test.so");

    let mut code = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, 0x1200, &mut code);
    }
    assert_eq!(code, main_code);
}

#[test]
fn semantics_execve_in_place_reload_rebuilds_process_state() {
    let mut t = TestVm::new();
    let mapped = tidemark_kernel::syscall::memory::sys_mmap(
        &mut t.vm,
        t.base,
        0,
        PAGE_SIZE,
        PROT_NONE as u64,
        (MAP_PRIVATE | MAP_ANONYMOUS) as u64,
        -1,
        0,
    );
    assert!(mapped >= 0);
    assert!(tidemark_kernel::syscall::memory::has_prot_none());

    t.memfs.create_file(b"keep.txt", b"payload");
    let kept_fd = t.sys_openat(b"/keep.txt", O_RDONLY);
    assert_eq!(kept_fd, 3);
    let cloexec_fd = t.sys_dup(kept_fd as u64);
    assert_eq!(cloexec_fd, 4);
    assert_eq!(t.sys_fcntl(cloexec_fd as u64, 2, 1), 0);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let argv_addr = write_strvec(&t, 0x400, &[b"/bin/test", b"arg1"]);
    let envp_addr = write_strvec(&t, 0x800, &[b"KEY=VALUE"]);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, argv_addr, envp_addr);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x1000);
    assert_eq!(t.vm.tid, 1);
    assert!(!tidemark_kernel::syscall::memory::range_has_prot_none(
        mapped as u64,
        PAGE_SIZE
    ));

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(ps.pid, 42);
    let kept_entry = unsafe {
        guest_mem::read_u32(
            t.base,
            t.vm.process_ptr as u64 + 3 * core::mem::size_of::<FdEntry>() as u64,
        )
    };
    let cloexec_entry = unsafe {
        guest_mem::read_u32(
            t.base,
            t.vm.process_ptr as u64 + 4 * core::mem::size_of::<FdEntry>() as u64,
        )
    };
    assert_ne!(kept_entry, 0);
    assert_eq!(cloexec_entry, 0);

    let argc = unsafe { guest_mem::read_u64(t.base, t.vm.x[2]) };
    assert_eq!(argc, 2);
    let argv0 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 8) };
    let argv1 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 16) };
    let env0 = unsafe { guest_mem::read_u64(t.base, t.vm.x[2] + 32) };
    let mut buf = [0u8; 32];
    let len0 = unsafe { guest_mem::read_cstr(t.base, argv0, &mut buf) };
    assert_eq!(&buf[..len0], b"/bin/test");
    let len1 = unsafe { guest_mem::read_cstr(t.base, argv1, &mut buf) };
    assert_eq!(&buf[..len1], b"arg1");
    let env_len = unsafe { guest_mem::read_cstr(t.base, env0, &mut buf) };
    assert_eq!(&buf[..env_len], b"KEY=VALUE");
    assert!(argv0 > t.vm.x[2]);
    assert!(argv1 > t.vm.x[2]);
    assert!(env0 > t.vm.x[2]);
}

#[test]
fn contract_execve_rejects_unbacked_argument_vector() {
    let mut t = TestVm::new();
    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);
    let guest_limit = tidemark_kernel::wasm::memory_size_bytes().saturating_sub(t.base as u64);
    let argv_addr = guest_limit - 4;

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, argv_addr, 0);

    assert_eq!(ret, EFAULT);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn semantics_execve_clears_blocked_resume_scratch() {
    let mut t = TestVm::new();
    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    let stdout_ofd = ps.fd_table[1].ofd_id;
    assert!(stdout_ofd > 0);

    tidemark_kernel::fs::fd_table::retain_ofd_id(stdout_ofd);
    t.vm.blocked_fd = 1;
    t.vm.blocked_ofd_id = stdout_ofd;
    t.vm.futex_wait_addr = 0x1234;
    t.vm.futex_wait_timeout = 0x5678;
    t.vm.futex_wait_expected = 0x9abc;
    t.vm.epoll_timeout_ms = 99;

    let before =
        tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd).expect("stdout OFD should exist");
    assert_eq!(before.refcount, 2);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let path_addr = install_exec_file(&t, b"test", &elf);

    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.blocked_fd, 0);
    assert_eq!(t.vm.blocked_ofd_id, 0);
    assert_eq!(t.vm.futex_wait_addr, 0);
    assert_eq!(t.vm.futex_wait_timeout, 0);
    assert_eq!(t.vm.futex_wait_expected, 0);
    assert_eq!(t.vm.epoll_timeout_ms, 0);

    let after = tidemark_kernel::fs::fd_table::get_ofd_by_id(stdout_ofd)
        .expect("stdout OFD should survive execve");
    assert_eq!(after.refcount, 1);
}

#[test]
fn semantics_execve_failure_preserves_thread_group_and_altstack() {
    let mut t = TestVm::new();
    let ps_before = t.vm.process_ptr;
    let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
    ps.thread_count
        .store(2, core::sync::atomic::Ordering::Release);
    ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
    t.vm.sigaltstack_sp = 0x7000;
    t.vm.sigaltstack_size = 4096;

    let path_addr = install_exec_file(&t, b"bad", b"not-an-elf");
    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
    assert_eq!(ret, ENOEXEC);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.process_ptr, ps_before);
    assert_eq!(t.vm.sigaltstack_sp, 0x7000);
    assert_eq!(t.vm.sigaltstack_size, 4096);

    let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
    assert_eq!(
        ps.thread_count.load(core::sync::atomic::Ordering::Acquire),
        2
    );
    assert_eq!(ps.threads[1].state, THREAD_RUNNING);
}

#[test]
fn semantics_execve_late_enomem_preserves_process_identity_and_fds() {
    let mut t = TestVm::new();
    let mut code = vec![0x13, 0x05, 0x70, 0x00];
    code.resize(4_500_000, 0);
    let elf = build_test_elf(&code);
    let path_addr = install_exec_file(&t, b"large_exec", &elf);
    let old_process_ptr = t.vm.process_ptr;
    let old_pid = signal::pid_from_vm(&t.vm, t.base);
    let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;
    let old_fs_ring_base =
        unsafe { guest_mem::read_u32(t.base, old_process_ptr as u64 + fs_ring_off) };
    let old_ps = unsafe { &*((t.base as u64 + old_process_ptr as u64) as *const ProcessState) };
    let old_fd0 = old_ps.fd_table[0];
    let old_fd1 = old_ps.fd_table[1];
    let old_fd2 = old_ps.fd_table[2];

    t.vm.guest_memory_policy_limit = 5 * 1024 * 1024;
    let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

    assert_eq!(ret, ENOMEM);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(signal::pid_from_vm(&t.vm, t.base), old_pid);
    let current_process_ptr = t.vm.process_ptr;
    let current_ps =
        unsafe { &*((t.base as u64 + current_process_ptr as u64) as *const ProcessState) };
    assert_eq!(current_ps.pid, old_pid);
    assert_eq!(current_ps.fd_table[0].ofd_id, old_fd0.ofd_id);
    assert_eq!(current_ps.fd_table[0].fd_flags, old_fd0.fd_flags);
    assert_eq!(current_ps.fd_table[1].ofd_id, old_fd1.ofd_id);
    assert_eq!(current_ps.fd_table[1].fd_flags, old_fd1.fd_flags);
    assert_eq!(current_ps.fd_table[2].ofd_id, old_fd2.ofd_id);
    assert_eq!(current_ps.fd_table[2].fd_flags, old_fd2.fd_flags);
    assert_eq!(
        unsafe { guest_mem::read_u32(t.base, current_process_ptr as u64 + fs_ring_off) },
        old_fs_ring_base
    );
}
