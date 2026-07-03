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
fn contract_supervisor_host_op_spawns_clone_thread_state() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;
    t.vm.pc = 0x4567_89ab;
    t.vm.x[1] = 0x1234_5678;
    t.vm.x[3] = 0x2345_6789;
    t.vm.x[27] = 0x3456_789a;

    let parent_vm_ptr = &mut t.vm as *mut ThreadState as u32;
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
    assert_eq!(t.vm.status, STATUS_CLONE_SPAWN);
    assert_eq!(
        supervisor_next_host_op(0, 0),
        supervisor_host_op_record_bytes() as i32
    );

    let mut too_small = [0u8; 63];
    assert_eq!(
        supervisor_next_host_op(too_small.as_mut_ptr() as u32, too_small.len() as u32),
        ENOSPC as i32
    );

    let mut record = [0u8; 64];
    assert_eq!(
        supervisor_next_host_op(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_host_op_record_bytes() as i32
    );

    assert_eq!(read_u32_le(&record, 0), 0x4f48_5354);
    assert_eq!(read_u32_le(&record, 4), supervisor_abi_version());
    assert_eq!(read_u32_le(&record, 8), supervisor_host_op_record_bytes());
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_host_op_kind_spawn_thread_worker()
    );
    assert_eq!(read_u64_le(&record, 16), 1);
    assert_eq!(read_u32_le(&record, 24), parent_vm_ptr);

    let child_ptr = read_u32_le(&record, 28);
    assert_ne!(child_ptr, 0);
    assert_eq!(read_u32_le(&record, 32), ret as u32);
    assert_eq!(read_u32_le(&record, 36), t.vm.process_ptr);
    assert_eq!(read_u32_le(&record, 40), STATUS_OK as u32);
    assert_eq!(read_u64_le(&record, 48), flags);
    assert_eq!(read_u64_le(&record, 56), child_tidptr);
    assert_eq!(supervisor_shadow_host_op_emit_count(), 1);

    let child = unsafe { &*(child_ptr as *const ThreadState) };
    assert_eq!(child.tid, ret as i32);
    assert_eq!(child.pc, 0x4567_89ab);
    assert_eq!(child.x[1], 0x1234_5678);
    assert_eq!(child.x[3], 0x2345_6789);
    assert_eq!(child.x[27], 0x3456_789a);
    assert_eq!(child.x[10], 0);
    assert_eq!(child.x[2], child_stack);
    assert_eq!(child.x[4], tls);
    assert_eq!(child.tls_base, tls);
    assert_eq!(child.clear_child_tid, child_tidptr);

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
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(supervisor_next_host_op(0, 0), 0);
}

#[test]
fn contract_supervisor_host_op_kind_filter_preserves_mixed_queue() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;
    t.vm.pc = 0x4567_89ab;
    let parent_vm_ptr = &mut t.vm as *mut ThreadState as u32;

    t.vm.status = STATUS_EPOLL_WAIT;
    t.vm.epoll_timeout_ms = 25;
    assert_eq!(supervisor_enqueue_blocked_wait_timer(parent_vm_ptr), 1);
    t.vm.status = STATUS_WAIT4;
    assert_eq!(supervisor_enqueue_blocked_retry_timer(parent_vm_ptr, 0), 1);
    t.vm.status = STATUS_OK;

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0x88000, 0, 0, 0);
    assert!(ret > 0);

    let mut clone_record = [0u8; 64];
    assert_eq!(
        supervisor_next_host_op_kind(
            supervisor_host_op_kind_spawn_thread_worker(),
            clone_record.as_mut_ptr() as u32,
            clone_record.len() as u32
        ),
        supervisor_host_op_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&clone_record, 12),
        supervisor_host_op_kind_spawn_thread_worker()
    );
    assert_eq!(read_u32_le(&clone_record, 24), parent_vm_ptr);

    let mut retry_record = [0u8; 64];
    assert_eq!(
        supervisor_next_host_op_kind(
            supervisor_host_op_kind_retry_blocked_worker(),
            retry_record.as_mut_ptr() as u32,
            retry_record.len() as u32
        ),
        supervisor_host_op_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&retry_record, 12),
        supervisor_host_op_kind_retry_blocked_worker()
    );
    assert_eq!(read_u32_le(&retry_record, 24), parent_vm_ptr);
    assert_eq!(read_u64_le(&retry_record, 48), 10);
    assert_eq!(
        read_u64_le(&retry_record, 56),
        supervisor_blocked_wait_retry_reason_default() as u64
    );

    let mut timer_record = [0u8; 64];
    assert_eq!(
        supervisor_next_host_op_kind(
            supervisor_host_op_kind_arm_host_timer(),
            timer_record.as_mut_ptr() as u32,
            timer_record.len() as u32
        ),
        supervisor_host_op_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&timer_record, 12),
        supervisor_host_op_kind_arm_host_timer()
    );
    assert_eq!(read_u32_le(&timer_record, 24), parent_vm_ptr);
    assert_eq!(supervisor_next_host_op(0, 0), 0);

    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;
    let parent_vm_ptr = &mut t.vm as *mut ThreadState as u32;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0x89000, 0, 0, 0);
    assert!(ret > 0);
    t.vm.status = STATUS_EPOLL_WAIT;
    t.vm.epoll_timeout_ms = 25;
    assert_eq!(t.vm.status, STATUS_EPOLL_WAIT);
    assert_eq!(t.vm.epoll_timeout_ms, 25);
    assert_eq!(supervisor_enqueue_blocked_wait_timer(parent_vm_ptr), 1);
    t.vm.status = STATUS_CLONE_SPAWN;
    assert_eq!(t.vm.status, STATUS_CLONE_SPAWN);

    let mut timer_record = [0u8; 64];
    assert_eq!(
        supervisor_next_host_op_kind(
            supervisor_host_op_kind_arm_host_timer(),
            timer_record.as_mut_ptr() as u32,
            timer_record.len() as u32
        ),
        supervisor_host_op_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&timer_record, 12),
        supervisor_host_op_kind_arm_host_timer()
    );

    let mut clone_record = [0u8; 64];
    assert_eq!(
        supervisor_next_host_op_kind(
            supervisor_host_op_kind_spawn_thread_worker(),
            clone_record.as_mut_ptr() as u32,
            clone_record.len() as u32
        ),
        supervisor_host_op_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&clone_record, 12),
        supervisor_host_op_kind_spawn_thread_worker()
    );
    assert_eq!(supervisor_next_host_op(0, 0), 0);
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
    t.vm.x[1] = 0x1234_5678;
    t.vm.x[3] = 0x2345_6789;
    t.vm.x[27] = 0x3456_789a;
    t.vm.pc = 0x4567_89ab;
    t.vm.guest_address_profile = tidemark_kernel::abi::GUEST_ADDRESS_PROFILE_MEMORY64;
    t.vm.guest_address_limit = tidemark_kernel::abi::max_guest_window_for_base(t.base);
    t.vm.guest_memory_policy_limit = 0x1_0000_0000;
    t.vm.process_max_memory_pages = 123;

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
    assert_eq!(child.pc, 0x4567_89ab);
    assert_eq!(child.x[1], 0x1234_5678);
    assert_eq!(child.x[3], 0x2345_6789);
    assert_eq!(child.x[27], 0x3456_789a);
    assert_eq!(child.x[10], 0);
    assert_eq!(child.x[2], child_stack);
    assert_eq!(child.x[4], tls);
    assert_eq!(child.tls_base, tls);
    assert_eq!(child.clear_child_tid, child_tidptr);
    assert_eq!(child.sig_mask, 0x55);
    assert_eq!(child.sig_pending, 0);
    assert_eq!(child.sigaltstack_sp, 0);
    assert_eq!(child.sigaltstack_size, 0);
    assert_eq!(child.sigaltstack_flags, SS_DISABLE);
    assert_eq!(child.guest_address_profile, t.vm.guest_address_profile);
    assert_eq!(child.guest_address_limit, t.vm.guest_address_limit);
    assert_eq!(
        child.guest_memory_policy_limit,
        t.vm.guest_memory_policy_limit
    );
    assert_eq!(
        child.process_max_memory_pages,
        t.vm.process_max_memory_pages
    );

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
fn contract_spawn_from_clone_preserves_child_entry_stack_contract() {
    let mut t = TestVm::new();
    t.vm.tid = 1;
    t.vm.pc = 0x83336;
    t.vm.x[1] = 0x4d9b4;
    t.vm.x[27] = 0x00bf_dc80;

    let child_stack = t.scratch + 0x4000;
    let mp = 0x37d4_c808u64;
    let gp = 0x37d0_8e00u64;
    let fn_ptr = 0x80f30u64;
    let sentinel = 1234u64;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 8, mp);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 16, gp);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 24, fn_ptr);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 32, sentinel);
    }

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, 0, 0);
    assert!(ret > 0);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let child = unsafe { &*(child_ptr as *const ThreadState) };
    assert_eq!(child.tid, ret as i32);
    assert_eq!(child.pc, 0x83336);
    assert_eq!(child.x[1], 0x4d9b4);
    assert_eq!(child.x[2], child_stack);
    assert_eq!(child.x[10], 0);
    assert_eq!(child.x[27], 0x00bf_dc80);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 8) },
        mp
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 16) },
        gp
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 24) },
        fn_ptr
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 32) },
        sentinel
    );
}

#[test]
fn contract_spawn_from_clone_first_thread_step_preserves_child_gettid_path() {
    let mut t = TestVm::new();
    let entry_pc = 0x10002u64;
    t.vm.tid = 1;
    t.vm.pc = entry_pc;
    t.vm.x[1] = 0x4d9b4;
    t.vm.x[27] = 0x00bf_dc80;

    let mapped = t.sys_mmap(
        0x10000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(mapped, 0x10000);

    // Synthetic RISC-V child continuation:
    // beq zero,a0, sentinel check, gettid, load child context from stack.
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc, 0x00a0_0563);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x0a, 0xfe01_3283);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x0e, 0x4d20_0513);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x12, 0x0055_0463);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x1a, 0x0b20_0893);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x1e, 0x0000_0073);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x22, 0xfe81_3383);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x26, 0xff01_3303);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x2a, 0xff81_3283);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x2e, 0x0050_0963);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x32, 0x0060_0763);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x36, 0x04a2_b023);
        tidemark_kernel::guest_mem::write_u32(t.base, entry_pc + 0x3a, 0x0253_3823);
        tidemark_kernel::guest_mem::write_u16(t.base, entry_pc + 0x3e, 0x8d9a);
    }

    let child_stack = t.scratch + 0x5000;
    let mp = t.scratch + 0x5400;
    let g = t.scratch + 0x5800;
    let fn_ptr = 0x80f30u64;
    let sentinel = 1234u64;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 8, mp);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 16, g);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 24, fn_ptr);
        tidemark_kernel::guest_mem::write_u64(t.base, child_stack - 32, sentinel);
        tidemark_kernel::guest_mem::write_u64(t.base, mp + 64, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, g + 48, 0);
    }

    let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
    let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, 0, 0);
    assert!(ret > 0);

    let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
    assert_ne!(child_ptr, 0);

    let remaining = tidemark_kernel::abi::thread_step(child_ptr, 14);
    assert_eq!(remaining, 0);

    let child = unsafe { &*(child_ptr as *const ThreadState) };
    assert_eq!(child.status, STATUS_OK);
    assert_eq!(child.pc, entry_pc + 0x40);
    assert_eq!(child.x[10], ret as u64);
    assert_eq!(child.x[27], g);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 8) },
        mp
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 16) },
        g
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 24) },
        fn_ptr
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, child_stack - 32) },
        sentinel
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, mp + 64) },
        ret as u64
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, g + 48) },
        mp
    );
}
