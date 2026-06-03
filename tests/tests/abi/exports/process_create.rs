use super::support::*;

#[test]
fn spawn_handoff_exports_round_trip() {
    let mut t = TestVm::new();
    let mut elf = vec![0u8; 0x104];
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&243u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[96..104].copy_from_slice(&4u64.to_le_bytes());
    elf[104..112].copy_from_slice(&4u64.to_le_bytes());
    elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[0x100..0x104].copy_from_slice(&[0x13, 0x05, 0x70, 0x00]);

    let ino = tidemark_kernel::fs::memfs::create_file(1, b"test", 0o755);
    assert_ne!(ino, 0);
    assert_eq!(
        tidemark_kernel::fs::memfs::write_file(ino, 0, &elf),
        elf.len() as i64
    );
    let path_addr = t.scratch;
    t.write_mem(path_addr, b"/test\0");

    tidemark_kernel::syscall::process::sys_vfork(&mut t.vm, t.base);
    let ret =
        tidemark_kernel::syscall::process::sys_execve(&mut t.vm, t.base, path_addr, 0x1111, 0x2222);
    assert!(ret > 0);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_EXECVE);
    assert_eq!(thread_spawn_child_pid(vm_ptr), ret as i32);
    assert_eq!(thread_spawn_path(vm_ptr), path_addr);
    assert_eq!(thread_spawn_argv(vm_ptr), 0x1111);
    assert_eq!(thread_spawn_envp(vm_ptr), 0x2222);

    thread_set_guest_memory_policy_limit(vm_ptr, 0x12345678);
    assert_eq!(thread_guest_memory_policy_limit(vm_ptr), 0x12345678);

    thread_set_guest_memory_policy_limit(vm_ptr, 0x1_0000_0000);
    assert_eq!(thread_guest_memory_policy_limit(vm_ptr), 0x1_0000_0000);

    thread_set_execve_memory_handoff(
        vm_ptr,
        0x4444,
        0xAAAA,
        0xBBBB,
        0xCCCC,
        abi_guest_address_profile_target(),
        0x3333,
        456,
    );
    assert_eq!(thread_process_ptr(vm_ptr), 0x4444);
    assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_EXECVE);
    assert_eq!(thread_spawn_path(vm_ptr), 0xAAAA);
    assert_eq!(thread_spawn_argv(vm_ptr), 0xBBBB);
    assert_eq!(thread_spawn_envp(vm_ptr), 0xCCCC);
    assert_eq!(
        thread_spawn_address_profile(vm_ptr),
        abi_guest_address_profile_target(),
    );
    assert_eq!(thread_spawn_guest_memory_policy_limit(vm_ptr), 0x3333);
    assert_eq!(thread_spawn_process_max_memory_pages(vm_ptr), 456);

    thread_set_execve_memory_handoff(
        vm_ptr,
        0x5555,
        0xAAAA,
        0xBBBB,
        0xCCCC,
        abi_guest_address_profile_target(),
        0x1_0000_0000,
        123,
    );
    assert_eq!(thread_process_ptr(vm_ptr), 0x5555);
    assert_eq!(thread_spawn_guest_memory_policy_limit(vm_ptr), 0x1_0000_0000);
    assert_eq!(thread_spawn_process_max_memory_pages(vm_ptr), 123);

    thread_clear_spawn_handoff(vm_ptr);
    assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_NONE);
    assert_eq!(thread_spawn_child_pid(vm_ptr), 0);
    assert_eq!(thread_spawn_path(vm_ptr), 0);
    assert_eq!(thread_spawn_guest_memory_policy_limit(vm_ptr), 0);
}

#[test]
fn target_address_profile_is_memory64() {
    let _t = TestVm::new();
    let memory64_profile = abi_guest_address_profile_memory64();
    let target_profile = abi_guest_address_profile_target();

    assert_ne!(memory64_profile, 0);
    assert_eq!(target_profile, memory64_profile);
    let target_base = process_guest_base_for_address_profile(target_profile);
    assert_ne!(target_base, 0);
    let target_limit = process_guest_address_limit_for_profile(target_profile, target_base);
    assert!(target_limit > u32::MAX as u64);
}

#[test]
fn resume_vfork_parent_export_restores_parent_view() {
    let mut t = TestVm::new();
    t.vm.x[1] = 0x1234;
    t.vm.pc = 0x4000;
    tidemark_kernel::syscall::process::sys_vfork(&mut t.vm, t.base);
    t.vm.x[1] = 0xFFFF;
    t.vm.pc = 0x9000;

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    thread_resume_vfork_parent(vm_ptr, 55);
    assert_eq!(t.vm.x[1], 0x1234);
    assert_eq!(t.vm.pc, 0x4000);
    assert_eq!(t.vm.x[10], 55);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn process_create_populates_initial_stack_contract() {
    let _t = TestVm::new();
    let guest_memory_policy_limit = 64 * 1024 * 1024;
    let stack_size = 1024 * 1024;
    let guest_base = test_process_guest_base();
    assert_ne!(guest_base, 0);

    let mut elf = vec![0u8; 0x104];
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&243u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[96..104].copy_from_slice(&4u64.to_le_bytes());
    elf[104..112].copy_from_slice(&4u64.to_le_bytes());
    elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[0x100..0x104].copy_from_slice(&[0x13, 0x05, 0x70, 0x00]);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test\0");
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x420, b"hello\0");
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x440, b"FOO=bar\0");
    }

    let arg0_ptr = elf_ptr + 0x400;
    let arg1_ptr = elf_ptr + 0x420;
    let env0_ptr = elf_ptr + 0x440;

    process_clear_args();
    process_push_arg(arg0_ptr);
    process_push_arg(arg1_ptr);
    process_push_env(env0_ptr);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, guest_memory_policy_limit as u64, stack_size);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    let sp = vm.x[2];
    assert_eq!(sp & 0xf, 0, "initial sp must stay 16-byte aligned");

    let argc = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp) };
    assert_eq!(argc, 2);

    let argv0 = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 8) };
    let argv1 = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 16) };
    let argv_null = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 24) };
    let env0 = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 32) };
    let env_null = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 40) };

    assert_ne!(argv0, 0);
    assert_ne!(argv1, 0);
    assert_eq!(argv_null, 0);
    assert_ne!(env0, 0);
    assert_eq!(env_null, 0);

    let mut buf = [0u8; 32];
    let argv0_len = unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, argv0, &mut buf) };
    assert_eq!(&buf[..argv0_len], b"/bin/test");
    let argv1_len = unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, argv1, &mut buf) };
    assert_eq!(&buf[..argv1_len], b"hello");
    let env0_len = unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, env0, &mut buf) };
    assert_eq!(&buf[..env0_len], b"FOO=bar");

    let auxv_start = sp + 48;
    let aux_pagesz_tag = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, auxv_start) };
    let aux_pagesz_val =
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, auxv_start + 8) };
    assert_eq!(aux_pagesz_tag, tidemark_kernel::elf::AT_PAGESZ);
    assert_eq!(aux_pagesz_val, 4096);

    let mut found_random = false;
    let mut found_execfn = false;
    let mut found_hwcap = false;
    let mut found_clktck = false;
    let mut cursor = auxv_start;
    for _ in 0..16 {
        let tag = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, cursor) };
        let val = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, cursor + 8) };
        if tag == tidemark_kernel::elf::AT_NULL {
            break;
        }
        if tag == tidemark_kernel::elf::AT_RANDOM {
            found_random = true;
            assert_ne!(val, 0);
        }
        if tag == tidemark_kernel::elf::AT_EXECFN {
            found_execfn = true;
            let mut execfn = [0u8; 32];
            let execfn_len =
                unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, val, &mut execfn) };
            assert_eq!(&execfn[..execfn_len], b"/bin/test");
        }
        if tag == tidemark_kernel::elf::AT_HWCAP {
            found_hwcap = true;
            assert_eq!(val, 0x112D);
        }
        if tag == tidemark_kernel::elf::AT_CLKTCK {
            found_clktck = true;
            assert_eq!(val, 100);
        }
        cursor += 16;
    }
    assert!(found_random, "AT_RANDOM must be present in auxv");
    assert!(found_execfn, "AT_EXECFN must be present in auxv");
    assert!(found_hwcap, "AT_HWCAP must be present in auxv");
    assert!(found_clktck, "AT_CLKTCK must be present in auxv");
}

#[test]
fn process_create_with_memory_policy_initializes_memory_contract() {
    let _t = TestVm::new();
    let guest_memory_policy_limit = 64 * 1024 * 1024u64;
    let stack_size = 1024 * 1024;
    let address_profile = abi_guest_address_profile_target();
    let guest_base = process_guest_base_for_address_profile(address_profile);
    assert_ne!(guest_base, 0);
    assert_ne!(
        process_guest_address_limit_for_profile(address_profile, guest_base),
        0,
    );

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
    }

    process_clear_args();
    let vm_ptr = process_create_with_memory_policy(
        elf_ptr,
        elf.len() as u32,
        address_profile,
        guest_memory_policy_limit,
        2048,
        stack_size,
    );
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.guest_address_profile, address_profile);
    assert_eq!(vm.guest_memory_policy_limit, guest_memory_policy_limit);
    assert_eq!(vm.process_max_memory_pages, 2048);
    assert_eq!(thread_guest_address_profile(vm_ptr), address_profile);
    assert_eq!(thread_guest_memory_policy_limit(vm_ptr), guest_memory_policy_limit);
    assert_eq!(thread_guest_memory_policy_limit(vm_ptr), guest_memory_policy_limit);
    assert_eq!(thread_process_max_memory_pages(vm_ptr), 2048);
}

#[test]
fn process_create_memory64_policy_accepts_above_wasm32_range() {
    let _t = TestVm::new();
    let policy_limit = 0x1_0000_0000u64;
    let stack_size = 1024 * 1024;
    let address_profile = abi_guest_address_profile_target();
    let guest_base = process_guest_base_for_address_profile(address_profile);
    assert_ne!(guest_base, 0);
    assert!(process_guest_address_limit_for_profile(address_profile, guest_base) > u32::MAX as u64);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
    }

    process_clear_args();
    let vm_ptr = process_create_with_memory_policy(
        elf_ptr,
        elf.len() as u32,
        address_profile,
        policy_limit,
        2048,
        stack_size,
    );
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.guest_address_profile, address_profile);
    assert_eq!(vm.guest_memory_policy_limit, policy_limit);
    assert_eq!(thread_guest_memory_policy_limit(vm_ptr), policy_limit);
}

#[test]
fn process_create_keeps_initial_stack_compact_for_large_ram_limit() {
    let _t = TestVm::new();
    let guest_memory_policy_limit = 512 * 1024 * 1024;
    let stack_size = 1024 * 1024;
    let guest_base = test_process_guest_base();
    assert_ne!(guest_base, 0);

    let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
    }

    process_clear_args();
    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, guest_memory_policy_limit as u64, stack_size);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.guest_memory_policy_limit, guest_memory_policy_limit as u64);
    assert!(
        vm.x[2] < (guest_memory_policy_limit as u64 / 2),
        "initial stack should not force materializing the full RAM window: sp=0x{:x}",
        vm.x[2],
    );

    let mut stack_vma_end = 0;
    for index in 0..tidemark_kernel::harness::memory::debug_vma_len() {
        let start = tidemark_kernel::harness::memory::debug_vma_start(index);
        let end = tidemark_kernel::harness::memory::debug_vma_end(index);
        let prot = tidemark_kernel::harness::memory::debug_vma_prot(index);
        if start <= vm.x[2] && vm.x[2] < end && prot == (PROT_READ | PROT_WRITE) {
            stack_vma_end = end;
            break;
        }
    }
    assert_ne!(stack_vma_end, 0, "initial stack VMA must cover sp");
    assert!(
        stack_vma_end < (guest_memory_policy_limit as u64 / 2),
        "stack VMA should be placed below the logical RAM ceiling: end=0x{stack_vma_end:x}",
    );
}

#[test]
fn process_guest_base_reserves_exec_scratch_headroom() {
    let _t = TestVm::new();
    let guest_base = test_process_guest_base();
    assert_ne!(guest_base, 0);

    let expected_floor =
        (((kernel_heap_ptr() as u64) + 4 * 1024 * 1024 + 256 * 1024 * 1024 + 0xF_FFFF) & !0xF_FFFF)
            as u32;
    assert_eq!(guest_base, expected_floor);
}

#[test]
fn process_create_rebases_user_brk_after_hidden_process_state() {
    let _t = TestVm::new();
    let guest_memory_policy_limit = 64 * 1024 * 1024;
    let stack_size = 1024 * 1024;
    let guest_base = test_process_guest_base();
    assert_ne!(guest_base, 0);

    let mut elf = vec![0u8; 0x104];
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&243u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[96..104].copy_from_slice(&4u64.to_le_bytes());
    elf[104..112].copy_from_slice(&4u64.to_le_bytes());
    elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[0x100..0x104].copy_from_slice(&[0x13, 0x05, 0x70, 0x00]);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);
    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, guest_memory_policy_limit as u64, stack_size);
    assert_ne!(vm_ptr, 0);

    let process_ptr = thread_process_ptr(vm_ptr) as u64;
    let ps_size = core::mem::size_of::<tidemark_kernel::types::ProcessState>() as u64;
    let hidden_end = process_ptr + ps_size;
    let public_brk =
        (hidden_end + tidemark_kernel::abi::PAGE_SIZE - 1) & !(tidemark_kernel::abi::PAGE_SIZE - 1);
    assert_eq!(tidemark_kernel::syscall::memory::current_brk(), public_brk);
    assert_eq!(
        tidemark_kernel::harness::memory::debug_brk_base(),
        public_brk
    );
}
