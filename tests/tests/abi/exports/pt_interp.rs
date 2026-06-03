use super::support::*;

#[test]
fn process_create_with_pt_interp_preserves_executable_entry_in_auxv() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-interp\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x3000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );
    assert!(find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_PHDR).is_some());
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_HWCAP),
        Some(0x112D)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_CLKTCK),
        Some(100)
    );
}

#[test]
fn process_create_with_pt_interp_follows_symlink_path() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/usr/lib/ld-test.so", &interp, 0o755);
    assert_ne!(memfs::create_symlink(1, b"lib", b"usr/lib"), 0);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-interp\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);
    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x3000);
}

#[test]
fn process_create_with_pt_interp_preserves_executable_tls_base() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let elf = build_test_elf_with_interp_and_tls(
        &[0x13, 0x05, 0x70, 0x00],
        b"/lib/ld-test.so",
        &[0x41, 0x42, 0x43, 0x44],
        0x20,
    );
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x800,
            b"/bin/test-interp-tls\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x800);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x5000);
    assert_eq!(vm.tls_base, 0x3000);
    assert_eq!(vm.x[4], 0x3000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1300)
    );
}

#[test]
fn process_create_with_pt_interp_preserves_biased_dynamic_tls_base() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let elf = build_test_elf_dyn_with_interp_and_tls(
        &[0x13, 0x05, 0x70, 0x00],
        b"/lib/ld-test.so",
        &[0x41, 0x42, 0x43, 0x44],
        0x20,
    );
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x800,
            b"/bin/test-dyn-interp-tls\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x800);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x6000);
    assert_eq!(vm.tls_base, 0x4000);
    assert_eq!(vm.x[4], 0x4000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x2300)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x5000)
    );
}

#[test]
fn process_create_with_pt_interp_accepts_et_dyn_interpreter() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp = build_test_elf_dyn(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-dyn-interp\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x3000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );
    let mut code = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, vm.pc, &mut code);
    }
    assert_eq!(code, [0x13, 0x05, 0x70, 0x00]);
}

#[test]
fn process_create_with_pt_interp_accepts_et_dyn_two_load_interpreter() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp = build_test_elf_dyn_two_loads(&[0x13, 0x05, 0x70, 0x00], &[0xaa, 0xbb, 0xcc, 0xdd]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-dyn-two-load-interp\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x3000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );
}

#[test]
fn process_create_with_pt_interp_biases_et_dyn_main_executable() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let elf = build_test_elf_dyn_with_interp(&main_code, b"/lib/ld-test.so");
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-dyn-main\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x4000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x2200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_PHDR),
        Some(0x2040)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x3000)
    );

    let mut interp = [0u8; 32];
    let interp_len =
        unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, 0x2100, &mut interp) };
    assert_eq!(&interp[..interp_len], b"/lib/ld-test.so");

    let mut code = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, 0x2200, &mut code);
    }
    assert_eq!(code, main_code);
}

#[test]
fn process_create_with_pt_interp_biases_et_dyn_two_load_main_executable() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_data = [0xaa, 0xbb, 0xcc, 0xdd];
    let elf = build_test_elf_dyn_with_interp_two_loads(&main_code, &main_data, b"/lib/ld-test.so");
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-dyn-two-load-main\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x6000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x2200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_PHDR),
        Some(0x2040)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x5000)
    );

    let mut data = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, 0x4000, &mut data);
    }
    assert_eq!(data, main_data);
}

#[test]
fn process_create_with_pt_interp_preserves_biased_main_dynamic_section() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let elf = build_test_elf_dyn_with_interp_dynamic(
        &[0x13, 0x05, 0x70, 0x00],
        &[0xaa, 0xbb, 0xcc, 0xdd],
        b"/lib/ld-test.so",
    );
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-dyn-dynamic\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x6000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x2200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_PHDR),
        Some(0x2040)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x5000)
    );

    let dyn_base = 0x4020u64;
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base) },
        7
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 8) },
        0x3300
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 16) },
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 24) },
        24
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 32) },
        0x6fff_ffff
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 40) },
        5
    );
}

#[test]
fn process_create_with_pt_interp_zero_fills_interpreter_brk_padding() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_elf = build_test_elf_with_interp(&main_code, b"/lib/ld-test.so");
    let interp_elf = build_test_elf_dyn_low(&[0x13, 0x06, 0x80, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp_elf, 0o755);

    let dirty_addr = 0x2ff0u64;
    assert!(unsafe {
        tidemark_kernel::syscall::memory::ensure_guest_memory_capacity(guest_base, dirty_addr + 16)
    });
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(guest_base, dirty_addr, &[0xa5; 16]);
    }

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &main_elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-pad\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, main_elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let mut padding = [0u8; 16];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, dirty_addr, &mut padding);
    }
    assert_eq!(padding, [0u8; 16]);
}

#[test]
fn process_create_with_pt_interp_maps_main_executable_image() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = test_process_guest_base();
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_elf = build_test_elf_with_interp(&main_code, b"/lib/ld-test.so");
    let interp_elf = build_test_elf_dyn_low(&[0x13, 0x06, 0x80, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp_elf, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &main_elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-main-mapped\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = test_process_create(elf_ptr, main_elf.len() as u32, ram_size as u64, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x2040);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );

    let mut interp = [0u8; 32];
    let interp_len =
        unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, 0x1100, &mut interp) };
    assert_eq!(&interp[..interp_len], b"/lib/ld-test.so");

    let mut code = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, 0x1200, &mut code);
    }
    assert_eq!(code, main_code);
}
