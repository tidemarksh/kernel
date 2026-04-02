use std::vec;
use tidemark_kernel::abi::*;
use tidemark_kernel::harness::TestVm;

#[test]
fn status_codes_are_distinct() {
    let codes = [
        STATUS_OK,
        STATUS_FAULT,
        STATUS_FS,
        STATUS_FUTEX_WAIT,
        STATUS_PIPE_WAIT,
        STATUS_EPOLL_WAIT,
        STATUS_VFORK_WAIT,
        STATUS_EXECVE_SPAWN,
        STATUS_CLONE_SPAWN,
        STATUS_SLEEP,
        STATUS_JIT_READY,
        STATUS_CONNECT,
        STATUS_SOCKET_SEND,
        STATUS_SOCKET_RECV,
        STATUS_WAIT4,
        STATUS_FLOCK_WAIT,
    ];
    for i in 0..codes.len() {
        for j in (i + 1)..codes.len() {
            assert_ne!(codes[i], codes[j]);
        }
    }
}

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
    assert_eq!(tidemark_kernel::fs::memfs::write_file(ino, 0, &elf), elf.len() as i64);
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

    thread_set_execve_handoff(vm_ptr, 0x4444, 0xAAAA, 0xBBBB, 0xCCCC);
    assert_eq!(thread_process_ptr(vm_ptr), 0x4444);
    assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_EXECVE);
    assert_eq!(thread_spawn_path(vm_ptr), 0xAAAA);
    assert_eq!(thread_spawn_argv(vm_ptr), 0xBBBB);
    assert_eq!(thread_spawn_envp(vm_ptr), 0xCCCC);

    thread_clear_spawn_handoff(vm_ptr);
    assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_NONE);
    assert_eq!(thread_spawn_child_pid(vm_ptr), 0);
    assert_eq!(thread_spawn_path(vm_ptr), 0);
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
    let ram_size = 64 * 1024 * 1024;
    let stack_size = 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
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

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, stack_size);
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
        cursor += 16;
    }
    assert!(found_random, "AT_RANDOM must be present in auxv");
}

#[test]
fn fd_types_are_distinct() {
    let types = [
        FD_TYPE_NONE,
        FD_TYPE_STDOUT,
        FD_TYPE_STDERR,
        FD_TYPE_FILE,
        FD_TYPE_DIR,
        FD_TYPE_DEVNULL,
        FD_TYPE_PIPE,
        FD_TYPE_EPOLL,
        FD_TYPE_SOCKET,
        FD_TYPE_EVENTFD,
        FD_TYPE_TIMERFD,
        FD_TYPE_PTY_MASTER,
        FD_TYPE_PTY_SLAVE,
        FD_TYPE_INOTIFY,
    ];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j]);
        }
    }
}

#[test]
fn error_codes_are_negative() {
    assert!(ENOENT < 0);
    assert!(EBADF < 0);
    assert!(EINVAL < 0);
    assert!(ENOMEM < 0);
    assert!(ENOSYS < 0);
}

#[test]
fn clone_flags_no_overlap() {
    assert_eq!(CLONE_VM & CLONE_THREAD, 0);
    assert_eq!(CLONE_VM & CLONE_VFORK, 0);
    assert_eq!(CLONE_THREAD & CLONE_VFORK, 0);
}
