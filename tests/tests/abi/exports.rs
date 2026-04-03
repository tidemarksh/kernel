use std::vec;
use tidemark_kernel::abi::*;
use tidemark_kernel::harness::TestVm;

fn ensure_dir(parent: u32, name: &[u8]) -> u32 {
    let ino = tidemark_kernel::fs::memfs::lookup(parent, name);
    if ino != 0 {
        ino
    } else {
        tidemark_kernel::fs::memfs::create_dir(parent, name, 0o755)
    }
}

fn build_test_elf_with_tls(code: &[u8], tls_init: &[u8], tls_memsz: u64) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let code_off = 0x100usize;
    let data_off = 0x200usize;
    let entry = 0x1000u64 + code_off as u64;
    let code_filesz = (code_off + code.len()) as u64;
    let data_vaddr = 0x3000u64;
    let data_filesz = tls_init.len() as u64;
    let data_memsz = tls_memsz.max(data_filesz);
    let total_len = data_off + tls_init.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 3);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code_filesz);
    put_u64(&mut elf, 104, code_filesz);
    put_u64(&mut elf, 112, 0x1000);

    put_u32(&mut elf, 120, 1);
    put_u32(&mut elf, 124, 6);
    put_u64(&mut elf, 128, data_off as u64);
    put_u64(&mut elf, 136, data_vaddr);
    put_u64(&mut elf, 152, data_filesz);
    put_u64(&mut elf, 160, data_memsz);
    put_u64(&mut elf, 168, 0x1000);

    put_u32(&mut elf, 176, 7);
    put_u32(&mut elf, 180, 4);
    put_u64(&mut elf, 184, data_off as u64);
    put_u64(&mut elf, 192, data_vaddr);
    put_u64(&mut elf, 208, data_filesz);
    put_u64(&mut elf, 216, tls_memsz);
    put_u64(&mut elf, 224, 8);

    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + tls_init.len()].copy_from_slice(tls_init);
    elf
}

fn build_test_elf_dyn(code: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut elf = vec![0u8; 0x100 + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x1000);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0x100);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[0x100..0x100 + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_exec_at(code: &[u8], entry: u64, vaddr: u64) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut elf = vec![0u8; 0x100 + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0x100);
    put_u64(&mut elf, 80, vaddr);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[0x100..0x100 + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_dyn_with_interp(code: &[u8], interp: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let code_off = 0x100usize;
    let interp_off = 0x200usize;
    let total_len = interp_off + interp.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x1000);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 2);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, code_off as u64);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);

    put_u32(&mut elf, 120, 3);
    put_u32(&mut elf, 124, 4);
    put_u64(&mut elf, 128, interp_off as u64);
    put_u64(&mut elf, 136, 0);
    put_u64(&mut elf, 152, interp.len() as u64);
    put_u64(&mut elf, 160, interp.len() as u64);
    put_u64(&mut elf, 168, 1);

    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[interp_off..interp_off + interp.len()].copy_from_slice(interp);
    elf
}

fn auxv_value(guest_base: u32, sp: u64, argc: usize, envc: usize, tag: u64) -> Option<u64> {
    let mut cursor = sp + ((1 + argc + 1 + envc + 1) as u64) * 8;
    for _ in 0..32 {
        let cur_tag = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, cursor) };
        let cur_val = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, cursor + 8) };
        if cur_tag == tidemark_kernel::elf::AT_NULL {
            return None;
        }
        if cur_tag == tag {
            return Some(cur_val);
        }
        cursor += 16;
    }
    None
}

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
fn process_create_initializes_tp_from_pt_tls() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let elf = build_test_elf_with_tls(&[0x13, 0x05, 0x70, 0x00], &[0x41, 0x42, 0x43, 0x44], 0x20);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.tls_base, 0x3000);
    assert_eq!(vm.x[4], 0x3000);
}

#[test]
fn process_create_accepts_et_dyn_without_pt_interp() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let elf = build_test_elf_dyn(&[0x13, 0x05, 0x70, 0x00]);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-dyn\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x1000);
}

#[test]
fn process_create_enters_pt_interp_loader() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let main_elf = build_test_elf_dyn_with_interp(
        &[0x13, 0x05, 0x70, 0x00],
        b"/lib/ld-test.so\0",
    );
    let interp_elf = build_test_elf_exec_at(&[0x13, 0x05, 0x70, 0x00], 0x4100, 0x4000);

    let lib_ino = ensure_dir(1, b"lib");
    let interp_ino = tidemark_kernel::fs::memfs::create_file(lib_ino, b"ld-test.so", 0o755);
    assert_ne!(interp_ino, 0);
    assert_eq!(
        tidemark_kernel::fs::memfs::write_file(interp_ino, 0, &interp_elf),
        interp_elf.len() as i64
    );

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x2000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &main_elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-dyn\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, main_elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let guest_base = process_guest_base(ram_size);
    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x4100);
    assert_eq!(
        auxv_value(guest_base, vm.x[2], 1, 0, tidemark_kernel::elf::AT_BASE),
        Some(0x3f00)
    );
    assert_eq!(
        auxv_value(guest_base, vm.x[2], 1, 0, tidemark_kernel::elf::AT_ENTRY),
        Some(0x1000)
    );
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
