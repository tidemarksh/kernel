use super::support::*;
use tidemark_kernel::syscall::fs::FS_EFFECT_SHARED_OFD_STATE;

fn encode_i(opcode: u32, rd: u32, funct3: u32, rs1: u32, imm: i32) -> u32 {
    (((imm as u32) & 0x0fff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

#[test]
fn resume_from_fs_rejects_unbacked_fs_ring_base() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let invalid_ring_base = tidemark_kernel::wasm::memory_size_bytes().saturating_sub(4) as u32;
    let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;

    unsafe {
        tidemark_kernel::guest_mem::write_u32(
            t.base,
            t.vm.process_ptr as u64 + fs_ring_off,
            invalid_ring_base,
        );
    }

    let ret = fs::resume_from_fs(vm_ptr, t.base);

    assert_eq!(ret, ENOMEM);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn thread_step_defers_openat_to_fs_control_before_resuming_remaining_ops() {
    let mut t = TestVm::new();
    t.memfs.create_file(b"shared-open.txt", b"contents");
    let path_addr = t.write_path(0x5800, b"/shared-open.txt");
    let code_addr = t.sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    ) as u64;
    assert!(code_addr > 0);

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr, 0x0000_0073); // ecall
        tidemark_kernel::guest_mem::write_u32(
            t.base,
            code_addr + 4,
            encode_i(0x13, 17, 0, 0, SYS_NEWFSTATAT as i32),
        );
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr + 8, encode_i(0x13, 5, 0, 0, 7));
    }

    t.vm.pc = code_addr;
    t.vm.x[10] = AT_FDCWD;
    t.vm.x[11] = path_addr;
    t.vm.x[12] = O_RDONLY as u64;
    t.vm.x[13] = 0;
    t.vm.x[17] = SYS_OPENAT;
    t.vm.status = STATUS_OK;

    let vm_ptr = &mut t.vm as *mut _ as u32;
    let remaining = tidemark_kernel::abi::thread_step(vm_ptr, 3);

    assert_eq!(remaining, 2);
    assert_eq!(t.vm.status, STATUS_FS);
    assert_eq!(t.vm.pc, code_addr + 4);
    assert_eq!(t.vm.x[5], 0);
    assert_eq!(t.vm.x[17], SYS_OPENAT);
    assert_eq!(
        fs::pending_request_effects(vm_ptr, t.base),
        FS_EFFECT_SHARED_OFD_STATE
    );

    fs::process_pending_requests(vm_ptr, t.base);
    let fd = fs::resume_from_fs(vm_ptr, t.base);
    assert!(fd >= 3);
    assert_eq!(tidemark_kernel::abi::thread_step(vm_ptr, remaining), 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code_addr + 12);
    assert_eq!(t.vm.x[10] as i64, fd);
    assert_eq!(t.vm.x[5], 7);
    assert_eq!(t.vm.x[17], SYS_NEWFSTATAT);
}

#[test]
fn thread_step_defers_regular_file_read_and_close_boundaries() {
    let mut t = TestVm::new();
    t.memfs.create_file(b"regular-boundary.txt", b"ruby");
    let fd = t.sys_openat(b"/regular-boundary.txt", O_RDONLY as i32);
    assert!(fd >= 3);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    let _ =
        tidemark_kernel::abi::supervisor_thread_take_completed_sync_effects(vm_ptr, t.vm.status);

    let buf_addr = t.scratch + 0x6200;
    let code_addr = t.sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    ) as u64;
    assert!(code_addr > 0);

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr, 0x0000_0073); // read ecall
        tidemark_kernel::guest_mem::write_u32(
            t.base,
            code_addr + 4,
            encode_i(0x13, 17, 0, 0, SYS_CLOSE as i32),
        );
        tidemark_kernel::guest_mem::write_u32(
            t.base,
            code_addr + 8,
            encode_i(0x13, 10, 0, 0, fd as i32),
        );
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr + 12, 0x0000_0073); // close ecall
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr + 16, encode_i(0x13, 5, 0, 0, 9));
    }

    t.vm.pc = code_addr;
    t.vm.x[10] = fd as u64;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 4;
    t.vm.x[17] = SYS_READ;
    t.vm.status = STATUS_OK;

    let remaining = tidemark_kernel::abi::thread_step(vm_ptr, 5);

    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code_addr + 20);
    assert_eq!(t.vm.x[5], 9);
    assert!(fd_table::get_ofd(t.base, &t.vm, fd as u64).is_none());
    let mut out = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf_addr, &mut out);
    }
    assert_eq!(&out, b"ruby");
    let effects =
        tidemark_kernel::abi::supervisor_thread_take_completed_sync_effects(vm_ptr, t.vm.status);
    assert_ne!(effects & SYNC_EFFECT_FORK_SHARED_OFD_STATE, 0);
}

#[test]
fn thread_step_keeps_pipe_close_as_runtime_boundary() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x6600;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
        0
    );
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as u64;

    let vm_ptr = &mut t.vm as *mut _ as u32;
    let _ =
        tidemark_kernel::abi::supervisor_thread_take_completed_sync_effects(vm_ptr, t.vm.status);

    let code_addr = t.sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    ) as u64;
    assert!(code_addr > 0);

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr, 0x0000_0073); // close ecall
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr + 4, encode_i(0x13, 5, 0, 0, 11));
    }

    t.vm.pc = code_addr;
    t.vm.x[10] = write_fd;
    t.vm.x[17] = SYS_CLOSE;
    t.vm.status = STATUS_OK;

    let remaining = tidemark_kernel::abi::thread_step(vm_ptr, 2);

    assert_eq!(remaining, 1);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code_addr + 4);
    assert_eq!(t.vm.x[5], 0);
    let effects =
        tidemark_kernel::abi::supervisor_thread_take_completed_sync_effects(vm_ptr, t.vm.status);
    assert_ne!(effects & SYNC_EFFECT_PIPE_STATE, 0);
    assert_ne!(effects & SYNC_EFFECT_FORK_SHARED_OFD_STATE, 0);
}

#[test]
fn dispatch_mmap_uses_local_resident_file_hit() {
    let mut t = TestVm::new();
    t.memfs.create_file(b"resident-map.txt", b"map-data");
    let fd = t.sys_openat(b"/resident-map.txt", O_RDONLY as i32);
    assert!(fd >= 3);

    let result = fs::dispatch_mmap(
        &mut t.vm,
        t.base,
        0,
        4096,
        PROT_READ as u64,
        MAP_PRIVATE,
        fd,
        0,
    );

    assert!(result > 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.guest_mem(result as u64, 8), b"map-data".to_vec());
}

#[test]
fn dispatch_mmap_falls_back_to_fs_ring_on_external_file_miss() {
    let mut t = TestVm::new();
    let ino = memfs::create_file(1, b"external-map.txt", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::set_file_external(ino, 8192), 0);
    let fd = t.sys_openat(b"/external-map.txt", O_RDONLY as i32);
    assert!(fd >= 3);

    let result = fs::dispatch_mmap(
        &mut t.vm,
        t.base,
        0,
        4096,
        PROT_READ as u64,
        MAP_PRIVATE,
        fd,
        0,
    );

    assert_eq!(result, 0);
    assert_eq!(t.vm.status, STATUS_FS);
}

#[test]
fn dispatch_openat_exposes_fork_shared_ofd_effect_to_fs_control() {
    let mut t = TestVm::new();
    t.memfs.create_file(b"shared-open.txt", b"contents");
    let path_addr = t.write_path(0x5800, b"/shared-open.txt");

    t.vm.x[10] = AT_FDCWD;
    t.vm.x[11] = path_addr;
    t.vm.x[12] = O_RDONLY as u64;
    t.vm.x[13] = 0;
    t.vm.x[17] = SYS_OPENAT;

    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_FS
    );
    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(
        fs::pending_request_effects(vm_ptr, t.base),
        FS_EFFECT_SHARED_OFD_STATE
    );
    fs::process_pending_requests(vm_ptr, t.base);
    let fd = fs::resume_from_fs(vm_ptr, t.base);
    assert!(fd >= 3);
}

#[test]
fn fs_ring_routes_mkdir_completions_to_the_owning_thread() {
    let t = TestVm::new();

    let mut vm1: tidemark_kernel::types::ThreadState = unsafe { core::mem::zeroed() };
    vm1.guest_base = t.base;
    vm1.process_ptr = t.vm.process_ptr;
    vm1.status = STATUS_OK;

    let mut vm2: tidemark_kernel::types::ThreadState = unsafe { core::mem::zeroed() };
    vm2.guest_base = t.base;
    vm2.process_ptr = t.vm.process_ptr;
    vm2.status = STATUS_OK;

    let path1 = t.write_path(0x9000, b"/thread-one");
    let path2 = t.write_path(0x9100, b"/thread-two");

    assert_eq!(
        fs::dispatch_mkdirat(&mut vm1, t.base, AT_FDCWD, path1, 0o755),
        0
    );
    assert_eq!(vm1.status, STATUS_FS);
    assert_eq!(
        fs::dispatch_mkdirat(&mut vm2, t.base, AT_FDCWD, path2, 0o755),
        0
    );
    assert_eq!(vm2.status, STATUS_FS);

    fs::process_pending_requests(
        (&mut vm1 as *mut tidemark_kernel::types::ThreadState) as u32,
        t.base,
    );

    let vm2_ptr = (&mut vm2 as *mut tidemark_kernel::types::ThreadState) as u32;
    assert_eq!(fs::resume_from_fs(vm2_ptr, t.base), EAGAIN);
    assert_eq!(vm2.status, STATUS_FS);
    fs::process_pending_requests(vm2_ptr, t.base);
    assert_eq!(fs::resume_from_fs(vm2_ptr, t.base), 0);
    assert_eq!(vm2.status, STATUS_OK);
    assert_eq!(
        fs::resume_from_fs(
            (&mut vm1 as *mut tidemark_kernel::types::ThreadState) as u32,
            t.base
        ),
        0
    );
    assert_eq!(vm1.status, STATUS_OK);

    assert!(memfs::resolve_path(b"/thread-one") > 0);
    assert!(memfs::resolve_path(b"/thread-two") > 0);
}

#[test]
fn pipe_writev_marks_pipe_sync_effect() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x7300;
    let buf_a = t.scratch + 0x7400;
    let buf_b = t.scratch + 0x7500;
    let iov_addr = t.scratch + 0x7600;

    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
        0
    );
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as i64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;

    t.write_mem(buf_a, b"pipe-");
    t.write_mem(buf_b, b"sync");
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr, buf_a);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 8, 5);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 16, buf_b);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 24, 4);
    }

    let written = fs::sys_write(&mut t.vm, t.base, write_fd as u64, iov_addr, 2, SYS_WRITEV);
    assert_eq!(written, 9);
    assert_ne!(t.vm.completed_sync_effects & SYNC_EFFECT_PIPE_STATE, 0);
    let pipe_slot = fd_table::get_ofd(t.base, &t.vm, write_fd as u64)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pipe_slot > 0 && pipe_slot < 64);
    assert_ne!(t.vm.completed_pipe_sync_slots & (1u64 << pipe_slot), 0);

    let mut out = [0u8; 16];
    assert_eq!(t.sys_read(read_fd, &mut out), 9);
    assert_eq!(&out[..9], b"pipe-sync");
}

#[test]
fn pipe_close_marks_pipe_control_sync_effect() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x7700;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
        0
    );
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as u64;
    let pipe_slot = fd_table::get_ofd(t.base, &t.vm, write_fd)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    t.vm.completed_pipe_sync_slots = 0;
    t.vm.completed_pipe_sync_control_slots = 0;

    assert_eq!(fd_table::sys_close(&mut t.vm, t.base, write_fd), 0);

    let bit = 1u64 << pipe_slot;
    assert_ne!(t.vm.completed_pipe_sync_slots & bit, 0);
    assert_ne!(t.vm.completed_pipe_sync_control_slots & bit, 0);
}

#[test]
fn process_exit_close_all_marks_pipe_control_sync_effect() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x7800;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
        0
    );
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as u64;
    let pipe_slot = fd_table::get_ofd(t.base, &t.vm, write_fd)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    t.vm.completed_pipe_sync_slots = 0;
    t.vm.completed_pipe_sync_control_slots = 0;

    fd_table::close_all_for_process(t.base, &mut t.vm);

    let bit = 1u64 << pipe_slot;
    assert_ne!(t.vm.completed_pipe_sync_slots & bit, 0);
    assert_ne!(t.vm.completed_pipe_sync_control_slots & bit, 0);
}
