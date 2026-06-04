use super::support::*;

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

fn dispatch_openat_marks_fork_shared_ofd_sync_effect_without_harness_trace() {
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
        STATUS_OK
    );
    assert!(t.vm.x[10] as i64 >= 3);
    assert_ne!(
        t.vm.completed_sync_effects & SYNC_EFFECT_FORK_SHARED_OFD_STATE,
        0
    );
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

    assert_eq!(
        fs::resume_from_fs(
            (&mut vm2 as *mut tidemark_kernel::types::ThreadState) as u32,
            t.base
        ),
        0
    );
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
