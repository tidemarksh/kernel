use tidemark_kernel::abi::{EAGAIN, O_CREAT, O_RDONLY, O_RDWR};
use tidemark_kernel::fs::ring_buffer::{
    FS_OP_FSYNC, FS_OP_MKDIR, FS_OP_RENAME, FS_OP_WRITE, HEADER_SIZE, OFF_COMPLETE_HEAD,
    OFF_CQ_LOCK, OFF_SQ_LOCK, OFF_SUBMIT_HEAD, REQ_SIZE, RESP_SIZE, RING_BUFFER_SIZE,
    process_requests, read_completion, submit_request,
};
use tidemark_kernel::harness::TestVm;

#[test]
fn ring_buffer_size() {
    assert_eq!(HEADER_SIZE, 32);
    assert_eq!(REQ_SIZE, 64);
    assert_eq!(RESP_SIZE, 16);
    assert_eq!(RING_BUFFER_SIZE, 32 + 64 * 64 + 64 * 16);
}

#[test]
fn ring_buffer_retries_submit_while_submission_queue_is_locked() {
    let mut t = TestVm::new();
    let ring_base = unsafe { tidemark_kernel::alloc::alloc_zeroed(RING_BUFFER_SIZE as u32, 16) };
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;

    unsafe {
        *((ring_base + OFF_SQ_LOCK) as *mut u32) = 1;
    }
    assert_eq!(
        submit_request(ring_base, FS_OP_FSYNC, -1, 0, 0, 0, 0, 0, 0, vm_ptr, 0, 0,),
        -1
    );
    assert_eq!(unsafe { *((ring_base + OFF_SUBMIT_HEAD) as *const u32) }, 0);
}

#[test]
fn ring_buffer_retries_processing_and_consumption_while_completion_queue_is_locked() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/ring_lock.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    let ring_base = unsafe { tidemark_kernel::alloc::alloc_zeroed(RING_BUFFER_SIZE as u32, 16) };
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    assert!(
        submit_request(
            ring_base,
            FS_OP_FSYNC,
            fd as i32,
            0,
            0,
            0,
            0,
            0,
            0,
            vm_ptr,
            0,
            0,
        ) >= 0
    );

    unsafe {
        *((ring_base + OFF_CQ_LOCK) as *mut u32) = 1;
    }
    process_requests(ring_base, vm_ptr, t.base);
    assert_eq!(
        unsafe { *((ring_base + OFF_COMPLETE_HEAD) as *const u32) },
        0
    );
    assert_eq!(read_completion(ring_base), EAGAIN);

    unsafe {
        *((ring_base + OFF_CQ_LOCK) as *mut u32) = 0;
    }
    process_requests(ring_base, vm_ptr, t.base);
    assert_eq!(read_completion(ring_base), 0);
}

#[test]
fn ring_buffer_dispatch_write() {
    let mut t = TestVm::new();

    let fd = t.sys_openat(b"/ring_write.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    let ring_base = unsafe { tidemark_kernel::alloc::alloc_zeroed(RING_BUFFER_SIZE as u32, 16) };
    assert!(ring_base != 0);

    let data = b"Hello ring!";
    let data_addr: u64 = t.scratch + 0xA000;
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(t.base, data_addr, data);
    }

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    let idx = submit_request(
        ring_base,
        FS_OP_WRITE,
        fd as i32,
        0,
        data.len() as u64,
        data_addr,
        0,
        0,
        0,
        vm_ptr,
        0,
        0,
    );
    assert!(idx >= 0);

    process_requests(ring_base, vm_ptr, t.base);

    let result = read_completion(ring_base);
    assert_eq!(result, data.len() as i64);

    let mut read_buf = [0u8; 32];
    let ino = tidemark_kernel::fs::memfs::resolve_path(b"/ring_write.txt");
    let nread = tidemark_kernel::fs::memfs::read_file(ino, 0, &mut read_buf);
    assert_eq!(nread, data.len() as i64);
    assert_eq!(&read_buf[..data.len()], data);
}

#[test]
fn ring_buffer_dispatch_fsync() {
    let mut t = TestVm::new();

    let fd = t.sys_openat(b"/ring_fsync.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"dirty"), 5);

    let ring_base = unsafe { tidemark_kernel::alloc::alloc_zeroed(RING_BUFFER_SIZE as u32, 16) };
    assert!(ring_base != 0);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    let idx = submit_request(
        ring_base,
        FS_OP_FSYNC,
        fd as i32,
        0,
        0,
        0,
        0,
        0,
        0,
        vm_ptr,
        0,
        0,
    );
    assert!(idx >= 0);

    process_requests(ring_base, vm_ptr, t.base);

    let result = read_completion(ring_base);
    assert_eq!(result, 0);
}

#[test]
fn ring_buffer_processes_one_requested_vm_boundary_per_call() {
    let mut t = TestVm::new();

    let fd = t.sys_openat(b"/ring_boundary.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    let ring_base = unsafe { tidemark_kernel::alloc::alloc_zeroed(RING_BUFFER_SIZE as u32, 16) };
    assert!(ring_base != 0);
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;

    for _ in 0..2 {
        assert!(
            submit_request(
                ring_base,
                FS_OP_FSYNC,
                fd as i32,
                0,
                0,
                0,
                0,
                0,
                0,
                vm_ptr,
                0,
                0,
            ) >= 0
        );
    }

    process_requests(ring_base, vm_ptr, t.base);
    assert_eq!(read_completion(ring_base), 0);
    assert_eq!(read_completion(ring_base), EAGAIN);

    process_requests(ring_base, vm_ptr, t.base);
    assert_eq!(read_completion(ring_base), 0);
    assert_eq!(read_completion(ring_base), EAGAIN);
}

#[test]
fn ring_buffer_dispatch_mkdir() {
    let mut t = TestVm::new();
    let ring_base = unsafe { tidemark_kernel::alloc::alloc_zeroed(RING_BUFFER_SIZE as u32, 16) };
    assert!(ring_base != 0);

    let path = b"/ringdir";
    let path_addr = t.write_path(0xB000, path);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    let idx = submit_request(
        ring_base,
        FS_OP_MKDIR,
        -100,
        0,
        0,
        0,
        path_addr,
        0,
        0o755,
        vm_ptr,
        0,
        0,
    );
    assert!(idx >= 0);

    process_requests(ring_base, vm_ptr, t.base);

    let result = read_completion(ring_base);
    assert_eq!(result, 0);

    let dir_ino = tidemark_kernel::fs::memfs::resolve_path(b"/ringdir");
    assert!(dir_ino > 0);
}

#[test]
fn ring_buffer_dispatch_mkdir_respects_dirfd() {
    let mut t = TestVm::new();
    let ring_base = unsafe { tidemark_kernel::alloc::alloc_zeroed(RING_BUFFER_SIZE as u32, 16) };
    assert!(ring_base != 0);

    assert_eq!(t.sys_mkdirat(b"/parent"), 0);
    let dirfd = t.sys_openat(b"/parent", O_RDONLY);
    assert!(dirfd >= 3);

    let path_addr = t.write_path(0xB100, b"child");
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    let idx = submit_request(
        ring_base,
        FS_OP_MKDIR,
        dirfd as i32,
        0,
        0,
        0,
        path_addr,
        0,
        0o755,
        vm_ptr,
        0,
        0,
    );
    assert!(idx >= 0);

    process_requests(ring_base, vm_ptr, t.base);

    let result = read_completion(ring_base);
    assert_eq!(result, 0);
    assert!(tidemark_kernel::fs::memfs::resolve_path(b"/parent/child") > 0);
    assert_eq!(tidemark_kernel::fs::memfs::resolve_path(b"/child"), 0);
}

#[test]
fn ring_buffer_dispatch_rename() {
    let mut t = TestVm::new();
    let ring_base = unsafe { tidemark_kernel::alloc::alloc_zeroed(RING_BUFFER_SIZE as u32, 16) };
    assert!(ring_base != 0);

    let fd = t.sys_openat(b"/old.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"rename"), 6);
    t.sys_close(fd);

    let old_addr = t.write_path(0xB200, b"/old.txt");
    let new_addr = t.write_path(0xB300, b"/new.txt");
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    let idx = submit_request(
        ring_base,
        FS_OP_RENAME,
        -100,
        (-100i64) as u64,
        0,
        new_addr,
        old_addr,
        0,
        0,
        vm_ptr,
        0,
        0,
    );
    assert!(idx >= 0);

    process_requests(ring_base, vm_ptr, t.base);

    let result = read_completion(ring_base);
    assert_eq!(result, 0);
    assert_eq!(tidemark_kernel::fs::memfs::resolve_path(b"/old.txt"), 0);
    assert!(tidemark_kernel::fs::memfs::resolve_path(b"/new.txt") > 0);
}
