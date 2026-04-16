use tidemark_kernel::abi::{O_CREAT, O_RDONLY, O_RDWR};
use tidemark_kernel::fs::ring_buffer::{
    FS_OP_MKDIR, FS_OP_RENAME, FS_OP_WRITE, HEADER_SIZE, REQ_SIZE, RESP_SIZE, RING_BUFFER_SIZE,
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
    );
    assert!(idx >= 0);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
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
fn ring_buffer_dispatch_mkdir() {
    let mut t = TestVm::new();
    let ring_base = unsafe { tidemark_kernel::alloc::alloc_zeroed(RING_BUFFER_SIZE as u32, 16) };
    assert!(ring_base != 0);

    let path = b"/ringdir";
    let path_addr = t.write_path(0xB000, path);

    let idx = submit_request(ring_base, FS_OP_MKDIR, -100, 0, 0, 0, path_addr, 0, 0o755);
    assert!(idx >= 0);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
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
    );
    assert!(idx >= 0);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
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
    );
    assert!(idx >= 0);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    process_requests(ring_base, vm_ptr, t.base);

    let result = read_completion(ring_base);
    assert_eq!(result, 0);
    assert_eq!(tidemark_kernel::fs::memfs::resolve_path(b"/old.txt"), 0);
    assert!(tidemark_kernel::fs::memfs::resolve_path(b"/new.txt") > 0);
}
