use super::support::*;

fn regular_file_write_advances_offset_across_large_chunks() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/large-partial", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    let buf_addr = t.scratch + 0x20_000;
    let chunk = vec![b'x'; 65_536];
    t.write_mem(buf_addr, &chunk);

    assert_eq!(
        fs::sys_write(&mut t.vm, t.base, fd as u64, buf_addr, 64_836, SYS_WRITE),
        64_836,
    );
    assert_eq!(
        fs::sys_write(&mut t.vm, t.base, fd as u64, buf_addr, 65_536, SYS_WRITE),
        65_536,
    );
    assert_eq!(t.sys_lseek(fd, 0, 1), 130_372);

    assert_eq!(
        fs::sys_write(&mut t.vm, t.base, fd as u64, buf_addr, 10_045, SYS_WRITE),
        10_045,
    );
    assert_eq!(t.sys_lseek(fd, 0, 1), 140_417);
}

#[test]
fn regular_file_read_spans_multiple_chunks() {
    let mut t = TestVm::new();
    let data: Vec<u8> = (0..10_000).map(|idx| (idx % 251) as u8).collect();
    let ino = memfs::create_file(1, b"big-read.bin", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::write_file(ino, 0, &data), data.len() as i64);

    let fd = t.sys_openat(b"/big-read.bin", O_RDONLY);
    assert!(fd >= 3);

    let mut buf = vec![0u8; data.len()];
    let nread = t.sys_read(fd, &mut buf);
    assert_eq!(nread, data.len() as i64);
    assert_eq!(buf, data);
}

#[test]
fn pread64_spans_multiple_chunks_from_nonzero_offset() {
    let mut t = TestVm::new();
    let data: Vec<u8> = (0..12_000).map(|idx| ((idx * 7) % 251) as u8).collect();
    let ino = memfs::create_file(1, b"big-pread.bin", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::write_file(ino, 0, &data), data.len() as i64);

    let fd = t.sys_openat(b"/big-pread.bin", O_RDONLY);
    assert!(fd >= 3);

    let offset = 4097u64;
    let len = 5000usize;
    let buf_addr = t.scratch + 0x7000;
    let nread = fs::sys_pread64(&mut t.vm, t.base, fd as u64, buf_addr, len as u64, offset);
    assert_eq!(nread, len as i64);
    assert_eq!(
        &t.guest_mem(buf_addr, len),
        &data[offset as usize..offset as usize + len]
    );
}

#[test]
fn read_and_pread64_on_directory_return_eisdir() {
    let mut t = TestVm::new();
    assert_eq!(t.sys_mkdirat(b"/read-dir"), 0);
    let fd = t.sys_openat(b"/read-dir", O_RDONLY | O_DIRECTORY);
    assert!(fd >= 3);

    let mut buf = [0u8; 8];
    assert_eq!(t.sys_read(fd, &mut buf), EISDIR);

    let buf_addr = t.scratch + 0x7100;
    assert_eq!(
        fs::sys_pread64(&mut t.vm, t.base, fd as u64, buf_addr, 8, 0),
        EISDIR
    );
}

#[test]
fn readv_reads_regular_file_into_multiple_iovecs() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/readv.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"readv-data"), 10);
    assert_eq!(t.sys_lseek(fd, 0, 0), 0);

    let buf_a = t.scratch + 0x7300;
    let buf_b = t.scratch + 0x7400;
    let iov_addr = t.scratch + 0x7500;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr, buf_a);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 8, 5);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 16, buf_b);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 24, 5);
    }

    let read = fs::sys_readv(&mut t.vm, t.base, fd as u64, iov_addr, 2);
    assert_eq!(read, 10);
    assert_eq!(t.guest_mem(buf_a, 5), b"readv".to_vec());
    assert_eq!(t.guest_mem(buf_b, 5), b"-data".to_vec());
}

#[test]
fn syscall_dispatch_routes_readv() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/dispatch-readv.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"dispatch"), 8);
    assert_eq!(t.sys_lseek(fd, 0, 0), 0);

    let buf_a = t.scratch + 0x7600;
    let buf_b = t.scratch + 0x7700;
    let iov_addr = t.scratch + 0x7800;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr, buf_a);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 8, 3);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 16, buf_b);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 24, 5);
    }

    t.vm.x[10] = fd as u64;
    t.vm.x[11] = iov_addr;
    t.vm.x[12] = 2;
    t.vm.x[17] = SYS_READV;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, 8);
    assert_eq!(t.guest_mem(buf_a, 3), b"dis".to_vec());
    assert_eq!(t.guest_mem(buf_b, 5), b"patch".to_vec());
}

#[test]
fn syscall_dispatch_routes_regular_file_read_through_fs_ring() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/dispatch-read.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"abcdef"), 6);
    assert_eq!(t.sys_lseek(fd, 0, 0), 0);

    let buf_addr = t.scratch + 0x7900;
    t.vm.x[10] = fd as u64;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 3;
    t.vm.x[17] = SYS_READ;

    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_FS
    );

    let vm_ptr = &mut t.vm as *mut _ as u32;
    fs::process_pending_requests(vm_ptr, t.base);
    let read = fs::resume_from_fs(vm_ptr, t.base);

    assert_eq!(read, 3);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.guest_mem(buf_addr, 3), b"abc".to_vec());
    assert_eq!(t.sys_lseek(fd, 0, 1), 3);
}

#[test]
fn syscall_dispatch_routes_regular_file_pread64_through_fs_ring() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/dispatch-pread.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"abcdef"), 6);
    assert_eq!(t.sys_lseek(fd, 0, 0), 0);

    let buf_addr = t.scratch + 0x7a00;
    t.vm.x[10] = fd as u64;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 3;
    t.vm.x[13] = 2;
    t.vm.x[17] = SYS_PREAD64;

    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_FS
    );

    let vm_ptr = &mut t.vm as *mut _ as u32;
    fs::process_pending_requests(vm_ptr, t.base);
    let read = fs::resume_from_fs(vm_ptr, t.base);

    assert_eq!(read, 3);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.guest_mem(buf_addr, 3), b"cde".to_vec());
    assert_eq!(t.sys_lseek(fd, 0, 1), 0);
}
