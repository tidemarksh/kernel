use super::support::*;
fn fs_syscalls() {
    let mut t = TestVm::new();

    let fd = t.sys_openat(b"/test.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"Hello FS!"), 9);
    assert_eq!(t.sys_lseek(fd, 0, 0), 0);

    let mut buf = [0u8; 16];
    let nread = t.sys_read(fd, &mut buf);
    assert_eq!(nread, 9);
    assert_eq!(&buf[..9], b"Hello FS!");

    let stat_addr = t.scratch + 0x3000;
    assert_eq!(t.sys_fstat(fd, stat_addr), 0);
    let size = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, stat_addr + 48) };
    assert_eq!(size, 9);
    assert_eq!(t.sys_close(fd), 0);

    assert_eq!(t.sys_mkdirat(b"/mydir"), 0);
    let fd_a = t.sys_openat(b"/mydir/a.txt", O_CREAT | O_RDWR);
    assert!(fd_a >= 3);
    t.sys_close(fd_a);

    let fd_b = t.sys_openat(b"/mydir/b.txt", O_CREAT | O_RDWR);
    assert!(fd_b >= 3);
    t.sys_close(fd_b);

    let dir_fd = t.sys_openat(b"/mydir", O_RDONLY);
    assert!(dir_fd >= 3);
    let dents_buf = t.scratch + 0x4000;
    let n = t.sys_getdents64(dir_fd, dents_buf, 4096);
    assert!(n > 0);
}

#[test]
fn umask_updates_process_mask_and_filters_create_modes() {
    let mut t = TestVm::new();

    t.vm.x[10] = 0o027;
    t.vm.x[17] = SYS_UMASK;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, 0o022);

    let file_path = t.write_path(0x5000, b"/umask-file");
    let fd = fs::sys_openat(
        &mut t.vm,
        t.base,
        AT_FDCWD,
        file_path,
        (O_CREAT | O_RDONLY) as u64,
        0o666,
    );
    assert!(fd >= 3);
    let file_stat = memfs::stat(memfs::resolve_path(b"/umask-file")).unwrap();
    assert_eq!(file_stat.mode & 0o777, 0o640);

    let dir_path = t.write_path(0x5100, b"/umask-dir");
    assert_eq!(
        fs::sys_mkdirat(&mut t.vm, t.base, AT_FDCWD, dir_path, 0o777,),
        0
    );
    let dir_stat = memfs::stat(memfs::resolve_path(b"/umask-dir")).unwrap();
    assert_eq!(dir_stat.mode & 0o777, 0o750);
}

#[test]
fn status_fs_round_trip_for_open_then_write_and_lseek() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;

    let path_addr = t.write_path(0x6000, b"/async.txt");
    let ret = fs::dispatch_openat(
        &mut t.vm,
        t.base,
        AT_FDCWD,
        path_addr,
        (O_CREAT | O_RDWR) as u64,
        0o644,
    );
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_FS);
    fs::process_pending_requests(vm_ptr, t.base);
    let fd = fs::resume_from_fs(vm_ptr, t.base);
    assert!(fd >= 3);

    let buf_addr = t.scratch + 0x6100;
    t.write_mem(buf_addr, b"async fs");
    let ret = fs::dispatch_write(&mut t.vm, t.base, fd as u64, buf_addr, 8, SYS_WRITE);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_FS);
    fs::process_pending_requests(vm_ptr, t.base);
    let ret = fs::resume_from_fs(vm_ptr, t.base);
    assert_eq!(ret, 8);
    assert_eq!(t.vm.status, STATUS_OK);

    let ret = fs::dispatch_lseek(&mut t.vm, t.base, fd as u64, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_OK);

    let mut out = [0u8; 8];
    assert_eq!(fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8), 8);
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf_addr, &mut out);
    }
    assert_eq!(&out, b"async fs");
}

#[test]
fn openat_with_o_directory_rejects_regular_files() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/plain", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    t.sys_close(fd);

    let ret = t.sys_openat(b"/plain", O_RDONLY | O_DIRECTORY);
    assert_eq!(ret, ENOTDIR);
}

#[test]
fn openat_o_trunc_external_file_keeps_data_external() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/external-open-trunc.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"payload"), 7);
    t.sys_close(fd);

    let ino = memfs::resolve_path(b"/external-open-trunc.txt");
    assert!(ino > 0);
    assert_eq!(memfs::set_file_external(ino, 7), 0);
    assert!(memfs::file_data_ptr(ino).is_none());

    let truncated = t.sys_openat(b"/external-open-trunc.txt", O_WRONLY | O_TRUNC);
    assert!(truncated >= 3);

    let stat_addr = t.scratch + 0x3000;
    assert_eq!(t.sys_fstat(truncated, stat_addr), 0);
    let size = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, stat_addr + 48) };
    assert_eq!(size, 0);
    assert!(memfs::file_data_ptr(ino).is_none());
    assert_eq!(memfs::debug_file_data_layout(ino) >> 32, 0);
    t.sys_close(truncated);
}
