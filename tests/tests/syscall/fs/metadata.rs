use super::support::*;

fn ioctl_on_regular_file_reports_enotty() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/plain", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    t.vm.x[17] = SYS_IOCTL;
    t.vm.x[10] = fd as u64;
    t.vm.x[11] = 0x5413; // TIOCGWINSZ
    t.vm.x[12] = t.scratch + 0x3800;

    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, ENOTTY);
}

#[test]
fn newfstatat_rejects_non_directory_dirfd() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/plain", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    let path_addr = t.write_path(0xF000, b"child");
    let stat_addr = t.scratch + 0x3000;
    assert_eq!(
        fs::sys_newfstatat(&mut t.vm, t.base, fd as u64, path_addr, stat_addr, 0),
        ENOTDIR
    );
}

#[test]
fn newfstatat_rejects_invalid_flags() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/plain", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    t.sys_close(fd);

    let path_addr = t.write_path(0xF000, b"/plain");
    let stat_addr = t.scratch + 0x3000;
    assert_eq!(
        fs::sys_newfstatat(&mut t.vm, t.base, AT_FDCWD, path_addr, stat_addr, 9999),
        EINVAL
    );
}

#[test]
fn newfstatat_empty_path_requires_at_empty_path() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/plain", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    let empty_addr = t.write_path(0xF000, b"");
    let stat_addr = t.scratch + 0x3000;
    assert_eq!(
        fs::sys_newfstatat(&mut t.vm, t.base, fd as u64, empty_addr, stat_addr, 0),
        ENOENT
    );
}

#[test]
fn newfstatat_empty_path_stats_referenced_fd() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/plain", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    let empty_addr = t.write_path(0xF000, b"");
    let stat_addr = t.scratch + 0x3000;
    assert_eq!(
        fs::sys_newfstatat(
            &mut t.vm,
            t.base,
            fd as u64,
            empty_addr,
            stat_addr,
            AT_EMPTY_PATH
        ),
        0
    );
    let ino = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, stat_addr + 8) };
    let mode = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, stat_addr + 16) };
    assert_eq!(ino, 2);
    assert_eq!(mode & memfs::S_IFMT, memfs::S_IFREG);
}

#[test]
fn newfstatat_empty_path_at_fdcwd_stats_cwd() {
    let mut t = TestVm::new();
    assert_eq!(t.sys_mkdirat(b"/work"), 0);
    let cwd_addr = t.write_path(0xF100, b"/work");
    assert_eq!(fs::sys_chdir(&mut t.vm, t.base, cwd_addr), 0);

    let empty_addr = t.write_path(0xF200, b"");
    let stat_addr = t.scratch + 0x3000;
    assert_eq!(
        fs::sys_newfstatat(
            &mut t.vm,
            t.base,
            AT_FDCWD,
            empty_addr,
            stat_addr,
            AT_EMPTY_PATH
        ),
        0
    );
    let mode = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, stat_addr + 16) };
    assert_eq!(mode & memfs::S_IFMT, memfs::S_IFDIR);
}

#[test]
fn truncate_reduces_file_size() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/trunc_test.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    let data = b"Hello, truncate test data!";
    assert_eq!(t.sys_write_data(fd, data), data.len() as i64);
    t.sys_close(fd);

    let path_addr = t.write_path(0xF000, b"/trunc_test.txt");
    assert_eq!(fs::sys_truncate(&mut t.vm, t.base, path_addr, 5), 0);

    let fd2 = t.sys_openat(b"/trunc_test.txt", O_RDONLY);
    assert!(fd2 >= 3);
    let stat_addr = t.scratch + 0x3000;
    assert_eq!(t.sys_fstat(fd2, stat_addr), 0);
    let size = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, stat_addr + 48) };
    assert_eq!(size, 5);

    let mut buf = [0u8; 16];
    let nread = t.sys_read(fd2, &mut buf);
    assert_eq!(nread, 5);
    assert_eq!(&buf[..5], b"Hello");
    t.sys_close(fd2);
}

#[test]
fn devnull_open_read_write_and_stat() {
    let mut t = TestVm::new();

    let rd = t.sys_openat(b"/dev/null", O_RDONLY);
    assert!(rd >= 3);
    let wr = t.sys_openat(b"/dev/null", O_WRONLY);
    assert!(wr >= 3);

    let mut buf = [0u8; 8];
    assert_eq!(t.sys_read(rd, &mut buf), 0);
    assert_eq!(t.sys_write_data(wr, b"discard me"), 10);

    let stat_addr = t.scratch + 0x3200;
    assert_eq!(t.sys_fstat(rd, stat_addr), 0);
    let mode = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, stat_addr + 16) };
    assert_eq!(mode & memfs::S_IFMT, memfs::S_IFCHR);

    let path_addr = t.write_path(0xF800, b"/dev/null");
    assert_eq!(
        fs::sys_newfstatat(&mut t.vm, t.base, AT_FDCWD, path_addr, stat_addr, 0),
        0
    );
    let size = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, stat_addr + 48) };
    assert_eq!(size, 0);
}

#[test]
fn fstat_pipe_returns_fifo_mode() {
    let mut t = TestVm::new();

    let pipefd_addr = t.scratch + 0x3500;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
        0
    );
    let rd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as i64;
    let stat_addr = t.scratch + 0x3600;
    assert_eq!(t.sys_fstat(rd, stat_addr), 0);
    let mode = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, stat_addr + 16) };
    assert_eq!(mode & memfs::S_IFMT, S_IFIFO);
}
