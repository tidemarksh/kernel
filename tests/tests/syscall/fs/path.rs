use super::support::*;

#[test]
fn unlinkat_with_at_removedir_removes_empty_directory() {
    let mut t = TestVm::new();
    assert_eq!(t.sys_mkdirat(b"/empty"), 0);
    let path_addr = t.write_path(0xF000, b"/empty");
    assert_eq!(
        fs::sys_unlinkat(&mut t.vm, t.base, AT_FDCWD, path_addr, AT_REMOVEDIR),
        0
    );
    assert_eq!(memfs::resolve_path(b"/empty"), 0);
}

#[test]
fn unlinkat_rejects_non_directory_dirfd() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/plain", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    let path_addr = t.write_path(0xF000, b"child");
    assert_eq!(
        fs::sys_unlinkat(&mut t.vm, t.base, fd as u64, path_addr, 0),
        ENOTDIR
    );
}

#[test]
fn unlinkat_rejects_invalid_flags() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/victim", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    t.sys_close(fd);

    let path_addr = t.write_path(0xF000, b"/victim");
    assert_eq!(
        fs::sys_unlinkat(&mut t.vm, t.base, AT_FDCWD, path_addr, 9999),
        EINVAL
    );
}

#[test]
fn renameat2_moves_file_between_paths() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/old.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"renamed"), 7);
    t.sys_close(fd);

    let old_addr = t.write_path(0xF000, b"/old.txt");
    let new_addr = t.write_path(0xF100, b"/new.txt");
    assert_eq!(
        fs::sys_renameat2(&mut t.vm, t.base, AT_FDCWD, old_addr, AT_FDCWD, new_addr, 0),
        0
    );

    assert_eq!(memfs::resolve_path(b"/old.txt"), 0);
    let moved_ino = memfs::resolve_path(b"/new.txt");
    assert!(moved_ino > 0);
    let mut buf = [0u8; 16];
    assert_eq!(memfs::read_file(moved_ino, 0, &mut buf), 7);
    assert_eq!(&buf[..7], b"renamed");
}

#[test]
fn renameat_moves_file_between_paths() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/old-renameat.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_write_data(fd, b"renameat"), 8);
    t.sys_close(fd);

    let old_addr = t.write_path(0xF000, b"/old-renameat.txt");
    let new_addr = t.write_path(0xF100, b"/new-renameat.txt");
    assert_eq!(
        fs::sys_renameat(&mut t.vm, t.base, AT_FDCWD, old_addr, AT_FDCWD, new_addr),
        0
    );

    assert_eq!(memfs::resolve_path(b"/old-renameat.txt"), 0);
    let moved_ino = memfs::resolve_path(b"/new-renameat.txt");
    assert!(moved_ino > 0);
    let mut buf = [0u8; 16];
    assert_eq!(memfs::read_file(moved_ino, 0, &mut buf), 8);
    assert_eq!(&buf[..8], b"renameat");
}

#[test]
fn dirfd_relative_openat() {
    let mut t = TestVm::new();
    assert_eq!(t.sys_mkdirat(b"/subdir"), 0);

    let fd_file = t.sys_openat(b"/subdir/nested.txt", O_CREAT | O_RDWR);
    assert!(fd_file >= 3);
    assert_eq!(t.sys_write_data(fd_file, b"nested content"), 14);
    t.sys_close(fd_file);

    let dir_fd = t.sys_openat(b"/subdir", O_RDONLY);
    assert!(dir_fd >= 3);

    let path_addr = t.write_path(0xF000, b"nested.txt");
    let rel_fd = fs::sys_openat(
        &mut t.vm,
        t.base,
        dir_fd as u64,
        path_addr,
        O_RDONLY as u64,
        0,
    );
    assert!(rel_fd >= 3);

    let buf_addr = t.scratch + 0xE000;
    assert_eq!(
        fs::sys_read(&mut t.vm, t.base, rel_fd as u64, buf_addr, 32),
        14
    );
    let data = t.guest_mem(buf_addr, 14);
    assert_eq!(&data[..], b"nested content");

    t.sys_close(dir_fd);
}

#[test]
fn openat_accepts_dot_path() {
    let mut t = TestVm::new();

    assert_eq!(t.sys_mkdirat(b"/dir"), 0);
    let dir_fd = t.sys_openat(b"/dir", O_RDONLY | O_DIRECTORY);
    assert!(dir_fd >= 3);

    let dot_addr = t.write_path(0xF100, b".");
    let reopened = fs::sys_openat(
        &mut t.vm,
        t.base,
        dir_fd as u64,
        dot_addr,
        (O_RDONLY | O_DIRECTORY) as u64,
        0,
    );
    assert!(reopened >= 3);

    t.sys_close(reopened);
    t.sys_close(dir_fd);
}

#[test]
fn getcwd_returns_length_and_nul_terminated_path() {
    let mut t = TestVm::new();
    assert_eq!(t.sys_mkdirat(b"/work"), 0);
    assert_eq!(t.sys_mkdirat(b"/work/hello"), 0);

    let cwd_addr = t.write_path(0xF100, b"/work/hello");
    assert_eq!(fs::sys_chdir(&mut t.vm, t.base, cwd_addr), 0);

    let buf_addr = t.scratch + 0x2000;
    assert_eq!(fs::sys_getcwd(&t.vm, t.base, buf_addr, 64), 12);
    assert_eq!(&t.guest_mem(buf_addr, 12), b"/work/hello\0");
}

#[test]
fn faccessat_basic_and_error_paths() {
    let mut t = TestVm::new();
    let read_ok = 4u64;

    assert_eq!(t.sys_mkdirat(b"/dir"), 0);
    let fd = t.sys_openat(b"/dir/file", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    t.sys_close(fd);

    let dir_fd = t.sys_openat(b"/dir", O_RDONLY | O_DIRECTORY);
    assert!(dir_fd >= 3);
    let file_fd = t.sys_openat(b"/dir/file", O_RDONLY);
    assert!(file_fd >= 3);

    let rel_addr = t.write_path(0xF100, b"file");
    let abs_addr = t.write_path(0xF200, b"/dir/file");
    let cwd_addr = t.write_path(0xF300, b"dir/file");
    let missing_addr = t.write_path(0xF400, b"missing");

    assert_eq!(
        fs::sys_faccessat(&mut t.vm, t.base, dir_fd as u64, rel_addr, read_ok),
        0
    );
    assert_eq!(
        fs::sys_faccessat(&mut t.vm, t.base, 999, abs_addr, read_ok),
        0
    );
    assert_eq!(
        fs::sys_faccessat(&mut t.vm, t.base, AT_FDCWD, cwd_addr, read_ok),
        0
    );
    assert_eq!(
        fs::sys_faccessat(&mut t.vm, t.base, file_fd as u64, missing_addr, read_ok),
        ENOTDIR
    );
    assert_eq!(
        fs::sys_faccessat(&mut t.vm, t.base, 999, rel_addr, read_ok),
        EBADF
    );
}
