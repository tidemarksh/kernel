use super::support::*;

#[test]
fn readlinkat_basic_and_error_paths() {
    let mut t = TestVm::new();

    let dir_ino = memfs::create_dir(1, b"dir", 0o755);
    assert!(dir_ino > 0);
    let file_ino = memfs::create_file(dir_ino, b"file", 0o644);
    assert!(file_ino > 0);
    let link_ino = memfs::create_symlink(dir_ino, b"link", b"file");
    assert!(link_ino > 0);

    let dir_fd = t.sys_openat(b"/dir", O_RDONLY | O_DIRECTORY);
    assert!(dir_fd >= 3);
    let file_fd = t.sys_openat(b"/dir/file", O_RDONLY);
    assert!(file_fd >= 3);
    let link_fd = fd_table::open_file(&mut t.vm, t.base, link_ino, O_RDONLY);
    assert!(link_fd >= 3);

    let rel_addr = t.write_path(0xF100, b"link");
    let abs_addr = t.write_path(0xF200, b"/dir/link");
    let cwd_addr = t.write_path(0xF300, b"dir/link");
    let empty_addr = t.write_path(0xF400, b"");
    let file_addr = t.write_path(0xF500, b"file");
    let missing_addr = t.write_path(0xF600, b"missing");
    let nested_addr = t.write_path(0xF700, b"file/child");
    let buf_addr = t.scratch + 0x2000;

    let n = fs::sys_readlinkat(&mut t.vm, t.base, dir_fd as u64, rel_addr, buf_addr, 16);
    assert_eq!(n, 4);
    assert_eq!(&t.guest_mem(buf_addr, 4), b"file");

    let n = fs::sys_readlinkat(&mut t.vm, t.base, 999, abs_addr, buf_addr, 16);
    assert_eq!(n, 4);
    assert_eq!(&t.guest_mem(buf_addr, 4), b"file");

    let n = fs::sys_readlinkat(&mut t.vm, t.base, AT_FDCWD, cwd_addr, buf_addr, 16);
    assert_eq!(n, 4);
    assert_eq!(&t.guest_mem(buf_addr, 4), b"file");

    let n = fs::sys_readlinkat(&mut t.vm, t.base, link_fd as u64, empty_addr, buf_addr, 16);
    assert_eq!(n, 4);
    assert_eq!(&t.guest_mem(buf_addr, 4), b"file");

    assert_eq!(
        fs::sys_readlinkat(&mut t.vm, t.base, dir_fd as u64, rel_addr, buf_addr, 0),
        EINVAL
    );
    assert_eq!(
        fs::sys_readlinkat(&mut t.vm, t.base, dir_fd as u64, file_addr, buf_addr, 16),
        EINVAL
    );
    assert_eq!(
        fs::sys_readlinkat(&mut t.vm, t.base, file_fd as u64, rel_addr, buf_addr, 16),
        ENOTDIR
    );
    assert_eq!(
        fs::sys_readlinkat(&mut t.vm, t.base, 999, rel_addr, buf_addr, 16),
        EBADF
    );
    assert_eq!(
        fs::sys_readlinkat(&mut t.vm, t.base, dir_fd as u64, missing_addr, buf_addr, 16),
        ENOENT
    );
    assert_eq!(
        fs::sys_readlinkat(&mut t.vm, t.base, dir_fd as u64, nested_addr, buf_addr, 16),
        ENOTDIR
    );
}

#[test]
fn openat_follows_trailing_symlink_by_default() {
    let mut t = TestVm::new();

    let dir_ino = memfs::create_dir(1, b"dir", 0o755);
    assert!(dir_ino > 0);
    let file_ino = memfs::create_file(dir_ino, b"file", 0o644);
    assert!(file_ino > 0);
    assert_eq!(memfs::write_file(file_ino, 0, b"hello via link"), 14);
    let link_ino = memfs::create_symlink(dir_ino, b"link", b"file");
    assert!(link_ino > 0);

    let fd = t.sys_openat(b"/dir/link", O_RDONLY);
    assert!(fd >= 3);

    let mut buf = [0u8; 32];
    let n = t.sys_read(fd, &mut buf);
    assert_eq!(n, 14);
    assert_eq!(&buf[..14], b"hello via link");
}

#[test]
fn openat_with_o_nofollow_rejects_trailing_symlink() {
    let mut t = TestVm::new();

    let dir_ino = memfs::create_dir(1, b"dir", 0o755);
    assert!(dir_ino > 0);
    let file_ino = memfs::create_file(dir_ino, b"file", 0o644);
    assert!(file_ino > 0);
    let link_ino = memfs::create_symlink(dir_ino, b"link", b"file");
    assert!(link_ino > 0);

    assert_eq!(t.sys_openat(b"/dir/link", O_RDONLY | O_NOFOLLOW), ELOOP);
}

#[test]
fn openat_follows_symlink_in_path_prefix() {
    let mut t = TestVm::new();

    let real_ino = memfs::create_dir(1, b"real", 0o755);
    assert!(real_ino > 0);
    let file_ino = memfs::create_file(real_ino, b"nested", 0o644);
    assert!(file_ino > 0);
    assert_eq!(memfs::write_file(file_ino, 0, b"prefix link"), 11);
    let alias_ino = memfs::create_symlink(1, b"alias", b"real");
    assert!(alias_ino > 0);

    let fd = t.sys_openat(b"/alias/nested", O_RDONLY);
    assert!(fd >= 3);

    let mut buf = [0u8; 32];
    let n = t.sys_read(fd, &mut buf);
    assert_eq!(n, 11);
    assert_eq!(&buf[..11], b"prefix link");
}
