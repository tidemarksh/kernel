use std::string::String;
use std::vec::Vec;
use tidemark_kernel::abi::*;
use tidemark_kernel::fs::{fd_table, memfs};
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::fs;

const AT_FDCWD: u64 = (-100i64) as u64;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;
const S_IFIFO: u32 = 0o010000;

#[test]
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
fn status_fs_round_trip_for_open_write_and_lseek() {
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
    let expected_ino = fd_table::get_ofd(t.base, &t.vm, fd as u64)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(expected_ino > 0);
    assert_eq!(fs::pending_request_target_ino(vm_ptr, t.base), expected_ino);
    fs::process_pending_requests(vm_ptr, t.base);
    assert_eq!(fs::resume_from_fs(vm_ptr, t.base), 8);

    let ret = fs::dispatch_lseek(&mut t.vm, t.base, fd as u64, 0, 0);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.status, STATUS_FS);
    fs::process_pending_requests(vm_ptr, t.base);
    assert_eq!(fs::resume_from_fs(vm_ptr, t.base), 0);

    let mut out = [0u8; 8];
    assert_eq!(fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8), 8);
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf_addr, &mut out);
    }
    assert_eq!(&out, b"async fs");
}

#[test]
fn getdents64_advances_directory_offset() {
    let mut t = TestVm::new();

    assert_eq!(t.sys_mkdirat(b"/dir"), 0);
    let fd_a = t.sys_openat(b"/dir/a", O_CREAT | O_RDWR);
    assert!(fd_a >= 3);
    t.sys_close(fd_a);
    let fd_b = t.sys_openat(b"/dir/b", O_CREAT | O_RDWR);
    assert!(fd_b >= 3);
    t.sys_close(fd_b);

    let dir_fd = t.sys_openat(b"/dir", O_RDONLY);
    assert!(dir_fd >= 3);

    let dents_buf = t.scratch + 0x5000;
    assert_eq!(t.sys_getdents64(dir_fd, dents_buf, 24), 24);
    assert_eq!(t.sys_getdents64(dir_fd, dents_buf, 24), 24);
    assert_eq!(t.sys_getdents64(dir_fd, dents_buf, 24), 0);
}

#[test]
fn getdents64_zero_fills_record_padding_after_names() {
    let mut t = TestVm::new();

    assert_eq!(t.sys_mkdirat(b"/dir"), 0);
    let fd_alpha = t.sys_openat(b"/dir/alpha.txt", O_CREAT | O_RDWR);
    assert!(fd_alpha >= 3);
    t.sys_close(fd_alpha);
    let fd_beta = t.sys_openat(b"/dir/beta.cfg", O_CREAT | O_RDWR);
    assert!(fd_beta >= 3);
    t.sys_close(fd_beta);

    let dir_fd = t.sys_openat(b"/dir", O_RDONLY);
    assert!(dir_fd >= 3);

    let dents_buf = t.scratch + 0x5800;
    t.write_mem(dents_buf, &[0xAA; 128]);
    let n = t.sys_getdents64(dir_fd, dents_buf, 128);
    assert!(n > 0);

    let bytes = t.guest_mem(dents_buf, n as usize);
    let mut offset = 0usize;
    let mut names = Vec::new();
    while offset < bytes.len() {
        let reclen = u16::from_le_bytes([bytes[offset + 16], bytes[offset + 17]]) as usize;
        assert!(reclen >= 24);
        let name_field = &bytes[offset + 19..offset + reclen];
        let nul = name_field
            .iter()
            .position(|byte| *byte == 0)
            .expect("dirent name must be NUL-terminated");
        names.push(String::from_utf8_lossy(&name_field[..nul]).into_owned());
        for byte in &name_field[nul..] {
            assert_eq!(*byte, 0);
        }
        offset += reclen;
    }

    names.sort();
    assert_eq!(
        names,
        vec![String::from("alpha.txt"), String::from("beta.cfg")]
    );
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

#[test]
fn stdio_pipe_ends_enforce_read_write_direction() {
    let mut t = TestVm::new();
    let mut buf = [0u8; 8];
    assert_eq!(t.sys_write_data(0, b"stdin"), EBADF);
    assert_eq!(t.sys_read(1, &mut buf), EBADF);
    assert_eq!(t.sys_read(2, &mut buf), EBADF);
}
