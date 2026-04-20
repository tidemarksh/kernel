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
const TCGETS: u64 = 0x5401;
const TIOCGWINSZ: u64 = 0x5413;

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
fn stdio_pty_ends_enforce_read_write_direction() {
    let mut t = TestVm::new();
    let mut buf = [0u8; 8];
    assert_eq!(t.sys_write_data(0, b"stdin"), EBADF);
    assert_eq!(t.sys_read(1, &mut buf), EBADF);
    assert_eq!(t.sys_read(2, &mut buf), EBADF);
}

#[test]
fn stdio_fds_report_tty_termios_and_winsize() {
    let mut t = TestVm::new();
    let termios_addr = t.scratch + 0x3700;
    let winsize_addr = t.scratch + 0x3800;
    let stat_addr = t.scratch + 0x3900;

    assert_eq!(
        tidemark_kernel::syscall::pty::sys_ioctl(&mut t.vm, t.base, 0, TCGETS, termios_addr),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::pty::sys_ioctl(&mut t.vm, t.base, 1, TIOCGWINSZ, winsize_addr),
        0
    );
    assert_eq!(t.sys_fstat(0, stat_addr), 0);

    let iflag = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, termios_addr) };
    let ws_row = unsafe { tidemark_kernel::guest_mem::read_u16(t.base, winsize_addr) };
    let ws_col = unsafe { tidemark_kernel::guest_mem::read_u16(t.base, winsize_addr + 2) };
    let mode = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, stat_addr + 16) };
    assert_ne!(iflag, 0);
    assert_eq!(ws_row, 24);
    assert_eq!(ws_col, 80);
    assert_eq!(mode & memfs::S_IFMT, memfs::S_IFCHR);
}

#[test]
fn dev_tty_opens_controlling_pty_slave() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/dev/tty", O_RDWR);
    assert!(fd >= 3);

    let winsize_addr = t.scratch + 0x3a00;
    assert_eq!(
        tidemark_kernel::syscall::pty::sys_ioctl(
            &mut t.vm,
            t.base,
            fd as u64,
            TIOCGWINSZ,
            winsize_addr
        ),
        0
    );
    let ws_col = unsafe { tidemark_kernel::guest_mem::read_u16(t.base, winsize_addr + 2) };
    assert_eq!(ws_col, 80);
}

#[test]
fn stdio_pty_slave_writev_reaches_master_output() {
    let mut t = TestVm::new();
    let buf_a = t.scratch + 0x7000;
    let buf_b = t.scratch + 0x7100;
    let iov_addr = t.scratch + 0x7200;

    t.write_mem(buf_a, b"pw");
    t.write_mem(buf_b, b"d\n");
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr, buf_a);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 8, 2);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 16, buf_b);
        tidemark_kernel::guest_mem::write_u64(t.base, iov_addr + 24, 2);
    }

    let written = fs::sys_write(&mut t.vm, t.base, 1, iov_addr, 2, SYS_WRITEV);
    assert_eq!(written, 4);

    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 1)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    let mut out = [0u8; 8];
    let n = tidemark_kernel::syscall::pty::master_read(pty_idx, &mut out);
    assert_eq!(n, 5);
    assert_eq!(&out[..5], b"pwd\r\n");
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
fn stdio_pty_master_canonical_mode_commits_input_only_after_newline() {
    let t = TestVm::new();
    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 1)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"l"),
        1
    );
    let mut cooked = [0u8; 16];
    assert_eq!(
        tidemark_kernel::syscall::pty::slave_read(pty_idx, &mut cooked),
        EAGAIN
    );

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"s\r"),
        2
    );
    let n = tidemark_kernel::syscall::pty::slave_read(pty_idx, &mut cooked);
    assert_eq!(n, 3);
    assert_eq!(&cooked[..3], b"ls\n");

    let mut echoed = [0u8; 16];
    let n = tidemark_kernel::syscall::pty::master_read(pty_idx, &mut echoed);
    assert_eq!(n, 4);
    assert_eq!(&echoed[..4], b"ls\r\n");
}

#[test]
fn stdio_pty_master_erase_updates_canonical_line() {
    let t = TestVm::new();
    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 1)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"lx\x7fs\r"),
        5
    );

    let mut cooked = [0u8; 16];
    let n = tidemark_kernel::syscall::pty::slave_read(pty_idx, &mut cooked);
    assert_eq!(n, 3);
    assert_eq!(&cooked[..3], b"ls\n");
}

#[test]
fn stdio_pty_blocked_read_resume_preserves_register_context() {
    let mut t = TestVm::new();
    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 0)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    let buf_addr = t.scratch + 0x3b00;
    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = 0;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 8;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    t.vm.pc = 0x4455_6677;
    t.vm.x[1] = 0x5566_7788;
    t.vm.x[2] = t.scratch + 0x2800;
    t.vm.x[27] = 0x7788_9900;

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"ls\r"),
        3
    );

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 3);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x4455_6677);
    assert_eq!(t.vm.x[1], 0x5566_7788);
    assert_eq!(t.vm.x[2], t.scratch + 0x2800);
    assert_eq!(t.vm.x[27], 0x7788_9900);

    let mut cooked = [0u8; 8];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf_addr, &mut cooked[..3]);
    }
    assert_eq!(&cooked[..3], b"ls\n");
}

#[test]
fn stdio_pty_blocked_read_resume_first_thread_step_preserves_s11() {
    let mut t = TestVm::new();
    let pty_idx = fd_table::get_ofd(t.base, &t.vm, 0)
        .map(|ofd| ofd.ino)
        .unwrap_or(0);
    assert!(pty_idx > 0);

    let code_addr = 0x10000u64;
    let mapped = t.sys_mmap(
        code_addr,
        0x1000,
        PROT_READ | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert_eq!(mapped, code_addr as i64);

    unsafe {
        // ecall
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr, 0x0000_0073);
        // addi s11, s11, 0
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr + 4, 0x000d_8d93);
    }

    let buf_addr = t.scratch + 0x3c00;
    t.vm.pc = code_addr;
    t.vm.x[1] = 0x5566_7788;
    t.vm.x[2] = t.scratch + 0x2800;
    t.vm.x[10] = 0;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 8;
    t.vm.x[17] = SYS_READ;
    t.vm.x[27] = 0x7788_9900;

    let vm_ptr = &mut t.vm as *mut _ as u32;
    let remaining = tidemark_kernel::abi::thread_step(vm_ptr, 1);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    assert_eq!(
        tidemark_kernel::syscall::pty::master_write(pty_idx, b"ls\r"),
        3
    );
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 3);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code_addr + 4);
    assert_eq!(t.vm.x[1], 0x5566_7788);
    assert_eq!(t.vm.x[2], t.scratch + 0x2800);
    assert_eq!(t.vm.x[10], 3);
    assert_eq!(t.vm.x[27], 0x7788_9900);

    let remaining = tidemark_kernel::abi::thread_step(vm_ptr, 1);
    assert_eq!(remaining, 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, code_addr + 8);
    assert_eq!(t.vm.x[1], 0x5566_7788);
    assert_eq!(t.vm.x[2], t.scratch + 0x2800);
    assert_eq!(t.vm.x[27], 0x7788_9900);

    let mut cooked = [0u8; 8];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf_addr, &mut cooked[..3]);
    }
    assert_eq!(&cooked[..3], b"ls\n");
}
