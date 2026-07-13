use super::support::*;

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
fn getdents64_dispatches_through_fs_ring_and_preserves_shared_offset() {
    let mut t = TestVm::new();

    assert_eq!(t.sys_mkdirat(b"/dispatch-dir"), 0);
    for name in [b"/dispatch-dir/a".as_slice(), b"/dispatch-dir/b".as_slice()] {
        let fd = t.sys_openat(name, O_CREAT | O_RDWR);
        assert!(fd >= 3);
        assert_eq!(t.sys_close(fd), 0);
    }
    let dir_fd = t.sys_openat(b"/dispatch-dir", O_RDONLY);
    assert!(dir_fd >= 3);
    let dents_buf = t.scratch + 0x5200;
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;

    for expected in [24, 24, 0] {
        t.vm.x[10] = dir_fd as u64;
        t.vm.x[11] = dents_buf;
        t.vm.x[12] = 24;
        t.vm.x[17] = SYS_GETDENTS64;

        assert_eq!(
            tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
            STATUS_FS
        );
        fs::process_pending_requests(vm_ptr, t.base);
        assert_eq!(fs::resume_from_fs(vm_ptr, t.base), expected);
        assert_eq!(t.vm.status, STATUS_OK);
    }

    assert_eq!(fd_table::get_offset(t.base, &t.vm, dir_fd as u64), 2);
}

#[test]
fn getdents64_on_regular_file_returns_enotdir() {
    let mut t = TestVm::new();

    let fd = t.sys_openat(b"/not-a-dir.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    let dents_buf = t.scratch + 0x5400;
    assert_eq!(t.sys_getdents64(fd, dents_buf, 128), ENOTDIR);
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
fn proc_self_fd_getdents_lists_open_descriptors() {
    let mut t = TestVm::new();
    process_impl::install_procfs_snapshot(b"/bin/test", 0);

    let file_fd = t.sys_openat(b"/visible-fd", O_CREAT | O_RDWR);
    assert!(file_fd >= 3);
    let proc_fd = t.sys_openat(b"/proc/self/fd", O_RDONLY | O_DIRECTORY);
    assert!(proc_fd >= 3);

    let dents_buf = t.scratch + 0x5A00;
    let n = t.sys_getdents64(proc_fd, dents_buf, 256);
    assert!(n > 0);

    let bytes = t.guest_mem(dents_buf, n as usize);
    let mut offset = 0usize;
    let mut names = Vec::new();
    while offset < bytes.len() {
        let reclen = u16::from_le_bytes([bytes[offset + 16], bytes[offset + 17]]) as usize;
        let d_type = bytes[offset + 18];
        let name_field = &bytes[offset + 19..offset + reclen];
        let nul = name_field
            .iter()
            .position(|byte| *byte == 0)
            .expect("dirent name must be NUL-terminated");
        names.push(String::from_utf8_lossy(&name_field[..nul]).into_owned());
        assert_eq!(d_type, 10);
        offset += reclen;
    }

    assert!(names.contains(&String::from("0")));
    assert!(names.contains(&String::from("1")));
    assert!(names.contains(&String::from("2")));
    assert!(names.contains(&file_fd.to_string()));
    assert!(names.contains(&proc_fd.to_string()));

    assert_eq!(t.sys_close(file_fd), 0);
    assert_eq!(t.sys_lseek(proc_fd, 0, 0), 0);
    let n = t.sys_getdents64(proc_fd, dents_buf, 256);
    let bytes = t.guest_mem(dents_buf, n as usize);
    let mut offset = 0usize;
    let mut names_after_close = Vec::new();
    while offset < bytes.len() {
        let reclen = u16::from_le_bytes([bytes[offset + 16], bytes[offset + 17]]) as usize;
        let name_field = &bytes[offset + 19..offset + reclen];
        let nul = name_field
            .iter()
            .position(|byte| *byte == 0)
            .expect("dirent name must be NUL-terminated");
        names_after_close.push(String::from_utf8_lossy(&name_field[..nul]).into_owned());
        offset += reclen;
    }
    assert!(!names_after_close.contains(&file_fd.to_string()));
}
