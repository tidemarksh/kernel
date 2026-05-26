use super::support::*;

#[test]
fn retain_fds_for_fork_counts_distinct_ofds_once() {
    let mut t = TestVm::new();
    let fd = t.sys_dup(1);
    assert_eq!(fd, 3);

    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, 1).expect("stdout OFD should exist");
    assert_eq!(
        fd_table::get_ofd_by_id(ofd_id)
            .expect("stdout OFD should exist")
            .refcount,
        2
    );

    fd_table::retain_fds_for_fork(t.base, &t.vm);
    assert_eq!(
        fd_table::get_ofd_by_id(ofd_id)
            .expect("stdout OFD should still exist")
            .refcount,
        4
    );
}

#[test]
fn inode_has_write_open_tracks_open_and_close() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/etxtbusy.bin", O_CREAT | O_WRONLY);
    assert!(fd >= 3);

    let ino = tidemark_kernel::fs::memfs::resolve_path(b"/etxtbusy.bin");
    assert!(ino > 0);
    assert!(fd_table::inode_has_write_open(ino));

    assert_eq!(t.sys_close(fd), 0);
    assert!(!fd_table::inode_has_write_open(ino));
}
