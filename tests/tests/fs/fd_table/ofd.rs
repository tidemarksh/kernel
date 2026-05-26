use super::support::*;

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
