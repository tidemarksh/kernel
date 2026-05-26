use super::support::*;

#[test]
fn fd_entry_flags_track_cloexec() {
    let mut t = TestVm::new();

    let fd = t.sys_dup(1);
    assert_eq!(fd, 3);

    assert_eq!(t.sys_fcntl(fd as u64, 1, 0), 0);
    assert_eq!(t.sys_fcntl(fd as u64, 2, 1), 0);
    assert_eq!(t.sys_fcntl(fd as u64, 1, 0), 1);

    assert_eq!(t.sys_close(fd), 0);
    assert_eq!(t.sys_close(fd), EBADF);
}
