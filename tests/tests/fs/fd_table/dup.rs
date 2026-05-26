use super::support::*;

#[test]
fn fd_table_syscalls() {
    let mut t = TestVm::new();

    let newfd = t.sys_dup(1);
    assert_eq!(newfd, 3);

    assert_eq!(t.sys_fcntl(3, 1, 0), 0);
    assert_eq!(t.sys_fcntl(3, 2, 1), 0);
    assert_eq!(t.sys_fcntl(3, 1, 0), 1);

    assert_eq!(t.sys_close(3), 0);
    assert_eq!(t.sys_close(3), EBADF);
    assert_eq!(t.sys_dup3(1, 10, O_CLOEXEC as u64), 10);
}
