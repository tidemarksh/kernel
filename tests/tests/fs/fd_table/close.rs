use super::support::*;

#[test]
fn close_range_closes_or_marks_fd_range() {
    let mut t = TestVm::new();

    let fd3 = t.sys_dup(1);
    let fd4 = t.sys_dup(1);
    let fd5 = t.sys_dup(1);
    assert_eq!((fd3, fd4, fd5), (3, 4, 5));

    assert_eq!(fd_table::sys_close_range(&mut t.vm, t.base, 4, 5, 0), 0);
    assert!(fd_table::get_ofd_id(t.base, &t.vm, 3).is_some());
    assert!(fd_table::get_ofd_id(t.base, &t.vm, 4).is_none());
    assert!(fd_table::get_ofd_id(t.base, &t.vm, 5).is_none());

    let fd4 = t.sys_dup(1);
    let fd5 = t.sys_dup(1);
    assert_eq!((fd4, fd5), (4, 5));
    assert_eq!(
        fd_table::sys_close_range(&mut t.vm, t.base, 4, 5, 1 << 2),
        0
    );
    assert_eq!(t.sys_fcntl(4, 1, 0), FD_CLOEXEC as i64);
    assert_eq!(t.sys_fcntl(5, 1, 0), FD_CLOEXEC as i64);
}
