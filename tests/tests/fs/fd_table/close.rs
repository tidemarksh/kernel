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

#[test]
fn close_shared_fd_drops_one_reference_per_descriptor() {
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

    assert_eq!(t.sys_close(fd), 0);
    assert_eq!(
        fd_table::get_ofd_by_id(ofd_id)
            .expect("stdout OFD should still exist after closing duplicate")
            .refcount,
        1
    );

    assert_eq!(t.sys_close(1), 0);
    assert!(fd_table::get_ofd_by_id(ofd_id).is_none());
}
