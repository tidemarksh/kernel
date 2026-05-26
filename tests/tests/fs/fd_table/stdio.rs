use super::support::*;

#[test]
fn close_shared_stdio_fd_drops_one_reference_per_descriptor() {
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

#[test]
fn retain_stdio_fds_for_fork_counts_distinct_ofds_once() {
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
