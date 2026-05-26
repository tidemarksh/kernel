use super::support::*;

#[test]
fn semantics_nested_child_can_join_existing_parent_group() {
    let t = TestVm::new();

    write_process_ids(&t, 2, 1);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 1);

    write_process_ids(&t, 3, 2);
    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 3);

    write_process_ids(&t, 4, 3);
    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 4);

    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 3), 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 3);
}

#[test]
fn semantics_fork_inherited_session_allows_nested_group_join() {
    let mut t = TestVm::new();

    let child1 = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child1 > 0);
    t.vm.status = STATUS_OK;

    write_process_ids(&t, child1, 42);
    let child2 = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
    assert!(child2 > 0);
    t.vm.status = STATUS_OK;

    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), child1 as i64);

    write_process_ids(&t, child2, child1);
    assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
    assert_eq!(
        process_impl::sys_setpgid(&t.vm, t.base, 0, child1 as i64),
        0
    );
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), child1 as i64);
}

#[test]
fn semantics_setsid_creates_new_session_for_non_group_leader() {
    let t = TestVm::new();

    write_process_ids(&t, 1, 0);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 1);

    write_process_ids(&t, 42, 1);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 1);

    assert_eq!(process_impl::sys_setsid(&t.vm, t.base), 42);
    assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 42);
}
