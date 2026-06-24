use super::support::*;

#[test]
fn mount_dispatch_reports_permission_denied_instead_of_enosys() {
    let mut t = TestVm::new();

    t.vm.x[10] = 0;
    t.vm.x[11] = 0;
    t.vm.x[12] = 0;
    t.vm.x[13] = 0;
    t.vm.x[14] = 0;
    t.vm.x[17] = SYS_MOUNT;

    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, EPERM);
}

#[test]
fn umount2_dispatch_reports_not_mounted_for_existing_path() {
    let mut t = TestVm::new();

    assert_eq!(t.sys_mkdirat(b"/plain-dir"), 0);
    let path_addr = t.write_path(0x5800, b"/plain-dir");

    t.vm.x[10] = path_addr;
    t.vm.x[11] = 0;
    t.vm.x[17] = SYS_UMOUNT2;

    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, EINVAL);
}
