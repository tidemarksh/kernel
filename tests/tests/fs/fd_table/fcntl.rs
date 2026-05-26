use super::support::*;

#[test]
fn flock_rejects_invalid_operations() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/flock-invalid.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    assert_eq!(t.sys_flock(fd as u64, LOCK_NB), EINVAL);
    assert_eq!(t.sys_flock(fd as u64, LOCK_SH | LOCK_EX), EINVAL);
}

#[test]
fn flock_is_shared_by_dup_and_conflicts_across_distinct_ofds() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/flock.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    let dup_fd = t.sys_dup(fd as u64);
    assert!(dup_fd >= 3);
    let other_fd = t.sys_openat(b"/flock.txt", O_RDWR);
    assert!(other_fd >= 3);

    assert_eq!(t.sys_flock(fd as u64, LOCK_EX), 0);
    assert_eq!(t.sys_flock(other_fd as u64, LOCK_EX | LOCK_NB), EAGAIN);

    assert_eq!(t.sys_flock(dup_fd as u64, LOCK_UN), 0);
    assert_eq!(t.sys_flock(other_fd as u64, LOCK_EX), 0);
}

#[test]
fn flock_blocks_without_lock_nb() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/flock-block.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    let other_fd = t.sys_openat(b"/flock-block.txt", O_RDWR);
    assert!(other_fd >= 3);

    assert_eq!(t.sys_flock(fd as u64, LOCK_EX), 0);
    assert_eq!(t.sys_flock(other_fd as u64, LOCK_SH), 0);
    assert_eq!(t.vm.status, STATUS_FLOCK_WAIT);

    assert_eq!(t.sys_flock(fd as u64, LOCK_UN), 0);
    t.vm.status = STATUS_OK;
    assert_eq!(t.sys_flock(other_fd as u64, LOCK_SH), 0);
    assert_ne!(t.vm.status, STATUS_FLOCK_WAIT);
}
