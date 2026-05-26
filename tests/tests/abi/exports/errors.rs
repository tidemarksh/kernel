use super::support::*;

#[test]
fn error_codes_are_negative() {
    assert!(ENOENT < 0);
    assert!(EBADF < 0);
    assert!(EINVAL < 0);
    assert!(ENOMEM < 0);
    assert!(ENOSYS < 0);
}

#[test]
fn clone_flags_no_overlap() {
    assert_eq!(CLONE_VM & CLONE_THREAD, 0);
    assert_eq!(CLONE_VM & CLONE_VFORK, 0);
    assert_eq!(CLONE_THREAD & CLONE_VFORK, 0);
}
