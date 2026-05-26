use super::support::*;

#[test]
fn dup_and_dup3_allocate_fd_entries() {
    let mut t = TestVm::new();

    let newfd = t.sys_dup(1);
    assert_eq!(newfd, 3);

    assert_eq!(t.sys_dup3(1, 10, O_CLOEXEC as u64), 10);
}
