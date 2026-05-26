use super::support::*;

#[test]
fn lseek_on_pipe_returns_espipe() {
    let mut t = TestVm::new();

    let pipefd_addr = t.scratch + 0x3650;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
        0
    );
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as i64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;

    assert_eq!(t.sys_lseek(read_fd, 0, 0), ESPIPE);
    assert_eq!(t.sys_lseek(write_fd, 0, 1), ESPIPE);
}

#[test]
fn lseek_negative_result_returns_einval() {
    let mut t = TestVm::new();

    let fd = t.sys_openat(b"/seek-negative.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    assert_eq!(t.sys_lseek(fd, -1, 0), EINVAL);
    assert_eq!(t.sys_lseek(fd, 0, 0), 0);
}
