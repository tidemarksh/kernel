use tidemark_kernel::harness::TestVm;

const RLIMIT_STACK: u64 = 3;
const RLIMIT_NOFILE: u64 = 7;

#[test]
fn prlimit64_reports_linux_shaped_defaults() {
    let t = TestVm::new();
    let stack_addr = t.scratch;
    let nofile_addr = t.scratch + 0x20;

    assert_eq!(
        tidemark_kernel::syscall::resource::sys_prlimit64(&t.vm, t.base, 0, RLIMIT_STACK, 0, stack_addr),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, stack_addr) },
        8 * 1024 * 1024
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, stack_addr + 8) },
        u64::MAX
    );

    assert_eq!(
        tidemark_kernel::syscall::resource::sys_prlimit64(&t.vm, t.base, 0, RLIMIT_NOFILE, 0, nofile_addr),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, nofile_addr) },
        tidemark_kernel::abi::MAX_FDS as u64
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, nofile_addr + 8) },
        tidemark_kernel::abi::MAX_FDS as u64
    );
}

#[test]
fn prlimit64_updates_current_process_limits() {
    let t = TestVm::new();
    let new_limit_addr = t.scratch;
    let old_limit_addr = t.scratch + 0x20;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, new_limit_addr, 512 * 1024);
        tidemark_kernel::guest_mem::write_u64(t.base, new_limit_addr + 8, 1024 * 1024);
    }
    assert_eq!(
        tidemark_kernel::syscall::resource::sys_prlimit64(
            &t.vm,
            t.base,
            0,
            RLIMIT_STACK,
            new_limit_addr,
            old_limit_addr,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, old_limit_addr) },
        8 * 1024 * 1024
    );
    assert_eq!(
        tidemark_kernel::syscall::resource::sys_prlimit64(&t.vm, t.base, 0, RLIMIT_STACK, 0, old_limit_addr),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, old_limit_addr) },
        512 * 1024
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, old_limit_addr + 8) },
        1024 * 1024
    );
}

#[test]
fn prlimit64_rejects_invalid_requests() {
    let t = TestVm::new();
    let limit_addr = t.scratch;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, limit_addr, 1024);
        tidemark_kernel::guest_mem::write_u64(t.base, limit_addr + 8, 512);
    }
    assert_eq!(
        tidemark_kernel::syscall::resource::sys_prlimit64(&t.vm, t.base, 0, RLIMIT_STACK, limit_addr, 0),
        tidemark_kernel::abi::EINVAL
    );
    assert_eq!(
        tidemark_kernel::syscall::resource::sys_prlimit64(&t.vm, t.base, 99, RLIMIT_STACK, 0, limit_addr),
        tidemark_kernel::abi::ESRCH
    );
    assert_eq!(
        tidemark_kernel::syscall::resource::sys_prlimit64(&t.vm, t.base, 0, 99, 0, limit_addr),
        tidemark_kernel::abi::EINVAL
    );
}
