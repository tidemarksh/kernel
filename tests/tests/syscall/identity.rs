use tidemark_kernel::harness::TestVm;

#[test]
fn identity_syscalls() {
    let mut t = TestVm::new();
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_getpid(&t.vm, t.base),
        42
    );
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_getppid(&t.vm, t.base),
        1
    );
    assert_eq!(tidemark_kernel::syscall::identity::sys_gettid(&t.vm), 1);

    let buf = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_uname(&t.vm, t.base, buf),
        0
    );
    let mut sysname = [0u8; 6];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf, &mut sysname);
    }
    assert_eq!(&sysname, b"Linux\0");

    let buf2 = t.scratch + 0x1000;
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_sysinfo(&t.vm, t.base, buf2),
        0
    );
    let totalram = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf2 + 32) };
    assert!(totalram > 0);
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_sysinfo(&t.vm, t.base, u64::MAX),
        tidemark_kernel::abi::EFAULT
    );
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_uname(&t.vm, t.base, u64::MAX),
        tidemark_kernel::abi::EFAULT
    );

    assert_eq!(tidemark_kernel::syscall::identity::sys_getuid(&t.vm), 0);
    assert_eq!(tidemark_kernel::syscall::identity::sys_geteuid(&t.vm), 0);
    assert_eq!(tidemark_kernel::syscall::identity::sys_getgid(&t.vm), 0);
    assert_eq!(tidemark_kernel::syscall::identity::sys_getegid(&t.vm), 0);
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_setgid(&mut t.vm, 65534),
        0
    );
    assert_eq!(tidemark_kernel::syscall::identity::sys_getgid(&t.vm), 65534);
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_getegid(&t.vm),
        65534
    );
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_setresuid(&mut t.vm, -1, 65534, -1),
        0
    );
    assert_eq!(tidemark_kernel::syscall::identity::sys_getuid(&t.vm), 0);
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_geteuid(&t.vm),
        65534
    );

    let ruid = t.scratch + 0x3000;
    let euid = ruid + 4;
    let suid = euid + 4;
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_getresuid(&t.vm, t.base, ruid, euid, suid),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, ruid) },
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, euid) },
        65534
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, suid) },
        65534
    );

    let rgid = suid + 4;
    let egid = rgid + 4;
    let sgid = egid + 4;
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_getresgid(&t.vm, t.base, rgid, egid, sgid),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, rgid) },
        65534
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, egid) },
        65534
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, sgid) },
        65534
    );

    let buf3 = t.scratch + 0x2000;
    unsafe {
        tidemark_kernel::guest_mem::zero_mem(t.base, buf3, 16);
    }
    let ret = tidemark_kernel::syscall::identity::sys_getrandom(&t.vm, t.base, buf3, 16, 0);
    assert_eq!(ret, 16);
    let mut bytes = [0u8; 16];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf3, &mut bytes);
    }
    assert!(bytes.iter().any(|&b| b != 0));
}
