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
    let mut release = [0u8; 6];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf + 130, &mut release);
    }
    assert_eq!(&release, b"6.1.0\0");

    let buf2 = t.scratch + 0x1000;
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_sysinfo(&t.vm, t.base, buf2),
        0
    );
    let totalram = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf2 + 32) };
    assert_eq!(
        totalram,
        tidemark_kernel::syscall::identity::SYSINFO_TOTALRAM_BYTES
    );
    let freeram = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf2 + 40) };
    assert_eq!(
        freeram,
        tidemark_kernel::syscall::identity::SYSINFO_FREERAM_BYTES
    );
    let mem_unit = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, buf2 + 104) };
    assert_eq!(
        mem_unit,
        tidemark_kernel::syscall::identity::SYSINFO_MEM_UNIT
    );

    t.vm.guest_memory_policy_limit = 2 * 1024 * 1024 * 1024;
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_sysinfo(&t.vm, t.base, buf2),
        0
    );
    let policy_totalram = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf2 + 32) };
    assert_eq!(policy_totalram, 2 * 1024 * 1024 * 1024);
    let policy_freeram = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf2 + 40) };
    assert_eq!(policy_freeram, 1024 * 1024 * 1024);

    t.vm.guest_memory_policy_limit = 0;
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

    let buf4 = buf3 + 0x40;
    unsafe {
        tidemark_kernel::guest_mem::zero_mem(t.base, buf4, 16);
    }
    let ret2 = tidemark_kernel::syscall::identity::sys_getrandom(&t.vm, t.base, buf4, 16, 0);
    assert_eq!(ret2, 16);
    let mut bytes2 = [0u8; 16];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(t.base, buf4, &mut bytes2);
    }
    assert_ne!(bytes, bytes2);

    assert_eq!(
        tidemark_kernel::syscall::identity::sys_getrandom(&t.vm, t.base, buf4, 0, 0),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_getrandom(&t.vm, t.base, u64::MAX, 16, 0),
        tidemark_kernel::abi::EFAULT
    );
    assert_eq!(
        tidemark_kernel::syscall::identity::sys_getrandom(&t.vm, t.base, buf4, 16, 0x8000),
        tidemark_kernel::abi::EINVAL
    );
}

#[test]
fn riscv_hwprobe_reports_base_ima_and_common_ima_extensions() {
    let t = TestVm::new();
    let pairs = t.scratch + 0x4000;
    let cpus = t.scratch + 0x4100;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, pairs, 3);
        tidemark_kernel::guest_mem::write_u64(t.base, pairs + 8, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, pairs + 16, 4);
        tidemark_kernel::guest_mem::write_u64(t.base, pairs + 24, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, pairs + 32, 7);
        tidemark_kernel::guest_mem::write_u64(t.base, pairs + 40, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, pairs + 48, 99);
        tidemark_kernel::guest_mem::write_u64(t.base, pairs + 56, 0);
        tidemark_kernel::guest_mem::write_u8(t.base, cpus, 0);
    }

    assert_eq!(
        tidemark_kernel::syscall::identity::sys_riscv_hwprobe(&t.vm, t.base, pairs, 4, 8, cpus, 1),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_i64(t.base, pairs) },
        3
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, pairs + 8) },
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_i64(t.base, pairs + 16) },
        4
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, pairs + 24) },
        0b11
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_i64(t.base, pairs + 32) },
        7
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, pairs + 40) },
        0x0000_7fff_ffff_ffff
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_i64(t.base, pairs + 48) },
        -1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, pairs + 56) },
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u8(t.base, cpus) },
        1
    );
}

#[test]
fn rseq_reports_enosys_for_no_rseq_posture() {
    let mut t = TestVm::new();
    t.vm.x[17] = tidemark_kernel::abi::SYS_RSEQ;
    assert_eq!(tidemark_kernel::syscall::dispatch(&mut t.vm, t.base), 0);
    assert_eq!(t.vm.x[10] as i64, tidemark_kernel::abi::ENOSYS);
}

#[test]
fn riscv_flush_icache_is_linux_shaped_noop_success() {
    let mut t = TestVm::new();
    t.vm.x[17] = tidemark_kernel::abi::SYS_RISCV_FLUSH_ICACHE;
    t.vm.x[10] = 0x1000;
    t.vm.x[11] = 0x2000;
    t.vm.x[12] = 0;
    assert_eq!(tidemark_kernel::syscall::dispatch(&mut t.vm, t.base), 0);
    assert_eq!(t.vm.x[10], 0);

    t.vm.x[17] = tidemark_kernel::abi::SYS_RISCV_FLUSH_ICACHE;
    t.vm.x[10] = u64::MAX;
    t.vm.x[11] = 0;
    t.vm.x[12] = u64::MAX;
    assert_eq!(tidemark_kernel::syscall::dispatch(&mut t.vm, t.base), 0);
    assert_eq!(t.vm.x[10], 0);
}
