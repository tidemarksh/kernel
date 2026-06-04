use super::support::*;

#[test]
fn signal_syscalls() {
    let mut t = TestVm::new();

    let set_addr = t.scratch;
    let oldset_addr = t.scratch + 0x100;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, set_addr, 1 << 9);
    }
    let ret = signal::sys_rt_sigprocmask(&mut t.vm, t.base, 0, set_addr, oldset_addr, 8);
    assert_eq!(ret, 0);
    assert_eq!(t.vm.sig_mask & (1 << 9), 1 << 9);
    t.vm.sig_pending = 1 << 9;
    let pending_addr = t.scratch + 0x80;
    let pending_ret = signal::sys_rt_sigpending(&t.vm, t.base, pending_addr, 8);
    assert_eq!(pending_ret, 0);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, pending_addr) },
        1 << 9
    );

    let act_addr = t.scratch + 0x200;
    let oldact_addr = t.scratch + 0x300;
    write_sigaction(t.base, act_addr, 0x12345, 0, 0);
    let ret2 = signal::sys_rt_sigaction(&mut t.vm, t.base, 10, act_addr, oldact_addr, 8);
    assert_eq!(ret2, 0);

    let ss_addr = t.scratch + 0x400;
    let old_ss_addr = t.scratch + 0x500;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, ss_addr, 0x50000);
        tidemark_kernel::guest_mem::write_u32(t.base, ss_addr + 8, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, ss_addr + 16, 8192);
    }
    let ret3 = signal::sys_sigaltstack(&mut t.vm, t.base, ss_addr, old_ss_addr);
    assert_eq!(ret3, 0);
    assert_eq!(t.vm.sigaltstack_sp, 0x50000);
    assert_eq!(t.vm.sigaltstack_size, 8192);

    let old_default_addr = t.scratch + 0x540;
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, 1, 0, old_default_addr, 8),
        0
    );
    assert_eq!(read_sigaction(t.base, old_default_addr).handler, SIG_DFL);

    let act_addr2 = t.scratch + 0x600;
    let oldact_addr2 = t.scratch + 0x680;
    write_sigaction(t.base, act_addr2, 0xABCD, 0, 0);
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, 14, act_addr2, 0, 8),
        0
    );
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, 14, 0, oldact_addr2, 8),
        0
    );
    assert_eq!(read_sigaction(t.base, oldact_addr2).handler, 0xABCD);

    let invalid_addr = u64::MAX - 3;
    assert_eq!(
        signal::sys_rt_sigprocmask(&mut t.vm, t.base, 0, invalid_addr, 0, 8),
        abi::EFAULT
    );
    assert_eq!(
        signal::sys_rt_sigprocmask(&mut t.vm, t.base, 0, 0, invalid_addr, 8),
        abi::EFAULT
    );
}
