use tidemark_kernel::abi;
use tidemark_kernel::harness::TestVm;

const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const ITIMER_REAL: u64 = 0;

#[test]
fn clock_gettime_realtime_uses_base_plus_monotonic() {
    let t = TestVm::new();
    tidemark_kernel::syscall::time::set_base_time(1735689600, 0);
    tidemark_kernel::syscall::time::advance_monotonic(100_000_000);

    let tp = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_REALTIME, tp),
        0
    );
    let sec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) };
    assert_eq!(sec, 1735689601);
}

#[test]
fn clock_gettime_monotonic_returns_ticks_based() {
    let t = TestVm::new();
    tidemark_kernel::syscall::time::advance_monotonic(200_000_000);

    let tp = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_MONOTONIC, tp),
        0
    );
    let sec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) };
    assert!(sec >= 2);
}

#[test]
fn sync_monotonic_ticks_floor_only_moves_forward() {
    let t = TestVm::new();
    let tp = t.scratch;

    tidemark_kernel::syscall::time::advance_monotonic(200_000_000);
    tidemark_kernel::syscall::time::sync_monotonic_ticks_floor(100_000_000);
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_MONOTONIC, tp),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) },
        2
    );

    tidemark_kernel::syscall::time::sync_monotonic_ticks_floor(300_000_000);
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_MONOTONIC, tp),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) },
        3
    );
}

#[test]
fn clock_gettime_monotonic_is_nonzero_at_startup() {
    let t = TestVm::new();
    let tp = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_MONOTONIC, tp),
        0
    );
    let sec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) };
    let nsec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp + 8) };
    assert!(sec > 0 || nsec > 0);
}

#[test]
fn clock_gettime_invalid_clk_id_returns_einval() {
    let t = TestVm::new();
    let tp = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, 999, tp),
        abi::EINVAL,
    );
}

#[test]
fn clock_gettime_null_tp_returns_efault() {
    let t = TestVm::new();
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, 0, 0),
        abi::EFAULT,
    );
}

#[test]
fn clock_getres_validates_clk_id() {
    let t = TestVm::new();
    let res = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_getres(&t.vm, t.base, 0, res),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_getres(&t.vm, t.base, 999, res),
        abi::EINVAL
    );
}

#[test]
fn setitimer_and_getitimer_round_trip() {
    let t = TestVm::new();
    let new_value = t.scratch + 0x100;
    let curr_value = t.scratch + 0x200;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, new_value, 3);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 8, 250_000);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 16, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 24, 125_000);
    }

    assert_eq!(
        tidemark_kernel::syscall::time::sys_setitimer(&t.vm, t.base, ITIMER_REAL, new_value, 0),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_getitimer(&t.vm, t.base, ITIMER_REAL, curr_value),
        0
    );

    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value) },
        3
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value + 8) },
        250_000
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value + 16) },
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value + 24) },
        125_000
    );
}

#[test]
fn setitimer_rejects_invalid_usec_fields() {
    let t = TestVm::new();
    let new_value = t.scratch + 0x300;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, new_value, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 8, 1_000_000);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 16, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 24, 0);
    }

    assert_eq!(
        tidemark_kernel::syscall::time::sys_setitimer(&t.vm, t.base, ITIMER_REAL, new_value, 0),
        abi::EINVAL
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_getitimer(&t.vm, t.base, ITIMER_REAL, 0),
        abi::EFAULT
    );
}

#[test]
fn sched_getaffinity_accepts_large_cpuset_buffers() {
    let t = TestVm::new();
    let mask_addr = t.scratch + 0x400;

    t.write_mem(mask_addr, &[0xaa; 128]);

    assert_eq!(
        tidemark_kernel::syscall::time::sys_sched_getaffinity(&t.vm, t.base, 0, 128, mask_addr),
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, mask_addr) },
        1
    );
}
