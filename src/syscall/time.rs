//! Time syscalls: clock_gettime, clock_getres, nanosleep, sched_yield.
//!
//! Struct layout (RV64):
//!
//! struct __kernel_timespec {        // 16 bytes total
//!     tv_sec:  i64,                 // offset 0
//!     tv_nsec: i64,                 // offset 8
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/time_types.h
//!
//! clock_gettime semantics:
//! https://man7.org/linux/man-pages/man2/clock_gettime.2.html
//!
//! CLOCK_REALTIME: base time (injected by runtime via set_base_time) + monotonic offset.
//! CLOCK_MONOTONIC: instruction-count-based virtual time.
//! WASM has no system clock — time is derived from execution progress.

use crate::abi;
use crate::guest_mem;
use crate::types::ThreadState;

// Clock IDs (https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/time.h)
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
const CLOCK_MONOTONIC_RAW: u64 = 4;
const CLOCK_REALTIME_COARSE: u64 = 5;
const CLOCK_MONOTONIC_COARSE: u64 = 6;
const CLOCK_BOOTTIME: u64 = 7;

// Base time injected by runtime. Defaults to a reasonable epoch if not set.
static mut BASE_TIME_SEC: u64 = 0;
static mut BASE_TIME_NSEC: u64 = 0;
static mut BASE_TIME_SET: bool = false;

// Monotonic counter incremented by instruction execution.
static mut MONOTONIC_TICKS: u64 = 0;

/// Reset time state. Called during test heap reset.
pub fn init() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(BASE_TIME_SEC), 0);
        core::ptr::write(core::ptr::addr_of_mut!(BASE_TIME_NSEC), 0);
        core::ptr::write(core::ptr::addr_of_mut!(BASE_TIME_SET), false);
        core::ptr::write(core::ptr::addr_of_mut!(MONOTONIC_TICKS), 0);
    }
}

/// Set the base wall-clock time. Called by runtime at initialization.
/// All subsequent clock_gettime(CLOCK_REALTIME) calls use this as the epoch.
pub fn set_base_time(sec: u64, nsec: u64) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(BASE_TIME_SEC), sec);
        core::ptr::write(core::ptr::addr_of_mut!(BASE_TIME_NSEC), nsec);
        core::ptr::write(core::ptr::addr_of_mut!(BASE_TIME_SET), true);
    }
}

/// Advance the monotonic clock by `ticks` (typically instruction count).
pub fn advance_monotonic(ticks: u64) {
    unsafe {
        let p = core::ptr::addr_of_mut!(MONOTONIC_TICKS);
        let current = core::ptr::read(p);
        core::ptr::write(p, current + ticks);
    }
}

fn monotonic_ticks() -> u64 {
    unsafe { core::ptr::read(core::ptr::addr_of!(MONOTONIC_TICKS)) }
}

fn base_time() -> (u64, u64) {
    unsafe {
        if core::ptr::read(core::ptr::addr_of!(BASE_TIME_SET)) {
            (core::ptr::read(core::ptr::addr_of!(BASE_TIME_SEC)),
             core::ptr::read(core::ptr::addr_of!(BASE_TIME_NSEC)))
        } else {
            (1700000000, 0) // fallback: ~2023-11-14 if runtime didn't set base time
        }
    }
}

/// Convert monotonic ticks to (sec, nsec). Assumes ~100M instructions/sec.
fn ticks_to_timespec(ticks: u64) -> (u64, u64) {
    const TICKS_PER_SEC: u64 = 100_000_000;
    let sec = ticks / TICKS_PER_SEC;
    let nsec = (ticks % TICKS_PER_SEC) * (1_000_000_000 / TICKS_PER_SEC);
    (sec, nsec)
}

/// clock_gettime: write timespec to guest memory.
/// https://man7.org/linux/man-pages/man2/clock_gettime.2.html
pub fn sys_clock_gettime(_vm: &ThreadState, base: u32, clk_id: u64, tp: u64) -> i64 {
    if tp == 0 { return abi::EFAULT; }

    let (sec, nsec) = match clk_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => {
            let (base_sec, base_nsec) = base_time();
            let (mono_sec, mono_nsec) = ticks_to_timespec(monotonic_ticks());
            let total_nsec = base_nsec + mono_nsec;
            (base_sec + mono_sec + total_nsec / 1_000_000_000,
             total_nsec % 1_000_000_000)
        }
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            ticks_to_timespec(monotonic_ticks())
        }
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            ticks_to_timespec(monotonic_ticks())
        }
        _ => return abi::EINVAL,
    };

    unsafe {
        guest_mem::write_u64(base, tp, sec);
        guest_mem::write_u64(base, tp + 8, nsec);
    }
    0
}

/// clock_getres: return resolution. Validates clk_id.
/// https://man7.org/linux/man-pages/man2/clock_getres.2.html
pub fn sys_clock_getres(_vm: &ThreadState, base: u32, clk_id: u64, res: u64) -> i64 {
    match clk_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID |
        CLOCK_THREAD_CPUTIME_ID | CLOCK_MONOTONIC_RAW | CLOCK_REALTIME_COARSE |
        CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {}
        _ => return abi::EINVAL,
    }
    if res != 0 {
        unsafe {
            guest_mem::write_u64(base, res, 0);     // tv_sec = 0
            guest_mem::write_u64(base, res + 8, 1); // tv_nsec = 1 (1 ns resolution)
        }
    }
    0
}

/// nanosleep: return STATUS_SLEEP so JS can setTimeout.
/// https://man7.org/linux/man-pages/man2/nanosleep.2.html
pub fn sys_nanosleep(vm: &mut ThreadState, base: u32, req: u64, _rem: u64) -> i32 {
    if req != 0 {
        let sec = unsafe { guest_mem::read_u64(base, req) };
        let nsec = unsafe { guest_mem::read_u64(base, req + 8) };
        // Store sleep duration for runtime to read
        vm.fault_addr = sec;
        vm.fault_pc = nsec;
    }
    vm.x[10] = 0; // return 0 on success
    vm.status = abi::STATUS_SLEEP;
    abi::STATUS_SLEEP
}

/// sched_yield: no-op, return success.
/// https://man7.org/linux/man-pages/man2/sched_yield.2.html
pub fn sys_sched_yield() -> i64 { 0 }

#[cfg(test)]
mod tests {
    use crate::test_helpers::TestVm;

    #[test]
    fn clock_gettime_realtime_uses_base_plus_monotonic() {
        let mut t = TestVm::new();
        // Set base time to 2025-01-01 00:00:00
        super::set_base_time(1735689600, 0);
        super::advance_monotonic(100_000_000); // 1 second worth of ticks

        let tp = t.scratch;
        assert_eq!(super::sys_clock_gettime(&t.vm, t.base, super::CLOCK_REALTIME, tp), 0);
        let sec = unsafe { crate::guest_mem::read_u64(t.base, tp) };
        assert_eq!(sec, 1735689601, "CLOCK_REALTIME should be base + monotonic offset");
    }

    #[test]
    fn clock_gettime_monotonic_returns_ticks_based() {
        let mut t = TestVm::new();
        super::advance_monotonic(200_000_000); // 2 seconds

        let tp = t.scratch;
        assert_eq!(super::sys_clock_gettime(&t.vm, t.base, super::CLOCK_MONOTONIC, tp), 0);
        let sec = unsafe { crate::guest_mem::read_u64(t.base, tp) };
        assert!(sec >= 2, "CLOCK_MONOTONIC should reflect monotonic ticks");
    }

    #[test]
    fn clock_gettime_invalid_clk_id_returns_einval() {
        let mut t = TestVm::new();
        let tp = t.scratch;
        assert_eq!(
            super::sys_clock_gettime(&t.vm, t.base, 999, tp),
            crate::abi::EINVAL,
        );
    }

    #[test]
    fn clock_gettime_null_tp_returns_efault() {
        let mut t = TestVm::new();
        assert_eq!(
            super::sys_clock_gettime(&t.vm, t.base, 0, 0),
            crate::abi::EFAULT,
        );
    }

    #[test]
    fn clock_getres_validates_clk_id() {
        let mut t = TestVm::new();
        let res = t.scratch;
        assert_eq!(super::sys_clock_getres(&t.vm, t.base, 0, res), 0);
        assert_eq!(super::sys_clock_getres(&t.vm, t.base, 999, res), crate::abi::EINVAL);
    }
}
