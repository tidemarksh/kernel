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
use crate::alloc;
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
const ITIMER_REAL: u64 = 0;
const ITIMER_VIRTUAL: u64 = 1;
const ITIMER_PROF: u64 = 2;

#[derive(Clone, Copy)]
struct ItimerState {
    interval_sec: u64,
    interval_usec: u64,
    value_sec: u64,
    value_usec: u64,
}

#[repr(C)]
struct TimeState {
    base_time_sec: u64,
    base_time_nsec: u64,
    base_time_set: u32,
    _pad: u32,
    monotonic_ticks: u64,
    itimers: [[ItimerState; 3]; abi::MAX_PROCESSES],
}

static mut TIME_STATE: *mut TimeState = core::ptr::null_mut();

fn ts() -> &'static mut TimeState {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(TIME_STATE));
        &mut *p
    }
}

/// Reset time state. Called during test heap reset.
pub fn init() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(TIME_STATE), core::ptr::null_mut());
        let ptr = alloc::alloc_zeroed(
            core::mem::size_of::<TimeState>() as u32,
            core::mem::align_of::<TimeState>() as u32,
        );
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            ptr as *mut TimeState,
            TimeState {
                base_time_sec: 0,
                base_time_nsec: 0,
                base_time_set: 0,
                _pad: 0,
                monotonic_ticks: 0,
                itimers: [[ItimerState {
                    interval_sec: 0,
                    interval_usec: 0,
                    value_sec: 0,
                    value_usec: 0,
                }; 3]; abi::MAX_PROCESSES],
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(TIME_STATE), ptr as *mut TimeState);
    }
}

pub fn time_state_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(TIME_STATE)) as u32 }
}

pub fn attach_time_state_ptr(ptr: u32) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(TIME_STATE), ptr as *mut TimeState);
    }
}

/// Set the base wall-clock time. Called by runtime at initialization.
/// All subsequent clock_gettime(CLOCK_REALTIME) calls use this as the epoch.
pub fn set_base_time(sec: u64, nsec: u64) {
    let state = ts();
    state.base_time_sec = sec;
    state.base_time_nsec = nsec;
    state.base_time_set = 1;
}

/// Advance the monotonic clock by `ticks` (typically instruction count).
pub fn advance_monotonic(ticks: u64) {
    ts().monotonic_ticks += ticks;
}

fn monotonic_ticks() -> u64 {
    ts().monotonic_ticks
}

fn base_time() -> (u64, u64) {
    let state = ts();
    if state.base_time_set != 0 {
        (state.base_time_sec, state.base_time_nsec)
    } else {
        (1700000000, 0) // fallback: ~2023-11-14 if runtime didn't set base time
    }
}

/// Convert monotonic ticks to (sec, nsec). Assumes ~100M instructions/sec.
fn ticks_to_timespec(ticks: u64) -> (u64, u64) {
    const TICKS_PER_SEC: u64 = 100_000_000;
    let sec = ticks / TICKS_PER_SEC;
    let nsec = (ticks % TICKS_PER_SEC) * (1_000_000_000 / TICKS_PER_SEC);
    (sec, nsec)
}

fn itimer_index(which: u64) -> Option<usize> {
    match which {
        ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF => Some(which as usize),
        _ => None,
    }
}

fn itimer_for_pid(pid: i32, which: u64) -> Option<&'static mut ItimerState> {
    let which_idx = itimer_index(which)?;
    if !(1..=abi::MAX_PROCESSES as i32).contains(&pid) {
        return None;
    }
    Some(&mut ts().itimers[(pid - 1) as usize][which_idx])
}

fn write_itimerval(base: u32, addr: u64, timer: ItimerState) {
    unsafe {
        guest_mem::write_u64(base, addr, timer.interval_sec);
        guest_mem::write_u64(base, addr + 8, timer.interval_usec);
        guest_mem::write_u64(base, addr + 16, timer.value_sec);
        guest_mem::write_u64(base, addr + 24, timer.value_usec);
    }
}

fn read_itimerval(base: u32, addr: u64) -> Result<ItimerState, i64> {
    if addr == 0 {
        return Ok(ItimerState {
            interval_sec: 0,
            interval_usec: 0,
            value_sec: 0,
            value_usec: 0,
        });
    }

    let interval_sec = unsafe { guest_mem::read_i64(base, addr) };
    let interval_usec = unsafe { guest_mem::read_i64(base, addr + 8) };
    let value_sec = unsafe { guest_mem::read_i64(base, addr + 16) };
    let value_usec = unsafe { guest_mem::read_i64(base, addr + 24) };

    if interval_sec < 0
        || value_sec < 0
        || !(0..=999_999).contains(&interval_usec)
        || !(0..=999_999).contains(&value_usec)
    {
        return Err(abi::EINVAL);
    }

    Ok(ItimerState {
        interval_sec: interval_sec as u64,
        interval_usec: interval_usec as u64,
        value_sec: value_sec as u64,
        value_usec: value_usec as u64,
    })
}

/// clock_gettime: write timespec to guest memory.
/// https://man7.org/linux/man-pages/man2/clock_gettime.2.html
pub fn sys_clock_gettime(_vm: &ThreadState, base: u32, clk_id: u64, tp: u64) -> i64 {
    if tp == 0 {
        return abi::EFAULT;
    }

    let (sec, nsec) = match clk_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => {
            let (base_sec, base_nsec) = base_time();
            let (mono_sec, mono_nsec) = ticks_to_timespec(monotonic_ticks());
            let total_nsec = base_nsec + mono_nsec;
            (
                base_sec + mono_sec + total_nsec / 1_000_000_000,
                total_nsec % 1_000_000_000,
            )
        }
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            ticks_to_timespec(monotonic_ticks())
        }
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => ticks_to_timespec(monotonic_ticks()),
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
        CLOCK_REALTIME
        | CLOCK_MONOTONIC
        | CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID
        | CLOCK_MONOTONIC_RAW
        | CLOCK_REALTIME_COARSE
        | CLOCK_MONOTONIC_COARSE
        | CLOCK_BOOTTIME => {}
        _ => return abi::EINVAL,
    }
    if res != 0 {
        unsafe {
            guest_mem::write_u64(base, res, 0); // tv_sec = 0
            guest_mem::write_u64(base, res + 8, 1); // tv_nsec = 1 (1 ns resolution)
        }
    }
    0
}

/// getitimer: return the current interval timer for this process.
/// https://man7.org/linux/man-pages/man2/setitimer.2.html
pub fn sys_getitimer(vm: &ThreadState, base: u32, which: u64, curr_value: u64) -> i64 {
    if curr_value == 0 {
        return abi::EFAULT;
    }

    let pid = crate::syscall::signal::pid_from_vm(vm, base);
    let timer = match itimer_for_pid(pid, which) {
        Some(timer) => *timer,
        None => return abi::EINVAL,
    };
    write_itimerval(base, curr_value, timer);
    0
}

/// setitimer: store per-process interval timer state.
/// We preserve Linux-visible state, but do not schedule asynchronous delivery yet.
/// https://man7.org/linux/man-pages/man2/setitimer.2.html
pub fn sys_setitimer(
    vm: &ThreadState,
    base: u32,
    which: u64,
    new_value: u64,
    old_value: u64,
) -> i64 {
    let pid = crate::syscall::signal::pid_from_vm(vm, base);
    let timer = match itimer_for_pid(pid, which) {
        Some(timer) => timer,
        None => return abi::EINVAL,
    };

    if old_value != 0 {
        write_itimerval(base, old_value, *timer);
    }

    let next = match read_itimerval(base, new_value) {
        Ok(timer) => timer,
        Err(errno) => return errno,
    };
    *timer = next;
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
pub fn sys_sched_yield() -> i64 {
    0
}

/// sched_getaffinity: expose a single online CPU.
/// The raw syscall returns the number of bytes written.
/// https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html
pub fn sys_sched_getaffinity(
    vm: &ThreadState,
    base: u32,
    pid: i64,
    cpusetsize: u64,
    mask_addr: u64,
) -> i64 {
    if mask_addr == 0 {
        return abi::EFAULT;
    }
    if cpusetsize < 8 {
        return abi::EINVAL;
    }

    let self_pid = crate::syscall::signal::pid_from_vm(vm, base) as i64;
    if pid != 0 && pid != self_pid && pid != vm.tid as i64 {
        return abi::ESRCH;
    }

    unsafe {
        guest_mem::zero_mem(base, mask_addr, cpusetsize as usize);
        guest_mem::write_u64(base, mask_addr, 1);
    }
    8
}

#[cfg(test)]
mod tests {
    use crate::abi;
    use crate::test_helpers::TestVm;

    #[test]
    fn clock_gettime_realtime_uses_base_plus_monotonic() {
        let mut t = TestVm::new();
        // Set base time to 2025-01-01 00:00:00
        super::set_base_time(1735689600, 0);
        super::advance_monotonic(100_000_000); // 1 second worth of ticks

        let tp = t.scratch;
        assert_eq!(
            super::sys_clock_gettime(&t.vm, t.base, super::CLOCK_REALTIME, tp),
            0
        );
        let sec = unsafe { crate::guest_mem::read_u64(t.base, tp) };
        assert_eq!(
            sec, 1735689601,
            "CLOCK_REALTIME should be base + monotonic offset"
        );
    }

    #[test]
    fn clock_gettime_monotonic_returns_ticks_based() {
        let mut t = TestVm::new();
        super::advance_monotonic(200_000_000); // 2 seconds

        let tp = t.scratch;
        assert_eq!(
            super::sys_clock_gettime(&t.vm, t.base, super::CLOCK_MONOTONIC, tp),
            0
        );
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
        assert_eq!(
            super::sys_clock_getres(&t.vm, t.base, 999, res),
            crate::abi::EINVAL
        );
    }

    #[test]
    fn setitimer_and_getitimer_round_trip() {
        let t = TestVm::new();
        let new_value = t.scratch + 0x100;
        let curr_value = t.scratch + 0x200;

        unsafe {
            crate::guest_mem::write_u64(t.base, new_value, 3);
            crate::guest_mem::write_u64(t.base, new_value + 8, 250_000);
            crate::guest_mem::write_u64(t.base, new_value + 16, 1);
            crate::guest_mem::write_u64(t.base, new_value + 24, 125_000);
        }

        assert_eq!(
            super::sys_setitimer(&t.vm, t.base, super::ITIMER_REAL, new_value, 0),
            0
        );
        assert_eq!(
            super::sys_getitimer(&t.vm, t.base, super::ITIMER_REAL, curr_value),
            0
        );

        assert_eq!(unsafe { crate::guest_mem::read_u64(t.base, curr_value) }, 3);
        assert_eq!(
            unsafe { crate::guest_mem::read_u64(t.base, curr_value + 8) },
            250_000
        );
        assert_eq!(
            unsafe { crate::guest_mem::read_u64(t.base, curr_value + 16) },
            1
        );
        assert_eq!(
            unsafe { crate::guest_mem::read_u64(t.base, curr_value + 24) },
            125_000
        );
    }

    #[test]
    fn setitimer_rejects_invalid_usec_fields() {
        let t = TestVm::new();
        let new_value = t.scratch + 0x300;

        unsafe {
            crate::guest_mem::write_u64(t.base, new_value, 0);
            crate::guest_mem::write_u64(t.base, new_value + 8, 1_000_000);
            crate::guest_mem::write_u64(t.base, new_value + 16, 0);
            crate::guest_mem::write_u64(t.base, new_value + 24, 0);
        }

        assert_eq!(
            super::sys_setitimer(&t.vm, t.base, super::ITIMER_REAL, new_value, 0),
            abi::EINVAL
        );
        assert_eq!(
            super::sys_getitimer(&t.vm, t.base, super::ITIMER_REAL, 0),
            abi::EFAULT
        );
    }
}
