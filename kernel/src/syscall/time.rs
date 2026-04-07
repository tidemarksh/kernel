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
use core::time::Duration;

// Clock IDs (https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/time.h)
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
const CLOCK_MONOTONIC_RAW: u64 = 4;
const CLOCK_REALTIME_COARSE: u64 = 5;
const CLOCK_MONOTONIC_COARSE: u64 = 6;
const CLOCK_BOOTTIME: u64 = 7;
const TIMER_ABSTIME: u64 = 1;
const ITIMER_REAL: u64 = 0;
const ITIMER_VIRTUAL: u64 = 1;
const ITIMER_PROF: u64 = 2;
const TICKS_PER_SEC: u64 = 100_000_000;

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
                monotonic_ticks: 1,
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

pub fn time_state_bytes() -> u32 {
    core::mem::size_of::<TimeState>() as u32
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

/// Advance monotonic time by an exact wall-clock duration in virtual time.
pub fn advance_monotonic_duration(duration: Duration) {
    let sec_ticks = duration.as_secs().saturating_mul(TICKS_PER_SEC);
    let subsec_ticks =
        (duration.subsec_nanos() as u64).saturating_mul(TICKS_PER_SEC) / 1_000_000_000;
    advance_monotonic(sec_ticks.saturating_add(subsec_ticks));
}

pub fn sync_monotonic_ticks_floor(ticks: u64) {
    let state = ts();
    if ticks > state.monotonic_ticks {
        state.monotonic_ticks = ticks;
    }
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

pub fn current_timespec(clk_id: u64) -> Option<(u64, u64)> {
    match clk_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => {
            let (base_sec, base_nsec) = base_time();
            let (mono_sec, mono_nsec) = ticks_to_timespec(monotonic_ticks());
            let total_nsec = base_nsec + mono_nsec;
            Some((
                base_sec + mono_sec + total_nsec / 1_000_000_000,
                total_nsec % 1_000_000_000,
            ))
        }
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            Some(ticks_to_timespec(monotonic_ticks()))
        }
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            Some(ticks_to_timespec(monotonic_ticks()))
        }
        _ => None,
    }
}

/// Convert monotonic ticks to (sec, nsec). Assumes ~100M instructions/sec.
fn ticks_to_timespec(ticks: u64) -> (u64, u64) {
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

    let Some((sec, nsec)) = current_timespec(clk_id) else {
        return abi::EINVAL;
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

pub fn sys_clock_nanosleep(
    vm: &mut ThreadState,
    base: u32,
    clk_id: u64,
    flags: u64,
    req: u64,
    _rem: u64,
) -> i32 {
    let Some((req_sec, req_nsec)) = (|| {
        if req == 0 {
            return None;
        }
        Some(unsafe { (guest_mem::read_u64(base, req), guest_mem::read_u64(base, req + 8)) })
    })() else {
        vm.x[10] = abi::EFAULT as u64;
        return abi::STATUS_OK;
    };

    if req_nsec >= 1_000_000_000 {
        vm.x[10] = abi::EINVAL as u64;
        return abi::STATUS_OK;
    }
    if current_timespec(clk_id).is_none() {
        vm.x[10] = abi::EINVAL as u64;
        return abi::STATUS_OK;
    }

    let (sleep_sec, sleep_nsec) = if flags & TIMER_ABSTIME != 0 {
        let Some((now_sec, now_nsec)) = current_timespec(clk_id) else {
            vm.x[10] = abi::EINVAL as u64;
            return abi::STATUS_OK;
        };
        let now_total = now_sec.saturating_mul(1_000_000_000).saturating_add(now_nsec);
        let req_total = req_sec.saturating_mul(1_000_000_000).saturating_add(req_nsec);
        if req_total <= now_total {
            (0, 0)
        } else {
            let delta = req_total - now_total;
            (delta / 1_000_000_000, delta % 1_000_000_000)
        }
    } else {
        (req_sec, req_nsec)
    };

    vm.fault_addr = sleep_sec;
    vm.fault_pc = sleep_nsec;
    vm.x[10] = 0;
    vm.status = abi::STATUS_SLEEP;
    abi::STATUS_SLEEP
}

/// sched_yield: cooperative yield point for the runtime/test harness.
/// Returns STATUS_SLEEP so the outer scheduler can run another runnable thread
/// before resuming this one; guest-visible return value remains 0.
/// https://man7.org/linux/man-pages/man2/sched_yield.2.html
pub fn sys_sched_yield(vm: &mut ThreadState) -> i32 {
    vm.fault_addr = 0;
    vm.fault_pc = 0;
    vm.x[10] = 0;
    vm.status = abi::STATUS_SLEEP;
    abi::STATUS_SLEEP
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

    if !crate::syscall::memory::guest_range_accessible(base, mask_addr, 8) {
        return abi::EFAULT;
    }

    unsafe {
        guest_mem::write_u64(base, mask_addr, 1);
    }
    8
}
