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

#[derive(Clone, Copy)]
struct TimerFdState {
    used: u32,
    _pad: u32,
    clock_id: u64,
    next_expiration_ticks: u64,
    interval_ticks: u64,
    expirations: u64,
}

const EMPTY_TIMERFD_STATE: TimerFdState = TimerFdState {
    used: 0,
    _pad: 0,
    clock_id: 0,
    next_expiration_ticks: 0,
    interval_ticks: 0,
    expirations: 0,
};

#[repr(C)]
struct TimeState {
    base_time_sec: u64,
    base_time_nsec: u64,
    base_time_set: u32,
    _pad: u32,
    monotonic_ticks: u64,
    itimers: [[ItimerState; 3]; abi::MAX_PROCESSES],
    timerfds: [TimerFdState; abi::MAX_TIMERFDS + 1],
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
                timerfds: [EMPTY_TIMERFD_STATE; abi::MAX_TIMERFDS + 1],
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

pub fn monotonic_ticks_current() -> u64 {
    monotonic_ticks()
}

fn timespec_to_ticks_floor(sec: u64, nsec: u64) -> u64 {
    sec.saturating_mul(TICKS_PER_SEC)
        .saturating_add(nsec.saturating_mul(TICKS_PER_SEC) / 1_000_000_000)
}

fn timespec_to_ticks_ceil(sec: u64, nsec: u64) -> u64 {
    let base = sec.saturating_mul(TICKS_PER_SEC);
    let sub = nsec.saturating_mul(TICKS_PER_SEC);
    let rounded = if sub == 0 {
        0
    } else {
        sub.div_ceil(1_000_000_000)
    };
    base.saturating_add(rounded)
}

pub fn sleep_deadline_ticks(sec: u64, nsec: u64) -> u64 {
    monotonic_ticks().saturating_add(timespec_to_ticks_ceil(sec, nsec))
}

fn base_time() -> (u64, u64) {
    let state = ts();
    if state.base_time_set != 0 {
        (state.base_time_sec, state.base_time_nsec)
    } else {
        (1700000000, 0) // fallback: ~2023-11-14 if runtime didn't set base time
    }
}

fn timerfd_clock_supported(clock_id: u64) -> bool {
    matches!(clock_id, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME)
}

fn current_ticks_for_clock(clock_id: u64) -> Option<u64> {
    match clock_id {
        CLOCK_MONOTONIC | CLOCK_BOOTTIME => Some(monotonic_ticks()),
        CLOCK_REALTIME => {
            let (sec, nsec) = current_timespec(CLOCK_REALTIME)?;
            Some(timespec_to_ticks_floor(sec, nsec))
        }
        _ => None,
    }
}

fn timerfd_slot(idx: u32) -> Option<&'static mut TimerFdState> {
    if idx == 0 || idx as usize > abi::MAX_TIMERFDS {
        return None;
    }
    Some(&mut ts().timerfds[idx as usize])
}

fn update_timerfd(slot: &mut TimerFdState) {
    if slot.used == 0 || slot.next_expiration_ticks == 0 {
        return;
    }
    let Some(now) = current_ticks_for_clock(slot.clock_id) else {
        return;
    };
    if now < slot.next_expiration_ticks {
        return;
    }

    if slot.interval_ticks == 0 {
        slot.expirations = slot.expirations.saturating_add(1);
        slot.next_expiration_ticks = 0;
        return;
    }

    let elapsed = now.saturating_sub(slot.next_expiration_ticks);
    let fired = elapsed / slot.interval_ticks + 1;
    slot.expirations = slot.expirations.saturating_add(fired);
    slot.next_expiration_ticks = slot
        .next_expiration_ticks
        .saturating_add(slot.interval_ticks.saturating_mul(fired));
}

fn timerfd_remaining_ticks(slot: &TimerFdState) -> u64 {
    if slot.used == 0 || slot.next_expiration_ticks == 0 {
        return 0;
    }
    let Some(now) = current_ticks_for_clock(slot.clock_id) else {
        return 0;
    };
    slot.next_expiration_ticks.saturating_sub(now)
}

fn write_timespec(base: u32, addr: u64, sec: u64, nsec: u64) {
    unsafe {
        guest_mem::write_u64(base, addr, sec);
        guest_mem::write_u64(base, addr + 8, nsec);
    }
}

fn read_kernel_timespec(base: u32, addr: u64) -> Result<(u64, u64), i64> {
    let sec = unsafe { guest_mem::read_i64(base, addr) };
    let nsec = unsafe { guest_mem::read_i64(base, addr + 8) };
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(abi::EINVAL);
    }
    Ok((sec as u64, nsec as u64))
}

fn write_timerfd_spec(base: u32, addr: u64, interval_ticks: u64, value_ticks: u64) {
    let (interval_sec, interval_nsec) = ticks_to_timespec(interval_ticks);
    let (value_sec, value_nsec) = ticks_to_timespec(value_ticks);
    write_timespec(base, addr, interval_sec, interval_nsec);
    write_timespec(base, addr + 16, value_sec, value_nsec);
}

fn alloc_timerfd_slot(clock_id: u64) -> Option<u32> {
    if !timerfd_clock_supported(clock_id) {
        return None;
    }
    let state = ts();
    for idx in 1..=abi::MAX_TIMERFDS {
        let slot = &mut state.timerfds[idx];
        if slot.used == 0 {
            *slot = TimerFdState {
                used: 1,
                _pad: 0,
                clock_id,
                next_expiration_ticks: 0,
                interval_ticks: 0,
                expirations: 0,
            };
            return Some(idx as u32);
        }
    }
    None
}

pub fn close_timerfd(timerfd_idx: u32) {
    if let Some(slot) = timerfd_slot(timerfd_idx) {
        *slot = EMPTY_TIMERFD_STATE;
    }
}

pub fn timerfd_is_readable(timerfd_idx: u32) -> bool {
    let Some(slot) = timerfd_slot(timerfd_idx) else {
        return false;
    };
    update_timerfd(slot);
    slot.expirations != 0
}

fn timerfd_take_expirations(timerfd_idx: u32) -> u64 {
    let Some(slot) = timerfd_slot(timerfd_idx) else {
        return 0;
    };
    update_timerfd(slot);
    let expirations = slot.expirations;
    slot.expirations = 0;
    expirations
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

/// timerfd_create: create a timerfd backed by the shared timerfd table.
pub fn sys_timerfd_create(vm: &mut ThreadState, base: u32, clock_id: u64, flags: u64) -> i64 {
    let allowed_flags = (abi::O_CLOEXEC | abi::O_NONBLOCK) as u64;
    if flags & !allowed_flags != 0 {
        return abi::EINVAL;
    }
    let Some(timerfd_idx) = alloc_timerfd_slot(clock_id) else {
        return if timerfd_clock_supported(clock_id) {
            abi::EMFILE
        } else {
            abi::EINVAL
        };
    };

    let fd = crate::fs::fd_table::open_timerfd(vm, base, timerfd_idx, flags as i32);
    if fd < 0 {
        close_timerfd(timerfd_idx);
    }
    fd
}

/// timerfd_settime: arm/disarm a timerfd and optionally report the previous spec.
pub fn sys_timerfd_settime(
    vm: &ThreadState,
    base: u32,
    fd: u64,
    flags: u64,
    new_value: u64,
    old_value: u64,
) -> i64 {
    let allowed_flags = abi::TFD_TIMER_ABSTIME | abi::TFD_TIMER_CANCEL_ON_SET;
    if flags & !allowed_flags != 0 {
        return abi::EINVAL;
    }
    if (flags & abi::TFD_TIMER_CANCEL_ON_SET) != 0 {
        return abi::EINVAL;
    }
    if new_value == 0 {
        return abi::EFAULT;
    }
    if !crate::syscall::memory::guest_range_accessible(base, new_value, 32) {
        return abi::EFAULT;
    }
    if old_value != 0 && !crate::syscall::memory::guest_range_accessible(base, old_value, 32) {
        return abi::EFAULT;
    }

    let Some(ofd) = crate::fs::fd_table::get_ofd(base, vm, fd) else {
        return abi::EBADF;
    };
    if ofd.fd_type != abi::FD_TYPE_TIMERFD {
        return abi::EINVAL;
    }
    let Some(slot) = timerfd_slot(ofd.ino) else {
        return abi::EINVAL;
    };

    update_timerfd(slot);
    if old_value != 0 {
        write_timerfd_spec(
            base,
            old_value,
            slot.interval_ticks,
            timerfd_remaining_ticks(slot),
        );
    }

    let (interval_sec, interval_nsec) = match read_kernel_timespec(base, new_value) {
        Ok(spec) => spec,
        Err(errno) => return errno,
    };
    let (value_sec, value_nsec) = match read_kernel_timespec(base, new_value + 16) {
        Ok(spec) => spec,
        Err(errno) => return errno,
    };

    let interval_ticks = timespec_to_ticks_ceil(interval_sec, interval_nsec);
    let value_ticks = timespec_to_ticks_ceil(value_sec, value_nsec);
    slot.expirations = 0;
    slot.interval_ticks = interval_ticks;
    if value_ticks == 0 {
        slot.next_expiration_ticks = 0;
        return 0;
    }

    let Some(now) = current_ticks_for_clock(slot.clock_id) else {
        return abi::EINVAL;
    };
    slot.next_expiration_ticks = if (flags & abi::TFD_TIMER_ABSTIME) != 0 {
        timespec_to_ticks_floor(value_sec, value_nsec)
    } else {
        now.saturating_add(value_ticks)
    };
    0
}

/// timerfd_gettime: report the current timer spec.
pub fn sys_timerfd_gettime(vm: &ThreadState, base: u32, fd: u64, curr_value: u64) -> i64 {
    if curr_value == 0 || !crate::syscall::memory::guest_range_accessible(base, curr_value, 32) {
        return abi::EFAULT;
    }

    let Some(ofd) = crate::fs::fd_table::get_ofd(base, vm, fd) else {
        return abi::EBADF;
    };
    if ofd.fd_type != abi::FD_TYPE_TIMERFD {
        return abi::EINVAL;
    }
    let Some(slot) = timerfd_slot(ofd.ino) else {
        return abi::EINVAL;
    };

    update_timerfd(slot);
    write_timerfd_spec(
        base,
        curr_value,
        slot.interval_ticks,
        timerfd_remaining_ticks(slot),
    );
    0
}

pub fn timerfd_read(base: u32, buf: u64, count: u64, timerfd_idx: u32) -> i64 {
    if count < 8 {
        return abi::EINVAL;
    }
    let expirations = timerfd_take_expirations(timerfd_idx);
    if expirations == 0 {
        return abi::EAGAIN;
    }
    if !crate::syscall::memory::guest_range_accessible(base, buf, 8) {
        return abi::EFAULT;
    }
    unsafe {
        guest_mem::write_u64(base, buf, expirations);
    }
    8
}

/// nanosleep: return STATUS_SLEEP so the owner scheduler can block until the
/// guest deadline expires.
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
        Some(unsafe {
            (
                guest_mem::read_u64(base, req),
                guest_mem::read_u64(base, req + 8),
            )
        })
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
        let now_total = now_sec
            .saturating_mul(1_000_000_000)
            .saturating_add(now_nsec);
        let req_total = req_sec
            .saturating_mul(1_000_000_000)
            .saturating_add(req_nsec);
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

/// sched_yield: cooperative yield point for the runtime scheduler.
/// Returns STATUS_SLEEP so the outer scheduler can run another runnable thread
/// before resuming this one; guest-visible return value remains 0.
/// https://man7.org/linux/man-pages/man2/sched_yield.2.html
pub fn sys_sched_yield(vm: &mut ThreadState) -> i32 {
    vm.fault_addr = 0;
    vm.fault_pc = 0;
    vm.x[10] = 0;
    vm.status = abi::STATUS_SLEEP;
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

    if !crate::syscall::memory::guest_range_accessible(base, mask_addr, 8) {
        return abi::EFAULT;
    }

    unsafe {
        guest_mem::write_u64(base, mask_addr, 1);
    }
    8
}

/// getcpu: report the current CPU and NUMA node.
/// Tidemark currently exposes a single online CPU on a single node, so both are 0.
/// Either pointer may be NULL; the third argument is unused by modern Linux.
/// https://man7.org/linux/man-pages/man2/getcpu.2.html
pub fn sys_getcpu(
    _vm: &ThreadState,
    base: u32,
    cpu_addr: u64,
    node_addr: u64,
    _tcache: u64,
) -> i64 {
    if cpu_addr != 0 {
        if !crate::syscall::memory::guest_range_accessible(base, cpu_addr, 4) {
            return abi::EFAULT;
        }
        unsafe {
            guest_mem::write_u32(base, cpu_addr, 0);
        }
    }
    if node_addr != 0 {
        if !crate::syscall::memory::guest_range_accessible(base, node_addr, 4) {
            return abi::EFAULT;
        }
        unsafe {
            guest_mem::write_u32(base, node_addr, 0);
        }
    }
    0
}
