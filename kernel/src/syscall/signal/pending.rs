use super::actions::sig_slots;
use crate::abi::*;
use crate::guest_mem;
use crate::types::{
    ProcessState, ThreadRecord, ThreadState, MAX_SIGNALS, THREAD_BLOCKED_FUTEX, THREAD_DEAD,
    THREAD_NONE,
};

// sigprocmask how
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;

pub(super) const SI_USER: i32 = 0;
const SI_TKILL: i32 = -6;
const ILL_ILLOPC: i32 = 1;
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;

static mut PROCESS_PENDING_PTR: *mut [u64; MAX_PROCESSES] = core::ptr::null_mut();

#[cfg(any(test, feature = "harness"))]
#[derive(Clone, Copy)]
pub(crate) struct ProcessPendingStateImage {
    process_pending: [u64; MAX_PROCESSES],
}

#[cfg(any(test, feature = "harness"))]
impl ProcessPendingStateImage {
    pub(crate) fn empty() -> Self {
        Self {
            process_pending: [0; MAX_PROCESSES],
        }
    }
}

#[inline(always)]
pub(super) fn process_pending() -> &'static mut [u64; MAX_PROCESSES] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(PROCESS_PENDING_PTR));
        &mut *p
    }
}

pub fn process_pending_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(PROCESS_PENDING_PTR)) as u32 }
}

pub fn process_pending_bytes() -> u32 {
    core::mem::size_of::<[u64; MAX_PROCESSES]>() as u32
}

pub fn attach_process_pending_state(process_pending_ptr: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_PENDING_PTR),
            process_pending_ptr as *mut [u64; MAX_PROCESSES],
        );
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn capture_process_pending_state_into(image: &mut ProcessPendingStateImage) {
    image.process_pending = *process_pending();
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn restore_process_pending_state_from(image: &ProcessPendingStateImage) {
    *process_pending() = image.process_pending;
}

pub(super) fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_PENDING_PTR),
            core::ptr::null_mut(),
        );

        let pending_size = core::mem::size_of::<[u64; MAX_PROCESSES]>() as u32;
        let pending_align = core::mem::align_of::<u64>() as u32;
        let pending_ptr = crate::alloc::alloc_zeroed(pending_size, pending_align);
        if pending_ptr == 0 {
            crate::wasm::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_PENDING_PTR),
            pending_ptr as *mut [u64; MAX_PROCESSES],
        );
    }
}

pub(crate) fn sanitized_signal_mask(mask: u64) -> u64 {
    let unblockable = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));
    mask & !unblockable
}

/// Read PID from ProcessState in guest Memory via ThreadState.process_ptr.
#[inline(always)]
pub fn pid_from_vm(vm: &ThreadState, base: u32) -> i32 {
    let ps_ptr = vm.process_ptr;
    if ps_ptr == 0 {
        return 1;
    }
    unsafe {
        let pid_offset = core::mem::offset_of!(crate::types::ProcessState, pid);
        guest_mem::read_i32(base, ps_ptr as u64 + pid_offset as u64)
    }
}

fn process_state_from_vm(vm: &ThreadState, base: u32) -> Option<&'static mut ProcessState> {
    if vm.process_ptr == 0 {
        return None;
    }
    let absolute = (base as u64 + vm.process_ptr as u64) as *mut ProcessState;
    if absolute.is_null() {
        return None;
    }
    unsafe { Some(&mut *absolute) }
}

unsafe fn read_thread_record(record: *const ThreadRecord) -> ThreadRecord {
    unsafe { core::ptr::read_unaligned(record) }
}

unsafe fn write_thread_record(record: *mut ThreadRecord, value: ThreadRecord) {
    unsafe { core::ptr::write_unaligned(record, value) }
}

pub(super) fn take_thread_pending_signals(vm: &mut ThreadState, base: u32) {
    let Some(ps) = process_state_from_vm(vm, base) else {
        return;
    };
    let tid = vm.tid;
    if tid <= 0 {
        return;
    }
    for index in 0..ps.threads.len() {
        let record_ptr = core::ptr::addr_of_mut!(ps.threads[index]);
        let mut record = unsafe { read_thread_record(record_ptr) };
        if record.tid != tid {
            continue;
        }
        vm.sig_pending |= record.pending_sigset;
        if record.pending_siginfo_code != 0 {
            vm.sig_info_code = record.pending_siginfo_code;
        }
        record.pending_sigset = 0;
        record.pending_siginfo_code = 0;
        unsafe { write_thread_record(record_ptr, record) };
        return;
    }
}

pub(super) fn peek_thread_pending_signals(vm: &ThreadState, base: u32) -> u64 {
    let Some(ps) = process_state_from_vm(vm, base) else {
        return 0;
    };
    for index in 0..ps.threads.len() {
        let record = unsafe { read_thread_record(core::ptr::addr_of!(ps.threads[index])) };
        if record.tid == vm.tid {
            return record.pending_sigset;
        }
    }
    0
}

/// rt_sigprocmask: change blocked signal mask.
/// how in a0, set in a1, oldset in a2, sigsetsize in a3.
pub fn sys_rt_sigprocmask(
    vm: &mut ThreadState,
    base: u32,
    how: u64,
    set_addr: u64,
    oldset_addr: u64,
    sigsetsize: u64,
) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    if oldset_addr != 0 && !crate::syscall::memory::guest_range_accessible(base, oldset_addr, 8) {
        return EFAULT;
    }
    if set_addr != 0 && !crate::syscall::memory::guest_range_accessible(base, set_addr, 8) {
        return EFAULT;
    }

    unsafe {
        // Write old mask
        if oldset_addr != 0 {
            guest_mem::write_u64(base, oldset_addr, vm.sig_mask);
        }

        // Apply new mask
        if set_addr != 0 {
            let set = guest_mem::read_u64(base, set_addr);
            vm.sig_mask = match how {
                SIG_BLOCK => vm.sig_mask | sanitized_signal_mask(set),
                SIG_UNBLOCK => vm.sig_mask & !set,
                SIG_SETMASK => sanitized_signal_mask(set),
                _ => return EINVAL,
            };
        }
    }
    0
}

/// rt_sigpending: return blocked pending signals visible to the caller.
pub fn sys_rt_sigpending(vm: &ThreadState, base: u32, set_addr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    if set_addr == 0 || crate::syscall::memory::range_has_prot_none(set_addr, 8) {
        return EFAULT;
    }

    let pid = pid_from_vm(vm, base);
    let mut pending = vm.sig_pending;
    if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            pending |= process_pending()[idx];
        }
    }

    unsafe {
        guest_mem::write_u64(base, set_addr, pending & vm.sig_mask);
    }
    0
}

/// Queue a signal for delivery.
pub fn send_signal(vm: &mut ThreadState, sig: i32) {
    if sig <= 0 || sig as usize >= MAX_SIGNALS {
        return;
    }
    vm.sig_pending |= 1u64 << (sig - 1);
}

pub fn send_signal_with_code(vm: &mut ThreadState, sig: i32, code: i32) {
    send_signal(vm, sig);
    vm.sig_info_code = code;
}

pub fn queue_process_signal(pid: i32, sig: i32) {
    if pid <= 0 || sig <= 0 || sig as usize >= MAX_SIGNALS {
        return;
    }
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES || sig_slots()[idx].is_null() {
        return;
    }
    process_pending()[idx] |= 1u64 << (sig - 1);
}

pub fn clear_process_signal(pid: i32, sig: i32) {
    if pid <= 0 || sig <= 0 || sig as usize >= MAX_SIGNALS {
        return;
    }
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES {
        return;
    }
    process_pending()[idx] &= !(1u64 << (sig - 1));
}

fn wake_current_process_futex_waiters(vm: &mut ThreadState, base: u32) {
    vm.sig_info_code = SI_USER;
    if let Some(ps) = process_state_from_vm(vm, base) {
        for index in 0..ps.threads.len() {
            let record = unsafe { read_thread_record(core::ptr::addr_of!(ps.threads[index])) };
            if record.state != THREAD_BLOCKED_FUTEX || record.blocked_addr == 0 {
                continue;
            }
            // FUTEX_WAIT may wake spuriously. Prefer waking blocked threads
            // over directly reading another worker's ThreadState.
            crate::syscall::thread::notify_futex_addr(base, record.blocked_addr, 1);
        }
    }
}

fn signal_process_if_present(pid: i32, sig: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES || sig_slots()[idx].is_null() {
        return false;
    }
    if sig != 0 {
        queue_process_signal(pid, sig);
    }
    true
}

/// Queue a process-directed signal. Delivery happens when the target process
/// next reaches a signal check boundary.
pub fn send_signal_to_pid(vm: &mut ThreadState, base: u32, pid: i32, sig: i32) -> i64 {
    if sig < 0 || sig as usize >= MAX_SIGNALS {
        return EINVAL;
    }
    if pid == i32::MIN {
        return ESRCH;
    }
    let current_pid = pid_from_vm(vm, base);
    if pid > 0 {
        if !signal_process_if_present(pid, sig) {
            return ESRCH;
        }
        if sig != 0 && pid == current_pid {
            wake_current_process_futex_waiters(vm, base);
        }
        return 0;
    }

    let mut delivered = false;
    if pid == 0 {
        let pgid = crate::syscall::process::current_process_pgid(vm, base);
        for target_pid in 1..=MAX_PROCESSES as i32 {
            if crate::syscall::process::process_pgid(target_pid) == pgid
                && signal_process_if_present(target_pid, sig)
            {
                delivered = true;
            }
        }
    } else if pid == -1 {
        for target_pid in 1..=MAX_PROCESSES as i32 {
            if target_pid != 1 && signal_process_if_present(target_pid, sig) {
                delivered = true;
            }
        }
    } else {
        let pgid = -pid;
        for target_pid in 1..=MAX_PROCESSES as i32 {
            if crate::syscall::process::process_pgid(target_pid) == pgid
                && signal_process_if_present(target_pid, sig)
            {
                delivered = true;
            }
        }
    }
    if !delivered {
        return ESRCH;
    }
    if sig != 0 {
        wake_current_process_futex_waiters(vm, base);
    }
    0
}

/// Queue a thread-directed signal for a thread in the caller's current process.
pub fn send_signal_to_tid(vm: &mut ThreadState, base: u32, tid: i32, sig: i32) -> i64 {
    if tid <= 0 || sig <= 0 || sig as usize >= MAX_SIGNALS {
        return EINVAL;
    }
    if tid == vm.tid {
        send_signal(vm, sig);
        vm.sig_info_code = SI_TKILL;
        return 0;
    }

    let Some(ps) = process_state_from_vm(vm, base) else {
        return ESRCH;
    };

    for index in 0..ps.threads.len() {
        let record_ptr = core::ptr::addr_of_mut!(ps.threads[index]);
        let mut record = unsafe { read_thread_record(record_ptr) };
        if record.tid != tid || record.thread_ptr == 0 {
            continue;
        }
        if record.state == THREAD_NONE || record.state == THREAD_DEAD {
            continue;
        }
        record.pending_sigset |= 1u64 << (sig - 1);
        record.pending_siginfo_code = SI_TKILL;
        if record.state == THREAD_BLOCKED_FUTEX && record.blocked_addr != 0 {
            crate::syscall::thread::notify_futex_addr(base, record.blocked_addr, 1);
        }
        unsafe { write_thread_record(record_ptr, record) };
        return 0;
    }

    ESRCH
}

pub fn queue_sigill(vm: &mut ThreadState, pc: u64, _raw: u32) {
    vm.fault_pc = pc;
    vm.fault_addr = pc;
    vm.fault_kind = FAULT_KIND_ILLEGAL_INSTRUCTION;
    vm.fault_signal = SIGILL;
    vm.fault_code = ILL_ILLOPC;
    send_signal_with_code(vm, SIGILL, ILL_ILLOPC);
}

pub fn queue_sigsegv(vm: &mut ThreadState, pc: u64, addr: u64, accerr: bool) {
    vm.fault_pc = pc;
    vm.fault_addr = addr;
    let code = if accerr { SEGV_ACCERR } else { SEGV_MAPERR };
    vm.fault_kind = if accerr {
        FAULT_KIND_GUEST_ACCERR
    } else {
        FAULT_KIND_GUEST_MAPERR
    };
    vm.fault_signal = SIGSEGV;
    vm.fault_code = code;
    send_signal_with_code(vm, SIGSEGV, code);
}
