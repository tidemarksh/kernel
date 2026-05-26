//! Signal syscalls: rt_sigaction, rt_sigprocmask, sigaltstack, signal delivery.
//!
//! Signal delivery pushes a frame onto the guest stack, redirects PC to the
//! handler, and rt_sigreturn restores the saved context.
//!
//! Struct layouts (RV64):
//!
//! struct sigaction {                // 24 bytes total (no SA_RESTORER on RISC-V)
//!     sa_handler: u64,              // offset 0
//!     sa_flags:   u64,              // offset 8
//!     sa_mask:    u64,              // offset 16 (sigset_t = unsigned long[1])
//! };
//!
//! struct sigaltstack {              // 24 bytes total
//!     ss_sp:    u64,                // offset 0
//!     ss_flags: i32,                // offset 8
//!     _pad:     [u8; 4],            // offset 12 (alignment)
//!     ss_size:  u64,                // offset 16
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal.h

mod actions;
mod frame;
mod signalfd;
mod sigreturn;
mod trace;

use crate::abi::*;
use crate::guest_mem;
use crate::types::{
    MAX_SIGNALS, ProcessState, SIG_DFL, SIG_IGN, SigAction, THREAD_BLOCKED_FUTEX, THREAD_DEAD,
    THREAD_NONE, ThreadRecord, ThreadState,
};

pub use actions::{
    fork_from_parent, init_for_process, reassign_process_pid, reset_on_execve, sys_rt_sigaction,
};
pub use frame::{is_current_sigreturn_trampoline, patch_current_signal_frame_a0};
pub use signalfd::{close_signalfd, signalfd_is_readable, signalfd_read, sys_signalfd4};
pub use sigreturn::sys_rt_sigreturn;
pub use trace::note_pc;

#[cfg(any(test, feature = "harness"))]
pub(crate) use trace::{
    default_signal_arg_regs, default_signal_trace, default_signal_vm_ptr, reset_trace_state,
    signal_delivery_trace, signal_delivery_trace_for_vm, sigreturn_trace, trampoline_trace_state,
};

use frame::push_signal_frame;
use trace::{record_default_signal, record_signal_delivery_trace, record_sigreturn_trace};

// SA flags (https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal-defs.h)
const SA_ONSTACK: u64 = 0x08000000;
const SA_RESTART: u64 = 0x10000000;
const SA_NODEFER: u64 = 0x40000000;
const SA_RESETHAND: u64 = 0x80000000;

// sigprocmask how
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;

// sigaltstack flags
const SS_ONSTACK: i32 = 1;
pub(crate) const SS_DISABLE: i32 = 2;
pub(super) const SI_USER: i32 = 0;
const SI_TKILL: i32 = -6;
const ILL_ILLOPC: i32 = 1;
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;

/// Per-process signal disposition tables, allocated in kernel Worker linear memory.
/// Each process gets its own [SigAction; MAX_SIGNALS] table, indexed by PID.
///
/// Signal dispositions are process-wide (shared by all threads in a process).
/// On execve, caught signals (handler != SIG_DFL and != SIG_IGN) are reset to SIG_DFL.
///
/// Semantics: https://man7.org/linux/man-pages/man2/rt_sigaction.2.html
/// execve reset: https://man7.org/linux/man-pages/man2/execve.2.html
///
/// SIGACTIONS_PTR points to a heap-allocated [SigAction; MAX_SIGNALS] for the
/// currently active process. Multi-process uses SIG_SLOTS_PTR (array of
/// MAX_PROCESSES pointers, each pointing to a per-process table).
static mut SIG_SLOTS_PTR: *mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES] =
    core::ptr::null_mut();
static mut PROCESS_PENDING_PTR: *mut [u64; MAX_PROCESSES] = core::ptr::null_mut();

#[cfg(any(test, feature = "harness"))]
#[derive(Clone, Copy)]
pub(crate) struct ProcessSignalStateImage {
    sig_slots: [u32; MAX_PROCESSES],
    process_pending: [u64; MAX_PROCESSES],
}

#[cfg(any(test, feature = "harness"))]
impl ProcessSignalStateImage {
    pub(crate) fn empty() -> Self {
        Self {
            sig_slots: [0; MAX_PROCESSES],
            process_pending: [0; MAX_PROCESSES],
        }
    }
}

const SYNC_FAULT_SIGNAL_MASK: u64 = (1u64 << (SIGILL - 1))
    | (1u64 << (SIGBUS - 1))
    | (1u64 << (SIGFPE - 1))
    | (1u64 << (SIGSEGV - 1));

#[inline(always)]
fn sig_slots() -> &'static mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(SIG_SLOTS_PTR));
        &mut *p
    }
}

#[inline(always)]
fn process_pending() -> &'static mut [u64; MAX_PROCESSES] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(PROCESS_PENDING_PTR));
        &mut *p
    }
}

pub fn sig_slots_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(SIG_SLOTS_PTR)) as u32 }
}

pub fn process_pending_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(PROCESS_PENDING_PTR)) as u32 }
}

pub fn signal_slots_bytes() -> u32 {
    core::mem::size_of::<[*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES]>() as u32
}

pub fn process_pending_bytes() -> u32 {
    core::mem::size_of::<[u64; MAX_PROCESSES]>() as u32
}

pub fn signal_action_table_bytes() -> u32 {
    core::mem::size_of::<[SigAction; MAX_SIGNALS]>() as u32
}

pub fn attach_process_signal_state(sig_slots_ptr: u32, process_pending_ptr: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SIG_SLOTS_PTR),
            sig_slots_ptr as *mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES],
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_PENDING_PTR),
            process_pending_ptr as *mut [u64; MAX_PROCESSES],
        );
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn capture_process_signal_state_into(image: &mut ProcessSignalStateImage) {
    for (idx, slot) in sig_slots().iter().enumerate() {
        image.sig_slots[idx] = *slot as u32;
    }
    image.process_pending = *process_pending();
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn restore_process_signal_state_from(image: &ProcessSignalStateImage) {
    for (idx, slot) in sig_slots().iter_mut().enumerate() {
        *slot = image.sig_slots[idx] as *mut [SigAction; MAX_SIGNALS];
    }
    *process_pending() = image.process_pending;
}

#[inline(always)]
fn sigactions_for(pid: i32) -> Option<&'static mut [SigAction; MAX_SIGNALS]> {
    if pid <= 0 {
        return None;
    }
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES {
        return None;
    }
    let slot = sig_slots()[idx];
    if slot.is_null() {
        return None;
    }
    unsafe { Some(&mut *slot) }
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

fn take_thread_pending_signals(vm: &mut ThreadState, base: u32) {
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

/// Initialize signal subsystem. Must be called once at kernel init.
pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SIG_SLOTS_PTR),
            core::ptr::null_mut(),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_PENDING_PTR),
            core::ptr::null_mut(),
        );
        let size = core::mem::size_of::<[*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES]>() as u32;
        let align = core::mem::align_of::<*mut [SigAction; MAX_SIGNALS]>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(SIG_SLOTS_PTR),
            ptr as *mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES],
        );

        let pending_size = core::mem::size_of::<[u64; MAX_PROCESSES]>() as u32;
        let pending_align = core::mem::align_of::<u64>() as u32;
        let pending_ptr = crate::alloc::alloc_zeroed(pending_size, pending_align);
        if pending_ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_PENDING_PTR),
            pending_ptr as *mut [u64; MAX_PROCESSES],
        );
    }
    signalfd::init();
}

pub(crate) fn sanitized_signal_mask(mask: u64) -> u64 {
    let unblockable = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));
    mask & !unblockable
}

fn peek_thread_pending_signals(vm: &ThreadState, base: u32) -> u64 {
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

pub fn pending_signal_interrupts_blocked_syscall(vm: &ThreadState, base: u32) -> bool {
    let pid = pid_from_vm(vm, base);
    let mut pending = vm.sig_pending | peek_thread_pending_signals(vm, base);
    if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            pending |= process_pending()[idx];
        }
    }

    let deliverable = pending & !vm.sig_mask;
    if deliverable == 0 {
        return false;
    }

    let sig = deliverable.trailing_zeros() as usize + 1;
    if sig >= MAX_SIGNALS {
        return false;
    }

    let action = sigactions_for(pid)
        .map(|table| table[sig])
        .unwrap_or(SigAction {
            handler: SIG_DFL,
            flags: 0,
            mask: 0,
        });

    match action.handler {
        SIG_IGN => false,
        SIG_DFL => !matches!(sig as i32, SIGCHLD | SIGURG | SIGWINCH | SIGCONT),
        _ => (action.flags & SA_RESTART) == 0,
    }
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

    unsafe {
        // Write old mask
        if oldset_addr != 0 {
            guest_mem::write_u64(base, oldset_addr, vm.sig_mask);
        }

        // Apply new mask
        if set_addr != 0 {
            let set = guest_mem::read_u64(base, set_addr);
            // SIGKILL and SIGSTOP cannot be blocked
            let unblockable = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));
            vm.sig_mask = match how {
                SIG_BLOCK => vm.sig_mask | (set & !unblockable),
                SIG_UNBLOCK => vm.sig_mask & !set,
                SIG_SETMASK => set & !unblockable,
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

/// sigaltstack: get/set alternate signal stack.
/// ss in a0, old_ss in a1.
pub fn sys_sigaltstack(vm: &mut ThreadState, base: u32, ss_addr: u64, old_ss_addr: u64) -> i64 {
    unsafe {
        // Write old stack
        if old_ss_addr != 0 {
            guest_mem::write_u64(base, old_ss_addr, vm.sigaltstack_sp);
            guest_mem::write_u32(base, old_ss_addr + 8, vm.sigaltstack_flags as u32);
            guest_mem::write_u64(base, old_ss_addr + 16, vm.sigaltstack_size);
        }

        // Read new stack
        if ss_addr != 0 {
            let flags = guest_mem::read_i32(base, ss_addr + 8);
            if flags & !(SS_ONSTACK | SS_DISABLE) != 0 {
                return EINVAL;
            }

            if flags & SS_DISABLE != 0 {
                vm.sigaltstack_sp = 0;
                vm.sigaltstack_size = 0;
                vm.sigaltstack_flags = SS_DISABLE;
            } else {
                let sp = guest_mem::read_u64(base, ss_addr);
                let size = guest_mem::read_u64(base, ss_addr + 16);
                if size < 2048 {
                    return ENOMEM;
                } // MINSIGSTKSZ
                vm.sigaltstack_sp = sp;
                vm.sigaltstack_size = size;
                vm.sigaltstack_flags = flags;
            }
        }
    }
    0
}

/// Check and deliver pending signals at syscall return boundary.
/// Called after each syscall returns. Returns true if a signal was delivered.
pub fn check_pending(vm: &mut ThreadState, base: u32) -> bool {
    let pid = pid_from_vm(vm, base);
    let process_pending_bits = if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            process_pending()[idx]
        } else {
            0
        }
    } else {
        0
    };
    let process_pending_deliverable = process_pending_bits & !vm.sig_mask;
    // Process-directed signals remain pending for the process until a thread
    // that does not block the signal actually accepts delivery. Do not move
    // blocked process-pending signals into this thread.
    take_thread_pending_signals(vm, base);

    let synchronous = if vm.sig_info_code != 0 {
        vm.sig_pending & SYNC_FAULT_SIGNAL_MASK
    } else {
        0
    };
    let thread_pending_deliverable = vm.sig_pending & !vm.sig_mask;
    let deliverable = thread_pending_deliverable | process_pending_deliverable | synchronous;
    if deliverable == 0 {
        return false;
    }

    // Find lowest pending unblocked signal
    let sig = deliverable.trailing_zeros() as usize + 1;
    if sig >= MAX_SIGNALS {
        return false;
    }

    // Clear from the pending set that supplied this delivery. Prefer
    // thread-directed pending state when both sets contain the same standard
    // signal, matching the fact that thread and process pending sets are
    // separate.
    let bit = 1u64 << (sig - 1);
    if (thread_pending_deliverable | synchronous) & bit != 0 {
        vm.sig_pending &= !bit;
    } else if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            process_pending()[idx] &= !bit;
        }
    }

    let action = sigactions_for(pid)
        .map(|table| table[sig])
        .unwrap_or(SigAction {
            handler: SIG_DFL,
            flags: 0,
            mask: 0,
        });

    match action.handler {
        0 => {
            // SIG_DFL: default action
            match sig as i32 {
                SIGCHLD | SIGURG | SIGWINCH => {} // ignore by default
                SIGCONT => {}                     // ignore (no job control)
                _ => {
                    record_default_signal(vm, sig);
                    crate::syscall::thread::terminate_process_with_reason(
                        vm,
                        base,
                        128 + sig as i32,
                        sig as i32,
                        crate::syscall::thread::TERMINATE_REASON_DEFAULT_SIGNAL,
                    );
                }
            }
        }
        1 => {} // SIG_IGN: ignore
        _handler_addr => {
            // User handler: push signal frame and redirect to handler
            if !push_signal_frame(vm, base, sig, &action) {
                record_default_signal(vm, sig);
                crate::syscall::thread::terminate_process_with_reason(
                    vm,
                    base,
                    128 + sig as i32,
                    sig as i32,
                    crate::syscall::thread::TERMINATE_REASON_DEFAULT_SIGNAL,
                );
            }
        }
    }

    vm.sig_info_code = 0;

    true
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

pub fn queue_sigill(vm: &mut ThreadState, pc: u64) {
    vm.fault_pc = pc;
    vm.fault_addr = pc;
    send_signal_with_code(vm, SIGILL, ILL_ILLOPC);
}

pub fn queue_sigsegv(vm: &mut ThreadState, pc: u64, addr: u64, accerr: bool) {
    vm.fault_pc = pc;
    vm.fault_addr = addr;
    send_signal_with_code(vm, SIGSEGV, if accerr { SEGV_ACCERR } else { SEGV_MAPERR });
}
