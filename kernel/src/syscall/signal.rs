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
mod pending;
mod signalfd;
mod sigreturn;
mod trace;

use crate::abi::*;
use crate::guest_mem;
use crate::types::{MAX_SIGNALS, SIG_DFL, SIG_IGN, SigAction, ThreadState};

pub use actions::{
    fork_from_parent, init_for_process, reassign_process_pid, reset_on_execve, sys_rt_sigaction,
};
pub use frame::{is_current_sigreturn_trampoline, patch_current_signal_frame_a0};
pub(crate) use pending::sanitized_signal_mask;
pub use pending::{
    clear_process_signal, process_pending_bytes, process_pending_ptr, queue_process_signal,
    queue_sigill, queue_sigsegv, send_signal, send_signal_to_pid, send_signal_to_tid,
    send_signal_with_code, sys_rt_sigpending, sys_rt_sigprocmask,
};
pub use signalfd::{close_signalfd, signalfd_is_readable, signalfd_read, sys_signalfd4};
pub use sigreturn::sys_rt_sigreturn;
pub use trace::note_pc;

#[cfg(any(test, feature = "harness"))]
pub(crate) use trace::{
    default_signal_arg_regs, default_signal_trace, default_signal_vm_ptr, reset_trace_state,
    signal_delivery_trace, signal_delivery_trace_for_vm, sigreturn_trace, trampoline_trace_state,
};

use frame::push_signal_frame;
use pending::{peek_thread_pending_signals, process_pending, take_thread_pending_signals};
use trace::{record_default_signal, record_signal_delivery_trace, record_sigreturn_trace};

// SA flags (https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal-defs.h)
const SA_ONSTACK: u64 = 0x08000000;
const SA_RESTART: u64 = 0x10000000;
const SA_NODEFER: u64 = 0x40000000;
const SA_RESETHAND: u64 = 0x80000000;

// sigaltstack flags
const SS_ONSTACK: i32 = 1;
pub(crate) const SS_DISABLE: i32 = 2;
pub(super) const SI_USER: i32 = 0;

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

pub fn sig_slots_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(SIG_SLOTS_PTR)) as u32 }
}

pub fn signal_slots_bytes() -> u32 {
    core::mem::size_of::<[*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES]>() as u32
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
    }
    pending::attach_process_pending_state(process_pending_ptr);
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn capture_process_signal_state_into(image: &mut ProcessSignalStateImage) {
    for (idx, slot) in sig_slots().iter().enumerate() {
        image.sig_slots[idx] = *slot as u32;
    }
    pending::capture_process_pending_state_into(image);
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn restore_process_signal_state_from(image: &ProcessSignalStateImage) {
    for (idx, slot) in sig_slots().iter_mut().enumerate() {
        *slot = image.sig_slots[idx] as *mut [SigAction; MAX_SIGNALS];
    }
    pending::restore_process_pending_state_from(image);
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

/// Initialize signal subsystem. Must be called once at kernel init.
pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SIG_SLOTS_PTR),
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
    }
    pending::init();
    signalfd::init();
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
