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
mod defaults;
mod delivery;
mod frame;
mod pending;
mod signalfd;
mod sigreturn;
mod trace;

use crate::abi::*;
use crate::guest_mem;
use crate::types::ThreadState;

pub use actions::{
    fork_from_parent, init_for_process, reassign_process_pid, reset_on_execve, sig_slots_ptr,
    signal_action_table_bytes, signal_slots_bytes, sys_rt_sigaction,
};
pub use delivery::{check_pending, pending_signal_interrupts_blocked_syscall};
pub(crate) use frame::SS_DISABLE;
pub use frame::{is_current_sigreturn_trampoline, patch_current_signal_frame_a0, sys_sigaltstack};
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

pub(super) const SI_USER: i32 = 0;

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

pub fn attach_process_signal_state(sig_slots_ptr: u32, process_pending_ptr: u32) {
    actions::attach_signal_action_state(sig_slots_ptr);
    pending::attach_process_pending_state(process_pending_ptr);
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn capture_process_signal_state_into(image: &mut ProcessSignalStateImage) {
    actions::capture_signal_action_state_into(image);
    pending::capture_process_pending_state_into(image);
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn restore_process_signal_state_from(image: &ProcessSignalStateImage) {
    actions::restore_signal_action_state_from(image);
    pending::restore_process_pending_state_from(image);
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
    actions::init_action_tables();
    pending::init();
    signalfd::init();
}
