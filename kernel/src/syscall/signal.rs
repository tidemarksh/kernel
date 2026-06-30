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

#[cfg(any(test, feature = "harness"))]
pub(crate) use actions::{
    SignalActionStateImage, capture_signal_action_state_into, restore_signal_action_state_from,
};
pub use actions::{
    attach_signal_action_state, fork_from_parent, init_for_process, reassign_process_pid,
    reset_on_execve, sig_slots_ptr, signal_action_table_bytes, signal_slots_bytes,
    sys_rt_sigaction,
};
pub use delivery::{
    check_pending, pending_signal_interrupts_blocked_syscall, pending_signal_snapshot,
};
pub(crate) use frame::SS_DISABLE;
pub use frame::{is_current_sigreturn_trampoline, patch_current_signal_frame_a0, sys_sigaltstack};
pub(crate) use pending::sanitized_signal_mask;
#[cfg(any(test, feature = "harness"))]
pub(crate) use pending::{
    ProcessPendingStateImage, capture_process_pending_state_into,
    restore_process_pending_state_from,
};
pub use pending::{
    attach_process_pending_state, clear_process_signal, pid_from_vm, process_pending_bytes,
    process_pending_ptr, queue_process_signal, queue_sigill, queue_sigsegv, send_signal,
    send_signal_to_pid, send_signal_to_tid, send_signal_with_code, sys_rt_sigpending,
    sys_rt_sigprocmask,
};
pub use signalfd::{
    attach_signalfd_state, close_signalfd, signalfd_is_readable, signalfd_read,
    signalfd_state_bytes, signalfd_state_ptr, sys_signalfd4,
};
pub use sigreturn::sys_rt_sigreturn;
pub use trace::note_pc;

#[cfg(any(test, feature = "harness"))]
pub(crate) use trace::{
    default_signal_arg_regs, default_signal_trace, default_signal_vm_ptr,
    illegal_instruction_context, illegal_instruction_jalr, illegal_instruction_signal_frame,
    illegal_instruction_trace, reset_trace_state, signal_delivery_trace,
    signal_delivery_trace_entry_code, signal_delivery_trace_entry_fault_addr,
    signal_delivery_trace_entry_fault_pc, signal_delivery_trace_entry_frame_base,
    signal_delivery_trace_entry_pc, signal_delivery_trace_entry_ra,
    signal_delivery_trace_entry_s11, signal_delivery_trace_entry_sig,
    signal_delivery_trace_entry_sp, signal_delivery_trace_entry_vm_ptr,
    signal_delivery_trace_for_vm, signal_delivery_trace_len, signal_send_trace,
    signal_send_trace_entry, signal_send_trace_len, sigreturn_trace, sync_fault_arg_reg,
    sync_fault_saved_reg, sync_fault_trace, trampoline_trace_state,
};

/// Initialize signal subsystem. Must be called once at kernel init.
pub fn init() {
    actions::init_action_tables();
    pending::init();
    signalfd::init();
}
