//! Kernel tracepoints for harness/debug observation.
//!
//! Production code depends only on this private trace API. The tracepoint
//! implementation is selected by build mode: harness/test builds re-export the
//! harness recorder, while production builds compile no-op stubs.

mod cpu;
mod execve;
mod io;
mod runtime;

pub(crate) use cpu::{
    record_exec_trace, record_guest_write_overlap, record_jalr, record_special_reg_transitions,
    record_zero_reg_transition,
};
pub(crate) use execve::{
    record_execve_approach, record_execve_dispatch, record_execve_ecall,
    record_execve_pre_dispatch, record_execve_stage,
};
pub(crate) use io::{
    record_epoll_wait, record_fd_syscall, record_memory_syscall, record_path_syscall,
    record_pipe_close_event, record_write_attempt,
};
pub(crate) use runtime::{
    record_fault_dispatch_trace, record_futex_resume_trace, record_sync_signal_trace,
    record_syscall, record_thread_count, record_thread_step_entry_trace, record_thread_step_phase,
    record_thread_step_trace,
};
