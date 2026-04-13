//! Harness instrumentation hooks for kernel-internal call sites.
//!
//! Production kernel code calls this module instead of touching
//! `harness/debug.rs` directly. The hook implementations remain no-op unless
//! harness instrumentation is enabled.

use crate::harness_debug;

pub(crate) use harness_debug::{
    record_guest_write_overlap,
    record_epoll_wait, record_exec_trace, record_execve_stage, record_fd_syscall, record_jalr,
    record_memory_syscall, record_path_syscall, record_pipe_close_event,
    record_special_reg_transitions, record_syscall, record_thread_count, record_write_attempt,
    record_zero_reg_transition,
};
