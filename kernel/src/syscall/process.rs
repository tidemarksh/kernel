//! Process lifecycle syscalls: execve, wait4, vfork, fork.
//!
//! vfork: parent suspends (STATUS_VFORK_WAIT), child runs in parent's memory.
//! execve: normal path replaces the current process in place; vfork+execve exports
//! handoff data so TS can create the post-exec child Worker in the runtime harness.
//! fork: guest Memory full copy → STATUS_EXECVE_SPAWN.
//! wait4: retrieve child exit status.
//!
//! Semantics:
//! https://man7.org/linux/man-pages/man2/vfork.2.html
//! https://man7.org/linux/man-pages/man2/execve.2.html
//! https://man7.org/linux/man-pages/man2/fork.2.html
//! https://man7.org/linux/man-pages/man2/wait4.2.html

mod common;
mod execve;
mod fork;
mod handoff;
mod lifecycle;
mod runtime;
mod vfork;
mod wait;

pub use execve::{
    complete_execve_in_place, complete_execve_in_place_from_handoff, install_procfs_snapshot,
    max_execve_guest_memory_limit, sys_execve, sys_execveat, EXECVE_GUEST_MEMORY_LIMIT,
};
pub use fork::sys_fork;
#[cfg(any(test, feature = "harness"))]
pub(crate) use lifecycle::has_process_entry;
pub use lifecycle::{
    current_process_did_exec, current_process_pgid, current_process_pid, current_process_ppid,
    current_process_sid, prepare_fork_child_after_handoff, process_pgid, record_child_exit,
    record_child_exit_for_parent, remove_process_entry, reset_process_lifecycle,
    restore_fork_parent_after_handoff, rewrite_child_pid, sys_getpgid, sys_setpgid, sys_setsid,
    upsert_process_entry,
};
pub use runtime::{
    advance_shared_heap_ptr, attach_process_runtime_state_ptr, init, process_runtime_state_bytes,
    process_runtime_state_ptr, shared_heap_alloc, shared_heap_base, shared_heap_ptr, vfork_active,
    vfork_child_pid,
};
#[cfg(any(test, feature = "harness"))]
pub(crate) use runtime::{
    child_entries_for_parent, child_entry_state, exited_children_for_parent, reset_for_tests,
    restore_runtime_state_from, snapshot_runtime_state_into, sync_child_entry,
    ProcessRuntimeStateImage,
};
pub use vfork::{
    clear_vfork_runtime_state, sys_clone_vfork, sys_vfork, vfork_parent_restore_without_cleanup,
    vfork_parent_resume, vfork_restore_parent_proc_self_exe_snapshot,
};
pub use wait::{resume_wait4, sys_wait4, sys_waitid};
