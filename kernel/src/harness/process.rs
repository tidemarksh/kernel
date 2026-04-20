#[cfg(any(test, feature = "harness"))]
use alloc_crate::vec::Vec;

#[cfg(any(test, feature = "harness"))]
#[derive(Clone, Copy)]
pub(crate) struct ProcessRuntimeSnapshot {
    state: crate::syscall::process::ProcessRuntimeStateImage,
}

#[cfg(any(test, feature = "harness"))]
impl ProcessRuntimeSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            state: crate::syscall::process::ProcessRuntimeStateImage::empty(),
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn snapshot_process_context_into(snapshot: &mut ProcessRuntimeSnapshot) {
    crate::syscall::process::snapshot_runtime_state_into(&mut snapshot.state);
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn restore_process_context(snapshot: &ProcessRuntimeSnapshot) {
    crate::syscall::process::restore_runtime_state_from(&snapshot.state);
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_child_entry(pid: i32) -> Option<(i32, bool, i32)> {
    crate::syscall::process::child_entry_state(pid)
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_exited_children_for_parent(parent_pid: i32) -> Vec<(i32, i32)> {
    crate::syscall::process::exited_children_for_parent(parent_pid)
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_child_entries_for_parent(parent_pid: i32) -> Vec<(i32, bool, i32)> {
    crate::syscall::process::child_entries_for_parent(parent_pid)
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_process_entry_exists(pid: i32) -> bool {
    crate::syscall::process::has_process_entry(pid)
}

#[cfg(any(test, feature = "harness"))]
pub fn sync_child_entry_for_parent(parent_pid: i32, pid: i32, exited: bool, wait_status: i32) {
    crate::syscall::process::sync_child_entry(parent_pid, pid, exited, wait_status);
}
