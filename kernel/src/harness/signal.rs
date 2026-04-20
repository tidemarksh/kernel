#[derive(Clone, Copy)]
pub(crate) struct ProcessSignalSnapshot {
    state: crate::syscall::signal::ProcessSignalStateImage,
}

impl ProcessSignalSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            state: crate::syscall::signal::ProcessSignalStateImage::empty(),
        }
    }
}

pub(crate) fn snapshot_process_context_into(snapshot: &mut ProcessSignalSnapshot) {
    crate::syscall::signal::capture_process_signal_state_into(&mut snapshot.state);
}

pub(crate) fn restore_process_context(snapshot: &ProcessSignalSnapshot) {
    crate::syscall::signal::restore_process_signal_state_from(&snapshot.state);
}

pub fn clear_debug_trace() {
    crate::syscall::signal::reset_trace_state();
}

pub fn last_signal_delivery() -> (u32, u64, u64, u64, u64, u64, u64, u64) {
    crate::syscall::signal::signal_delivery_trace()
}

pub fn last_signal_delivery_for_vm(vm_ptr: u32) -> (u32, u64, u64, u64, u64, u64, u64, u64) {
    crate::syscall::signal::signal_delivery_trace_for_vm(vm_ptr)
}

pub fn last_sigreturn() -> (u32, u64, u64, u64, u64, u64, u64, u64) {
    crate::syscall::signal::sigreturn_trace()
}

pub fn last_default_signal() -> (u32, i32, u64, u64, u64, u64, u64, u64, u64, u64) {
    crate::syscall::signal::default_signal_trace()
}

pub fn last_trampoline_hit() -> (i32, u64, u32) {
    crate::syscall::signal::trampoline_trace_state()
}
