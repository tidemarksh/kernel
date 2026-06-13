#[derive(Clone, Copy)]
pub(crate) struct ProcessSignalSnapshot {
    action_state: crate::syscall::signal::SignalActionStateImage,
    pending_state: crate::syscall::signal::ProcessPendingStateImage,
}

impl ProcessSignalSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            action_state: crate::syscall::signal::SignalActionStateImage::empty(),
            pending_state: crate::syscall::signal::ProcessPendingStateImage::empty(),
        }
    }
}

pub(crate) fn snapshot_process_context_into(snapshot: &mut ProcessSignalSnapshot) {
    crate::syscall::signal::capture_signal_action_state_into(&mut snapshot.action_state);
    crate::syscall::signal::capture_process_pending_state_into(&mut snapshot.pending_state);
}

pub(crate) fn restore_process_context(snapshot: &ProcessSignalSnapshot) {
    crate::syscall::signal::restore_signal_action_state_from(&snapshot.action_state);
    crate::syscall::signal::restore_process_pending_state_from(&snapshot.pending_state);
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

pub fn signal_delivery_trace_len() -> u32 {
    crate::syscall::signal::signal_delivery_trace_len()
}

pub fn signal_delivery_trace_entry_vm_ptr(index: u32) -> u32 {
    crate::syscall::signal::signal_delivery_trace_entry_vm_ptr(index)
}

pub fn signal_delivery_trace_entry_sig(index: u32) -> u32 {
    crate::syscall::signal::signal_delivery_trace_entry_sig(index)
}

pub fn signal_delivery_trace_entry_code(index: u32) -> i32 {
    crate::syscall::signal::signal_delivery_trace_entry_code(index)
}

pub fn signal_delivery_trace_entry_frame_base(index: u32) -> u64 {
    crate::syscall::signal::signal_delivery_trace_entry_frame_base(index)
}

pub fn signal_delivery_trace_entry_pc(index: u32) -> u64 {
    crate::syscall::signal::signal_delivery_trace_entry_pc(index)
}

pub fn signal_delivery_trace_entry_ra(index: u32) -> u64 {
    crate::syscall::signal::signal_delivery_trace_entry_ra(index)
}

pub fn signal_delivery_trace_entry_sp(index: u32) -> u64 {
    crate::syscall::signal::signal_delivery_trace_entry_sp(index)
}

pub fn signal_delivery_trace_entry_s11(index: u32) -> u64 {
    crate::syscall::signal::signal_delivery_trace_entry_s11(index)
}

pub fn signal_delivery_trace_entry_fault_pc(index: u32) -> u64 {
    crate::syscall::signal::signal_delivery_trace_entry_fault_pc(index)
}

pub fn signal_delivery_trace_entry_fault_addr(index: u32) -> u64 {
    crate::syscall::signal::signal_delivery_trace_entry_fault_addr(index)
}

pub fn last_sigreturn() -> (u32, u64, u64, u64, u64, u64, u64, u64) {
    crate::syscall::signal::sigreturn_trace()
}

pub fn last_default_signal() -> (u32, i32, u64, u64, u64, u64, u64, u64, u64, u64) {
    crate::syscall::signal::default_signal_trace()
}

pub fn last_default_signal_arg_regs() -> [u64; 8] {
    crate::syscall::signal::default_signal_arg_regs()
}

pub fn last_default_signal_vm_ptr() -> u32 {
    crate::syscall::signal::default_signal_vm_ptr()
}

pub fn last_illegal_instruction() -> (u32, u64, u32) {
    crate::syscall::signal::illegal_instruction_trace()
}

pub fn last_illegal_instruction_context() -> (u64, u64, u64, u64, u64) {
    crate::syscall::signal::illegal_instruction_context()
}

pub fn last_illegal_instruction_jalr() -> (u64, u64, u64, u32, u32) {
    crate::syscall::signal::illegal_instruction_jalr()
}

#[allow(clippy::type_complexity)]
pub fn last_illegal_instruction_signal_frame() -> (u64, u64, i32, u64, u64, u64, u64, u64) {
    crate::syscall::signal::illegal_instruction_signal_frame()
}

pub fn last_signal_send() -> (u32, u32, i32, i32, i32, i64) {
    crate::syscall::signal::signal_send_trace()
}

pub fn signal_send_trace_len() -> u32 {
    crate::syscall::signal::signal_send_trace_len()
}

pub fn signal_send_trace_entry(index: u32) -> (u32, u32, i32, i32, i32, i64) {
    crate::syscall::signal::signal_send_trace_entry(index)
}

pub fn last_sync_fault() -> (u32, i32, u64, u64, u64, u64, u64, u64, i32) {
    crate::syscall::signal::sync_fault_trace()
}

pub fn last_sync_fault_arg_reg(index: u32) -> u64 {
    crate::syscall::signal::sync_fault_arg_reg(index)
}

pub fn last_sync_fault_saved_reg(index: u32) -> u64 {
    crate::syscall::signal::sync_fault_saved_reg(index)
}

pub fn last_trampoline_hit() -> (i32, u64, u32) {
    crate::syscall::signal::trampoline_trace_state()
}
