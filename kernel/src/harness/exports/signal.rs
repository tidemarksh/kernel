#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clear_signal_trace() {
    crate::harness::signal::clear_debug_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_sig() -> u32 {
    crate::harness::signal::last_signal_delivery().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_for_vm_sig(vm_ptr: u32) -> u32 {
    crate::harness::signal::last_signal_delivery_for_vm(vm_ptr).0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_frame_base() -> u64 {
    crate::harness::signal::last_signal_delivery().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_for_vm_frame_base(vm_ptr: u32) -> u64 {
    crate::harness::signal::last_signal_delivery_for_vm(vm_ptr).1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_pc() -> u64 {
    crate::harness::signal::last_signal_delivery().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_for_vm_pc(vm_ptr: u32) -> u64 {
    crate::harness::signal::last_signal_delivery_for_vm(vm_ptr).2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_ra() -> u64 {
    crate::harness::signal::last_signal_delivery().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_for_vm_ra(vm_ptr: u32) -> u64 {
    crate::harness::signal::last_signal_delivery_for_vm(vm_ptr).3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_sp() -> u64 {
    crate::harness::signal::last_signal_delivery().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_for_vm_sp(vm_ptr: u32) -> u64 {
    crate::harness::signal::last_signal_delivery_for_vm(vm_ptr).4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_gp() -> u64 {
    crate::harness::signal::last_signal_delivery().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_for_vm_gp(vm_ptr: u32) -> u64 {
    crate::harness::signal::last_signal_delivery_for_vm(vm_ptr).5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_tp() -> u64 {
    crate::harness::signal::last_signal_delivery().6
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_for_vm_tp(vm_ptr: u32) -> u64 {
    crate::harness::signal::last_signal_delivery_for_vm(vm_ptr).6
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_s11() -> u64 {
    crate::harness::signal::last_signal_delivery().7
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_for_vm_s11(vm_ptr: u32) -> u64 {
    crate::harness::signal::last_signal_delivery_for_vm(vm_ptr).7
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_len() -> u32 {
    crate::harness::signal::signal_delivery_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_vm_ptr(index: u32) -> u32 {
    crate::harness::signal::signal_delivery_trace_entry_vm_ptr(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_sig(index: u32) -> u32 {
    crate::harness::signal::signal_delivery_trace_entry_sig(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_code(index: u32) -> i32 {
    crate::harness::signal::signal_delivery_trace_entry_code(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_frame_base(index: u32) -> u64 {
    crate::harness::signal::signal_delivery_trace_entry_frame_base(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_pc(index: u32) -> u64 {
    crate::harness::signal::signal_delivery_trace_entry_pc(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_ra(index: u32) -> u64 {
    crate::harness::signal::signal_delivery_trace_entry_ra(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_sp(index: u32) -> u64 {
    crate::harness::signal::signal_delivery_trace_entry_sp(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_s11(index: u32) -> u64 {
    crate::harness::signal::signal_delivery_trace_entry_s11(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_fault_pc(index: u32) -> u64 {
    crate::harness::signal::signal_delivery_trace_entry_fault_pc(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_trace_entry_fault_addr(index: u32) -> u64 {
    crate::harness::signal::signal_delivery_trace_entry_fault_addr(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_sig() -> u32 {
    crate::harness::signal::last_default_signal().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_code() -> i32 {
    crate::harness::signal::last_default_signal().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_vm_ptr() -> u32 {
    crate::harness::signal::last_default_signal_vm_ptr()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_pc() -> u64 {
    crate::harness::signal::last_default_signal().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_ra() -> u64 {
    crate::harness::signal::last_default_signal().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_sp() -> u64 {
    crate::harness::signal::last_default_signal().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_gp() -> u64 {
    crate::harness::signal::last_default_signal().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_tp() -> u64 {
    crate::harness::signal::last_default_signal().6
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_s11() -> u64 {
    crate::harness::signal::last_default_signal().7
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_fault_pc() -> u64 {
    crate::harness::signal::last_default_signal().8
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_default_signal_fault_addr() -> u64 {
    crate::harness::signal::last_default_signal().9
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_vm_ptr() -> u32 {
    crate::harness::signal::last_illegal_instruction().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_pc() -> u64 {
    crate::harness::signal::last_illegal_instruction().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_raw() -> u32 {
    crate::harness::signal::last_illegal_instruction().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_ra() -> u64 {
    crate::harness::signal::last_illegal_instruction_context().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_sp() -> u64 {
    crate::harness::signal::last_illegal_instruction_context().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_a0() -> u64 {
    crate::harness::signal::last_illegal_instruction_context().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_a4() -> u64 {
    crate::harness::signal::last_illegal_instruction_context().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_s11() -> u64 {
    crate::harness::signal::last_illegal_instruction_context().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_jalr_pc() -> u64 {
    crate::harness::signal::last_illegal_instruction_jalr().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_jalr_rs1_value() -> u64 {
    crate::harness::signal::last_illegal_instruction_jalr().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_jalr_target() -> u64 {
    crate::harness::signal::last_illegal_instruction_jalr().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_jalr_rd() -> u32 {
    crate::harness::signal::last_illegal_instruction_jalr().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_jalr_rs1() -> u32 {
    crate::harness::signal::last_illegal_instruction_jalr().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_signal_frame_base() -> u64 {
    crate::harness::signal::last_illegal_instruction_signal_frame().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_signal_handler_pc() -> u64 {
    crate::harness::signal::last_illegal_instruction_signal_frame().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_signal_code() -> i32 {
    crate::harness::signal::last_illegal_instruction_signal_frame().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_signal_addr() -> u64 {
    crate::harness::signal::last_illegal_instruction_signal_frame().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_signal_uc_pc() -> u64 {
    crate::harness::signal::last_illegal_instruction_signal_frame().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_signal_uc_ra() -> u64 {
    crate::harness::signal::last_illegal_instruction_signal_frame().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_signal_uc_sp() -> u64 {
    crate::harness::signal::last_illegal_instruction_signal_frame().6
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_illegal_instruction_signal_uc_a0() -> u64 {
    crate::harness::signal::last_illegal_instruction_signal_frame().7
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_caller_vm_ptr() -> u32 {
    crate::harness::signal::last_signal_send().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_kind() -> u32 {
    crate::harness::signal::last_signal_send().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_pid() -> i32 {
    crate::harness::signal::last_signal_send().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_tid() -> i32 {
    crate::harness::signal::last_signal_send().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_sig() -> i32 {
    crate::harness::signal::last_signal_send().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_result() -> i64 {
    crate::harness::signal::last_signal_send().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_vm_ptr() -> u32 {
    crate::harness::signal::last_sync_fault().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_tid() -> i32 {
    crate::harness::signal::last_sync_fault().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_pc() -> u64 {
    crate::harness::signal::last_sync_fault().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_ra() -> u64 {
    crate::harness::signal::last_sync_fault().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_sp() -> u64 {
    crate::harness::signal::last_sync_fault().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_s11() -> u64 {
    crate::harness::signal::last_sync_fault().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_a0() -> u64 {
    crate::harness::signal::last_sync_fault().6
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_a1() -> u64 {
    crate::harness::signal::last_sync_fault_arg_reg(1)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_a2() -> u64 {
    crate::harness::signal::last_sync_fault_arg_reg(2)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_a3() -> u64 {
    crate::harness::signal::last_sync_fault_arg_reg(3)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_a4() -> u64 {
    crate::harness::signal::last_sync_fault_arg_reg(4)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_a5() -> u64 {
    crate::harness::signal::last_sync_fault_arg_reg(5)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_a6() -> u64 {
    crate::harness::signal::last_sync_fault_arg_reg(6)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_a7() -> u64 {
    crate::harness::signal::last_sync_fault_arg_reg(7)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_s1() -> u64 {
    crate::harness::signal::last_sync_fault_saved_reg(1)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_s2() -> u64 {
    crate::harness::signal::last_sync_fault_saved_reg(2)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_s3() -> u64 {
    crate::harness::signal::last_sync_fault_saved_reg(3)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_s4() -> u64 {
    crate::harness::signal::last_sync_fault_saved_reg(4)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_s5() -> u64 {
    crate::harness::signal::last_sync_fault_saved_reg(5)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_s6() -> u64 {
    crate::harness::signal::last_sync_fault_saved_reg(6)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_s7() -> u64 {
    crate::harness::signal::last_sync_fault_saved_reg(7)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_addr() -> u64 {
    crate::harness::signal::last_sync_fault().7
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_code() -> i32 {
    crate::harness::signal::last_sync_fault().8
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_trace_len() -> u32 {
    crate::harness::signal::signal_send_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_trace_entry_caller_vm_ptr(index: u32) -> u32 {
    crate::harness::signal::signal_send_trace_entry(index).0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_trace_entry_kind(index: u32) -> u32 {
    crate::harness::signal::signal_send_trace_entry(index).1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_trace_entry_pid(index: u32) -> i32 {
    crate::harness::signal::signal_send_trace_entry(index).2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_trace_entry_tid(index: u32) -> i32 {
    crate::harness::signal::signal_send_trace_entry(index).3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_trace_entry_sig(index: u32) -> i32 {
    crate::harness::signal::signal_send_trace_entry(index).4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_send_trace_entry_result(index: u32) -> i64 {
    crate::harness::signal::signal_send_trace_entry(index).5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_frame_base() -> u64 {
    crate::harness::signal::last_sigreturn().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_pc() -> u64 {
    crate::harness::signal::last_sigreturn().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_ra() -> u64 {
    crate::harness::signal::last_sigreturn().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_sp() -> u64 {
    crate::harness::signal::last_sigreturn().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_gp() -> u64 {
    crate::harness::signal::last_sigreturn().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_tp() -> u64 {
    crate::harness::signal::last_sigreturn().6
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_s11() -> u64 {
    crate::harness::signal::last_sigreturn().7
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_trampoline_hit_tid() -> i32 {
    crate::harness::signal::last_trampoline_hit().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_trampoline_hit_pc() -> u64 {
    crate::harness::signal::last_trampoline_hit().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_count() -> u32 {
    crate::harness::signal::last_trampoline_hit().2
}
