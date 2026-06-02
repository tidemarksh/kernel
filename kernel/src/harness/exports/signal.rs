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
