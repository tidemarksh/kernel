#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clear_syscall_trace() {
    crate::harness::trace::clear_syscall_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_nr() -> u64 {
    crate::harness::debug::syscall_trace_summary().nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_result() -> i64 {
    crate::harness::debug::syscall_trace_summary().result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_status() -> i32 {
    crate::harness::debug::syscall_trace_summary().status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_len() -> u32 {
    crate::harness::debug::syscall_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::syscall_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_nr(index: u32) -> u64 {
    crate::harness::debug::syscall_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_arg0(index: u32) -> u64 {
    crate::harness::debug::syscall_trace_entry(index).arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_arg1(index: u32) -> u64 {
    crate::harness::debug::syscall_trace_entry(index).arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_arg2(index: u32) -> u64 {
    crate::harness::debug::syscall_trace_entry(index).arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_arg3(index: u32) -> u64 {
    crate::harness::debug::syscall_trace_entry(index).arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_arg4(index: u32) -> u64 {
    crate::harness::debug::syscall_trace_entry(index).arg4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_arg5(index: u32) -> u64 {
    crate::harness::debug::syscall_trace_entry(index).arg5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_result(index: u32) -> i64 {
    crate::harness::debug::syscall_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_status(index: u32) -> i32 {
    crate::harness::debug::syscall_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_pid_sample0(index: u32) -> u64 {
    crate::harness::debug::syscall_trace_entry(index).pid_sample0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_entry_pid_sample1(index: u32) -> u64 {
    crate::harness::debug::syscall_trace_entry(index).pid_sample1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_profile_count(nr: u32) -> u64 {
    crate::harness::debug::syscall_profile_slot_count(nr)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_profile_non_ok_status_count(nr: u32) -> u64 {
    crate::harness::debug::syscall_profile_slot_non_ok_status_count(nr)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_profile_error_count(nr: u32) -> u64 {
    crate::harness::debug::syscall_profile_slot_error_count(nr)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_len() -> u32 {
    crate::harness::debug::futex_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::futex_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_tid(index: u32) -> i32 {
    crate::harness::debug::futex_trace_entry(index).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_pc(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_ra(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_sp(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_s0(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).s0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_s1(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).s1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_s2(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).s2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_s3(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).s3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_a0(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).a0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_a1(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).a1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_a2(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).a2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_a3(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).a3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_a4(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).a4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_a5(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).a5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_op(index: u32) -> u32 {
    crate::harness::debug::futex_trace_entry(index).op
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_addr(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).addr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_addr2(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).addr2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_val(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).val
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_val3(index: u32) -> u64 {
    crate::harness::debug::futex_trace_entry(index).val3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_current(index: u32) -> u32 {
    crate::harness::debug::futex_trace_entry(index).current
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_local(index: u32) -> u32 {
    crate::harness::debug::futex_trace_entry(index).local
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_external(index: u32) -> u32 {
    crate::harness::debug::futex_trace_entry(index).external
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_requeued(index: u32) -> u32 {
    crate::harness::debug::futex_trace_entry(index).requeued
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_result(index: u32) -> i64 {
    crate::harness::debug::futex_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_futex_trace_entry_status(index: u32) -> i32 {
    crate::harness::debug::futex_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_len() -> u32 {
    crate::harness::debug::riscv_syscall_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::riscv_syscall_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_nr(index: u32) -> u64 {
    crate::harness::debug::riscv_syscall_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_arg0(index: u32) -> u64 {
    crate::harness::debug::riscv_syscall_trace_entry(index).arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_arg1(index: u32) -> u64 {
    crate::harness::debug::riscv_syscall_trace_entry(index).arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_arg2(index: u32) -> u64 {
    crate::harness::debug::riscv_syscall_trace_entry(index).arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_arg3(index: u32) -> u64 {
    crate::harness::debug::riscv_syscall_trace_entry(index).arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_arg4(index: u32) -> u64 {
    crate::harness::debug::riscv_syscall_trace_entry(index).arg4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_arg5(index: u32) -> u64 {
    crate::harness::debug::riscv_syscall_trace_entry(index).arg5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_result(index: u32) -> i64 {
    crate::harness::debug::riscv_syscall_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_riscv_syscall_trace_entry_status(index: u32) -> i32 {
    crate::harness::debug::riscv_syscall_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_completed_sync_effects() -> u32 {
    crate::harness::debug::completed_sync_effects()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_panic_file_ptr() -> u32 {
    crate::last_panic_location().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_panic_file_len() -> u32 {
    crate::last_panic_location().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_panic_line() -> u32 {
    crate::last_panic_location().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_panic_column() -> u32 {
    crate::last_panic_location().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_stage() -> u32 {
    crate::harness::debug::execve_stage()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_value0() -> u64 {
    crate::harness::debug::execve_value0()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_value1() -> u64 {
    crate::harness::debug::execve_value1()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_error_errno() -> i64 {
    crate::harness::debug::execve_error_errno()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_error_stage() -> u32 {
    crate::harness::debug::execve_error_stage()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_error_value0() -> u64 {
    crate::harness::debug::execve_error_value0()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_error_value1() -> u64 {
    crate::harness::debug::execve_error_value1()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_stage_trace_len() -> u32 {
    crate::harness::debug::execve_stage_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_stage_trace_stage(index: u32) -> u32 {
    crate::harness::debug::execve_stage_trace_entry(index).stage
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_stage_trace_value0(index: u32) -> u64 {
    crate::harness::debug::execve_stage_trace_entry(index).value0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_stage_trace_value1(index: u32) -> u64 {
    crate::harness::debug::execve_stage_trace_entry(index).value1
}
