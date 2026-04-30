#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_tid(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).tid }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_tp(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[4] }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_gp(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[3] }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_s11(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[27] }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_reg(vm_ptr: u32, reg_index: u32) -> u64 {
    if reg_index >= 32 {
        return 0;
    }
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[reg_index as usize] }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_tls_base(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).tls_base }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_sig_mask(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).sig_mask }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_sig_info_code(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).sig_info_code }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_fault_pc(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).fault_pc }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_fault_addr(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).fault_addr }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_ra(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[1] }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_stack_word(vm_ptr: u32, word_index: u32) -> u64 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::guest_mem::read_u64(vm.guest_base, vm.x[2] + (word_index as u64) * 8)
    }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn thread_stack_minus(vm_ptr: u32, byte_offset: u32) -> u64 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        let sp = vm.x[2];
        if sp < byte_offset as u64 {
            return 0;
        }
        crate::guest_mem::read_u64(vm.guest_base, sp - byte_offset as u64)
    }
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clear_syscall_trace() {
    crate::harness::debug::clear_syscall_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clear_signal_trace() {
    crate::harness::signal::clear_debug_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clear_cpu_trace() {
    crate::harness::debug::clear_cpu_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clear_guest_write_watch_trace() {
    crate::harness::debug::clear_guest_write_watch_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_configure_guest_write_watch(slot: u32, start: u64, end: u64) {
    crate::harness::debug::configure_guest_write_watch(slot, start, end);
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
pub extern "C" fn debug_fd_syscall_trace_len() -> u32 {
    crate::harness::debug::fd_syscall_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::fd_syscall_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_nr(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg0(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg0_ofd_id(index: u32) -> u32 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg0_ofd_id
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg0_ofd_type(index: u32) -> i32 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg0_ofd_type
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg1(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg2(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg2_ofd_id(index: u32) -> u32 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg2_ofd_id
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg2_ofd_type(index: u32) -> i32 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg2_ofd_type
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg3(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_result(index: u32) -> i64 {
    crate::harness::debug::fd_syscall_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_status(index: u32) -> i32 {
    crate::harness::debug::fd_syscall_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_pid_sample0(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).pid_sample0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_pid_sample1(index: u32) -> u64 {
    crate::harness::debug::fd_syscall_trace_entry(index).pid_sample1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_len() -> u32 {
    crate::harness::debug::path_syscall_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::path_syscall_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_nr(index: u32) -> u64 {
    crate::harness::debug::path_syscall_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_dirfd(index: u32) -> i64 {
    crate::harness::debug::path_syscall_trace_entry(index).dirfd
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_result(index: u32) -> i64 {
    crate::harness::debug::path_syscall_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_status(index: u32) -> i32 {
    crate::harness::debug::path_syscall_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_path_ptr(index: u32) -> u32 {
    crate::harness::debug::path_syscall_trace_path_ptr(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_path_len(index: u32) -> u32 {
    crate::harness::debug::path_syscall_trace_entry(index).path_len
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_nr() -> u64 {
    crate::harness::debug::memory_trace_summary().nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg0() -> u64 {
    crate::harness::debug::memory_trace_summary().arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg1() -> u64 {
    crate::harness::debug::memory_trace_summary().arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg2() -> u64 {
    crate::harness::debug::memory_trace_summary().arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg3() -> u64 {
    crate::harness::debug::memory_trace_summary().arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_result() -> i64 {
    crate::harness::debug::memory_trace_summary().result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_len() -> u32 {
    crate::harness::debug::memory_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_nr(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_arg0(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_arg1(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_arg2(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_arg3(index: u32) -> u64 {
    crate::harness::debug::memory_trace_entry(index).arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_entry_result(index: u32) -> i64 {
    crate::harness::debug::memory_trace_entry(index).result
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
pub extern "C" fn debug_clone_spawn_tid() -> i32 {
    crate::syscall::thread::last_clone_spawn().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_pc() -> u64 {
    crate::syscall::thread::last_clone_spawn().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_ra() -> u64 {
    crate::syscall::thread::last_clone_spawn().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_gp() -> u64 {
    crate::syscall::thread::last_clone_spawn().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_sp() -> u64 {
    crate::syscall::thread::last_clone_spawn().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_s11() -> u64 {
    crate::syscall::thread::last_clone_spawn().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_stack_m32() -> u64 {
    crate::syscall::thread::last_clone_spawn().6
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_stack_m24() -> u64 {
    crate::syscall::thread::last_clone_spawn().7
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_stack_m16() -> u64 {
    crate::syscall::thread::last_clone_spawn().8
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_stack_m8() -> u64 {
    crate::syscall::thread::last_clone_spawn().9
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
pub extern "C" fn debug_jalr_pc() -> u64 {
    crate::harness::debug::last_jalr_trace().pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_jalr_pc() -> u64 {
    crate::harness::debug::last_clone_jalr_trace().pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_for_vm_pc(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_jalr_trace_for_vm(vm_ptr).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_pc() -> u64 {
    crate::harness::debug::last_zero_reg_trace().pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_for_vm_pc(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_zero_reg_trace_for_vm(vm_ptr).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_tid() -> i32 {
    crate::harness::debug::last_zero_reg_trace().tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_for_vm_tid(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_zero_reg_trace_for_vm(vm_ptr).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_raw() -> u32 {
    crate::harness::debug::last_zero_reg_trace().raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_for_vm_raw(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_zero_reg_trace_for_vm(vm_ptr).raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_index() -> u32 {
    crate::harness::debug::last_zero_reg_trace().reg
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_for_vm_index(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_zero_reg_trace_for_vm(vm_ptr).reg
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_prev_value() -> u64 {
    crate::harness::debug::last_zero_reg_trace().prev_value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_for_vm_prev_value(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_zero_reg_trace_for_vm(vm_ptr).prev_value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_sp() -> u64 {
    crate::harness::debug::last_zero_reg_trace().sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_for_vm_sp(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_zero_reg_trace_for_vm(vm_ptr).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_s11() -> u64 {
    crate::harness::debug::last_zero_reg_trace().s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_for_vm_s11(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_zero_reg_trace_for_vm(vm_ptr).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_tid() -> i32 {
    crate::harness::debug::last_s11_write_trace().tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_for_vm_tid(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_s11_write_trace_for_vm(vm_ptr).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_pc() -> u64 {
    crate::harness::debug::last_s11_write_trace().pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_for_vm_pc(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_s11_write_trace_for_vm(vm_ptr).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_raw() -> u32 {
    crate::harness::debug::last_s11_write_trace().raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_for_vm_raw(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_s11_write_trace_for_vm(vm_ptr).raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_source() -> u32 {
    crate::harness::debug::last_s11_write_trace().source
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_for_vm_source(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_s11_write_trace_for_vm(vm_ptr).source
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_prev_value() -> u64 {
    crate::harness::debug::last_s11_write_trace().prev_value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_for_vm_prev_value(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_s11_write_trace_for_vm(vm_ptr).prev_value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_value() -> u64 {
    crate::harness::debug::last_s11_write_trace().value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_s11_write_for_vm_value(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_s11_write_trace_for_vm(vm_ptr).value
}

pub extern "C" fn debug_sp_write_pc() -> u64 {
    crate::harness::debug::last_sp_write_trace().pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_for_vm_pc(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_sp_write_trace_for_vm(vm_ptr).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_raw() -> u32 {
    crate::harness::debug::last_sp_write_trace().raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_for_vm_raw(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_sp_write_trace_for_vm(vm_ptr).raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_source() -> u32 {
    crate::harness::debug::last_sp_write_trace().source
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_for_vm_source(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_sp_write_trace_for_vm(vm_ptr).source
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_prev_value() -> u64 {
    crate::harness::debug::last_sp_write_trace().prev_value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_for_vm_prev_value(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_sp_write_trace_for_vm(vm_ptr).prev_value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_value() -> u64 {
    crate::harness::debug::last_sp_write_trace().value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_for_vm_value(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_sp_write_trace_for_vm(vm_ptr).value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_tid() -> i32 {
    crate::harness::debug::last_sp_write_trace().tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_for_vm_tid(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_sp_write_trace_for_vm(vm_ptr).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_rs1_value() -> u64 {
    crate::harness::debug::last_jalr_trace().rs1_value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_jalr_rs1_value() -> u64 {
    crate::harness::debug::last_clone_jalr_trace().rs1_value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_for_vm_rs1_value(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_jalr_trace_for_vm(vm_ptr).rs1_value
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_target() -> u64 {
    crate::harness::debug::last_jalr_trace().target
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_jalr_target() -> u64 {
    crate::harness::debug::last_clone_jalr_trace().target
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_for_vm_target(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_jalr_trace_for_vm(vm_ptr).target
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_rd() -> u32 {
    crate::harness::debug::last_jalr_trace().rd
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_jalr_rd() -> u32 {
    crate::harness::debug::last_clone_jalr_trace().rd
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_for_vm_rd(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_jalr_trace_for_vm(vm_ptr).rd
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_rs1() -> u32 {
    crate::harness::debug::last_jalr_trace().rs1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_jalr_rs1() -> u32 {
    crate::harness::debug::last_clone_jalr_trace().rs1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_len() -> u32 {
    crate::harness::debug::clone_startup_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_entry_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::clone_startup_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_entry_tid(index: u32) -> i32 {
    crate::harness::debug::clone_startup_trace_entry(index).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_entry_pc(index: u32) -> u64 {
    crate::harness::debug::clone_startup_trace_entry(index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_entry_raw(index: u32) -> u32 {
    crate::harness::debug::clone_startup_trace_entry(index).raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_entry_a0(index: u32) -> u64 {
    crate::harness::debug::clone_startup_trace_entry(index).a0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_entry_t1(index: u32) -> u64 {
    crate::harness::debug::clone_startup_trace_entry(index).t1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_entry_t2(index: u32) -> u64 {
    crate::harness::debug::clone_startup_trace_entry(index).t2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_entry_sp(index: u32) -> u64 {
    crate::harness::debug::clone_startup_trace_entry(index).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_startup_trace_entry_s11(index: u32) -> u64 {
    crate::harness::debug::clone_startup_trace_entry(index).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_for_vm_rs1(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_jalr_trace_for_vm(vm_ptr).rs1
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

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_len() -> u32 {
    crate::harness::debug::exec_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::exec_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_epoch(index: u32) -> u32 {
    crate::harness::debug::exec_trace_entry(index).epoch
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_tid(index: u32) -> i32 {
    crate::harness::debug::exec_trace_entry(index).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_pc(index: u32) -> u64 {
    crate::harness::debug::exec_trace_entry(index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_raw(index: u32) -> u32 {
    crate::harness::debug::exec_trace_entry(index).raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_step(index: u32) -> u32 {
    crate::harness::debug::exec_trace_entry(index).step
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_sp(index: u32) -> u64 {
    crate::harness::debug::exec_trace_entry(index).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_ra(index: u32) -> u64 {
    crate::harness::debug::exec_trace_entry(index).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_a0(index: u32) -> u64 {
    crate::harness::debug::exec_trace_entry(index).a0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_entry_s11(index: u32) -> u64 {
    crate::harness::debug::exec_trace_entry(index).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_exec_trace_epoch_for_vm(vm_ptr: u32) -> u32 {
    crate::harness::debug::exec_trace_epoch_for_vm(vm_ptr)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_exec_trace_len_for_vm(vm_ptr: u32) -> u32 {
    crate::harness::debug::fault_exec_trace_len_for_vm(vm_ptr)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_exec_trace_len_for_vm(vm_ptr: u32) -> u32 {
    crate::harness::debug::sync_fault_exec_trace_len_for_vm(vm_ptr)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_exec_trace_entry_pc_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::fault_exec_trace_entry_for_vm(vm_ptr, index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_exec_trace_entry_raw_for_vm(vm_ptr: u32, index: u32) -> u32 {
    crate::harness::debug::fault_exec_trace_entry_for_vm(vm_ptr, index).raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_exec_trace_entry_step_for_vm(vm_ptr: u32, index: u32) -> u32 {
    crate::harness::debug::fault_exec_trace_entry_for_vm(vm_ptr, index).step
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_exec_trace_entry_sp_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::fault_exec_trace_entry_for_vm(vm_ptr, index).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_exec_trace_entry_ra_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::fault_exec_trace_entry_for_vm(vm_ptr, index).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_exec_trace_entry_a0_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::fault_exec_trace_entry_for_vm(vm_ptr, index).a0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_exec_trace_entry_s11_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::fault_exec_trace_entry_for_vm(vm_ptr, index).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_exec_trace_entry_pc_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::sync_fault_exec_trace_entry_for_vm(vm_ptr, index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_exec_trace_entry_raw_for_vm(vm_ptr: u32, index: u32) -> u32 {
    crate::harness::debug::sync_fault_exec_trace_entry_for_vm(vm_ptr, index).raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_exec_trace_entry_step_for_vm(vm_ptr: u32, index: u32) -> u32 {
    crate::harness::debug::sync_fault_exec_trace_entry_for_vm(vm_ptr, index).step
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_exec_trace_entry_sp_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::sync_fault_exec_trace_entry_for_vm(vm_ptr, index).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_exec_trace_entry_ra_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::sync_fault_exec_trace_entry_for_vm(vm_ptr, index).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_exec_trace_entry_a0_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::sync_fault_exec_trace_entry_for_vm(vm_ptr, index).a0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sync_fault_exec_trace_entry_s11_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::sync_fault_exec_trace_entry_for_vm(vm_ptr, index).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_exec_trace_len_for_vm(vm_ptr: u32) -> u32 {
    crate::harness::debug::thread_step_exec_trace_len_for_vm(vm_ptr)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_exec_trace_entry_pc_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::thread_step_exec_trace_entry_for_vm(vm_ptr, index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_exec_trace_entry_raw_for_vm(vm_ptr: u32, index: u32) -> u32 {
    crate::harness::debug::thread_step_exec_trace_entry_for_vm(vm_ptr, index).raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_exec_trace_entry_step_for_vm(vm_ptr: u32, index: u32) -> u32 {
    crate::harness::debug::thread_step_exec_trace_entry_for_vm(vm_ptr, index).step
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_exec_trace_entry_sp_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::thread_step_exec_trace_entry_for_vm(vm_ptr, index).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_exec_trace_entry_ra_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::thread_step_exec_trace_entry_for_vm(vm_ptr, index).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_exec_trace_entry_a0_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::thread_step_exec_trace_entry_for_vm(vm_ptr, index).a0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_exec_trace_entry_s11_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::thread_step_exec_trace_entry_for_vm(vm_ptr, index).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_break_exec_trace_len_for_vm(vm_ptr: u32) -> u32 {
    crate::harness::debug::break_exec_trace_len_for_vm(vm_ptr)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_break_exec_trace_entry_pc_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::break_exec_trace_entry_for_vm(vm_ptr, index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_break_exec_trace_entry_raw_for_vm(vm_ptr: u32, index: u32) -> u32 {
    crate::harness::debug::break_exec_trace_entry_for_vm(vm_ptr, index).raw
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_break_exec_trace_entry_step_for_vm(vm_ptr: u32, index: u32) -> u32 {
    crate::harness::debug::break_exec_trace_entry_for_vm(vm_ptr, index).step
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_break_exec_trace_entry_sp_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::break_exec_trace_entry_for_vm(vm_ptr, index).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_break_exec_trace_entry_ra_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::break_exec_trace_entry_for_vm(vm_ptr, index).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_break_exec_trace_entry_a0_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::break_exec_trace_entry_for_vm(vm_ptr, index).a0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_break_exec_trace_entry_s11_for_vm(vm_ptr: u32, index: u32) -> u64 {
    crate::harness::debug::break_exec_trace_entry_for_vm(vm_ptr, index).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_len() -> u32 {
    crate::harness::debug::thread_step_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_entry_vm_ptr(index: u32) -> u32 {
    crate::harness::debug::thread_step_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_entry_tid(index: u32) -> i32 {
    crate::harness::debug::thread_step_trace_entry(index).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_entry_status(index: u32) -> i32 {
    crate::harness::debug::thread_step_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_entry_budget(index: u32) -> i32 {
    crate::harness::debug::thread_step_trace_entry(index).budget
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_entry_remaining(index: u32) -> i32 {
    crate::harness::debug::thread_step_trace_entry(index).remaining
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_entry_pc(index: u32) -> u64 {
    crate::harness::debug::thread_step_trace_entry(index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_entry_ra(index: u32) -> u64 {
    crate::harness::debug::thread_step_trace_entry(index).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_entry_sp(index: u32) -> u64 {
    crate::harness::debug::thread_step_trace_entry(index).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_trace_entry_s11(index: u32) -> u64 {
    crate::harness::debug::thread_step_trace_entry(index).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_entry_for_vm_tid(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_entry_trace_for_vm(vm_ptr).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_entry_for_vm_status(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_entry_trace_for_vm(vm_ptr).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_entry_for_vm_budget(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_entry_trace_for_vm(vm_ptr).budget
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_entry_for_vm_pc(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_entry_trace_for_vm(vm_ptr).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_entry_for_vm_ra(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_entry_trace_for_vm(vm_ptr).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_entry_for_vm_sp(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_entry_trace_for_vm(vm_ptr).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_entry_for_vm_s11(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_entry_trace_for_vm(vm_ptr).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_tid() -> i32 {
    crate::harness::debug::last_thread_step_trace().tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_vm_ptr() -> u32 {
    crate::harness::debug::last_thread_step_trace().vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_for_vm_tid(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_trace_for_vm(vm_ptr).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_status() -> i32 {
    crate::harness::debug::last_thread_step_trace().status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_for_vm_status(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_trace_for_vm(vm_ptr).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_budget() -> i32 {
    crate::harness::debug::last_thread_step_trace().budget
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_for_vm_budget(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_trace_for_vm(vm_ptr).budget
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_remaining() -> i32 {
    crate::harness::debug::last_thread_step_trace().remaining
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_for_vm_remaining(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_trace_for_vm(vm_ptr).remaining
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_pc() -> u64 {
    crate::harness::debug::last_thread_step_trace().pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_for_vm_pc(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_trace_for_vm(vm_ptr).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_ra() -> u64 {
    crate::harness::debug::last_thread_step_trace().ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_for_vm_ra(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_trace_for_vm(vm_ptr).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_sp() -> u64 {
    crate::harness::debug::last_thread_step_trace().sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_for_vm_sp(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_trace_for_vm(vm_ptr).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_s11() -> u64 {
    crate::harness::debug::last_thread_step_trace().s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_for_vm_s11(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_trace_for_vm(vm_ptr).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase() -> u32 {
    crate::harness::debug::last_thread_step_phase().phase
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_vm_ptr() -> u32 {
    crate::harness::debug::last_thread_step_phase().vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_for_vm(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_thread_step_phase_for_vm(vm_ptr).phase
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_status() -> i32 {
    crate::harness::debug::last_thread_step_phase().status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_for_vm_status(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_phase_for_vm(vm_ptr).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_budget() -> i32 {
    crate::harness::debug::last_thread_step_phase().budget
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_for_vm_budget(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_phase_for_vm(vm_ptr).budget
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_remaining() -> i32 {
    crate::harness::debug::last_thread_step_phase().remaining
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_for_vm_remaining(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_thread_step_phase_for_vm(vm_ptr).remaining
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_pc() -> u64 {
    crate::harness::debug::last_thread_step_phase().pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_for_vm_pc(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_phase_for_vm(vm_ptr).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_ra() -> u64 {
    crate::harness::debug::last_thread_step_phase().ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_for_vm_ra(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_phase_for_vm(vm_ptr).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_sp() -> u64 {
    crate::harness::debug::last_thread_step_phase().sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_for_vm_sp(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_phase_for_vm(vm_ptr).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_s11() -> u64 {
    crate::harness::debug::last_thread_step_phase().s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_step_phase_for_vm_s11(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_thread_step_phase_for_vm(vm_ptr).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_dispatch_for_vm_phase(vm_ptr: u32) -> u32 {
    crate::harness::debug::last_fault_dispatch_trace_for_vm(vm_ptr).phase
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_dispatch_for_vm_tid(vm_ptr: u32) -> i32 {
    crate::harness::debug::last_fault_dispatch_trace_for_vm(vm_ptr).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_dispatch_for_vm_pc(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_fault_dispatch_trace_for_vm(vm_ptr).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_dispatch_for_vm_ra(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_fault_dispatch_trace_for_vm(vm_ptr).ra
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_dispatch_for_vm_sp(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_fault_dispatch_trace_for_vm(vm_ptr).sp
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_dispatch_for_vm_s11(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_fault_dispatch_trace_for_vm(vm_ptr).s11
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fault_dispatch_for_vm_addr(vm_ptr: u32) -> u64 {
    crate::harness::debug::last_fault_dispatch_trace_for_vm(vm_ptr).fault_addr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_brk_base() -> u64 {
    crate::harness::memory::debug_brk_base()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_brk_current() -> u64 {
    crate::harness::memory::current_brk()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_mmap_next() -> u64 {
    crate::harness::memory::debug_mmap_next()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_len() -> u32 {
    crate::harness::memory::debug_vma_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_start(index: u32) -> u64 {
    crate::harness::memory::debug_vma_start(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_end(index: u32) -> u64 {
    crate::harness::memory::debug_vma_end(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_prot(index: u32) -> i32 {
    crate::harness::memory::debug_vma_prot(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_flags(index: u32) -> i32 {
    crate::harness::memory::debug_vma_flags(index)
}
