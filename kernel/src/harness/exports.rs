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
pub extern "C" fn thread_x27(vm_ptr: u32) -> u64 {
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
pub extern "C" fn debug_clear_write_trace() {
    crate::harness_debug::clear_write_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clear_syscall_trace() {
    crate::harness_debug::clear_syscall_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clear_memory_trace() {
    crate::harness_debug::clear_memory_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_write_calls() -> u32 {
    crate::harness_debug::write_trace_summary().write_calls
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_writev_calls() -> u32 {
    crate::harness_debug::write_trace_summary().writev_calls
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_fd() -> u64 {
    crate::harness_debug::write_trace_summary().last_fd
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_nr() -> u64 {
    crate::harness_debug::write_trace_summary().last_nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_buf_addr() -> u64 {
    crate::harness_debug::write_trace_summary().last_buf_addr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_count() -> u64 {
    crate::harness_debug::write_trace_summary().last_count
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_result() -> i64 {
    crate::harness_debug::write_trace_summary().last_result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_ofd_id() -> u32 {
    crate::harness_debug::write_trace_summary().last_ofd_id
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_ofd_type() -> i32 {
    crate::harness_debug::write_trace_summary().last_ofd_type
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_ofd_ino() -> u32 {
    crate::harness_debug::write_trace_summary().last_ofd_ino
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_status_flags() -> i32 {
    crate::harness_debug::write_trace_summary().last_status_flags
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_pipe_read_open() -> i32 {
    crate::harness_debug::write_trace_summary().last_pipe_read_open
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_last_pipe_write_open() -> i32 {
    crate::harness_debug::write_trace_summary().last_pipe_write_open
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_ptr() -> u32 {
    crate::harness_debug::write_trace_ptr()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_write_trace_len() -> u32 {
    crate::harness_debug::write_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_pipe_read_open(slot: u32) -> i32 {
    crate::syscall::pipe::debug_read_open(slot)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_pipe_write_open(slot: u32) -> i32 {
    crate::syscall::pipe::debug_write_open(slot)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_last_pipe_close_slot() -> u32 {
    crate::harness_debug::pipe_close_trace_summary().pipe_idx
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_last_pipe_close_is_read_end() -> u32 {
    crate::harness_debug::pipe_close_trace_summary().is_read_end
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_last_pipe_close_ofd_id() -> u32 {
    crate::harness_debug::pipe_close_trace_summary().ofd_id
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_last_pipe_close_read_open() -> i32 {
    crate::harness_debug::pipe_close_trace_summary().read_open
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_last_pipe_close_write_open() -> i32 {
    crate::harness_debug::pipe_close_trace_summary().write_open
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_vm_ptr() -> u32 {
    crate::harness_debug::syscall_trace_summary().vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_nr() -> u64 {
    crate::harness_debug::syscall_trace_summary().nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_result() -> i64 {
    crate::harness_debug::syscall_trace_summary().result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_syscall_trace_status() -> i32 {
    crate::harness_debug::syscall_trace_summary().status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_completed_sync_effects() -> u32 {
    crate::harness_debug::completed_sync_effects()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_len() -> u32 {
    crate::harness_debug::fd_syscall_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_vm_ptr(index: u32) -> u32 {
    crate::harness_debug::fd_syscall_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_nr(index: u32) -> u64 {
    crate::harness_debug::fd_syscall_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg0(index: u32) -> u64 {
    crate::harness_debug::fd_syscall_trace_entry(index).arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg0_ofd_id(index: u32) -> u32 {
    crate::harness_debug::fd_syscall_trace_entry(index).arg0_ofd_id
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg0_ofd_type(index: u32) -> i32 {
    crate::harness_debug::fd_syscall_trace_entry(index).arg0_ofd_type
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg1(index: u32) -> u64 {
    crate::harness_debug::fd_syscall_trace_entry(index).arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg2(index: u32) -> u64 {
    crate::harness_debug::fd_syscall_trace_entry(index).arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg2_ofd_id(index: u32) -> u32 {
    crate::harness_debug::fd_syscall_trace_entry(index).arg2_ofd_id
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg2_ofd_type(index: u32) -> i32 {
    crate::harness_debug::fd_syscall_trace_entry(index).arg2_ofd_type
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_arg3(index: u32) -> u64 {
    crate::harness_debug::fd_syscall_trace_entry(index).arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_result(index: u32) -> i64 {
    crate::harness_debug::fd_syscall_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_fd_syscall_trace_status(index: u32) -> i32 {
    crate::harness_debug::fd_syscall_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_len() -> u32 {
    crate::harness_debug::path_syscall_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_vm_ptr(index: u32) -> u32 {
    crate::harness_debug::path_syscall_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_nr(index: u32) -> u64 {
    crate::harness_debug::path_syscall_trace_entry(index).nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_dirfd(index: u32) -> i64 {
    crate::harness_debug::path_syscall_trace_entry(index).dirfd
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_result(index: u32) -> i64 {
    crate::harness_debug::path_syscall_trace_entry(index).result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_status(index: u32) -> i32 {
    crate::harness_debug::path_syscall_trace_entry(index).status
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_path_ptr(index: u32) -> u32 {
    crate::harness_debug::path_syscall_trace_path_ptr(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_path_syscall_trace_path_len(index: u32) -> u32 {
    crate::harness_debug::path_syscall_trace_entry(index).path_len
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_count_trace_len() -> u32 {
    crate::harness_debug::thread_count_trace_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_count_trace_kind(index: u32) -> u32 {
    crate::harness_debug::thread_count_trace_entry(index).kind
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_count_trace_vm_ptr(index: u32) -> u32 {
    crate::harness_debug::thread_count_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_count_trace_tid(index: u32) -> i32 {
    crate::harness_debug::thread_count_trace_entry(index).tid
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_count_trace_process_ptr(index: u32) -> u32 {
    crate::harness_debug::thread_count_trace_entry(index).process_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_count_trace_before(index: u32) -> u32 {
    crate::harness_debug::thread_count_trace_entry(index).before
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_thread_count_trace_after(index: u32) -> u32 {
    crate::harness_debug::thread_count_trace_entry(index).after
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_nr() -> u64 {
    crate::harness_debug::memory_trace_summary().nr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg0() -> u64 {
    crate::harness_debug::memory_trace_summary().arg0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg1() -> u64 {
    crate::harness_debug::memory_trace_summary().arg1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg2() -> u64 {
    crate::harness_debug::memory_trace_summary().arg2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_arg3() -> u64 {
    crate::harness_debug::memory_trace_summary().arg3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_trace_result() -> i64 {
    crate::harness_debug::memory_trace_summary().result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_mem_last_addr() -> u64 {
    crate::guest_mem::last_access_addr()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_mem_last_len() -> u32 {
    crate::guest_mem::last_access_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_guest_mem_last_kind() -> u32 {
    crate::guest_mem::last_access_kind()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_sig() -> u32 {
    crate::syscall::signal::last_signal_delivery().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_frame_base() -> u64 {
    crate::syscall::signal::last_signal_delivery().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_pc() -> u64 {
    crate::syscall::signal::last_signal_delivery().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_ra() -> u64 {
    crate::syscall::signal::last_signal_delivery().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_sp() -> u64 {
    crate::syscall::signal::last_signal_delivery().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_delivery_x27() -> u64 {
    crate::syscall::signal::last_signal_delivery().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_frame_base() -> u64 {
    crate::syscall::signal::last_sigreturn().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_pc() -> u64 {
    crate::syscall::signal::last_sigreturn().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_ra() -> u64 {
    crate::syscall::signal::last_sigreturn().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_sp() -> u64 {
    crate::syscall::signal::last_sigreturn().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_x27() -> u64 {
    crate::syscall::signal::last_sigreturn().5
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
pub extern "C" fn debug_clone_spawn_sp() -> u64 {
    crate::syscall::thread::last_clone_spawn().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_clone_spawn_x27() -> u64 {
    crate::syscall::thread::last_clone_spawn().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_trampoline_hit_tid() -> i32 {
    crate::syscall::signal::last_trampoline_hit().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_signal_trampoline_hit_pc() -> u64 {
    crate::syscall::signal::last_trampoline_hit().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sigreturn_count() -> u32 {
    crate::syscall::signal::last_trampoline_hit().2
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
    crate::cpu::last_jalr_trace().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_pc() -> u64 {
    crate::cpu::last_zero_reg_trace().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_raw() -> u32 {
    crate::cpu::last_zero_reg_trace().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_index() -> u32 {
    crate::cpu::last_zero_reg_trace().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_prev_value() -> u64 {
    crate::cpu::last_zero_reg_trace().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_sp() -> u64 {
    crate::cpu::last_zero_reg_trace().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_zero_reg_x27() -> u64 {
    crate::cpu::last_zero_reg_trace().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_x27_write_pc() -> u64 {
    crate::cpu::last_x27_write_trace().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_x27_write_raw() -> u32 {
    crate::cpu::last_x27_write_trace().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_x27_write_source() -> u32 {
    crate::cpu::last_x27_write_trace().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_x27_write_prev_value() -> u64 {
    crate::cpu::last_x27_write_trace().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_x27_write_value() -> u64 {
    crate::cpu::last_x27_write_trace().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_tp_write_pc() -> u64 {
    crate::cpu::last_tp_write_trace().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_tp_write_raw() -> u32 {
    crate::cpu::last_tp_write_trace().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_tp_write_source() -> u32 {
    crate::cpu::last_tp_write_trace().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_tp_write_prev_value() -> u64 {
    crate::cpu::last_tp_write_trace().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_tp_write_value() -> u64 {
    crate::cpu::last_tp_write_trace().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_tp_write_rs1() -> u32 {
    crate::cpu::last_tp_write_trace().6
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_tp_write_rs1_value() -> u64 {
    crate::cpu::last_tp_write_trace().7
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_tp_write_tid() -> i32 {
    crate::cpu::last_tp_write_trace().0
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_pc() -> u64 {
    crate::cpu::last_sp_write_trace().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_raw() -> u32 {
    crate::cpu::last_sp_write_trace().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_source() -> u32 {
    crate::cpu::last_sp_write_trace().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_prev_value() -> u64 {
    crate::cpu::last_sp_write_trace().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_sp_write_value() -> u64 {
    crate::cpu::last_sp_write_trace().5
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_rs1_value() -> u64 {
    crate::cpu::last_jalr_trace().1
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_target() -> u64 {
    crate::cpu::last_jalr_trace().2
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_rd() -> u32 {
    crate::cpu::last_jalr_trace().3
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_jalr_rs1() -> u32 {
    crate::cpu::last_jalr_trace().4
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_stage() -> u32 {
    crate::harness_debug::execve_stage()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_value0() -> u64 {
    crate::harness_debug::execve_value0()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_execve_value1() -> u64 {
    crate::harness_debug::execve_value1()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_brk_base() -> u64 {
    crate::syscall::memory::debug_brk_base()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_brk_current() -> u64 {
    crate::syscall::memory::current_brk()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_mmap_next() -> u64 {
    crate::syscall::memory::debug_mmap_next()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_len() -> u32 {
    crate::syscall::memory::debug_vma_len()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_start(index: u32) -> u64 {
    crate::syscall::memory::debug_vma_start(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_end(index: u32) -> u64 {
    crate::syscall::memory::debug_vma_end(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_prot(index: u32) -> i32 {
    crate::syscall::memory::debug_vma_prot(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_memory_vma_flags(index: u32) -> i32 {
    crate::syscall::memory::debug_vma_flags(index)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_epoll_wait_epfd() -> u64 {
    crate::harness_debug::epoll_wait_trace().epfd
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_epoll_wait_ofd_id() -> u32 {
    crate::harness_debug::epoll_wait_trace().ofd_id
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_epoll_wait_ofd_type() -> i32 {
    crate::harness_debug::epoll_wait_trace().ofd_type
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_epoll_wait_idx() -> u32 {
    crate::harness_debug::epoll_wait_trace().epoll_idx
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_epoll_wait_ptr() -> u32 {
    crate::harness_debug::epoll_wait_trace().epoll_ptr
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_epoll_wait_count() -> u32 {
    crate::harness_debug::epoll_wait_trace().epoll_count
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_epoll_wait_result() -> i64 {
    crate::harness_debug::epoll_wait_trace().result
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_epoll_wait_reason() -> u32 {
    crate::harness_debug::epoll_wait_trace().reason
}
