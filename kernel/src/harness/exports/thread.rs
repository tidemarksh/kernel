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
pub extern "C" fn debug_clear_cpu_trace() {
    crate::harness::trace::clear_cpu_trace();
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_hits() -> u64 {
    crate::harness::debug::cpu_profile_block_hits()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_misses() -> u64 {
    crate::harness::debug::cpu_profile_block_misses()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_builds() -> u64 {
    crate::harness::debug::cpu_profile_block_builds()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_build_failures() -> u64 {
    crate::harness::debug::cpu_profile_block_build_failures()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_build_ops() -> u64 {
    crate::harness::debug::cpu_profile_block_build_ops()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_build_budget() -> u64 {
    crate::harness::debug::cpu_profile_block_build_budget()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_budget_skips() -> u64 {
    crate::harness::debug::cpu_profile_block_budget_skips()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_cache_unsupported() -> u64 {
    crate::harness::debug::cpu_profile_block_cache_unsupported()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_exec_ops() -> u64 {
    crate::harness::debug::cpu_profile_block_exec_ops()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_exec_unsupported() -> u64 {
    crate::harness::debug::cpu_profile_block_exec_unsupported()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_exec_op_sample_interval() -> u64 {
    crate::harness::debug::cpu_profile_block_exec_op_sample_interval()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_exec_sampled_blocks() -> u64 {
    crate::harness::debug::cpu_profile_block_exec_sampled_blocks()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_miss_sample_interval() -> u64 {
    crate::harness::debug::cpu_profile_block_miss_sample_interval()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_miss_sampled() -> u64 {
    crate::harness::debug::cpu_profile_block_miss_sampled()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_miss_sample_count() -> u32 {
    crate::harness::debug::cpu_profile_block_miss_sample_count()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_miss_sample_pc(index: u32) -> u64 {
    crate::harness::debug::cpu_profile_block_miss_sample_entry(index).pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_miss_sample_evicted_pc(index: u32) -> u64 {
    crate::harness::debug::cpu_profile_block_miss_sample_entry(index).evicted_pc
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_miss_sample_cache_index(index: u32) -> u32 {
    crate::harness::debug::cpu_profile_block_miss_sample_entry(index).index
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_miss_sample_count_at(index: u32) -> u64 {
    crate::harness::debug::cpu_profile_block_miss_sample_entry(index).count
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_interpreter_ops() -> u64 {
    crate::harness::debug::cpu_profile_interpreter_ops()
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_build_op_count(op_id: u32) -> u64 {
    crate::harness::debug::cpu_profile_block_build_op_count(op_id)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_block_exec_op_count(op_id: u32) -> u64 {
    crate::harness::debug::cpu_profile_block_exec_op_count(op_id)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_interpreter_op_count(op_id: u32) -> u64 {
    crate::harness::debug::cpu_profile_interpreter_op_count(op_id)
}

#[cfg(any(test, feature = "harness"))]
#[unsafe(no_mangle)]
pub extern "C" fn debug_cpu_profile_unsupported_op_count(op_id: u32) -> u64 {
    crate::harness::debug::cpu_profile_unsupported_op_count(op_id)
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
