pub(crate) mod fd {
    pub(crate) use crate::harness::trace::{
        fd_syscall_trace_entry, fd_syscall_trace_len, path_syscall_trace_entry,
        path_syscall_trace_len, path_syscall_trace_path_ptr,
    };
}

pub(crate) mod memory {
    pub(crate) use crate::harness::trace::{
        guest_write_overlap_trace_entry, guest_write_overlap_trace_len, memory_permit_cache_hits,
        memory_permit_cache_hits_by_prot, memory_permit_checks, memory_permit_checks_by_prot,
        memory_permit_cover_hits, memory_permit_cover_hits_by_prot, memory_permit_denied,
        memory_permit_denied_by_prot, memory_trace_entry, memory_trace_len, memory_trace_summary,
    };
}

pub(crate) mod process {
    pub(crate) use crate::harness::trace::{
        completed_sync_effects, execve_error_errno, execve_error_stage, execve_error_value0,
        execve_error_value1, execve_stage, execve_stage_trace_entry, execve_stage_trace_len,
        execve_value0, execve_value1, futex_trace_entry, futex_trace_len,
        riscv_syscall_trace_entry, riscv_syscall_trace_len, syscall_profile_slot_count,
        syscall_profile_slot_error_count, syscall_profile_slot_non_ok_status_count,
        syscall_trace_entry, syscall_trace_len, syscall_trace_summary,
    };
}

pub(crate) mod thread {
    pub(crate) use crate::harness::trace::{
        break_exec_trace_entry_for_vm, break_exec_trace_len_for_vm, clone_startup_trace_entry,
        clone_startup_trace_len, cpu_profile_block_budget_skips, cpu_profile_block_build_budget,
        cpu_profile_block_build_failures, cpu_profile_block_build_op_count,
        cpu_profile_block_build_ops, cpu_profile_block_builds, cpu_profile_block_cache_unsupported,
        cpu_profile_block_exec_op_count, cpu_profile_block_exec_op_sample_interval,
        cpu_profile_block_exec_ops, cpu_profile_block_exec_sampled_blocks,
        cpu_profile_block_exec_unsupported, cpu_profile_block_hits,
        cpu_profile_block_miss_sample_count, cpu_profile_block_miss_sample_entry,
        cpu_profile_block_miss_sample_interval, cpu_profile_block_miss_sampled,
        cpu_profile_block_misses, cpu_profile_interpreter_op_count, cpu_profile_interpreter_ops,
        cpu_profile_unsupported_op_count, exec_trace_entry, exec_trace_epoch_for_vm,
        exec_trace_len, fault_exec_trace_entry_for_vm, fault_exec_trace_len_for_vm,
        last_clone_jalr_trace, last_fault_dispatch_trace_for_vm, last_jalr_trace,
        last_jalr_trace_for_vm, last_s11_write_trace, last_s11_write_trace_for_vm,
        last_sp_write_trace, last_sp_write_trace_for_vm, last_thread_step_entry_trace_for_vm,
        last_thread_step_phase, last_thread_step_phase_for_vm, last_thread_step_trace,
        last_thread_step_trace_for_vm, last_zero_reg_trace, last_zero_reg_trace_for_vm,
        sync_fault_exec_trace_entry_for_vm, sync_fault_exec_trace_len_for_vm,
        thread_step_exec_trace_entry_for_vm, thread_step_exec_trace_len_for_vm,
        thread_step_trace_entry, thread_step_trace_len,
    };
}
