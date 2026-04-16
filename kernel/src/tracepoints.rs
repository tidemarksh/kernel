//! Kernel tracepoints for harness/debug observation.
//!
//! Production code depends only on this private trace API. The tracepoint
//! implementation is selected by build mode: harness/test builds re-export the
//! harness recorder, while production builds compile no-op stubs.

#[cfg(any(test, all(target_arch = "wasm32", feature = "harness")))]
pub(crate) use crate::harness_debug::{
    record_epoll_wait, record_exec_trace, record_execve_approach, record_execve_dispatch,
    record_execve_ecall, record_execve_pre_dispatch, record_execve_stage,
    record_fault_dispatch_trace, record_fd_syscall, record_futex_resume_trace,
    record_guest_write_overlap, record_jalr, record_memory_syscall, record_path_syscall,
    record_pipe_close_event, record_special_reg_transitions, record_sync_signal_trace,
    record_syscall, record_thread_count, record_thread_step_entry_trace,
    record_thread_step_phase, record_thread_step_trace, record_write_attempt,
    record_zero_reg_transition,
};

macro_rules! noop_tracepoint {
    ($(fn $name:ident($($arg:ident : $ty:ty),* $(,)?) $(-> $ret:ty)? $body:block)*) => {
        $(
            #[cfg(not(any(test, all(target_arch = "wasm32", feature = "harness"))))]
            #[inline(always)]
            pub(crate) fn $name($($arg: $ty),*) $(-> $ret)? {
                let _ = ($($arg),*);
                $body
            }
        )*
    };
}

noop_tracepoint! {
    fn record_epoll_wait(
        vm_ptr: u32,
        epfd: u64,
        ofd_id: u32,
        ofd_type: i32,
        epoll_idx: u32,
        epoll_ptr: u32,
        epoll_count: u32,
        result: i64,
        reason: u32,
    ) {}
    fn record_exec_trace(vm_ptr: u32, tid: i32, pc: u64, raw: u32, step: u64, x: &[u64; 32]) {}
    fn record_execve_approach(vm_ptr: u32, pc: u64, raw: u32) {}
    fn record_execve_dispatch(vm_ptr: u32, stage: u32) {}
    fn record_execve_ecall(value0: u64, value1: u64) {}
    fn record_execve_pre_dispatch(pc: u64, raw: u32, value0: u64, value1: u64) {}
    fn record_execve_stage(stage: u32, value0: u64, value1: u64) {}
    fn record_fault_dispatch_trace(
        vm: &crate::types::ThreadState,
        phase: u32,
        pc: u64,
        ra: u64,
        sp: u64,
        s11: u64,
        fault_addr: u64,
    ) {}
    fn record_fd_syscall(
        vm_ptr: u32,
        nr: u64,
        arg0: u64,
        arg0_ofd_id: u32,
        arg0_ofd_type: i32,
        arg1: u64,
        arg2: u64,
        arg2_ofd_id: u32,
        arg2_ofd_type: i32,
        arg3: u64,
        result: i64,
        status: i32,
    ) {}
    fn record_futex_resume_trace(vm: &crate::types::ThreadState, phase: u32) {}
    fn record_guest_write_overlap(addr: u64, len: u32, op: u32, sample: u64, sample_len: u32) {}
    fn record_jalr(vm_ptr: u32, pc: u64, rd: usize, rs1: usize, rs1_value: u64, target: u64) {}
    fn record_memory_syscall(nr: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, result: i64) {}
    fn record_path_syscall(vm_ptr: u32, nr: u64, dirfd: i64, path: &[u8], result: i64, status: i32) {}
    fn record_pipe_close_event(
        pipe_idx: u32,
        is_read_end: bool,
        ofd_id: u32,
        read_open: i32,
        write_open: i32,
    ) {}
    fn record_special_reg_transitions(
        vm_ptr: u32,
        tid: i32,
        pc: u64,
        raw: u32,
        source: u32,
        prev_sp: u64,
        prev_tp: u64,
        prev_s11: u64,
        x: &[u64; 32],
    ) {}
    fn record_sync_signal_trace(
        vm: &crate::types::ThreadState,
        local_pc: u64,
        local_ra: u64,
        local_sp: u64,
        local_s11: u64,
        local_a0: u64,
        fault_addr: u64,
    ) {}
    fn record_syscall(
        vm_ptr: u32,
        nr: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        result: i64,
        status: i32,
    ) {}
    fn record_thread_count(kind: u32, vm_ptr: u32, tid: i32, process_ptr: u32, before: u32, after: u32) {}
    fn record_thread_step_entry_trace(vm: &crate::types::ThreadState, budget: i32) {}
    fn record_thread_step_phase(vm: &crate::types::ThreadState, phase: u32, budget: i32, remaining: i32) {}
    fn record_thread_step_trace(vm: &crate::types::ThreadState, budget: i32, remaining: i32) {}
    fn record_write_attempt(
        fd: u64,
        nr: u64,
        buf_addr: u64,
        count: u64,
        result: i64,
        ofd_id: u32,
        ofd_type: i32,
        ofd_ino: u32,
        status_flags: i32,
        pipe_read_open: i32,
        pipe_write_open: i32,
        bytes: Option<&[u8]>,
    ) {}
    fn record_zero_reg_transition(
        vm_ptr: u32,
        tid: i32,
        pc: u64,
        raw: u32,
        prev_sp: u64,
        prev_s11: u64,
        x: &[u64; 32],
    ) {}
}
