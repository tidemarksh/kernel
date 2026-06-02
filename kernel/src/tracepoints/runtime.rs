#[cfg(any(test, all(any(target_arch = "wasm32", target_arch = "wasm64"), feature = "harness")))]
pub(crate) use crate::harness::trace::{
    record_fault_dispatch_trace, record_futex_resume_trace, record_sync_signal_trace,
    record_syscall, record_thread_count, record_thread_step_entry_trace, record_thread_step_phase,
    record_thread_step_trace, snapshot_recent_exec_trace_for_vm,
};

macro_rules! noop_tracepoint {
    ($(fn $name:ident($($arg:ident : $ty:ty),* $(,)?) $(-> $ret:ty)? $body:block)*) => {
        $(
            #[cfg(not(any(test, all(any(target_arch = "wasm32", target_arch = "wasm64"), feature = "harness"))))]
            #[inline(always)]
            pub(crate) fn $name($($arg: $ty),*) $(-> $ret)? {
                let _ = ($($arg),*);
                $body
            }
        )*
    };
}

noop_tracepoint! {
    fn record_fault_dispatch_trace(
        vm: &crate::types::ThreadState,
        phase: u32,
        pc: u64,
        ra: u64,
        sp: u64,
        s11: u64,
        fault_addr: u64,
    ) {}
    fn record_futex_resume_trace(vm: &crate::types::ThreadState, phase: u32) {}
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
    fn snapshot_recent_exec_trace_for_vm(vm_ptr: u32) {}
}
