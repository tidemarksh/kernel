#[cfg(any(test, all(target_arch = "wasm32", feature = "harness")))]
pub(crate) use crate::harness::debug::{
    guest_write_overlap_enabled, record_block_cache_budget_skip, record_block_cache_build,
    record_block_cache_build_failure, record_block_cache_build_op, record_block_cache_hit,
    record_block_cache_miss, record_block_cache_unsupported_op, record_block_exec_ops,
    record_block_exec_sample_start, record_block_exec_sampled_op, record_block_exec_unsupported_op,
    record_exec_trace, record_guest_write_overlap, record_interpreter_op, record_jalr,
    record_special_reg_transitions, record_zero_reg_transition,
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
    fn record_block_cache_hit() {}
    fn record_block_cache_miss(pc: u64, index: u32, evicted_pc: u64) {}
    fn record_block_cache_build(len: u32, budget: u32) {}
    fn record_block_cache_build_op(op_id: u32) {}
    fn record_block_cache_build_failure() {}
    fn record_block_cache_budget_skip() {}
    fn record_block_cache_unsupported_op(op_id: u32) {}
    fn record_block_exec_ops(count: u32) {}
    fn record_block_exec_sample_start() -> bool { false }
    fn record_block_exec_sampled_op(op_id: u32) {}
    fn record_block_exec_unsupported_op(op_id: u32) {}
    fn record_interpreter_op(op_id: u32) {}
    fn record_exec_trace(vm_ptr: u32, tid: i32, pc: u64, raw: u32, step: u64, x: &[u64; 32]) {}
    fn guest_write_overlap_enabled() -> bool { false }
    fn record_guest_write_overlap(addr: u64, len: u32, op: u32, sample: u64, sample_len: u32) {}
    fn record_jalr(vm_ptr: u32, pc: u64, rd: usize, rs1: usize, rs1_value: u64, target: u64) {}
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
