#[cfg(any(test, all(target_arch = "wasm32", feature = "harness")))]
pub(crate) use crate::harness::debug::{
    record_execve_approach, record_execve_dispatch, record_execve_ecall, record_execve_error,
    record_execve_pre_dispatch, record_execve_stage,
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
    fn record_execve_approach(vm_ptr: u32, pc: u64, raw: u32) {}
    fn record_execve_dispatch(vm_ptr: u32, stage: u32) {}
    fn record_execve_ecall(value0: u64, value1: u64) {}
    fn record_execve_error(errno: i64) {}
    fn record_execve_pre_dispatch(pc: u64, raw: u32, value0: u64, value1: u64) {}
    fn record_execve_stage(stage: u32, value0: u64, value1: u64) {}
}
