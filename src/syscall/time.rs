//! Time syscalls: clock_gettime, nanosleep, sched_yield.
//!
//! Struct layout (RV64):
//!
//! struct __kernel_timespec {        // 16 bytes total
//!     tv_sec:  i64,                 // offset 0
//!     tv_nsec: i64,                 // offset 8
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/time_types.h

use crate::abi;
use crate::guest_mem;
use crate::types::ThreadState;

/// clock_gettime: write timespec to guest memory.
/// In WASM we don't have a real clock. Return a monotonically increasing value
/// based on instruction count as a rough approximation.
pub fn sys_clock_gettime(_vm: &ThreadState, base: u32, _clk_id: u64, tp: u64) -> i64 {
    if tp == 0 { return crate::abi::EFAULT; }
    // Stub: return 0.0 for now. Runtime (TS) will provide real time via host import.
    unsafe {
        guest_mem::write_u64(base, tp, 0);     // tv_sec
        guest_mem::write_u64(base, tp + 8, 0); // tv_nsec
    }
    0
}

/// nanosleep: return STATUS_SLEEP so JS can setTimeout.
/// The sleep duration is in the timespec at `req` in guest memory.
/// Returns a blocking status — caller must NOT set a0.
pub fn sys_nanosleep(vm: &mut ThreadState, base: u32, req: u64, _rem: u64) -> i32 {
    if req != 0 {
        let sec = unsafe { guest_mem::read_u64(base, req) };
        let nsec = unsafe { guest_mem::read_u64(base, req + 8) };
        // Store sleep duration in fault_addr/fault_pc for JS to read
        vm.fault_addr = sec;
        vm.fault_pc = nsec;
    }
    vm.x[10] = 0; // return 0 on success
    vm.status = abi::STATUS_SLEEP;
    abi::STATUS_SLEEP
}
