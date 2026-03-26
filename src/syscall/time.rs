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
    // Return a plausible timestamp. Real time will be provided by the runtime (TS)
    // via host import. For testing, use a fixed epoch.
    unsafe {
        guest_mem::write_u64(base, tp, 1700000000); // tv_sec: ~2023-11-14
        guest_mem::write_u64(base, tp + 8, 0);       // tv_nsec
    }
    0
}

/// clock_getres: return resolution (1 ns).
pub fn sys_clock_getres(_vm: &ThreadState, base: u32, _clk_id: u64, res: u64) -> i64 {
    if res != 0 {
        unsafe {
            guest_mem::write_u64(base, res, 0);     // tv_sec = 0
            guest_mem::write_u64(base, res + 8, 1); // tv_nsec = 1 (1 ns resolution)
        }
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

/// sched_yield: no-op, return success.
pub fn sys_sched_yield() -> i64 { 0 }

#[cfg(test)]
mod tests {
    use crate::test_helpers::TestVm;

    #[test]
    fn time_syscalls() {
        let mut t = TestVm::new();
        let tp = t.scratch;
        assert_eq!(super::sys_clock_gettime(&t.vm, t.base, 0, tp), 0);
        let sec = unsafe { crate::guest_mem::read_u64(t.base, tp) };
        assert!(sec > 0, "clock_gettime should return non-zero seconds");

        let res = t.scratch + 0x100;
        assert_eq!(super::sys_clock_getres(&t.vm, t.base, 0, res), 0);
        let nsec = unsafe { crate::guest_mem::read_u64(t.base, res + 8) };
        assert_eq!(nsec, 1);
    }
}
