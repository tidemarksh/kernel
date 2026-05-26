use super::RUNTIME_DEBUG_ENABLED;

const CPU_PROFILE_OP_SLOTS: usize = 32;
const CPU_PROFILE_BLOCK_EXEC_OP_SAMPLE_INTERVAL: u64 = 1024;
const CPU_PROFILE_BLOCK_MISS_SAMPLE_INTERVAL: u64 = 1024;
const CPU_PROFILE_BLOCK_MISS_SAMPLE_CAP: usize = 64;

static mut CPU_PROFILE_BLOCK_HITS: u64 = 0;
static mut CPU_PROFILE_BLOCK_MISSES: u64 = 0;
static mut CPU_PROFILE_BLOCK_BUILDS: u64 = 0;
static mut CPU_PROFILE_BLOCK_BUILD_FAILURES: u64 = 0;
static mut CPU_PROFILE_BLOCK_BUILD_OPS: u64 = 0;
static mut CPU_PROFILE_BLOCK_BUILD_BUDGET: u64 = 0;
static mut CPU_PROFILE_BLOCK_BUDGET_SKIPS: u64 = 0;
static mut CPU_PROFILE_BLOCK_CACHE_UNSUPPORTED: u64 = 0;
static mut CPU_PROFILE_BLOCK_EXEC_OPS: u64 = 0;
static mut CPU_PROFILE_BLOCK_EXEC_UNSUPPORTED: u64 = 0;
static mut CPU_PROFILE_BLOCK_EXEC_SAMPLE_TICKS: u64 = 0;
static mut CPU_PROFILE_BLOCK_EXEC_SAMPLED_BLOCKS: u64 = 0;
static mut CPU_PROFILE_BLOCK_MISS_SAMPLE_TICKS: u64 = 0;
static mut CPU_PROFILE_BLOCK_MISS_SAMPLED: u64 = 0;
static mut CPU_PROFILE_INTERPRETER_OPS: u64 = 0;
static mut CPU_PROFILE_BLOCK_BUILD_OP_COUNTS: [u64; CPU_PROFILE_OP_SLOTS] =
    [0; CPU_PROFILE_OP_SLOTS];
static mut CPU_PROFILE_BLOCK_EXEC_OP_COUNTS: [u64; CPU_PROFILE_OP_SLOTS] =
    [0; CPU_PROFILE_OP_SLOTS];
static mut CPU_PROFILE_INTERPRETER_OP_COUNTS: [u64; CPU_PROFILE_OP_SLOTS] =
    [0; CPU_PROFILE_OP_SLOTS];
static mut CPU_PROFILE_UNSUPPORTED_OP_COUNTS: [u64; CPU_PROFILE_OP_SLOTS] =
    [0; CPU_PROFILE_OP_SLOTS];
static mut CPU_PROFILE_BLOCK_MISS_SAMPLES: [BlockMissSample; CPU_PROFILE_BLOCK_MISS_SAMPLE_CAP] =
    [BlockMissSample {
        pc: 0,
        evicted_pc: 0,
        count: 0,
        index: 0,
    }; CPU_PROFILE_BLOCK_MISS_SAMPLE_CAP];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockMissSample {
    pub pc: u64,
    pub evicted_pc: u64,
    pub count: u64,
    pub index: u32,
}

#[inline(always)]
fn cpu_profile_slot(op_id: u32) -> Option<usize> {
    if (op_id as usize) < CPU_PROFILE_OP_SLOTS {
        Some(op_id as usize)
    } else {
        None
    }
}

#[inline(always)]
unsafe fn cpu_profile_add(ptr: *mut u64, delta: u64) {
    unsafe {
        let value = core::ptr::read(ptr);
        core::ptr::write(ptr, value.wrapping_add(delta));
    }
}

#[inline(always)]
unsafe fn cpu_profile_add_op_count(ptr: *mut [u64; CPU_PROFILE_OP_SLOTS], op_id: u32) {
    if let Some(slot) = cpu_profile_slot(op_id) {
        unsafe {
            let slot_ptr = core::ptr::addr_of_mut!((*ptr)[slot]);
            cpu_profile_add(slot_ptr, 1);
        }
    }
}

pub(crate) fn record_block_cache_hit() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe { cpu_profile_add(core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_HITS), 1) }
}

pub(crate) fn record_block_cache_miss(pc: u64, index: u32, evicted_pc: u64) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (pc, index, evicted_pc);
        return;
    }
    unsafe {
        cpu_profile_add(core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_MISSES), 1);
        let ticks = core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_MISS_SAMPLE_TICKS))
            .wrapping_add(1);
        core::ptr::write(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_MISS_SAMPLE_TICKS),
            ticks,
        );
        if ticks % CPU_PROFILE_BLOCK_MISS_SAMPLE_INTERVAL != 0 {
            return;
        }
        cpu_profile_add(core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_MISS_SAMPLED), 1);

        let samples = core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_MISS_SAMPLES);
        let mut empty_slot = CPU_PROFILE_BLOCK_MISS_SAMPLE_CAP;
        let mut min_slot = 0usize;
        let mut min_count = u64::MAX;
        for slot in 0..CPU_PROFILE_BLOCK_MISS_SAMPLE_CAP {
            let entry = core::ptr::read(core::ptr::addr_of!((*samples)[slot]));
            if entry.count != 0 && entry.pc == pc && entry.index == index {
                let entry_ptr = core::ptr::addr_of_mut!((*samples)[slot]);
                core::ptr::write(
                    entry_ptr,
                    BlockMissSample {
                        count: entry.count.wrapping_add(1),
                        evicted_pc,
                        ..entry
                    },
                );
                return;
            }
            if entry.count == 0 && empty_slot == CPU_PROFILE_BLOCK_MISS_SAMPLE_CAP {
                empty_slot = slot;
            }
            if entry.count < min_count {
                min_count = entry.count;
                min_slot = slot;
            }
        }
        let slot = if empty_slot < CPU_PROFILE_BLOCK_MISS_SAMPLE_CAP {
            empty_slot
        } else {
            min_slot
        };
        core::ptr::write(
            core::ptr::addr_of_mut!((*samples)[slot]),
            BlockMissSample {
                pc,
                evicted_pc,
                count: 1,
                index,
            },
        );
    }
}

pub(crate) fn record_block_cache_build(len: u32, budget: u32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (len, budget);
        return;
    }
    unsafe {
        cpu_profile_add(core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_BUILDS), 1);
        cpu_profile_add(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_BUILD_OPS),
            len as u64,
        );
        cpu_profile_add(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_BUILD_BUDGET),
            budget as u64,
        );
    }
}

pub(crate) fn record_block_cache_build_op(op_id: u32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = op_id;
        return;
    }
    unsafe {
        cpu_profile_add_op_count(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_BUILD_OP_COUNTS),
            op_id,
        );
    }
}

pub(crate) fn record_block_cache_build_failure() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        cpu_profile_add(core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_BUILD_FAILURES), 1);
    }
}

pub(crate) fn record_block_cache_budget_skip() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe { cpu_profile_add(core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_BUDGET_SKIPS), 1) }
}

pub(crate) fn record_block_cache_unsupported_op(op_id: u32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = op_id;
        return;
    }
    unsafe {
        cpu_profile_add(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_CACHE_UNSUPPORTED),
            1,
        );
        cpu_profile_add_op_count(
            core::ptr::addr_of_mut!(CPU_PROFILE_UNSUPPORTED_OP_COUNTS),
            op_id,
        );
    }
}

pub(crate) fn record_block_exec_ops(count: u32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = count;
        return;
    }
    unsafe {
        cpu_profile_add(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_EXEC_OPS),
            count as u64,
        );
    }
}

pub(crate) fn record_block_exec_sample_start() -> bool {
    if !RUNTIME_DEBUG_ENABLED {
        return false;
    }
    unsafe {
        let next = core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_EXEC_SAMPLE_TICKS))
            .wrapping_add(1);
        core::ptr::write(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_EXEC_SAMPLE_TICKS),
            next,
        );
        if next % CPU_PROFILE_BLOCK_EXEC_OP_SAMPLE_INTERVAL != 0 {
            return false;
        }
        cpu_profile_add(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_EXEC_SAMPLED_BLOCKS),
            1,
        );
        true
    }
}

pub(crate) fn record_block_exec_sampled_op(op_id: u32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = op_id;
        return;
    }
    unsafe {
        cpu_profile_add_op_count(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_EXEC_OP_COUNTS),
            op_id,
        );
    }
}

pub(crate) fn record_block_exec_unsupported_op(op_id: u32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = op_id;
        return;
    }
    unsafe {
        cpu_profile_add(
            core::ptr::addr_of_mut!(CPU_PROFILE_BLOCK_EXEC_UNSUPPORTED),
            1,
        );
        cpu_profile_add_op_count(
            core::ptr::addr_of_mut!(CPU_PROFILE_UNSUPPORTED_OP_COUNTS),
            op_id,
        );
    }
}

pub(crate) fn record_interpreter_op(op_id: u32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = op_id;
        return;
    }
    unsafe {
        cpu_profile_add(core::ptr::addr_of_mut!(CPU_PROFILE_INTERPRETER_OPS), 1);
        cpu_profile_add_op_count(
            core::ptr::addr_of_mut!(CPU_PROFILE_INTERPRETER_OP_COUNTS),
            op_id,
        );
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_hits() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_HITS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_misses() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_MISSES)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_builds() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_BUILDS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_build_failures() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_BUILD_FAILURES)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_build_ops() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_BUILD_OPS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_build_budget() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_BUILD_BUDGET)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_budget_skips() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_BUDGET_SKIPS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_cache_unsupported() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_CACHE_UNSUPPORTED)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_exec_ops() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_EXEC_OPS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_exec_unsupported() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_EXEC_UNSUPPORTED)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_exec_op_sample_interval() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    CPU_PROFILE_BLOCK_EXEC_OP_SAMPLE_INTERVAL
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_exec_sampled_blocks() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_EXEC_SAMPLED_BLOCKS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_miss_sample_interval() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    CPU_PROFILE_BLOCK_MISS_SAMPLE_INTERVAL
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_miss_sampled() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_MISS_SAMPLED)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_miss_sample_count() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    let mut count = 0u32;
    unsafe {
        for slot in 0..CPU_PROFILE_BLOCK_MISS_SAMPLE_CAP {
            let entry = core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_MISS_SAMPLES[slot]));
            if entry.count != 0 {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_miss_sample_entry(index: u32) -> BlockMissSample {
    if !RUNTIME_DEBUG_ENABLED {
        return BlockMissSample {
            pc: 0,
            evicted_pc: 0,
            count: 0,
            index: 0,
        };
    }
    let mut seen = 0u32;
    unsafe {
        for slot in 0..CPU_PROFILE_BLOCK_MISS_SAMPLE_CAP {
            let entry = core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_MISS_SAMPLES[slot]));
            if entry.count == 0 {
                continue;
            }
            if seen == index {
                return entry;
            }
            seen = seen.saturating_add(1);
        }
    }
    BlockMissSample {
        pc: 0,
        evicted_pc: 0,
        count: 0,
        index: 0,
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_interpreter_ops() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_INTERPRETER_OPS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_build_op_count(op_id: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    let Some(slot) = cpu_profile_slot(op_id) else {
        return 0;
    };
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_BUILD_OP_COUNTS[slot])) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_block_exec_op_count(op_id: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    let Some(slot) = cpu_profile_slot(op_id) else {
        return 0;
    };
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_BLOCK_EXEC_OP_COUNTS[slot])) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_interpreter_op_count(op_id: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    let Some(slot) = cpu_profile_slot(op_id) else {
        return 0;
    };
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_INTERPRETER_OP_COUNTS[slot])) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn cpu_profile_unsupported_op_count(op_id: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    let Some(slot) = cpu_profile_slot(op_id) else {
        return 0;
    };
    unsafe { core::ptr::read(core::ptr::addr_of!(CPU_PROFILE_UNSUPPORTED_OP_COUNTS[slot])) }
}

pub(crate) fn record_thread_count(
    kind: u32,
    vm_ptr: u32,
    tid: i32,
    process_ptr: u32,
    before: u32,
    after: u32,
) {
    let _ = (kind, vm_ptr, tid, process_ptr, before, after);
}

pub(crate) fn record_futex_resume_trace(vm: &crate::types::ThreadState, phase: u32) {
    let _ = (vm, phase);
}
