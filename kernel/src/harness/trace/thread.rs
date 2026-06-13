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

const CPU_EXEC_TRACE_CAP: usize = 1024;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct JalrTraceSummary {
    pub vm_ptr: u32,
    pub pc: u64,
    pub rs1_value: u64,
    pub target: u64,
    pub rd: u32,
    pub rs1: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloneStartupTraceEntry {
    pub vm_ptr: u32,
    pub tid: i32,
    pub pc: u64,
    pub raw: u32,
    pub a0: u64,
    pub t1: u64,
    pub t2: u64,
    pub sp: u64,
    pub s11: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZeroRegTraceSummary {
    pub vm_ptr: u32,
    pub tid: i32,
    pub pc: u64,
    pub raw: u32,
    pub reg: u32,
    pub prev_value: u64,
    pub sp: u64,
    pub s11: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RegWriteTraceSummary {
    pub vm_ptr: u32,
    pub tid: i32,
    pub pc: u64,
    pub raw: u32,
    pub source: u32,
    pub prev_value: u64,
    pub value: u64,
    pub rs1: u32,
    pub rs1_value: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecTraceEntry {
    pub vm_ptr: u32,
    pub epoch: u32,
    pub tid: i32,
    pub pc: u64,
    pub raw: u32,
    pub step: u32,
    pub sp: u64,
    pub ra: u64,
    pub a0: u64,
    pub a4: u64,
    pub a5: u64,
    pub s11: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadStepTraceSummary {
    pub vm_ptr: u32,
    pub tid: i32,
    pub status: i32,
    pub budget: i32,
    pub remaining: i32,
    pub pc: u64,
    pub ra: u64,
    pub sp: u64,
    pub s11: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadStepEntryTraceSummary {
    pub vm_ptr: u32,
    pub tid: i32,
    pub status: i32,
    pub budget: i32,
    pub pc: u64,
    pub ra: u64,
    pub sp: u64,
    pub s11: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadStepPhaseSummary {
    pub vm_ptr: u32,
    pub tid: i32,
    pub phase: u32,
    pub status: i32,
    pub budget: i32,
    pub remaining: i32,
    pub pc: u64,
    pub ra: u64,
    pub sp: u64,
    pub s11: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FaultDispatchTraceSummary {
    pub vm_ptr: u32,
    pub tid: i32,
    pub phase: u32,
    pub pc: u64,
    pub ra: u64,
    pub sp: u64,
    pub s11: u64,
    pub fault_addr: u64,
}

static mut LAST_JALR_TRACE: JalrTraceSummary = JalrTraceSummary {
    vm_ptr: 0,
    pc: 0,
    rs1_value: 0,
    target: 0,
    rd: 0,
    rs1: 0,
};

static mut LAST_CLONE_JALR_TRACE: JalrTraceSummary = JalrTraceSummary {
    vm_ptr: 0,
    pc: 0,
    rs1_value: 0,
    target: 0,
    rd: 0,
    rs1: 0,
};
const CLONE_STARTUP_TRACE_CAP: usize = 8;
static mut CLONE_STARTUP_TRACE_RING: [CloneStartupTraceEntry; CLONE_STARTUP_TRACE_CAP] =
    [CloneStartupTraceEntry {
        vm_ptr: 0,
        tid: 0,
        pc: 0,
        raw: 0,
        a0: 0,
        t1: 0,
        t2: 0,
        sp: 0,
        s11: 0,
    }; CLONE_STARTUP_TRACE_CAP];
static mut CLONE_STARTUP_TRACE_LEN: u32 = 0;
static mut CLONE_STARTUP_TRACE_NEXT: u32 = 0;

static mut LAST_ZERO_REG_TRACE: ZeroRegTraceSummary = ZeroRegTraceSummary {
    vm_ptr: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    reg: 0,
    prev_value: 0,
    sp: 0,
    s11: 0,
};

static mut LAST_S11_WRITE_TRACE: RegWriteTraceSummary = RegWriteTraceSummary {
    vm_ptr: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    source: 0,
    prev_value: 0,
    value: 0,
    rs1: 0,
    rs1_value: 0,
};

static mut LAST_SP_WRITE_TRACE: RegWriteTraceSummary = RegWriteTraceSummary {
    vm_ptr: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    source: 0,
    prev_value: 0,
    value: 0,
    rs1: 0,
    rs1_value: 0,
};

const CPU_REG_TRACE_CAP: usize = 64;

static mut JALR_TRACE_RING: [JalrTraceSummary; CPU_REG_TRACE_CAP] = [JalrTraceSummary {
    vm_ptr: 0,
    pc: 0,
    rs1_value: 0,
    target: 0,
    rd: 0,
    rs1: 0,
}; CPU_REG_TRACE_CAP];
static mut JALR_TRACE_LEN: u32 = 0;
static mut JALR_TRACE_NEXT: u32 = 0;

static mut ZERO_REG_TRACE_RING: [ZeroRegTraceSummary; CPU_REG_TRACE_CAP] = [ZeroRegTraceSummary {
    vm_ptr: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    reg: 0,
    prev_value: 0,
    sp: 0,
    s11: 0,
}; CPU_REG_TRACE_CAP];
static mut ZERO_REG_TRACE_LEN: u32 = 0;
static mut ZERO_REG_TRACE_NEXT: u32 = 0;

static mut S11_WRITE_TRACE_RING: [RegWriteTraceSummary; CPU_REG_TRACE_CAP] =
    [RegWriteTraceSummary {
        vm_ptr: 0,
        tid: 0,
        pc: 0,
        raw: 0,
        source: 0,
        prev_value: 0,
        value: 0,
        rs1: 0,
        rs1_value: 0,
    }; CPU_REG_TRACE_CAP];
static mut S11_WRITE_TRACE_LEN: u32 = 0;
static mut S11_WRITE_TRACE_NEXT: u32 = 0;

static mut SP_WRITE_TRACE_RING: [RegWriteTraceSummary; CPU_REG_TRACE_CAP] = [RegWriteTraceSummary {
    vm_ptr: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    source: 0,
    prev_value: 0,
    value: 0,
    rs1: 0,
    rs1_value: 0,
}; CPU_REG_TRACE_CAP];
static mut SP_WRITE_TRACE_LEN: u32 = 0;
static mut SP_WRITE_TRACE_NEXT: u32 = 0;

static mut EXEC_TRACE_RING: [ExecTraceEntry; CPU_EXEC_TRACE_CAP] = [ExecTraceEntry {
    vm_ptr: 0,
    epoch: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    step: 0,
    sp: 0,
    ra: 0,
    a0: 0,
    a4: 0,
    a5: 0,
    s11: 0,
}; CPU_EXEC_TRACE_CAP];
static mut EXEC_TRACE_RING_LEN: u32 = 0;
static mut EXEC_TRACE_RING_NEXT: u32 = 0;
static mut EXEC_TRACE_EPOCH_BY_VM: [(u32, u32); THREAD_STEP_VM_TRACE_CAP] =
    [(0, 0); THREAD_STEP_VM_TRACE_CAP];
static mut EXEC_TRACE_EPOCH_BY_VM_NEXT: u32 = 0;
const FAULT_EXEC_TRACE_CAP: usize = 64;
static mut LAST_FAULT_EXEC_TRACE_VM_PTR: u32 = 0;
static mut LAST_FAULT_EXEC_TRACE_EPOCH: u32 = 0;
static mut LAST_FAULT_EXEC_TRACE: [ExecTraceEntry; FAULT_EXEC_TRACE_CAP] = [ExecTraceEntry {
    vm_ptr: 0,
    epoch: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    step: 0,
    sp: 0,
    ra: 0,
    a0: 0,
    a4: 0,
    a5: 0,
    s11: 0,
}; FAULT_EXEC_TRACE_CAP];
static mut LAST_FAULT_EXEC_TRACE_LEN: u32 = 0;
static mut LAST_SYNC_FAULT_EXEC_TRACE_VM_PTR: u32 = 0;
static mut LAST_SYNC_FAULT_EXEC_TRACE_EPOCH: u32 = 0;
static mut LAST_SYNC_FAULT_EXEC_TRACE: [ExecTraceEntry; FAULT_EXEC_TRACE_CAP] = [ExecTraceEntry {
    vm_ptr: 0,
    epoch: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    step: 0,
    sp: 0,
    ra: 0,
    a0: 0,
    a4: 0,
    a5: 0,
    s11: 0,
};
    FAULT_EXEC_TRACE_CAP];
static mut LAST_SYNC_FAULT_EXEC_TRACE_LEN: u32 = 0;
static mut LAST_THREAD_STEP_EXEC_TRACE_VM_PTR: u32 = 0;
static mut LAST_THREAD_STEP_EXEC_TRACE_EPOCH: u32 = 0;
static mut LAST_THREAD_STEP_EXEC_TRACE: [ExecTraceEntry; FAULT_EXEC_TRACE_CAP] = [ExecTraceEntry {
    vm_ptr: 0,
    epoch: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    step: 0,
    sp: 0,
    ra: 0,
    a0: 0,
    a4: 0,
    a5: 0,
    s11: 0,
};
    FAULT_EXEC_TRACE_CAP];
static mut LAST_THREAD_STEP_EXEC_TRACE_LEN: u32 = 0;
static mut LAST_BREAK_EXEC_TRACE_VM_PTR: u32 = 0;
static mut LAST_BREAK_EXEC_TRACE_EPOCH: u32 = 0;
static mut LAST_BREAK_EXEC_TRACE: [ExecTraceEntry; FAULT_EXEC_TRACE_CAP] = [ExecTraceEntry {
    vm_ptr: 0,
    epoch: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    step: 0,
    sp: 0,
    ra: 0,
    a0: 0,
    a4: 0,
    a5: 0,
    s11: 0,
}; FAULT_EXEC_TRACE_CAP];
static mut LAST_BREAK_EXEC_TRACE_LEN: u32 = 0;

static mut LAST_THREAD_STEP_TRACE: ThreadStepTraceSummary = ThreadStepTraceSummary {
    vm_ptr: 0,
    tid: 0,
    status: 0,
    budget: 0,
    remaining: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    s11: 0,
};
static mut LAST_THREAD_STEP_ENTRY_TRACE: ThreadStepEntryTraceSummary =
    ThreadStepEntryTraceSummary {
        vm_ptr: 0,
        tid: 0,
        status: 0,
        budget: 0,
        pc: 0,
        ra: 0,
        sp: 0,
        s11: 0,
    };
static mut LAST_THREAD_STEP_PHASE: ThreadStepPhaseSummary = ThreadStepPhaseSummary {
    vm_ptr: 0,
    tid: 0,
    phase: 0,
    status: 0,
    budget: 0,
    remaining: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    s11: 0,
};
const THREAD_STEP_VM_TRACE_CAP: usize = 16;
pub(crate) const THREAD_STEP_TRACE_CAP: usize = 64;
static mut THREAD_STEP_TRACE_BY_VM: [ThreadStepTraceSummary; THREAD_STEP_VM_TRACE_CAP] =
    [ThreadStepTraceSummary {
        vm_ptr: 0,
        tid: 0,
        status: 0,
        budget: 0,
        remaining: 0,
        pc: 0,
        ra: 0,
        sp: 0,
        s11: 0,
    }; THREAD_STEP_VM_TRACE_CAP];
static mut THREAD_STEP_TRACE_BY_VM_NEXT: u32 = 0;
static mut THREAD_STEP_TRACE_RING: [ThreadStepTraceSummary; THREAD_STEP_TRACE_CAP] =
    [ThreadStepTraceSummary {
        vm_ptr: 0,
        tid: 0,
        status: 0,
        budget: 0,
        remaining: 0,
        pc: 0,
        ra: 0,
        sp: 0,
        s11: 0,
    }; THREAD_STEP_TRACE_CAP];
static mut THREAD_STEP_TRACE_LEN: u32 = 0;
static mut THREAD_STEP_TRACE_NEXT: u32 = 0;
static mut THREAD_STEP_ENTRY_TRACE_BY_VM: [ThreadStepEntryTraceSummary; THREAD_STEP_VM_TRACE_CAP] =
    [ThreadStepEntryTraceSummary {
        vm_ptr: 0,
        tid: 0,
        status: 0,
        budget: 0,
        pc: 0,
        ra: 0,
        sp: 0,
        s11: 0,
    }; THREAD_STEP_VM_TRACE_CAP];
static mut THREAD_STEP_ENTRY_TRACE_BY_VM_NEXT: u32 = 0;
static mut THREAD_STEP_ENTRY_TRACE_RING: [ThreadStepEntryTraceSummary; THREAD_STEP_TRACE_CAP] =
    [ThreadStepEntryTraceSummary {
        vm_ptr: 0,
        tid: 0,
        status: 0,
        budget: 0,
        pc: 0,
        ra: 0,
        sp: 0,
        s11: 0,
    }; THREAD_STEP_TRACE_CAP];
static mut THREAD_STEP_ENTRY_TRACE_LEN: u32 = 0;
static mut THREAD_STEP_ENTRY_TRACE_NEXT: u32 = 0;
static mut THREAD_STEP_PHASE_BY_VM: [ThreadStepPhaseSummary; THREAD_STEP_VM_TRACE_CAP] =
    [ThreadStepPhaseSummary {
        vm_ptr: 0,
        tid: 0,
        phase: 0,
        status: 0,
        budget: 0,
        remaining: 0,
        pc: 0,
        ra: 0,
        sp: 0,
        s11: 0,
    }; THREAD_STEP_VM_TRACE_CAP];
static mut THREAD_STEP_PHASE_BY_VM_NEXT: u32 = 0;

static mut LAST_FAULT_DISPATCH_TRACE: FaultDispatchTraceSummary = FaultDispatchTraceSummary {
    vm_ptr: 0,
    tid: 0,
    phase: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    s11: 0,
    fault_addr: 0,
};

fn current_exec_trace_epoch_for_vm(vm_ptr: u32) -> u32 {
    if vm_ptr == 0 {
        return 0;
    }
    unsafe {
        let next = (EXEC_TRACE_EPOCH_BY_VM_NEXT as usize) % THREAD_STEP_VM_TRACE_CAP;
        for offset in 0..THREAD_STEP_VM_TRACE_CAP {
            let index = (next + THREAD_STEP_VM_TRACE_CAP - 1 - offset) % THREAD_STEP_VM_TRACE_CAP;
            let entry = EXEC_TRACE_EPOCH_BY_VM[index];
            if entry.0 == vm_ptr {
                return entry.1;
            }
        }
    }
    0
}

fn bump_exec_trace_epoch_for_vm(vm_ptr: u32) -> u32 {
    if vm_ptr == 0 {
        return 0;
    }
    unsafe {
        let next_epoch = current_exec_trace_epoch_for_vm(vm_ptr)
            .wrapping_add(1)
            .max(1);
        let slot = (EXEC_TRACE_EPOCH_BY_VM_NEXT as usize) % THREAD_STEP_VM_TRACE_CAP;
        EXEC_TRACE_EPOCH_BY_VM[slot] = (vm_ptr, next_epoch);
        EXEC_TRACE_EPOCH_BY_VM_NEXT = EXEC_TRACE_EPOCH_BY_VM_NEXT.wrapping_add(1);
        next_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_exec_trace_epoch_uses_ring_recency_after_wrap() {
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!(EXEC_TRACE_EPOCH_BY_VM),
                [(0, 0); THREAD_STEP_VM_TRACE_CAP],
            );
            core::ptr::write(core::ptr::addr_of_mut!(EXEC_TRACE_EPOCH_BY_VM_NEXT), 1);
            let entries = core::ptr::addr_of_mut!(EXEC_TRACE_EPOCH_BY_VM);
            core::ptr::write(core::ptr::addr_of_mut!((*entries)[0]), (42, 7));
            core::ptr::write(
                core::ptr::addr_of_mut!((*entries)[THREAD_STEP_VM_TRACE_CAP - 1]),
                (42, 3),
            );
        }

        assert_eq!(current_exec_trace_epoch_for_vm(42), 7);
    }
}

fn snapshot_fault_exec_trace_for_vm(vm_ptr: u32, epoch: u32) {
    unsafe {
        LAST_FAULT_EXEC_TRACE_VM_PTR = vm_ptr;
        LAST_FAULT_EXEC_TRACE_EPOCH = epoch;
        LAST_FAULT_EXEC_TRACE_LEN = 0;
        if vm_ptr == 0 || epoch == 0 {
            return;
        }
        let len = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_LEN)) as usize;
        if len == 0 {
            return;
        }
        let next = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_NEXT)) as usize;
        let start = len.saturating_sub(FAULT_EXEC_TRACE_CAP);
        let mut out = 0usize;
        for logical in start..len {
            let slot = if len < CPU_EXEC_TRACE_CAP {
                logical
            } else {
                (next + logical) % CPU_EXEC_TRACE_CAP
            };
            let entry = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING[slot]));
            if entry.vm_ptr != vm_ptr || entry.epoch != epoch {
                continue;
            }
            LAST_FAULT_EXEC_TRACE[out] = entry;
            out += 1;
            if out >= FAULT_EXEC_TRACE_CAP {
                break;
            }
        }
        LAST_FAULT_EXEC_TRACE_LEN = out as u32;
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn snapshot_recent_exec_trace_for_vm(vm_ptr: u32) {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        LAST_FAULT_EXEC_TRACE_VM_PTR = vm_ptr;
        LAST_FAULT_EXEC_TRACE_EPOCH = current_exec_trace_epoch_for_vm(vm_ptr);
        LAST_FAULT_EXEC_TRACE_LEN = 0;
        if vm_ptr == 0 {
            return;
        }
        let len = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_LEN)) as usize;
        if len == 0 {
            return;
        }
        let next = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_NEXT)) as usize;
        let start = len.saturating_sub(CPU_EXEC_TRACE_CAP);
        let mut out = 0usize;
        for logical in start..len {
            let slot = if len < CPU_EXEC_TRACE_CAP {
                logical
            } else {
                (next + logical) % CPU_EXEC_TRACE_CAP
            };
            let entry = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING[slot]));
            if entry.vm_ptr != vm_ptr {
                continue;
            }
            if out == FAULT_EXEC_TRACE_CAP {
                for idx in 1..FAULT_EXEC_TRACE_CAP {
                    LAST_FAULT_EXEC_TRACE[idx - 1] = LAST_FAULT_EXEC_TRACE[idx];
                }
                out = FAULT_EXEC_TRACE_CAP - 1;
            }
            LAST_FAULT_EXEC_TRACE[out] = entry;
            out += 1;
        }
        LAST_FAULT_EXEC_TRACE_LEN = out as u32;
    }
}

fn snapshot_sync_fault_exec_trace_for_vm(vm_ptr: u32, epoch: u32) {
    unsafe {
        LAST_SYNC_FAULT_EXEC_TRACE_VM_PTR = vm_ptr;
        LAST_SYNC_FAULT_EXEC_TRACE_EPOCH = epoch;
        LAST_SYNC_FAULT_EXEC_TRACE_LEN = 0;
        if vm_ptr == 0 {
            return;
        }
        let len = EXEC_TRACE_RING_LEN as usize;
        if len == 0 {
            return;
        }
        let next = EXEC_TRACE_RING_NEXT as usize;
        let mut out = 0usize;
        let start = len.saturating_sub(FAULT_EXEC_TRACE_CAP);
        for index in start..len {
            let slot = if len < CPU_EXEC_TRACE_CAP {
                index
            } else {
                (next + index) % CPU_EXEC_TRACE_CAP
            };
            let entry = EXEC_TRACE_RING[slot];
            if entry.vm_ptr != vm_ptr || entry.epoch != epoch {
                continue;
            }
            LAST_SYNC_FAULT_EXEC_TRACE[out] = entry;
            out += 1;
            if out >= FAULT_EXEC_TRACE_CAP {
                break;
            }
        }
        LAST_SYNC_FAULT_EXEC_TRACE_LEN = out as u32;
    }
}

fn snapshot_thread_step_exec_trace_for_vm(vm_ptr: u32, epoch: u32) {
    unsafe {
        LAST_THREAD_STEP_EXEC_TRACE_VM_PTR = vm_ptr;
        LAST_THREAD_STEP_EXEC_TRACE_EPOCH = epoch;
        LAST_THREAD_STEP_EXEC_TRACE_LEN = 0;
        if vm_ptr == 0 || epoch == 0 {
            return;
        }
        let len = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_LEN)) as usize;
        if len == 0 {
            return;
        }
        let next = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_NEXT)) as usize;
        let start = len.saturating_sub(FAULT_EXEC_TRACE_CAP);
        let mut out = 0usize;
        for logical in start..len {
            let slot = if len < CPU_EXEC_TRACE_CAP {
                logical
            } else {
                (next + logical) % CPU_EXEC_TRACE_CAP
            };
            let entry = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING[slot]));
            if entry.vm_ptr != vm_ptr || entry.epoch != epoch {
                continue;
            }
            LAST_THREAD_STEP_EXEC_TRACE[out] = entry;
            out += 1;
            if out >= FAULT_EXEC_TRACE_CAP {
                break;
            }
        }
        LAST_THREAD_STEP_EXEC_TRACE_LEN = out as u32;
    }
}

fn snapshot_break_exec_trace_for_vm(vm_ptr: u32, epoch: u32) {
    unsafe {
        LAST_BREAK_EXEC_TRACE_VM_PTR = vm_ptr;
        LAST_BREAK_EXEC_TRACE_EPOCH = epoch;
        LAST_BREAK_EXEC_TRACE_LEN = 0;
        if vm_ptr == 0 || epoch == 0 {
            return;
        }
        let len = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_LEN)) as usize;
        if len == 0 {
            return;
        }
        let next = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_NEXT)) as usize;
        let start = len.saturating_sub(FAULT_EXEC_TRACE_CAP);
        let mut out = 0usize;
        for logical in start..len {
            let slot = if len < CPU_EXEC_TRACE_CAP {
                logical
            } else {
                (next + logical) % CPU_EXEC_TRACE_CAP
            };
            let entry = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING[slot]));
            if entry.vm_ptr != vm_ptr || entry.epoch != epoch {
                continue;
            }
            LAST_BREAK_EXEC_TRACE[out] = entry;
            out += 1;
            if out >= FAULT_EXEC_TRACE_CAP {
                break;
            }
        }
        LAST_BREAK_EXEC_TRACE_LEN = out as u32;
    }
}

pub(crate) fn record_exec_trace(
    vm_ptr: u32,
    tid: i32,
    pc: u64,
    raw: u32,
    step: u64,
    x: &[u64; 32],
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm_ptr, tid, pc, raw, step, x);
        return;
    }
    unsafe {
        let next = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_NEXT));
        let slot = (next as usize) % CPU_EXEC_TRACE_CAP;
        core::ptr::write(
            core::ptr::addr_of_mut!(EXEC_TRACE_RING[slot]),
            ExecTraceEntry {
                vm_ptr,
                epoch: current_exec_trace_epoch_for_vm(vm_ptr),
                tid,
                pc,
                raw,
                step: step as u32,
                sp: x[2],
                ra: x[1],
                a0: x[10],
                a4: x[14],
                a5: x[15],
                s11: x[27],
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(EXEC_TRACE_RING_LEN),
            core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_LEN))
                .saturating_add(1)
                .min(CPU_EXEC_TRACE_CAP as u32),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(EXEC_TRACE_RING_NEXT),
            next.wrapping_add(1),
        );
        let clone_pc = crate::syscall::thread::last_clone_spawn().1;
        if clone_pc != 0 && pc >= clone_pc && pc <= clone_pc.saturating_add(0x40) {
            let clone_index = (CLONE_STARTUP_TRACE_NEXT as usize) % CLONE_STARTUP_TRACE_CAP;
            core::ptr::write(
                core::ptr::addr_of_mut!(CLONE_STARTUP_TRACE_RING[clone_index]),
                CloneStartupTraceEntry {
                    vm_ptr,
                    tid,
                    pc,
                    raw,
                    a0: x[10],
                    t1: x[6],
                    t2: x[7],
                    sp: x[2],
                    s11: x[27],
                },
            );
            core::ptr::write(
                core::ptr::addr_of_mut!(CLONE_STARTUP_TRACE_NEXT),
                ((clone_index + 1) % CLONE_STARTUP_TRACE_CAP) as u32,
            );
            core::ptr::write(
                core::ptr::addr_of_mut!(CLONE_STARTUP_TRACE_LEN),
                core::ptr::read(core::ptr::addr_of!(CLONE_STARTUP_TRACE_LEN))
                    .saturating_add(1)
                    .min(CLONE_STARTUP_TRACE_CAP as u32),
            );
        }
    }
}

pub(crate) fn record_thread_step_trace(
    vm: &crate::types::ThreadState,
    budget: i32,
    remaining: i32,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm, budget, remaining);
        return;
    }
    let summary = ThreadStepTraceSummary {
        vm_ptr: vm as *const crate::types::ThreadState as u32,
        tid: vm.tid,
        status: vm.status,
        budget,
        remaining,
        pc: vm.pc,
        ra: vm.x[1],
        sp: vm.x[2],
        s11: vm.x[27],
    };
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(LAST_THREAD_STEP_TRACE), summary);
        record_thread_step_trace_by_vm(summary);
        let next = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_NEXT)) as usize;
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_TRACE_RING[next]),
            summary,
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_TRACE_NEXT),
            ((next + 1) % THREAD_STEP_TRACE_CAP) as u32,
        );
        let len = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_LEN));
        if len < THREAD_STEP_TRACE_CAP as u32 {
            core::ptr::write(core::ptr::addr_of_mut!(THREAD_STEP_TRACE_LEN), len + 1);
        }
        let epoch = current_exec_trace_epoch_for_vm(summary.vm_ptr);
        snapshot_thread_step_exec_trace_for_vm(summary.vm_ptr, epoch);
        if summary.pc < 0x1000 || summary.sp == 0 || summary.s11 == 0 {
            snapshot_break_exec_trace_for_vm(summary.vm_ptr, epoch);
        }
    }
}

pub(crate) fn record_thread_step_entry_trace(vm: &crate::types::ThreadState, budget: i32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm, budget);
        return;
    }
    let summary = ThreadStepEntryTraceSummary {
        vm_ptr: vm as *const crate::types::ThreadState as u32,
        tid: vm.tid,
        status: vm.status,
        budget,
        pc: vm.pc,
        ra: vm.x[1],
        sp: vm.x[2],
        s11: vm.x[27],
    };
    unsafe {
        bump_exec_trace_epoch_for_vm(summary.vm_ptr);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_THREAD_STEP_ENTRY_TRACE),
            summary,
        );
        record_thread_step_entry_trace_by_vm(summary);
        let next = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_ENTRY_TRACE_NEXT)) as usize;
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_ENTRY_TRACE_RING[next]),
            summary,
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_ENTRY_TRACE_NEXT),
            ((next + 1) % THREAD_STEP_TRACE_CAP) as u32,
        );
        let len = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_ENTRY_TRACE_LEN));
        if len < THREAD_STEP_TRACE_CAP as u32 {
            core::ptr::write(
                core::ptr::addr_of_mut!(THREAD_STEP_ENTRY_TRACE_LEN),
                len + 1,
            );
        }
    }
}

pub(crate) fn record_thread_step_phase(
    vm: &crate::types::ThreadState,
    phase: u32,
    budget: i32,
    remaining: i32,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm, phase, budget, remaining);
        return;
    }
    let summary = ThreadStepPhaseSummary {
        vm_ptr: vm as *const crate::types::ThreadState as u32,
        tid: vm.tid,
        phase,
        status: vm.status,
        budget,
        remaining,
        pc: vm.pc,
        ra: vm.x[1],
        sp: vm.x[2],
        s11: vm.x[27],
    };
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(LAST_THREAD_STEP_PHASE), summary);
        record_thread_step_phase_by_vm(summary);
    }
}

unsafe fn record_thread_step_trace_by_vm(summary: ThreadStepTraceSummary) {
    if summary.vm_ptr == 0 {
        return;
    }
    for index in 0..THREAD_STEP_VM_TRACE_CAP {
        if unsafe { THREAD_STEP_TRACE_BY_VM[index].vm_ptr } == summary.vm_ptr {
            unsafe {
                THREAD_STEP_TRACE_BY_VM[index] = summary;
            }
            return;
        }
    }
    let next = unsafe { THREAD_STEP_TRACE_BY_VM_NEXT as usize % THREAD_STEP_VM_TRACE_CAP };
    unsafe {
        THREAD_STEP_TRACE_BY_VM[next] = summary;
        THREAD_STEP_TRACE_BY_VM_NEXT = ((next + 1) % THREAD_STEP_VM_TRACE_CAP) as u32;
    }
}

unsafe fn record_thread_step_phase_by_vm(summary: ThreadStepPhaseSummary) {
    if summary.vm_ptr == 0 {
        return;
    }
    for index in 0..THREAD_STEP_VM_TRACE_CAP {
        if unsafe { THREAD_STEP_PHASE_BY_VM[index].vm_ptr } == summary.vm_ptr {
            unsafe {
                THREAD_STEP_PHASE_BY_VM[index] = summary;
            }
            return;
        }
    }
    let next = unsafe { THREAD_STEP_PHASE_BY_VM_NEXT as usize % THREAD_STEP_VM_TRACE_CAP };
    unsafe {
        THREAD_STEP_PHASE_BY_VM[next] = summary;
        THREAD_STEP_PHASE_BY_VM_NEXT = ((next + 1) % THREAD_STEP_VM_TRACE_CAP) as u32;
    }
}

unsafe fn record_thread_step_entry_trace_by_vm(summary: ThreadStepEntryTraceSummary) {
    if summary.vm_ptr == 0 {
        return;
    }
    for index in 0..THREAD_STEP_VM_TRACE_CAP {
        if unsafe { THREAD_STEP_ENTRY_TRACE_BY_VM[index].vm_ptr } == summary.vm_ptr {
            unsafe {
                THREAD_STEP_ENTRY_TRACE_BY_VM[index] = summary;
            }
            return;
        }
    }
    let next = unsafe { THREAD_STEP_ENTRY_TRACE_BY_VM_NEXT as usize % THREAD_STEP_VM_TRACE_CAP };
    unsafe {
        THREAD_STEP_ENTRY_TRACE_BY_VM[next] = summary;
        THREAD_STEP_ENTRY_TRACE_BY_VM_NEXT = ((next + 1) % THREAD_STEP_VM_TRACE_CAP) as u32;
    }
}

pub(crate) fn record_fault_dispatch_trace(
    vm: &crate::types::ThreadState,
    phase: u32,
    pc: u64,
    ra: u64,
    sp: u64,
    s11: u64,
    fault_addr: u64,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm, phase, pc, ra, sp, s11, fault_addr);
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_FAULT_DISPATCH_TRACE),
            FaultDispatchTraceSummary {
                vm_ptr: vm as *const crate::types::ThreadState as u32,
                tid: vm.tid,
                phase,
                pc,
                ra,
                sp,
                s11,
                fault_addr,
            },
        );
        if phase == 1 {
            snapshot_fault_exec_trace_for_vm(
                vm as *const crate::types::ThreadState as u32,
                current_exec_trace_epoch_for_vm(vm as *const crate::types::ThreadState as u32),
            );
            snapshot_sync_fault_exec_trace_for_vm(
                vm as *const crate::types::ThreadState as u32,
                current_exec_trace_epoch_for_vm(vm as *const crate::types::ThreadState as u32),
            );
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn exec_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn exec_trace_entry(index: u32) -> ExecTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return ExecTraceEntry {
            vm_ptr: 0,
            epoch: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            step: 0,
            sp: 0,
            ra: 0,
            a0: 0,
            a4: 0,
            a5: 0,
            s11: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_LEN));
        if index >= len {
            return ExecTraceEntry {
                vm_ptr: 0,
                epoch: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                step: 0,
                sp: 0,
                ra: 0,
                a0: 0,
                a4: 0,
                a5: 0,
                s11: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING_NEXT)) as usize;
        let len_usize = len as usize;
        let slot = if len_usize < CPU_EXEC_TRACE_CAP {
            index as usize
        } else {
            (next + index as usize) % CPU_EXEC_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(EXEC_TRACE_RING[slot]))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn exec_trace_epoch_for_vm(vm_ptr: u32) -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    current_exec_trace_epoch_for_vm(vm_ptr)
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn fault_exec_trace_len_for_vm(vm_ptr: u32) -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe {
        if LAST_FAULT_EXEC_TRACE_VM_PTR == vm_ptr {
            LAST_FAULT_EXEC_TRACE_LEN
        } else {
            0
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn fault_exec_trace_entry_for_vm(vm_ptr: u32, index: u32) -> ExecTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return ExecTraceEntry {
            vm_ptr: 0,
            epoch: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            step: 0,
            sp: 0,
            ra: 0,
            a0: 0,
            a4: 0,
            a5: 0,
            s11: 0,
        };
    }
    unsafe {
        if LAST_FAULT_EXEC_TRACE_VM_PTR != vm_ptr || index >= LAST_FAULT_EXEC_TRACE_LEN {
            return ExecTraceEntry {
                vm_ptr: 0,
                epoch: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                step: 0,
                sp: 0,
                ra: 0,
                a0: 0,
                a4: 0,
                a5: 0,
                s11: 0,
            };
        }
        LAST_FAULT_EXEC_TRACE[index as usize]
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn thread_step_exec_trace_len_for_vm(vm_ptr: u32) -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe {
        if LAST_THREAD_STEP_EXEC_TRACE_VM_PTR == vm_ptr {
            LAST_THREAD_STEP_EXEC_TRACE_LEN
        } else {
            0
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn thread_step_exec_trace_entry_for_vm(vm_ptr: u32, index: u32) -> ExecTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return ExecTraceEntry {
            vm_ptr: 0,
            epoch: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            step: 0,
            sp: 0,
            ra: 0,
            a0: 0,
            a4: 0,
            a5: 0,
            s11: 0,
        };
    }
    unsafe {
        if LAST_THREAD_STEP_EXEC_TRACE_VM_PTR != vm_ptr || index >= LAST_THREAD_STEP_EXEC_TRACE_LEN
        {
            return ExecTraceEntry {
                vm_ptr: 0,
                epoch: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                step: 0,
                sp: 0,
                ra: 0,
                a0: 0,
                a4: 0,
                a5: 0,
                s11: 0,
            };
        }
        LAST_THREAD_STEP_EXEC_TRACE[index as usize]
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn break_exec_trace_len_for_vm(vm_ptr: u32) -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe {
        if LAST_BREAK_EXEC_TRACE_VM_PTR == vm_ptr {
            LAST_BREAK_EXEC_TRACE_LEN
        } else {
            0
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn break_exec_trace_entry_for_vm(vm_ptr: u32, index: u32) -> ExecTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return ExecTraceEntry {
            vm_ptr: 0,
            epoch: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            step: 0,
            sp: 0,
            ra: 0,
            a0: 0,
            a4: 0,
            a5: 0,
            s11: 0,
        };
    }
    unsafe {
        if LAST_BREAK_EXEC_TRACE_VM_PTR != vm_ptr || index >= LAST_BREAK_EXEC_TRACE_LEN {
            return ExecTraceEntry {
                vm_ptr: 0,
                epoch: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                step: 0,
                sp: 0,
                ra: 0,
                a0: 0,
                a4: 0,
                a5: 0,
                s11: 0,
            };
        }
        LAST_BREAK_EXEC_TRACE[index as usize]
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn sync_fault_exec_trace_len_for_vm(vm_ptr: u32) -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe {
        if LAST_SYNC_FAULT_EXEC_TRACE_VM_PTR == vm_ptr {
            LAST_SYNC_FAULT_EXEC_TRACE_LEN
        } else {
            0
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn sync_fault_exec_trace_entry_for_vm(vm_ptr: u32, index: u32) -> ExecTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return ExecTraceEntry {
            vm_ptr: 0,
            epoch: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            step: 0,
            sp: 0,
            ra: 0,
            a0: 0,
            a4: 0,
            a5: 0,
            s11: 0,
        };
    }
    unsafe {
        if LAST_SYNC_FAULT_EXEC_TRACE_VM_PTR != vm_ptr || index >= LAST_SYNC_FAULT_EXEC_TRACE_LEN {
            return ExecTraceEntry {
                vm_ptr: 0,
                epoch: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                step: 0,
                sp: 0,
                ra: 0,
                a0: 0,
                a4: 0,
                a5: 0,
                s11: 0,
            };
        }
        LAST_SYNC_FAULT_EXEC_TRACE[index as usize]
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn thread_step_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn clone_startup_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(CLONE_STARTUP_TRACE_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn clone_startup_trace_entry(index: u32) -> CloneStartupTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return CloneStartupTraceEntry {
            vm_ptr: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            a0: 0,
            t1: 0,
            t2: 0,
            sp: 0,
            s11: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(CLONE_STARTUP_TRACE_LEN));
        if index >= len {
            return CloneStartupTraceEntry {
                vm_ptr: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                a0: 0,
                t1: 0,
                t2: 0,
                sp: 0,
                s11: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(CLONE_STARTUP_TRACE_NEXT)) as usize;
        let slot = if len < CLONE_STARTUP_TRACE_CAP as u32 {
            index as usize
        } else {
            (next + index as usize) % CLONE_STARTUP_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(CLONE_STARTUP_TRACE_RING[slot]))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn thread_step_trace_entry(index: u32) -> ThreadStepTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return ThreadStepTraceSummary {
            vm_ptr: 0,
            tid: 0,
            status: 0,
            budget: 0,
            remaining: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            s11: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_LEN));
        if index >= len {
            return ThreadStepTraceSummary {
                vm_ptr: 0,
                tid: 0,
                status: 0,
                budget: 0,
                remaining: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_NEXT)) as usize;
        let slot = if len < THREAD_STEP_TRACE_CAP as u32 {
            index as usize
        } else {
            (next + index as usize) % THREAD_STEP_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_RING[slot]))
    }
}

pub(crate) fn record_jalr(
    vm_ptr: u32,
    pc: u64,
    rd: usize,
    rs1: usize,
    rs1_value: u64,
    target: u64,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm_ptr, pc, rd, rs1, rs1_value, target);
        return;
    }
    let entry = JalrTraceSummary {
        vm_ptr,
        pc,
        rs1_value,
        target,
        rd: rd as u32,
        rs1: rs1 as u32,
    };
    let clone_pc = crate::syscall::thread::last_clone_spawn().1;
    let capture_clone_startup =
        clone_pc != 0 && pc >= clone_pc.saturating_add(0x40) && pc < clone_pc.saturating_add(0x48);
    if capture_clone_startup {
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(LAST_CLONE_JALR_TRACE), entry);
        }
    }
    if rs1 == 1 || target < 0x1000 {
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(LAST_JALR_TRACE), entry);
            let idx = (JALR_TRACE_NEXT as usize) % CPU_REG_TRACE_CAP;
            JALR_TRACE_RING[idx] = entry;
            JALR_TRACE_NEXT = ((idx + 1) % CPU_REG_TRACE_CAP) as u32;
            if JALR_TRACE_LEN < CPU_REG_TRACE_CAP as u32 {
                JALR_TRACE_LEN += 1;
            }
        }
    }
}

fn push_zero_reg_trace(entry: ZeroRegTraceSummary) {
    unsafe {
        let idx = (ZERO_REG_TRACE_NEXT as usize) % CPU_REG_TRACE_CAP;
        ZERO_REG_TRACE_RING[idx] = entry;
        ZERO_REG_TRACE_NEXT = ((idx + 1) % CPU_REG_TRACE_CAP) as u32;
        if ZERO_REG_TRACE_LEN < CPU_REG_TRACE_CAP as u32 {
            ZERO_REG_TRACE_LEN += 1;
        }
    }
}

fn push_reg_write_trace(
    ring: *mut [RegWriteTraceSummary; CPU_REG_TRACE_CAP],
    next_ptr: *mut u32,
    len_ptr: *mut u32,
    entry: RegWriteTraceSummary,
) {
    unsafe {
        let idx = (*next_ptr as usize) % CPU_REG_TRACE_CAP;
        (*ring)[idx] = entry;
        *next_ptr = ((idx + 1) % CPU_REG_TRACE_CAP) as u32;
        if *len_ptr < CPU_REG_TRACE_CAP as u32 {
            *len_ptr += 1;
        }
    }
}

fn latest_zero_reg_trace_for_vm(vm_ptr: u32) -> ZeroRegTraceSummary {
    if vm_ptr == 0 {
        return ZeroRegTraceSummary {
            vm_ptr: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            reg: 0,
            prev_value: 0,
            sp: 0,
            s11: 0,
        };
    }
    unsafe {
        let len = ZERO_REG_TRACE_LEN.min(CPU_REG_TRACE_CAP as u32) as usize;
        let next = ZERO_REG_TRACE_NEXT as usize % CPU_REG_TRACE_CAP;
        for offset in 0..len {
            let idx = if len < CPU_REG_TRACE_CAP {
                len - 1 - offset
            } else {
                (next + CPU_REG_TRACE_CAP - 1 - offset) % CPU_REG_TRACE_CAP
            };
            let entry = ZERO_REG_TRACE_RING[idx];
            if entry.vm_ptr == vm_ptr {
                return entry;
            }
        }
    }
    ZeroRegTraceSummary {
        vm_ptr: 0,
        tid: 0,
        pc: 0,
        raw: 0,
        reg: 0,
        prev_value: 0,
        sp: 0,
        s11: 0,
    }
}

fn latest_reg_write_trace_for_vm(
    ring: *const [RegWriteTraceSummary; CPU_REG_TRACE_CAP],
    len: u32,
    next: u32,
    vm_ptr: u32,
) -> RegWriteTraceSummary {
    if vm_ptr == 0 {
        return RegWriteTraceSummary {
            vm_ptr: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            source: 0,
            prev_value: 0,
            value: 0,
            rs1: 0,
            rs1_value: 0,
        };
    }
    let len = len.min(CPU_REG_TRACE_CAP as u32) as usize;
    let next = next as usize % CPU_REG_TRACE_CAP;
    for offset in 0..len {
        let idx = if len < CPU_REG_TRACE_CAP {
            len - 1 - offset
        } else {
            (next + CPU_REG_TRACE_CAP - 1 - offset) % CPU_REG_TRACE_CAP
        };
        let entry = unsafe { (*ring)[idx] };
        if entry.vm_ptr == vm_ptr {
            return entry;
        }
    }
    RegWriteTraceSummary {
        vm_ptr: 0,
        tid: 0,
        pc: 0,
        raw: 0,
        source: 0,
        prev_value: 0,
        value: 0,
        rs1: 0,
        rs1_value: 0,
    }
}

pub(crate) fn record_zero_reg_transition(
    vm_ptr: u32,
    tid: i32,
    pc: u64,
    raw: u32,
    prev_sp: u64,
    prev_s11: u64,
    x: &[u64; 32],
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm_ptr, tid, pc, raw, prev_sp, prev_s11, x);
        return;
    }
    unsafe {
        if prev_s11 != 0 && x[27] == 0 {
            let entry = ZeroRegTraceSummary {
                vm_ptr,
                tid,
                pc,
                raw,
                reg: 27,
                prev_value: prev_s11,
                sp: x[2],
                s11: x[27],
            };
            core::ptr::write(core::ptr::addr_of_mut!(LAST_ZERO_REG_TRACE), entry);
            push_zero_reg_trace(entry);
            snapshot_break_exec_trace_for_vm(vm_ptr, current_exec_trace_epoch_for_vm(vm_ptr));
            return;
        }
        if prev_sp != 0 && x[2] == 0 {
            let entry = ZeroRegTraceSummary {
                vm_ptr,
                tid,
                pc,
                raw,
                reg: 2,
                prev_value: prev_sp,
                sp: x[2],
                s11: x[27],
            };
            core::ptr::write(core::ptr::addr_of_mut!(LAST_ZERO_REG_TRACE), entry);
            push_zero_reg_trace(entry);
            snapshot_break_exec_trace_for_vm(vm_ptr, current_exec_trace_epoch_for_vm(vm_ptr));
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_special_reg_transitions(
    vm_ptr: u32,
    tid: i32,
    pc: u64,
    raw: u32,
    source: u32,
    prev_sp: u64,
    prev_tp: u64,
    prev_s11: u64,
    x: &[u64; 32],
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm_ptr, tid, pc, raw, source, prev_sp, prev_tp, prev_s11, x);
        return;
    }
    unsafe {
        let rs1 = if raw == 0 {
            0
        } else {
            crate::cpu::decode::rs1(raw) as u32
        };
        let rs1_value = if raw == 0 { 0 } else { x[rs1 as usize] };
        if prev_s11 != x[27] {
            let entry = RegWriteTraceSummary {
                vm_ptr,
                tid,
                pc,
                raw,
                source,
                prev_value: prev_s11,
                value: x[27],
                rs1,
                rs1_value,
            };
            core::ptr::write(core::ptr::addr_of_mut!(LAST_S11_WRITE_TRACE), entry);
            push_reg_write_trace(
                core::ptr::addr_of_mut!(S11_WRITE_TRACE_RING),
                core::ptr::addr_of_mut!(S11_WRITE_TRACE_NEXT),
                core::ptr::addr_of_mut!(S11_WRITE_TRACE_LEN),
                entry,
            );
        }
        if prev_sp != x[2] {
            let entry = RegWriteTraceSummary {
                vm_ptr,
                tid,
                pc,
                raw,
                source,
                prev_value: prev_sp,
                value: x[2],
                rs1,
                rs1_value,
            };
            core::ptr::write(core::ptr::addr_of_mut!(LAST_SP_WRITE_TRACE), entry);
            push_reg_write_trace(
                core::ptr::addr_of_mut!(SP_WRITE_TRACE_RING),
                core::ptr::addr_of_mut!(SP_WRITE_TRACE_NEXT),
                core::ptr::addr_of_mut!(SP_WRITE_TRACE_LEN),
                entry,
            );
        }
        let _ = prev_tp;
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_jalr_trace() -> JalrTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return JalrTraceSummary {
            vm_ptr: 0,
            pc: 0,
            rs1_value: 0,
            target: 0,
            rd: 0,
            rs1: 0,
        };
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_JALR_TRACE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_clone_jalr_trace() -> JalrTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return JalrTraceSummary {
            vm_ptr: 0,
            pc: 0,
            rs1_value: 0,
            target: 0,
            rd: 0,
            rs1: 0,
        };
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_CLONE_JALR_TRACE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_jalr_trace_for_vm(vm_ptr: u32) -> JalrTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = vm_ptr;
        return JalrTraceSummary {
            vm_ptr: 0,
            pc: 0,
            rs1_value: 0,
            target: 0,
            rd: 0,
            rs1: 0,
        };
    }
    if vm_ptr == 0 {
        return JalrTraceSummary {
            vm_ptr: 0,
            pc: 0,
            rs1_value: 0,
            target: 0,
            rd: 0,
            rs1: 0,
        };
    }
    unsafe {
        let len = JALR_TRACE_LEN.min(CPU_REG_TRACE_CAP as u32) as usize;
        let next = JALR_TRACE_NEXT as usize % CPU_REG_TRACE_CAP;
        for offset in 0..len {
            let idx = if len < CPU_REG_TRACE_CAP {
                len - 1 - offset
            } else {
                (next + CPU_REG_TRACE_CAP - 1 - offset) % CPU_REG_TRACE_CAP
            };
            let entry = JALR_TRACE_RING[idx];
            if entry.vm_ptr == vm_ptr {
                return entry;
            }
        }
    }
    JalrTraceSummary {
        vm_ptr: 0,
        pc: 0,
        rs1_value: 0,
        target: 0,
        rd: 0,
        rs1: 0,
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_zero_reg_trace() -> ZeroRegTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return ZeroRegTraceSummary {
            vm_ptr: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            reg: 0,
            prev_value: 0,
            sp: 0,
            s11: 0,
        };
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_ZERO_REG_TRACE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_zero_reg_trace_for_vm(vm_ptr: u32) -> ZeroRegTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = vm_ptr;
        return ZeroRegTraceSummary {
            vm_ptr: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            reg: 0,
            prev_value: 0,
            sp: 0,
            s11: 0,
        };
    }
    latest_zero_reg_trace_for_vm(vm_ptr)
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_s11_write_trace() -> RegWriteTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return RegWriteTraceSummary {
            vm_ptr: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            source: 0,
            prev_value: 0,
            value: 0,
            rs1: 0,
            rs1_value: 0,
        };
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_S11_WRITE_TRACE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_s11_write_trace_for_vm(vm_ptr: u32) -> RegWriteTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = vm_ptr;
        return RegWriteTraceSummary {
            vm_ptr: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            source: 0,
            prev_value: 0,
            value: 0,
            rs1: 0,
            rs1_value: 0,
        };
    }
    unsafe {
        latest_reg_write_trace_for_vm(
            core::ptr::addr_of!(S11_WRITE_TRACE_RING),
            S11_WRITE_TRACE_LEN,
            S11_WRITE_TRACE_NEXT,
            vm_ptr,
        )
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_sp_write_trace() -> RegWriteTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return RegWriteTraceSummary {
            vm_ptr: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            source: 0,
            prev_value: 0,
            value: 0,
            rs1: 0,
            rs1_value: 0,
        };
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_SP_WRITE_TRACE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_sp_write_trace_for_vm(vm_ptr: u32) -> RegWriteTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = vm_ptr;
        return RegWriteTraceSummary {
            vm_ptr: 0,
            tid: 0,
            pc: 0,
            raw: 0,
            source: 0,
            prev_value: 0,
            value: 0,
            rs1: 0,
            rs1_value: 0,
        };
    }
    unsafe {
        latest_reg_write_trace_for_vm(
            core::ptr::addr_of!(SP_WRITE_TRACE_RING),
            SP_WRITE_TRACE_LEN,
            SP_WRITE_TRACE_NEXT,
            vm_ptr,
        )
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_thread_step_trace() -> ThreadStepTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return ThreadStepTraceSummary {
            vm_ptr: 0,
            tid: 0,
            status: 0,
            budget: 0,
            remaining: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            s11: 0,
        };
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_THREAD_STEP_TRACE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_thread_step_trace_for_vm(vm_ptr: u32) -> ThreadStepTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = vm_ptr;
        return ThreadStepTraceSummary {
            vm_ptr: 0,
            tid: 0,
            status: 0,
            budget: 0,
            remaining: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            s11: 0,
        };
    }
    unsafe {
        for index in 0..THREAD_STEP_VM_TRACE_CAP {
            let entry = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_BY_VM[index]));
            if entry.vm_ptr == vm_ptr {
                return entry;
            }
        }
        let len = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_LEN))
            .min(THREAD_STEP_TRACE_CAP as u32);
        let next = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_NEXT)) as usize;
        for offset in 0..len as usize {
            let idx = (next + THREAD_STEP_TRACE_CAP - 1 - offset) % THREAD_STEP_TRACE_CAP;
            let entry = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_TRACE_RING[idx]));
            if entry.vm_ptr == vm_ptr {
                return entry;
            }
        }
        ThreadStepTraceSummary {
            vm_ptr: 0,
            tid: 0,
            status: 0,
            budget: 0,
            remaining: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            s11: 0,
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_thread_step_phase() -> ThreadStepPhaseSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return ThreadStepPhaseSummary {
            vm_ptr: 0,
            tid: 0,
            phase: 0,
            status: 0,
            budget: 0,
            remaining: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            s11: 0,
        };
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_THREAD_STEP_PHASE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_thread_step_phase_for_vm(vm_ptr: u32) -> ThreadStepPhaseSummary {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = vm_ptr;
        return ThreadStepPhaseSummary {
            vm_ptr: 0,
            tid: 0,
            phase: 0,
            status: 0,
            budget: 0,
            remaining: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            s11: 0,
        };
    }
    unsafe {
        for index in 0..THREAD_STEP_VM_TRACE_CAP {
            let entry = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_PHASE_BY_VM[index]));
            if entry.vm_ptr == vm_ptr {
                return entry;
            }
        }
    }
    ThreadStepPhaseSummary {
        vm_ptr: 0,
        tid: 0,
        phase: 0,
        status: 0,
        budget: 0,
        remaining: 0,
        pc: 0,
        ra: 0,
        sp: 0,
        s11: 0,
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_thread_step_entry_trace_for_vm(vm_ptr: u32) -> ThreadStepEntryTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = vm_ptr;
        return ThreadStepEntryTraceSummary {
            vm_ptr: 0,
            tid: 0,
            status: 0,
            budget: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            s11: 0,
        };
    }
    unsafe {
        for index in 0..THREAD_STEP_VM_TRACE_CAP {
            let entry = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_ENTRY_TRACE_BY_VM[index]));
            if entry.vm_ptr == vm_ptr {
                return entry;
            }
        }
        let len = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_ENTRY_TRACE_LEN))
            .min(THREAD_STEP_TRACE_CAP as u32);
        let next = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_ENTRY_TRACE_NEXT)) as usize;
        for offset in 0..len as usize {
            let idx = (next + THREAD_STEP_TRACE_CAP - 1 - offset) % THREAD_STEP_TRACE_CAP;
            let entry = core::ptr::read(core::ptr::addr_of!(THREAD_STEP_ENTRY_TRACE_RING[idx]));
            if entry.vm_ptr == vm_ptr {
                return entry;
            }
        }
        ThreadStepEntryTraceSummary {
            vm_ptr: 0,
            tid: 0,
            status: 0,
            budget: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            s11: 0,
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn last_fault_dispatch_trace_for_vm(vm_ptr: u32) -> FaultDispatchTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = vm_ptr;
        return FaultDispatchTraceSummary {
            vm_ptr: 0,
            tid: 0,
            phase: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            s11: 0,
            fault_addr: 0,
        };
    }
    unsafe {
        let entry = core::ptr::read(core::ptr::addr_of!(LAST_FAULT_DISPATCH_TRACE));
        if entry.vm_ptr == vm_ptr {
            entry
        } else {
            FaultDispatchTraceSummary {
                vm_ptr: 0,
                tid: 0,
                phase: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
                fault_addr: 0,
            }
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn clear_cpu_trace() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_JALR_TRACE),
            JalrTraceSummary {
                vm_ptr: 0,
                pc: 0,
                rs1_value: 0,
                target: 0,
                rd: 0,
                rs1: 0,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_CLONE_JALR_TRACE),
            JalrTraceSummary {
                vm_ptr: 0,
                pc: 0,
                rs1_value: 0,
                target: 0,
                rd: 0,
                rs1: 0,
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(CLONE_STARTUP_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(CLONE_STARTUP_TRACE_NEXT), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_ZERO_REG_TRACE),
            ZeroRegTraceSummary {
                vm_ptr: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                reg: 0,
                prev_value: 0,
                sp: 0,
                s11: 0,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_S11_WRITE_TRACE),
            RegWriteTraceSummary {
                vm_ptr: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                source: 0,
                prev_value: 0,
                value: 0,
                rs1: 0,
                rs1_value: 0,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_SP_WRITE_TRACE),
            RegWriteTraceSummary {
                vm_ptr: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                source: 0,
                prev_value: 0,
                value: 0,
                rs1: 0,
                rs1_value: 0,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_THREAD_STEP_TRACE),
            ThreadStepTraceSummary {
                vm_ptr: 0,
                tid: 0,
                status: 0,
                budget: 0,
                remaining: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_TRACE_RING),
            [ThreadStepTraceSummary {
                vm_ptr: 0,
                tid: 0,
                status: 0,
                budget: 0,
                remaining: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
            }; THREAD_STEP_TRACE_CAP],
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_TRACE_BY_VM),
            [ThreadStepTraceSummary {
                vm_ptr: 0,
                tid: 0,
                status: 0,
                budget: 0,
                remaining: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
            }; THREAD_STEP_VM_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(THREAD_STEP_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(THREAD_STEP_TRACE_NEXT), 0);
        core::ptr::write(core::ptr::addr_of_mut!(THREAD_STEP_TRACE_BY_VM_NEXT), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_THREAD_STEP_ENTRY_TRACE),
            ThreadStepEntryTraceSummary {
                vm_ptr: 0,
                tid: 0,
                status: 0,
                budget: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_THREAD_STEP_PHASE),
            ThreadStepPhaseSummary {
                vm_ptr: 0,
                tid: 0,
                phase: 0,
                status: 0,
                budget: 0,
                remaining: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_ENTRY_TRACE_RING),
            [ThreadStepEntryTraceSummary {
                vm_ptr: 0,
                tid: 0,
                status: 0,
                budget: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
            }; THREAD_STEP_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(THREAD_STEP_ENTRY_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(THREAD_STEP_ENTRY_TRACE_NEXT), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_ENTRY_TRACE_BY_VM),
            [ThreadStepEntryTraceSummary {
                vm_ptr: 0,
                tid: 0,
                status: 0,
                budget: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
            }; THREAD_STEP_VM_TRACE_CAP],
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_ENTRY_TRACE_BY_VM_NEXT),
            0,
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(THREAD_STEP_PHASE_BY_VM),
            [ThreadStepPhaseSummary {
                vm_ptr: 0,
                tid: 0,
                phase: 0,
                status: 0,
                budget: 0,
                remaining: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
            }; THREAD_STEP_VM_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(THREAD_STEP_PHASE_BY_VM_NEXT), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_FAULT_DISPATCH_TRACE),
            FaultDispatchTraceSummary {
                vm_ptr: 0,
                tid: 0,
                phase: 0,
                pc: 0,
                ra: 0,
                sp: 0,
                s11: 0,
                fault_addr: 0,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(JALR_TRACE_RING),
            [JalrTraceSummary {
                vm_ptr: 0,
                pc: 0,
                rs1_value: 0,
                target: 0,
                rd: 0,
                rs1: 0,
            }; CPU_REG_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(JALR_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(JALR_TRACE_NEXT), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(ZERO_REG_TRACE_RING),
            [ZeroRegTraceSummary {
                vm_ptr: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                reg: 0,
                prev_value: 0,
                sp: 0,
                s11: 0,
            }; CPU_REG_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(ZERO_REG_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(ZERO_REG_TRACE_NEXT), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(S11_WRITE_TRACE_RING),
            [RegWriteTraceSummary {
                vm_ptr: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                source: 0,
                prev_value: 0,
                value: 0,
                rs1: 0,
                rs1_value: 0,
            }; CPU_REG_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(S11_WRITE_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(S11_WRITE_TRACE_NEXT), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(SP_WRITE_TRACE_RING),
            [RegWriteTraceSummary {
                vm_ptr: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                source: 0,
                prev_value: 0,
                value: 0,
                rs1: 0,
                rs1_value: 0,
            }; CPU_REG_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(SP_WRITE_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(SP_WRITE_TRACE_NEXT), 0);
        core::ptr::write(core::ptr::addr_of_mut!(EXEC_TRACE_RING_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(EXEC_TRACE_RING_NEXT), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(EXEC_TRACE_EPOCH_BY_VM),
            [(0, 0); THREAD_STEP_VM_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(EXEC_TRACE_EPOCH_BY_VM_NEXT), 0);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_FAULT_EXEC_TRACE_VM_PTR), 0);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_FAULT_EXEC_TRACE_EPOCH), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_FAULT_EXEC_TRACE),
            [ExecTraceEntry {
                vm_ptr: 0,
                epoch: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                step: 0,
                sp: 0,
                ra: 0,
                a0: 0,
                a4: 0,
                a5: 0,
                s11: 0,
            }; FAULT_EXEC_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(LAST_FAULT_EXEC_TRACE_LEN), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_SYNC_FAULT_EXEC_TRACE_VM_PTR),
            0,
        );
        core::ptr::write(core::ptr::addr_of_mut!(LAST_SYNC_FAULT_EXEC_TRACE_EPOCH), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_SYNC_FAULT_EXEC_TRACE),
            [ExecTraceEntry {
                vm_ptr: 0,
                epoch: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                step: 0,
                sp: 0,
                ra: 0,
                a0: 0,
                a4: 0,
                a5: 0,
                s11: 0,
            }; FAULT_EXEC_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(LAST_SYNC_FAULT_EXEC_TRACE_LEN), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_THREAD_STEP_EXEC_TRACE_VM_PTR),
            0,
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_THREAD_STEP_EXEC_TRACE_EPOCH),
            0,
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_THREAD_STEP_EXEC_TRACE),
            [ExecTraceEntry {
                vm_ptr: 0,
                epoch: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                step: 0,
                sp: 0,
                ra: 0,
                a0: 0,
                a4: 0,
                a5: 0,
                s11: 0,
            }; FAULT_EXEC_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(LAST_THREAD_STEP_EXEC_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_BREAK_EXEC_TRACE_VM_PTR), 0);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_BREAK_EXEC_TRACE_EPOCH), 0);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_BREAK_EXEC_TRACE),
            [ExecTraceEntry {
                vm_ptr: 0,
                epoch: 0,
                tid: 0,
                pc: 0,
                raw: 0,
                step: 0,
                sp: 0,
                ra: 0,
                a0: 0,
                a4: 0,
                a5: 0,
                s11: 0,
            }; FAULT_EXEC_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(LAST_BREAK_EXEC_TRACE_LEN), 0);
    }
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
