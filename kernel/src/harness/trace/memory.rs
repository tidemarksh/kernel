use super::{RUNTIME_DEBUG_ENABLED, process::current_execve_stage};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryTraceSummary {
    pub nr: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub result: i64,
}

const MEMORY_TRACE_CAP: usize = 64;
static mut MEMORY_TRACE: MemoryTraceSummary = MemoryTraceSummary {
    nr: 0,
    arg0: 0,
    arg1: 0,
    arg2: 0,
    arg3: 0,
    result: 0,
};
static mut MEMORY_TRACE_RING: [MemoryTraceSummary; MEMORY_TRACE_CAP] = [MemoryTraceSummary {
    nr: 0,
    arg0: 0,
    arg1: 0,
    arg2: 0,
    arg3: 0,
    result: 0,
}; MEMORY_TRACE_CAP];
static mut MEMORY_TRACE_LEN: u32 = 0;
static mut MEMORY_TRACE_NEXT: u32 = 0;

const GUEST_WRITE_WATCH_CAP: usize = 2;
const GUEST_WRITE_OVERLAP_TRACE_CAP: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GuestWriteWatchRegion {
    pub start: u64,
    pub end: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GuestWriteOverlapTraceEntry {
    pub slot: u32,
    pub op: u32,
    pub tid: i32,
    pub pc: u64,
    pub addr: u64,
    pub len: u32,
    pub sample_len: u32,
    pub sample: u64,
    pub execve_stage: u32,
}

static mut GUEST_WRITE_WATCH: [GuestWriteWatchRegion; GUEST_WRITE_WATCH_CAP] =
    [GuestWriteWatchRegion { start: 0, end: 0 }; GUEST_WRITE_WATCH_CAP];
static mut GUEST_WRITE_OVERLAP_TRACE: [GuestWriteOverlapTraceEntry; GUEST_WRITE_OVERLAP_TRACE_CAP] =
    [GuestWriteOverlapTraceEntry {
        slot: 0,
        op: 0,
        tid: 0,
        pc: 0,
        addr: 0,
        len: 0,
        sample_len: 0,
        sample: 0,
        execve_stage: 0,
    }; GUEST_WRITE_OVERLAP_TRACE_CAP];
static mut GUEST_WRITE_OVERLAP_TRACE_LEN: u32 = 0;
static mut GUEST_WRITE_OVERLAP_TRACE_NEXT: u32 = 0;
static mut GUEST_WRITE_CONTEXT_PC: u64 = 0;
static mut GUEST_WRITE_CONTEXT_TID: i32 = 0;

const MEMORY_PERMIT_PROT_SLOTS: usize = 8;
const MEMORY_PERMIT_OUTCOME_CACHE_HIT: u32 = 1;
const MEMORY_PERMIT_OUTCOME_COVER_HIT: u32 = 2;
const MEMORY_PERMIT_OUTCOME_DENIED: u32 = 3;

static mut MEMORY_PERMIT_CHECKS: u64 = 0;
static mut MEMORY_PERMIT_CACHE_HITS: u64 = 0;
static mut MEMORY_PERMIT_COVER_HITS: u64 = 0;
static mut MEMORY_PERMIT_DENIED: u64 = 0;
static mut MEMORY_PERMIT_CHECKS_BY_PROT: [u64; MEMORY_PERMIT_PROT_SLOTS] =
    [0; MEMORY_PERMIT_PROT_SLOTS];
static mut MEMORY_PERMIT_CACHE_HITS_BY_PROT: [u64; MEMORY_PERMIT_PROT_SLOTS] =
    [0; MEMORY_PERMIT_PROT_SLOTS];
static mut MEMORY_PERMIT_COVER_HITS_BY_PROT: [u64; MEMORY_PERMIT_PROT_SLOTS] =
    [0; MEMORY_PERMIT_PROT_SLOTS];
static mut MEMORY_PERMIT_DENIED_BY_PROT: [u64; MEMORY_PERMIT_PROT_SLOTS] =
    [0; MEMORY_PERMIT_PROT_SLOTS];

#[inline(always)]
unsafe fn memory_permit_add(ptr: *mut u64, delta: u64) {
    unsafe {
        let value = core::ptr::read(ptr);
        core::ptr::write(ptr, value.wrapping_add(delta));
    }
}

#[inline(always)]
fn memory_permit_prot_slot(prot: u32) -> usize {
    (prot as usize) & (MEMORY_PERMIT_PROT_SLOTS - 1)
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn clear_memory_trace() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(MEMORY_TRACE),
            MemoryTraceSummary {
                nr: 0,
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                result: 0,
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(MEMORY_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(MEMORY_TRACE_NEXT), 0);
    }
}

pub(crate) fn record_memory_syscall(
    nr: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    result: i64,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (nr, arg0, arg1, arg2, arg3, result);
        return;
    }
    unsafe {
        let entry = MemoryTraceSummary {
            nr,
            arg0,
            arg1,
            arg2,
            arg3,
            result,
        };
        core::ptr::write(core::ptr::addr_of_mut!(MEMORY_TRACE), entry);
        let next = core::ptr::read(core::ptr::addr_of!(MEMORY_TRACE_NEXT)) as usize;
        core::ptr::write(core::ptr::addr_of_mut!(MEMORY_TRACE_RING[next]), entry);
        core::ptr::write(
            core::ptr::addr_of_mut!(MEMORY_TRACE_NEXT),
            ((next + 1) % MEMORY_TRACE_CAP) as u32,
        );
        let len = core::ptr::read(core::ptr::addr_of!(MEMORY_TRACE_LEN));
        if len < MEMORY_TRACE_CAP as u32 {
            core::ptr::write(core::ptr::addr_of_mut!(MEMORY_TRACE_LEN), len + 1);
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn clear_guest_write_watch_trace() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(GUEST_WRITE_WATCH),
            [GuestWriteWatchRegion { start: 0, end: 0 }; GUEST_WRITE_WATCH_CAP],
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(GUEST_WRITE_OVERLAP_TRACE),
            [GuestWriteOverlapTraceEntry {
                slot: 0,
                op: 0,
                tid: 0,
                pc: 0,
                addr: 0,
                len: 0,
                sample_len: 0,
                sample: 0,
                execve_stage: 0,
            }; GUEST_WRITE_OVERLAP_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(GUEST_WRITE_OVERLAP_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(GUEST_WRITE_OVERLAP_TRACE_NEXT), 0);
        core::ptr::write(core::ptr::addr_of_mut!(GUEST_WRITE_CONTEXT_PC), 0);
        core::ptr::write(core::ptr::addr_of_mut!(GUEST_WRITE_CONTEXT_TID), 0);
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn configure_guest_write_watch(slot: u32, start: u64, end: u64) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (slot, start, end);
        return;
    }
    if slot as usize >= GUEST_WRITE_WATCH_CAP {
        return;
    }
    unsafe {
        GUEST_WRITE_WATCH[slot as usize] = GuestWriteWatchRegion { start, end };
    }
}

pub(crate) fn set_guest_write_context(pc: u64, tid: i32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (pc, tid);
        return;
    }
    unsafe {
        GUEST_WRITE_CONTEXT_PC = pc;
        GUEST_WRITE_CONTEXT_TID = tid;
    }
}

pub(crate) fn clear_guest_write_context() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        GUEST_WRITE_CONTEXT_PC = 0;
        GUEST_WRITE_CONTEXT_TID = 0;
    }
}

pub(crate) fn record_guest_write_overlap(
    addr: u64,
    len: u32,
    op: u32,
    sample: u64,
    sample_len: u32,
) {
    if !RUNTIME_DEBUG_ENABLED || len == 0 {
        let _ = (addr, len, op, sample, sample_len);
        return;
    }
    let end = addr.saturating_add(len as u64);
    unsafe {
        for slot in 0..GUEST_WRITE_WATCH_CAP {
            let region = GUEST_WRITE_WATCH[slot];
            if region.start >= region.end {
                continue;
            }
            if end <= region.start || addr >= region.end {
                continue;
            }
            let next = GUEST_WRITE_OVERLAP_TRACE_NEXT as usize % GUEST_WRITE_OVERLAP_TRACE_CAP;
            GUEST_WRITE_OVERLAP_TRACE[next] = GuestWriteOverlapTraceEntry {
                slot: slot as u32,
                op,
                tid: GUEST_WRITE_CONTEXT_TID,
                pc: GUEST_WRITE_CONTEXT_PC,
                addr,
                len,
                sample_len,
                sample,
                execve_stage: current_execve_stage(),
            };
            GUEST_WRITE_OVERLAP_TRACE_NEXT = GUEST_WRITE_OVERLAP_TRACE_NEXT.wrapping_add(1);
            GUEST_WRITE_OVERLAP_TRACE_LEN =
                (GUEST_WRITE_OVERLAP_TRACE_LEN + 1).min(GUEST_WRITE_OVERLAP_TRACE_CAP as u32);
        }
    }
}

pub(crate) fn record_guest_range_permit_check(prot: u32, outcome: u32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (prot, outcome);
        return;
    }
    unsafe {
        let slot = memory_permit_prot_slot(prot);
        memory_permit_add(core::ptr::addr_of_mut!(MEMORY_PERMIT_CHECKS), 1);
        memory_permit_add(
            core::ptr::addr_of_mut!(MEMORY_PERMIT_CHECKS_BY_PROT[slot]),
            1,
        );
        match outcome {
            MEMORY_PERMIT_OUTCOME_CACHE_HIT => {
                memory_permit_add(core::ptr::addr_of_mut!(MEMORY_PERMIT_CACHE_HITS), 1);
                memory_permit_add(
                    core::ptr::addr_of_mut!(MEMORY_PERMIT_CACHE_HITS_BY_PROT[slot]),
                    1,
                );
            }
            MEMORY_PERMIT_OUTCOME_COVER_HIT => {
                memory_permit_add(core::ptr::addr_of_mut!(MEMORY_PERMIT_COVER_HITS), 1);
                memory_permit_add(
                    core::ptr::addr_of_mut!(MEMORY_PERMIT_COVER_HITS_BY_PROT[slot]),
                    1,
                );
            }
            MEMORY_PERMIT_OUTCOME_DENIED => {
                memory_permit_add(core::ptr::addr_of_mut!(MEMORY_PERMIT_DENIED), 1);
                memory_permit_add(
                    core::ptr::addr_of_mut!(MEMORY_PERMIT_DENIED_BY_PROT[slot]),
                    1,
                );
            }
            _ => {}
        }
    }
}

#[inline(always)]
pub(crate) fn guest_write_overlap_enabled() -> bool {
    if !RUNTIME_DEBUG_ENABLED {
        return false;
    }
    unsafe {
        for slot in 0..GUEST_WRITE_WATCH_CAP {
            let region = GUEST_WRITE_WATCH[slot];
            if region.start < region.end {
                return true;
            }
        }
    }
    false
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_trace_summary() -> MemoryTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return MemoryTraceSummary {
            nr: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            result: 0,
        };
    }
    unsafe { *core::ptr::addr_of!(MEMORY_TRACE) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(MEMORY_TRACE_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_trace_entry(index: u32) -> MemoryTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return MemoryTraceSummary {
            nr: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            result: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(MEMORY_TRACE_LEN));
        if index >= len {
            return MemoryTraceSummary {
                nr: 0,
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                result: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(MEMORY_TRACE_NEXT)) as usize;
        let len_usize = len as usize;
        let slot = if len_usize < MEMORY_TRACE_CAP {
            index as usize
        } else {
            (next + index as usize) % MEMORY_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(MEMORY_TRACE_RING[slot]))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn guest_write_overlap_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(GUEST_WRITE_OVERLAP_TRACE_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn guest_write_overlap_trace_entry(index: u32) -> GuestWriteOverlapTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return GuestWriteOverlapTraceEntry {
            slot: 0,
            op: 0,
            tid: 0,
            pc: 0,
            addr: 0,
            len: 0,
            sample_len: 0,
            sample: 0,
            execve_stage: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(GUEST_WRITE_OVERLAP_TRACE_LEN));
        if index >= len {
            return GuestWriteOverlapTraceEntry {
                slot: 0,
                op: 0,
                tid: 0,
                pc: 0,
                addr: 0,
                len: 0,
                sample_len: 0,
                sample: 0,
                execve_stage: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(GUEST_WRITE_OVERLAP_TRACE_NEXT)) as usize;
        let len_usize = len as usize;
        let slot = if len_usize < GUEST_WRITE_OVERLAP_TRACE_CAP {
            index as usize
        } else {
            (next + index as usize) % GUEST_WRITE_OVERLAP_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(GUEST_WRITE_OVERLAP_TRACE[slot]))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_permit_checks() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(MEMORY_PERMIT_CHECKS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_permit_cache_hits() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(MEMORY_PERMIT_CACHE_HITS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_permit_cover_hits() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(MEMORY_PERMIT_COVER_HITS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_permit_denied() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(MEMORY_PERMIT_DENIED)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_permit_checks_by_prot(prot: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe {
        core::ptr::read(core::ptr::addr_of!(
            MEMORY_PERMIT_CHECKS_BY_PROT[memory_permit_prot_slot(prot)]
        ))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_permit_cache_hits_by_prot(prot: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe {
        core::ptr::read(core::ptr::addr_of!(
            MEMORY_PERMIT_CACHE_HITS_BY_PROT[memory_permit_prot_slot(prot)]
        ))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_permit_cover_hits_by_prot(prot: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe {
        core::ptr::read(core::ptr::addr_of!(
            MEMORY_PERMIT_COVER_HITS_BY_PROT[memory_permit_prot_slot(prot)]
        ))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn memory_permit_denied_by_prot(prot: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe {
        core::ptr::read(core::ptr::addr_of!(
            MEMORY_PERMIT_DENIED_BY_PROT[memory_permit_prot_slot(prot)]
        ))
    }
}
