use super::RUNTIME_DEBUG_ENABLED;

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
