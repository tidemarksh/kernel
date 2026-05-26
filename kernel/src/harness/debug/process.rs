use super::RUNTIME_DEBUG_ENABLED;

static mut LAST_EXECVE_STAGE: u32 = 0;
static mut LAST_EXECVE_VALUE0: u64 = 0;
static mut LAST_EXECVE_VALUE1: u64 = 0;
static mut LAST_EXECVE_ERROR_ERRNO: i64 = 0;
static mut LAST_EXECVE_ERROR_STAGE: u32 = 0;
static mut LAST_EXECVE_ERROR_VALUE0: u64 = 0;
static mut LAST_EXECVE_ERROR_VALUE1: u64 = 0;
const EXECVE_STAGE_TRACE_CAP: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveStageTraceEntry {
    pub stage: u32,
    pub value0: u64,
    pub value1: u64,
}

static mut EXECVE_STAGE_TRACE: [ExecveStageTraceEntry; EXECVE_STAGE_TRACE_CAP] =
    [ExecveStageTraceEntry {
        stage: 0,
        value0: 0,
        value1: 0,
    }; EXECVE_STAGE_TRACE_CAP];
static mut EXECVE_STAGE_TRACE_LEN: u32 = 0;
static mut EXECVE_STAGE_TRACE_NEXT: u32 = 0;

pub(crate) fn record_execve_stage(stage: u32, value0: u64, value1: u64) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (stage, value0, value1);
        return;
    }
    unsafe {
        if stage == 0 {
            core::ptr::write(core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE_LEN), 0);
            core::ptr::write(core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE_NEXT), 0);
        }
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_STAGE), stage);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_VALUE0), value0);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_VALUE1), value1);
        let len = core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_LEN)) as usize;
        let next = core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_NEXT)) as usize;
        let slot = if len < EXECVE_STAGE_TRACE_CAP {
            len
        } else {
            next
        };
        core::ptr::write(
            core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE[slot]),
            ExecveStageTraceEntry {
                stage,
                value0,
                value1,
            },
        );
        if len < EXECVE_STAGE_TRACE_CAP {
            core::ptr::write(
                core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE_LEN),
                (len + 1) as u32,
            );
        } else {
            core::ptr::write(
                core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE_NEXT),
                ((next + 1) % EXECVE_STAGE_TRACE_CAP) as u32,
            );
        }
    }
}

pub(super) fn current_execve_stage() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_STAGE)) }
}

pub(crate) fn record_execve_error(errno: i64) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = errno;
        return;
    }
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_ERROR_ERRNO), errno);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_EXECVE_ERROR_STAGE),
            core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_STAGE)),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_EXECVE_ERROR_VALUE0),
            core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE0)),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_EXECVE_ERROR_VALUE1),
            core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE1)),
        );
    }
}

pub(crate) fn record_execve_approach(vm_ptr: u32, pc: u64, raw: u32) {
    let _ = (vm_ptr, pc, raw);
}

pub(crate) fn record_execve_dispatch(vm_ptr: u32, stage: u32) {
    let _ = (vm_ptr, stage);
}

pub(crate) fn record_execve_ecall(value0: u64, value1: u64) {
    let _ = (value0, value1);
}

pub(crate) fn record_execve_pre_dispatch(pc: u64, raw: u32, value0: u64, value1: u64) {
    let _ = (pc, raw, value0, value1);
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_stage() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_STAGE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_value0() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE0)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_value1() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE1)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_error_errno() -> i64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_ERROR_ERRNO)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_error_stage() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_ERROR_STAGE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_error_value0() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_ERROR_VALUE0)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_error_value1() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_ERROR_VALUE1)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_stage_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_stage_trace_entry(index: u32) -> ExecveStageTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return ExecveStageTraceEntry {
            stage: 0,
            value0: 0,
            value1: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_LEN));
        if index >= len {
            return ExecveStageTraceEntry {
                stage: 0,
                value0: 0,
                value1: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_NEXT)) as usize;
        let len_usize = len as usize;
        let slot = if len_usize < EXECVE_STAGE_TRACE_CAP {
            index as usize
        } else {
            (next + index as usize) % EXECVE_STAGE_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE[slot]))
    }
}
