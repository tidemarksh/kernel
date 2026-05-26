mod fd;
mod memory;
mod process;
mod signal;
mod socket;
mod thread;

pub use fd::{FdSyscallTraceEntry, PathSyscallTraceEntry};
pub(crate) use fd::{
    fd_syscall_trace_entry, fd_syscall_trace_len, path_syscall_trace_entry, path_syscall_trace_len,
    path_syscall_trace_path_ptr, record_fd_syscall, record_path_syscall, record_pipe_close_event,
    record_write_attempt,
};
pub use memory::{GuestWriteOverlapTraceEntry, GuestWriteWatchRegion, MemoryTraceSummary};
pub(crate) use memory::{
    clear_guest_write_watch_trace, clear_memory_trace, configure_guest_write_watch,
    guest_write_overlap_enabled, guest_write_overlap_trace_entry, guest_write_overlap_trace_len,
    memory_permit_cache_hits, memory_permit_cache_hits_by_prot, memory_permit_checks,
    memory_permit_checks_by_prot, memory_permit_cover_hits, memory_permit_cover_hits_by_prot,
    memory_permit_denied, memory_permit_denied_by_prot, memory_trace_entry, memory_trace_len,
    memory_trace_summary, record_guest_range_permit_check, record_guest_write_overlap,
    record_memory_syscall,
};
pub(crate) use process::*;
pub use process::{ExecveStageTraceEntry, RiscvSyscallTraceEntry, SyscallTraceSummary};
pub(crate) use signal::record_sync_signal_trace;
pub(crate) use socket::record_epoll_wait;
pub use thread::BlockMissSample;
pub(crate) use thread::*;

const RUNTIME_DEBUG_ENABLED: bool = cfg!(any(test, feature = "harness"));

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
const THREAD_STEP_TRACE_CAP: usize = 64;
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
        for offset in 0..THREAD_STEP_VM_TRACE_CAP {
            let index = THREAD_STEP_VM_TRACE_CAP - 1 - offset;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_thread_state(
        tid: i32,
        status: i32,
        pc: u64,
        ra: u64,
        sp: u64,
        s11: u64,
    ) -> crate::types::ThreadState {
        let mut vm: crate::types::ThreadState = unsafe { core::mem::zeroed() };
        vm.tid = tid;
        vm.status = status;
        vm.pc = pc;
        vm.x[1] = ra;
        vm.x[2] = sp;
        vm.x[27] = s11;
        vm
    }

    #[test]
    fn last_thread_step_trace_for_vm_scans_recent_ring() {
        clear_cpu_trace();

        let vm1 = make_thread_state(1, 0, 0x111, 0x211, 0x311, 0x411);
        let vm2 = make_thread_state(2, 3, 0x122, 0x222, 0x322, 0x422);
        let vm1_ptr = &vm1 as *const crate::types::ThreadState as u32;
        let vm2_ptr = &vm2 as *const crate::types::ThreadState as u32;

        record_thread_step_trace(&vm1, 20000, 19999);
        record_thread_step_trace(&vm2, 20000, 19998);

        let vm1_entry = last_thread_step_trace_for_vm(vm1_ptr);
        assert_eq!(vm1_entry.vm_ptr, vm1_ptr);
        assert_eq!(vm1_entry.tid, 1);
        assert_eq!(vm1_entry.pc, 0x111);
        assert_eq!(vm1_entry.ra, 0x211);
        assert_eq!(vm1_entry.sp, 0x311);
        assert_eq!(vm1_entry.s11, 0x411);

        let vm2_entry = last_thread_step_trace_for_vm(vm2_ptr);
        assert_eq!(vm2_entry.vm_ptr, vm2_ptr);
        assert_eq!(vm2_entry.tid, 2);
        assert_eq!(vm2_entry.pc, 0x122);
        assert_eq!(vm2_entry.ra, 0x222);
        assert_eq!(vm2_entry.sp, 0x322);
        assert_eq!(vm2_entry.s11, 0x422);
    }

    #[test]
    fn clear_cpu_trace_resets_thread_step_ring() {
        clear_cpu_trace();

        let vm = make_thread_state(3, 0, 0x144, 0x244, 0x344, 0x444);
        let vm_ptr = &vm as *const crate::types::ThreadState as u32;
        record_thread_step_trace(&vm, 20000, 19997);
        assert_eq!(last_thread_step_trace_for_vm(vm_ptr).tid, 3);

        clear_cpu_trace();
        let cleared = last_thread_step_trace_for_vm(vm_ptr);
        assert_eq!(cleared.vm_ptr, 0);
        assert_eq!(cleared.tid, 0);
        assert_eq!(cleared.pc, 0);
    }

    #[test]
    fn last_thread_step_trace_for_vm_survives_recent_ring_churn() {
        clear_cpu_trace();

        let target = make_thread_state(3, 0, 0x144, 0x244, 0x344, 0x444);
        let target_ptr = &target as *const crate::types::ThreadState as u32;
        record_thread_step_trace(&target, 20000, 19997);

        for index in 0..(THREAD_STEP_TRACE_CAP + 8) {
            let vm = make_thread_state(
                10 + index as i32,
                0,
                0x1000 + index as u64,
                0x2000 + index as u64,
                0x3000 + index as u64,
                0x4000 + index as u64,
            );
            record_thread_step_trace(&vm, 20000, 19996 - index as i32);
        }

        let entry = last_thread_step_trace_for_vm(target_ptr);
        assert_eq!(entry.vm_ptr, target_ptr);
        assert_eq!(entry.tid, 3);
        assert_eq!(entry.pc, 0x144);
        assert_eq!(entry.ra, 0x244);
        assert_eq!(entry.sp, 0x344);
        assert_eq!(entry.s11, 0x444);
    }

    #[test]
    fn memory_trace_ring_keeps_recent_entries() {
        clear_memory_trace();

        record_memory_syscall(crate::abi::SYS_MMAP, 0x1000, 0x2000, 3, 0x22, 0x1000);
        record_memory_syscall(crate::abi::SYS_MPROTECT, 0x3000, 0x1000, 5, 0, 0);

        assert_eq!(memory_trace_len(), 2);
        let first = memory_trace_entry(0);
        assert_eq!(first.nr, crate::abi::SYS_MMAP);
        assert_eq!(first.arg0, 0x1000);
        assert_eq!(first.arg1, 0x2000);
        assert_eq!(first.arg2, 3);
        assert_eq!(first.arg3, 0x22);
        assert_eq!(first.result, 0x1000);

        let second = memory_trace_entry(1);
        assert_eq!(second.nr, crate::abi::SYS_MPROTECT);
        assert_eq!(second.arg0, 0x3000);
        assert_eq!(second.arg1, 0x1000);
        assert_eq!(second.arg2, 5);
        assert_eq!(second.result, 0);

        clear_memory_trace();
        assert_eq!(memory_trace_len(), 0);
    }

    #[test]
    fn last_thread_step_entry_trace_for_vm_survives_recent_ring_churn() {
        clear_cpu_trace();

        let target = make_thread_state(4, 20, 0x83336, 0x4d9b4, 0x37d6c000, 0xbfdc80);
        let target_ptr = &target as *const crate::types::ThreadState as u32;
        record_thread_step_entry_trace(&target, 20000);

        for index in 0..(THREAD_STEP_TRACE_CAP + 8) {
            let vm = make_thread_state(
                20 + index as i32,
                0,
                0x5000 + index as u64,
                0x6000 + index as u64,
                0x7000 + index as u64,
                0x8000 + index as u64,
            );
            record_thread_step_entry_trace(&vm, 20000 - index as i32);
        }

        let entry = last_thread_step_entry_trace_for_vm(target_ptr);
        assert_eq!(entry.vm_ptr, target_ptr);
        assert_eq!(entry.tid, 4);
        assert_eq!(entry.status, 20);
        assert_eq!(entry.pc, 0x83336);
        assert_eq!(entry.ra, 0x4d9b4);
        assert_eq!(entry.sp, 0x37d6c000);
        assert_eq!(entry.s11, 0xbfdc80);
    }

    #[test]
    fn last_thread_step_phase_for_vm_uses_direct_slot() {
        clear_cpu_trace();

        let vm = make_thread_state(5, 20, 0x83336, 0x4d9b4, 0x37d6c000, 0xbfdc80);
        let vm_ptr = &vm as *const crate::types::ThreadState as u32;
        record_thread_step_phase(&vm, 3, 20000, 0);

        let entry = last_thread_step_phase_for_vm(vm_ptr);
        assert_eq!(entry.vm_ptr, vm_ptr);
        assert_eq!(entry.tid, 5);
        assert_eq!(entry.phase, 3);
        assert_eq!(entry.status, 20);
        assert_eq!(entry.budget, 20000);
        assert_eq!(entry.pc, 0x83336);
        assert_eq!(entry.ra, 0x4d9b4);
        assert_eq!(entry.sp, 0x37d6c000);
        assert_eq!(entry.s11, 0xbfdc80);
    }
}
