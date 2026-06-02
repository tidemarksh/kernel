use crate::types::ThreadState;

const RELEASE_EXEC_TRACE_CAP: usize = 32;

#[derive(Clone, Copy)]
pub struct ReleaseExecTraceEntry {
    pub vm_ptr: u32,
    pub tid: i32,
    pub pc: u64,
    pub raw: u32,
    pub step: u32,
    pub ra: u64,
    pub sp: u64,
    pub a0: u64,
    pub a1: u64,
    pub a7: u64,
    pub s11: u64,
}

#[derive(Clone, Copy)]
pub struct ReleaseExecMismatchTraceEntry {
    pub vm_ptr: u32,
    pub tid: i32,
    pub pc: u64,
    pub raw: u32,
    pub step: u32,
    pub mem_sample: u64,
    pub mem_sample_len: u32,
    pub file_sample: u64,
    pub file_sample_len: u32,
    pub vma_start: u64,
    pub vma_end: u64,
    pub vma_prot: i32,
    pub vma_fd: i32,
    pub vma_offset: u64,
}

#[derive(Clone, Copy)]
pub struct ReleaseDefaultSignalTrace {
    pub sig: u32,
    pub code: i32,
    pub vm_ptr: u32,
    pub pc: u64,
    pub ra: u64,
    pub sp: u64,
    pub gp: u64,
    pub tp: u64,
    pub s11: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
    pub a7: u64,
    pub fault_pc: u64,
    pub fault_addr: u64,
    pub pending: u64,
}

const EMPTY_EXEC_ENTRY: ReleaseExecTraceEntry = ReleaseExecTraceEntry {
    vm_ptr: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    step: 0,
    ra: 0,
    sp: 0,
    a0: 0,
    a1: 0,
    a7: 0,
    s11: 0,
};

const EMPTY_EXEC_MISMATCH: ReleaseExecMismatchTraceEntry = ReleaseExecMismatchTraceEntry {
    vm_ptr: 0,
    tid: 0,
    pc: 0,
    raw: 0,
    step: 0,
    mem_sample: 0,
    mem_sample_len: 0,
    file_sample: 0,
    file_sample_len: 0,
    vma_start: 0,
    vma_end: 0,
    vma_prot: 0,
    vma_fd: 0,
    vma_offset: 0,
};

const EMPTY_DEFAULT_SIGNAL: ReleaseDefaultSignalTrace = ReleaseDefaultSignalTrace {
    sig: 0,
    code: 0,
    vm_ptr: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    gp: 0,
    tp: 0,
    s11: 0,
    a0: 0,
    a1: 0,
    a2: 0,
    a3: 0,
    a4: 0,
    a5: 0,
    a6: 0,
    a7: 0,
    fault_pc: 0,
    fault_addr: 0,
    pending: 0,
};

static mut RELEASE_EXEC_TRACE_ENABLED: u32 = 0;
static mut RELEASE_EXEC_TRACE: [ReleaseExecTraceEntry; RELEASE_EXEC_TRACE_CAP] =
    [EMPTY_EXEC_ENTRY; RELEASE_EXEC_TRACE_CAP];
static mut RELEASE_EXEC_TRACE_LEN: u32 = 0;
static mut RELEASE_EXEC_TRACE_CURSOR: u32 = 0;
static mut RELEASE_EXEC_MISMATCH_TRACE: [ReleaseExecMismatchTraceEntry; RELEASE_EXEC_TRACE_CAP] =
    [EMPTY_EXEC_MISMATCH; RELEASE_EXEC_TRACE_CAP];
static mut RELEASE_EXEC_MISMATCH_TRACE_LEN: u32 = 0;
static mut RELEASE_DEFAULT_SIGNAL: ReleaseDefaultSignalTrace = EMPTY_DEFAULT_SIGNAL;

pub fn debug_set_release_exec_trace_enabled(enabled: u32) {
    unsafe {
        RELEASE_EXEC_TRACE_ENABLED = if enabled == 0 { 0 } else { 1 };
    }
}

pub fn debug_clear_release_exec_trace() {
    unsafe {
        RELEASE_EXEC_TRACE = [EMPTY_EXEC_ENTRY; RELEASE_EXEC_TRACE_CAP];
        RELEASE_EXEC_TRACE_LEN = 0;
        RELEASE_EXEC_TRACE_CURSOR = 0;
        RELEASE_EXEC_MISMATCH_TRACE = [EMPTY_EXEC_MISMATCH; RELEASE_EXEC_TRACE_CAP];
        RELEASE_EXEC_MISMATCH_TRACE_LEN = 0;
        RELEASE_DEFAULT_SIGNAL = EMPTY_DEFAULT_SIGNAL;
    }
}

#[inline(always)]
fn sample_guest_instruction(vm: &ThreadState, pc: u64, step: u64) -> Option<(u64, u32)> {
    match step {
        2 => Some((
            unsafe { crate::guest_mem::read_u16_seqlock(vm.guest_base, pc) as u64 },
            2,
        )),
        4 => Some((
            unsafe { crate::guest_mem::read_u32_seqlock(vm.guest_base, pc) as u64 },
            4,
        )),
        _ => None,
    }
}

#[inline(always)]
fn low_bytes_mask(len: u32) -> u64 {
    if len >= 8 {
        u64::MAX
    } else {
        (1u64 << (len * 8)) - 1
    }
}

fn record_exec_mismatch(vm: &ThreadState, pc: u64, raw: u32, step: u64) {
    unsafe {
        if RELEASE_EXEC_MISMATCH_TRACE_LEN >= RELEASE_EXEC_TRACE_CAP as u32 {
            return;
        }
    }
    let Some((mem_sample, mem_sample_len)) = sample_guest_instruction(vm, pc, step) else {
        return;
    };
    let vma_len = crate::syscall::memory::address_space_vma_len();
    for index in 0..vma_len {
        let prot = crate::syscall::memory::address_space_vma_prot(index);
        if (prot & crate::abi::PROT_EXEC) == 0 {
            continue;
        }
        let vma_start = crate::syscall::memory::address_space_vma_start(index);
        let vma_end = crate::syscall::memory::address_space_vma_end(index);
        if pc < vma_start || pc >= vma_end {
            continue;
        }
        let vma_fd = crate::syscall::memory::address_space_vma_fd(index);
        if vma_fd < 0 {
            return;
        }
        let file_sample_len = crate::syscall::memory::address_space_vma_file_sample_len(index, pc);
        if file_sample_len < mem_sample_len {
            return;
        }
        let file_sample = crate::syscall::memory::address_space_vma_file_sample(index, pc);
        let mask = low_bytes_mask(mem_sample_len);
        if (mem_sample & mask) == (file_sample & mask) {
            return;
        }
        unsafe {
            let slot = RELEASE_EXEC_MISMATCH_TRACE_LEN as usize;
            RELEASE_EXEC_MISMATCH_TRACE[slot] = ReleaseExecMismatchTraceEntry {
                vm_ptr: vm as *const ThreadState as u32,
                tid: vm.tid,
                pc,
                raw,
                step: step as u32,
                mem_sample,
                mem_sample_len,
                file_sample,
                file_sample_len,
                vma_start,
                vma_end,
                vma_prot: prot,
                vma_fd,
                vma_offset: crate::syscall::memory::address_space_vma_offset(index),
            };
            RELEASE_EXEC_MISMATCH_TRACE_LEN += 1;
        }
        return;
    }
}

#[inline(always)]
pub fn record_exec(vm: &ThreadState, pc: u64, raw: u32, step: u64, x: &[u64; 32]) {
    unsafe {
        if RELEASE_EXEC_TRACE_ENABLED == 0 {
            return;
        }
        let cursor = RELEASE_EXEC_TRACE_CURSOR as usize % RELEASE_EXEC_TRACE_CAP;
        RELEASE_EXEC_TRACE[cursor] = ReleaseExecTraceEntry {
            vm_ptr: vm as *const ThreadState as u32,
            tid: vm.tid,
            pc,
            raw,
            step: step as u32,
            ra: x[1],
            sp: x[2],
            a0: x[10],
            a1: x[11],
            a7: x[17],
            s11: x[27],
        };
        RELEASE_EXEC_TRACE_CURSOR = RELEASE_EXEC_TRACE_CURSOR.wrapping_add(1);
        if RELEASE_EXEC_TRACE_LEN < RELEASE_EXEC_TRACE_CAP as u32 {
            RELEASE_EXEC_TRACE_LEN += 1;
        }
    }
    record_exec_mismatch(vm, pc, raw, step);
}

pub fn record_default_signal(vm: &ThreadState, sig: usize) {
    unsafe {
        if RELEASE_EXEC_TRACE_ENABLED == 0 {
            return;
        }
        RELEASE_DEFAULT_SIGNAL = ReleaseDefaultSignalTrace {
            sig: sig as u32,
            code: vm.sig_info_code,
            vm_ptr: vm as *const ThreadState as u32,
            pc: vm.pc,
            ra: vm.x[1],
            sp: vm.x[2],
            gp: vm.x[3],
            tp: vm.x[4],
            s11: vm.x[27],
            a0: vm.x[10],
            a1: vm.x[11],
            a2: vm.x[12],
            a3: vm.x[13],
            a4: vm.x[14],
            a5: vm.x[15],
            a6: vm.x[16],
            a7: vm.x[17],
            fault_pc: vm.fault_pc,
            fault_addr: vm.fault_addr,
            pending: vm.sig_pending,
        };
    }
}

pub fn debug_release_exec_trace_len() -> u32 {
    unsafe { RELEASE_EXEC_TRACE_LEN }
}

pub fn debug_release_exec_trace_entry(index: u32) -> ReleaseExecTraceEntry {
    unsafe {
        let len = RELEASE_EXEC_TRACE_LEN.min(RELEASE_EXEC_TRACE_CAP as u32);
        if index >= len {
            return EMPTY_EXEC_ENTRY;
        }
        let start = RELEASE_EXEC_TRACE_CURSOR.wrapping_sub(len);
        let slot = start.wrapping_add(index) as usize % RELEASE_EXEC_TRACE_CAP;
        RELEASE_EXEC_TRACE[slot]
    }
}

pub fn debug_release_exec_mismatch_trace_len() -> u32 {
    unsafe { RELEASE_EXEC_MISMATCH_TRACE_LEN }
}

pub fn debug_release_exec_mismatch_trace_entry(index: u32) -> ReleaseExecMismatchTraceEntry {
    unsafe {
        if index >= RELEASE_EXEC_MISMATCH_TRACE_LEN.min(RELEASE_EXEC_TRACE_CAP as u32) {
            return EMPTY_EXEC_MISMATCH;
        }
        RELEASE_EXEC_MISMATCH_TRACE[index as usize]
    }
}

pub fn debug_release_default_signal() -> ReleaseDefaultSignalTrace {
    unsafe { RELEASE_DEFAULT_SIGNAL }
}
