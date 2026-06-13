use crate::abi::{FAULT_KIND_ILLEGAL_INSTRUCTION, SIGILL};
use crate::types::ThreadState;

const ILL_ILLOPC: i32 = 1;

#[derive(Clone, Copy)]
#[cfg_attr(not(any(test, feature = "harness")), allow(dead_code))]
struct SignalTrace {
    vm_ptr: u32,
    sig: u32,
    sig_info_code: i32,
    frame_base: u64,
    pc: u64,
    ra: u64,
    sp: u64,
    gp: u64,
    tp: u64,
    s11: u64,
    fault_pc: u64,
    fault_addr: u64,
}

const EMPTY_SIGNAL_TRACE: SignalTrace = SignalTrace {
    vm_ptr: 0,
    sig: 0,
    sig_info_code: 0,
    frame_base: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    gp: 0,
    tp: 0,
    s11: 0,
    fault_pc: 0,
    fault_addr: 0,
};

#[derive(Clone, Copy)]
#[cfg_attr(not(any(test, feature = "harness")), allow(dead_code))]
struct DefaultSignalTrace {
    vm_ptr: u32,
    sig: u32,
    sig_info_code: i32,
    pc: u64,
    ra: u64,
    sp: u64,
    gp: u64,
    tp: u64,
    s11: u64,
    fault_pc: u64,
    fault_addr: u64,
    arg_regs: [u64; 8],
}

#[derive(Clone, Copy)]
#[cfg_attr(not(any(test, feature = "harness")), allow(dead_code))]
struct IllegalInstructionTrace {
    vm_ptr: u32,
    pc: u64,
    raw: u32,
    ra: u64,
    sp: u64,
    a0: u64,
    a4: u64,
    s11: u64,
    jalr_pc: u64,
    jalr_rs1_value: u64,
    jalr_target: u64,
    jalr_rd: u32,
    jalr_rs1: u32,
    signal_frame_base: u64,
    signal_handler_pc: u64,
    signal_code: i32,
    signal_addr: u64,
    signal_uc_pc: u64,
    signal_uc_ra: u64,
    signal_uc_sp: u64,
    signal_uc_a0: u64,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(any(test, feature = "harness")), allow(dead_code))]
struct SignalSendTrace {
    caller_vm_ptr: u32,
    kind: u32,
    pid: i32,
    tid: i32,
    sig: i32,
    result: i64,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(any(test, feature = "harness")), allow(dead_code))]
struct SyncFaultTrace {
    vm_ptr: u32,
    tid: i32,
    pc: u64,
    ra: u64,
    sp: u64,
    s11: u64,
    a0: u64,
    arg_regs: [u64; 8],
    saved_regs: [u64; 7],
    addr: u64,
    code: i32,
}

static mut LAST_SIGNAL_DELIVERY: SignalTrace = EMPTY_SIGNAL_TRACE;
static mut LAST_SIGRETURN: SignalTrace = EMPTY_SIGNAL_TRACE;
static mut LAST_DEFAULT_SIGNAL: DefaultSignalTrace = DefaultSignalTrace {
    vm_ptr: 0,
    sig: 0,
    sig_info_code: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    gp: 0,
    tp: 0,
    s11: 0,
    fault_pc: 0,
    fault_addr: 0,
    arg_regs: [0; 8],
};
static mut LAST_ILLEGAL_INSTRUCTION: IllegalInstructionTrace = IllegalInstructionTrace {
    vm_ptr: 0,
    pc: 0,
    raw: 0,
    ra: 0,
    sp: 0,
    a0: 0,
    a4: 0,
    s11: 0,
    jalr_pc: 0,
    jalr_rs1_value: 0,
    jalr_target: 0,
    jalr_rd: 0,
    jalr_rs1: 0,
    signal_frame_base: 0,
    signal_handler_pc: 0,
    signal_code: 0,
    signal_addr: 0,
    signal_uc_pc: 0,
    signal_uc_ra: 0,
    signal_uc_sp: 0,
    signal_uc_a0: 0,
};
static mut LAST_SIGNAL_SEND: SignalSendTrace = SignalSendTrace {
    caller_vm_ptr: 0,
    kind: 0,
    pid: 0,
    tid: 0,
    sig: 0,
    result: 0,
};
static mut LAST_SYNC_FAULT: SyncFaultTrace = SyncFaultTrace {
    vm_ptr: 0,
    tid: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    s11: 0,
    a0: 0,
    arg_regs: [0; 8],
    saved_regs: [0; 7],
    addr: 0,
    code: 0,
};
static mut LAST_TRAMPOLINE_PC: u64 = 0;
static mut LAST_TRAMPOLINE_HIT_TID: i32 = 0;
static mut LAST_TRAMPOLINE_HIT_PC: u64 = 0;
static mut SIGRETURN_COUNT: u32 = 0;

const SIGNAL_TRACE_RING_CAP: usize = 32;

static mut SIGNAL_DELIVERY_RING: [SignalTrace; SIGNAL_TRACE_RING_CAP] =
    [EMPTY_SIGNAL_TRACE; SIGNAL_TRACE_RING_CAP];
static mut SIGNAL_DELIVERY_RING_LEN: u32 = 0;
static mut SIGNAL_DELIVERY_RING_NEXT: u32 = 0;

static mut DEFAULT_SIGNAL_RING: [DefaultSignalTrace; SIGNAL_TRACE_RING_CAP] = [DefaultSignalTrace {
    vm_ptr: 0,
    sig: 0,
    sig_info_code: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    gp: 0,
    tp: 0,
    s11: 0,
    fault_pc: 0,
    fault_addr: 0,
    arg_regs: [0; 8],
};
    SIGNAL_TRACE_RING_CAP];
static mut DEFAULT_SIGNAL_RING_LEN: u32 = 0;
static mut DEFAULT_SIGNAL_RING_NEXT: u32 = 0;

static mut SIGNAL_SEND_RING: [SignalSendTrace; SIGNAL_TRACE_RING_CAP] = [SignalSendTrace {
    caller_vm_ptr: 0,
    kind: 0,
    pid: 0,
    tid: 0,
    sig: 0,
    result: 0,
}; SIGNAL_TRACE_RING_CAP];
static mut SIGNAL_SEND_RING_LEN: u32 = 0;
static mut SIGNAL_SEND_RING_NEXT: u32 = 0;

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace() -> (u32, u64, u64, u64, u64, u64, u64, u64) {
    unsafe {
        let t = LAST_SIGNAL_DELIVERY;
        (t.sig, t.frame_base, t.pc, t.ra, t.sp, t.gp, t.tp, t.s11)
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_for_vm(
    vm_ptr: u32,
) -> (u32, u64, u64, u64, u64, u64, u64, u64) {
    unsafe {
        let len = SIGNAL_DELIVERY_RING_LEN.min(SIGNAL_TRACE_RING_CAP as u32);
        for offset in 0..len {
            let index = ((SIGNAL_DELIVERY_RING_NEXT + SIGNAL_TRACE_RING_CAP as u32 - 1 - offset)
                % SIGNAL_TRACE_RING_CAP as u32) as usize;
            let trace = SIGNAL_DELIVERY_RING[index];
            if trace.vm_ptr == vm_ptr {
                return (
                    trace.sig,
                    trace.frame_base,
                    trace.pc,
                    trace.ra,
                    trace.sp,
                    trace.gp,
                    trace.tp,
                    trace.s11,
                );
            }
        }
        (0, 0, 0, 0, 0, 0, 0, 0)
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_len() -> u32 {
    unsafe { SIGNAL_DELIVERY_RING_LEN.min(SIGNAL_TRACE_RING_CAP as u32) }
}

#[cfg(any(test, feature = "harness"))]
fn signal_delivery_trace_entry(index: u32) -> SignalTrace {
    unsafe {
        let len = SIGNAL_DELIVERY_RING_LEN.min(SIGNAL_TRACE_RING_CAP as u32);
        if index >= len {
            return EMPTY_SIGNAL_TRACE;
        }
        let start = (SIGNAL_DELIVERY_RING_NEXT + SIGNAL_TRACE_RING_CAP as u32 - len)
            % SIGNAL_TRACE_RING_CAP as u32;
        SIGNAL_DELIVERY_RING[((start + index) % SIGNAL_TRACE_RING_CAP as u32) as usize]
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_vm_ptr(index: u32) -> u32 {
    signal_delivery_trace_entry(index).vm_ptr
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_sig(index: u32) -> u32 {
    signal_delivery_trace_entry(index).sig
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_code(index: u32) -> i32 {
    signal_delivery_trace_entry(index).sig_info_code
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_frame_base(index: u32) -> u64 {
    signal_delivery_trace_entry(index).frame_base
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_pc(index: u32) -> u64 {
    signal_delivery_trace_entry(index).pc
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_ra(index: u32) -> u64 {
    signal_delivery_trace_entry(index).ra
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_sp(index: u32) -> u64 {
    signal_delivery_trace_entry(index).sp
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_s11(index: u32) -> u64 {
    signal_delivery_trace_entry(index).s11
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_fault_pc(index: u32) -> u64 {
    signal_delivery_trace_entry(index).fault_pc
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_delivery_trace_entry_fault_addr(index: u32) -> u64 {
    signal_delivery_trace_entry(index).fault_addr
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn sigreturn_trace() -> (u32, u64, u64, u64, u64, u64, u64, u64) {
    unsafe {
        let t = LAST_SIGRETURN;
        (t.sig, t.frame_base, t.pc, t.ra, t.sp, t.gp, t.tp, t.s11)
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn default_signal_trace() -> (u32, i32, u64, u64, u64, u64, u64, u64, u64, u64) {
    unsafe {
        let t = LAST_DEFAULT_SIGNAL;
        (
            t.sig,
            t.sig_info_code,
            t.pc,
            t.ra,
            t.sp,
            t.gp,
            t.tp,
            t.s11,
            t.fault_pc,
            t.fault_addr,
        )
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn default_signal_arg_regs() -> [u64; 8] {
    unsafe { LAST_DEFAULT_SIGNAL.arg_regs }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn default_signal_vm_ptr() -> u32 {
    unsafe { LAST_DEFAULT_SIGNAL.vm_ptr }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn illegal_instruction_trace() -> (u32, u64, u32) {
    unsafe {
        let t = LAST_ILLEGAL_INSTRUCTION;
        (t.vm_ptr, t.pc, t.raw)
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn illegal_instruction_context() -> (u64, u64, u64, u64, u64) {
    unsafe {
        let t = LAST_ILLEGAL_INSTRUCTION;
        (t.ra, t.sp, t.a0, t.a4, t.s11)
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn illegal_instruction_jalr() -> (u64, u64, u64, u32, u32) {
    unsafe {
        let t = LAST_ILLEGAL_INSTRUCTION;
        (
            t.jalr_pc,
            t.jalr_rs1_value,
            t.jalr_target,
            t.jalr_rd,
            t.jalr_rs1,
        )
    }
}

#[cfg(any(test, feature = "harness"))]
#[allow(clippy::type_complexity)]
pub(crate) fn illegal_instruction_signal_frame() -> (u64, u64, i32, u64, u64, u64, u64, u64) {
    unsafe {
        let t = LAST_ILLEGAL_INSTRUCTION;
        (
            t.signal_frame_base,
            t.signal_handler_pc,
            t.signal_code,
            t.signal_addr,
            t.signal_uc_pc,
            t.signal_uc_ra,
            t.signal_uc_sp,
            t.signal_uc_a0,
        )
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_send_trace() -> (u32, u32, i32, i32, i32, i64) {
    unsafe {
        let t = LAST_SIGNAL_SEND;
        (t.caller_vm_ptr, t.kind, t.pid, t.tid, t.sig, t.result)
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_send_trace_len() -> u32 {
    unsafe { SIGNAL_SEND_RING_LEN.min(SIGNAL_TRACE_RING_CAP as u32) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn signal_send_trace_entry(index: u32) -> (u32, u32, i32, i32, i32, i64) {
    unsafe {
        let len = SIGNAL_SEND_RING_LEN.min(SIGNAL_TRACE_RING_CAP as u32);
        if index >= len {
            return (0, 0, 0, 0, 0, 0);
        }
        let start = if len == SIGNAL_TRACE_RING_CAP as u32 {
            SIGNAL_SEND_RING_NEXT
        } else {
            0
        };
        let ring_index = ((start + index) % SIGNAL_TRACE_RING_CAP as u32) as usize;
        let t = SIGNAL_SEND_RING[ring_index];
        (t.caller_vm_ptr, t.kind, t.pid, t.tid, t.sig, t.result)
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn sync_fault_trace() -> (u32, i32, u64, u64, u64, u64, u64, u64, i32) {
    unsafe {
        let t = LAST_SYNC_FAULT;
        (
            t.vm_ptr, t.tid, t.pc, t.ra, t.sp, t.s11, t.a0, t.addr, t.code,
        )
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn sync_fault_arg_reg(index: u32) -> u64 {
    if index >= 8 {
        return 0;
    }
    unsafe { LAST_SYNC_FAULT.arg_regs[index as usize] }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn sync_fault_saved_reg(index: u32) -> u64 {
    if index == 0 || index > 7 {
        return 0;
    }
    unsafe { LAST_SYNC_FAULT.saved_regs[(index - 1) as usize] }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn trampoline_trace_state() -> (i32, u64, u32) {
    unsafe {
        (
            LAST_TRAMPOLINE_HIT_TID,
            LAST_TRAMPOLINE_HIT_PC,
            SIGRETURN_COUNT,
        )
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn reset_trace_state() {
    unsafe {
        LAST_SIGNAL_DELIVERY = EMPTY_SIGNAL_TRACE;
        LAST_SIGRETURN = EMPTY_SIGNAL_TRACE;
        LAST_DEFAULT_SIGNAL = DefaultSignalTrace {
            vm_ptr: 0,
            sig: 0,
            sig_info_code: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            gp: 0,
            tp: 0,
            s11: 0,
            fault_pc: 0,
            fault_addr: 0,
            arg_regs: [0; 8],
        };
        LAST_ILLEGAL_INSTRUCTION = IllegalInstructionTrace {
            vm_ptr: 0,
            pc: 0,
            raw: 0,
            ra: 0,
            sp: 0,
            a0: 0,
            a4: 0,
            s11: 0,
            jalr_pc: 0,
            jalr_rs1_value: 0,
            jalr_target: 0,
            jalr_rd: 0,
            jalr_rs1: 0,
            signal_frame_base: 0,
            signal_handler_pc: 0,
            signal_code: 0,
            signal_addr: 0,
            signal_uc_pc: 0,
            signal_uc_ra: 0,
            signal_uc_sp: 0,
            signal_uc_a0: 0,
        };
        LAST_SIGNAL_SEND = SignalSendTrace {
            caller_vm_ptr: 0,
            kind: 0,
            pid: 0,
            tid: 0,
            sig: 0,
            result: 0,
        };
        LAST_TRAMPOLINE_PC = 0;
        LAST_TRAMPOLINE_HIT_TID = 0;
        LAST_TRAMPOLINE_HIT_PC = 0;
        SIGRETURN_COUNT = 0;
        SIGNAL_DELIVERY_RING_LEN = 0;
        SIGNAL_DELIVERY_RING_NEXT = 0;
        DEFAULT_SIGNAL_RING_LEN = 0;
        DEFAULT_SIGNAL_RING_NEXT = 0;
        SIGNAL_SEND_RING_LEN = 0;
        SIGNAL_SEND_RING_NEXT = 0;
    }
}

pub(super) fn record_illegal_instruction(vm: &ThreadState, pc: u64, raw: u32) {
    unsafe {
        let vm_ptr = vm as *const ThreadState as u32;
        #[cfg(any(test, feature = "harness"))]
        crate::tracepoints::snapshot_recent_exec_trace_for_vm(vm_ptr);
        let (jalr_pc, jalr_rs1_value, jalr_target, jalr_rd, jalr_rs1) = {
            #[cfg(any(test, feature = "harness"))]
            {
                let jalr = crate::harness::debug::last_jalr_trace_for_vm(vm_ptr);
                (jalr.pc, jalr.rs1_value, jalr.target, jalr.rd, jalr.rs1)
            }
            #[cfg(not(any(test, feature = "harness")))]
            {
                (0, 0, 0, 0, 0)
            }
        };
        LAST_ILLEGAL_INSTRUCTION = IllegalInstructionTrace {
            vm_ptr,
            pc,
            raw,
            ra: vm.x[1],
            sp: vm.x[2],
            a0: vm.x[10],
            a4: vm.x[14],
            s11: vm.x[27],
            jalr_pc,
            jalr_rs1_value,
            jalr_target,
            jalr_rd,
            jalr_rs1,
            signal_frame_base: 0,
            signal_handler_pc: 0,
            signal_code: 0,
            signal_addr: 0,
            signal_uc_pc: 0,
            signal_uc_ra: 0,
            signal_uc_sp: 0,
            signal_uc_a0: 0,
        };
    }
}

pub(super) fn record_signal_send(
    vm: &ThreadState,
    kind: u32,
    pid: i32,
    tid: i32,
    sig: i32,
    result: i64,
) {
    unsafe {
        let trace = SignalSendTrace {
            caller_vm_ptr: vm as *const ThreadState as u32,
            kind,
            pid,
            tid,
            sig,
            result,
        };
        LAST_SIGNAL_SEND = trace;
        SIGNAL_SEND_RING[SIGNAL_SEND_RING_NEXT as usize] = trace;
        SIGNAL_SEND_RING_NEXT = (SIGNAL_SEND_RING_NEXT + 1) % SIGNAL_TRACE_RING_CAP as u32;
        if SIGNAL_SEND_RING_LEN < SIGNAL_TRACE_RING_CAP as u32 {
            SIGNAL_SEND_RING_LEN += 1;
        }
    }
}

pub(super) fn record_default_signal(vm: &ThreadState, sig: usize) {
    #[cfg(any(test, feature = "harness"))]
    crate::tracepoints::snapshot_recent_exec_trace_for_vm(vm as *const ThreadState as u32);

    let trace = DefaultSignalTrace {
        vm_ptr: vm as *const ThreadState as u32,
        sig: sig as u32,
        sig_info_code: vm.sig_info_code,
        pc: vm.pc,
        ra: vm.x[1],
        sp: vm.x[2],
        gp: vm.x[3],
        tp: vm.x[4],
        s11: vm.x[27],
        fault_pc: vm.fault_pc,
        fault_addr: vm.fault_addr,
        arg_regs: [
            vm.x[10], vm.x[11], vm.x[12], vm.x[13], vm.x[14], vm.x[15], vm.x[16], vm.x[17],
        ],
    };
    unsafe {
        LAST_DEFAULT_SIGNAL = trace;
        DEFAULT_SIGNAL_RING[DEFAULT_SIGNAL_RING_NEXT as usize] = trace;
        DEFAULT_SIGNAL_RING_NEXT = (DEFAULT_SIGNAL_RING_NEXT + 1) % SIGNAL_TRACE_RING_CAP as u32;
        if DEFAULT_SIGNAL_RING_LEN < SIGNAL_TRACE_RING_CAP as u32 {
            DEFAULT_SIGNAL_RING_LEN += 1;
        }
    }
}

pub(super) fn record_sync_fault(vm: &ThreadState, pc: u64, addr: u64, code: i32) {
    unsafe {
        LAST_SYNC_FAULT = SyncFaultTrace {
            vm_ptr: vm as *const ThreadState as u32,
            tid: vm.tid,
            pc,
            ra: vm.x[1],
            sp: vm.x[2],
            s11: vm.x[27],
            a0: vm.x[10],
            arg_regs: [
                vm.x[10], vm.x[11], vm.x[12], vm.x[13], vm.x[14], vm.x[15], vm.x[16], vm.x[17],
            ],
            saved_regs: [
                vm.x[9], vm.x[18], vm.x[19], vm.x[20], vm.x[21], vm.x[22], vm.x[23],
            ],
            addr,
            code,
        };
    }
}

#[inline(always)]
pub fn note_pc(vm: &ThreadState, pc: u64) {
    unsafe {
        if LAST_TRAMPOLINE_PC != 0 && pc == LAST_TRAMPOLINE_PC {
            LAST_TRAMPOLINE_HIT_TID = vm.tid;
            LAST_TRAMPOLINE_HIT_PC = pc;
        }
    }
}

pub(super) fn record_signal_delivery_trace(
    vm: &ThreadState,
    sig: usize,
    frame_base: u64,
    trampoline_pc: u64,
    handler_pc: u64,
) {
    unsafe {
        if sig as i32 == SIGILL
            && vm.fault_kind == FAULT_KIND_ILLEGAL_INSTRUCTION
            && vm.sig_info_code == ILL_ILLOPC
        {
            LAST_ILLEGAL_INSTRUCTION.signal_frame_base = frame_base;
            LAST_ILLEGAL_INSTRUCTION.signal_handler_pc = handler_pc;
            LAST_ILLEGAL_INSTRUCTION.signal_code = vm.sig_info_code;
            LAST_ILLEGAL_INSTRUCTION.signal_addr = vm.fault_addr;
            LAST_ILLEGAL_INSTRUCTION.signal_uc_pc = vm.pc;
            LAST_ILLEGAL_INSTRUCTION.signal_uc_ra = vm.x[1];
            LAST_ILLEGAL_INSTRUCTION.signal_uc_sp = vm.x[2];
            LAST_ILLEGAL_INSTRUCTION.signal_uc_a0 = vm.x[10];
        }
        let trace = SignalTrace {
            vm_ptr: vm as *const ThreadState as u32,
            sig: sig as u32,
            sig_info_code: vm.sig_info_code,
            frame_base,
            pc: vm.pc,
            ra: vm.x[1],
            sp: vm.x[2],
            gp: vm.x[3],
            tp: vm.x[4],
            s11: vm.x[27],
            fault_pc: vm.fault_pc,
            fault_addr: vm.fault_addr,
        };
        LAST_SIGNAL_DELIVERY = trace;
        SIGNAL_DELIVERY_RING[SIGNAL_DELIVERY_RING_NEXT as usize] = trace;
        SIGNAL_DELIVERY_RING_NEXT = (SIGNAL_DELIVERY_RING_NEXT + 1) % SIGNAL_TRACE_RING_CAP as u32;
        if SIGNAL_DELIVERY_RING_LEN < SIGNAL_TRACE_RING_CAP as u32 {
            SIGNAL_DELIVERY_RING_LEN += 1;
        }
        LAST_TRAMPOLINE_PC = trampoline_pc;
    }
}

pub(super) fn record_sigreturn_trace(vm: &ThreadState, frame_base: u64) {
    unsafe {
        LAST_SIGRETURN = SignalTrace {
            vm_ptr: vm as *const ThreadState as u32,
            sig: 0,
            sig_info_code: 0,
            frame_base,
            pc: vm.pc,
            ra: vm.x[1],
            sp: vm.x[2],
            gp: vm.x[3],
            tp: vm.x[4],
            s11: vm.x[27],
            fault_pc: vm.fault_pc,
            fault_addr: vm.fault_addr,
        };
        LAST_TRAMPOLINE_PC = 0;
        SIGRETURN_COUNT = SIGRETURN_COUNT.wrapping_add(1);
    }
}
