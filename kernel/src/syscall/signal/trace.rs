use crate::types::ThreadState;

#[derive(Clone, Copy)]
#[cfg_attr(not(any(test, feature = "harness")), allow(dead_code))]
struct SignalTrace {
    vm_ptr: u32,
    sig: u32,
    frame_base: u64,
    pc: u64,
    ra: u64,
    sp: u64,
    gp: u64,
    tp: u64,
    s11: u64,
}

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

static mut LAST_SIGNAL_DELIVERY: SignalTrace = SignalTrace {
    vm_ptr: 0,
    sig: 0,
    frame_base: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    gp: 0,
    tp: 0,
    s11: 0,
};
static mut LAST_SIGRETURN: SignalTrace = SignalTrace {
    vm_ptr: 0,
    sig: 0,
    frame_base: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    gp: 0,
    tp: 0,
    s11: 0,
};
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
static mut LAST_TRAMPOLINE_PC: u64 = 0;
static mut LAST_TRAMPOLINE_HIT_TID: i32 = 0;
static mut LAST_TRAMPOLINE_HIT_PC: u64 = 0;
static mut SIGRETURN_COUNT: u32 = 0;

const SIGNAL_TRACE_RING_CAP: usize = 32;

static mut SIGNAL_DELIVERY_RING: [SignalTrace; SIGNAL_TRACE_RING_CAP] = [SignalTrace {
    vm_ptr: 0,
    sig: 0,
    frame_base: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    gp: 0,
    tp: 0,
    s11: 0,
}; SIGNAL_TRACE_RING_CAP];
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
        LAST_SIGNAL_DELIVERY = SignalTrace {
            vm_ptr: 0,
            sig: 0,
            frame_base: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            gp: 0,
            tp: 0,
            s11: 0,
        };
        LAST_SIGRETURN = SignalTrace {
            vm_ptr: 0,
            sig: 0,
            frame_base: 0,
            pc: 0,
            ra: 0,
            sp: 0,
            gp: 0,
            tp: 0,
            s11: 0,
        };
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
        LAST_TRAMPOLINE_PC = 0;
        LAST_TRAMPOLINE_HIT_TID = 0;
        LAST_TRAMPOLINE_HIT_PC = 0;
        SIGRETURN_COUNT = 0;
        SIGNAL_DELIVERY_RING_LEN = 0;
        SIGNAL_DELIVERY_RING_NEXT = 0;
        DEFAULT_SIGNAL_RING_LEN = 0;
        DEFAULT_SIGNAL_RING_NEXT = 0;
    }
}

pub(super) fn record_default_signal(vm: &ThreadState, sig: usize) {
    #[cfg(any(test, feature = "harness"))]
    crate::harness::debug::snapshot_recent_exec_trace_for_vm(vm as *const ThreadState as u32);

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
) {
    unsafe {
        let trace = SignalTrace {
            vm_ptr: vm as *const ThreadState as u32,
            sig: sig as u32,
            frame_base,
            pc: vm.pc,
            ra: vm.x[1],
            sp: vm.x[2],
            gp: vm.x[3],
            tp: vm.x[4],
            s11: vm.x[27],
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
            frame_base,
            pc: vm.pc,
            ra: vm.x[1],
            sp: vm.x[2],
            gp: vm.x[3],
            tp: vm.x[4],
            s11: vm.x[27],
        };
        LAST_TRAMPOLINE_PC = 0;
        SIGRETURN_COUNT = SIGRETURN_COUNT.wrapping_add(1);
    }
}
