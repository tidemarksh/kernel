use super::{
    actions::sigactions_for,
    defaults,
    frame::push_signal_frame,
    pending::{
        peek_thread_pending_signals, pid_from_vm, process_pending, take_thread_pending_signals,
    },
};
use crate::abi::*;
use crate::types::{MAX_SIGNALS, SIG_DFL, SIG_IGN, SigAction, ThreadState};

const SA_RESTART: u64 = 0x10000000;

const SYNC_FAULT_SIGNAL_MASK: u64 = (1u64 << (SIGILL - 1))
    | (1u64 << (SIGBUS - 1))
    | (1u64 << (SIGFPE - 1))
    | (1u64 << (SIGSEGV - 1));

fn process_pending_bits_for_vm(vm: &ThreadState, base: u32) -> u64 {
    let pid = pid_from_vm(vm, base);
    if pid <= 0 {
        return 0;
    }
    let idx = (pid - 1) as usize;
    if idx < MAX_PROCESSES {
        process_pending()[idx]
    } else {
        0
    }
}

pub fn pending_signal_snapshot(vm: &ThreadState, base: u32) -> (u64, u64, u64, u64) {
    let thread_pending = vm.sig_pending;
    let record_pending = peek_thread_pending_signals(vm, base);
    let process_pending = process_pending_bits_for_vm(vm, base);
    let synchronous = if vm.sig_info_code > 0 {
        vm.sig_pending & SYNC_FAULT_SIGNAL_MASK
    } else {
        0
    };
    let deliverable =
        ((thread_pending | record_pending | process_pending) & !vm.sig_mask) | synchronous;
    (thread_pending, process_pending, record_pending, deliverable)
}

pub fn pending_signal_interrupts_blocked_syscall(vm: &ThreadState, base: u32) -> bool {
    let pid = pid_from_vm(vm, base);
    let mut pending = vm.sig_pending | peek_thread_pending_signals(vm, base);
    if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            pending |= process_pending()[idx];
        }
    }

    let deliverable = pending & !vm.sig_mask;
    if deliverable == 0 {
        return false;
    }

    let sig = deliverable.trailing_zeros() as usize + 1;
    if sig >= MAX_SIGNALS {
        return false;
    }

    let action = sigactions_for(pid)
        .map(|table| table[sig])
        .unwrap_or(SigAction {
            handler: SIG_DFL,
            flags: 0,
            mask: 0,
        });

    match action.handler {
        SIG_IGN => false,
        SIG_DFL => defaults::default_action_interrupts_blocked_syscall(sig),
        _ => (action.flags & SA_RESTART) == 0,
    }
}

/// Check and deliver pending signals at syscall return boundary.
/// Called after each syscall returns. Returns true if a signal was delivered.
pub fn check_pending(vm: &mut ThreadState, base: u32) -> bool {
    check_pending_at_boundary(
        vm,
        base,
        crate::supervisor::SUPERVISOR_SIGNAL_BOUNDARY_SYSCALL_RETURN,
    )
}

/// Check and deliver pending signals at the supervisor-described boundary.
pub fn check_pending_at_boundary(vm: &mut ThreadState, base: u32, boundary: u32) -> bool {
    let pid = pid_from_vm(vm, base);
    let process_pending_bits = process_pending_bits_for_vm(vm, base);
    let thread_pending_before = vm.sig_pending;
    let record_pending_bits = peek_thread_pending_signals(vm, base);
    let process_pending_deliverable = process_pending_bits & !vm.sig_mask;
    // Process-directed signals remain pending for the process until a thread
    // that does not block the signal actually accepts delivery. Do not move
    // blocked process-pending signals into this thread.
    take_thread_pending_signals(vm, base);

    let synchronous = if vm.sig_info_code > 0 {
        vm.sig_pending & SYNC_FAULT_SIGNAL_MASK
    } else {
        0
    };
    let thread_pending_deliverable = vm.sig_pending & !vm.sig_mask;
    let deliverable = thread_pending_deliverable | process_pending_deliverable | synchronous;
    if deliverable == 0 {
        return false;
    }

    // Find lowest pending unblocked signal
    let sig = deliverable.trailing_zeros() as usize + 1;
    if sig >= MAX_SIGNALS {
        return false;
    }
    crate::supervisor::record_signal_control(
        crate::supervisor::SUPERVISOR_SIGNAL_CONTROL_KIND_BOUNDARY_CHECK,
        vm,
        base,
        sig as u32,
        boundary,
        thread_pending_before,
        process_pending_bits,
        record_pending_bits,
        deliverable,
        0,
        0,
    );

    // Clear from the pending set that supplied this delivery. Prefer
    // thread-directed pending state when both sets contain the same standard
    // signal, matching the fact that thread and process pending sets are
    // separate.
    let bit = 1u64 << (sig - 1);
    if (thread_pending_deliverable | synchronous) & bit != 0 {
        vm.sig_pending &= !bit;
    } else if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            process_pending()[idx] &= !bit;
        }
    }

    let action = sigactions_for(pid)
        .map(|table| table[sig])
        .unwrap_or(SigAction {
            handler: SIG_DFL,
            flags: 0,
            mask: 0,
        });

    match action.handler {
        0 => defaults::apply_default_action(vm, base, sig),
        1 => {} // SIG_IGN: ignore
        _handler_addr => {
            // User handler: push signal frame and redirect to handler
            if !push_signal_frame(vm, base, sig, &action) {
                defaults::terminate_with_default_action(vm, base, sig);
            }
        }
    }
    crate::supervisor::record_signal_control(
        crate::supervisor::SUPERVISOR_SIGNAL_CONTROL_KIND_SIGNAL_DELIVERED,
        vm,
        base,
        sig as u32,
        boundary,
        thread_pending_before,
        process_pending_bits,
        record_pending_bits,
        deliverable,
        action.handler,
        action.flags,
    );

    vm.sig_info_code = 0;

    true
}
