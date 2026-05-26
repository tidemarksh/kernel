use super::trace::record_default_signal;
use crate::abi::{SIGCHLD, SIGCONT, SIGURG, SIGWINCH};
use crate::types::ThreadState;

fn default_action_is_ignore(sig: usize) -> bool {
    matches!(sig as i32, SIGCHLD | SIGURG | SIGWINCH | SIGCONT)
}

pub(super) fn default_action_interrupts_blocked_syscall(sig: usize) -> bool {
    !default_action_is_ignore(sig)
}

pub(super) fn terminate_with_default_action(vm: &mut ThreadState, base: u32, sig: usize) {
    record_default_signal(vm, sig);
    crate::syscall::thread::terminate_process_with_reason(
        vm,
        base,
        128 + sig as i32,
        sig as i32,
        crate::syscall::thread::TERMINATE_REASON_DEFAULT_SIGNAL,
    );
}

pub(super) fn apply_default_action(vm: &mut ThreadState, base: u32, sig: usize) {
    if default_action_is_ignore(sig) {
        return;
    }
    terminate_with_default_action(vm, base, sig);
}
