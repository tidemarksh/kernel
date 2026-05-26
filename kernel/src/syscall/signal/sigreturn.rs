use super::frame::{
    MCONTEXT_OFF_FCSR, MCONTEXT_OFF_FREGS, MCONTEXT_OFF_REGS, SIGFRAME_OFF_ALTSTACK_FLAGS,
    SIGFRAME_OFF_UCONTEXT, UCONTEXT_OFF_MCONTEXT, UCONTEXT_OFF_SIGMASK,
};
use super::record_sigreturn_trace;
use crate::guest_mem;
use crate::types::ThreadState;

/// rt_sigreturn: restore state from signal frame on stack.
/// The frame is at the current sp (x2).
pub fn sys_rt_sigreturn(vm: &mut ThreadState, base: u32) {
    let frame_base = vm.x[2];
    let ucontext_base = frame_base + SIGFRAME_OFF_UCONTEXT;
    let regs_base = ucontext_base + UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_REGS;
    let fpregs_base = ucontext_base + UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_FREGS;

    unsafe {
        vm.sig_mask = guest_mem::read_u64(base, ucontext_base + UCONTEXT_OFF_SIGMASK);
        vm.pc = guest_mem::read_u64(base, regs_base);
        vm.x[0] = 0;
        for i in 1..32 {
            vm.x[i as usize] = guest_mem::read_u64(base, regs_base + (i as u64) * 8);
        }
        for i in 0..32 {
            vm.f[i as usize] = guest_mem::read_u64(base, fpregs_base + i * 8);
        }
        vm.fcsr = guest_mem::read_u32(base, fpregs_base + MCONTEXT_OFF_FCSR);
        vm.sigaltstack_flags =
            guest_mem::read_u64(base, frame_base + SIGFRAME_OFF_ALTSTACK_FLAGS) as i32;
    }

    record_sigreturn_trace(vm, frame_base);
}
