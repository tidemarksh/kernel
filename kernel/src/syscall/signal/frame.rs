use super::{actions::sigactions_for, pending::pid_from_vm, trace::record_signal_delivery_trace};
use crate::abi::*;
use crate::guest_mem;
use crate::types::{SIG_DFL, SigAction, ThreadState};

// SA flags (https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal-defs.h)
const SA_ONSTACK: u64 = 0x08000000;
const SA_NODEFER: u64 = 0x40000000;
const SA_RESETHAND: u64 = 0x80000000;

// sigaltstack flags
const SS_ONSTACK: i32 = 1;
pub(crate) const SS_DISABLE: i32 = 2;

/// Signal frame layout on guest stack (RISC-V rt_sigframe).
///
/// Linux delivers signal handler arguments in registers, but the RISC-V ABI
/// also gives the callee stack home slots for those arguments. Keep both the
/// register arguments and their stack homes (`sp+8`, `sp+16`, `sp+24`) valid
/// so any conforming handler entry sequence observes a complete call frame.
const SIGFRAME_OFF_ABI_SIGNO: u64 = 8;
const SIGFRAME_OFF_ABI_SIGINFO_PTR: u64 = 16;
const SIGFRAME_OFF_ABI_UCONTEXT_PTR: u64 = 24;
const SIGINFO_SIZE: u64 = 128;
const SIGINFO_OFF_SIGNO: u64 = 0;
const SIGINFO_OFF_ERRNO: u64 = 4;
const SIGINFO_OFF_CODE: u64 = 8;
const SIGINFO_OFF_ADDR: u64 = 16;

const UCONTEXT_OFF_FLAGS: u64 = 0;
const UCONTEXT_OFF_LINK: u64 = 8;
const UCONTEXT_OFF_STACK: u64 = 16;
const UCONTEXT_STACK_OFF_SP: u64 = 0;
const UCONTEXT_STACK_OFF_FLAGS: u64 = 8;
const UCONTEXT_STACK_OFF_SIZE: u64 = 16;
pub(super) const UCONTEXT_OFF_SIGMASK: u64 = 40;
const UCONTEXT_SIGMASK_WORDS: u64 = 16;
const UCONTEXT_OFF_RESERVED_PAD: u64 = 168;
pub(super) const UCONTEXT_OFF_MCONTEXT: u64 = 176;
pub(super) const MCONTEXT_OFF_REGS: u64 = 0;
pub(super) const MCONTEXT_OFF_FREGS: u64 = 256;
const MCONTEXT_FREGS_BYTES: u64 = 528;
pub(super) const MCONTEXT_OFF_FCSR: u64 = 256;
const UCONTEXT_SIZE: u64 = UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_FREGS + MCONTEXT_FREGS_BYTES;

const SIGFRAME_OFF_SIGINFO: u64 = 32;
pub(super) const SIGFRAME_OFF_UCONTEXT: u64 = SIGFRAME_OFF_SIGINFO + SIGINFO_SIZE;
pub(super) const SIGFRAME_OFF_ALTSTACK_FLAGS: u64 = SIGFRAME_OFF_UCONTEXT + UCONTEXT_SIZE;
const SIGFRAME_OFF_TRAMPOLINE: u64 = SIGFRAME_OFF_ALTSTACK_FLAGS + 8;
const SIGFRAME_SIZE: u64 = SIGFRAME_OFF_TRAMPOLINE + 8;

/// RISC-V machine code: li a7, 139 (SYS_RT_SIGRETURN); ecall
/// addi x17, x0, 139 -> 0x08b00893
/// ecall              -> 0x00000073
const TRAMPOLINE_CODE: [u8; 8] = [
    0x93, 0x08, 0xb0, 0x08, // addi x17, x0, 139
    0x73, 0x00, 0x00, 0x00, // ecall
];

#[inline(always)]
pub fn is_current_sigreturn_trampoline(sp: u64, pc: u64) -> bool {
    sp != 0 && pc.checked_sub(sp) == Some(SIGFRAME_OFF_TRAMPOLINE)
}

/// Push a signal frame onto the guest stack and redirect execution to the handler.
///
/// Stack layout after push:
///   sp -> [signal frame (544 bytes)]
///   ra -> trampoline address (within the frame)
///   a0 -> signal number
///   pc -> handler address
///
/// When the handler returns (via ra), it executes the trampoline which
/// calls SYS_RT_SIGRETURN to restore the saved context.
pub(super) fn push_signal_frame(
    vm: &mut ThreadState,
    base: u32,
    sig: usize,
    action: &SigAction,
) -> bool {
    let use_altstack = action.flags & SA_ONSTACK != 0
        && vm.sigaltstack_flags != SS_DISABLE
        && vm.sigaltstack_size > 0
        && vm.sigaltstack_flags & SS_ONSTACK == 0;
    let sp = if use_altstack {
        vm.sigaltstack_sp + vm.sigaltstack_size
    } else {
        vm.x[2]
    };

    let Some(frame_base) = sp.checked_sub(SIGFRAME_SIZE).map(|value| value & !15) else {
        return false;
    };
    let siginfo_base = frame_base + SIGFRAME_OFF_SIGINFO;
    let ucontext_base = frame_base + SIGFRAME_OFF_UCONTEXT;
    let regs_base = ucontext_base + UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_REGS;
    let fpregs_base = ucontext_base + UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_FREGS;
    let saved_altstack_flags = vm.sigaltstack_flags as u64;

    unsafe {
        guest_mem::zero_mem(base, frame_base, SIGFRAME_SIZE as usize);

        guest_mem::write_u32(base, siginfo_base + SIGINFO_OFF_SIGNO, sig as u32);
        guest_mem::write_u32(base, siginfo_base + SIGINFO_OFF_ERRNO, 0);
        guest_mem::write_u32(
            base,
            siginfo_base + SIGINFO_OFF_CODE,
            vm.sig_info_code as u32,
        );
        let sig_addr = match sig as i32 {
            SIGILL | SIGBUS | SIGFPE | SIGSEGV => vm.fault_addr,
            _ => 0,
        };
        guest_mem::write_u64(base, siginfo_base + SIGINFO_OFF_ADDR, sig_addr);

        guest_mem::write_u64(base, ucontext_base + UCONTEXT_OFF_FLAGS, 0);
        guest_mem::write_u64(base, ucontext_base + UCONTEXT_OFF_LINK, 0);
        guest_mem::write_u64(
            base,
            ucontext_base + UCONTEXT_OFF_STACK + UCONTEXT_STACK_OFF_SP,
            vm.sigaltstack_sp,
        );
        guest_mem::write_u32(
            base,
            ucontext_base + UCONTEXT_OFF_STACK + UCONTEXT_STACK_OFF_FLAGS,
            vm.sigaltstack_flags as u32,
        );
        guest_mem::write_u64(
            base,
            ucontext_base + UCONTEXT_OFF_STACK + UCONTEXT_STACK_OFF_SIZE,
            vm.sigaltstack_size,
        );
        guest_mem::write_u64(base, ucontext_base + UCONTEXT_OFF_SIGMASK, vm.sig_mask);
        for word in 1..UCONTEXT_SIGMASK_WORDS {
            guest_mem::write_u64(base, ucontext_base + UCONTEXT_OFF_SIGMASK + word * 8, 0);
        }
        guest_mem::write_u64(base, ucontext_base + UCONTEXT_OFF_RESERVED_PAD, 0);

        guest_mem::write_u64(base, regs_base, vm.pc);
        for i in 1..32 {
            guest_mem::write_u64(base, regs_base + (i as u64) * 8, vm.x[i as usize]);
        }
        for i in 0..32 {
            guest_mem::write_u64(base, fpregs_base + i * 8, vm.f[i as usize]);
        }
        guest_mem::write_u32(base, fpregs_base + MCONTEXT_OFF_FCSR, vm.fcsr);
        guest_mem::write_u64(base, frame_base + SIGFRAME_OFF_ABI_SIGNO, sig as u64);
        guest_mem::write_u64(
            base,
            frame_base + SIGFRAME_OFF_ABI_SIGINFO_PTR,
            siginfo_base,
        );
        guest_mem::write_u64(
            base,
            frame_base + SIGFRAME_OFF_ABI_UCONTEXT_PTR,
            ucontext_base,
        );
        guest_mem::write_u64(
            base,
            frame_base + SIGFRAME_OFF_ALTSTACK_FLAGS,
            saved_altstack_flags,
        );
        guest_mem::write_bytes(base, frame_base + SIGFRAME_OFF_TRAMPOLINE, &TRAMPOLINE_CODE);
    }

    let unblockable = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));
    vm.sig_mask |= action.mask & !unblockable;

    if action.flags & SA_NODEFER == 0 {
        vm.sig_mask |= (1u64 << (sig - 1)) & !unblockable;
    }

    if action.flags & SA_RESETHAND != 0 {
        let pid = pid_from_vm(vm, base);
        if let Some(table) = sigactions_for(pid) {
            table[sig] = SigAction {
                handler: SIG_DFL,
                flags: 0,
                mask: 0,
            };
        }
    }
    if use_altstack {
        vm.sigaltstack_flags |= SS_ONSTACK;
    }

    let trampoline_pc = frame_base + SIGFRAME_OFF_TRAMPOLINE;
    record_signal_delivery_trace(vm, sig, frame_base, trampoline_pc, action.handler);

    vm.x[2] = frame_base;
    vm.x[1] = trampoline_pc;
    vm.x[10] = sig as u64;
    vm.x[11] = siginfo_base;
    vm.x[12] = ucontext_base;
    vm.pc = action.handler;
    true
}

/// Patch the currently active signal frame so rt_sigreturn restores a
/// different a0 result to user code. This is used for interrupted blocking
/// syscalls that must become -EINTR after the handler returns.
pub fn patch_current_signal_frame_a0(vm: &ThreadState, base: u32, value: i64) -> bool {
    let frame_base = vm.x[2];
    if frame_base == 0 || vm.x[1] != frame_base + SIGFRAME_OFF_TRAMPOLINE {
        return false;
    }
    let regs_base = frame_base + SIGFRAME_OFF_UCONTEXT + UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_REGS;
    unsafe {
        guest_mem::write_u64(base, regs_base + (10u64 * 8), value as u64);
    }
    true
}

/// sigaltstack: get/set alternate signal stack.
/// ss in a0, old_ss in a1.
pub fn sys_sigaltstack(vm: &mut ThreadState, base: u32, ss_addr: u64, old_ss_addr: u64) -> i64 {
    unsafe {
        // Write old stack
        if old_ss_addr != 0 {
            guest_mem::write_u64(base, old_ss_addr, vm.sigaltstack_sp);
            guest_mem::write_u32(base, old_ss_addr + 8, vm.sigaltstack_flags as u32);
            guest_mem::write_u64(base, old_ss_addr + 16, vm.sigaltstack_size);
        }

        // Read new stack
        if ss_addr != 0 {
            let flags = guest_mem::read_i32(base, ss_addr + 8);
            if flags & !(SS_ONSTACK | SS_DISABLE) != 0 {
                return EINVAL;
            }

            if flags & SS_DISABLE != 0 {
                vm.sigaltstack_sp = 0;
                vm.sigaltstack_size = 0;
                vm.sigaltstack_flags = SS_DISABLE;
            } else {
                let sp = guest_mem::read_u64(base, ss_addr);
                let size = guest_mem::read_u64(base, ss_addr + 16);
                if size < 2048 {
                    return ENOMEM;
                } // MINSIGSTKSZ
                vm.sigaltstack_sp = sp;
                vm.sigaltstack_size = size;
                vm.sigaltstack_flags = flags;
            }
        }
    }
    0
}
