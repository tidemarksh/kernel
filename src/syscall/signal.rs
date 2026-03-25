//! Signal syscalls: rt_sigaction, rt_sigprocmask, sigaltstack, signal delivery.
//!
//! Signal delivery pushes a frame onto the guest stack, redirects PC to the
//! handler, and rt_sigreturn restores the saved context.
//!
//! Struct layouts (RV64):
//!
//! struct sigaction {                // 24 bytes total (no SA_RESTORER on RISC-V)
//!     sa_handler: u64,              // offset 0
//!     sa_flags:   u64,              // offset 8
//!     sa_mask:    u64,              // offset 16 (sigset_t = unsigned long[1])
//! };
//!
//! struct sigaltstack {              // 24 bytes total
//!     ss_sp:    u64,                // offset 0
//!     ss_flags: i32,                // offset 8
//!     _pad:     [u8; 4],            // offset 12 (alignment)
//!     ss_size:  u64,                // offset 16
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal.h

use crate::abi::*;
use crate::guest_mem;
use crate::types::{ThreadState, SigAction, SIG_DFL, MAX_SIGNALS};

// SA flags (https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal-defs.h)
const SA_NOCLDSTOP: u64 = 0x00000001;
const SA_NOCLDWAIT: u64 = 0x00000002;
const SA_SIGINFO: u64   = 0x00000004;
const SA_ONSTACK: u64   = 0x08000000;
const SA_RESTART: u64   = 0x10000000;
const SA_NODEFER: u64   = 0x40000000;
const SA_RESETHAND: u64 = 0x80000000;

// sigprocmask how
const SIG_BLOCK: u64   = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;

// sigaltstack flags
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;

/// Pointer to signal disposition table in kernel Worker linear memory.
static mut SIGACTIONS_PTR: *mut [SigAction; MAX_SIGNALS] = core::ptr::null_mut();

fn sigactions() -> &'static mut [SigAction; MAX_SIGNALS] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(SIGACTIONS_PTR));
        &mut *p
    }
}

/// Initialize signal state. Allocates via alloc.rs.
pub fn init() {
    unsafe {
        let size = core::mem::size_of::<[SigAction; MAX_SIGNALS]>() as u32;
        let align = core::mem::align_of::<SigAction>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 { core::arch::wasm32::unreachable(); }
        core::ptr::write(core::ptr::addr_of_mut!(SIGACTIONS_PTR), ptr as *mut [SigAction; MAX_SIGNALS]);
    }
}

/// rt_sigaction: get/set signal disposition.
/// signum in a0, act in a1, oldact in a2, sigsetsize in a3.
pub fn sys_rt_sigaction(
    _vm: &mut ThreadState, base: u32,
    signum: u64, act_addr: u64, oldact_addr: u64, sigsetsize: u64,
) -> i64 {
    if sigsetsize != 8 { return EINVAL; }
    let sig = signum as usize;
    if sig == 0 || sig >= MAX_SIGNALS { return EINVAL; }
    if sig == SIGKILL as usize || sig == SIGSTOP as usize { return EINVAL; }

    unsafe {
        // Write old action
        if oldact_addr != 0 {
            let old = &sigactions()[sig];
            guest_mem::write_u64(base, oldact_addr, old.handler);
            guest_mem::write_u64(base, oldact_addr + 8, old.flags);
            guest_mem::write_u64(base, oldact_addr + 16, old.mask);
        }

        // Read new action
        if act_addr != 0 {
            sigactions()[sig] = SigAction {
                handler: guest_mem::read_u64(base, act_addr),
                flags: guest_mem::read_u64(base, act_addr + 8),
                mask: guest_mem::read_u64(base, act_addr + 16),
            };
        }
    }
    0
}

/// rt_sigprocmask: change blocked signal mask.
/// how in a0, set in a1, oldset in a2, sigsetsize in a3.
pub fn sys_rt_sigprocmask(
    vm: &mut ThreadState, base: u32,
    how: u64, set_addr: u64, oldset_addr: u64, sigsetsize: u64,
) -> i64 {
    if sigsetsize != 8 { return EINVAL; }

    unsafe {
        // Write old mask
        if oldset_addr != 0 {
            guest_mem::write_u64(base, oldset_addr, vm.sig_mask);
        }

        // Apply new mask
        if set_addr != 0 {
            let set = guest_mem::read_u64(base, set_addr);
            // SIGKILL and SIGSTOP cannot be blocked
            let unblockable = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));
            vm.sig_mask = match how {
                SIG_BLOCK => vm.sig_mask | (set & !unblockable),
                SIG_UNBLOCK => vm.sig_mask & !set,
                SIG_SETMASK => set & !unblockable,
                _ => return EINVAL,
            };
        }
    }
    0
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
            if flags & !(SS_ONSTACK | SS_DISABLE) != 0 { return EINVAL; }

            if flags & SS_DISABLE != 0 {
                vm.sigaltstack_sp = 0;
                vm.sigaltstack_size = 0;
                vm.sigaltstack_flags = SS_DISABLE;
            } else {
                let sp = guest_mem::read_u64(base, ss_addr);
                let size = guest_mem::read_u64(base, ss_addr + 16);
                if size < 2048 { return ENOMEM; } // MINSIGSTKSZ
                vm.sigaltstack_sp = sp;
                vm.sigaltstack_size = size;
                vm.sigaltstack_flags = flags;
            }
        }
    }
    0
}

/// Signal frame layout on guest stack (RISC-V rt_sigframe).
///
/// Linux uses a full ucontext with 32 GP regs + 32 FP regs + PC + signal mask.
/// We use a simplified layout that preserves the same semantics:
///
/// offset  type    field
/// +0      u64     saved_pc
/// +8      u64     saved_sig_mask
/// +16     u64     saved_x[0..31] (256 bytes)
/// +272    u64     saved_f[0..31] (256 bytes)
/// +528    u32     saved_fcsr
/// +532    u32     _pad (alignment)
/// +536    u8[8]   trampoline: li a7, SYS_RT_SIGRETURN; ecall
/// Total: 544 bytes, 16-byte aligned
const SIGFRAME_SIZE: u64 = 544;
const SIGFRAME_OFF_PC: u64 = 0;
const SIGFRAME_OFF_MASK: u64 = 8;
const SIGFRAME_OFF_REGS: u64 = 16;
const SIGFRAME_OFF_FREGS: u64 = 272;
const SIGFRAME_OFF_FCSR: u64 = 528;
const SIGFRAME_OFF_TRAMPOLINE: u64 = 536;

/// RISC-V machine code: li a7, 139 (SYS_RT_SIGRETURN); ecall
/// addi x17, x0, 139 → 0x08b00893
/// ecall              → 0x00000073
const TRAMPOLINE_CODE: [u8; 8] = [
    0x93, 0x08, 0xb0, 0x08, // addi x17, x0, 139
    0x73, 0x00, 0x00, 0x00, // ecall
];

/// Push a signal frame onto the guest stack and redirect execution to the handler.
///
/// Stack layout after push:
///   sp → [signal frame (544 bytes)]
///   ra → trampoline address (within the frame)
///   a0 → signal number
///   pc → handler address
///
/// When the handler returns (via ra), it executes the trampoline which
/// calls SYS_RT_SIGRETURN to restore the saved context.
fn push_signal_frame(vm: &mut ThreadState, base: u32, sig: usize, action: &SigAction) {
    // Choose stack: use sigaltstack if SA_ONSTACK and stack is configured
    let sp = if action.flags & SA_ONSTACK != 0
        && vm.sigaltstack_flags != SS_DISABLE
        && vm.sigaltstack_size > 0
    {
        vm.sigaltstack_sp + vm.sigaltstack_size
    } else {
        vm.x[2] // current sp
    };

    // Align down to 16 bytes, then reserve frame
    let frame_base = (sp - SIGFRAME_SIZE) & !15;

    unsafe {
        // Save PC
        guest_mem::write_u64(base, frame_base + SIGFRAME_OFF_PC, vm.pc);
        // Save signal mask
        guest_mem::write_u64(base, frame_base + SIGFRAME_OFF_MASK, vm.sig_mask);
        // Save integer registers
        for i in 0..32 {
            guest_mem::write_u64(base, frame_base + SIGFRAME_OFF_REGS + i * 8, vm.x[i as usize]);
        }
        // Save FP registers
        for i in 0..32 {
            guest_mem::write_u64(base, frame_base + SIGFRAME_OFF_FREGS + i * 8, vm.f[i as usize]);
        }
        // Save fcsr
        guest_mem::write_u32(base, frame_base + SIGFRAME_OFF_FCSR, vm.fcsr);
        // Write trampoline code
        guest_mem::write_bytes(base, frame_base + SIGFRAME_OFF_TRAMPOLINE, &TRAMPOLINE_CODE);
    }

    // Block signals specified in sa_mask during handler execution
    let unblockable = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));
    vm.sig_mask |= action.mask & !unblockable;

    // If SA_NODEFER is not set, also block the delivered signal
    if action.flags & SA_NODEFER == 0 {
        vm.sig_mask |= (1u64 << (sig - 1)) & !unblockable;
    }

    // If SA_RESETHAND, reset disposition to SIG_DFL
    if action.flags & SA_RESETHAND != 0 {
        sigactions()[sig] = SigAction { handler: SIG_DFL, flags: 0, mask: 0 };
    }

    // Set up registers for handler entry
    vm.x[2] = frame_base;                                       // sp = frame base
    vm.x[1] = frame_base + SIGFRAME_OFF_TRAMPOLINE;             // ra = trampoline
    vm.x[10] = sig as u64;                                       // a0 = signal number
    vm.pc = action.handler;                                      // pc = handler
}

/// rt_sigreturn: restore state from signal frame on stack.
/// The frame is at the current sp (x2).
pub fn sys_rt_sigreturn(vm: &mut ThreadState, base: u32) {
    let frame_base = vm.x[2];

    unsafe {
        // Restore PC
        vm.pc = guest_mem::read_u64(base, frame_base + SIGFRAME_OFF_PC);
        // Restore signal mask
        vm.sig_mask = guest_mem::read_u64(base, frame_base + SIGFRAME_OFF_MASK);
        // Restore integer registers
        for i in 0..32 {
            vm.x[i as usize] = guest_mem::read_u64(base, frame_base + SIGFRAME_OFF_REGS + i * 8);
        }
        // Restore FP registers
        for i in 0..32 {
            vm.f[i as usize] = guest_mem::read_u64(base, frame_base + SIGFRAME_OFF_FREGS + i * 8);
        }
        // Restore fcsr
        vm.fcsr = guest_mem::read_u32(base, frame_base + SIGFRAME_OFF_FCSR);
    }
}

/// Check and deliver pending signals at syscall return boundary.
/// Called after each syscall returns. Returns true if a signal was delivered.
pub fn check_pending(vm: &mut ThreadState, base: u32) -> bool {
    let deliverable = vm.sig_pending & !vm.sig_mask;
    if deliverable == 0 { return false; }

    // Find lowest pending unblocked signal
    let sig = deliverable.trailing_zeros() as usize + 1;
    if sig >= MAX_SIGNALS { return false; }

    // Clear from pending
    vm.sig_pending &= !(1u64 << (sig - 1));

    let action = sigactions()[sig];

    match action.handler {
        0 => {
            // SIG_DFL: default action
            match sig as i32 {
                SIGCHLD | SIGURG | SIGWINCH => {} // ignore by default
                SIGCONT => {} // ignore (no job control)
                _ => {
                    // Terminate
                    vm.exit_code = 128 + sig as i32; // convention: 128 + signal
                    vm.status = STATUS_FAULT;
                }
            }
        }
        1 => {} // SIG_IGN: ignore
        _handler_addr => {
            // User handler: push signal frame and redirect to handler
            push_signal_frame(vm, base, sig, &action);
        }
    }

    true
}

/// Queue a signal for delivery.
pub fn send_signal(vm: &mut ThreadState, sig: i32) {
    if sig <= 0 || sig as usize >= MAX_SIGNALS { return; }
    vm.sig_pending |= 1u64 << (sig - 1);
}
