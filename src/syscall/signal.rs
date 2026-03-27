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
use crate::types::{MAX_SIGNALS, SIG_DFL, SIG_IGN, SigAction, ThreadState};

// SA flags (https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal-defs.h)
const SA_NOCLDSTOP: u64 = 0x00000001;
const SA_NOCLDWAIT: u64 = 0x00000002;
const SA_SIGINFO: u64 = 0x00000004;
const SA_ONSTACK: u64 = 0x08000000;
const SA_RESTART: u64 = 0x10000000;
const SA_NODEFER: u64 = 0x40000000;
const SA_RESETHAND: u64 = 0x80000000;

// sigprocmask how
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;

// sigaltstack flags
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;

/// Per-process signal disposition tables, allocated in kernel Worker linear memory.
/// Each process gets its own [SigAction; MAX_SIGNALS] table, indexed by PID.
///
/// Signal dispositions are process-wide (shared by all threads in a process).
/// On execve, caught signals (handler != SIG_DFL and != SIG_IGN) are reset to SIG_DFL.
///
/// Semantics: https://man7.org/linux/man-pages/man2/rt_sigaction.2.html
/// execve reset: https://man7.org/linux/man-pages/man2/execve.2.html
///
/// SIGACTIONS_PTR points to a heap-allocated [SigAction; MAX_SIGNALS] for the
/// currently active process. Multi-process uses SIG_SLOTS_PTR (array of
/// MAX_PROCESSES pointers, each pointing to a per-process table).
static mut SIG_SLOTS_PTR: *mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES] =
    core::ptr::null_mut();
static mut PROCESS_PENDING_PTR: *mut [u64; MAX_PROCESSES] = core::ptr::null_mut();

#[inline(always)]
fn sig_slots() -> &'static mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(SIG_SLOTS_PTR));
        &mut *p
    }
}

#[inline(always)]
fn process_pending() -> &'static mut [u64; MAX_PROCESSES] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(PROCESS_PENDING_PTR));
        &mut *p
    }
}

#[inline(always)]
fn sigactions_for(pid: i32) -> &'static mut [SigAction; MAX_SIGNALS] {
    let idx = (pid - 1) as usize;
    unsafe { &mut *sig_slots()[idx] }
}

/// Read PID from ProcessState in guest Memory via ThreadState.process_ptr.
#[inline(always)]
pub fn pid_from_vm(vm: &ThreadState, base: u32) -> i32 {
    let ps_ptr = vm.process_ptr;
    if ps_ptr == 0 {
        return 1;
    }
    unsafe {
        let pid_offset = core::mem::offset_of!(crate::types::ProcessState, pid);
        guest_mem::read_i32(base, ps_ptr as u64 + pid_offset as u64)
    }
}

/// Initialize signal subsystem. Must be called once at kernel init.
pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SIG_SLOTS_PTR),
            core::ptr::null_mut(),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_PENDING_PTR),
            core::ptr::null_mut(),
        );

        let size = core::mem::size_of::<[*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES]>() as u32;
        let align = core::mem::align_of::<*mut [SigAction; MAX_SIGNALS]>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(SIG_SLOTS_PTR),
            ptr as *mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES],
        );

        let pending_size = core::mem::size_of::<[u64; MAX_PROCESSES]>() as u32;
        let pending_align = core::mem::align_of::<u64>() as u32;
        let pending_ptr = crate::alloc::alloc_zeroed(pending_size, pending_align);
        if pending_ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_PENDING_PTR),
            pending_ptr as *mut [u64; MAX_PROCESSES],
        );
    }
}

/// Allocate a new signal disposition table for a process.
pub fn init_for_process(pid: i32) {
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES {
        return;
    }
    unsafe {
        let size = core::mem::size_of::<[SigAction; MAX_SIGNALS]>() as u32;
        let align = core::mem::align_of::<SigAction>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        sig_slots()[idx] = ptr as *mut [SigAction; MAX_SIGNALS];
        process_pending()[idx] = 0;
    }
}

/// fork(): child inherits the parent's signal dispositions but starts with no
/// pending signals. This mirrors Linux process semantics.
pub fn fork_from_parent(parent_pid: i32, child_pid: i32) {
    let parent_idx = (parent_pid - 1) as usize;
    let child_idx = (child_pid - 1) as usize;
    if parent_idx >= MAX_PROCESSES || child_idx >= MAX_PROCESSES {
        return;
    }
    if sig_slots()[parent_idx].is_null() {
        return;
    }

    init_for_process(child_pid);
    let parent = sigactions_for(parent_pid);
    let child = sigactions_for(child_pid);
    child.copy_from_slice(parent);
    process_pending()[child_idx] = 0;
}

/// Reset signal dispositions on execve: caught signals (handler != SIG_DFL
/// and handler != SIG_IGN) are reset to SIG_DFL.
///
/// https://man7.org/linux/man-pages/man2/execve.2.html
/// "POSIX.1 specifies that the dispositions of any signals that are being
///  caught are reset to the default."
pub fn reset_on_execve(pid: i32) {
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES {
        return;
    }
    let table = sigactions_for(pid);
    for sig in 1..MAX_SIGNALS {
        let action = &mut table[sig];
        if action.handler != SIG_DFL && action.handler != SIG_IGN {
            *action = SigAction {
                handler: SIG_DFL,
                flags: 0,
                mask: 0,
            };
        }
    }
}

/// rt_sigaction: get/set signal disposition.
/// signum in a0, act in a1, oldact in a2, sigsetsize in a3.
pub fn sys_rt_sigaction(
    vm: &mut ThreadState,
    base: u32,
    signum: u64,
    act_addr: u64,
    oldact_addr: u64,
    sigsetsize: u64,
) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    let sig = signum as usize;
    if sig == 0 || sig >= MAX_SIGNALS {
        return EINVAL;
    }
    if sig == SIGKILL as usize || sig == SIGSTOP as usize {
        return EINVAL;
    }

    let pid = pid_from_vm(vm, base);
    let table = sigactions_for(pid);

    unsafe {
        // Write old action
        if oldact_addr != 0 {
            let old = &table[sig];
            guest_mem::write_u64(base, oldact_addr, old.handler);
            guest_mem::write_u64(base, oldact_addr + 8, old.flags);
            guest_mem::write_u64(base, oldact_addr + 16, old.mask);
        }

        // Read new action
        if act_addr != 0 {
            table[sig] = SigAction {
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
    vm: &mut ThreadState,
    base: u32,
    how: u64,
    set_addr: u64,
    oldset_addr: u64,
    sigsetsize: u64,
) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }

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
            guest_mem::write_u64(
                base,
                frame_base + SIGFRAME_OFF_REGS + i * 8,
                vm.x[i as usize],
            );
        }
        // Save FP registers
        for i in 0..32 {
            guest_mem::write_u64(
                base,
                frame_base + SIGFRAME_OFF_FREGS + i * 8,
                vm.f[i as usize],
            );
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
        let pid = pid_from_vm(vm, base);
        sigactions_for(pid)[sig] = SigAction {
            handler: SIG_DFL,
            flags: 0,
            mask: 0,
        };
    }

    // Set up registers for handler entry
    vm.x[2] = frame_base; // sp = frame base
    vm.x[1] = frame_base + SIGFRAME_OFF_TRAMPOLINE; // ra = trampoline
    vm.x[10] = sig as u64; // a0 = signal number
    vm.pc = action.handler; // pc = handler
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
    let pid = pid_from_vm(vm, base);
    if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            vm.sig_pending |= process_pending()[idx];
            process_pending()[idx] = 0;
        }
    }

    let deliverable = vm.sig_pending & !vm.sig_mask;
    if deliverable == 0 {
        return false;
    }

    // Find lowest pending unblocked signal
    let sig = deliverable.trailing_zeros() as usize + 1;
    if sig >= MAX_SIGNALS {
        return false;
    }

    // Clear from pending
    vm.sig_pending &= !(1u64 << (sig - 1));

    let action = sigactions_for(pid)[sig];

    match action.handler {
        0 => {
            // SIG_DFL: default action
            match sig as i32 {
                SIGCHLD | SIGURG | SIGWINCH => {} // ignore by default
                SIGCONT => {}                     // ignore (no job control)
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
    if sig <= 0 || sig as usize >= MAX_SIGNALS {
        return;
    }
    vm.sig_pending |= 1u64 << (sig - 1);
}

/// Queue a process-directed signal. Delivery happens when the target process
/// next reaches a signal check boundary.
pub fn send_signal_to_pid(pid: i32, sig: i32) -> i64 {
    if pid <= 0 || sig <= 0 || sig as usize >= MAX_SIGNALS {
        return EINVAL;
    }
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES || sig_slots()[idx].is_null() {
        return ESRCH;
    }
    process_pending()[idx] |= 1u64 << (sig - 1);
    0
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::TestVm;

    /// Signal syscalls: rt_sigprocmask, rt_sigaction, sigaltstack,
    /// plus per-process init_for_process, rt_sigaction per-process write,
    /// and pending signal delivery.
    #[test]
    fn signal_syscalls() {
        let mut t = TestVm::new();

        // rt_sigprocmask: block SIGUSR1 (signal 10)
        let set_addr = t.scratch;
        let oldset_addr = t.scratch + 0x100;
        unsafe {
            crate::guest_mem::write_u64(t.base, set_addr, 1 << 9);
        } // bit 9 = signal 10
        let ret = super::sys_rt_sigprocmask(
            &mut t.vm,
            t.base,
            0,
            set_addr,
            oldset_addr,
            8, // SIG_BLOCK=0
        );
        assert_eq!(ret, 0);
        assert_eq!(t.vm.sig_mask & (1 << 9), 1 << 9);

        // rt_sigaction: set handler for SIGUSR1
        let act_addr = t.scratch + 0x200;
        let oldact_addr = t.scratch + 0x300;
        unsafe {
            crate::guest_mem::write_u64(t.base, act_addr, 0x12345); // handler
            crate::guest_mem::write_u64(t.base, act_addr + 8, 0); // flags
            crate::guest_mem::write_u64(t.base, act_addr + 16, 0); // mask
        }
        let ret2 = super::sys_rt_sigaction(&mut t.vm, t.base, 10, act_addr, oldact_addr, 8);
        assert_eq!(ret2, 0);

        // sigaltstack
        let ss_addr = t.scratch + 0x400;
        let old_ss_addr = t.scratch + 0x500;
        unsafe {
            crate::guest_mem::write_u64(t.base, ss_addr, 0x50000); // sp
            crate::guest_mem::write_u32(t.base, ss_addr + 8, 0); // flags
            crate::guest_mem::write_u64(t.base, ss_addr + 16, 8192); // size
        }
        let ret3 = super::sys_sigaltstack(&mut t.vm, t.base, ss_addr, old_ss_addr);
        assert_eq!(ret3, 0);
        assert_eq!(t.vm.sigaltstack_sp, 0x50000);
        assert_eq!(t.vm.sigaltstack_size, 8192);

        // --- Per-process signal disposition tests ---

        // init_for_process: table is zero-initialized (all SIG_DFL)
        let table = super::sigactions_for(42);
        // Skip slot 10 which was set above; check the rest
        assert_eq!(table[0].handler, crate::types::SIG_DFL);
        assert_eq!(table[1].handler, crate::types::SIG_DFL);
        assert_eq!(table[15].handler, crate::types::SIG_DFL);

        // rt_sigaction writes to per-process table via pid_from_vm
        let act_addr2 = t.scratch + 0x600;
        unsafe {
            crate::guest_mem::write_u64(t.base, act_addr2, 0xABCD);
            crate::guest_mem::write_u64(t.base, act_addr2 + 8, 0);
            crate::guest_mem::write_u64(t.base, act_addr2 + 16, 0);
        }
        let ret4 = super::sys_rt_sigaction(&mut t.vm, t.base, 14, act_addr2, 0, 8);
        assert_eq!(ret4, 0);
        assert_eq!(super::sigactions_for(42)[14].handler, 0xABCD);
    }

    /// Pending signal delivery and reset_on_execve semantics.
    /// SIGTERM (15) with SIG_DFL terminates (exit_code = 128 + sig).
    /// reset_on_execve resets caught signals to SIG_DFL, preserves SIG_IGN.
    #[test]
    fn pending_signal_delivery() {
        let mut t = TestVm::new();

        // Ensure SIGTERM is not blocked.
        t.vm.sig_mask = 0;
        t.vm.sig_pending = 0;

        // Queue SIGTERM via direct manipulation.
        super::send_signal(&mut t.vm, crate::abi::SIGTERM);
        assert!(
            t.vm.sig_pending & (1u64 << (crate::abi::SIGTERM - 1)) != 0,
            "SIGTERM should be pending after send_signal"
        );

        // check_pending should deliver the signal and return true.
        let delivered = super::check_pending(&mut t.vm, t.base);
        assert!(
            delivered,
            "check_pending should return true when a signal is deliverable"
        );

        // SIGTERM with SIG_DFL terminates: exit_code = 128 + 15 = 143
        assert_eq!(
            t.vm.status,
            crate::abi::STATUS_FAULT,
            "SIGTERM with SIG_DFL should set STATUS_FAULT"
        );
        assert_eq!(
            t.vm.exit_code,
            128 + crate::abi::SIGTERM,
            "exit_code should be 128 + SIGTERM"
        );

        // The pending bit should be cleared.
        assert_eq!(
            t.vm.sig_pending & (1u64 << (crate::abi::SIGTERM - 1)),
            0,
            "SIGTERM should no longer be pending after delivery"
        );

        // --- reset_on_execve ---
        // Re-init VM for clean state
        let _t2 = TestVm::new();
        let tbl = super::sigactions_for(42);
        // Set signal 10 to a user handler (caught)
        tbl[10] = crate::types::SigAction {
            handler: 0x12345,
            flags: 0,
            mask: 0,
        };
        // Set signal 15 to SIG_IGN
        tbl[15] = crate::types::SigAction {
            handler: crate::types::SIG_IGN,
            flags: 0,
            mask: 0,
        };
        // Set signal 2 to SIG_DFL (already default)
        tbl[2] = crate::types::SigAction {
            handler: crate::types::SIG_DFL,
            flags: 0,
            mask: 0,
        };

        super::reset_on_execve(42);

        // Caught signal 10 should be reset to SIG_DFL
        assert_eq!(tbl[10].handler, crate::types::SIG_DFL);
        // SIG_IGN should be preserved
        assert_eq!(tbl[15].handler, crate::types::SIG_IGN);
        // SIG_DFL should remain SIG_DFL
        assert_eq!(tbl[2].handler, crate::types::SIG_DFL);
    }
}
