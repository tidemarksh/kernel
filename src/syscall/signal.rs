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
use crate::types::{
    MAX_SIGNALS, ProcessState, SIG_DFL, SIG_IGN, SigAction, ThreadState, THREAD_DEAD,
    THREAD_BLOCKED_FUTEX, THREAD_NONE,
};

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
const SI_USER: i32 = 0;
const SI_TKILL: i32 = -6;
const ILL_ILLOPC: i32 = 1;
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;

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

#[derive(Clone, Copy)]
struct SignalTrace {
    sig: u32,
    frame_base: u64,
    pc: u64,
    ra: u64,
    sp: u64,
    g: u64,
}

static mut LAST_SIGNAL_DELIVERY: SignalTrace = SignalTrace {
    sig: 0,
    frame_base: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    g: 0,
};
static mut LAST_SIGRETURN: SignalTrace = SignalTrace {
    sig: 0,
    frame_base: 0,
    pc: 0,
    ra: 0,
    sp: 0,
    g: 0,
};
static mut LAST_TRAMPOLINE_PC: u64 = 0;
static mut LAST_TRAMPOLINE_HIT_TID: i32 = 0;
static mut LAST_TRAMPOLINE_HIT_PC: u64 = 0;
static mut SIGRETURN_COUNT: u32 = 0;

const SYNC_FAULT_SIGNAL_MASK: u64 = (1u64 << (SIGILL - 1))
    | (1u64 << (SIGBUS - 1))
    | (1u64 << (SIGFPE - 1))
    | (1u64 << (SIGSEGV - 1));

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

pub fn sig_slots_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(SIG_SLOTS_PTR)) as u32 }
}

pub fn process_pending_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(PROCESS_PENDING_PTR)) as u32 }
}

pub fn signal_slots_bytes() -> u32 {
    core::mem::size_of::<[*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES]>() as u32
}

pub fn process_pending_bytes() -> u32 {
    core::mem::size_of::<[u64; MAX_PROCESSES]>() as u32
}

pub fn last_signal_delivery() -> (u32, u64, u64, u64, u64, u64) {
    unsafe {
        let t = LAST_SIGNAL_DELIVERY;
        (t.sig, t.frame_base, t.pc, t.ra, t.sp, t.g)
    }
}

pub fn last_sigreturn() -> (u32, u64, u64, u64, u64, u64) {
    unsafe {
        let t = LAST_SIGRETURN;
        (t.sig, t.frame_base, t.pc, t.ra, t.sp, t.g)
    }
}

pub fn last_trampoline_hit() -> (i32, u64, u32) {
    unsafe { (LAST_TRAMPOLINE_HIT_TID, LAST_TRAMPOLINE_HIT_PC, SIGRETURN_COUNT) }
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

pub fn signal_action_table_bytes() -> u32 {
    core::mem::size_of::<[SigAction; MAX_SIGNALS]>() as u32
}

pub fn attach_process_signal_state(sig_slots_ptr: u32, process_pending_ptr: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SIG_SLOTS_PTR),
            sig_slots_ptr as *mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES],
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_PENDING_PTR),
            process_pending_ptr as *mut [u64; MAX_PROCESSES],
        );
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

fn process_state_from_vm(vm: &ThreadState, base: u32) -> Option<&'static mut ProcessState> {
    if vm.process_ptr == 0 {
        return None;
    }
    let absolute = (base as u64 + vm.process_ptr as u64) as *mut ProcessState;
    if absolute.is_null() {
        return None;
    }
    unsafe { Some(&mut *absolute) }
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

/// Move per-process signal state from one PID slot to another.
/// Used when runtime canonicalizes a provisional child PID before the child runs.
pub fn reassign_process_pid(old_pid: i32, new_pid: i32) {
    if old_pid <= 0 || new_pid <= 0 || old_pid == new_pid {
        return;
    }

    let old_idx = (old_pid - 1) as usize;
    let new_idx = (new_pid - 1) as usize;
    if old_idx >= MAX_PROCESSES || new_idx >= MAX_PROCESSES {
        return;
    }

    let old_slot = sig_slots()[old_idx];
    if !old_slot.is_null() {
        sig_slots()[new_idx] = old_slot;
        sig_slots()[old_idx] = core::ptr::null_mut();
        process_pending()[new_idx] = process_pending()[old_idx];
        process_pending()[old_idx] = 0;
        return;
    }

    if sig_slots()[new_idx].is_null() {
        init_for_process(new_pid);
    }
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

/// rt_sigpending: return blocked pending signals visible to the caller.
pub fn sys_rt_sigpending(vm: &ThreadState, base: u32, set_addr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    if set_addr == 0 || crate::syscall::memory::range_has_prot_none(set_addr, 8) {
        return EFAULT;
    }

    let pid = pid_from_vm(vm, base);
    let mut pending = vm.sig_pending;
    if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            pending |= process_pending()[idx];
        }
    }

    unsafe {
        guest_mem::write_u64(base, set_addr, pending & vm.sig_mask);
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
const UCONTEXT_OFF_SIGMASK: u64 = 40;
const UCONTEXT_SIGMASK_WORDS: u64 = 16;
const UCONTEXT_OFF_PAD_CGO: u64 = 168;
const UCONTEXT_OFF_MCONTEXT: u64 = 176;
const MCONTEXT_OFF_REGS: u64 = 0;
const MCONTEXT_OFF_FREGS: u64 = 256;
const MCONTEXT_FREGS_BYTES: u64 = 528;
const MCONTEXT_OFF_FCSR: u64 = 256;
const UCONTEXT_SIZE: u64 = UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_FREGS + MCONTEXT_FREGS_BYTES;

const SIGFRAME_OFF_SIGINFO: u64 = 32;
const SIGFRAME_OFF_UCONTEXT: u64 = SIGFRAME_OFF_SIGINFO + SIGINFO_SIZE;
const SIGFRAME_OFF_ALTSTACK_FLAGS: u64 = SIGFRAME_OFF_UCONTEXT + UCONTEXT_SIZE;
const SIGFRAME_OFF_TRAMPOLINE: u64 = SIGFRAME_OFF_ALTSTACK_FLAGS + 8;
const SIGFRAME_SIZE: u64 = SIGFRAME_OFF_TRAMPOLINE + 8;

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
    let use_altstack = action.flags & SA_ONSTACK != 0
        && vm.sigaltstack_flags != SS_DISABLE
        && vm.sigaltstack_size > 0
        && vm.sigaltstack_flags & SS_ONSTACK == 0;
    let sp = if use_altstack {
        vm.sigaltstack_sp + vm.sigaltstack_size
    } else {
        vm.x[2]
    };

    // Align down to 16 bytes, then reserve frame
    let frame_base = (sp - SIGFRAME_SIZE) & !15;
    let siginfo_base = frame_base + SIGFRAME_OFF_SIGINFO;
    let ucontext_base = frame_base + SIGFRAME_OFF_UCONTEXT;
    let regs_base = ucontext_base + UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_REGS;
    let fpregs_base = ucontext_base + UCONTEXT_OFF_MCONTEXT + MCONTEXT_OFF_FREGS;
    let saved_altstack_flags = vm.sigaltstack_flags as u64;

    unsafe {
        guest_mem::zero_mem(base, frame_base, SIGFRAME_SIZE as usize);

        guest_mem::write_u32(base, siginfo_base + SIGINFO_OFF_SIGNO, sig as u32);
        guest_mem::write_u32(base, siginfo_base + SIGINFO_OFF_ERRNO, 0);
        guest_mem::write_u32(base, siginfo_base + SIGINFO_OFF_CODE, vm.sig_info_code as u32);
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
        guest_mem::write_u64(base, ucontext_base + UCONTEXT_OFF_PAD_CGO, 0);

        guest_mem::write_u64(base, regs_base, vm.pc);
        for i in 1..32 {
            guest_mem::write_u64(
                base,
                regs_base + (i as u64) * 8,
                vm.x[i as usize],
            );
        }
        for i in 0..32 {
            guest_mem::write_u64(
                base,
                fpregs_base + i * 8,
                vm.f[i as usize],
            );
        }
        guest_mem::write_u32(base, fpregs_base + MCONTEXT_OFF_FCSR, vm.fcsr);
        guest_mem::write_u64(base, frame_base + SIGFRAME_OFF_ABI_SIGNO, sig as u64);
        guest_mem::write_u64(base, frame_base + SIGFRAME_OFF_ABI_SIGINFO_PTR, siginfo_base);
        guest_mem::write_u64(base, frame_base + SIGFRAME_OFF_ABI_UCONTEXT_PTR, ucontext_base);
        guest_mem::write_u64(base, frame_base + SIGFRAME_OFF_ALTSTACK_FLAGS, saved_altstack_flags);
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
    if use_altstack {
        vm.sigaltstack_flags |= SS_ONSTACK;
    }

    unsafe {
        LAST_SIGNAL_DELIVERY = SignalTrace {
            sig: sig as u32,
            frame_base,
            pc: vm.pc,
            ra: vm.x[1],
            sp: vm.x[2],
            g: vm.x[27],
        };
        LAST_TRAMPOLINE_PC = frame_base + SIGFRAME_OFF_TRAMPOLINE;
    }

    // Set up registers for handler entry
    vm.x[2] = frame_base;
    vm.x[1] = frame_base + SIGFRAME_OFF_TRAMPOLINE;
    vm.x[10] = sig as u64;
    vm.x[11] = siginfo_base;
    vm.x[12] = ucontext_base;
    vm.pc = action.handler;
}

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
        vm.sigaltstack_flags = guest_mem::read_u64(base, frame_base + SIGFRAME_OFF_ALTSTACK_FLAGS) as i32;
        LAST_SIGRETURN = SignalTrace {
            sig: 0,
            frame_base,
            pc: vm.pc,
            ra: vm.x[1],
            sp: vm.x[2],
            g: vm.x[27],
        };
        SIGRETURN_COUNT = SIGRETURN_COUNT.wrapping_add(1);
    }
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

    let synchronous = if vm.sig_info_code != 0 {
        vm.sig_pending & SYNC_FAULT_SIGNAL_MASK
    } else {
        0
    };
    let deliverable = (vm.sig_pending & !vm.sig_mask) | synchronous;
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
                    crate::syscall::thread::terminate_process(
                        vm,
                        base,
                        128 + sig as i32,
                        sig as i32,
                    );
                }
            }
        }
        1 => {} // SIG_IGN: ignore
        _handler_addr => {
            // User handler: push signal frame and redirect to handler
            push_signal_frame(vm, base, sig, &action);
        }
    }

    vm.sig_info_code = 0;

    true
}

/// Queue a signal for delivery.
pub fn send_signal(vm: &mut ThreadState, sig: i32) {
    if sig <= 0 || sig as usize >= MAX_SIGNALS {
        return;
    }
    vm.sig_pending |= 1u64 << (sig - 1);
}

pub fn send_signal_with_code(vm: &mut ThreadState, sig: i32, code: i32) {
    send_signal(vm, sig);
    vm.sig_info_code = code;
}

/// Queue a process-directed signal. Delivery happens when the target process
/// next reaches a signal check boundary.
pub fn send_signal_to_pid(vm: &mut ThreadState, base: u32, pid: i32, sig: i32) -> i64 {
    if pid <= 0 || sig <= 0 || sig as usize >= MAX_SIGNALS {
        return EINVAL;
    }
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES || sig_slots()[idx].is_null() {
        return ESRCH;
    }
    process_pending()[idx] |= 1u64 << (sig - 1);
    if pid == pid_from_vm(vm, base) {
        vm.sig_info_code = SI_USER;
        if let Some(ps) = process_state_from_vm(vm, base) {
            for record in ps.threads.iter() {
                if record.state != THREAD_BLOCKED_FUTEX || record.blocked_addr == 0 {
                    continue;
                }
                crate::syscall::thread::notify_futex_addr(base, record.blocked_addr, 1);
            }
        }
    }
    0
}

/// Queue a thread-directed signal for a thread in the caller's current process.
pub fn send_signal_to_tid(vm: &mut ThreadState, base: u32, tid: i32, sig: i32) -> i64 {
    if tid <= 0 || sig <= 0 || sig as usize >= MAX_SIGNALS {
        return EINVAL;
    }
    if tid == vm.tid {
        send_signal(vm, sig);
        vm.sig_info_code = SI_TKILL;
        return 0;
    }

    let Some(ps) = process_state_from_vm(vm, base) else {
        return ESRCH;
    };

    for record in ps.threads.iter() {
        if record.tid != tid || record.thread_ptr == 0 {
            continue;
        }
        if record.state == THREAD_NONE || record.state == THREAD_DEAD {
            continue;
        }
        let target = unsafe { &mut *(record.thread_ptr as *mut ThreadState) };
        target.sig_pending |= 1u64 << (sig - 1);
        target.sig_info_code = SI_TKILL;
        if record.state == THREAD_BLOCKED_FUTEX && record.blocked_addr != 0 {
            crate::syscall::thread::notify_futex_addr(base, record.blocked_addr, 1);
        }
        return 0;
    }

    ESRCH
}

pub fn queue_sigill(vm: &mut ThreadState, pc: u64) {
    vm.fault_pc = pc;
    vm.fault_addr = pc;
    send_signal_with_code(vm, SIGILL, ILL_ILLOPC);
}

pub fn queue_sigsegv(vm: &mut ThreadState, pc: u64, addr: u64, accerr: bool) {
    vm.fault_pc = pc;
    vm.fault_addr = addr;
    send_signal_with_code(vm, SIGSEGV, if accerr { SEGV_ACCERR } else { SEGV_MAPERR });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{CLONE_FS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VM, SIGURG, SYS_RT_SIGRETURN};
    use crate::syscall::thread as thread_impl;
    use crate::test_helpers::TestVm;
    use crate::types::ThreadState;

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
        t.vm.sig_pending = 1 << 9;
        let pending_addr = t.scratch + 0x80;
        let pending_ret = super::sys_rt_sigpending(&t.vm, t.base, pending_addr, 8);
        assert_eq!(pending_ret, 0);
        assert_eq!(unsafe { crate::guest_mem::read_u64(t.base, pending_addr) }, 1 << 9);

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
        assert_eq!(t.vm.term_signal, crate::abi::SIGTERM);
        let ps =
            unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const crate::types::ProcessState) };
        assert_eq!(ps.thread_count.load(core::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(ps.threads[0].state, crate::types::THREAD_NONE);

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

    #[test]
    fn send_signal_to_pid_queues_process_pending_signal() {
        let mut t = TestVm::new();
        super::sigactions_for(42)[crate::abi::SIGALRM as usize].handler = crate::types::SIG_IGN;

        assert_eq!(super::send_signal_to_pid(&mut t.vm, t.base, 42, crate::abi::SIGALRM), 0);
        assert_eq!(
            t.vm.sig_pending, 0,
            "thread-local pending should stay empty before merge"
        );

        let delivered = super::check_pending(&mut t.vm, t.base);
        assert!(
            delivered,
            "process-directed SIGALRM should be merged and delivered"
        );
        assert_eq!(t.vm.status, crate::abi::STATUS_OK);
        assert_eq!(
            t.vm.sig_pending & (1u64 << (crate::abi::SIGALRM - 1)),
            0,
            "SIGALRM should be cleared after delivery"
        );
    }

    #[test]
    fn send_signal_to_tid_targets_requested_thread() {
        let mut t = TestVm::new();
        t.vm.tid = 1;

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0x88000, 0, 0, 0) as i32;
        assert!(child_tid > 0);

        let child_ptr = thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);

        assert_eq!(super::send_signal_to_tid(&mut t.vm, t.base, child_tid, SIGURG), 0);
        assert_eq!(t.vm.sig_pending, 0, "caller should not receive the directed signal");

        let child = unsafe { &*(child_ptr as *const ThreadState) };
        assert_ne!(
            child.sig_pending & (1u64 << (SIGURG - 1)),
            0,
            "target thread should receive the directed signal"
        );
        assert_eq!(child.sig_info_code, SI_TKILL);
    }

    #[test]
    fn rt_sigreturn_dispatch_preserves_restored_registers() {
        let mut t = TestVm::new();

        let original_pc = 0x1234_5000;
        let original_ra = 0xdead_beef;
        let original_sp = 0x9fff0;
        let original_a0 = 0x1122_3344_5566_7788;
        let original_a1 = 0x2233_4455_6677_8899;
        let original_a2 = 0x3344_5566_7788_99aa;
        let original_a7 = 0x4455_6677_8899_aabb;
        let original_sig_mask = 1u64 << (SIGALRM - 1);

        t.vm.pc = original_pc;
        t.vm.x[1] = original_ra;
        t.vm.x[2] = original_sp;
        t.vm.x[10] = original_a0;
        t.vm.x[11] = original_a1;
        t.vm.x[12] = original_a2;
        t.vm.x[17] = original_a7;
        t.vm.sig_mask = original_sig_mask;

        let act_addr = t.scratch;
        unsafe {
            crate::guest_mem::write_u64(t.base, act_addr, 0x88_000);
            crate::guest_mem::write_u64(t.base, act_addr + 8, SA_SIGINFO);
            crate::guest_mem::write_u64(t.base, act_addr + 16, 0);
        }
        assert_eq!(
            super::sys_rt_sigaction(&mut t.vm, t.base, crate::abi::SIGURG as u64, act_addr, 0, 8),
            0
        );

        super::send_signal(&mut t.vm, crate::abi::SIGURG);
        assert!(super::check_pending(&mut t.vm, t.base));
        assert_eq!(t.vm.pc, 0x88_000, "signal delivery should jump to handler");
        assert_ne!(t.vm.x[2], original_sp, "signal delivery should switch to frame stack");

        t.vm.x[17] = SYS_RT_SIGRETURN;
        let status = crate::syscall::dispatch(&mut t.vm, t.base);
        assert_eq!(status, crate::abi::STATUS_OK);
        assert_eq!(t.vm.pc, original_pc);
        assert_eq!(t.vm.x[1], original_ra);
        assert_eq!(t.vm.x[2], original_sp);
        assert_eq!(t.vm.x[10], original_a0);
        assert_eq!(t.vm.x[11], original_a1);
        assert_eq!(t.vm.x[12], original_a2);
        assert_eq!(t.vm.x[17], original_a7);
        assert_eq!(t.vm.sig_mask, original_sig_mask);
    }

    #[test]
    fn patch_current_signal_frame_a0_updates_rt_sigreturn_result() {
        let mut t = TestVm::new();

        t.vm.pc = 0x1234_5000;
        t.vm.x[1] = 0xdead_beef;
        t.vm.x[2] = 0x9fff0;
        t.vm.x[10] = 5;

        let act_addr = t.scratch;
        unsafe {
            crate::guest_mem::write_u64(t.base, act_addr, 0x88_000);
            crate::guest_mem::write_u64(t.base, act_addr + 8, SA_SIGINFO);
            crate::guest_mem::write_u64(t.base, act_addr + 16, 0);
        }
        assert_eq!(
            super::sys_rt_sigaction(&mut t.vm, t.base, crate::abi::SIGURG as u64, act_addr, 0, 8),
            0
        );

        super::send_signal(&mut t.vm, crate::abi::SIGURG);
        assert!(super::check_pending(&mut t.vm, t.base));
        assert!(super::patch_current_signal_frame_a0(&t.vm, t.base, crate::abi::EINTR));

        t.vm.x[17] = SYS_RT_SIGRETURN;
        let status = crate::syscall::dispatch(&mut t.vm, t.base);
        assert_eq!(status, crate::abi::STATUS_OK);
        assert_eq!(t.vm.x[10], crate::abi::EINTR as u64);
    }

    #[test]
    fn signal_delivery_populates_riscv_arg_home_slots() {
        let mut t = TestVm::new();
        t.vm.x[2] = 0x9fff0;

        let act_addr = t.scratch;
        unsafe {
            crate::guest_mem::write_u64(t.base, act_addr, 0x88_000);
            crate::guest_mem::write_u64(t.base, act_addr + 8, SA_SIGINFO);
            crate::guest_mem::write_u64(t.base, act_addr + 16, 0);
        }
        assert_eq!(
            super::sys_rt_sigaction(&mut t.vm, t.base, crate::abi::SIGURG as u64, act_addr, 0, 8),
            0
        );

        super::send_signal(&mut t.vm, crate::abi::SIGURG);
        assert!(super::check_pending(&mut t.vm, t.base));

        let frame_base = t.vm.x[2];
        unsafe {
            assert_eq!(
                crate::guest_mem::read_u32(t.base, frame_base + SIGFRAME_OFF_ABI_SIGNO),
                crate::abi::SIGURG as u32
            );
            assert_eq!(
                crate::guest_mem::read_u64(t.base, frame_base + SIGFRAME_OFF_ABI_SIGINFO_PTR),
                frame_base + SIGFRAME_OFF_SIGINFO
            );
            assert_eq!(
                crate::guest_mem::read_u64(t.base, frame_base + SIGFRAME_OFF_ABI_UCONTEXT_PTR),
                frame_base + SIGFRAME_OFF_UCONTEXT
            );
        }
    }

    #[test]
    fn nested_sa_onstack_signal_keeps_current_stack() {
        let mut t = TestVm::new();
        let original_sp = 0x9fff0;
        t.vm.x[2] = original_sp;
        t.vm.sigaltstack_sp = 0x50000;
        t.vm.sigaltstack_size = 8192;
        t.vm.sigaltstack_flags = SS_ONSTACK;

        let act_addr = t.scratch;
        unsafe {
            crate::guest_mem::write_u64(t.base, act_addr, 0x88_000);
            crate::guest_mem::write_u64(t.base, act_addr + 8, SA_SIGINFO | SA_ONSTACK);
            crate::guest_mem::write_u64(t.base, act_addr + 16, 0);
        }
        assert_eq!(
            super::sys_rt_sigaction(&mut t.vm, t.base, crate::abi::SIGURG as u64, act_addr, 0, 8),
            0
        );

        super::send_signal(&mut t.vm, crate::abi::SIGURG);
        assert!(super::check_pending(&mut t.vm, t.base));

        let expected_frame_base = (original_sp - SIGFRAME_SIZE) & !15;
        let altstack_frame_base = ((t.vm.sigaltstack_sp + t.vm.sigaltstack_size) - SIGFRAME_SIZE) & !15;
        assert_eq!(t.vm.x[2], expected_frame_base);
        assert_ne!(t.vm.x[2], altstack_frame_base);
    }

    #[test]
    fn synchronous_sigsegv_ignores_signal_mask() {
        let mut t = TestVm::new();
        let handler = 0x88_000;
        let act_addr = t.scratch;
        t.vm.x[2] = 0x9fff0;

        unsafe {
            crate::guest_mem::write_u64(t.base, act_addr, handler);
            crate::guest_mem::write_u64(t.base, act_addr + 8, SA_SIGINFO);
            crate::guest_mem::write_u64(t.base, act_addr + 16, 0);
        }
        assert_eq!(
            super::sys_rt_sigaction(&mut t.vm, t.base, crate::abi::SIGSEGV as u64, act_addr, 0, 8),
            0
        );

        t.vm.sig_mask = 1u64 << (crate::abi::SIGSEGV - 1);
        super::queue_sigsegv(&mut t.vm, 0x1234, 0x5678, false);

        assert!(super::check_pending(&mut t.vm, t.base));
        assert_eq!(t.vm.pc, handler);
        assert_eq!(t.vm.fault_pc, 0x1234);
        assert_eq!(t.vm.fault_addr, 0x5678);
        assert_eq!(t.vm.sig_pending & (1u64 << (crate::abi::SIGSEGV - 1)), 0);
    }
}
