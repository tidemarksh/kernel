use super::pending::{pid_from_vm, process_pending};
use crate::abi::*;
use crate::guest_mem;
use crate::types::{MAX_SIGNALS, SIG_DFL, SIG_IGN, SigAction, ThreadState};

/// Per-process signal disposition tables, allocated in kernel Worker linear memory.
/// Each process gets its own [SigAction; MAX_SIGNALS] table, indexed by PID.
///
/// Signal dispositions are process-wide (shared by all threads in a process).
/// On execve, caught signals (handler != SIG_DFL and != SIG_IGN) are reset to SIG_DFL.
///
/// Semantics: https://man7.org/linux/man-pages/man2/rt_sigaction.2.html
/// execve reset: https://man7.org/linux/man-pages/man2/execve.2.html
///
/// SIG_SLOTS_PTR is an array of MAX_PROCESSES pointers, each pointing to a
/// per-process table.
static mut SIG_SLOTS_PTR: *mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES] =
    core::ptr::null_mut();

#[cfg(any(test, feature = "harness"))]
#[derive(Clone, Copy)]
pub(crate) struct SignalActionStateImage {
    sig_slots: [u32; MAX_PROCESSES],
}

#[cfg(any(test, feature = "harness"))]
impl SignalActionStateImage {
    pub(crate) fn empty() -> Self {
        Self {
            sig_slots: [0; MAX_PROCESSES],
        }
    }
}

#[inline(always)]
pub(super) fn sig_slots() -> &'static mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(SIG_SLOTS_PTR));
        &mut *p
    }
}

pub(super) fn init_action_tables() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SIG_SLOTS_PTR),
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
    }
}

pub fn sig_slots_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(SIG_SLOTS_PTR)) as u32 }
}

pub fn signal_slots_bytes() -> u32 {
    core::mem::size_of::<[*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES]>() as u32
}

pub fn signal_action_table_bytes() -> u32 {
    core::mem::size_of::<[SigAction; MAX_SIGNALS]>() as u32
}

pub fn attach_signal_action_state(sig_slots_ptr: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SIG_SLOTS_PTR),
            sig_slots_ptr as *mut [*mut [SigAction; MAX_SIGNALS]; MAX_PROCESSES],
        );
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn capture_signal_action_state_into(image: &mut SignalActionStateImage) {
    for (idx, slot) in sig_slots().iter().enumerate() {
        image.sig_slots[idx] = *slot as u32;
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn restore_signal_action_state_from(image: &SignalActionStateImage) {
    for (idx, slot) in sig_slots().iter_mut().enumerate() {
        *slot = image.sig_slots[idx] as *mut [SigAction; MAX_SIGNALS];
    }
}

#[inline(always)]
pub(super) fn sigactions_for(pid: i32) -> Option<&'static mut [SigAction; MAX_SIGNALS]> {
    if pid <= 0 {
        return None;
    }
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES {
        return None;
    }
    let slot = sig_slots()[idx];
    if slot.is_null() {
        return None;
    }
    unsafe { Some(&mut *slot) }
}

/// Allocate a new signal disposition table for a process.
pub fn init_for_process(pid: i32) {
    let idx = (pid - 1) as usize;
    if idx >= MAX_PROCESSES {
        return;
    }
    unsafe {
        let existing = sig_slots()[idx];
        if !existing.is_null() {
            core::ptr::write_bytes(
                existing as *mut u8,
                0,
                core::mem::size_of::<[SigAction; MAX_SIGNALS]>(),
            );
            process_pending()[idx] = 0;
            return;
        }
        let size = core::mem::size_of::<[SigAction; MAX_SIGNALS]>() as u32;
        let align = core::mem::align_of::<SigAction>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            panic!(
                "signal::init_for_process oom pid={} idx={} size={} align={} heap_base=0x{:x} heap_ptr=0x{:x} heap_used={}",
                pid,
                idx,
                size,
                align,
                crate::alloc::heap_base(),
                crate::alloc::heap_ptr(),
                crate::alloc::heap_used(),
            );
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
    let Some(parent) = sigactions_for(parent_pid) else {
        return;
    };
    let Some(child) = sigactions_for(child_pid) else {
        return;
    };
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
    if !sig_slots()[new_idx].is_null() {
        return;
    }
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
    let Some(table) = sigactions_for(pid) else {
        return;
    };
    for action in table.iter_mut().take(MAX_SIGNALS).skip(1) {
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
    let Some(table) = sigactions_for(pid) else {
        return ESRCH;
    };

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
