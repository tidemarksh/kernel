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
    MAX_SIGNALS, ProcessState, SIG_DFL, SIG_IGN, SigAction, THREAD_BLOCKED_FUTEX, THREAD_DEAD,
    THREAD_NONE, ThreadRecord, ThreadState,
};

// SA flags (https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal-defs.h)
const SA_ONSTACK: u64 = 0x08000000;
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
static mut SIGNALFD_PTR: *mut [SignalFdState; MAX_SIGNALFDS + 1] = core::ptr::null_mut();

#[cfg(any(test, feature = "harness"))]
#[derive(Clone, Copy)]
pub(crate) struct ProcessSignalStateImage {
    sig_slots: [u32; MAX_PROCESSES],
    process_pending: [u64; MAX_PROCESSES],
}

#[cfg(any(test, feature = "harness"))]
impl ProcessSignalStateImage {
    pub(crate) fn empty() -> Self {
        Self {
            sig_slots: [0; MAX_PROCESSES],
            process_pending: [0; MAX_PROCESSES],
        }
    }
}

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
}

#[derive(Clone, Copy)]
struct SignalFdState {
    used: u32,
    _pad: u32,
    mask: u64,
}

const EMPTY_SIGNALFD_STATE: SignalFdState = SignalFdState {
    used: 0,
    _pad: 0,
    mask: 0,
};

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
};
    SIGNAL_TRACE_RING_CAP];
static mut DEFAULT_SIGNAL_RING_LEN: u32 = 0;
static mut DEFAULT_SIGNAL_RING_NEXT: u32 = 0;

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

#[inline(always)]
fn signalfd_slots() -> &'static mut [SignalFdState; MAX_SIGNALFDS + 1] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(SIGNALFD_PTR));
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

fn record_default_signal(vm: &ThreadState, sig: usize) {
    let trace = DefaultSignalTrace {
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

#[inline(always)]
pub fn is_current_sigreturn_trampoline(sp: u64, pc: u64) -> bool {
    sp != 0 && pc == sp + SIGFRAME_OFF_TRAMPOLINE
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

#[cfg(any(test, feature = "harness"))]
pub(crate) fn capture_process_signal_state_into(image: &mut ProcessSignalStateImage) {
    for (idx, slot) in sig_slots().iter().enumerate() {
        image.sig_slots[idx] = *slot as u32;
    }
    image.process_pending = *process_pending();
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn restore_process_signal_state_from(image: &ProcessSignalStateImage) {
    for (idx, slot) in sig_slots().iter_mut().enumerate() {
        *slot = image.sig_slots[idx] as *mut [SigAction; MAX_SIGNALS];
    }
    *process_pending() = image.process_pending;
}

#[inline(always)]
fn sigactions_for(pid: i32) -> Option<&'static mut [SigAction; MAX_SIGNALS]> {
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

unsafe fn read_thread_record(record: *const ThreadRecord) -> ThreadRecord {
    unsafe { core::ptr::read_unaligned(record) }
}

unsafe fn write_thread_record(record: *mut ThreadRecord, value: ThreadRecord) {
    unsafe { core::ptr::write_unaligned(record, value) }
}

fn take_thread_pending_signals(vm: &mut ThreadState, base: u32) {
    let Some(ps) = process_state_from_vm(vm, base) else {
        return;
    };
    let tid = vm.tid;
    if tid <= 0 {
        return;
    }
    for index in 0..ps.threads.len() {
        let record_ptr = core::ptr::addr_of_mut!(ps.threads[index]);
        let mut record = unsafe { read_thread_record(record_ptr) };
        if record.tid != tid {
            continue;
        }
        vm.sig_pending |= record.pending_sigset;
        if record.pending_siginfo_code != 0 {
            vm.sig_info_code = record.pending_siginfo_code;
        }
        record.pending_sigset = 0;
        record.pending_siginfo_code = 0;
        unsafe { write_thread_record(record_ptr, record) };
        return;
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
        core::ptr::write(core::ptr::addr_of_mut!(SIGNALFD_PTR), core::ptr::null_mut());

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

        let signalfd_size = core::mem::size_of::<[SignalFdState; MAX_SIGNALFDS + 1]>() as u32;
        let signalfd_align = core::mem::align_of::<SignalFdState>() as u32;
        let signalfd_ptr = crate::alloc::alloc_zeroed(signalfd_size, signalfd_align);
        if signalfd_ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(SIGNALFD_PTR),
            signalfd_ptr as *mut [SignalFdState; MAX_SIGNALFDS + 1],
        );
    }
}

fn signalfd_slot(idx: u32) -> Option<&'static mut SignalFdState> {
    if idx == 0 || idx as usize > MAX_SIGNALFDS {
        return None;
    }
    Some(&mut signalfd_slots()[idx as usize])
}

fn signalfd_mask_sanitized(mask: u64) -> u64 {
    let unblockable = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));
    mask & !unblockable
}

fn alloc_signalfd_slot(mask: u64) -> Option<u32> {
    let slots = signalfd_slots();
    for idx in 1..=MAX_SIGNALFDS {
        if slots[idx].used == 0 {
            slots[idx] = SignalFdState {
                used: 1,
                _pad: 0,
                mask: signalfd_mask_sanitized(mask),
            };
            return Some(idx as u32);
        }
    }
    None
}

pub fn close_signalfd(signalfd_idx: u32) {
    if let Some(slot) = signalfd_slot(signalfd_idx) {
        *slot = EMPTY_SIGNALFD_STATE;
    }
}

fn peek_thread_pending_signals(vm: &ThreadState, base: u32) -> u64 {
    let Some(ps) = process_state_from_vm(vm, base) else {
        return 0;
    };
    for index in 0..ps.threads.len() {
        let record = unsafe { read_thread_record(core::ptr::addr_of!(ps.threads[index])) };
        if record.tid == vm.tid {
            return record.pending_sigset;
        }
    }
    0
}

fn signalfd_pending_mask(vm: &ThreadState, base: u32, mask: u64) -> u64 {
    let pid = pid_from_vm(vm, base);
    let mut pending = vm.sig_pending | peek_thread_pending_signals(vm, base);
    if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES {
            pending |= process_pending()[idx];
        }
    }
    pending & signalfd_mask_sanitized(mask)
}

fn consume_signalfd_signal(vm: &mut ThreadState, base: u32, mask: u64) -> Option<(usize, i32)> {
    take_thread_pending_signals(vm, base);

    let matched = signalfd_pending_mask(vm, base, mask);
    if matched == 0 {
        return None;
    }

    let sig = matched.trailing_zeros() as usize + 1;
    let bit = 1u64 << (sig - 1);
    if (vm.sig_pending & bit) != 0 {
        vm.sig_pending &= !bit;
        let code = if vm.sig_info_code != 0 {
            vm.sig_info_code
        } else {
            SI_USER
        };
        vm.sig_info_code = 0;
        return Some((sig, code));
    }

    let pid = pid_from_vm(vm, base);
    if pid > 0 {
        let idx = (pid - 1) as usize;
        if idx < MAX_PROCESSES && (process_pending()[idx] & bit) != 0 {
            process_pending()[idx] &= !bit;
            return Some((sig, SI_USER));
        }
    }

    None
}

fn write_signalfd_siginfo(vm: &ThreadState, base: u32, buf: u64, sig: usize, code: i32, pid: i32) {
    unsafe {
        guest_mem::zero_mem(base, buf, 128);
        guest_mem::write_u32(base, buf, sig as u32);
        guest_mem::write_u32(base, buf + 4, 0);
        guest_mem::write_u32(base, buf + 8, code as u32);
        guest_mem::write_u32(base, buf + 12, pid as u32);
        guest_mem::write_u32(base, buf + 16, vm.uid as u32);
        guest_mem::write_u32(base, buf + 24, vm.tid as u32);
    }
}

pub fn signalfd_is_readable(vm: &ThreadState, base: u32, signalfd_idx: u32) -> bool {
    let Some(slot) = signalfd_slot(signalfd_idx) else {
        return false;
    };
    slot.used != 0 && signalfd_pending_mask(vm, base, slot.mask) != 0
}

pub fn signalfd_read(
    vm: &mut ThreadState,
    base: u32,
    buf: u64,
    count: u64,
    signalfd_idx: u32,
) -> i64 {
    if count < 128 {
        return EINVAL;
    }
    if !crate::syscall::memory::guest_range_accessible(base, buf, 128) {
        return EFAULT;
    }
    let Some(slot) = signalfd_slot(signalfd_idx) else {
        return EINVAL;
    };
    let Some((sig, code)) = consume_signalfd_signal(vm, base, slot.mask) else {
        return EAGAIN;
    };
    write_signalfd_siginfo(vm, base, buf, sig, code, pid_from_vm(vm, base));
    128
}

pub fn sys_signalfd4(
    vm: &mut ThreadState,
    base: u32,
    fd: i64,
    mask_addr: u64,
    sigsetsize: u64,
    flags: u64,
) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    let allowed_flags = (O_CLOEXEC | O_NONBLOCK) as u64;
    if flags & !allowed_flags != 0 {
        return EINVAL;
    }
    if mask_addr == 0 || !crate::syscall::memory::guest_range_accessible(base, mask_addr, 8) {
        return EFAULT;
    }
    let mask = unsafe { guest_mem::read_u64(base, mask_addr) };

    if fd == -1 {
        let Some(signalfd_idx) = alloc_signalfd_slot(mask) else {
            return EMFILE;
        };
        let new_fd = crate::fs::fd_table::open_signalfd(vm, base, signalfd_idx, flags as i32);
        if new_fd < 0 {
            close_signalfd(signalfd_idx);
        }
        return new_fd;
    }

    let Some(ofd) = crate::fs::fd_table::get_ofd(base, vm, fd as u64) else {
        return EBADF;
    };
    if ofd.fd_type != FD_TYPE_SIGNALFD {
        return EINVAL;
    }
    let Some(slot) = signalfd_slot(ofd.ino) else {
        return EINVAL;
    };
    slot.mask = signalfd_mask_sanitized(mask);
    fd
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
const UCONTEXT_OFF_RESERVED_PAD: u64 = 168;
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
fn push_signal_frame(vm: &mut ThreadState, base: u32, sig: usize, action: &SigAction) -> bool {
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
        LAST_TRAMPOLINE_PC = frame_base + SIGFRAME_OFF_TRAMPOLINE;
    }

    // Set up registers for handler entry
    vm.x[2] = frame_base;
    vm.x[1] = frame_base + SIGFRAME_OFF_TRAMPOLINE;
    vm.x[10] = sig as u64;
    vm.x[11] = siginfo_base;
    vm.x[12] = ucontext_base;
    vm.pc = action.handler;
    true
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
        vm.sigaltstack_flags =
            guest_mem::read_u64(base, frame_base + SIGFRAME_OFF_ALTSTACK_FLAGS) as i32;
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
    take_thread_pending_signals(vm, base);

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

    let action = sigactions_for(pid)
        .map(|table| table[sig])
        .unwrap_or(SigAction {
            handler: SIG_DFL,
            flags: 0,
            mask: 0,
        });

    match action.handler {
        0 => {
            // SIG_DFL: default action
            match sig as i32 {
                SIGCHLD | SIGURG | SIGWINCH => {} // ignore by default
                SIGCONT => {}                     // ignore (no job control)
                _ => {
                    record_default_signal(vm, sig);
                    crate::syscall::thread::terminate_process_with_reason(
                        vm,
                        base,
                        128 + sig as i32,
                        sig as i32,
                        crate::syscall::thread::TERMINATE_REASON_DEFAULT_SIGNAL,
                    );
                }
            }
        }
        1 => {} // SIG_IGN: ignore
        _handler_addr => {
            // User handler: push signal frame and redirect to handler
            if !push_signal_frame(vm, base, sig, &action) {
                record_default_signal(vm, sig);
                crate::syscall::thread::terminate_process_with_reason(
                    vm,
                    base,
                    128 + sig as i32,
                    sig as i32,
                    crate::syscall::thread::TERMINATE_REASON_DEFAULT_SIGNAL,
                );
            }
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
            for index in 0..ps.threads.len() {
                let record = unsafe { read_thread_record(core::ptr::addr_of!(ps.threads[index])) };
                if record.state != THREAD_BLOCKED_FUTEX || record.blocked_addr == 0 {
                    continue;
                }
                // FUTEX_WAIT may wake spuriously. Prefer waking blocked threads
                // over directly reading another worker's ThreadState.
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

    for index in 0..ps.threads.len() {
        let record_ptr = core::ptr::addr_of_mut!(ps.threads[index]);
        let mut record = unsafe { read_thread_record(record_ptr) };
        if record.tid != tid || record.thread_ptr == 0 {
            continue;
        }
        if record.state == THREAD_NONE || record.state == THREAD_DEAD {
            continue;
        }
        record.pending_sigset |= 1u64 << (sig - 1);
        record.pending_siginfo_code = SI_TKILL;
        if record.state == THREAD_BLOCKED_FUTEX && record.blocked_addr != 0 {
            crate::syscall::thread::notify_futex_addr(base, record.blocked_addr, 1);
        }
        unsafe { write_thread_record(record_ptr, record) };
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
