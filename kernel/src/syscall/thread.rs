//! Thread syscalls: clone, futex, exit, exit_group, set_tid_address,
//! set_robust_list, get_robust_list.
//!
//! clone(CLONE_VM | CLONE_THREAD) → STATUS_CLONE_SPAWN → TS spawns Worker.
//! futex(WAIT/WAKE) uses guest Memory Atomics directly.
//! futex(CMP_REQUEUE) reuses the shared thread registry as the wait queue.
//!
//! Semantics:
//! https://man7.org/linux/man-pages/man2/clone.2.html
//! https://man7.org/linux/man-pages/man2/futex.2.html
//! https://man7.org/linux/man-pages/man2/set_tid_address.2.html

use crate::abi::*;
use crate::guest_mem;
use crate::types::{
    ProcessState, THREAD_BLOCKED_FUTEX, THREAD_DEAD, THREAD_EXITING, THREAD_NONE, THREAD_RUNNING,
    ThreadRecord, ThreadState,
};
use core::sync::atomic::Ordering;

#[cfg(any(
    test,
    all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        feature = "harness"
    )
))]
#[inline(always)]
fn wake_external_waiters(caller_pid: i32, addr: u64, max_wake: u32) -> u32 {
    crate::harness::support::wake_external_futex_waits_from_pid(caller_pid, addr, max_wake)
}

#[cfg(not(any(
    test,
    all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        feature = "harness"
    )
)))]
#[inline(always)]
fn wake_external_waiters(caller_pid: i32, addr: u64, max_wake: u32) -> u32 {
    let _ = (caller_pid, addr, max_wake);
    0
}

#[cfg(any(
    test,
    all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        feature = "harness"
    )
))]
#[inline(always)]
fn requeue_external_waiters(addr: u64, new_addr: u64, max_requeue: u32) -> u32 {
    crate::harness::support::requeue_external_futex_waits(addr, new_addr, max_requeue)
}

#[cfg(not(any(
    test,
    all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        feature = "harness"
    )
)))]
#[inline(always)]
fn requeue_external_waiters(addr: u64, new_addr: u64, max_requeue: u32) -> u32 {
    let _ = (addr, new_addr, max_requeue);
    0
}

#[cfg(any(
    test,
    all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        feature = "harness"
    )
))]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn record_futex_trace(
    vm: &ThreadState,
    op: u32,
    addr: u64,
    addr2: u64,
    val: u64,
    val3: u64,
    current: u32,
    local: u32,
    external: u32,
    requeued: u32,
    result: i64,
    status: i32,
) {
    crate::harness::trace::record_futex_trace(
        vm as *const ThreadState as u32,
        vm.tid,
        op,
        addr,
        addr2,
        val,
        val3,
        current,
        local,
        external,
        requeued,
        result,
        status,
    );
}

#[cfg(not(any(
    test,
    all(
        any(target_arch = "wasm32", target_arch = "wasm64"),
        feature = "harness"
    )
)))]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn record_futex_trace(
    vm: &ThreadState,
    op: u32,
    addr: u64,
    addr2: u64,
    val: u64,
    val3: u64,
    current: u32,
    local: u32,
    external: u32,
    requeued: u32,
    result: i64,
    status: i32,
) {
    let _ = (
        vm, op, addr, addr2, val, val3, current, local, external, requeued, result, status,
    );
}

const ROBUST_LIST_HEAD_LEN: u64 = 24;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
const ROBUST_LIST_LIMIT: u32 = 2048;

#[derive(Clone, Copy)]
struct CloneSpawnTrace {
    tid: i32,
    flags: u64,
    pc: u64,
    ra: u64,
    gp: u64,
    sp: u64,
    tls: u64,
    child_tidptr: u64,
    s11: u64,
    stack_m32: u64,
    stack_m24: u64,
    stack_m16: u64,
    stack_m8: u64,
}

static mut LAST_CLONE_SPAWN: CloneSpawnTrace = CloneSpawnTrace {
    tid: 0,
    flags: 0,
    pc: 0,
    ra: 0,
    gp: 0,
    sp: 0,
    tls: 0,
    child_tidptr: 0,
    s11: 0,
    stack_m32: 0,
    stack_m24: 0,
    stack_m16: 0,
    stack_m8: 0,
};

static mut NEXT_TID_HINTS: [i32; MAX_PROCESSES] = [0; MAX_PROCESSES];

const THREAD_COUNT_TRACE_INIT_MAIN: u32 = 1;
const THREAD_COUNT_TRACE_CLONE_INC: u32 = 2;
const THREAD_COUNT_TRACE_EXIT_DEC: u32 = 3;
const THREAD_COUNT_TRACE_TERMINATE: u32 = 4;
const THREAD_COUNT_TRACE_EXEC_RESET: u32 = 5;

pub const TERMINATE_REASON_UNKNOWN: u32 = 0;
pub const TERMINATE_REASON_EXIT_GROUP: u32 = 1;
pub const TERMINATE_REASON_DEFAULT_SIGNAL: u32 = 2;

pub fn last_clone_spawn() -> (i32, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    unsafe {
        let t = LAST_CLONE_SPAWN;
        (
            t.tid,
            t.pc,
            t.ra,
            t.gp,
            t.sp,
            t.s11,
            t.stack_m32,
            t.stack_m24,
            t.stack_m16,
            t.stack_m8,
        )
    }
}

pub fn last_clone_spawn_details() -> (i32, u64, u64, u64, u64, u64) {
    unsafe {
        let t = LAST_CLONE_SPAWN;
        (t.tid, t.flags, t.pc, t.sp, t.tls, t.child_tidptr)
    }
}

pub fn init() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(NEXT_TID_HINTS), [0; MAX_PROCESSES]);
    }
    #[cfg(any(
        test,
        all(
            any(target_arch = "wasm32", target_arch = "wasm64"),
            feature = "harness"
        )
    ))]
    crate::harness::trace::clear_futex_trace();
}

fn process_slot_from_ptr(base: u32, process_ptr: u32) -> Option<usize> {
    let ps = process_state_ptr(base, process_ptr)?;
    let pid = unsafe { (*ps).pid };
    if pid <= 0 || pid as usize > MAX_PROCESSES {
        return None;
    }
    Some((pid - 1) as usize)
}

fn set_next_tid_hint(base: u32, process_ptr: u32, next_tid: i32) {
    let Some(slot) = process_slot_from_ptr(base, process_ptr) else {
        return;
    };
    unsafe {
        NEXT_TID_HINTS[slot] = next_tid;
    }
}

fn next_tid_hint(base: u32, process_ptr: u32) -> i32 {
    let Some(slot) = process_slot_from_ptr(base, process_ptr) else {
        return 1;
    };
    unsafe { NEXT_TID_HINTS[slot] }
}

fn process_state_ptr(base: u32, process_ptr: u32) -> Option<*mut ProcessState> {
    if process_ptr == 0 {
        return None;
    }
    Some((base as u64 + process_ptr as u64) as *mut ProcessState)
}

fn thread_record_ptr(base: u32, process_ptr: u32, tid: i32) -> Option<*mut ThreadRecord> {
    if tid <= 0 || tid as usize > MAX_THREADS {
        return None;
    }
    let ps = process_state_ptr(base, process_ptr)?;
    let thread_index = (tid - 1) as usize;
    unsafe { Some(core::ptr::addr_of_mut!((*ps).threads[thread_index])) }
}

unsafe fn read_thread_record(record: *const ThreadRecord) -> ThreadRecord {
    unsafe { core::ptr::read_unaligned(record) }
}

unsafe fn write_thread_record(record: *mut ThreadRecord, value: ThreadRecord) {
    unsafe { core::ptr::write_unaligned(record, value) };
}

unsafe fn write_thread_record_state(record: *mut ThreadRecord, state: i32) {
    unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!((*record).state), state) };
}

unsafe fn write_thread_record_blocked_addr(record: *mut ThreadRecord, blocked_addr: u64) {
    unsafe {
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*record).blocked_addr),
            blocked_addr,
        )
    };
}

unsafe fn write_thread_record_clear_child_tid(record: *mut ThreadRecord, clear_child_tid: u64) {
    unsafe {
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*record).clear_child_tid),
            clear_child_tid,
        )
    };
}

unsafe fn mark_thread_record_blocked_futex(
    record: *mut ThreadRecord,
    clear_child_tid: u64,
    blocked_addr: u64,
) {
    unsafe {
        write_thread_record_clear_child_tid(record, clear_child_tid);
        write_thread_record_blocked_addr(record, blocked_addr);
        write_thread_record_state(record, THREAD_BLOCKED_FUTEX);
    }
}

unsafe fn mark_thread_record_running_from_futex(record: *mut ThreadRecord, clear_child_tid: u64) {
    unsafe {
        write_thread_record_state(record, THREAD_RUNNING);
        write_thread_record_blocked_addr(record, 0);
        write_thread_record_clear_child_tid(record, clear_child_tid);
    }
}

fn thread_state_from_record_ptr(thread_ptr: u32) -> Option<*mut ThreadState> {
    if thread_ptr == 0 {
        return None;
    }

    let align = core::mem::align_of::<ThreadState>();
    let absolute = thread_ptr as usize;
    if (absolute & (align - 1)) != 0 {
        return None;
    }

    let end = absolute.checked_add(core::mem::size_of::<ThreadState>())?;
    let memory_size = crate::wasm::memory_size_bytes();
    if end as u64 > memory_size {
        return None;
    }

    Some(absolute as *mut ThreadState)
}

fn matching_thread_state_from_record(
    record: &ThreadRecord,
    base: u32,
    process_ptr: u32,
) -> Option<*mut ThreadState> {
    let thread_ptr = thread_state_from_record_ptr(record.thread_ptr)?;
    unsafe {
        let thread = &*thread_ptr;
        if thread.guest_base != base
            || thread.process_ptr != process_ptr
            || thread.tid != record.tid
        {
            return None;
        }
    }
    Some(thread_ptr)
}

fn clear_tid_and_wake(process_ptr: u32, base: u32, addr: u64) -> u32 {
    if addr == 0 {
        return 0;
    }
    unsafe {
        guest_mem::write_u32(base, addr, 0);
    }
    wake_futex_waiters_by_process_ptr(process_ptr, base, addr, u32::MAX, FUTEX_BITSET_MATCH_ANY)
}

fn wake_futex_waiters_by_process_ptr(
    process_ptr: u32,
    base: u32,
    addr: u64,
    max_wake: u32,
    wake_bitset: u32,
) -> u32 {
    if process_ptr == 0 || max_wake == 0 {
        return 0;
    }

    let woken = unsafe {
        let ps = &mut *((base as u64 + process_ptr as u64) as *mut ProcessState);
        let mut woken = 0;
        for record in ps.threads.iter_mut() {
            if woken >= max_wake {
                break;
            }
            if record.state != THREAD_BLOCKED_FUTEX || record.blocked_addr != addr {
                continue;
            }
            let waiter_bitset = thread_state_from_record_ptr(record.thread_ptr)
                .map(|thread_ptr| (*thread_ptr).futex_wait_bitset)
                .unwrap_or(FUTEX_BITSET_MATCH_ANY);
            if (waiter_bitset & wake_bitset) == 0 {
                continue;
            }
            write_thread_record_state(record, THREAD_RUNNING);
            write_thread_record_blocked_addr(record, 0);
            woken += 1;
        }
        woken
    };
    if woken > 0 {
        notify_futex_addr(base, addr, woken);
    }
    woken
}

#[cfg(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
))]
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn tidemark_memory_atomic_notify(ptr: *mut i32, max_wake: u32) -> u32;
}

#[cfg(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
))]
pub(crate) fn notify_futex_addr(base: u32, addr: u64, max_wake: u32) {
    unsafe {
        let ptr = (base as u64 + addr as u64) as usize as *mut i32;
        let _ = tidemark_memory_atomic_notify(ptr, max_wake);
    }
}

#[cfg(not(all(
    any(target_arch = "wasm32", target_arch = "wasm64"),
    target_os = "unknown"
)))]
pub(crate) fn notify_futex_addr(_base: u32, _addr: u64, _max_wake: u32) {}

fn requeue_futex_waiters_by_process_ptr(
    process_ptr: u32,
    base: u32,
    addr: u64,
    new_addr: u64,
    max_requeue: u32,
) -> u32 {
    if process_ptr == 0 || max_requeue == 0 || addr == new_addr {
        return 0;
    }

    unsafe {
        let ps = &mut *((base as u64 + process_ptr as u64) as *mut ProcessState);
        let mut requeued = 0;
        for record in ps.threads.iter_mut() {
            if requeued >= max_requeue {
                break;
            }
            if record.state != THREAD_BLOCKED_FUTEX || record.blocked_addr != addr {
                continue;
            }
            record.blocked_addr = new_addr;
            requeued += 1;
        }
        requeued
    }
}

fn mark_robust_futex_owner_died(
    process_ptr: u32,
    base: u32,
    owner_tid: u32,
    entry_addr: u64,
    futex_offset: i64,
) {
    let futex_addr = if futex_offset >= 0 {
        match entry_addr.checked_add(futex_offset as u64) {
            Some(addr) => addr,
            None => return,
        }
    } else {
        match entry_addr.checked_sub((-futex_offset) as u64) {
            Some(addr) => addr,
            None => return,
        }
    };

    if !crate::syscall::memory::guest_range_accessible(base, futex_addr, 4) {
        return;
    }
    let owner = unsafe { guest_mem::read_u32(base, futex_addr) };
    if owner & FUTEX_TID_MASK != owner_tid {
        return;
    }

    let updated = (owner & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
    unsafe {
        guest_mem::write_u32(base, futex_addr, updated);
    }
    wake_futex_waiters_by_process_ptr(
        process_ptr,
        base,
        futex_addr,
        u32::MAX,
        FUTEX_BITSET_MATCH_ANY,
    );
}

fn cleanup_robust_futexes(process_ptr: u32, base: u32, owner_tid: u32, robust_head: u64) {
    if process_ptr == 0 || owner_tid == 0 || robust_head == 0 {
        return;
    }
    if !crate::syscall::memory::guest_range_accessible(base, robust_head, ROBUST_LIST_HEAD_LEN) {
        return;
    }

    let first = unsafe { guest_mem::read_u64(base, robust_head) };
    let futex_offset = unsafe { guest_mem::read_u64(base, robust_head + 8) as i64 };
    let pending = unsafe { guest_mem::read_u64(base, robust_head + 16) };

    let mut entry = first;
    let mut walked = 0;
    while entry != 0 && entry != robust_head && walked < ROBUST_LIST_LIMIT {
        if !crate::syscall::memory::guest_range_accessible(base, entry, 8) {
            break;
        }
        mark_robust_futex_owner_died(process_ptr, base, owner_tid, entry, futex_offset);
        entry = unsafe { guest_mem::read_u64(base, entry) };
        walked += 1;
    }

    if pending != 0 && pending != robust_head {
        mark_robust_futex_owner_died(process_ptr, base, owner_tid, pending, futex_offset);
    }
}

fn decrement_thread_count(vm: &ThreadState, base: u32) -> u32 {
    let Some(ps) = process_state_ptr(base, vm.process_ptr) else {
        return 0;
    };
    unsafe {
        let before = (*ps)
            .thread_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            })
            .unwrap_or(0);
        let after = before.saturating_sub(1);
        crate::tracepoints::record_thread_count(
            THREAD_COUNT_TRACE_EXIT_DEC,
            vm as *const ThreadState as u32,
            vm.tid,
            vm.process_ptr,
            before,
            after,
        );
        after
    }
}

pub fn init_main_thread(vm_ptr: u32, base: u32) {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let Some(ps) = process_state_ptr(base, vm.process_ptr) else {
            return;
        };
        let ps = &mut *ps;

        let before = ps.thread_count.load(Ordering::Acquire);
        ps.thread_count.store(1, Ordering::Release);
        for record in ps.threads.iter_mut() {
            *record = ThreadRecord::empty();
        }

        if vm.tid > 0 && vm.tid as usize <= MAX_THREADS {
            ps.threads[(vm.tid - 1) as usize] =
                ThreadRecord::new(vm.tid, THREAD_RUNNING, vm_ptr, vm.clear_child_tid, 0);
        }

        let gen_ptr =
            core::ptr::addr_of!(ps.reservation_gen) as *const core::sync::atomic::AtomicU32;
        let lock_ptr =
            core::ptr::addr_of!(ps.reservation_lock) as *const core::sync::atomic::AtomicU32;
        let tc_ptr = core::ptr::addr_of!(ps.thread_count);
        guest_mem::init(gen_ptr, lock_ptr, tc_ptr);
        crate::tracepoints::record_thread_count(
            THREAD_COUNT_TRACE_INIT_MAIN,
            vm_ptr,
            vm.tid,
            vm.process_ptr,
            before,
            1,
        );
        set_next_tid_hint(base, vm.process_ptr, vm.tid.saturating_add(1).max(1));
    }
}

pub fn discard_other_threads_for_exec(vm: &ThreadState, base: u32) -> u32 {
    unsafe {
        let Some(ps) = process_state_ptr(base, vm.process_ptr) else {
            return 0;
        };
        let ps = &mut *ps;
        let current_idx = if vm.tid > 0 && vm.tid as usize <= MAX_THREADS {
            Some((vm.tid - 1) as usize)
        } else {
            None
        };
        let current_ptr = current_idx
            .and_then(|idx| ps.threads.get(idx))
            .map(|record| record.thread_ptr)
            .unwrap_or(0);

        let mut discarded = 0;
        for (idx, record) in ps.threads.iter_mut().enumerate() {
            if Some(idx) == current_idx {
                continue;
            }
            if record.state == THREAD_NONE || record.state == THREAD_DEAD {
                continue;
            }
            let thread_vm = if record.tid > 0 {
                matching_thread_state_from_record(record, base, vm.process_ptr)
            } else {
                None
            };
            if thread_vm.is_none() {
                *record = ThreadRecord::empty();
                discarded += 1;
                continue;
            }
            if let Some(thread_vm) = thread_vm {
                crate::fs::fd_table::clear_blocked_ofd_pin(&mut *thread_vm);
            }
            if record.clear_child_tid != 0 {
                clear_tid_and_wake(vm.process_ptr, base, record.clear_child_tid);
            }
            *record = ThreadRecord::empty();
            discarded += 1;
        }

        if let Some(idx) = current_idx {
            let before = ps.thread_count.load(Ordering::Acquire);
            ps.threads[idx] =
                ThreadRecord::new(vm.tid, THREAD_RUNNING, current_ptr, vm.clear_child_tid, 0);
            ps.thread_count.store(1, Ordering::Release);
            crate::tracepoints::record_thread_count(
                THREAD_COUNT_TRACE_EXEC_RESET,
                vm as *const ThreadState as u32,
                vm.tid,
                vm.process_ptr,
                before,
                1,
            );
            set_next_tid_hint(base, vm.process_ptr, vm.tid.saturating_add(1).max(1));
        }

        discarded
    }
}

/// set_tid_address: record the address where 0 will be written on thread exit,
/// then futex-wake that address. Returns the caller's TID.
/// https://man7.org/linux/man-pages/man2/set_tid_address.2.html
pub fn sys_set_tid_address(vm: &mut ThreadState, tidptr: u64) -> i64 {
    vm.clear_child_tid = tidptr;
    vm.tid as i64
}

/// set_robust_list: record robust futex list head for exit-time owner-death cleanup.
/// https://man7.org/linux/man-pages/man2/set_robust_list.2.html
pub fn sys_set_robust_list(vm: &mut ThreadState, head: u64, len: u64) -> i64 {
    if len != ROBUST_LIST_HEAD_LEN {
        return EINVAL;
    }
    vm.robust_list_head = head;
    vm.robust_list_len = len;
    0
}

/// get_robust_list: return the registered robust futex list head/len.
/// We currently support the calling thread (`pid == 0` or `pid == self.tid`).
/// Existing non-self tids return EPERM; missing tids return ESRCH.
pub fn sys_get_robust_list(
    vm: &ThreadState,
    base: u32,
    pid: i64,
    head_ptr: u64,
    len_ptr: u64,
) -> i64 {
    if head_ptr == 0
        || len_ptr == 0
        || !crate::syscall::memory::guest_range_accessible(base, head_ptr, 8)
        || !crate::syscall::memory::guest_range_accessible(base, len_ptr, 8)
    {
        return EFAULT;
    }

    let (head, len) = if pid == 0 || pid == vm.tid as i64 {
        (vm.robust_list_head, vm.robust_list_len)
    } else {
        let Some(record_ptr) = thread_record_ptr(base, vm.process_ptr, pid as i32) else {
            return ESRCH;
        };
        let record = unsafe { read_thread_record(record_ptr) };
        if matches!(record.state, THREAD_NONE | THREAD_DEAD) || record.thread_ptr == 0 {
            return ESRCH;
        }
        return EPERM;
    };

    unsafe {
        guest_mem::write_u64(base, head_ptr, head);
        guest_mem::write_u64(base, len_ptr, len);
    }
    0
}

/// exit: terminate the calling thread.
/// Decrements thread_count. If clear_child_tid is set, writes 0 and wakes futex.
/// Returns STATUS_FAULT to stop execution.
/// https://man7.org/linux/man-pages/man2/exit.2.html
pub fn sys_exit(vm: &mut ThreadState, base: u32, exit_code: u64) -> i32 {
    vm.exit_code = exit_code as i32;
    vm.term_signal = 0;

    if crate::syscall::process::vfork_active() {
        vm.status = STATUS_FAULT;
        return STATUS_FAULT;
    }

    unsafe {
        if let Some(record) = thread_record_ptr(base, vm.process_ptr, vm.tid) {
            let mut updated = read_thread_record(record);
            updated.state = THREAD_EXITING;
            updated.blocked_addr = 0;
            updated.thread_ptr = 0;
            updated.clear_child_tid = vm.clear_child_tid;
            write_thread_record(record, updated);
        }
    }
    cleanup_robust_futexes(vm.process_ptr, base, vm.tid as u32, vm.robust_list_head);
    vm.robust_list_head = 0;
    vm.robust_list_len = 0;
    crate::fs::fd_table::clear_blocked_ofd_pin(vm);
    let remaining_threads = decrement_thread_count(vm, base);

    // clear_child_tid: write 0 and wake futex waiters
    if vm.clear_child_tid != 0 {
        clear_tid_and_wake(vm.process_ptr, base, vm.clear_child_tid);
        vm.clear_child_tid = 0;
    }

    if remaining_threads == 0 {
        crate::fs::fd_table::close_all_for_process(base, vm);
        set_next_tid_hint(base, vm.process_ptr, 0);
    }

    unsafe {
        if let Some(record) = thread_record_ptr(base, vm.process_ptr, vm.tid) {
            write_thread_record(record, ThreadRecord::new(vm.tid, THREAD_DEAD, 0, 0, 0));
        }
    }

    vm.status = STATUS_FAULT;
    STATUS_FAULT
}

pub fn terminate_process(vm: &mut ThreadState, base: u32, exit_code: i32, term_signal: i32) -> i32 {
    terminate_process_with_reason(vm, base, exit_code, term_signal, TERMINATE_REASON_UNKNOWN)
}

pub fn terminate_process_with_reason(
    vm: &mut ThreadState,
    base: u32,
    exit_code: i32,
    term_signal: i32,
    _reason: u32,
) -> i32 {
    vm.exit_code = exit_code;
    vm.term_signal = term_signal;

    if crate::syscall::process::vfork_active() {
        vm.status = STATUS_FAULT;
        return STATUS_FAULT;
    }

    let process_ptr = vm.process_ptr;

    unsafe {
        if process_ptr != 0 {
            let ps = &mut *((base as u64 + process_ptr as u64) as *mut ProcessState);
            let before = ps.thread_count.load(Ordering::Acquire);
            for record in ps.threads.iter_mut() {
                if record.state == THREAD_NONE || record.state == THREAD_DEAD {
                    continue;
                }
                let thread_vm_ptr = thread_state_from_record_ptr(record.thread_ptr);
                let robust_head = if record.tid == vm.tid {
                    vm.robust_list_head
                } else if let Some(thread_vm) = thread_vm_ptr {
                    (*thread_vm).robust_list_head
                } else {
                    0
                };
                cleanup_robust_futexes(vm.process_ptr, base, record.tid as u32, robust_head);
                if record.tid == vm.tid {
                    vm.robust_list_head = 0;
                    vm.robust_list_len = 0;
                    vm.clear_child_tid = 0;
                } else if let Some(thread_vm) = thread_vm_ptr {
                    let thread_vm = &mut *thread_vm;
                    thread_vm.exit_code = exit_code;
                    thread_vm.term_signal = term_signal;
                    thread_vm.status = STATUS_FAULT;
                    thread_vm.robust_list_head = 0;
                    thread_vm.robust_list_len = 0;
                    thread_vm.clear_child_tid = 0;
                    crate::fs::fd_table::clear_blocked_ofd_pin(thread_vm);
                }
                if record.clear_child_tid != 0 {
                    clear_tid_and_wake(vm.process_ptr, base, record.clear_child_tid);
                }
                *record = ThreadRecord::empty();
            }
            ps.thread_count.store(0, Ordering::Release);
            crate::tracepoints::record_thread_count(
                THREAD_COUNT_TRACE_TERMINATE,
                vm as *const ThreadState as u32,
                vm.tid,
                vm.process_ptr,
                before,
                0,
            );
            set_next_tid_hint(base, vm.process_ptr, 0);
        }
    }

    crate::fs::fd_table::close_all_for_process(base, vm);
    crate::fs::fd_table::clear_blocked_ofd_pin(vm);

    if vm.clear_child_tid != 0 {
        clear_tid_and_wake(vm.process_ptr, base, vm.clear_child_tid);
        vm.clear_child_tid = 0;
    }
    vm.robust_list_head = 0;
    vm.robust_list_len = 0;

    vm.status = STATUS_FAULT;
    STATUS_FAULT
}

pub fn thread_may_step(vm: &mut ThreadState, base: u32) -> bool {
    let Some(ps) = process_state_ptr(base, vm.process_ptr) else {
        return true;
    };
    if unsafe { (*ps).thread_count.load(Ordering::Acquire) } == 0 {
        vm.status = STATUS_FAULT;
        return false;
    }
    let Some(record_ptr) = thread_record_ptr(base, vm.process_ptr, vm.tid) else {
        return true;
    };
    let record = unsafe { read_thread_record(record_ptr) };
    if matches!(record.state, THREAD_NONE | THREAD_DEAD) || record.thread_ptr == 0 {
        vm.status = STATUS_FAULT;
        return false;
    }
    true
}

/// exit_group: terminate all threads in the process.
/// Marks the entire process dead so runtime/process teardown can proceed.
/// https://man7.org/linux/man-pages/man2/exit_group.2.html
pub fn sys_exit_group(vm: &mut ThreadState, base: u32, exit_code: u64) -> i32 {
    terminate_process_with_reason(vm, base, exit_code as i32, 0, TERMINATE_REASON_EXIT_GROUP)
}

/// clone: create a new thread or process.
/// For CLONE_VM | CLONE_THREAD: creates ThreadState, returns STATUS_CLONE_SPAWN.
/// TS runtime will spawn a new Worker with the same shared Memory.
/// https://man7.org/linux/man-pages/man2/clone.2.html
pub fn sys_clone(
    vm: &mut ThreadState,
    base: u32,
    flags: u64,
    child_stack: u64,
    parent_tidptr: u64,
    tls: u64,
    child_tidptr: u64,
) -> i64 {
    let clone_flags = flags;

    // CLONE_VM | CLONE_THREAD → new thread in same process
    if clone_flags & CLONE_VM != 0 && clone_flags & CLONE_THREAD != 0 {
        // Allocate new TID
        let new_tid = allocate_tid(vm, base);
        if new_tid <= 0 {
            return ENOMEM;
        }

        unsafe {
            let Some(ps) = process_state_ptr(base, vm.process_ptr) else {
                return ESRCH;
            };
            let before = (*ps).thread_count.fetch_add(1, Ordering::AcqRel);
            crate::tracepoints::record_thread_count(
                THREAD_COUNT_TRACE_CLONE_INC,
                vm as *const ThreadState as u32,
                vm.tid,
                vm.process_ptr,
                before,
                before.saturating_add(1),
            );
        }

        // Write child TID to parent_tidptr if CLONE_PARENT_SETTID
        if clone_flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
            unsafe { guest_mem::write_u32(base, parent_tidptr, new_tid as u32) };
        }

        // Store child_tidptr for CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID
        // These will be set in the child's ThreadState by the TS runtime.
        vm.clone_flags = clone_flags;
        vm.clone_child_stack = child_stack;
        vm.clone_tls = tls;
        vm.clone_child_tidptr = child_tidptr;
        vm.clone_child_tid = new_tid;
        vm.clone_pending = 1;

        // Set up clone result in VM state for TS handoff
        vm.x[10] = new_tid as u64; // parent returns child TID
        vm.status = STATUS_CLONE_SPAWN;

        // The TS runtime reads: child_stack, tls, new_tid, child_tidptr, flags
        // from designated locations. Store them in registers for handoff.
        // a0 = new_tid (already set), a1 = child_stack, a2 = tls, a3 = child_tidptr
        // The TS runtime will create a new ThreadState with:
        //   - pc = current pc (next instruction after ecall)
        //   - sp (x2) = child_stack (if nonzero)
        //   - tp (x4) = tls (if CLONE_SETTLS)
        //   - a0 = 0 (child returns 0 from clone)
        //   - process_ptr = same as parent
        //   - tid = new_tid

        return new_tid as i64;
    }

    // Other clone variants (fork, vfork) handled by process.rs
    ENOSYS
}

pub fn sys_clone3(vm: &mut ThreadState, base: u32, clone_args_ptr: u64, size: u64) -> i64 {
    const CLONE_ARGS_V1_SIZE: u64 = 64;

    if clone_args_ptr == 0 || size < CLONE_ARGS_V1_SIZE {
        return EINVAL;
    }

    let flags = unsafe { guest_mem::read_u64(base, clone_args_ptr) };
    let pidfd = unsafe { guest_mem::read_u64(base, clone_args_ptr + 8) };
    let child_tidptr = unsafe { guest_mem::read_u64(base, clone_args_ptr + 16) };
    let parent_tidptr = unsafe { guest_mem::read_u64(base, clone_args_ptr + 24) };
    let exit_signal = unsafe { guest_mem::read_u64(base, clone_args_ptr + 32) };
    let stack = unsafe { guest_mem::read_u64(base, clone_args_ptr + 40) };
    let stack_size = unsafe { guest_mem::read_u64(base, clone_args_ptr + 48) };
    let tls = unsafe { guest_mem::read_u64(base, clone_args_ptr + 56) };

    let combined_flags = flags | (exit_signal & 0xff);
    let child_stack = if stack != 0 && stack_size != 0 {
        stack.saturating_add(stack_size)
    } else {
        stack
    };

    let result = sys_clone(
        vm,
        base,
        combined_flags,
        child_stack,
        parent_tidptr,
        tls,
        child_tidptr,
    );
    if result > 0 && (combined_flags & CLONE_PIDFD) != 0 && pidfd != 0 {
        unsafe {
            guest_mem::write_u32(base, pidfd, result as u32);
        }
    }
    result
}

/// Runtime handoff helper: allocate and initialize the child ThreadState for
/// a pending clone(CLONE_VM | CLONE_THREAD).
pub fn spawn_from_clone(parent_vm_ptr: u32, base: u32) -> u32 {
    unsafe {
        let parent = &mut *(parent_vm_ptr as *mut ThreadState);
        if parent.clone_pending == 0 {
            return 0;
        }

        let child_ptr = crate::alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        );
        if child_ptr == 0 {
            return 0;
        }

        let child = &mut *(child_ptr as *mut ThreadState);
        core::ptr::write_bytes(child_ptr as *mut u8, 0, core::mem::size_of::<ThreadState>());

        // clone(2) creates a new thread with copied CPU state, but the rest of
        // ThreadState is thread-local scratch and must start clean. Copying the
        // whole parent struct leaks blocked-syscall, fault, signal, and handoff
        // bookkeeping into the child before its startup path completes.
        child.x = parent.x;
        child.x[0] = 0;
        child.x[10] = 0;
        child.f = parent.f;
        child.pc = parent.pc;
        child.fcsr = parent.fcsr;
        child.tid = parent.clone_child_tid;
        child.uid = parent.uid;
        child.euid = parent.euid;
        child.gid = parent.gid;
        child.egid = parent.egid;
        child.tls_base = parent.tls_base;
        child.clear_child_tid = 0;
        child.robust_list_head = 0;
        child.robust_list_len = 0;
        child.sig_mask = parent.sig_mask;
        child.sig_pending = 0;
        child.sig_info_code = 0;
        child.sigaltstack_sp = 0;
        child.sigaltstack_size = 0;
        child.sigaltstack_flags = crate::syscall::signal::SS_DISABLE;
        child.lr_addr = u64::MAX;
        child.lr_val = 0;
        child.lr_gen = 0;
        child.lr_gen_end = 0;
        child.insn_budget = 0;
        child.fault_pc = 0;
        child.fault_addr = 0;
        child.guest_base = parent.guest_base;
        child.guest_address_profile = parent.guest_address_profile;
        child.guest_address_limit = parent.guest_address_limit;
        child.guest_memory_policy_limit = parent.guest_memory_policy_limit;
        child.process_max_memory_pages = parent.process_max_memory_pages;
        child.process_ptr = parent.process_ptr;
        child.completed_sync_effects = 0;
        child.blocked_syscall_nr = 0;
        child.blocked_syscall_args = [0; 6];
        child.completed_pipe_sync_slots = 0;
        child.completed_pipe_sync_read_slots = 0;
        child.completed_pipe_sync_write_slots = 0;
        child.completed_pipe_fresh_slots = 0;
        child.completed_pipe_read_guest_ptr = 0;
        child.completed_pipe_read_len = 0;
        child.block_cache_ptr = 0;
        child.execve_backing_miss_ino = 0;
        child.execve_backing_miss_len = 0;
        child.execve_backing_miss_offset = 0;
        child.execve_backing_miss_expected_size = 0;
        child.status = STATUS_OK;
        child.exit_code = 0;
        child.term_signal = 0;

        if parent.clone_child_stack != 0 {
            child.x[2] = parent.clone_child_stack;
        }

        if parent.clone_flags & CLONE_SETTLS != 0 {
            child.x[4] = parent.clone_tls;
            child.tls_base = parent.clone_tls;
        }

        if parent.clone_flags & CLONE_CHILD_CLEARTID != 0 {
            child.clear_child_tid = parent.clone_child_tidptr;
        } else {
            child.clear_child_tid = 0;
        }

        if parent.clone_flags & CLONE_CHILD_SETTID != 0 && parent.clone_child_tidptr != 0 {
            guest_mem::write_u32(
                base,
                parent.clone_child_tidptr,
                parent.clone_child_tid as u32,
            );
        }

        let ps = &mut *((base as u64 + child.process_ptr as u64) as *mut ProcessState);
        ps.threads[(parent.clone_child_tid - 1) as usize] = ThreadRecord::new(
            parent.clone_child_tid,
            THREAD_RUNNING,
            child_ptr,
            child.clear_child_tid,
            0,
        );

        LAST_CLONE_SPAWN = CloneSpawnTrace {
            tid: child.tid,
            flags: parent.clone_flags,
            pc: child.pc,
            ra: child.x[1],
            gp: child.x[3],
            sp: child.x[2],
            tls: parent.clone_tls,
            child_tidptr: parent.clone_child_tidptr,
            s11: child.x[27],
            stack_m32: if child.x[2] >= 32 {
                guest_mem::read_u64(base, child.x[2] - 32)
            } else {
                0
            },
            stack_m24: if child.x[2] >= 24 {
                guest_mem::read_u64(base, child.x[2] - 24)
            } else {
                0
            },
            stack_m16: if child.x[2] >= 16 {
                guest_mem::read_u64(base, child.x[2] - 16)
            } else {
                0
            },
            stack_m8: if child.x[2] >= 8 {
                guest_mem::read_u64(base, child.x[2] - 8)
            } else {
                0
            },
        };

        parent.clone_flags = 0;
        parent.clone_child_stack = 0;
        parent.clone_tls = 0;
        parent.clone_child_tidptr = 0;
        parent.clone_child_tid = 0;
        parent.clone_pending = 0;
        parent.status = STATUS_OK;

        child_ptr
    }
}

pub fn process_thread_count(vm_ptr: u32, base: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        match process_state_ptr(base, vm.process_ptr) {
            Some(ps) => (*ps).thread_count.load(Ordering::Acquire),
            None => 0,
        }
    }
}

/// Read the blocked_addr for the given thread from its ThreadRecord.
/// Returns 0 if woken (FUTEX_WAKE clears this), u64::MAX if not found.
pub fn thread_record_blocked_addr(vm: &ThreadState, base: u32) -> u64 {
    unsafe {
        if vm.tid <= 0 || vm.tid as usize > MAX_THREADS {
            return u64::MAX;
        }
        let Some(record) = thread_record_ptr(base, vm.process_ptr, vm.tid) else {
            return u64::MAX;
        };
        let record = read_thread_record(record);
        if record.state == THREAD_BLOCKED_FUTEX {
            record.blocked_addr
        } else {
            0
        }
    }
}

/// Allocate a new thread ID. Simple increment based on thread registry.
fn allocate_tid(vm: &ThreadState, base: u32) -> i32 {
    unsafe {
        let Some(ps) = process_state_ptr(base, vm.process_ptr) else {
            return -1;
        };
        let mut start_tid = next_tid_hint(base, vm.process_ptr).max(1);
        if start_tid <= vm.tid {
            start_tid = vm.tid.saturating_add(1).max(1);
        }
        for tid in start_tid..=(MAX_THREADS as i32) {
            let record = &mut (*ps).threads[(tid - 1) as usize];
            if record.state == THREAD_NONE || record.state == THREAD_DEAD {
                *record = ThreadRecord::new(tid, crate::types::THREAD_STARTING, 0, 0, 0);
                set_next_tid_hint(base, vm.process_ptr, tid.saturating_add(1));
                return tid;
            }
        }
    }
    -1 // no free slot
}

#[inline(always)]
fn futex_uaddr_readable(vm: &ThreadState, base: u32, addr: u64) -> bool {
    crate::syscall::memory::guest_range_permitted(vm, base, addr, 4, PROT_READ)
}

/// futex: fast userspace mutex.
#[allow(clippy::too_many_arguments)]
pub fn sys_futex(
    vm: &mut ThreadState,
    base: u32,
    addr: u64,
    op: u64,
    val: u64,
    timeout_or_requeue: u64,
    addr2: u64,
    val3: u64,
) -> i64 {
    let futex_flags = (op as u32) & (FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    let futex_op = (op as u32) & !futex_flags;

    match futex_op {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let bitset = if futex_op == FUTEX_WAIT_BITSET {
                let bitset = val3 as u32;
                if bitset == 0 {
                    return EINVAL;
                }
                bitset
            } else {
                FUTEX_BITSET_MATCH_ANY
            };
            if !futex_uaddr_readable(vm, base, addr) {
                return EFAULT;
            }
            let current = unsafe { guest_mem::read_u32(base, addr) };
            if current != val as u32 {
                record_futex_trace(
                    vm, futex_op, addr, 0, val, val3, current, 0, 0, 0, EAGAIN, STATUS_OK,
                );
                return EAGAIN;
            }
            unsafe {
                if let Some(record) = thread_record_ptr(base, vm.process_ptr, vm.tid) {
                    mark_thread_record_blocked_futex(record, vm.clear_child_tid, addr);
                }
            }
            vm.futex_wait_addr = addr;
            vm.futex_wait_timeout = timeout_or_requeue;
            vm.futex_wait_expected = val as u32;
            vm.futex_wait_bitset = bitset;
            vm.futex_wait_absolute = if futex_op == FUTEX_WAIT_BITSET { 1 } else { 0 };
            vm.futex_wait_flags = futex_flags;
            // Value matches — block. Return STATUS_FUTEX_WAIT for TS to Atomics.wait.
            vm.x[10] = addr; // stash addr for TS
            vm.status = STATUS_FUTEX_WAIT;
            record_futex_trace(
                vm,
                futex_op,
                addr,
                0,
                val,
                val3,
                current,
                0,
                0,
                0,
                0,
                STATUS_FUTEX_WAIT,
            );
            0
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let wake_bitset = if futex_op == FUTEX_WAKE_BITSET {
                let bitset = val3 as u32;
                if bitset == 0 {
                    return EINVAL;
                }
                bitset
            } else {
                FUTEX_BITSET_MATCH_ANY
            };
            if !futex_uaddr_readable(vm, base, addr) {
                return EFAULT;
            }
            let local = wake_futex_waiters_by_process_ptr(
                vm.process_ptr,
                base,
                addr,
                val.min(u32::MAX as u64) as u32,
                wake_bitset,
            );
            // Deferred process children are not represented by live
            // ThreadRecord slots while the harness runner keeps the parent
            // executing, so external waiters must be counted separately.
            let caller_pid = crate::syscall::process::current_process_pid(vm, base);
            let external = wake_external_waiters(caller_pid, addr, val.min(u32::MAX as u64) as u32);
            let result = (local + external) as i64;
            record_futex_trace(
                vm, futex_op, addr, 0, val, val3, 0, local, external, 0, result, STATUS_OK,
            );
            result
        }
        FUTEX_CMP_REQUEUE => {
            if (val as i64) < 0 || (timeout_or_requeue as i64) < 0 {
                return EINVAL;
            }
            if !futex_uaddr_readable(vm, base, addr) || !futex_uaddr_readable(vm, base, addr2) {
                return EFAULT;
            }

            let current = unsafe { guest_mem::read_u32(base, addr) };
            if current != val3 as u32 {
                record_futex_trace(
                    vm, futex_op, addr, addr2, val, val3, current, 0, 0, 0, EAGAIN, STATUS_OK,
                );
                return EAGAIN;
            }

            let wake_count = val.min(u32::MAX as u64) as u32;
            let requeue_count = timeout_or_requeue.min(u32::MAX as u64) as u32;

            let local_wake = wake_futex_waiters_by_process_ptr(
                vm.process_ptr,
                base,
                addr,
                wake_count,
                FUTEX_BITSET_MATCH_ANY,
            );
            let caller_pid = crate::syscall::process::current_process_pid(vm, base);
            let external_wake = wake_external_waiters(caller_pid, addr, wake_count);

            let local_requeue = requeue_futex_waiters_by_process_ptr(
                vm.process_ptr,
                base,
                addr,
                addr2,
                requeue_count,
            );
            let external_requeue = requeue_external_waiters(addr, addr2, requeue_count);

            let result = (local_wake + external_wake + local_requeue + external_requeue) as i64;
            record_futex_trace(
                vm,
                futex_op,
                addr,
                addr2,
                val,
                val3,
                current,
                local_wake,
                external_wake,
                local_requeue + external_requeue,
                result,
                STATUS_OK,
            );
            result
        }
        _ => ENOSYS,
    }
}

pub fn resume_futex_wait(vm: &mut ThreadState, base: u32) {
    resume_futex_wait_result(vm, base, 0);
}

pub fn resume_futex_wait_result(vm: &mut ThreadState, base: u32, result: i64) {
    unsafe {
        if let Some(record) = thread_record_ptr(base, vm.process_ptr, vm.tid) {
            let record_state = read_thread_record(record).state;
            if record_state == THREAD_BLOCKED_FUTEX {
                mark_thread_record_running_from_futex(record, vm.clear_child_tid);
            }
        }
    }
    vm.futex_wait_addr = 0;
    vm.futex_wait_timeout = 0;
    vm.futex_wait_expected = 0;
    vm.futex_wait_bitset = 0;
    vm.futex_wait_absolute = 0;
    vm.futex_wait_flags = 0;
    vm.status = STATUS_OK;
    vm.x[10] = result as u64;
    crate::tracepoints::record_futex_resume_trace(vm, 1);
    crate::syscall::signal::check_pending(vm, base);
    crate::tracepoints::record_futex_resume_trace(vm, 2);
}
