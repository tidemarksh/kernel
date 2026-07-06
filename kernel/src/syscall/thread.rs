//! Thread syscalls: clone, futex, exit, exit_group, set_tid_address,
//! set_robust_list, get_robust_list.
//!
//! clone(CLONE_VM | CLONE_THREAD) → STATUS_CLONE_SPAWN → supervisor HostOp.
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
    ProcessState, THREAD_BLOCKED_FUTEX, THREAD_DEAD, THREAD_NONE, THREAD_RUNNING, ThreadRecord,
    ThreadState,
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
        vm.pc,
        vm.x[1],
        vm.x[2],
        vm.x[8],
        vm.x[9],
        vm.x[18],
        vm.x[19],
        vm.x[10],
        vm.x[11],
        vm.x[12],
        vm.x[13],
        vm.x[14],
        vm.x[15],
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

pub const TERMINATE_REASON_UNKNOWN: u32 = 0;
pub const TERMINATE_REASON_EXIT_GROUP: u32 = 1;
pub const TERMINATE_REASON_DEFAULT_SIGNAL: u32 = 2;

pub fn last_clone_spawn() -> (i32, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    crate::supervisor::last_clone_spawn()
}

pub fn last_clone_spawn_details() -> (i32, u64, u64, u64, u64, u64) {
    crate::supervisor::last_clone_spawn_details()
}

pub fn init() {
    crate::supervisor::reset_thread_clone_registry();
    #[cfg(any(
        test,
        all(
            any(target_arch = "wasm32", target_arch = "wasm64"),
            feature = "harness"
        )
    ))]
    crate::harness::trace::clear_futex_trace();
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
            let woken_record = read_thread_record(record);
            write_thread_record_state(record, THREAD_RUNNING);
            write_thread_record_blocked_addr(record, 0);
            crate::supervisor::enqueue_futex_resume(
                process_ptr,
                woken_record.thread_ptr,
                woken_record.tid,
                addr,
            );
            woken += 1;
        }
        woken
    };
    if woken > 0 {
        notify_futex_addr(base, addr, woken);
    }
    woken
}

pub(crate) fn supervisor_wake_futex_waiters_by_process_ptr(
    process_ptr: u32,
    base: u32,
    addr: u64,
    max_wake: u32,
    wake_bitset: u32,
) -> u32 {
    wake_futex_waiters_by_process_ptr(process_ptr, base, addr, max_wake, wake_bitset)
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

pub fn init_main_thread(vm_ptr: u32, base: u32) {
    crate::supervisor::init_main_thread(vm_ptr, base);
}

pub fn discard_other_threads_for_exec(vm: &ThreadState, base: u32) -> u32 {
    crate::supervisor::discard_other_threads_for_exec(vm, base)
}

/// set_tid_address: record the address where 0 will be written on thread exit,
/// then futex-wake that address. Returns the caller's TID.
/// https://man7.org/linux/man-pages/man2/set_tid_address.2.html
pub fn sys_set_tid_address(vm: &mut ThreadState, tidptr: u64) -> i64 {
    crate::supervisor::set_thread_clear_child_tid(vm, vm.guest_base, tidptr);
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

    crate::fs::fd_table::clear_blocked_ofd_pin(vm);
    let remaining_threads = crate::supervisor::complete_thread_exit(vm, base);

    if remaining_threads == 0 {
        crate::fs::fd_table::close_all_for_process(base, vm);
    }
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

    crate::supervisor::complete_thread_group_exit(vm, base, exit_code, term_signal);

    crate::fs::fd_table::close_all_for_process(base, vm);
    crate::fs::fd_table::clear_blocked_ofd_pin(vm);

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
/// For CLONE_VM | CLONE_THREAD: records pending thread state and returns
/// STATUS_CLONE_SPAWN. The supervisor publishes the Worker spawn HostOp.
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
        return crate::supervisor::register_clone_thread(
            vm,
            base,
            clone_flags,
            child_stack,
            parent_tidptr,
            tls,
            child_tidptr,
        );
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
    crate::supervisor::spawn_from_clone(parent_vm_ptr, base)
}

pub fn process_thread_count(vm_ptr: u32, base: u32) -> u32 {
    crate::supervisor::process_thread_count(vm_ptr, base)
}

/// Read the blocked_addr for the given thread from its ThreadRecord.
/// Returns 0 if woken (FUTEX_WAKE clears this), u64::MAX if not found.
pub fn thread_record_blocked_addr(vm: &ThreadState, base: u32) -> u64 {
    crate::supervisor::thread_record_blocked_addr(vm, base)
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
            crate::supervisor::enqueue_futex_wait_timer(vm);
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
