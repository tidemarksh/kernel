//! Thread syscalls: clone, futex, exit, exit_group, set_tid_address, set_robust_list.
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

const ROBUST_LIST_HEAD_LEN: u64 = 24;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
const ROBUST_LIST_LIMIT: u32 = 2048;

pub fn init() {
    // clone handoff scratch lives in ThreadState (shared guest-visible memory),
    // so there is no thread subsystem global state to reset here.
}

unsafe fn process_state(base: u32, vm: &ThreadState) -> Option<&mut ProcessState> {
    if vm.process_ptr == 0 {
        return None;
    }
    Some(&mut *((base as u64 + vm.process_ptr as u64) as *mut ProcessState))
}

unsafe fn thread_record(vm: &ThreadState, base: u32) -> Option<&mut ThreadRecord> {
    if vm.tid <= 0 || vm.tid as usize > MAX_THREADS {
        return None;
    }
    let ps = process_state(base, vm)?;
    Some(&mut ps.threads[(vm.tid - 1) as usize])
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
    let memory_size = (core::arch::wasm32::memory_size(0) as usize).checked_mul(65536)?;
    if end > memory_size {
        return None;
    }

    Some(absolute as *mut ThreadState)
}

fn clear_tid_and_wake(process_ptr: u32, base: u32, addr: u64) -> u32 {
    if addr == 0 {
        return 0;
    }
    unsafe {
        guest_mem::write_u32(base, addr, 0);
    }
    wake_futex_waiters_by_process_ptr(process_ptr, base, addr as u32, u32::MAX)
}

fn wake_futex_waiters_by_process_ptr(process_ptr: u32, base: u32, addr: u32, max_wake: u32) -> u32 {
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
            record.state = THREAD_RUNNING;
            record.blocked_addr = 0;
            woken += 1;
        }
        woken
    };
    if woken > 0 {
        notify_futex_addr(base, addr, woken);
    }
    woken
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn tidemark_memory_atomic_notify(ptr: *mut i32, max_wake: u32) -> u32;
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn notify_futex_addr(base: u32, addr: u32, max_wake: u32) {
    unsafe {
        let ptr = (base as u64 + addr as u64) as usize as *mut i32;
        let _ = tidemark_memory_atomic_notify(ptr, max_wake);
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn notify_futex_addr(_base: u32, _addr: u32, _max_wake: u32) {}

fn requeue_futex_waiters_by_process_ptr(
    process_ptr: u32,
    base: u32,
    addr: u32,
    new_addr: u32,
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

    let owner = unsafe { guest_mem::read_u32(base, futex_addr) };
    if owner & FUTEX_TID_MASK != owner_tid {
        return;
    }

    let updated = (owner & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
    unsafe {
        guest_mem::write_u32(base, futex_addr, updated);
    }
    wake_futex_waiters_by_process_ptr(process_ptr, base, futex_addr as u32, u32::MAX);
}

fn cleanup_robust_futexes(process_ptr: u32, base: u32, owner_tid: u32, robust_head: u64) {
    if process_ptr == 0 || owner_tid == 0 || robust_head == 0 {
        return;
    }

    let first = unsafe { guest_mem::read_u64(base, robust_head) };
    let futex_offset = unsafe { guest_mem::read_u64(base, robust_head + 8) as i64 };
    let pending = unsafe { guest_mem::read_u64(base, robust_head + 16) };

    let mut entry = first;
    let mut walked = 0;
    while entry != 0 && entry != robust_head && walked < ROBUST_LIST_LIMIT {
        mark_robust_futex_owner_died(process_ptr, base, owner_tid, entry, futex_offset);
        entry = unsafe { guest_mem::read_u64(base, entry) };
        walked += 1;
    }

    if pending != 0 && pending != robust_head {
        mark_robust_futex_owner_died(process_ptr, base, owner_tid, pending, futex_offset);
    }
}

fn decrement_thread_count(vm: &ThreadState, base: u32) -> u32 {
    unsafe {
        match process_state(base, vm) {
            Some(ps) => ps
                .thread_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    Some(count.saturating_sub(1))
                })
                .unwrap_or(0)
                .saturating_sub(1),
            None => 0,
        }
    }
}

pub fn init_main_thread(vm_ptr: u32, base: u32) {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let Some(ps) = process_state(base, vm) else {
            return;
        };

        ps.thread_count.store(1, Ordering::Release);
        for record in ps.threads.iter_mut() {
            *record = ThreadRecord::empty();
        }

        if vm.tid > 0 && vm.tid as usize <= MAX_THREADS {
            ps.threads[(vm.tid - 1) as usize] =
                ThreadRecord::new(vm.tid, THREAD_RUNNING, vm_ptr, vm.clear_child_tid as u32, 0);
        }

        let tc_ptr = core::ptr::addr_of!(ps.thread_count);
        guest_mem::init(core::ptr::null(), tc_ptr);
    }
}

pub fn discard_other_threads_for_exec(vm: &ThreadState, base: u32) -> u32 {
    unsafe {
        let Some(ps) = process_state(base, vm) else {
            return 0;
        };
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
            let has_valid_thread =
                record.tid > 0 && thread_state_from_record_ptr(record.thread_ptr).is_some();
            if !has_valid_thread {
                *record = ThreadRecord::empty();
                discarded += 1;
                continue;
            }
            if let Some(thread_vm) = thread_state_from_record_ptr(record.thread_ptr) {
                crate::fs::fd_table::clear_blocked_ofd_pin(&mut *thread_vm);
            }
            if record.clear_child_tid != 0 {
                clear_tid_and_wake(vm.process_ptr, base, record.clear_child_tid as u64);
            }
            *record = ThreadRecord::empty();
            discarded += 1;
        }

        if let Some(idx) = current_idx {
            ps.threads[idx] = ThreadRecord::new(
                vm.tid,
                THREAD_RUNNING,
                current_ptr,
                vm.clear_child_tid as u32,
                0,
            );
            ps.thread_count.store(1, Ordering::Release);
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
        if let Some(record) = thread_record(vm, base) {
            record.state = THREAD_EXITING;
            record.blocked_addr = 0;
            record.thread_ptr = 0;
            record.clear_child_tid = vm.clear_child_tid as u32;
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
    }

    unsafe {
        if let Some(record) = thread_record(vm, base) {
            *record = ThreadRecord::empty();
        }
    }

    vm.status = STATUS_FAULT;
    STATUS_FAULT
}

pub fn terminate_process(vm: &mut ThreadState, base: u32, exit_code: i32, term_signal: i32) -> i32 {
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
                    thread_vm.robust_list_head = 0;
                    thread_vm.robust_list_len = 0;
                    thread_vm.clear_child_tid = 0;
                    crate::fs::fd_table::clear_blocked_ofd_pin(thread_vm);
                }
                if record.clear_child_tid != 0 {
                    clear_tid_and_wake(vm.process_ptr, base, record.clear_child_tid as u64);
                }
                *record = ThreadRecord::empty();
            }
            ps.thread_count.store(0, Ordering::Release);
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

/// exit_group: terminate all threads in the process.
/// Marks the entire process dead so runtime/process teardown can proceed.
/// https://man7.org/linux/man-pages/man2/exit_group.2.html
pub fn sys_exit_group(vm: &mut ThreadState, base: u32, exit_code: u64) -> i32 {
    terminate_process(vm, base, exit_code as i32, 0)
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
            let Some(ps) = process_state(base, vm) else {
                return ESRCH;
            };
            ps.thread_count.fetch_add(1, Ordering::AcqRel);
        }

        // Write child TID to parent_tidptr if CLONE_PARENT_SETTID
        if clone_flags & CLONE_PARENT_SETTID as u64 != 0 && parent_tidptr != 0 {
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

/// Runtime handoff helper: allocate and initialize the child ThreadState for
/// a pending clone(CLONE_VM | CLONE_THREAD).
pub fn spawn_from_clone(parent_vm_ptr: u32, base: u32) -> u32 {
    unsafe {
        let parent = &mut *(parent_vm_ptr as *mut ThreadState);
        if parent.clone_pending == 0 {
            return 0;
        }

        let child_ptr = unsafe {
            crate::alloc::alloc_zeroed(
                core::mem::size_of::<ThreadState>() as u32,
                core::mem::align_of::<ThreadState>() as u32,
            )
        };
        if child_ptr == 0 {
            return 0;
        }

        let child = &mut *(child_ptr as *mut ThreadState);
        core::ptr::copy_nonoverlapping(parent as *const ThreadState, child, 1);

        child.tid = parent.clone_child_tid;
        child.x[10] = 0;
        child.status = STATUS_OK;
        child.exit_code = 0;
        child.sig_pending = 0;
        child.clone_flags = 0;
        child.clone_child_stack = 0;
        child.clone_tls = 0;
        child.clone_child_tidptr = 0;
        child.clone_child_tid = 0;
        child.clone_pending = 0;
        child.blocked_fd = 0;
        child.blocked_ofd_id = 0;

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

        // For CLONE_VM without CLONE_VFORK, the child does not inherit an
        // alternate signal stack; pending signals are also thread-local.
        if parent.clone_flags & CLONE_VM != 0 && parent.clone_flags & CLONE_VFORK == 0 {
            child.sigaltstack_sp = 0;
            child.sigaltstack_size = 0;
            child.sigaltstack_flags = 0;
        }

        let ps = &mut *((base as u64 + child.process_ptr as u64) as *mut ProcessState);
        ps.threads[(parent.clone_child_tid - 1) as usize] = ThreadRecord::new(
            parent.clone_child_tid,
            THREAD_RUNNING,
            child_ptr,
            child.clear_child_tid as u32,
            0,
        );

        parent.clone_flags = 0;
        parent.clone_child_stack = 0;
        parent.clone_tls = 0;
        parent.clone_child_tidptr = 0;
        parent.clone_child_tid = 0;
        parent.clone_pending = 0;

        child_ptr
    }
}

pub fn process_thread_count(vm_ptr: u32, base: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        match process_state(base, vm) {
            Some(ps) => ps.thread_count.load(Ordering::Acquire),
            None => 0,
        }
    }
}

/// Read the blocked_addr for the given thread from its ThreadRecord.
/// Returns 0 if woken (FUTEX_WAKE clears this), u32::MAX if not found.
pub fn thread_record_blocked_addr(vm: &ThreadState, base: u32) -> u32 {
    unsafe {
        if vm.tid <= 0 || vm.tid as usize > MAX_THREADS {
            return u32::MAX;
        }
        let Some(ps) = process_state(base, vm) else {
            return u32::MAX;
        };
        ps.threads[(vm.tid - 1) as usize].blocked_addr
    }
}

/// Allocate a new thread ID. Simple increment based on thread registry.
fn allocate_tid(vm: &ThreadState, base: u32) -> i32 {
    unsafe {
        let Some(ps) = process_state(base, vm) else {
            return -1;
        };
        for (i, record) in ps.threads.iter_mut().enumerate() {
            if record.state == THREAD_NONE || record.state == THREAD_DEAD {
                let tid = (i + 1) as i32;
                *record = ThreadRecord::new(tid, crate::types::THREAD_STARTING, 0, 0, 0);
                return tid;
            }
        }
    }
    -1 // no free slot
}

/// futex: fast userspace mutex.
/// FUTEX_WAIT: if *addr == val, block (return STATUS_FUTEX_WAIT for TS to Atomics.wait)
/// FUTEX_WAKE: wake up to `val` waiters on addr (return count woken)
/// https://man7.org/linux/man-pages/man2/futex.2.html
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
    let futex_op = (op & 0x7F) as u32; // mask out FUTEX_PRIVATE_FLAG

    match futex_op {
        FUTEX_WAIT => {
            let current = unsafe { guest_mem::read_u32(base, addr) };
            if current != val as u32 {
                return EAGAIN;
            }
            unsafe {
                if let Some(record) = thread_record(vm, base) {
                    record.state = THREAD_BLOCKED_FUTEX;
                    record.blocked_addr = addr as u32;
                    record.clear_child_tid = vm.clear_child_tid as u32;
                }
            }
            vm.futex_wait_addr = addr;
            vm.futex_wait_timeout = timeout_or_requeue;
            // Value matches — block. Return STATUS_FUTEX_WAIT for TS to Atomics.wait.
            vm.x[10] = addr; // stash addr for TS
            vm.status = STATUS_FUTEX_WAIT;
            return 0;
        }
        FUTEX_WAKE => {
            let local = wake_futex_waiters_by_process_ptr(
                vm.process_ptr,
                base,
                addr as u32,
                val.min(u32::MAX as u64) as u32,
            );
            #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
            let external = crate::runtime_test_support::wake_plain_fork_futex_waits(
                addr as u32,
                val.min(u32::MAX as u64) as u32,
            );
            #[cfg(not(all(target_arch = "wasm32", target_os = "wasi")))]
            let external = 0u32;
            return (local + external) as i64;
        }
        FUTEX_CMP_REQUEUE => {
            if (val as i64) < 0 || (timeout_or_requeue as i64) < 0 {
                return EINVAL;
            }

            let current = unsafe { guest_mem::read_u32(base, addr) };
            if current != val3 as u32 {
                return EAGAIN;
            }

            let wake_count = val.min(u32::MAX as u64) as u32;
            let requeue_count = timeout_or_requeue.min(u32::MAX as u64) as u32;

            let local_wake =
                wake_futex_waiters_by_process_ptr(vm.process_ptr, base, addr as u32, wake_count);
            #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
            let external_wake =
                crate::runtime_test_support::wake_plain_fork_futex_waits(addr as u32, wake_count);
            #[cfg(not(all(target_arch = "wasm32", target_os = "wasi")))]
            let external_wake = 0u32;

            let local_requeue = requeue_futex_waiters_by_process_ptr(
                vm.process_ptr,
                base,
                addr as u32,
                addr2 as u32,
                requeue_count,
            );
            #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
            let external_requeue = crate::runtime_test_support::requeue_plain_fork_futex_waits(
                addr as u32,
                addr2 as u32,
                requeue_count,
            );
            #[cfg(not(all(target_arch = "wasm32", target_os = "wasi")))]
            let external_requeue = 0u32;

            (local_wake + external_wake + local_requeue + external_requeue) as i64
        }
        _ => ENOSYS,
    }
}

pub fn resume_futex_wait(vm: &mut ThreadState, base: u32) {
    resume_futex_wait_result(vm, base, 0);
}

pub fn resume_futex_wait_result(vm: &mut ThreadState, base: u32, result: i64) {
    unsafe {
        if let Some(record) = thread_record(vm, base) {
            if record.state == THREAD_BLOCKED_FUTEX {
                record.state = THREAD_RUNNING;
                record.blocked_addr = 0;
                record.clear_child_tid = vm.clear_child_tid as u32;
            }
        }
    }
    vm.futex_wait_addr = 0;
    vm.futex_wait_timeout = 0;
    vm.status = STATUS_OK;
    vm.x[10] = result as u64;
    crate::syscall::signal::check_pending(vm, base);
}

#[cfg(test)]
mod tests {
    use crate::abi::*;
    use crate::test_helpers::TestVm;
    use crate::types::*;
    use core::sync::atomic::Ordering;

    mod contract_tests {
        use super::*;
        use crate::syscall::thread as thread_impl;

        // Permanent Tidemark contract tests. These assert worker handoff and
        // bookkeeping that LTP cannot observe.
        #[test]
        fn contract_exit_decrements_thread_count() {
            let mut t = TestVm::new();
            let ps_ptr = t.vm.process_ptr as u64;
            let tc_off = core::mem::offset_of!(ProcessState, thread_count) as u64;
            unsafe { crate::guest_mem::write_u32(t.base, ps_ptr + tc_off, 2) };

            let status = thread_impl::sys_exit(&mut t.vm, t.base, 42);
            assert_eq!(status, STATUS_FAULT);
            assert_eq!(t.vm.exit_code, 42);

            let tc = unsafe { crate::guest_mem::read_u32(t.base, ps_ptr + tc_off) };
            assert_eq!(tc, 1, "thread_count should be decremented from 2 to 1");
        }

        #[test]
        fn contract_clone_thread_returns_status_clone_spawn() {
            let mut t = TestVm::new();
            t.vm.tid = 1;
            let ps_ptr = t.vm.process_ptr as u64;
            let tc_off = core::mem::offset_of!(ProcessState, thread_count) as u64;

            let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
            let child_stack = 0x80000u64;
            let ret = thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, 0, 0);

            assert!(ret > 0, "clone should return positive TID, got {}", ret);
            assert_eq!(t.vm.status, STATUS_CLONE_SPAWN);

            // thread_count should be incremented
            let tc = unsafe { crate::guest_mem::read_u32(t.base, ps_ptr + tc_off) };
            assert_eq!(tc, 2, "thread_count should be incremented from 1 to 2");
        }

        #[test]
        fn contract_spawn_from_clone_initializes_child_thread_state() {
            let mut t = TestVm::new();
            t.vm.tid = 1;
            t.vm.sig_mask = 0x55;
            t.vm.sig_pending = 0xAA;
            t.vm.sigaltstack_sp = 0x9000;
            t.vm.sigaltstack_size = 4096;
            t.vm.sigaltstack_flags = 1;

            let ps_ptr = t.vm.process_ptr as u64;

            let child_tidptr = t.scratch + 0x280;
            let flags = (CLONE_VM
                | CLONE_THREAD
                | CLONE_SIGHAND
                | CLONE_FS
                | CLONE_SETTLS
                | CLONE_CHILD_SETTID
                | CLONE_CHILD_CLEARTID) as u64;
            let child_stack = 0x88000u64;
            let tls = 0x1234_5000u64;

            let ret =
                thread_impl::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, tls, child_tidptr);
            assert!(ret > 0);
            assert_eq!(t.vm.clone_pending, 1);
            assert_eq!(t.vm.clone_child_tid, ret as i32);
            assert_eq!(t.vm.clone_child_stack, child_stack);
            assert_eq!(t.vm.clone_tls, tls);
            assert_eq!(t.vm.clone_child_tidptr, child_tidptr);

            let child_ptr =
                thread_impl::spawn_from_clone(&t.vm as *const ThreadState as u32, t.base);
            assert_ne!(child_ptr, 0);

            let child = unsafe { &*(child_ptr as *const ThreadState) };
            assert_eq!(child.tid, ret as i32);
            assert_eq!(child.x[10], 0);
            assert_eq!(child.x[2], child_stack);
            assert_eq!(child.x[4], tls);
            assert_eq!(child.tls_base, tls);
            assert_eq!(child.clear_child_tid, child_tidptr);
            assert_eq!(child.sig_mask, 0x55);
            assert_eq!(child.sig_pending, 0);
            assert_eq!(child.sigaltstack_sp, 0);
            assert_eq!(child.sigaltstack_size, 0);
            assert_eq!(child.sigaltstack_flags, 0);

            let written_tid = unsafe { crate::guest_mem::read_u32(t.base, child_tidptr) };
            assert_eq!(written_tid, ret as u32);

            let threads_off = core::mem::offset_of!(ProcessState, threads) as u64;
            let record_size = core::mem::size_of::<ThreadRecord>() as u64;
            let record_off = ps_ptr + threads_off + ((ret as u64) - 1) * record_size;
            let state = unsafe { crate::guest_mem::read_u32(t.base, record_off) };
            let thread_ptr = unsafe { crate::guest_mem::read_u32(t.base, record_off + 8) };
            assert_eq!(state as i32, THREAD_RUNNING);
            assert_eq!(thread_ptr, child_ptr);

            assert_eq!(t.vm.clone_pending, 0);
            assert_eq!(t.vm.clone_child_tid, 0);
            assert_eq!(t.vm.clone_child_stack, 0);
            assert_eq!(t.vm.clone_tls, 0);
            assert_eq!(t.vm.clone_child_tidptr, 0);
        }

        #[test]
        fn contract_thread_record_ptr_is_absolute_even_with_nonzero_guest_base() {
            let child_ptr = unsafe {
                crate::alloc::alloc_zeroed(
                    core::mem::size_of::<ThreadState>() as u32,
                    core::mem::align_of::<ThreadState>() as u32,
                )
            };
            assert_ne!(child_ptr, 0);

            let resolved = thread_impl::thread_state_from_record_ptr(child_ptr);
            assert_eq!(resolved, Some(child_ptr as *mut ThreadState));

            // A non-zero guest base must not be added here. thread_ptr stores an
            // absolute pointer in the shared WASM linear memory.
            let fake_guest_base = 0x10_0000u32;
            let wrong_absolute = fake_guest_base as usize + child_ptr as usize;
            assert_ne!(wrong_absolute as u32, child_ptr);
        }

        #[test]
        fn contract_futex_wake_unblocks_waiting_thread_record() {
            let mut t = TestVm::new();
            let addr = t.scratch + 0x500;
            let ps =
                unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
            ps.threads[1] =
                ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0xDEAD_BEEFu32, 0, addr as u32);
            ps.thread_count.store(2, Ordering::Release);

            let ret =
                thread_impl::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
            assert_eq!(ret, 1, "futex_wake should report one woken waiter");
            assert_eq!(ps.threads[1].state, THREAD_RUNNING);
            assert_eq!(ps.threads[1].blocked_addr, 0);
        }

        #[test]
        fn contract_futex_cmp_requeue_moves_remaining_waiters() {
            let mut t = TestVm::new();
            let from_addr = t.scratch + 0x520;
            let to_addr = t.scratch + 0x524;
            unsafe {
                crate::guest_mem::write_u32(t.base, from_addr, 7);
            }
            let ps =
                unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
            ps.thread_count.store(3, Ordering::Release);
            ps.threads[1] =
                ThreadRecord::new(2, THREAD_BLOCKED_FUTEX, 0x1000, 0, from_addr as u32);
            ps.threads[2] =
                ThreadRecord::new(3, THREAD_BLOCKED_FUTEX, 0x2000, 0, from_addr as u32);

            let ret = thread_impl::sys_futex(
                &mut t.vm,
                t.base,
                from_addr,
                FUTEX_CMP_REQUEUE as u64,
                1,
                1,
                to_addr,
                7,
            );

            assert_eq!(ret, 2);
            assert_eq!(ps.threads[1].state, THREAD_RUNNING);
            assert_eq!(ps.threads[1].blocked_addr, 0);
            assert_eq!(ps.threads[2].state, THREAD_BLOCKED_FUTEX);
            assert_eq!(ps.threads[2].blocked_addr, to_addr as u32);
        }

        #[test]
        fn contract_futex_cmp_requeue_validates_counts_and_compare_value() {
            let mut t = TestVm::new();
            let from_addr = t.scratch + 0x600;
            let to_addr = t.scratch + 0x604;
            unsafe {
                crate::guest_mem::write_u32(t.base, from_addr, 11);
            }

            let invalid_wake = thread_impl::sys_futex(
                &mut t.vm,
                t.base,
                from_addr,
                FUTEX_CMP_REQUEUE as u64,
                u64::MAX,
                1,
                to_addr,
                11,
            );
            assert_eq!(invalid_wake, EINVAL);

            let invalid_requeue = thread_impl::sys_futex(
                &mut t.vm,
                t.base,
                from_addr,
                FUTEX_CMP_REQUEUE as u64,
                1,
                u64::MAX,
                to_addr,
                11,
            );
            assert_eq!(invalid_requeue, EINVAL);

            let mismatched = thread_impl::sys_futex(
                &mut t.vm,
                t.base,
                from_addr,
                FUTEX_CMP_REQUEUE as u64,
                1,
                1,
                to_addr,
                12,
            );
            assert_eq!(mismatched, EAGAIN);
        }

        #[test]
        fn contract_exit_marks_owned_robust_futex_owner_died_and_wakes_waiters() {
            let mut t = TestVm::new();
            let head = t.scratch + 0x600;
            let node = head + 0x40;
            let futex_addr = node + 8;

            unsafe {
                crate::guest_mem::write_u64(t.base, head, node);
                crate::guest_mem::write_u64(t.base, head + 8, 8);
                crate::guest_mem::write_u64(t.base, head + 16, 0);
                crate::guest_mem::write_u64(t.base, node, head);
                crate::guest_mem::write_u32(
                    t.base,
                    futex_addr,
                    thread_impl::FUTEX_WAITERS | t.vm.tid as u32,
                );
            }
            t.vm.robust_list_head = head;
            t.vm.robust_list_len = thread_impl::ROBUST_LIST_HEAD_LEN;

            let ps =
                unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
            ps.threads[1] = ThreadRecord::new(
                2,
                THREAD_BLOCKED_FUTEX,
                0xDEAD_BEEFu32,
                0,
                futex_addr as u32,
            );
            ps.thread_count.store(2, Ordering::Release);

            let status = thread_impl::sys_exit(&mut t.vm, t.base, 7);
            assert_eq!(status, STATUS_FAULT);
            assert_eq!(
                unsafe { crate::guest_mem::read_u32(t.base, futex_addr) },
                thread_impl::FUTEX_WAITERS | thread_impl::FUTEX_OWNER_DIED
            );
            assert_eq!(ps.threads[1].state, THREAD_RUNNING);
            assert_eq!(ps.threads[1].blocked_addr, 0);
        }

        #[test]
        fn contract_exit_group_cleans_up_other_thread_robust_futexes() {
            let mut t = TestVm::new();
            let head = t.scratch + 0x700;
            let node = head + 0x40;
            let futex_addr = node + 8;

            unsafe {
                crate::guest_mem::write_u64(t.base, head, node);
                crate::guest_mem::write_u64(t.base, head + 8, 8);
                crate::guest_mem::write_u64(t.base, head + 16, 0);
                crate::guest_mem::write_u64(t.base, node, head);
                crate::guest_mem::write_u32(t.base, futex_addr, thread_impl::FUTEX_WAITERS | 2);
            }

            let child_ptr = unsafe {
                crate::alloc::alloc_zeroed(
                    core::mem::size_of::<ThreadState>() as u32,
                    core::mem::align_of::<ThreadState>() as u32,
                )
            };
            assert_ne!(child_ptr, 0);
            let child = unsafe { &mut *(child_ptr as *mut ThreadState) };
            child.tid = 2;
            child.process_ptr = t.vm.process_ptr;
            child.robust_list_head = head;
            child.robust_list_len = thread_impl::ROBUST_LIST_HEAD_LEN;

            let ps =
                unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
            ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, child_ptr, 0, 0);
            ps.thread_count.store(2, Ordering::Release);

            let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
            assert_eq!(status, STATUS_FAULT);
            assert_eq!(
                unsafe { crate::guest_mem::read_u32(t.base, futex_addr) },
                thread_impl::FUTEX_WAITERS | thread_impl::FUTEX_OWNER_DIED
            );
            assert_eq!(ps.thread_count.load(Ordering::Acquire), 0);
            assert_eq!(ps.threads[0].state, THREAD_NONE);
            assert_eq!(ps.threads[1].state, THREAD_NONE);
        }

        #[test]
        fn contract_exit_group_marks_process_dead() {
            let mut t = TestVm::new();
            let ps =
                unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
            ps.thread_count.store(2, Ordering::Release);
            ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xCAFE_BABEu32, 0, 0);

            let status = thread_impl::sys_exit_group(&mut t.vm, t.base, 9);
            assert_eq!(status, STATUS_FAULT);
            assert_eq!(t.vm.exit_code, 9);
            assert_eq!(ps.thread_count.load(Ordering::Acquire), 0);
            assert_eq!(ps.threads[0].state, THREAD_NONE);
            assert_eq!(ps.threads[1].state, THREAD_NONE);
        }

        #[test]
        fn contract_init_main_thread_records_running_slot() {
            let mut t = TestVm::new();
            let vm_ptr = &mut t.vm as *mut ThreadState as u32;
            thread_impl::init_main_thread(vm_ptr, t.base);

            let ps =
                unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
            assert_eq!(ps.thread_count.load(Ordering::Acquire), 1);
            assert_eq!(ps.threads[0].tid, 1);
            assert_eq!(ps.threads[0].state, THREAD_RUNNING);
            assert_eq!(ps.threads[0].thread_ptr, vm_ptr);
        }

        #[test]
        fn contract_discard_exec_ignores_invalid_stale_slots() {
            let mut t = TestVm::new();
            let ps =
                unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
            ps.thread_count.store(2, Ordering::Release);
            ps.threads[1] = ThreadRecord::new(0, THREAD_RUNNING, 0, 0x6e69_622f, 0);

            let discarded = thread_impl::discard_other_threads_for_exec(&t.vm, t.base);
            assert_eq!(discarded, 1);
            assert_eq!(ps.thread_count.load(Ordering::Acquire), 1);
            assert_eq!(ps.threads[1].state, THREAD_NONE);
        }
    }
}
