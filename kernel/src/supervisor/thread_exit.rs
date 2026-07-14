use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::abi::*;
use crate::guest_mem;
use crate::types::{ProcessState, THREAD_DEAD, THREAD_NONE, ThreadRecord, ThreadState};

const ROBUST_LIST_HEAD_LEN: u64 = 24;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
const ROBUST_LIST_LIMIT: u32 = 2048;

static THREAD_EXIT_CLEANUP_COUNT: AtomicU64 = AtomicU64::new(0);
static THREAD_EXIT_CLEANUP_LOCK: AtomicU32 = AtomicU32::new(0);
static LAST_GROUP_EXIT_SOURCE_VM_PTR: AtomicU32 = AtomicU32::new(0);
static mut LAST_THREAD_EXIT_CLEANUP: super::SupervisorThreadExitCleanupRecord =
    super::SupervisorThreadExitCleanupRecord::empty();

#[derive(Clone, Copy)]
struct RobustCleanupStats {
    head: u64,
    pending: u64,
    marked: u32,
    woken: u32,
    first_futex_addr: u64,
}

impl RobustCleanupStats {
    const fn empty(head: u64) -> Self {
        Self {
            head,
            pending: 0,
            marked: 0,
            woken: 0,
            first_futex_addr: 0,
        }
    }

    fn record_marked(&mut self, futex_addr: u64, woken: u32) {
        self.marked = self.marked.saturating_add(1);
        self.woken = self.woken.saturating_add(woken);
        if self.first_futex_addr == 0 {
            self.first_futex_addr = futex_addr;
        }
    }
}

pub(super) fn init() {
    THREAD_EXIT_CLEANUP_COUNT.store(0, Ordering::Relaxed);
    LAST_GROUP_EXIT_SOURCE_VM_PTR.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&THREAD_EXIT_CLEANUP_LOCK, || unsafe {
        LAST_THREAD_EXIT_CLEANUP = super::SupervisorThreadExitCleanupRecord::empty();
    });
}

pub(super) fn group_exit_source_vm_ptr(vm: &ThreadState) -> u32 {
    let source_vm_ptr = LAST_GROUP_EXIT_SOURCE_VM_PTR.load(Ordering::Acquire);
    let Some(source) = super::thread::state_from_ptr(source_vm_ptr) else {
        return 0;
    };
    if source.guest_base != vm.guest_base
        || source.process_ptr != vm.process_ptr
        || source.exit_code != vm.exit_code
        || source.term_signal != vm.term_signal
    {
        return 0;
    }
    source_vm_ptr
}

pub fn thread_exit_cleanup_count() -> u64 {
    THREAD_EXIT_CLEANUP_COUNT.load(Ordering::Relaxed)
}

pub fn clear_tid_and_wake(process_ptr: u32, base: u32, addr: u64) -> u32 {
    if addr == 0 {
        return 0;
    }
    unsafe {
        guest_mem::write_u32(base, addr, 0);
    }
    crate::syscall::thread::supervisor_wake_futex_waiters_by_process_ptr(
        process_ptr,
        base,
        addr,
        u32::MAX,
        FUTEX_BITSET_MATCH_ANY,
    )
}

fn mark_robust_futex_owner_died(
    process_ptr: u32,
    base: u32,
    owner_tid: u32,
    entry_addr: u64,
    futex_offset: i64,
) -> Option<(u64, u32)> {
    let futex_addr = if futex_offset >= 0 {
        entry_addr.checked_add(futex_offset as u64)?
    } else {
        entry_addr.checked_sub((-futex_offset) as u64)?
    };

    if !crate::syscall::memory::guest_range_accessible(base, futex_addr, 4) {
        return None;
    }
    let owner = unsafe { guest_mem::read_u32(base, futex_addr) };
    if owner & FUTEX_TID_MASK != owner_tid {
        return None;
    }

    let updated = (owner & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
    unsafe {
        guest_mem::write_u32(base, futex_addr, updated);
    }
    let woken = crate::syscall::thread::supervisor_wake_futex_waiters_by_process_ptr(
        process_ptr,
        base,
        futex_addr,
        u32::MAX,
        FUTEX_BITSET_MATCH_ANY,
    );
    Some((futex_addr, woken))
}

fn cleanup_robust_futexes(
    process_ptr: u32,
    base: u32,
    owner_tid: u32,
    robust_head: u64,
) -> RobustCleanupStats {
    let mut stats = RobustCleanupStats::empty(robust_head);
    if process_ptr == 0 || owner_tid == 0 || robust_head == 0 {
        return stats;
    }
    if !crate::syscall::memory::guest_range_accessible(base, robust_head, ROBUST_LIST_HEAD_LEN) {
        return stats;
    }

    let first = unsafe { guest_mem::read_u64(base, robust_head) };
    let futex_offset = unsafe { guest_mem::read_u64(base, robust_head + 8) as i64 };
    let pending = unsafe { guest_mem::read_u64(base, robust_head + 16) };
    stats.pending = pending;

    let mut entry = first;
    let mut walked = 0;
    while entry != 0 && entry != robust_head && walked < ROBUST_LIST_LIMIT {
        if !crate::syscall::memory::guest_range_accessible(base, entry, 8) {
            break;
        }
        if let Some((futex_addr, woken)) =
            mark_robust_futex_owner_died(process_ptr, base, owner_tid, entry, futex_offset)
        {
            stats.record_marked(futex_addr, woken);
        }
        entry = unsafe { guest_mem::read_u64(base, entry) };
        walked += 1;
    }

    if pending != 0 && pending != robust_head {
        if let Some((futex_addr, woken)) =
            mark_robust_futex_owner_died(process_ptr, base, owner_tid, pending, futex_offset)
        {
            stats.record_marked(futex_addr, woken);
        }
    }
    stats
}

pub fn cleanup_thread_robust_futexes(
    process_ptr: u32,
    base: u32,
    owner_tid: u32,
    robust_head: u64,
) {
    let _ = cleanup_robust_futexes(process_ptr, base, owner_tid, robust_head);
}

pub fn complete_thread_exit(vm: &mut ThreadState, base: u32) -> u32 {
    super::thread::mark_current_thread_exiting(vm, base);

    let robust_order = if vm.robust_list_head != 0 { 1 } else { 0 };
    let robust_stats =
        cleanup_robust_futexes(vm.process_ptr, base, vm.tid as u32, vm.robust_list_head);
    vm.robust_list_head = 0;
    vm.robust_list_len = 0;

    let remaining_threads = super::thread::decrement_thread_count(vm, base);

    let clear_child_tid = vm.clear_child_tid;
    let clear_child_tid_order = if clear_child_tid != 0 {
        if robust_order == 0 {
            1
        } else {
            robust_order + 1
        }
    } else {
        0
    };
    let clear_child_tid_woken = if clear_child_tid != 0 {
        let woken = clear_tid_and_wake(vm.process_ptr, base, clear_child_tid);
        vm.clear_child_tid = 0;
        woken
    } else {
        0
    };

    if remaining_threads == 0 {
        super::thread::clear_next_tid_hint(base, vm.process_ptr);
    }

    super::thread::mark_current_thread_dead(vm, base);
    vm.status = STATUS_FAULT;
    record_thread_exit_cleanup(
        super::SUPERVISOR_THREAD_EXIT_CLEANUP_KIND_THREAD_EXIT,
        vm as *const ThreadState as u32,
        vm.tid as u32,
        vm.process_ptr,
        vm.status as u32,
        robust_stats.marked,
        robust_stats.woken,
        clear_child_tid_woken,
        robust_order,
        clear_child_tid_order,
        clear_child_tid,
        robust_stats.head,
        robust_stats.pending,
        robust_stats.first_futex_addr,
    );
    remaining_threads
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

pub fn complete_thread_group_exit(
    vm: &mut ThreadState,
    base: u32,
    exit_code: i32,
    term_signal: i32,
) {
    LAST_GROUP_EXIT_SOURCE_VM_PTR.store(vm as *mut ThreadState as u32, Ordering::Release);
    let process_ptr = vm.process_ptr;
    let mut completed_sync_effects = vm.completed_sync_effects;
    let mut completed_pipe_sync_slots = vm.completed_pipe_sync_slots;
    let mut completed_pipe_sync_read_slots = vm.completed_pipe_sync_read_slots;
    let mut completed_pipe_sync_write_slots = vm.completed_pipe_sync_write_slots;
    let mut completed_pipe_sync_control_slots = vm.completed_pipe_sync_control_slots;
    let mut completed_pipe_fresh_slots = vm.completed_pipe_fresh_slots;
    unsafe {
        if process_ptr == 0 {
            vm.exit_code = exit_code;
            vm.term_signal = term_signal;
            vm.status = STATUS_FAULT;
            vm.robust_list_head = 0;
            vm.robust_list_len = 0;
            vm.clear_child_tid = 0;
            return;
        }
        let ps = &mut *((base as u64 + process_ptr as u64) as *mut ProcessState);
        for record in ps.threads.iter() {
            let Some(thread_vm) = thread_state_from_record_ptr(record.thread_ptr) else {
                continue;
            };
            let thread_vm = &*thread_vm;
            completed_sync_effects |= thread_vm.completed_sync_effects;
            completed_pipe_sync_slots |= thread_vm.completed_pipe_sync_slots;
            completed_pipe_sync_read_slots |= thread_vm.completed_pipe_sync_read_slots;
            completed_pipe_sync_write_slots |= thread_vm.completed_pipe_sync_write_slots;
            completed_pipe_sync_control_slots |= thread_vm.completed_pipe_sync_control_slots;
            completed_pipe_fresh_slots |= thread_vm.completed_pipe_fresh_slots;
        }
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
            let _ = cleanup_robust_futexes(process_ptr, base, record.tid as u32, robust_head);

            let clear_child_tid = if record.tid == vm.tid {
                vm.clear_child_tid
            } else if let Some(thread_vm) = thread_vm_ptr {
                (*thread_vm).clear_child_tid
            } else {
                record.clear_child_tid
            };
            if record.tid == vm.tid {
                vm.exit_code = exit_code;
                vm.term_signal = term_signal;
                vm.status = STATUS_FAULT;
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

            if let Some(thread_vm) = thread_vm_ptr {
                let thread_vm = &mut *thread_vm;
                thread_vm.completed_sync_effects = completed_sync_effects;
                thread_vm.completed_pipe_sync_slots = completed_pipe_sync_slots;
                thread_vm.completed_pipe_sync_read_slots = completed_pipe_sync_read_slots;
                thread_vm.completed_pipe_sync_write_slots = completed_pipe_sync_write_slots;
                thread_vm.completed_pipe_sync_control_slots = completed_pipe_sync_control_slots;
                thread_vm.completed_pipe_fresh_slots = completed_pipe_fresh_slots;
            }

            if clear_child_tid != 0 {
                clear_tid_and_wake(process_ptr, base, clear_child_tid);
            }
            *record = ThreadRecord::empty();
        }

        super::thread::reset_thread_count_for_group_exit(vm, base);
    }

    vm.exit_code = exit_code;
    vm.term_signal = term_signal;
    vm.status = STATUS_FAULT;
    vm.robust_list_head = 0;
    vm.robust_list_len = 0;
    vm.clear_child_tid = 0;
    vm.completed_sync_effects |= completed_sync_effects;
    vm.completed_pipe_sync_slots |= completed_pipe_sync_slots;
    vm.completed_pipe_sync_read_slots |= completed_pipe_sync_read_slots;
    vm.completed_pipe_sync_write_slots |= completed_pipe_sync_write_slots;
    vm.completed_pipe_sync_control_slots |= completed_pipe_sync_control_slots;
    vm.completed_pipe_fresh_slots |= completed_pipe_fresh_slots;
}

#[allow(clippy::too_many_arguments)]
pub fn record_thread_exit_cleanup(
    kind: u32,
    vm_ptr: u32,
    tid: u32,
    process_ptr: u32,
    status: u32,
    robust_marked: u32,
    robust_woken: u32,
    clear_child_tid_woken: u32,
    robust_order: u32,
    clear_child_tid_order: u32,
    clear_child_tid: u64,
    robust_head: u64,
    robust_pending: u64,
    first_robust_futex_addr: u64,
) {
    let seq = THREAD_EXIT_CLEANUP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = super::SupervisorThreadExitCleanupRecord {
        kind,
        seq,
        vm_ptr,
        tid,
        process_ptr,
        status,
        robust_marked,
        robust_woken,
        clear_child_tid_woken,
        robust_order,
        clear_child_tid_order,
        clear_child_tid,
        robust_head,
        robust_pending,
        first_robust_futex_addr,
    };
    super::lock::with_spin_lock(&THREAD_EXIT_CLEANUP_LOCK, || unsafe {
        LAST_THREAD_EXIT_CLEANUP = record;
    });
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = super::lock::with_spin_lock(&THREAD_EXIT_CLEANUP_LOCK, || unsafe {
        LAST_THREAD_EXIT_CLEANUP
    });
    let mut encoded = [0u8; super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_THREAD_EXIT_CLEANUP_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES);
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.vm_ptr);
    super::write_u32(&mut encoded, 28, record.tid);
    super::write_u32(&mut encoded, 32, record.process_ptr);
    super::write_u32(&mut encoded, 36, record.status);
    super::write_u32(&mut encoded, 40, record.robust_marked);
    super::write_u32(&mut encoded, 44, record.robust_woken);
    super::write_u32(&mut encoded, 48, record.clear_child_tid_woken);
    super::write_u32(&mut encoded, 52, record.robust_order);
    super::write_u32(&mut encoded, 56, record.clear_child_tid_order);
    super::write_u32(&mut encoded, 60, 0);
    super::write_u64(&mut encoded, 64, record.clear_child_tid);
    super::write_u64(&mut encoded, 72, record.robust_head);
    super::write_u64(&mut encoded, 80, record.robust_pending);
    super::write_u64(&mut encoded, 88, record.first_robust_futex_addr);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as i32
}
