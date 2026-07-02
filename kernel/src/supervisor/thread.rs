use core::sync::atomic::Ordering;

use crate::abi::*;
use crate::guest_mem;
use crate::types::{
    ProcessState, THREAD_BLOCKED_FUTEX, THREAD_DEAD, THREAD_EXITING, THREAD_NONE, THREAD_RUNNING,
    THREAD_STARTING, ThreadRecord, ThreadState,
};

const THREAD_COUNT_TRACE_INIT_MAIN: u32 = 1;
const THREAD_COUNT_TRACE_CLONE_INC: u32 = 2;
const THREAD_COUNT_TRACE_EXIT_DEC: u32 = 3;
const THREAD_COUNT_TRACE_TERMINATE: u32 = 4;
const THREAD_COUNT_TRACE_EXEC_RESET: u32 = 5;

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

impl CloneSpawnTrace {
    const fn empty() -> Self {
        Self {
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
        }
    }
}

static mut LAST_CLONE_SPAWN: CloneSpawnTrace = CloneSpawnTrace::empty();
static mut NEXT_TID_HINTS: [i32; MAX_PROCESSES] = [0; MAX_PROCESSES];

pub(super) fn init() {
    reset_thread_clone_registry();
}

pub fn reset_thread_clone_registry() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(NEXT_TID_HINTS), [0; MAX_PROCESSES]);
        LAST_CLONE_SPAWN = CloneSpawnTrace::empty();
    }
}

pub(super) fn state_from_ptr(vm_ptr: u32) -> Option<&'static crate::types::ThreadState> {
    if vm_ptr == 0 {
        return None;
    }
    let absolute = vm_ptr as usize;
    let align = core::mem::align_of::<crate::types::ThreadState>();
    if (absolute & (align - 1)) != 0 {
        return None;
    }
    let end = absolute.checked_add(core::mem::size_of::<crate::types::ThreadState>())?;
    let memory_size = crate::wasm::memory_size_bytes();
    if memory_size == 0 || end as u64 > memory_size {
        return None;
    }
    Some(unsafe { &*(absolute as *const crate::types::ThreadState) })
}

pub(super) fn state_mut_from_ptr(vm_ptr: u32) -> Option<&'static mut crate::types::ThreadState> {
    if vm_ptr == 0 {
        return None;
    }
    let absolute = vm_ptr as usize;
    if absolute < core::mem::size_of::<crate::types::ThreadState>() {
        return None;
    }
    Some(unsafe { &mut *(absolute as *mut crate::types::ThreadState) })
}

fn status_from_record(record: &crate::types::ThreadRecord, base: u32, process_ptr: u32) -> u32 {
    super::state::validated_thread_status_from_record(record, base, process_ptr).unwrap_or(0)
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

pub(super) fn mark_current_thread_exiting(vm: &ThreadState, base: u32) {
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
}

pub(super) fn decrement_thread_count(vm: &ThreadState, base: u32) -> u32 {
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

pub(super) fn clear_next_tid_hint(base: u32, process_ptr: u32) {
    set_next_tid_hint(base, process_ptr, 0);
}

pub(super) fn mark_current_thread_dead(vm: &ThreadState, base: u32) {
    unsafe {
        if let Some(record) = thread_record_ptr(base, vm.process_ptr, vm.tid) {
            write_thread_record(record, ThreadRecord::new(vm.tid, THREAD_DEAD, 0, 0, 0));
        }
    }
}

pub(super) fn reset_thread_count_for_group_exit(vm: &ThreadState, base: u32) {
    unsafe {
        let Some(ps) = process_state_ptr(base, vm.process_ptr) else {
            return;
        };
        let before = (*ps).thread_count.load(Ordering::Acquire);
        (*ps).thread_count.store(0, Ordering::Release);
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
                super::thread_exit::clear_tid_and_wake(
                    vm.process_ptr,
                    base,
                    record.clear_child_tid,
                );
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

pub fn register_clone_thread(
    vm: &mut ThreadState,
    base: u32,
    clone_flags: u64,
    child_stack: u64,
    parent_tidptr: u64,
    tls: u64,
    child_tidptr: u64,
) -> i64 {
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

    vm.clone_flags = clone_flags;
    vm.clone_child_stack = child_stack;
    vm.clone_tls = tls;
    vm.clone_child_tidptr = child_tidptr;
    vm.clone_child_tid = new_tid;
    vm.clone_pending = 1;

    if !super::enqueue_clone_spawn(vm as *mut ThreadState as u32) {
        unsafe {
            if let Some(ps) = process_state_ptr(base, vm.process_ptr) {
                let before = (*ps).thread_count.fetch_sub(1, Ordering::AcqRel);
                crate::tracepoints::record_thread_count(
                    THREAD_COUNT_TRACE_EXIT_DEC,
                    vm as *const ThreadState as u32,
                    vm.tid,
                    vm.process_ptr,
                    before,
                    before.saturating_sub(1),
                );
                if new_tid > 0 && new_tid as usize <= MAX_THREADS {
                    (*ps).threads[(new_tid - 1) as usize] = ThreadRecord::empty();
                    set_next_tid_hint(base, vm.process_ptr, new_tid);
                }
            }
        }
        vm.clone_flags = 0;
        vm.clone_child_stack = 0;
        vm.clone_tls = 0;
        vm.clone_child_tidptr = 0;
        vm.clone_child_tid = 0;
        vm.clone_pending = 0;
        return EAGAIN;
    }

    if clone_flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
        unsafe { guest_mem::write_u32(base, parent_tidptr, new_tid as u32) };
    }

    vm.x[10] = new_tid as u64;
    vm.status = STATUS_CLONE_SPAWN;

    new_tid as i64
}

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

        super::discard_clone_spawn(parent_vm_ptr);

        child_ptr
    }
}

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

pub fn process_thread_count(vm_ptr: u32, base: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        match process_state_ptr(base, vm.process_ptr) {
            Some(ps) => (*ps).thread_count.load(Ordering::Acquire),
            None => 0,
        }
    }
}

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
                *record = ThreadRecord::new(tid, THREAD_STARTING, 0, 0, 0);
                set_next_tid_hint(base, vm.process_ptr, tid.saturating_add(1));
                return tid;
            }
        }
    }
    -1
}

pub(super) fn write_state_snapshot(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as i32;
    }
    if vm_ptr == 0 || out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if vm.process_ptr == 0 {
        return crate::abi::EINVAL as i32;
    }
    let ps = unsafe {
        &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState)
    };
    let mut snapshot = [0u8; super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as usize];
    super::write_u32(
        &mut snapshot,
        0,
        super::SUPERVISOR_THREAD_STATE_SNAPSHOT_MAGIC,
    );
    super::write_u32(&mut snapshot, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(
        &mut snapshot,
        8,
        super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES,
    );
    super::write_u32(&mut snapshot, 12, crate::abi::MAX_THREADS as u32);
    super::write_u32(&mut snapshot, 16, vm.process_ptr);
    super::write_u32(&mut snapshot, 20, vm_ptr);
    super::write_u32(
        &mut snapshot,
        24,
        super::SUPERVISOR_THREAD_STATE_RECORD_BYTES as u32,
    );
    super::write_u32(&mut snapshot, 28, 0);
    for slot in 0..crate::abi::MAX_THREADS {
        let record = ps.threads[slot];
        let offset = super::SUPERVISOR_THREAD_STATE_HEADER_BYTES
            + slot * super::SUPERVISOR_THREAD_STATE_RECORD_BYTES;
        let override_state =
            super::event::thread_state_override(record.thread_ptr, record.tid as u32);
        let state = override_state
            .as_ref()
            .map(|event| event.state)
            .unwrap_or(record.state as u32);
        let status = override_state
            .as_ref()
            .map(|event| event.status)
            .unwrap_or_else(|| status_from_record(&record, vm.guest_base, vm.process_ptr));
        let blocked_addr = override_state
            .as_ref()
            .and_then(|event| (event.blocked_addr != 0).then_some(event.blocked_addr))
            .unwrap_or(record.blocked_addr);
        super::write_u32(&mut snapshot, offset, record.tid as u32);
        super::write_u32(&mut snapshot, offset + 4, state);
        super::write_u32(&mut snapshot, offset + 8, record.thread_ptr);
        super::write_u32(&mut snapshot, offset + 12, status);
        super::write_u64(&mut snapshot, offset + 16, blocked_addr);
        super::write_u64(&mut snapshot, offset + 24, record.pending_sigset);
    }
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as usize,
        )
    };
    out.copy_from_slice(&snapshot);
    super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as i32
}
