//! Additive supervisor shadow protocol.
//!
//! Phase A records deterministic shadows of runtime decisions without changing
//! guest-visible behavior. Later phases can replace these no-op decisions with
//! supervisor-owned policy.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

mod abi;
mod event;
mod exports;
mod futex;
mod host_op;
mod records;
mod resume;
mod runnable;
mod state;
mod thread;
mod timer;

pub use abi::*;
pub use exports::*;
pub(super) use records::*;

const SNAPSHOT_MAGIC: u32 = 0x5055_5354; // "TSUP" little-endian.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
static THREAD_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static HOST_COMPLETION_COUNT: AtomicU64 = AtomicU64::new(0);
static FAULT_EXIT_DECISION_COUNT: AtomicU64 = AtomicU64::new(0);
static THREAD_EXIT_CLEANUP_COUNT: AtomicU64 = AtomicU64::new(0);
static PROCESS_LIFECYCLE_COUNT: AtomicU64 = AtomicU64::new(0);
static FD_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static FS_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static SIGNAL_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static THREAD_EVENT_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static HOST_COMPLETION_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static HOST_OP_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static LAST_THREAD_EVENT_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_HOST_COMPLETION_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_HOST_OP_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_THREAD_EVENT_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_HOST_COMPLETION_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_HOST_OP_LEN: AtomicU32 = AtomicU32::new(0);
static THREAD_EXIT_CLEANUP_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_THREAD_EXIT_CLEANUP: SupervisorThreadExitCleanupRecord =
    SupervisorThreadExitCleanupRecord::empty();
static PROCESS_LIFECYCLE_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_PROCESS_LIFECYCLE: SupervisorProcessLifecycleRecord =
    SupervisorProcessLifecycleRecord::empty();
static FD_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_FD_CONTROL: SupervisorFdControlRecord = SupervisorFdControlRecord::empty();
static FS_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_FS_CONTROL: SupervisorFsControlRecord = SupervisorFsControlRecord::empty();
static SIGNAL_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_SIGNAL_CONTROL: SupervisorSignalControlRecord =
    SupervisorSignalControlRecord::empty();

pub fn init() {
    THREAD_EVENT_COUNT.store(0, Ordering::Relaxed);
    HOST_COMPLETION_COUNT.store(0, Ordering::Relaxed);
    FAULT_EXIT_DECISION_COUNT.store(0, Ordering::Relaxed);
    THREAD_EXIT_CLEANUP_COUNT.store(0, Ordering::Relaxed);
    PROCESS_LIFECYCLE_COUNT.store(0, Ordering::Relaxed);
    FD_CONTROL_COUNT.store(0, Ordering::Relaxed);
    FS_CONTROL_COUNT.store(0, Ordering::Relaxed);
    SIGNAL_CONTROL_COUNT.store(0, Ordering::Relaxed);
    THREAD_EVENT_LOG_HASH.store(FNV_OFFSET, Ordering::Relaxed);
    HOST_COMPLETION_LOG_HASH.store(FNV_OFFSET, Ordering::Relaxed);
    HOST_OP_LOG_HASH.store(FNV_OFFSET, Ordering::Relaxed);
    LAST_THREAD_EVENT_HASH.store(0, Ordering::Relaxed);
    LAST_HOST_COMPLETION_HASH.store(0, Ordering::Relaxed);
    LAST_HOST_OP_HASH.store(0, Ordering::Relaxed);
    LAST_THREAD_EVENT_LEN.store(0, Ordering::Relaxed);
    LAST_HOST_COMPLETION_LEN.store(0, Ordering::Relaxed);
    LAST_HOST_OP_LEN.store(0, Ordering::Relaxed);
    event::init_state();
    runnable::init();
    resume::init();
    host_op::init();
    with_thread_exit_cleanup_lock(|| unsafe {
        LAST_THREAD_EXIT_CLEANUP = SupervisorThreadExitCleanupRecord::empty();
    });
    with_process_lifecycle_lock(|| unsafe {
        LAST_PROCESS_LIFECYCLE = SupervisorProcessLifecycleRecord::empty();
    });
    with_fd_control_lock(|| unsafe {
        LAST_FD_CONTROL = SupervisorFdControlRecord::empty();
    });
    with_fs_control_lock(|| unsafe {
        LAST_FS_CONTROL = SupervisorFsControlRecord::empty();
    });
    with_signal_control_lock(|| unsafe {
        LAST_SIGNAL_CONTROL = SupervisorSignalControlRecord::empty();
    });
}

pub fn thread_event_count() -> u64 {
    THREAD_EVENT_COUNT.load(Ordering::Relaxed)
}

pub fn host_completion_count() -> u64 {
    HOST_COMPLETION_COUNT.load(Ordering::Relaxed)
}

pub fn host_op_poll_count() -> u64 {
    host_op::poll_count()
}

pub fn host_op_emit_count() -> u64 {
    host_op::emit_count()
}

pub fn host_op_overflow_count() -> u64 {
    host_op::overflow_count()
}

pub fn thread_exit_cleanup_count() -> u64 {
    THREAD_EXIT_CLEANUP_COUNT.load(Ordering::Relaxed)
}

pub fn process_lifecycle_count() -> u64 {
    PROCESS_LIFECYCLE_COUNT.load(Ordering::Relaxed)
}

pub fn fd_control_count() -> u64 {
    FD_CONTROL_COUNT.load(Ordering::Relaxed)
}

pub fn fs_control_count() -> u64 {
    FS_CONTROL_COUNT.load(Ordering::Relaxed)
}

pub fn signal_control_count() -> u64 {
    SIGNAL_CONTROL_COUNT.load(Ordering::Relaxed)
}

pub fn resume_poll_count() -> u64 {
    resume::poll_count()
}

pub fn resume_enqueue_count() -> u64 {
    resume::enqueue_count()
}

pub fn resume_overflow_count() -> u64 {
    resume::overflow_count()
}

pub fn thread_event_log_hash() -> u64 {
    THREAD_EVENT_LOG_HASH.load(Ordering::Relaxed)
}

pub fn host_completion_log_hash() -> u64 {
    HOST_COMPLETION_LOG_HASH.load(Ordering::Relaxed)
}

pub fn host_op_log_hash() -> u64 {
    HOST_OP_LOG_HASH.load(Ordering::Relaxed)
}

fn fnv_hash(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fold_log_hash(current: &AtomicU64, entry_hash: u64, entry_len: u32) -> u64 {
    let previous = current.load(Ordering::Relaxed);
    let mut next = previous ^ entry_hash;
    next = next.wrapping_mul(FNV_PRIME);
    next ^= u64::from(entry_len);
    next = next.wrapping_mul(FNV_PRIME);
    current.store(next, Ordering::Relaxed);
    next
}

fn record_host_op_log_entry(encoded: &[u8], entry_len: u32) {
    let entry_hash = fnv_hash(encoded);
    LAST_HOST_OP_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_HOST_OP_LEN.store(entry_len, Ordering::Relaxed);
    fold_log_hash(&HOST_OP_LOG_HASH, entry_hash, entry_len);
}

fn read_shadow_bytes(ptr: u32, len: u32) -> Result<&'static [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr == 0 {
        return Err(crate::abi::EFAULT as i32);
    }
    let start = ptr as usize;
    let len = len as usize;
    let end = start.checked_add(len).ok_or(crate::abi::EFAULT as i32)?;
    if end > isize::MAX as usize {
        return Err(crate::abi::EFAULT as i32);
    }
    Ok(unsafe { core::slice::from_raw_parts(start as *const u8, len) })
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn with_thread_exit_cleanup_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if THREAD_EXIT_CLEANUP_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    THREAD_EXIT_CLEANUP_LOCK.store(0, Ordering::Release);
    result
}

fn with_process_lifecycle_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if PROCESS_LIFECYCLE_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    PROCESS_LIFECYCLE_LOCK.store(0, Ordering::Release);
    result
}

fn with_fd_control_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if FD_CONTROL_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    FD_CONTROL_LOCK.store(0, Ordering::Release);
    result
}

fn with_fs_control_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if FS_CONTROL_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    FS_CONTROL_LOCK.store(0, Ordering::Release);
    result
}

fn with_signal_control_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if SIGNAL_CONTROL_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    SIGNAL_CONTROL_LOCK.store(0, Ordering::Release);
    result
}

pub fn enqueue_clone_spawn(parent_vm_ptr: u32) -> bool {
    host_op::enqueue_clone_spawn(parent_vm_ptr)
}

pub fn discard_clone_spawn(parent_vm_ptr: u32) -> bool {
    host_op::discard_clone_spawn(parent_vm_ptr)
}

pub fn enqueue_futex_wait_timer(vm: &crate::types::ThreadState) -> bool {
    timer::enqueue_futex_wait_timer(vm)
}

pub fn enqueue_sleep_timer(vm: &crate::types::ThreadState) -> bool {
    timer::enqueue_sleep_timer(vm)
}

pub fn enqueue_blocked_wait_timer(vm: &crate::types::ThreadState, status: i32) -> bool {
    timer::enqueue_blocked_wait_timer(vm, status)
}

fn fault_exit_priority(thread: &crate::types::ThreadState) -> u32 {
    if thread.fault_signal != 0 {
        return 4;
    }
    if thread.fault_kind != 0 {
        return 3;
    }
    if thread.fault_pc != 0 || thread.fault_addr != 0 {
        return 2;
    }
    if thread.term_signal != 0 {
        return 1;
    }
    0
}

fn select_fault_exit_decision(vm_ptr: u32) -> Result<SupervisorFaultExitDecision, i32> {
    let vm = thread::state_from_ptr(vm_ptr).ok_or(crate::abi::EFAULT as i32)?;
    if vm.process_ptr == 0 {
        return Err(crate::abi::EINVAL as i32);
    }
    let ps = unsafe {
        &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState)
    };
    let remaining_threads = ps.thread_count.load(Ordering::Acquire);
    let mut live_threads = 0u32;
    let mut selected_vm_ptr = vm_ptr;
    let mut selected = vm;
    let mut selected_priority = fault_exit_priority(vm);
    for record in ps.threads.iter() {
        if matches!(
            record.state,
            crate::types::THREAD_NONE | crate::types::THREAD_DEAD
        ) || record.thread_ptr == 0
        {
            continue;
        }
        let Some(thread) =
            state::validated_thread_from_record(record, vm.guest_base, vm.process_ptr)
        else {
            continue;
        };
        live_threads = live_threads.saturating_add(1);
        let priority = fault_exit_priority(thread);
        if priority > selected_priority {
            selected_priority = priority;
            selected_vm_ptr = record.thread_ptr;
            selected = thread;
        }
    }
    let kind = if remaining_threads == 0 || live_threads == 0 {
        SUPERVISOR_FAULT_EXIT_KIND_PROCESS_EXIT
    } else {
        SUPERVISOR_FAULT_EXIT_KIND_THREAD_EXIT
    };
    let exit_vm_ptr = if kind == SUPERVISOR_FAULT_EXIT_KIND_PROCESS_EXIT {
        selected_vm_ptr
    } else {
        vm_ptr
    };
    let exit_thread = if kind == SUPERVISOR_FAULT_EXIT_KIND_PROCESS_EXIT {
        selected
    } else {
        vm
    };
    let seq = FAULT_EXIT_DECISION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    Ok(SupervisorFaultExitDecision {
        kind,
        seq,
        vm_ptr,
        exit_vm_ptr,
        tid: exit_thread.tid as u32,
        process_ptr: vm.process_ptr,
        remaining_threads,
        live_threads,
        exit_code: exit_thread.exit_code,
        term_signal: exit_thread.term_signal,
        status: exit_thread.status as u32,
        fault_signal: exit_thread.fault_signal as u32,
        fault_kind: exit_thread.fault_kind,
        fault_pc: exit_thread.fault_pc,
        fault_addr: exit_thread.fault_addr,
    })
}

fn write_fault_exit_decision(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return SUPERVISOR_FAULT_EXIT_DECISION_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < SUPERVISOR_FAULT_EXIT_DECISION_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let decision = match select_fault_exit_decision(vm_ptr) {
        Ok(decision) => decision,
        Err(errno) => return errno,
    };
    let mut encoded = [0u8; SUPERVISOR_FAULT_EXIT_DECISION_BYTES as usize];
    write_u32(&mut encoded, 0, SUPERVISOR_FAULT_EXIT_DECISION_MAGIC);
    write_u32(&mut encoded, 4, SUPERVISOR_ABI_VERSION);
    write_u32(&mut encoded, 8, SUPERVISOR_FAULT_EXIT_DECISION_BYTES);
    write_u32(&mut encoded, 12, decision.kind);
    write_u64(&mut encoded, 16, decision.seq);
    write_u32(&mut encoded, 24, decision.vm_ptr);
    write_u32(&mut encoded, 28, decision.exit_vm_ptr);
    write_u32(&mut encoded, 32, decision.tid);
    write_u32(&mut encoded, 36, decision.process_ptr);
    write_u32(&mut encoded, 40, decision.remaining_threads);
    write_u32(&mut encoded, 44, decision.live_threads);
    write_u32(&mut encoded, 48, decision.exit_code as u32);
    write_u32(&mut encoded, 52, decision.term_signal as u32);
    write_u32(&mut encoded, 56, decision.status);
    write_u32(&mut encoded, 60, decision.fault_signal);
    write_u32(&mut encoded, 64, decision.fault_kind);
    write_u32(&mut encoded, 68, 0);
    write_u64(&mut encoded, 72, decision.fault_pc);
    write_u64(&mut encoded, 80, decision.fault_addr);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            SUPERVISOR_FAULT_EXIT_DECISION_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    SUPERVISOR_FAULT_EXIT_DECISION_BYTES as i32
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
    let record = SupervisorThreadExitCleanupRecord {
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
    with_thread_exit_cleanup_lock(|| unsafe {
        LAST_THREAD_EXIT_CLEANUP = record;
    });
}

fn write_thread_exit_cleanup_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = with_thread_exit_cleanup_lock(|| unsafe { LAST_THREAD_EXIT_CLEANUP });
    let mut encoded = [0u8; SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as usize];
    write_u32(&mut encoded, 0, SUPERVISOR_THREAD_EXIT_CLEANUP_MAGIC);
    write_u32(&mut encoded, 4, SUPERVISOR_ABI_VERSION);
    write_u32(&mut encoded, 8, SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES);
    write_u32(&mut encoded, 12, record.kind);
    write_u64(&mut encoded, 16, record.seq);
    write_u32(&mut encoded, 24, record.vm_ptr);
    write_u32(&mut encoded, 28, record.tid);
    write_u32(&mut encoded, 32, record.process_ptr);
    write_u32(&mut encoded, 36, record.status);
    write_u32(&mut encoded, 40, record.robust_marked);
    write_u32(&mut encoded, 44, record.robust_woken);
    write_u32(&mut encoded, 48, record.clear_child_tid_woken);
    write_u32(&mut encoded, 52, record.robust_order);
    write_u32(&mut encoded, 56, record.clear_child_tid_order);
    write_u32(&mut encoded, 60, 0);
    write_u64(&mut encoded, 64, record.clear_child_tid);
    write_u64(&mut encoded, 72, record.robust_head);
    write_u64(&mut encoded, 80, record.robust_pending);
    write_u64(&mut encoded, 88, record.first_robust_futex_addr);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as i32
}

#[allow(clippy::too_many_arguments)]
pub fn record_process_lifecycle(
    kind: u32,
    vm_ptr: u32,
    parent_pid: i32,
    child_pid: i32,
    wait_status: i32,
    wait_kind: u32,
    vm_status: u32,
    result: i64,
    wait_target: i64,
    options: u64,
    wstatus_addr: u64,
    rusage_addr: u64,
    detail: u64,
) {
    let seq = PROCESS_LIFECYCLE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = SupervisorProcessLifecycleRecord {
        kind,
        seq,
        vm_ptr,
        parent_pid: parent_pid as u32,
        child_pid: child_pid as u32,
        wait_status: wait_status as u32,
        wait_kind,
        vm_status,
        result,
        wait_target,
        options,
        wstatus_addr,
        rusage_addr,
        detail,
    };
    with_process_lifecycle_lock(|| unsafe {
        LAST_PROCESS_LIFECYCLE = record;
    });
}

fn write_process_lifecycle_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return SUPERVISOR_PROCESS_LIFECYCLE_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < SUPERVISOR_PROCESS_LIFECYCLE_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = with_process_lifecycle_lock(|| unsafe { LAST_PROCESS_LIFECYCLE });
    let mut encoded = [0u8; SUPERVISOR_PROCESS_LIFECYCLE_BYTES as usize];
    write_u32(&mut encoded, 0, SUPERVISOR_PROCESS_LIFECYCLE_MAGIC);
    write_u32(&mut encoded, 4, SUPERVISOR_ABI_VERSION);
    write_u32(&mut encoded, 8, SUPERVISOR_PROCESS_LIFECYCLE_BYTES);
    write_u32(&mut encoded, 12, record.kind);
    write_u64(&mut encoded, 16, record.seq);
    write_u32(&mut encoded, 24, record.vm_ptr);
    write_u32(&mut encoded, 28, record.parent_pid);
    write_u32(&mut encoded, 32, record.child_pid);
    write_u32(&mut encoded, 36, record.wait_status);
    write_u32(&mut encoded, 40, record.wait_kind);
    write_u32(&mut encoded, 44, record.vm_status);
    write_u64(&mut encoded, 48, record.result as u64);
    write_u64(&mut encoded, 56, record.wait_target as u64);
    write_u64(&mut encoded, 64, record.options);
    write_u64(&mut encoded, 72, record.wstatus_addr);
    write_u64(&mut encoded, 80, record.rusage_addr);
    write_u64(&mut encoded, 88, record.detail);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            SUPERVISOR_PROCESS_LIFECYCLE_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    SUPERVISOR_PROCESS_LIFECYCLE_BYTES as i32
}

#[allow(clippy::too_many_arguments)]
pub fn record_fd_control(
    kind: u32,
    vm_ptr: u32,
    process_ptr: u32,
    pid: i32,
    fd: u32,
    fd2: u32,
    ofd_id: u32,
    ofd2_id: u32,
    fd_type: u32,
    resource_slot: u32,
    resource_generation: u32,
    result: i64,
    flags: u64,
    detail0: u64,
    detail1: u64,
) {
    let seq = FD_CONTROL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = SupervisorFdControlRecord {
        kind,
        seq,
        vm_ptr,
        process_ptr,
        pid: pid as u32,
        fd,
        fd2,
        ofd_id,
        ofd2_id,
        fd_type,
        resource_slot,
        resource_generation,
        result,
        flags,
        detail0,
        detail1,
    };
    with_fd_control_lock(|| unsafe {
        LAST_FD_CONTROL = record;
    });
}

#[allow(clippy::too_many_arguments)]
pub fn record_fs_control(
    kind: u32,
    vm_ptr: u32,
    process_ptr: u32,
    pid: i32,
    fd: u32,
    ino: u32,
    opcode: u32,
    file_object_id: u64,
    page_index: u64,
    offset: u64,
    length: u64,
    result: i64,
    flags: u64,
    detail0: u64,
    detail1: u64,
) {
    let seq = FS_CONTROL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = SupervisorFsControlRecord {
        kind,
        seq,
        vm_ptr,
        process_ptr,
        pid: pid as u32,
        fd,
        ino,
        opcode,
        file_object_id,
        page_index,
        offset,
        length,
        result,
        flags,
        detail0,
        detail1,
    };
    with_fs_control_lock(|| unsafe {
        LAST_FS_CONTROL = record;
    });
}

fn first_signal_from_bits(bits: u64) -> u32 {
    if bits == 0 {
        0
    } else {
        bits.trailing_zeros() + 1
    }
}

#[allow(clippy::too_many_arguments)]
pub fn record_signal_control(
    kind: u32,
    vm: &crate::types::ThreadState,
    base: u32,
    sig: u32,
    boundary: u32,
    thread_pending: u64,
    process_pending: u64,
    record_pending: u64,
    deliverable: u64,
    detail0: u64,
    detail1: u64,
) {
    let seq = SIGNAL_CONTROL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = SupervisorSignalControlRecord {
        kind,
        seq,
        vm_ptr: vm as *const crate::types::ThreadState as u32,
        process_ptr: vm.process_ptr,
        pid: crate::syscall::signal::pid_from_vm(vm, base) as u32,
        tid: vm.tid as u32,
        sig,
        status: vm.status as u32,
        sig_info_code: vm.sig_info_code,
        boundary,
        thread_pending,
        process_pending,
        record_pending,
        deliverable,
        mask: vm.sig_mask,
        pc: vm.pc,
        detail0,
        detail1,
    };
    with_signal_control_lock(|| unsafe {
        LAST_SIGNAL_CONTROL = record;
    });
}

fn write_fd_control_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return SUPERVISOR_FD_CONTROL_RECORD_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < SUPERVISOR_FD_CONTROL_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = with_fd_control_lock(|| unsafe { LAST_FD_CONTROL });
    let mut encoded = [0u8; SUPERVISOR_FD_CONTROL_RECORD_BYTES as usize];
    write_u32(&mut encoded, 0, SUPERVISOR_FD_CONTROL_RECORD_MAGIC);
    write_u32(&mut encoded, 4, SUPERVISOR_ABI_VERSION);
    write_u32(&mut encoded, 8, SUPERVISOR_FD_CONTROL_RECORD_BYTES);
    write_u32(&mut encoded, 12, record.kind);
    write_u64(&mut encoded, 16, record.seq);
    write_u32(&mut encoded, 24, record.vm_ptr);
    write_u32(&mut encoded, 28, record.process_ptr);
    write_u32(&mut encoded, 32, record.pid);
    write_u32(&mut encoded, 36, record.fd);
    write_u32(&mut encoded, 40, record.fd2);
    write_u32(&mut encoded, 44, record.ofd_id);
    write_u32(&mut encoded, 48, record.ofd2_id);
    write_u32(&mut encoded, 52, record.fd_type);
    write_u32(&mut encoded, 56, record.resource_slot);
    write_u32(&mut encoded, 60, record.resource_generation);
    write_u64(&mut encoded, 64, record.result as u64);
    write_u64(&mut encoded, 72, record.flags);
    write_u64(&mut encoded, 80, record.detail0);
    write_u64(&mut encoded, 88, record.detail1);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            SUPERVISOR_FD_CONTROL_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    SUPERVISOR_FD_CONTROL_RECORD_BYTES as i32
}

fn write_fs_control_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return SUPERVISOR_FS_CONTROL_RECORD_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < SUPERVISOR_FS_CONTROL_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = with_fs_control_lock(|| unsafe { LAST_FS_CONTROL });
    let mut encoded = [0u8; SUPERVISOR_FS_CONTROL_RECORD_BYTES as usize];
    write_u32(&mut encoded, 0, SUPERVISOR_FS_CONTROL_RECORD_MAGIC);
    write_u32(&mut encoded, 4, SUPERVISOR_ABI_VERSION);
    write_u32(&mut encoded, 8, SUPERVISOR_FS_CONTROL_RECORD_BYTES);
    write_u32(&mut encoded, 12, record.kind);
    write_u64(&mut encoded, 16, record.seq);
    write_u32(&mut encoded, 24, record.vm_ptr);
    write_u32(&mut encoded, 28, record.process_ptr);
    write_u32(&mut encoded, 32, record.pid);
    write_u32(&mut encoded, 36, record.fd);
    write_u32(&mut encoded, 40, record.ino);
    write_u32(&mut encoded, 44, record.opcode);
    write_u64(&mut encoded, 48, record.file_object_id);
    write_u64(&mut encoded, 56, record.page_index);
    write_u64(&mut encoded, 64, record.offset);
    write_u64(&mut encoded, 72, record.length);
    write_u64(&mut encoded, 80, record.result as u64);
    write_u64(&mut encoded, 88, record.flags);
    write_u64(&mut encoded, 96, record.detail0);
    write_u64(&mut encoded, 104, record.detail1);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            SUPERVISOR_FS_CONTROL_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    SUPERVISOR_FS_CONTROL_RECORD_BYTES as i32
}

fn write_signal_control_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = with_signal_control_lock(|| unsafe { LAST_SIGNAL_CONTROL });
    let mut encoded = [0u8; SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES as usize];
    write_u32(&mut encoded, 0, SUPERVISOR_SIGNAL_CONTROL_RECORD_MAGIC);
    write_u32(&mut encoded, 4, SUPERVISOR_ABI_VERSION);
    write_u32(&mut encoded, 8, SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES);
    write_u32(&mut encoded, 12, record.kind);
    write_u64(&mut encoded, 16, record.seq);
    write_u32(&mut encoded, 24, record.vm_ptr);
    write_u32(&mut encoded, 28, record.process_ptr);
    write_u32(&mut encoded, 32, record.pid);
    write_u32(&mut encoded, 36, record.tid);
    write_u32(&mut encoded, 40, record.sig);
    write_u32(&mut encoded, 44, record.status);
    write_u32(&mut encoded, 48, record.sig_info_code as u32);
    write_u32(&mut encoded, 52, record.boundary);
    write_u64(&mut encoded, 56, record.thread_pending);
    write_u64(&mut encoded, 64, record.process_pending);
    write_u64(&mut encoded, 72, record.record_pending);
    write_u64(&mut encoded, 80, record.deliverable);
    write_u64(&mut encoded, 88, record.mask);
    write_u64(&mut encoded, 96, record.pc);
    write_u64(&mut encoded, 104, record.detail0);
    write_u64(&mut encoded, 112, record.detail1);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES as i32
}

fn write_snapshot(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return SUPERVISOR_DEBUG_SNAPSHOT_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < SUPERVISOR_DEBUG_SNAPSHOT_BYTES {
        return crate::abi::ENOSPC as i32;
    }

    let mut snapshot = [0u8; SUPERVISOR_DEBUG_SNAPSHOT_BYTES as usize];
    write_u32(&mut snapshot, 0, SNAPSHOT_MAGIC);
    write_u32(&mut snapshot, 4, SUPERVISOR_ABI_VERSION);
    write_u32(&mut snapshot, 8, SUPERVISOR_DEBUG_SNAPSHOT_BYTES);
    write_u32(&mut snapshot, 12, 0);
    write_u64(&mut snapshot, 16, thread_event_count());
    write_u64(&mut snapshot, 24, host_completion_count());
    write_u64(&mut snapshot, 32, host_op_poll_count());
    write_u64(&mut snapshot, 40, resume_poll_count());
    write_u64(&mut snapshot, 48, thread_event_log_hash());
    write_u64(&mut snapshot, 56, host_completion_log_hash());
    write_u32(
        &mut snapshot,
        64,
        LAST_THREAD_EVENT_LEN.load(Ordering::Relaxed),
    );
    write_u32(
        &mut snapshot,
        68,
        LAST_HOST_COMPLETION_LEN.load(Ordering::Relaxed),
    );
    write_u64(
        &mut snapshot,
        72,
        LAST_THREAD_EVENT_HASH.load(Ordering::Relaxed),
    );
    write_u64(
        &mut snapshot,
        80,
        LAST_HOST_COMPLETION_HASH.load(Ordering::Relaxed),
    );
    write_u64(&mut snapshot, 88, host_op_log_hash());
    write_u64(&mut snapshot, 96, LAST_HOST_OP_HASH.load(Ordering::Relaxed));
    write_u32(&mut snapshot, 104, LAST_HOST_OP_LEN.load(Ordering::Relaxed));
    write_u32(&mut snapshot, 108, 0);

    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            SUPERVISOR_DEBUG_SNAPSHOT_BYTES as usize,
        )
    };
    out.copy_from_slice(&snapshot);
    SUPERVISOR_DEBUG_SNAPSHOT_BYTES as i32
}

pub fn enqueue_futex_resume(process_ptr: u32, vm_ptr: u32, tid: i32, futex_addr: u64) -> bool {
    futex::enqueue_resume(process_ptr, vm_ptr, tid, futex_addr)
}
