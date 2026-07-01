//! Additive supervisor shadow protocol.
//!
//! Phase A records deterministic shadows of runtime decisions without changing
//! guest-visible behavior. Later phases can replace these no-op decisions with
//! supervisor-owned policy.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

mod event;
mod futex;
mod host_op;
mod resume;
mod runnable;
mod state;

pub const SUPERVISOR_ABI_VERSION: u32 = 1;
pub const SUPERVISOR_DEBUG_SNAPSHOT_BYTES: u32 = 112;
pub const SUPERVISOR_THREAD_EVENT_RECORD_BYTES: u32 = 80;
pub const SUPERVISOR_THREAD_EVENT_RECORD_MAGIC: u32 = 0x5645_5354; // "TSEV" little-endian.
pub const SUPERVISOR_THREAD_EVENT_KIND_BLOCKED: u32 = 1;
pub const SUPERVISOR_THREAD_EVENT_KIND_READY: u32 = 2;
pub const SUPERVISOR_THREAD_EVENT_KIND_FAULTED: u32 = 3;
pub const SUPERVISOR_THREAD_EVENT_KIND_EXITED: u32 = 4;
pub const SUPERVISOR_THREAD_EVENT_KIND_HOST_COMPLETION_ARRIVED: u32 = 5;
pub const SUPERVISOR_THREAD_EVENT_KIND_TIMER_FIRED: u32 = 6;
pub const SUPERVISOR_THREAD_EVENT_KIND_NETWORK_READABLE: u32 = 7;
pub const SUPERVISOR_THREAD_EVENT_KIND_BACKING_STORE_READY: u32 = 8;
pub const SUPERVISOR_THREAD_STATE_HEADER_BYTES: usize = 32;
pub const SUPERVISOR_THREAD_STATE_RECORD_BYTES: usize = 32;
pub const SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES: u32 = (SUPERVISOR_THREAD_STATE_HEADER_BYTES
    + crate::abi::MAX_THREADS * SUPERVISOR_THREAD_STATE_RECORD_BYTES)
    as u32;
pub const SUPERVISOR_THREAD_STATE_SNAPSHOT_MAGIC: u32 = 0x4854_5354; // "TSTH" little-endian.
pub const SUPERVISOR_RESUME_RECORD_BYTES: u32 = 48;
pub const SUPERVISOR_RESUME_RECORD_MAGIC: u32 = 0x5255_5354; // "TSUR" little-endian.
pub const SUPERVISOR_RESUME_KIND_FUTEX_WAKE: u32 = 1;
pub const SUPERVISOR_HOST_COMPLETION_RECORD_BYTES: u32 = 64;
pub const SUPERVISOR_HOST_COMPLETION_RECORD_MAGIC: u32 = 0x4348_5354; // "TSHC" little-endian.
pub const SUPERVISOR_HOST_COMPLETION_OUTCOME_SUCCESS: u32 = 1;
pub const SUPERVISOR_HOST_COMPLETION_OUTCOME_FAILURE: u32 = 2;
pub const SUPERVISOR_HOST_OP_RECORD_BYTES: u32 = 64;
pub const SUPERVISOR_HOST_OP_RECORD_MAGIC: u32 = 0x4f48_5354; // "TSHO" little-endian.
pub const SUPERVISOR_HOST_OP_KIND_SPAWN_THREAD_WORKER: u32 = 1;
pub const SUPERVISOR_HOST_OP_KIND_SPAWN_PROCESS_WORKER: u32 = 2;
pub const SUPERVISOR_HOST_OP_KIND_CREATE_PROCESS_MEMORY: u32 = 3;
pub const SUPERVISOR_HOST_OP_KIND_COPY_MEMORY_RANGES: u32 = 4;
pub const SUPERVISOR_HOST_OP_KIND_FILL_PAGE_FROM_BACKING: u32 = 5;
pub const SUPERVISOR_HOST_OP_KIND_FLUSH_DIRTY_PAGE: u32 = 6;
pub const SUPERVISOR_HOST_OP_KIND_PROCESS_FS_REQUEST: u32 = 7;
pub const SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_CONNECT: u32 = 8;
pub const SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_READ: u32 = 9;
pub const SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_WRITE: u32 = 10;
pub const SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_CLOSE: u32 = 11;
pub const SUPERVISOR_HOST_OP_KIND_ARM_HOST_TIMER: u32 = 12;
pub const SUPERVISOR_HOST_OP_KIND_RESUME_THREAD: u32 = 13;
pub const SUPERVISOR_HOST_OP_KIND_TERMINATE_WORKER: u32 = 14;
pub const SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES: u32 = 96;
pub const SUPERVISOR_PROCESS_HOST_OP_RECORD_MAGIC: u32 = 0x4850_5354; // "TSPH" little-endian.
pub const SUPERVISOR_PROCESS_HOST_OP_KIND_SPAWN_PROCESS_WORKER: u32 = 1;
pub const SUPERVISOR_FAULT_EXIT_DECISION_BYTES: u32 = 88;
pub const SUPERVISOR_FAULT_EXIT_DECISION_MAGIC: u32 = 0x5846_5354; // "TSFX" little-endian.
pub const SUPERVISOR_FAULT_EXIT_KIND_THREAD_EXIT: u32 = 1;
pub const SUPERVISOR_FAULT_EXIT_KIND_PROCESS_EXIT: u32 = 2;
pub const SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES: u32 = 96;
pub const SUPERVISOR_THREAD_EXIT_CLEANUP_MAGIC: u32 = 0x4358_5354; // "TSXC" little-endian.
pub const SUPERVISOR_THREAD_EXIT_CLEANUP_KIND_THREAD_EXIT: u32 = 1;
pub const SUPERVISOR_PROCESS_LIFECYCLE_BYTES: u32 = 96;
pub const SUPERVISOR_PROCESS_LIFECYCLE_MAGIC: u32 = 0x4350_5354; // "TSPC" little-endian.
pub const SUPERVISOR_PROCESS_LIFECYCLE_KIND_CHILD_EXIT_PUBLISHED: u32 = 1;
pub const SUPERVISOR_PROCESS_LIFECYCLE_KIND_WAIT4_COMPLETED: u32 = 2;
pub const SUPERVISOR_FD_CONTROL_RECORD_BYTES: u32 = 96;
pub const SUPERVISOR_FD_CONTROL_RECORD_MAGIC: u32 = 0x4446_5354; // "TSFD" little-endian.
pub const SUPERVISOR_FD_CONTROL_KIND_PIPE_CREATED: u32 = 1;
pub const SUPERVISOR_FD_CONTROL_KIND_FD_CLOSED: u32 = 2;
pub const SUPERVISOR_FD_CONTROL_KIND_FD_DUPLICATED: u32 = 3;
pub const SUPERVISOR_FD_CONTROL_KIND_FD_FLAGS_UPDATED: u32 = 4;
pub const SUPERVISOR_FD_CONTROL_KIND_EPOLL_CREATED: u32 = 5;
pub const SUPERVISOR_FD_CONTROL_KIND_EPOLL_CTL_ADD: u32 = 6;
pub const SUPERVISOR_FD_CONTROL_KIND_EPOLL_CTL_DEL: u32 = 7;
pub const SUPERVISOR_FD_CONTROL_KIND_EPOLL_CTL_MOD: u32 = 8;
pub const SUPERVISOR_FD_CONTROL_KIND_SOCKET_CREATED: u32 = 9;
pub const SUPERVISOR_FD_CONTROL_KIND_SOCKETPAIR_CREATED: u32 = 10;
pub const SUPERVISOR_FD_CONTROL_KIND_SOCKET_BOUND: u32 = 11;
pub const SUPERVISOR_FD_CONTROL_KIND_SOCKET_LISTENING: u32 = 12;
pub const SUPERVISOR_FD_CONTROL_KIND_SOCKET_CONNECT_STARTED: u32 = 13;
pub const SUPERVISOR_FD_CONTROL_KIND_SOCKET_CONNECTED: u32 = 14;
pub const SUPERVISOR_FD_CONTROL_KIND_SOCKET_CONNECT_FAILED: u32 = 15;
pub const SUPERVISOR_FD_CONTROL_KIND_SOCKET_ACCEPTED: u32 = 16;
pub const SUPERVISOR_FS_CONTROL_RECORD_BYTES: u32 = 112;
pub const SUPERVISOR_FS_CONTROL_RECORD_MAGIC: u32 = 0x5346_5354; // "TSFS" little-endian.
pub const SUPERVISOR_FS_CONTROL_KIND_PAGE_CACHE_MISS: u32 = 1;
pub const SUPERVISOR_FS_CONTROL_KIND_PAGE_CACHE_FILL: u32 = 2;
pub const SUPERVISOR_FS_CONTROL_KIND_DIRTY_PAGE_PUBLISHED: u32 = 3;
pub const SUPERVISOR_FS_CONTROL_KIND_DIRTY_PAGE_FLUSHED: u32 = 4;
pub const SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES: u32 = 120;
pub const SUPERVISOR_SIGNAL_CONTROL_RECORD_MAGIC: u32 = 0x4753_5354; // "TSSG" little-endian.
pub const SUPERVISOR_SIGNAL_CONTROL_KIND_BOUNDARY_CHECK: u32 = 1;
pub const SUPERVISOR_SIGNAL_CONTROL_KIND_SIGNAL_DELIVERED: u32 = 2;
pub const SUPERVISOR_SIGNAL_CONTROL_KIND_BLOCKED_WAIT_INTERRUPTED: u32 = 3;
pub const SUPERVISOR_SIGNAL_BOUNDARY_SYSCALL_RETURN: u32 = 1;
pub const SUPERVISOR_SIGNAL_BOUNDARY_BLOCKED_WAIT: u32 = 2;
pub const SUPERVISOR_RUNNABLE_SELECTION_BYTES: u32 = 48;
pub const SUPERVISOR_RUNNABLE_SELECTION_MAGIC: u32 = 0x4e52_5354; // "TSRN" little-endian.
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_WOKEN: u32 = 1;
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_NOT_EQUAL: u32 = 2;
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT: u32 = 3;
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_INVALID_ADDRESS: u32 = 4;
pub const SUPERVISOR_FUTEX_WAIT_COMPLETION_SIGNAL_CHECK: u32 = 5;

const SNAPSHOT_MAGIC: u32 = 0x5055_5354; // "TSUP" little-endian.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const RESUME_QUEUE_CAP: usize = 256;
const HOST_OP_QUEUE_CAP: usize = 256;
const RESUME_QUEUE_EMPTY: SupervisorResumeRecord = SupervisorResumeRecord {
    kind: 0,
    seq: 0,
    vm_ptr: 0,
    tid: 0,
    process_ptr: 0,
    status: 0,
    detail0: 0,
};
const HOST_OP_QUEUE_EMPTY: SupervisorHostOpRequest = SupervisorHostOpRequest {
    kind: 0,
    parent_vm_ptr: 0,
    child_vm_ptr: 0,
    tid: 0,
    process_ptr: 0,
    status: 0,
    detail0: 0,
    detail1: 0,
};

static THREAD_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static HOST_COMPLETION_COUNT: AtomicU64 = AtomicU64::new(0);
static HOST_OP_POLL_COUNT: AtomicU64 = AtomicU64::new(0);
static HOST_OP_EMIT_COUNT: AtomicU64 = AtomicU64::new(0);
static HOST_OP_OVERFLOW_COUNT: AtomicU64 = AtomicU64::new(0);
static FAULT_EXIT_DECISION_COUNT: AtomicU64 = AtomicU64::new(0);
static THREAD_EXIT_CLEANUP_COUNT: AtomicU64 = AtomicU64::new(0);
static PROCESS_LIFECYCLE_COUNT: AtomicU64 = AtomicU64::new(0);
static FD_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static FS_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static SIGNAL_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static RESUME_POLL_COUNT: AtomicU64 = AtomicU64::new(0);
static RESUME_ENQUEUE_COUNT: AtomicU64 = AtomicU64::new(0);
static RESUME_OVERFLOW_COUNT: AtomicU64 = AtomicU64::new(0);
static RUNNABLE_SELECTION_COUNT: AtomicU64 = AtomicU64::new(0);
static RUNNABLE_SELECTION_CURSOR: AtomicU32 = AtomicU32::new(0);
static THREAD_EVENT_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static HOST_COMPLETION_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static HOST_OP_LOG_HASH: AtomicU64 = AtomicU64::new(FNV_OFFSET);
static LAST_THREAD_EVENT_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_HOST_COMPLETION_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_HOST_OP_HASH: AtomicU64 = AtomicU64::new(0);
static LAST_THREAD_EVENT_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_HOST_COMPLETION_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_HOST_OP_LEN: AtomicU32 = AtomicU32::new(0);
static RESUME_QUEUE_LOCK: AtomicU32 = AtomicU32::new(0);
static RESUME_QUEUE_HEAD: AtomicU32 = AtomicU32::new(0);
static RESUME_QUEUE_TAIL: AtomicU32 = AtomicU32::new(0);
static mut RESUME_QUEUE: [SupervisorResumeRecord; RESUME_QUEUE_CAP] =
    [RESUME_QUEUE_EMPTY; RESUME_QUEUE_CAP];
static HOST_OP_QUEUE_LOCK: AtomicU32 = AtomicU32::new(0);
static HOST_OP_QUEUE_HEAD: AtomicU32 = AtomicU32::new(0);
static HOST_OP_QUEUE_TAIL: AtomicU32 = AtomicU32::new(0);
static mut HOST_OP_QUEUE: [SupervisorHostOpRequest; HOST_OP_QUEUE_CAP] =
    [HOST_OP_QUEUE_EMPTY; HOST_OP_QUEUE_CAP];
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

#[derive(Clone, Copy)]
struct SupervisorResumeRecord {
    kind: u32,
    seq: u64,
    vm_ptr: u32,
    tid: u32,
    process_ptr: u32,
    status: u32,
    detail0: u64,
}

#[derive(Clone, Copy)]
struct SupervisorHostOpRequest {
    kind: u32,
    parent_vm_ptr: u32,
    child_vm_ptr: u32,
    tid: u32,
    process_ptr: u32,
    status: u32,
    detail0: u64,
    detail1: u64,
}

#[derive(Clone, Copy)]
struct SupervisorHostOpRecord {
    kind: u32,
    seq: u64,
    parent_vm_ptr: u32,
    child_vm_ptr: u32,
    tid: u32,
    process_ptr: u32,
    status: u32,
    flags: u64,
    child_tidptr: u64,
}

#[derive(Clone, Copy)]
struct SupervisorProcessHostOpRecord {
    kind: u32,
    seq: u64,
    log_emission: bool,
    parent_vm_ptr: u32,
    spawn_kind: u32,
    child_pid: i32,
    process_ptr: u32,
    status: u32,
    address_profile: u32,
    guest_memory_policy_limit: u64,
    process_max_memory_pages: u32,
    path: u64,
    argv: u64,
    envp: u64,
}

#[derive(Clone, Copy)]
struct SupervisorFaultExitDecision {
    kind: u32,
    seq: u64,
    vm_ptr: u32,
    exit_vm_ptr: u32,
    tid: u32,
    process_ptr: u32,
    remaining_threads: u32,
    live_threads: u32,
    exit_code: i32,
    term_signal: i32,
    status: u32,
    fault_signal: u32,
    fault_kind: u32,
    fault_pc: u64,
    fault_addr: u64,
}

#[derive(Clone, Copy)]
pub struct SupervisorThreadExitCleanupRecord {
    kind: u32,
    seq: u64,
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
}

impl SupervisorThreadExitCleanupRecord {
    const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            tid: 0,
            process_ptr: 0,
            status: 0,
            robust_marked: 0,
            robust_woken: 0,
            clear_child_tid_woken: 0,
            robust_order: 0,
            clear_child_tid_order: 0,
            clear_child_tid: 0,
            robust_head: 0,
            robust_pending: 0,
            first_robust_futex_addr: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SupervisorProcessLifecycleRecord {
    kind: u32,
    seq: u64,
    vm_ptr: u32,
    parent_pid: u32,
    child_pid: u32,
    wait_status: u32,
    wait_kind: u32,
    vm_status: u32,
    result: i64,
    wait_target: i64,
    options: u64,
    wstatus_addr: u64,
    rusage_addr: u64,
    detail: u64,
}

impl SupervisorProcessLifecycleRecord {
    const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            parent_pid: 0,
            child_pid: 0,
            wait_status: 0,
            wait_kind: 0,
            vm_status: 0,
            result: 0,
            wait_target: 0,
            options: 0,
            wstatus_addr: 0,
            rusage_addr: 0,
            detail: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SupervisorFdControlRecord {
    kind: u32,
    seq: u64,
    vm_ptr: u32,
    process_ptr: u32,
    pid: u32,
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
}

impl SupervisorFdControlRecord {
    const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            process_ptr: 0,
            pid: 0,
            fd: 0,
            fd2: 0,
            ofd_id: 0,
            ofd2_id: 0,
            fd_type: 0,
            resource_slot: 0,
            resource_generation: 0,
            result: 0,
            flags: 0,
            detail0: 0,
            detail1: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SupervisorFsControlRecord {
    kind: u32,
    seq: u64,
    vm_ptr: u32,
    process_ptr: u32,
    pid: u32,
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
}

impl SupervisorFsControlRecord {
    const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            process_ptr: 0,
            pid: 0,
            fd: 0,
            ino: 0,
            opcode: 0,
            file_object_id: 0,
            page_index: 0,
            offset: 0,
            length: 0,
            result: 0,
            flags: 0,
            detail0: 0,
            detail1: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SupervisorSignalControlRecord {
    kind: u32,
    seq: u64,
    vm_ptr: u32,
    process_ptr: u32,
    pid: u32,
    tid: u32,
    sig: u32,
    status: u32,
    sig_info_code: i32,
    boundary: u32,
    thread_pending: u64,
    process_pending: u64,
    record_pending: u64,
    deliverable: u64,
    mask: u64,
    pc: u64,
    detail0: u64,
    detail1: u64,
}

impl SupervisorSignalControlRecord {
    const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            process_ptr: 0,
            pid: 0,
            tid: 0,
            sig: 0,
            status: 0,
            sig_info_code: 0,
            boundary: 0,
            thread_pending: 0,
            process_pending: 0,
            record_pending: 0,
            deliverable: 0,
            mask: 0,
            pc: 0,
            detail0: 0,
            detail1: 0,
        }
    }
}

pub fn init() {
    THREAD_EVENT_COUNT.store(0, Ordering::Relaxed);
    HOST_COMPLETION_COUNT.store(0, Ordering::Relaxed);
    HOST_OP_POLL_COUNT.store(0, Ordering::Relaxed);
    HOST_OP_EMIT_COUNT.store(0, Ordering::Relaxed);
    HOST_OP_OVERFLOW_COUNT.store(0, Ordering::Relaxed);
    FAULT_EXIT_DECISION_COUNT.store(0, Ordering::Relaxed);
    THREAD_EXIT_CLEANUP_COUNT.store(0, Ordering::Relaxed);
    PROCESS_LIFECYCLE_COUNT.store(0, Ordering::Relaxed);
    FD_CONTROL_COUNT.store(0, Ordering::Relaxed);
    FS_CONTROL_COUNT.store(0, Ordering::Relaxed);
    SIGNAL_CONTROL_COUNT.store(0, Ordering::Relaxed);
    RESUME_POLL_COUNT.store(0, Ordering::Relaxed);
    RESUME_ENQUEUE_COUNT.store(0, Ordering::Relaxed);
    RESUME_OVERFLOW_COUNT.store(0, Ordering::Relaxed);
    RUNNABLE_SELECTION_COUNT.store(0, Ordering::Relaxed);
    RUNNABLE_SELECTION_CURSOR.store(0, Ordering::Relaxed);
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
    resume::init_queue();
    host_op::init_queue();
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
    HOST_OP_POLL_COUNT.load(Ordering::Relaxed)
}

pub fn host_op_emit_count() -> u64 {
    HOST_OP_EMIT_COUNT.load(Ordering::Relaxed)
}

pub fn host_op_overflow_count() -> u64 {
    HOST_OP_OVERFLOW_COUNT.load(Ordering::Relaxed)
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
    RESUME_POLL_COUNT.load(Ordering::Relaxed)
}

pub fn resume_enqueue_count() -> u64 {
    RESUME_ENQUEUE_COUNT.load(Ordering::Relaxed)
}

pub fn resume_overflow_count() -> u64 {
    RESUME_OVERFLOW_COUNT.load(Ordering::Relaxed)
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
    host_op::enqueue_futex_wait_timer(vm)
}

fn candidate_list_contains(candidates: &[u8], vm_ptr: u32) -> bool {
    for entry in candidates.chunks_exact(4) {
        let candidate = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        if candidate == vm_ptr {
            return true;
        }
    }
    false
}

fn thread_state_from_ptr(vm_ptr: u32) -> Option<&'static crate::types::ThreadState> {
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

fn thread_state_mut_from_ptr(vm_ptr: u32) -> Option<&'static mut crate::types::ThreadState> {
    if vm_ptr == 0 {
        return None;
    }
    let absolute = vm_ptr as usize;
    if absolute < core::mem::size_of::<crate::types::ThreadState>() {
        return None;
    }
    Some(unsafe { &mut *(absolute as *mut crate::types::ThreadState) })
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
    let vm = thread_state_from_ptr(vm_ptr).ok_or(crate::abi::EFAULT as i32)?;
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

fn thread_status_from_record(
    record: &crate::types::ThreadRecord,
    base: u32,
    process_ptr: u32,
) -> u32 {
    state::validated_thread_status_from_record(record, base, process_ptr).unwrap_or(0)
}

fn write_thread_state_snapshot(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as i32;
    }
    if vm_ptr == 0 || out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if vm.process_ptr == 0 {
        return crate::abi::EINVAL as i32;
    }
    let ps = unsafe {
        &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState)
    };
    let mut snapshot = [0u8; SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as usize];
    write_u32(&mut snapshot, 0, SUPERVISOR_THREAD_STATE_SNAPSHOT_MAGIC);
    write_u32(&mut snapshot, 4, SUPERVISOR_ABI_VERSION);
    write_u32(&mut snapshot, 8, SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES);
    write_u32(&mut snapshot, 12, crate::abi::MAX_THREADS as u32);
    write_u32(&mut snapshot, 16, vm.process_ptr);
    write_u32(&mut snapshot, 20, vm_ptr);
    write_u32(
        &mut snapshot,
        24,
        SUPERVISOR_THREAD_STATE_RECORD_BYTES as u32,
    );
    write_u32(&mut snapshot, 28, 0);
    for slot in 0..crate::abi::MAX_THREADS {
        let record = ps.threads[slot];
        let offset =
            SUPERVISOR_THREAD_STATE_HEADER_BYTES + slot * SUPERVISOR_THREAD_STATE_RECORD_BYTES;
        write_u32(&mut snapshot, offset, record.tid as u32);
        write_u32(&mut snapshot, offset + 4, record.state as u32);
        write_u32(&mut snapshot, offset + 8, record.thread_ptr);
        write_u32(
            &mut snapshot,
            offset + 12,
            thread_status_from_record(&record, vm.guest_base, vm.process_ptr),
        );
        write_u64(&mut snapshot, offset + 16, record.blocked_addr);
        write_u64(&mut snapshot, offset + 24, record.pending_sigset);
    }
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as usize,
        )
    };
    out.copy_from_slice(&snapshot);
    SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as i32
}

pub fn enqueue_futex_resume(process_ptr: u32, vm_ptr: u32, tid: i32, futex_addr: u64) -> bool {
    futex::enqueue_resume(process_ptr, vm_ptr, tid, futex_addr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_abi_version() -> u32 {
    SUPERVISOR_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_debug_snapshot_bytes() -> u32 {
    SUPERVISOR_DEBUG_SNAPSHOT_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_event_record_bytes() -> u32 {
    SUPERVISOR_THREAD_EVENT_RECORD_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_event_kind_blocked() -> u32 {
    SUPERVISOR_THREAD_EVENT_KIND_BLOCKED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_event_kind_ready() -> u32 {
    SUPERVISOR_THREAD_EVENT_KIND_READY
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_event_kind_faulted() -> u32 {
    SUPERVISOR_THREAD_EVENT_KIND_FAULTED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_event_kind_exited() -> u32 {
    SUPERVISOR_THREAD_EVENT_KIND_EXITED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_event_kind_host_completion_arrived() -> u32 {
    SUPERVISOR_THREAD_EVENT_KIND_HOST_COMPLETION_ARRIVED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_event_kind_timer_fired() -> u32 {
    SUPERVISOR_THREAD_EVENT_KIND_TIMER_FIRED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_event_kind_network_readable() -> u32 {
    SUPERVISOR_THREAD_EVENT_KIND_NETWORK_READABLE
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_event_kind_backing_store_ready() -> u32 {
    SUPERVISOR_THREAD_EVENT_KIND_BACKING_STORE_READY
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_state_snapshot_bytes() -> u32 {
    SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_resume_record_bytes() -> u32 {
    SUPERVISOR_RESUME_RECORD_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_completion_record_bytes() -> u32 {
    SUPERVISOR_HOST_COMPLETION_RECORD_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_completion_outcome_success() -> u32 {
    SUPERVISOR_HOST_COMPLETION_OUTCOME_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_completion_outcome_failure() -> u32 {
    SUPERVISOR_HOST_COMPLETION_OUTCOME_FAILURE
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_record_bytes() -> u32 {
    SUPERVISOR_HOST_OP_RECORD_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_spawn_thread_worker() -> u32 {
    SUPERVISOR_HOST_OP_KIND_SPAWN_THREAD_WORKER
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_spawn_process_worker() -> u32 {
    SUPERVISOR_HOST_OP_KIND_SPAWN_PROCESS_WORKER
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_create_process_memory() -> u32 {
    SUPERVISOR_HOST_OP_KIND_CREATE_PROCESS_MEMORY
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_copy_memory_ranges() -> u32 {
    SUPERVISOR_HOST_OP_KIND_COPY_MEMORY_RANGES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_fill_page_from_backing() -> u32 {
    SUPERVISOR_HOST_OP_KIND_FILL_PAGE_FROM_BACKING
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_flush_dirty_page() -> u32 {
    SUPERVISOR_HOST_OP_KIND_FLUSH_DIRTY_PAGE
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_process_fs_request() -> u32 {
    SUPERVISOR_HOST_OP_KIND_PROCESS_FS_REQUEST
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_host_network_connect() -> u32 {
    SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_CONNECT
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_host_network_read() -> u32 {
    SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_READ
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_host_network_write() -> u32 {
    SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_WRITE
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_host_network_close() -> u32 {
    SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_CLOSE
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_arm_host_timer() -> u32 {
    SUPERVISOR_HOST_OP_KIND_ARM_HOST_TIMER
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_resume_thread() -> u32 {
    SUPERVISOR_HOST_OP_KIND_RESUME_THREAD
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_host_op_kind_terminate_worker() -> u32 {
    SUPERVISOR_HOST_OP_KIND_TERMINATE_WORKER
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_host_op_record_bytes() -> u32 {
    SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_host_op_kind_spawn_process_worker() -> u32 {
    SUPERVISOR_PROCESS_HOST_OP_KIND_SPAWN_PROCESS_WORKER
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fault_exit_decision_bytes() -> u32 {
    SUPERVISOR_FAULT_EXIT_DECISION_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fault_exit_kind_thread_exit() -> u32 {
    SUPERVISOR_FAULT_EXIT_KIND_THREAD_EXIT
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fault_exit_kind_process_exit() -> u32 {
    SUPERVISOR_FAULT_EXIT_KIND_PROCESS_EXIT
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_exit_cleanup_record_bytes() -> u32 {
    SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_exit_cleanup_kind_thread_exit() -> u32 {
    SUPERVISOR_THREAD_EXIT_CLEANUP_KIND_THREAD_EXIT
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_lifecycle_record_bytes() -> u32 {
    SUPERVISOR_PROCESS_LIFECYCLE_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_lifecycle_kind_child_exit_published() -> u32 {
    SUPERVISOR_PROCESS_LIFECYCLE_KIND_CHILD_EXIT_PUBLISHED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_lifecycle_kind_wait4_completed() -> u32 {
    SUPERVISOR_PROCESS_LIFECYCLE_KIND_WAIT4_COMPLETED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_record_bytes() -> u32 {
    SUPERVISOR_FD_CONTROL_RECORD_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_pipe_created() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_PIPE_CREATED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_fd_closed() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_FD_CLOSED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_fd_duplicated() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_FD_DUPLICATED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_fd_flags_updated() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_FD_FLAGS_UPDATED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_epoll_created() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_EPOLL_CREATED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_epoll_ctl_add() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_EPOLL_CTL_ADD
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_epoll_ctl_del() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_EPOLL_CTL_DEL
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_epoll_ctl_mod() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_EPOLL_CTL_MOD
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_socket_created() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_SOCKET_CREATED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_socketpair_created() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_SOCKETPAIR_CREATED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_socket_bound() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_SOCKET_BOUND
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_socket_listening() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_SOCKET_LISTENING
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_socket_connect_started() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_SOCKET_CONNECT_STARTED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_socket_connected() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_SOCKET_CONNECTED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_socket_connect_failed() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_SOCKET_CONNECT_FAILED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_kind_socket_accepted() -> u32 {
    SUPERVISOR_FD_CONTROL_KIND_SOCKET_ACCEPTED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_control_record_bytes() -> u32 {
    SUPERVISOR_FS_CONTROL_RECORD_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_control_kind_page_cache_miss() -> u32 {
    SUPERVISOR_FS_CONTROL_KIND_PAGE_CACHE_MISS
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_control_kind_page_cache_fill() -> u32 {
    SUPERVISOR_FS_CONTROL_KIND_PAGE_CACHE_FILL
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_control_kind_dirty_page_published() -> u32 {
    SUPERVISOR_FS_CONTROL_KIND_DIRTY_PAGE_PUBLISHED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_control_kind_dirty_page_flushed() -> u32 {
    SUPERVISOR_FS_CONTROL_KIND_DIRTY_PAGE_FLUSHED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_signal_control_record_bytes() -> u32 {
    SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_signal_control_kind_boundary_check() -> u32 {
    SUPERVISOR_SIGNAL_CONTROL_KIND_BOUNDARY_CHECK
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_signal_control_kind_signal_delivered() -> u32 {
    SUPERVISOR_SIGNAL_CONTROL_KIND_SIGNAL_DELIVERED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_signal_control_kind_blocked_wait_interrupted() -> u32 {
    SUPERVISOR_SIGNAL_CONTROL_KIND_BLOCKED_WAIT_INTERRUPTED
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_runnable_selection_bytes() -> u32 {
    SUPERVISOR_RUNNABLE_SELECTION_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_resume_kind_futex_wake() -> u32 {
    SUPERVISOR_RESUME_KIND_FUTEX_WAKE
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_woken() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_WOKEN
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_not_equal() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_NOT_EQUAL
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_timed_out() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_invalid_address() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_INVALID_ADDRESS
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_futex_wait_completion_signal_check() -> u32 {
    SUPERVISOR_FUTEX_WAIT_COMPLETION_SIGNAL_CHECK
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_reset_shadow_log() {
    init();
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_thread_event_count() -> u64 {
    thread_event_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_completion_count() -> u64 {
    host_completion_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_poll_count() -> u64 {
    host_op_poll_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_emit_count() -> u64 {
    host_op_emit_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_overflow_count() -> u64 {
    host_op_overflow_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_thread_exit_cleanup_count() -> u64 {
    thread_exit_cleanup_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_process_lifecycle_count() -> u64 {
    process_lifecycle_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_fd_control_count() -> u64 {
    fd_control_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_fs_control_count() -> u64 {
    fs_control_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_signal_control_count() -> u64 {
    signal_control_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_resume_poll_count() -> u64 {
    resume_poll_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_resume_enqueue_count() -> u64 {
    resume_enqueue_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_resume_overflow_count() -> u64 {
    resume_overflow_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_thread_event_log_hash() -> u64 {
    thread_event_log_hash()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_completion_log_hash() -> u64 {
    host_completion_log_hash()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_log_hash() -> u64 {
    host_op_log_hash()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_last_hash() -> u64 {
    LAST_HOST_OP_HASH.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_last_len() -> u32 {
    LAST_HOST_OP_LEN.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_submit_thread_event(event_ptr: u32, event_len: u32) -> i32 {
    event::submit(event_ptr, event_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_complete_host_op(completion_ptr: u32, completion_len: u32) -> i32 {
    let bytes = match read_shadow_bytes(completion_ptr, completion_len) {
        Ok(bytes) => bytes,
        Err(errno) => return errno,
    };
    let entry_hash = fnv_hash(bytes);
    HOST_COMPLETION_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_HOST_COMPLETION_HASH.store(entry_hash, Ordering::Relaxed);
    LAST_HOST_COMPLETION_LEN.store(completion_len, Ordering::Relaxed);
    fold_log_hash(&HOST_COMPLETION_LOG_HASH, entry_hash, completion_len);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_complete_futex_wait(vm_ptr: u32, completion: u32) -> i32 {
    futex::complete_wait(vm_ptr, completion)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_signal_pending_for_blocked_wait(vm_ptr: u32) -> i32 {
    futex::blocked_wait_signal_decision(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_next_host_op(_out_ptr: u32, _out_len: u32) -> i32 {
    host_op::write_record(_out_ptr, _out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_host_op(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    host_op::write_process_record(vm_ptr, out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_next_resume(_out_ptr: u32, _out_len: u32) -> i32 {
    resume::write_record(_out_ptr, _out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_select_runnable(
    vm_ptr: u32,
    candidates_ptr: u32,
    candidate_count: u32,
    out_ptr: u32,
    out_len: u32,
) -> i32 {
    runnable::write_selection(vm_ptr, candidates_ptr, candidate_count, out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fault_exit_decision(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    write_fault_exit_decision(vm_ptr, out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_exit_cleanup_record(out_ptr: u32, out_len: u32) -> i32 {
    write_thread_exit_cleanup_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_lifecycle_record(out_ptr: u32, out_len: u32) -> i32 {
    write_process_lifecycle_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_record(out_ptr: u32, out_len: u32) -> i32 {
    write_fd_control_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_control_record(out_ptr: u32, out_len: u32) -> i32 {
    write_fs_control_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_signal_control_record(out_ptr: u32, out_len: u32) -> i32 {
    write_signal_control_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_debug_snapshot(out_ptr: u32, out_len: u32) -> i32 {
    write_snapshot(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_state_snapshot(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    write_thread_state_snapshot(vm_ptr, out_ptr, out_len)
}
