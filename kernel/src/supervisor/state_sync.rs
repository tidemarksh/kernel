use core::sync::atomic::{AtomicU32, Ordering};

const STATE_SYNC_CAP: usize = 256;

#[derive(Clone, Copy)]
struct StateSyncRequest {
    vm_ptr: u32,
    kind: u32,
    queued_run_flags: u32,
    in_flight: u32,
}

impl StateSyncRequest {
    const fn empty() -> Self {
        Self {
            vm_ptr: 0,
            kind: 0,
            queued_run_flags: 0,
            in_flight: 0,
        }
    }

    fn matches(&self, vm_ptr: u32, kind: u32) -> bool {
        self.vm_ptr == vm_ptr && self.kind == kind
    }
}

static STATE_SYNC_LOCK: AtomicU32 = AtomicU32::new(0);
static STATE_SYNC_CURSOR: AtomicU32 = AtomicU32::new(0);
static mut STATE_SYNC_REQUESTS: [StateSyncRequest; STATE_SYNC_CAP] =
    [StateSyncRequest::empty(); STATE_SYNC_CAP];

pub(super) const WAKE_SOURCE_PIPE_SYNC: u32 = 1;
pub(super) const WAKE_SOURCE_EPOLL_SYNC: u32 = 2;
pub(super) const WAKE_SOURCE_SOCKET_SYNC: u32 = 3;
pub(super) const WAKE_SOURCE_PIPE_AND_EPOLL_SYNC: u32 = 4;

pub(super) const WAKE_TARGET_PIPE_WAIT: u32 = 1;
pub(super) const WAKE_TARGET_EPOLL_WAIT: u32 = 1 << 1;
pub(super) const WAKE_TARGET_SOCKET_RECV: u32 = 1 << 2;
pub(super) const WAKE_TARGET_SOCKET_SEND: u32 = 1 << 3;

pub(super) const WAKE_BLOCKED_FLAG_RPC_PENDING: u32 = 1;

pub(super) const WAKE_BLOCKED_ACTION_SKIP: u32 = 0;
pub(super) const WAKE_BLOCKED_ACTION_RETRY: u32 = 1;
pub(super) const WAKE_BLOCKED_ACTION_CLEAR_PIPE_SYNC_AND_RETRY: u32 = 2;
pub(super) const WAKE_BLOCKED_ACTION_LOG_EPOLL_AND_RETRY: u32 = 3;

pub(super) const OWNED_STATE_SYNC_ACTION_NONE: u32 = 0;
pub(super) const OWNED_STATE_SYNC_ACTION_MARK_PROCESS_MEMFS_DIRTY: u32 = 1;
pub(super) const OWNED_STATE_SYNC_ACTION_SYNC_FORK_SHARED: u32 = 1 << 1;
pub(super) const OWNED_STATE_SYNC_ACTION_SYNC_EPOLL_DEPENDENT_OFDS: u32 = 1 << 2;
pub(super) const OWNED_STATE_SYNC_ACTION_SYNC_SOCKET: u32 = 1 << 3;
pub(super) const OWNED_STATE_SYNC_ACTION_WAKE_SOCKET_WAITERS: u32 = 1 << 4;
pub(super) const OWNED_STATE_SYNC_ACTION_SYNC_PROCESS_MEMFS: u32 = 1 << 5;
pub(super) const OWNED_STATE_SYNC_ACTION_SYNC_EPOLL: u32 = 1 << 6;
pub(super) const OWNED_STATE_SYNC_ACTION_RETRY_EPOLL_WAITERS: u32 = 1 << 7;

pub(super) const OWNED_STATE_SYNC_FLAG_RUNNING_WORKER: u32 = 1;
pub(super) const OWNED_STATE_SYNC_FLAG_WORKER_OWNS_AUTHORITATIVE_STATE: u32 = 1 << 1;
pub(super) const OWNED_STATE_SYNC_FLAG_KERNEL_WORKER_AVAILABLE: u32 = 1 << 2;
pub(super) const OWNED_STATE_SYNC_FLAG_EPOLL_STATE_KERNEL_OWNS: u32 = 1 << 3;
pub(super) const OWNED_STATE_SYNC_FLAG_FORK_SHARED_EFFECT_REQUESTED: u32 = 1 << 4;
pub(super) const OWNED_STATE_SYNC_FLAG_ACTIVE_VFORK_CHILD_OWNER_MISMATCH: u32 = 1 << 5;
pub(super) const OWNED_STATE_SYNC_FLAG_PROCESS_MEMFS_DIRTY: u32 = 1 << 6;
pub(super) const OWNED_STATE_SYNC_FLAG_HELD_EPOLL_OFD: u32 = 1 << 7;
pub(super) const OWNED_STATE_SYNC_FLAG_WROTE_OR_DRAINED_PIPE: u32 = 1 << 8;

pub(super) const STATE_SYNC_START_ACTION_SKIP: u32 = 0;
pub(super) const STATE_SYNC_START_ACTION_REQUEST_SYNC: u32 = 1;
pub(super) const STATE_SYNC_START_ACTION_RETRY_WAITERS: u32 = 2;

pub(super) const STATE_SYNC_START_FLAG_ACTIVE_VFORK_CHILD_OWNER_MISMATCH: u32 = 1;
pub(super) const STATE_SYNC_START_FLAG_KERNEL_WORKER_AVAILABLE: u32 = 1 << 1;
pub(super) const STATE_SYNC_START_FLAG_EPOLL_STATE_KERNEL_OWNS: u32 = 1 << 2;
pub(super) const STATE_SYNC_START_FLAG_HELD_EPOLL_OFD: u32 = 1 << 3;
pub(super) const STATE_SYNC_START_FLAG_WAKE_WAITERS: u32 = 1 << 4;

fn with_state_sync_lock<T>(f: impl FnOnce(&mut [StateSyncRequest; STATE_SYNC_CAP]) -> T) -> T {
    loop {
        if STATE_SYNC_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let requests_ptr = core::ptr::addr_of_mut!(STATE_SYNC_REQUESTS);
    let result = unsafe { f(&mut *requests_ptr) };
    STATE_SYNC_LOCK.store(0, Ordering::Release);
    result
}

pub(super) fn init() {
    with_state_sync_lock(|requests| {
        STATE_SYNC_CURSOR.store(0, Ordering::Relaxed);
        for request in requests.iter_mut() {
            *request = StateSyncRequest::empty();
        }
    });
}

pub(super) fn wake_source_pipe_sync() -> u32 {
    WAKE_SOURCE_PIPE_SYNC
}

pub(super) fn wake_source_epoll_sync() -> u32 {
    WAKE_SOURCE_EPOLL_SYNC
}

pub(super) fn wake_source_socket_sync() -> u32 {
    WAKE_SOURCE_SOCKET_SYNC
}

pub(super) fn wake_source_pipe_and_epoll_sync() -> u32 {
    WAKE_SOURCE_PIPE_AND_EPOLL_SYNC
}

pub(super) fn wake_target_pipe_wait() -> u32 {
    WAKE_TARGET_PIPE_WAIT
}

pub(super) fn wake_target_epoll_wait() -> u32 {
    WAKE_TARGET_EPOLL_WAIT
}

pub(super) fn wake_target_socket_recv() -> u32 {
    WAKE_TARGET_SOCKET_RECV
}

pub(super) fn wake_target_socket_send() -> u32 {
    WAKE_TARGET_SOCKET_SEND
}

pub(super) fn wake_blocked_flag_rpc_pending() -> u32 {
    WAKE_BLOCKED_FLAG_RPC_PENDING
}

pub(super) fn wake_blocked_action_skip() -> u32 {
    WAKE_BLOCKED_ACTION_SKIP
}

pub(super) fn wake_blocked_action_retry() -> u32 {
    WAKE_BLOCKED_ACTION_RETRY
}

pub(super) fn wake_blocked_action_clear_pipe_sync_and_retry() -> u32 {
    WAKE_BLOCKED_ACTION_CLEAR_PIPE_SYNC_AND_RETRY
}

pub(super) fn wake_blocked_action_log_epoll_and_retry() -> u32 {
    WAKE_BLOCKED_ACTION_LOG_EPOLL_AND_RETRY
}

pub(super) fn owned_state_sync_action_none() -> u32 {
    OWNED_STATE_SYNC_ACTION_NONE
}

pub(super) fn owned_state_sync_action_mark_process_memfs_dirty() -> u32 {
    OWNED_STATE_SYNC_ACTION_MARK_PROCESS_MEMFS_DIRTY
}

pub(super) fn owned_state_sync_action_sync_fork_shared() -> u32 {
    OWNED_STATE_SYNC_ACTION_SYNC_FORK_SHARED
}

pub(super) fn owned_state_sync_action_sync_epoll_dependent_ofds() -> u32 {
    OWNED_STATE_SYNC_ACTION_SYNC_EPOLL_DEPENDENT_OFDS
}

pub(super) fn owned_state_sync_action_sync_socket() -> u32 {
    OWNED_STATE_SYNC_ACTION_SYNC_SOCKET
}

pub(super) fn owned_state_sync_action_wake_socket_waiters() -> u32 {
    OWNED_STATE_SYNC_ACTION_WAKE_SOCKET_WAITERS
}

pub(super) fn owned_state_sync_action_sync_process_memfs() -> u32 {
    OWNED_STATE_SYNC_ACTION_SYNC_PROCESS_MEMFS
}

pub(super) fn owned_state_sync_action_sync_epoll() -> u32 {
    OWNED_STATE_SYNC_ACTION_SYNC_EPOLL
}

pub(super) fn owned_state_sync_action_retry_epoll_waiters() -> u32 {
    OWNED_STATE_SYNC_ACTION_RETRY_EPOLL_WAITERS
}

pub(super) fn owned_state_sync_flag_running_worker() -> u32 {
    OWNED_STATE_SYNC_FLAG_RUNNING_WORKER
}

pub(super) fn owned_state_sync_flag_worker_owns_authoritative_state() -> u32 {
    OWNED_STATE_SYNC_FLAG_WORKER_OWNS_AUTHORITATIVE_STATE
}

pub(super) fn owned_state_sync_flag_kernel_worker_available() -> u32 {
    OWNED_STATE_SYNC_FLAG_KERNEL_WORKER_AVAILABLE
}

pub(super) fn owned_state_sync_flag_epoll_state_kernel_owns() -> u32 {
    OWNED_STATE_SYNC_FLAG_EPOLL_STATE_KERNEL_OWNS
}

pub(super) fn owned_state_sync_flag_fork_shared_effect_requested() -> u32 {
    OWNED_STATE_SYNC_FLAG_FORK_SHARED_EFFECT_REQUESTED
}

pub(super) fn owned_state_sync_flag_active_vfork_child_owner_mismatch() -> u32 {
    OWNED_STATE_SYNC_FLAG_ACTIVE_VFORK_CHILD_OWNER_MISMATCH
}

pub(super) fn owned_state_sync_flag_process_memfs_dirty() -> u32 {
    OWNED_STATE_SYNC_FLAG_PROCESS_MEMFS_DIRTY
}

pub(super) fn owned_state_sync_flag_held_epoll_ofd() -> u32 {
    OWNED_STATE_SYNC_FLAG_HELD_EPOLL_OFD
}

pub(super) fn owned_state_sync_flag_wrote_or_drained_pipe() -> u32 {
    OWNED_STATE_SYNC_FLAG_WROTE_OR_DRAINED_PIPE
}

pub(super) fn state_sync_start_action_skip() -> u32 {
    STATE_SYNC_START_ACTION_SKIP
}

pub(super) fn state_sync_start_action_request_sync() -> u32 {
    STATE_SYNC_START_ACTION_REQUEST_SYNC
}

pub(super) fn state_sync_start_action_retry_waiters() -> u32 {
    STATE_SYNC_START_ACTION_RETRY_WAITERS
}

pub(super) fn state_sync_start_flag_active_vfork_child_owner_mismatch() -> u32 {
    STATE_SYNC_START_FLAG_ACTIVE_VFORK_CHILD_OWNER_MISMATCH
}

pub(super) fn state_sync_start_flag_kernel_worker_available() -> u32 {
    STATE_SYNC_START_FLAG_KERNEL_WORKER_AVAILABLE
}

pub(super) fn state_sync_start_flag_epoll_state_kernel_owns() -> u32 {
    STATE_SYNC_START_FLAG_EPOLL_STATE_KERNEL_OWNS
}

pub(super) fn state_sync_start_flag_held_epoll_ofd() -> u32 {
    STATE_SYNC_START_FLAG_HELD_EPOLL_OFD
}

pub(super) fn state_sync_start_flag_wake_waiters() -> u32 {
    STATE_SYNC_START_FLAG_WAKE_WAITERS
}

fn valid_sync_kind(kind: u32) -> bool {
    matches!(
        kind,
        super::SUPERVISOR_STATE_SYNC_KIND_PIPE
            | super::SUPERVISOR_STATE_SYNC_KIND_EPOLL
            | super::SUPERVISOR_STATE_SYNC_KIND_SOCKET
    )
}

fn request_run_flags(flags: u32) -> u32 {
    let mut run_flags = super::SUPERVISOR_STATE_SYNC_RUN_FLAG_RUN;
    if (flags & super::SUPERVISOR_STATE_SYNC_REQUEST_FLAG_WAKE_WAITERS) != 0 {
        run_flags |= super::SUPERVISOR_STATE_SYNC_RUN_FLAG_WAKE_WAITERS;
    }
    run_flags
}

fn state_sync_slot(
    requests: &mut [StateSyncRequest; STATE_SYNC_CAP],
    vm_ptr: u32,
    kind: u32,
) -> usize {
    for (idx, request) in requests.iter().enumerate() {
        if request.matches(vm_ptr, kind) {
            return idx;
        }
    }
    for (idx, request) in requests.iter_mut().enumerate() {
        if request.vm_ptr == 0 {
            *request = StateSyncRequest {
                vm_ptr,
                kind,
                queued_run_flags: 0,
                in_flight: 0,
            };
            return idx;
        }
    }
    let idx = STATE_SYNC_CURSOR.fetch_add(1, Ordering::Relaxed) as usize % STATE_SYNC_CAP;
    requests[idx] = StateSyncRequest {
        vm_ptr,
        kind,
        queued_run_flags: 0,
        in_flight: 0,
    };
    idx
}

fn find_state_sync_slot(
    requests: &mut [StateSyncRequest; STATE_SYNC_CAP],
    vm_ptr: u32,
    kind: u32,
) -> Option<usize> {
    requests
        .iter()
        .enumerate()
        .find_map(|(idx, request)| request.matches(vm_ptr, kind).then_some(idx))
}

fn validate_request(vm_ptr: u32, kind: u32) -> Result<(), i32> {
    if vm_ptr == 0 {
        return Err(-(crate::abi::EFAULT as i32));
    }
    if !valid_sync_kind(kind) {
        return Err(-(crate::abi::EINVAL as i32));
    }
    Ok(())
}

pub fn request(vm_ptr: u32, kind: u32, flags: u32) -> i32 {
    if let Err(errno) = validate_request(vm_ptr, kind) {
        return errno;
    }
    with_state_sync_lock(|requests| {
        let idx = state_sync_slot(requests, vm_ptr, kind);
        requests[idx].queued_run_flags |= request_run_flags(flags);
        if requests[idx].in_flight != 0 {
            return 0;
        }
        requests[idx].in_flight = 1;
        1
    })
}

pub fn next_run_flags(vm_ptr: u32, kind: u32) -> i32 {
    if let Err(errno) = validate_request(vm_ptr, kind) {
        return errno;
    }
    with_state_sync_lock(|requests| {
        let Some(idx) = find_state_sync_slot(requests, vm_ptr, kind) else {
            return 0;
        };
        let run_flags = requests[idx].queued_run_flags;
        requests[idx].queued_run_flags = 0;
        run_flags as i32
    })
}

pub fn complete(vm_ptr: u32, kind: u32) -> i32 {
    if let Err(errno) = validate_request(vm_ptr, kind) {
        return errno;
    }
    with_state_sync_lock(|requests| {
        let Some(idx) = find_state_sync_slot(requests, vm_ptr, kind) else {
            return 0;
        };
        if requests[idx].queued_run_flags != 0 {
            return 1;
        }
        requests[idx] = StateSyncRequest::empty();
        0
    })
}

pub fn clear(vm_ptr: u32, kind: u32) -> i32 {
    if let Err(errno) = validate_request(vm_ptr, kind) {
        return errno;
    }
    with_state_sync_lock(|requests| {
        for request in requests.iter_mut() {
            if request.matches(vm_ptr, kind) {
                *request = StateSyncRequest::empty();
            }
        }
    });
    0
}

pub(super) fn start_action(kind: u32, flags: u32) -> i32 {
    if !valid_sync_kind(kind) {
        return -(crate::abi::EINVAL as i32);
    }
    if (flags & STATE_SYNC_START_FLAG_ACTIVE_VFORK_CHILD_OWNER_MISMATCH) != 0 {
        return STATE_SYNC_START_ACTION_SKIP as i32;
    }

    match kind {
        super::SUPERVISOR_STATE_SYNC_KIND_PIPE | super::SUPERVISOR_STATE_SYNC_KIND_SOCKET => {
            if (flags & STATE_SYNC_START_FLAG_KERNEL_WORKER_AVAILABLE) != 0 {
                STATE_SYNC_START_ACTION_REQUEST_SYNC as i32
            } else {
                STATE_SYNC_START_ACTION_SKIP as i32
            }
        }
        super::SUPERVISOR_STATE_SYNC_KIND_EPOLL => {
            if (flags & STATE_SYNC_START_FLAG_EPOLL_STATE_KERNEL_OWNS) == 0 {
                return STATE_SYNC_START_ACTION_SKIP as i32;
            }
            if (flags & STATE_SYNC_START_FLAG_HELD_EPOLL_OFD) != 0 {
                return STATE_SYNC_START_ACTION_REQUEST_SYNC as i32;
            }
            if (flags & STATE_SYNC_START_FLAG_WAKE_WAITERS) != 0 {
                STATE_SYNC_START_ACTION_RETRY_WAITERS as i32
            } else {
                STATE_SYNC_START_ACTION_SKIP as i32
            }
        }
        _ => -(crate::abi::EINVAL as i32),
    }
}

pub(super) fn wake_mask_for_sync(source: u32) -> i32 {
    match source {
        WAKE_SOURCE_PIPE_SYNC => WAKE_TARGET_PIPE_WAIT as i32,
        WAKE_SOURCE_EPOLL_SYNC => WAKE_TARGET_EPOLL_WAIT as i32,
        WAKE_SOURCE_SOCKET_SYNC => {
            (WAKE_TARGET_PIPE_WAIT
                | WAKE_TARGET_EPOLL_WAIT
                | WAKE_TARGET_SOCKET_RECV
                | WAKE_TARGET_SOCKET_SEND) as i32
        }
        WAKE_SOURCE_PIPE_AND_EPOLL_SYNC => (WAKE_TARGET_PIPE_WAIT | WAKE_TARGET_EPOLL_WAIT) as i32,
        _ => -(crate::abi::EINVAL as i32),
    }
}

fn valid_wake_source(source: u32) -> bool {
    matches!(
        source,
        WAKE_SOURCE_PIPE_SYNC
            | WAKE_SOURCE_EPOLL_SYNC
            | WAKE_SOURCE_SOCKET_SYNC
            | WAKE_SOURCE_PIPE_AND_EPOLL_SYNC
    )
}

fn wake_target_for_status(status: i32) -> u32 {
    match status {
        crate::abi::STATUS_PIPE_WAIT => WAKE_TARGET_PIPE_WAIT,
        crate::abi::STATUS_EPOLL_WAIT => WAKE_TARGET_EPOLL_WAIT,
        crate::abi::STATUS_SOCKET_RECV => WAKE_TARGET_SOCKET_RECV,
        crate::abi::STATUS_SOCKET_SEND => WAKE_TARGET_SOCKET_SEND,
        _ => 0,
    }
}

pub(super) fn status_matches_wake_source(status: i32, source: u32) -> i32 {
    if !valid_wake_source(source) {
        return -(crate::abi::EINVAL as i32);
    }
    let mask = wake_mask_for_sync(source);
    let target = wake_target_for_status(status);
    i32::from(target != 0 && ((mask as u32) & target) != 0)
}

pub(super) fn wake_blocked_action(status: i32, source: u32, flags: u32) -> i32 {
    if !valid_wake_source(source) {
        return -(crate::abi::EINVAL as i32);
    }
    if status_matches_wake_source(status, source) == 0 {
        return WAKE_BLOCKED_ACTION_SKIP as i32;
    }
    let rpc_pending = (flags & WAKE_BLOCKED_FLAG_RPC_PENDING) != 0;
    match status {
        crate::abi::STATUS_PIPE_WAIT => {
            if rpc_pending {
                WAKE_BLOCKED_ACTION_SKIP as i32
            } else {
                WAKE_BLOCKED_ACTION_CLEAR_PIPE_SYNC_AND_RETRY as i32
            }
        }
        crate::abi::STATUS_EPOLL_WAIT => {
            if rpc_pending {
                WAKE_BLOCKED_ACTION_SKIP as i32
            } else {
                WAKE_BLOCKED_ACTION_LOG_EPOLL_AND_RETRY as i32
            }
        }
        _ => WAKE_BLOCKED_ACTION_RETRY as i32,
    }
}

pub(super) fn owned_state_sync_action(status: i32, completed_sync_effects: u32, flags: u32) -> i32 {
    let running_worker = (flags & OWNED_STATE_SYNC_FLAG_RUNNING_WORKER) != 0;
    let worker_owns_authoritative_state =
        (flags & OWNED_STATE_SYNC_FLAG_WORKER_OWNS_AUTHORITATIVE_STATE) != 0;
    let kernel_worker_available = (flags & OWNED_STATE_SYNC_FLAG_KERNEL_WORKER_AVAILABLE) != 0;
    let epoll_state_kernel_owns = (flags & OWNED_STATE_SYNC_FLAG_EPOLL_STATE_KERNEL_OWNS) != 0;
    let fork_shared_effect_requested =
        (flags & OWNED_STATE_SYNC_FLAG_FORK_SHARED_EFFECT_REQUESTED) != 0;
    let active_vfork_child_owner_mismatch =
        (flags & OWNED_STATE_SYNC_FLAG_ACTIVE_VFORK_CHILD_OWNER_MISMATCH) != 0;
    let process_memfs_dirty = (flags & OWNED_STATE_SYNC_FLAG_PROCESS_MEMFS_DIRTY) != 0;
    let held_epoll_ofd = (flags & OWNED_STATE_SYNC_FLAG_HELD_EPOLL_OFD) != 0;
    let wrote_or_drained_pipe = (flags & OWNED_STATE_SYNC_FLAG_WROTE_OR_DRAINED_PIPE) != 0;

    let has_pipe_effect =
        (completed_sync_effects & super::sync_effects::SYNC_EFFECT_PIPE_STATE) != 0;
    let has_socket_effect =
        (completed_sync_effects & super::sync_effects::SYNC_EFFECT_SOCKET_STATE) != 0;
    let has_epoll_effect =
        (completed_sync_effects & super::sync_effects::SYNC_EFFECT_EPOLL_STATE) != 0;
    let has_epoll_dependent_ofd_effect =
        (completed_sync_effects & super::sync_effects::SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE) != 0;
    let has_process_memfs_effect =
        (completed_sync_effects & super::sync_effects::SYNC_EFFECT_PROCESS_MEMFS) != 0;

    let mut action = OWNED_STATE_SYNC_ACTION_NONE;
    let mark_process_memfs_dirty = running_worker && has_process_memfs_effect;
    if mark_process_memfs_dirty {
        action |= OWNED_STATE_SYNC_ACTION_MARK_PROCESS_MEMFS_DIRTY;
    }
    if status == crate::abi::STATUS_OK && has_socket_effect {
        action |= OWNED_STATE_SYNC_ACTION_WAKE_SOCKET_WAITERS;
    }

    if active_vfork_child_owner_mismatch || super::process::status_is_lifecycle_handoff(status) != 0
    {
        return action as i32;
    }

    let should_sync_fork_shared = worker_owns_authoritative_state
        && kernel_worker_available
        && fork_shared_effect_requested
        && status == crate::abi::STATUS_OK;
    if should_sync_fork_shared {
        action |= OWNED_STATE_SYNC_ACTION_SYNC_FORK_SHARED;
    }

    if running_worker && epoll_state_kernel_owns && has_epoll_dependent_ofd_effect {
        action |= OWNED_STATE_SYNC_ACTION_SYNC_EPOLL_DEPENDENT_OFDS;
    }

    if should_sync_fork_shared && running_worker && kernel_worker_available && has_socket_effect {
        action |= OWNED_STATE_SYNC_ACTION_SYNC_SOCKET;
    }

    let dirty_process_memfs = process_memfs_dirty || mark_process_memfs_dirty;
    let should_publish_dirty_memfs = status != crate::abi::STATUS_OK || has_pipe_effect;
    if running_worker
        && kernel_worker_available
        && dirty_process_memfs
        && should_publish_dirty_memfs
    {
        action |= OWNED_STATE_SYNC_ACTION_SYNC_PROCESS_MEMFS;
    }

    if running_worker && epoll_state_kernel_owns && has_epoll_effect && held_epoll_ofd {
        action |= OWNED_STATE_SYNC_ACTION_SYNC_EPOLL;
        if !wrote_or_drained_pipe {
            action |= OWNED_STATE_SYNC_ACTION_RETRY_EPOLL_WAITERS;
        }
    }

    action as i32
}
