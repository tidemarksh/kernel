pub(super) const WORKER_ACTION_ENQUEUE: u32 = 0;
pub(super) const WORKER_ACTION_CONNECT_WAIT: u32 = 1;
pub(super) const WORKER_ACTION_PARK_FUTEX: u32 = 2;
pub(super) const WORKER_ACTION_HOST_WAIT: u32 = 3;

pub(super) const WORKER_STATUS_SYNC_ACTION_NONE: u32 = 0;
pub(super) const WORKER_STATUS_SYNC_ACTION_SYNC_PIPE: u32 = 1;
pub(super) const WORKER_STATUS_SYNC_ACTION_SYNC_SOCKET: u32 = 1 << 1;
pub(super) const WORKER_STATUS_SYNC_ACTION_SYNC_LIFECYCLE: u32 = 1 << 2;
pub(super) const WORKER_STATUS_SYNC_ACTION_WAKE_SIGNAL_WAITERS: u32 = 1 << 3;

pub(super) const WORKER_STATUS_SYNC_FLAG_WROTE_OR_DRAINED_PIPE: u32 = 1;

pub(super) const WORKER_SLEEP_STATUS_ACTION_NONE: u32 = 0;
pub(super) const WORKER_SLEEP_STATUS_ACTION_YIELD: u32 = 1;
pub(super) const WORKER_SLEEP_STATUS_ACTION_ARM_HOST_TIMER: u32 = 1 << 1;
pub(super) const WORKER_SLEEP_STATUS_ACTION_SYNC_PIPE_BEFORE_YIELD_CLEAR: u32 = 1 << 2;

pub(super) fn worker_action_enqueue() -> u32 {
    WORKER_ACTION_ENQUEUE
}

pub(super) fn worker_action_connect_wait() -> u32 {
    WORKER_ACTION_CONNECT_WAIT
}

pub(super) fn worker_action_park_futex() -> u32 {
    WORKER_ACTION_PARK_FUTEX
}

pub(super) fn worker_action_host_wait() -> u32 {
    WORKER_ACTION_HOST_WAIT
}

pub(super) fn worker_status_sync_action_none() -> u32 {
    WORKER_STATUS_SYNC_ACTION_NONE
}

pub(super) fn worker_status_sync_action_sync_pipe() -> u32 {
    WORKER_STATUS_SYNC_ACTION_SYNC_PIPE
}

pub(super) fn worker_status_sync_action_sync_socket() -> u32 {
    WORKER_STATUS_SYNC_ACTION_SYNC_SOCKET
}

pub(super) fn worker_status_sync_action_sync_lifecycle() -> u32 {
    WORKER_STATUS_SYNC_ACTION_SYNC_LIFECYCLE
}

pub(super) fn worker_status_sync_action_wake_signal_waiters() -> u32 {
    WORKER_STATUS_SYNC_ACTION_WAKE_SIGNAL_WAITERS
}

pub(super) fn worker_status_sync_flag_wrote_or_drained_pipe() -> u32 {
    WORKER_STATUS_SYNC_FLAG_WROTE_OR_DRAINED_PIPE
}

pub(super) fn worker_sleep_status_action_none() -> u32 {
    WORKER_SLEEP_STATUS_ACTION_NONE
}

pub(super) fn worker_sleep_status_action_yield() -> u32 {
    WORKER_SLEEP_STATUS_ACTION_YIELD
}

pub(super) fn worker_sleep_status_action_arm_host_timer() -> u32 {
    WORKER_SLEEP_STATUS_ACTION_ARM_HOST_TIMER
}

pub(super) fn worker_sleep_status_action_sync_pipe_before_yield_clear() -> u32 {
    WORKER_SLEEP_STATUS_ACTION_SYNC_PIPE_BEFORE_YIELD_CLEAR
}

pub(super) fn worker_action(status: i32) -> i32 {
    if status == crate::abi::STATUS_CONNECT {
        return WORKER_ACTION_CONNECT_WAIT as i32;
    }
    if status == crate::abi::STATUS_FUTEX_WAIT {
        return WORKER_ACTION_PARK_FUTEX as i32;
    }
    if super::blocked::status_is_host_wait(status) != 0 {
        return WORKER_ACTION_HOST_WAIT as i32;
    }
    WORKER_ACTION_ENQUEUE as i32
}

pub(super) fn worker_status_sync_action(
    status: i32,
    completed_sync_effects: u32,
    flags: u32,
) -> i32 {
    let wrote_or_drained_pipe = (flags & WORKER_STATUS_SYNC_FLAG_WROTE_OR_DRAINED_PIPE) != 0;
    let has_pipe_effect =
        (completed_sync_effects & super::sync_effects::SYNC_EFFECT_PIPE_STATE) != 0;
    let has_socket_effect =
        (completed_sync_effects & super::sync_effects::SYNC_EFFECT_SOCKET_STATE) != 0;
    let has_lifecycle_effect =
        (completed_sync_effects & super::sync_effects::SYNC_EFFECT_PROCESS_LIFECYCLE) != 0;
    let has_signal_waiters_effect =
        (completed_sync_effects & super::sync_effects::SYNC_EFFECT_SIGNAL_WAITERS) != 0;

    let mut action = WORKER_STATUS_SYNC_ACTION_NONE;
    if status != crate::abi::STATUS_FS && (wrote_or_drained_pipe || has_pipe_effect) {
        action |= WORKER_STATUS_SYNC_ACTION_SYNC_PIPE;
    }
    if status == crate::abi::STATUS_OK {
        if has_socket_effect {
            action |= WORKER_STATUS_SYNC_ACTION_SYNC_SOCKET;
        }
        if has_lifecycle_effect {
            action |= WORKER_STATUS_SYNC_ACTION_SYNC_LIFECYCLE;
        }
        if has_signal_waiters_effect {
            action |= WORKER_STATUS_SYNC_ACTION_WAKE_SIGNAL_WAITERS;
        }
    }
    action as i32
}

pub(super) fn worker_sleep_status_action(
    vm_ptr: u32,
    status: i32,
    completed_sync_effects: u32,
) -> i32 {
    if status != crate::abi::STATUS_SLEEP {
        return WORKER_SLEEP_STATUS_ACTION_NONE as i32;
    }
    if vm_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    let vm = unsafe { &mut *(vm_ptr as *mut crate::types::ThreadState) };
    if vm.fault_addr != 0 || vm.fault_pc != 0 {
        return WORKER_SLEEP_STATUS_ACTION_ARM_HOST_TIMER as i32;
    }

    vm.status = crate::abi::STATUS_OK;
    let mut action = WORKER_SLEEP_STATUS_ACTION_YIELD;
    if (completed_sync_effects & super::sync_effects::SYNC_EFFECT_PIPE_STATE) != 0 {
        action |= WORKER_SLEEP_STATUS_ACTION_SYNC_PIPE_BEFORE_YIELD_CLEAR;
    }
    action as i32
}
