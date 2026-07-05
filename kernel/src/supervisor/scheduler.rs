pub(super) const CLEAR_BLOCKED_ACTION_NONE: u32 = 0;
pub(super) const CLEAR_BLOCKED_ACTION_CLEAR_PIPE_SYNC_BEFORE_RETRY: u32 = 1;
pub(super) const CLEAR_BLOCKED_FLAG_CLEAR_PIPE_SYNC_BEFORE_RETRY: u32 = 1;

pub(super) const BLOCK_WORKER_ACTION_RECORD_BLOCKED: u32 = 0;
pub(super) const BLOCK_WORKER_ACTION_PARK_FUTEX: u32 = 1;

pub(super) const FUTEX_WAITER_ACTION_NOT_WAITER: u32 = 0;
pub(super) const FUTEX_WAITER_ACTION_WAITER: u32 = 1;

pub(super) fn clear_blocked_action_none() -> u32 {
    CLEAR_BLOCKED_ACTION_NONE
}

pub(super) fn clear_blocked_action_clear_pipe_sync_before_retry() -> u32 {
    CLEAR_BLOCKED_ACTION_CLEAR_PIPE_SYNC_BEFORE_RETRY
}

pub(super) fn clear_blocked_flag_clear_pipe_sync_before_retry() -> u32 {
    CLEAR_BLOCKED_FLAG_CLEAR_PIPE_SYNC_BEFORE_RETRY
}

pub(super) fn block_worker_action_record_blocked() -> u32 {
    BLOCK_WORKER_ACTION_RECORD_BLOCKED
}

pub(super) fn block_worker_action_park_futex() -> u32 {
    BLOCK_WORKER_ACTION_PARK_FUTEX
}

pub(super) fn futex_waiter_action_not_waiter() -> u32 {
    FUTEX_WAITER_ACTION_NOT_WAITER
}

pub(super) fn futex_waiter_action_waiter() -> u32 {
    FUTEX_WAITER_ACTION_WAITER
}

pub(super) fn clear_blocked_action(status: i32, flags: u32) -> i32 {
    if (flags & CLEAR_BLOCKED_FLAG_CLEAR_PIPE_SYNC_BEFORE_RETRY) != 0
        && status == crate::abi::STATUS_PIPE_WAIT
    {
        CLEAR_BLOCKED_ACTION_CLEAR_PIPE_SYNC_BEFORE_RETRY as i32
    } else {
        CLEAR_BLOCKED_ACTION_NONE as i32
    }
}

pub(super) fn block_worker_action(status: i32) -> i32 {
    match status {
        crate::abi::STATUS_FUTEX_WAIT => BLOCK_WORKER_ACTION_PARK_FUTEX as i32,
        _ => BLOCK_WORKER_ACTION_RECORD_BLOCKED as i32,
    }
}

pub(super) fn futex_waiter_action(status: i32) -> i32 {
    match status {
        crate::abi::STATUS_FUTEX_WAIT => FUTEX_WAITER_ACTION_WAITER as i32,
        _ => FUTEX_WAITER_ACTION_NOT_WAITER as i32,
    }
}
