pub(super) const WORKER_ACTION_ENQUEUE: u32 = 0;
pub(super) const WORKER_ACTION_CONNECT_WAIT: u32 = 1;
pub(super) const WORKER_ACTION_PARK_FUTEX: u32 = 2;
pub(super) const WORKER_ACTION_HOST_WAIT: u32 = 3;

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
