pub(super) const STATUS_ACTION_NONE: u32 = 0;
pub(super) const STATUS_ACTION_BLOCK_EPOLL_TIMEOUT: u32 = 1;
pub(super) const STATUS_ACTION_PARK_FUTEX: u32 = 1 << 1;
pub(super) const STATUS_ACTION_BLOCK_WAIT4_AND_SYNC_PIPE: u32 = 1 << 2;
pub(super) const STATUS_ACTION_SYNC_SOCKET: u32 = 1 << 3;
pub(super) const STATUS_ACTION_SYNC_EPOLL: u32 = 1 << 4;
pub(super) const STATUS_ACTION_SYNC_PIPE: u32 = 1 << 5;
pub(super) const STATUS_ACTION_DRAIN_LOCAL_PIPE: u32 = 1 << 6;

pub(super) const STATUS_ACTION_FLAG_RUNNING_WORKER: u32 = 1;
pub(super) const STATUS_ACTION_FLAG_KERNEL_WORKER_AVAILABLE: u32 = 1 << 1;
pub(super) const STATUS_ACTION_FLAG_EPOLL_STATE_KERNEL_OWNS: u32 = 1 << 2;

pub(super) fn status_action_none() -> u32 {
    STATUS_ACTION_NONE
}

pub(super) fn status_action_block_epoll_timeout() -> u32 {
    STATUS_ACTION_BLOCK_EPOLL_TIMEOUT
}

pub(super) fn status_action_park_futex() -> u32 {
    STATUS_ACTION_PARK_FUTEX
}

pub(super) fn status_action_block_wait4_and_sync_pipe() -> u32 {
    STATUS_ACTION_BLOCK_WAIT4_AND_SYNC_PIPE
}

pub(super) fn status_action_sync_socket() -> u32 {
    STATUS_ACTION_SYNC_SOCKET
}

pub(super) fn status_action_sync_epoll() -> u32 {
    STATUS_ACTION_SYNC_EPOLL
}

pub(super) fn status_action_sync_pipe() -> u32 {
    STATUS_ACTION_SYNC_PIPE
}

pub(super) fn status_action_drain_local_pipe() -> u32 {
    STATUS_ACTION_DRAIN_LOCAL_PIPE
}

pub(super) fn status_action_flag_running_worker() -> u32 {
    STATUS_ACTION_FLAG_RUNNING_WORKER
}

pub(super) fn status_action_flag_kernel_worker_available() -> u32 {
    STATUS_ACTION_FLAG_KERNEL_WORKER_AVAILABLE
}

pub(super) fn status_action_flag_epoll_state_kernel_owns() -> u32 {
    STATUS_ACTION_FLAG_EPOLL_STATE_KERNEL_OWNS
}

pub(super) fn status_action(vm_ptr: u32, status: i32, flags: u32) -> i32 {
    let running_worker = (flags & STATUS_ACTION_FLAG_RUNNING_WORKER) != 0;
    let kernel_worker_available = (flags & STATUS_ACTION_FLAG_KERNEL_WORKER_AVAILABLE) != 0;
    let epoll_state_kernel_owns = (flags & STATUS_ACTION_FLAG_EPOLL_STATE_KERNEL_OWNS) != 0;
    let mut actions = STATUS_ACTION_NONE;
    if !kernel_worker_available {
        actions |= STATUS_ACTION_DRAIN_LOCAL_PIPE;
    }

    if status == crate::abi::STATUS_EPOLL_WAIT {
        if vm_ptr == 0 {
            return crate::abi::EFAULT as i32;
        }
        let timeout_ms = super::timer::epoll_wait_timeout_ms_for_vm(vm_ptr);
        if timeout_ms < -1 {
            return timeout_ms as i32;
        }
        if timeout_ms == 0 {
            return (actions | STATUS_ACTION_BLOCK_EPOLL_TIMEOUT) as i32;
        }
    }

    if status == crate::abi::STATUS_FUTEX_WAIT {
        return (actions | STATUS_ACTION_PARK_FUTEX) as i32;
    }

    if kernel_worker_available && status == crate::abi::STATUS_WAIT4 {
        return (actions | STATUS_ACTION_BLOCK_WAIT4_AND_SYNC_PIPE) as i32;
    }

    if !running_worker {
        return actions as i32;
    }

    if kernel_worker_available
        && matches!(
            status,
            crate::abi::STATUS_SOCKET_RECV | crate::abi::STATUS_SOCKET_SEND
        )
    {
        actions |= STATUS_ACTION_SYNC_SOCKET;
    }
    if epoll_state_kernel_owns
        && matches!(
            status,
            crate::abi::STATUS_EPOLL_WAIT
                | crate::abi::STATUS_SOCKET_RECV
                | crate::abi::STATUS_SOCKET_SEND
        )
    {
        actions |= STATUS_ACTION_SYNC_EPOLL;
    }
    if kernel_worker_available && status == crate::abi::STATUS_PIPE_WAIT {
        actions |= STATUS_ACTION_SYNC_PIPE;
    }
    actions as i32
}
