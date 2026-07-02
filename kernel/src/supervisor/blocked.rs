pub(super) const RESUME_FLAG_TIMEOUT_EXPIRED: u32 = 1;
pub(super) const RETRY_REASON_DEFAULT: u32 = 0;
pub(super) const RETRY_REASON_IMMEDIATE: u32 = 1;
pub(super) const RETRY_REASON_STANDARD_DEFER: u32 = 2;
pub(super) const RETRY_REASON_ACTIVE_CHILD: u32 = 3;
pub(super) const RETRY_REASON_PASSIVE_WAIT: u32 = 4;
pub(super) const RETRY_REASON_PROCESS_GATE: u32 = 5;
pub(super) const RETRY_FLAG_HOST_PROGRESS: u32 = 1;
pub(super) const RETRY_FLAG_ACTIVE_CHILD: u32 = 1 << 1;
pub(super) const RETRY_FLAG_PASSIVE_WAIT: u32 = 1 << 2;
pub(super) const RETRY_FLAG_PROCESS_GATE: u32 = 1 << 3;
pub(super) const RETRY_FLAG_THREAD_INIT_PENDING: u32 = 1 << 4;
pub(super) const RESUME_DELEGATION_FLAG_KERNEL_WORKER_AVAILABLE: u32 = 1;
pub(super) const RESUME_DELEGATION_DIRECT: u32 = 0;
pub(super) const RESUME_DELEGATION_KERNEL_WORKER: u32 = 1;
pub(super) const RESUME_DELEGATION_WAIT4_KERNEL_WORKER: u32 = 2;
pub(super) const RESUME_DELEGATION_UNSUPPORTED: u32 = 3;
pub(super) const RESUME_DELEGATION_EPOLL_DIRECT: u32 = 4;

fn status(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).status }
}

fn resume_socket_wait_timeout(vm_ptr: u32) -> i64 {
    crate::exports::thread::thread_resume_socket_wait_timeout(vm_ptr);
    0
}

fn resume_epoll_wait_timeout(vm_ptr: u32) -> i64 {
    crate::exports::thread::thread_resume_epoll_wait_timeout(vm_ptr);
    0
}

fn resume_poll_wait_timeout(vm_ptr: u32) -> i64 {
    crate::exports::thread::thread_resume_poll_wait_timeout(vm_ptr);
    0
}

pub(super) fn resume_blocked_syscall(vm_ptr: u32, flags: u32) -> i64 {
    if vm_ptr == 0 {
        return -(crate::abi::EFAULT as i64);
    }

    let timeout_expired = (flags & RESUME_FLAG_TIMEOUT_EXPIRED) != 0;
    match (status(vm_ptr), timeout_expired) {
        (crate::abi::STATUS_WAIT4, _) => crate::exports::thread::thread_resume_wait4(vm_ptr),
        (
            crate::abi::STATUS_CONNECT
            | crate::abi::STATUS_SOCKET_RECV
            | crate::abi::STATUS_SOCKET_SEND,
            true,
        ) => resume_socket_wait_timeout(vm_ptr),
        (crate::abi::STATUS_EPOLL_WAIT, true) => resume_epoll_wait_timeout(vm_ptr),
        (crate::abi::STATUS_PIPE_WAIT, true) => resume_poll_wait_timeout(vm_ptr),
        _ => crate::exports::thread::thread_resume_blocked_syscall(vm_ptr),
    }
}

pub(super) fn retry_reason_default() -> u32 {
    RETRY_REASON_DEFAULT
}

pub(super) fn retry_reason_immediate() -> u32 {
    RETRY_REASON_IMMEDIATE
}

pub(super) fn retry_reason_standard_defer() -> u32 {
    RETRY_REASON_STANDARD_DEFER
}

pub(super) fn retry_reason_active_child() -> u32 {
    RETRY_REASON_ACTIVE_CHILD
}

pub(super) fn retry_reason_passive_wait() -> u32 {
    RETRY_REASON_PASSIVE_WAIT
}

pub(super) fn retry_reason_process_gate() -> u32 {
    RETRY_REASON_PROCESS_GATE
}

pub(super) fn retry_flag_host_progress() -> u32 {
    RETRY_FLAG_HOST_PROGRESS
}

pub(super) fn retry_flag_active_child() -> u32 {
    RETRY_FLAG_ACTIVE_CHILD
}

pub(super) fn retry_flag_passive_wait() -> u32 {
    RETRY_FLAG_PASSIVE_WAIT
}

pub(super) fn retry_flag_process_gate() -> u32 {
    RETRY_FLAG_PROCESS_GATE
}

pub(super) fn retry_flag_thread_init_pending() -> u32 {
    RETRY_FLAG_THREAD_INIT_PENDING
}

pub(super) fn retry_reason(vm_ptr: u32, flags: u32) -> i32 {
    if vm_ptr == 0 {
        return -(crate::abi::EFAULT as i32);
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if (flags & RETRY_FLAG_PROCESS_GATE) != 0 {
        return RETRY_REASON_PROCESS_GATE as i32;
    }
    if (flags & RETRY_FLAG_ACTIVE_CHILD) != 0 {
        return RETRY_REASON_ACTIVE_CHILD as i32;
    }
    if (flags & RETRY_FLAG_PASSIVE_WAIT) != 0 {
        return RETRY_REASON_PASSIVE_WAIT as i32;
    }
    if (flags & RETRY_FLAG_HOST_PROGRESS) != 0 {
        return RETRY_REASON_IMMEDIATE as i32;
    }
    if (flags & RETRY_FLAG_THREAD_INIT_PENDING) != 0 {
        return RETRY_REASON_STANDARD_DEFER as i32;
    }
    match vm.status {
        crate::abi::STATUS_EPOLL_WAIT
            if super::thread::process_thread_count(vm_ptr, vm.guest_base) > 1 =>
        {
            RETRY_REASON_STANDARD_DEFER as i32
        }
        crate::abi::STATUS_PIPE_WAIT
            if crate::syscall::poll::wait_set_ready_count(vm, vm.guest_base) > 0 =>
        {
            RETRY_REASON_IMMEDIATE as i32
        }
        _ => RETRY_REASON_DEFAULT as i32,
    }
}

pub(super) fn retry_delay_ms(vm_ptr: u32, reason: u32) -> i32 {
    if vm_ptr == 0 {
        return -(crate::abi::EFAULT as i32);
    }
    match reason {
        RETRY_REASON_IMMEDIATE => 0,
        RETRY_REASON_STANDARD_DEFER => 10,
        RETRY_REASON_ACTIVE_CHILD => 5,
        RETRY_REASON_PASSIVE_WAIT => 25,
        RETRY_REASON_PROCESS_GATE => 50,
        _ => {
            if status(vm_ptr) == crate::abi::STATUS_WAIT4 {
                10
            } else {
                1
            }
        }
    }
}

pub(super) fn resume_delegation_flag_kernel_worker_available() -> u32 {
    RESUME_DELEGATION_FLAG_KERNEL_WORKER_AVAILABLE
}

pub(super) fn resume_delegation_direct() -> u32 {
    RESUME_DELEGATION_DIRECT
}

pub(super) fn resume_delegation_kernel_worker() -> u32 {
    RESUME_DELEGATION_KERNEL_WORKER
}

pub(super) fn resume_delegation_wait4_kernel_worker() -> u32 {
    RESUME_DELEGATION_WAIT4_KERNEL_WORKER
}

pub(super) fn resume_delegation_unsupported() -> u32 {
    RESUME_DELEGATION_UNSUPPORTED
}

pub(super) fn resume_delegation_epoll_direct() -> u32 {
    RESUME_DELEGATION_EPOLL_DIRECT
}

pub(super) fn resume_delegation(vm_ptr: u32, flags: u32) -> i32 {
    if vm_ptr == 0 {
        return -(crate::abi::EFAULT as i32);
    }

    let kernel_worker_available = (flags & RESUME_DELEGATION_FLAG_KERNEL_WORKER_AVAILABLE) != 0;
    if kernel_worker_available {
        return match status(vm_ptr) {
            crate::abi::STATUS_PIPE_WAIT
            | crate::abi::STATUS_CONNECT
            | crate::abi::STATUS_SOCKET_RECV
            | crate::abi::STATUS_SOCKET_SEND
            | crate::abi::STATUS_FLOCK_WAIT => RESUME_DELEGATION_KERNEL_WORKER as i32,
            crate::abi::STATUS_WAIT4 => RESUME_DELEGATION_WAIT4_KERNEL_WORKER as i32,
            _ => RESUME_DELEGATION_UNSUPPORTED as i32,
        };
    }

    match status(vm_ptr) {
        crate::abi::STATUS_EPOLL_WAIT => RESUME_DELEGATION_EPOLL_DIRECT as i32,
        _ => RESUME_DELEGATION_DIRECT as i32,
    }
}
