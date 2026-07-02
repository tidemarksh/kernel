pub(super) const RESUME_FLAG_TIMEOUT_EXPIRED: u32 = 1;
pub(super) const RETRY_REASON_DEFAULT: u32 = 0;
pub(super) const RETRY_REASON_IMMEDIATE: u32 = 1;
pub(super) const RETRY_REASON_STANDARD_DEFER: u32 = 2;
pub(super) const RETRY_REASON_ACTIVE_CHILD: u32 = 3;
pub(super) const RETRY_REASON_PASSIVE_WAIT: u32 = 4;
pub(super) const RETRY_REASON_PROCESS_GATE: u32 = 5;

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
