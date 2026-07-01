pub(super) const RESUME_FLAG_TIMEOUT_EXPIRED: u32 = 1;

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
