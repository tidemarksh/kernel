pub(super) fn complete_arm_host_timer(parent_vm_ptr: u32, deadline_ticks: u64) -> i32 {
    if parent_vm_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    let vm = unsafe { &mut *(parent_vm_ptr as *mut crate::types::ThreadState) };
    match vm.status {
        crate::abi::STATUS_SLEEP => {
            sync_completion_deadline(deadline_ticks);
            vm.fault_addr = 0;
            vm.fault_pc = 0;
            vm.status = crate::abi::STATUS_OK;
            super::resume::enqueue_runnable_thread(vm);
            crate::abi::STATUS_OK
        }
        crate::abi::STATUS_FUTEX_WAIT => super::futex::complete_wait(
            parent_vm_ptr,
            super::SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT,
        ),
        crate::abi::STATUS_EPOLL_WAIT => {
            sync_completion_deadline(deadline_ticks);
            crate::syscall::epoll::resume_timeout(vm);
            enqueue_runnable_if_ok(vm);
            vm.status
        }
        crate::abi::STATUS_PIPE_WAIT => {
            sync_completion_deadline(deadline_ticks);
            crate::syscall::poll::resume_poll_timeout(vm, vm.guest_base);
            enqueue_runnable_if_ok(vm);
            vm.status
        }
        crate::abi::STATUS_CONNECT
        | crate::abi::STATUS_SOCKET_RECV
        | crate::abi::STATUS_SOCKET_SEND => {
            sync_completion_deadline(deadline_ticks);
            complete_socket_wait_timer(vm);
            enqueue_runnable_if_ok(vm);
            vm.status
        }
        _ => vm.status,
    }
}

fn sync_completion_deadline(deadline_ticks: u64) {
    if deadline_ticks != 0 {
        crate::syscall::time::sync_monotonic_ticks_floor(deadline_ticks);
    }
}

fn enqueue_runnable_if_ok(vm: &crate::types::ThreadState) {
    if vm.status == crate::abi::STATUS_OK {
        super::resume::enqueue_runnable_thread(vm);
    }
}

fn complete_socket_wait_timer(vm: &mut crate::types::ThreadState) {
    if vm.x[17] == crate::abi::SYS_CONNECT {
        crate::syscall::socket::resume_connect_result(vm, vm.guest_base, crate::abi::ETIMEDOUT);
        return;
    }
    crate::fs::fd_table::clear_blocked_ofd_pin(vm);
    vm.socket_timeout_ms = -1;
    vm.fault_pc = 0;
    vm.fault_addr = 0;
    vm.x[10] = crate::abi::EAGAIN as u64;
    vm.status = crate::abi::STATUS_OK;
}

fn enqueue_timer_request(
    vm: &crate::types::ThreadState,
    delay_ms: u64,
    deadline_ticks: u64,
) -> bool {
    super::host_op::push_request(super::SupervisorHostOpRequest {
        kind: super::SUPERVISOR_HOST_OP_KIND_ARM_HOST_TIMER,
        parent_vm_ptr: vm as *const crate::types::ThreadState as u32,
        child_vm_ptr: 0,
        tid: vm.tid as u32,
        process_ptr: vm.process_ptr,
        status: vm.status as u32,
        detail0: delay_ms,
        detail1: deadline_ticks,
    })
}

pub(super) fn enqueue_futex_wait_timer(vm: &crate::types::ThreadState) -> bool {
    if vm.futex_wait_timeout == 0 {
        return false;
    }
    let delay_ticks = crate::syscall::time::timeout_timespec_delta_ticks(
        vm.guest_base,
        vm.futex_wait_timeout,
        vm.futex_wait_absolute != 0,
        (vm.futex_wait_flags & crate::abi::FUTEX_CLOCK_REALTIME) != 0,
    )
    .unwrap_or(0);
    let delay_ms = crate::syscall::time::ticks_to_millis_ceil(delay_ticks);
    enqueue_timer_request(vm, delay_ms, delay_ticks)
}

pub(super) fn enqueue_sleep_timer(vm: &crate::types::ThreadState) -> bool {
    if vm.fault_addr == 0 && vm.fault_pc == 0 {
        return false;
    }
    let deadline_ticks = crate::syscall::time::sleep_deadline_ticks(vm.fault_addr, vm.fault_pc);
    let delay_ticks =
        deadline_ticks.saturating_sub(crate::syscall::time::monotonic_ticks_current());
    let delay_ms = crate::syscall::time::ticks_to_millis_ceil(delay_ticks);
    enqueue_timer_request(vm, delay_ms, deadline_ticks)
}

pub(super) fn enqueue_blocked_wait_timer(vm: &crate::types::ThreadState, status: i32) -> bool {
    match status {
        crate::abi::STATUS_EPOLL_WAIT => enqueue_epoll_wait_timer(vm),
        crate::abi::STATUS_PIPE_WAIT => enqueue_poll_wait_timer(vm),
        crate::abi::STATUS_CONNECT
        | crate::abi::STATUS_SOCKET_RECV
        | crate::abi::STATUS_SOCKET_SEND => enqueue_socket_wait_timer(vm),
        _ => false,
    }
}

pub(super) fn enqueue_blocked_wait_timer_for_vm(vm_ptr: u32) -> i32 {
    if vm_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if enqueue_blocked_wait_timer(vm, vm.status) {
        1
    } else {
        0
    }
}

pub(super) fn enqueue_blocked_retry_timer_for_vm(vm_ptr: u32, flags: u32) -> i32 {
    if vm_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    let reason = super::blocked::retry_reason(vm_ptr, flags);
    if reason < 0 {
        return reason;
    }
    let delay_ms = super::blocked::retry_delay_ms(vm_ptr, reason as u32);
    if delay_ms < 0 {
        return delay_ms;
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if enqueue_retry_request(vm, delay_ms as u64, reason as u64) {
        1
    } else {
        0
    }
}

fn enqueue_retry_request(vm: &crate::types::ThreadState, delay_ms: u64, reason: u64) -> bool {
    super::host_op::push_request(super::SupervisorHostOpRequest {
        kind: super::SUPERVISOR_HOST_OP_KIND_RETRY_BLOCKED_WORKER,
        parent_vm_ptr: vm as *const crate::types::ThreadState as u32,
        child_vm_ptr: 0,
        tid: vm.tid as u32,
        process_ptr: vm.process_ptr,
        status: vm.status as u32,
        detail0: delay_ms,
        detail1: reason,
    })
}

pub(super) fn blocked_wait_timer_required_for_vm(vm_ptr: u32) -> i32 {
    if vm_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if blocked_wait_timer_required(vm) {
        1
    } else {
        0
    }
}

fn blocked_wait_timer_required(vm: &crate::types::ThreadState) -> bool {
    match vm.status {
        crate::abi::STATUS_EPOLL_WAIT => epoll_wait_timer_required(vm),
        crate::abi::STATUS_PIPE_WAIT => poll_wait_timer_required(vm),
        crate::abi::STATUS_CONNECT
        | crate::abi::STATUS_SOCKET_RECV
        | crate::abi::STATUS_SOCKET_SEND => socket_wait_timer_required(vm),
        _ => false,
    }
}

fn enqueue_epoll_wait_timer(vm: &crate::types::ThreadState) -> bool {
    if vm.epoll_timeout_ms >= 0 {
        return enqueue_timer_request(vm, vm.epoll_timeout_ms as u64, 0);
    }
    let deadline_ticks = crate::syscall::epoll::timerfd_deadline_ticks(vm, vm.guest_base);
    if deadline_ticks == 0 {
        return false;
    }
    let delay_ticks =
        deadline_ticks.saturating_sub(crate::syscall::time::monotonic_ticks_current());
    let delay_ms = crate::syscall::time::ticks_to_millis_ceil(delay_ticks);
    enqueue_timer_request(vm, delay_ms, deadline_ticks)
}

fn epoll_wait_timer_required(vm: &crate::types::ThreadState) -> bool {
    vm.epoll_timeout_ms >= 0
        || crate::syscall::epoll::timerfd_deadline_ticks(vm, vm.guest_base) != 0
}

fn enqueue_poll_wait_timer(vm: &crate::types::ThreadState) -> bool {
    if !poll_wait_timer_required(vm) {
        return false;
    }
    enqueue_timer_request(vm, vm.epoll_timeout_ms as u64, 0)
}

fn poll_wait_timer_required(vm: &crate::types::ThreadState) -> bool {
    vm.epoll_timeout_ms >= 0 && crate::syscall::poll::wait_set_ready_count(vm, vm.guest_base) <= 0
}

fn enqueue_socket_wait_timer(vm: &crate::types::ThreadState) -> bool {
    socket_wait_timer_required(vm) && enqueue_timer_request(vm, vm.socket_timeout_ms as u64, 0)
}

fn socket_wait_timer_required(vm: &crate::types::ThreadState) -> bool {
    vm.socket_timeout_ms >= 0
}
