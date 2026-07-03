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

use crate::types::ThreadState;

const POLLFD_SIZE: u64 = 8;

pub(super) fn status_is_host_wait(status: i32) -> i32 {
    i32::from(matches!(
        status,
        crate::abi::STATUS_WAIT4
            | crate::abi::STATUS_PIPE_WAIT
            | crate::abi::STATUS_EPOLL_WAIT
            | crate::abi::STATUS_SOCKET_RECV
            | crate::abi::STATUS_SOCKET_SEND
            | crate::abi::STATUS_FLOCK_WAIT
            | crate::abi::STATUS_CONNECT
    ))
}

pub(super) fn status_is_connect_wait(status: i32) -> i32 {
    i32::from(status == crate::abi::STATUS_CONNECT)
}

pub(super) fn status_is_epoll_wait(status: i32) -> i32 {
    i32::from(status == crate::abi::STATUS_EPOLL_WAIT)
}

pub(super) fn status_is_pipe_wait(status: i32) -> i32 {
    i32::from(status == crate::abi::STATUS_PIPE_WAIT)
}

pub(super) fn status_is_wait4(status: i32) -> i32 {
    i32::from(status == crate::abi::STATUS_WAIT4)
}

pub(super) fn status_needs_network_sidecar_restore(status: i32) -> i32 {
    i32::from(matches!(
        status,
        crate::abi::STATUS_CONNECT
            | crate::abi::STATUS_SOCKET_RECV
            | crate::abi::STATUS_SOCKET_SEND
            | crate::abi::STATUS_PIPE_WAIT
            | crate::abi::STATUS_EPOLL_WAIT
    ))
}

pub(super) fn status_syncs_socket_after_resume(status: i32) -> i32 {
    i32::from(matches!(
        status,
        crate::abi::STATUS_CONNECT
            | crate::abi::STATUS_SOCKET_RECV
            | crate::abi::STATUS_SOCKET_SEND
    ))
}

pub(super) fn status_uses_fork_shared_state_sync(status: i32) -> i32 {
    i32::from(matches!(
        status,
        crate::abi::STATUS_PIPE_WAIT
            | crate::abi::STATUS_SOCKET_RECV
            | crate::abi::STATUS_SOCKET_SEND
            | crate::abi::STATUS_FLOCK_WAIT
    ))
}

fn status(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).status }
}

fn state(vm_ptr: u32) -> Result<&'static ThreadState, i32> {
    if vm_ptr == 0 {
        return Err(crate::abi::EFAULT as i32);
    }
    Ok(unsafe { &*(vm_ptr as *const ThreadState) })
}

fn active_child_pid_for_blocked_wait(vm: &ThreadState) -> i32 {
    match vm.status {
        crate::abi::STATUS_PIPE_WAIT
            if vm.epoll_timeout_ms < 0
                && !crate::syscall::poll::wait_set_has_socket(vm, vm.guest_base) =>
        {
            let parent_pid = crate::syscall::signal::pid_from_vm(vm, vm.guest_base);
            crate::supervisor::process_lifecycle::active_child_pid(parent_pid)
        }
        crate::abi::STATUS_WAIT4 => {
            let parent_pid = crate::syscall::signal::pid_from_vm(vm, vm.guest_base);
            crate::supervisor::process_lifecycle::active_child_pid(parent_pid)
        }
        _ => 0,
    }
}

fn blocked_or_current_syscall_nr(vm: &ThreadState) -> u64 {
    if vm.blocked_syscall_nr != 0 {
        vm.blocked_syscall_nr
    } else {
        vm.x[17]
    }
}

fn blocked_or_current_syscall_arg(vm: &ThreadState, index: usize) -> u64 {
    if vm.blocked_syscall_nr != 0 {
        vm.blocked_syscall_args[index]
    } else {
        vm.x[10 + index]
    }
}

fn poll_like_syscall(vm: &ThreadState) -> bool {
    let syscall = blocked_or_current_syscall_nr(vm);
    syscall == crate::abi::SYS_PPOLL || syscall == crate::abi::SYS_PSELECT6
}

fn positive_resume_len(resume_result: i64) -> Option<u64> {
    if resume_result > 0 {
        Some(resume_result as u64)
    } else {
        None
    }
}

fn capped_nfds(value: u64) -> u64 {
    value.min(crate::abi::MAX_FDS as u64)
}

fn pselect_set_bytes(nfds: u64) -> u64 {
    ((nfds + 63) / 64) * 8
}

fn raw_blocked_resume_writeback_range(
    vm: &ThreadState,
    blocked_status: i32,
    resume_result: i64,
    index: u32,
) -> Option<(u64, u64)> {
    let resume_len = positive_resume_len(resume_result)?;
    let syscall = blocked_or_current_syscall_nr(vm);
    match (blocked_status, syscall, index) {
        (crate::abi::STATUS_PIPE_WAIT, crate::abi::SYS_PPOLL, 0) => {
            let nfds = capped_nfds(blocked_or_current_syscall_arg(vm, 1));
            (nfds > 0).then(|| {
                (
                    blocked_or_current_syscall_arg(vm, 0),
                    nfds.saturating_mul(POLLFD_SIZE),
                )
            })
        }
        (crate::abi::STATUS_PIPE_WAIT, crate::abi::SYS_PSELECT6, 0..=2) => {
            let nfds = capped_nfds(blocked_or_current_syscall_arg(vm, 0));
            (nfds > 0).then(|| {
                (
                    blocked_or_current_syscall_arg(vm, (index + 1) as usize),
                    pselect_set_bytes(nfds),
                )
            })
        }
        (crate::abi::STATUS_PIPE_WAIT, crate::abi::SYS_READ, 0)
        | (crate::abi::STATUS_SOCKET_RECV, crate::abi::SYS_READ, 0)
        | (crate::abi::STATUS_SOCKET_RECV, crate::abi::SYS_RECVFROM, 0) => {
            Some((blocked_or_current_syscall_arg(vm, 1), resume_len))
        }
        _ => None,
    }
}

fn valid_blocked_resume_writeback_range(
    vm: &ThreadState,
    blocked_status: i32,
    resume_result: i64,
    candidate_index: u32,
) -> Option<(u64, u64)> {
    let (ptr, len) =
        raw_blocked_resume_writeback_range(vm, blocked_status, resume_result, candidate_index)?;
    (ptr > 0 && len > 0).then_some((ptr, len))
}

fn blocked_resume_writeback_range(
    vm: &ThreadState,
    blocked_status: i32,
    resume_result: i64,
    index: u32,
) -> Option<(u64, u64)> {
    (0..3)
        .filter_map(|candidate_index| {
            valid_blocked_resume_writeback_range(vm, blocked_status, resume_result, candidate_index)
        })
        .nth(index as usize)
}

pub(super) fn resume_writeback_count(vm_ptr: u32, blocked_status: i32, resume_result: i64) -> i32 {
    let vm = match state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    (0..3)
        .filter(|candidate_index| {
            valid_blocked_resume_writeback_range(
                vm,
                blocked_status,
                resume_result,
                *candidate_index,
            )
            .is_some()
        })
        .count() as i32
}

pub(super) fn resume_writeback_ptr(
    vm_ptr: u32,
    blocked_status: i32,
    resume_result: i64,
    index: u32,
) -> u64 {
    match state(vm_ptr) {
        Ok(vm) => blocked_resume_writeback_range(vm, blocked_status, resume_result, index)
            .map(|(ptr, _)| ptr)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

pub(super) fn resume_writeback_len(
    vm_ptr: u32,
    blocked_status: i32,
    resume_result: i64,
    index: u32,
) -> u64 {
    match state(vm_ptr) {
        Ok(vm) => blocked_resume_writeback_range(vm, blocked_status, resume_result, index)
            .map(|(_, len)| len)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

pub(super) fn poll_wait_timeout_ms(vm_ptr: u32) -> i64 {
    let vm = match state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -(errno as i64),
    };
    poll_wait_timeout_ms_for_vm(vm)
}

fn poll_wait_timeout_ms_for_vm(vm: &ThreadState) -> i64 {
    if vm.status != crate::abi::STATUS_PIPE_WAIT || !poll_like_syscall(vm) {
        return -1;
    }
    vm.epoll_timeout_ms
}

fn poll_wait_has_socket_for_vm(vm: &ThreadState) -> bool {
    vm.status == crate::abi::STATUS_PIPE_WAIT
        && poll_like_syscall(vm)
        && crate::syscall::poll::wait_set_has_socket(vm, vm.guest_base)
}

fn pipe_wait_ready_count_for_vm(vm: &ThreadState) -> i32 {
    if vm.status != crate::abi::STATUS_PIPE_WAIT {
        return 0;
    }
    crate::syscall::poll::wait_set_ready_count(vm, vm.guest_base)
}

fn blocked_wait_may_depend_on_network_for_vm(vm: &ThreadState) -> bool {
    match vm.status {
        crate::abi::STATUS_PIPE_WAIT => {
            if poll_wait_timeout_ms_for_vm(vm) >= 0 && poll_wait_has_socket_for_vm(vm) {
                return true;
            }
            if pipe_wait_ready_count_for_vm(vm) > 0 {
                return false;
            }
            false
        }
        crate::abi::STATUS_SOCKET_RECV
        | crate::abi::STATUS_SOCKET_SEND
        | crate::abi::STATUS_CONNECT => true,
        _ => false,
    }
}

fn blocked_wait_should_pump_network_for_vm(vm: &ThreadState) -> bool {
    match vm.status {
        crate::abi::STATUS_PIPE_WAIT => {
            blocked_wait_may_depend_on_network_for_vm(vm) || pipe_wait_ready_count_for_vm(vm) <= 0
        }
        crate::abi::STATUS_SOCKET_RECV
        | crate::abi::STATUS_SOCKET_SEND
        | crate::abi::STATUS_CONNECT => true,
        _ => false,
    }
}

pub(super) fn poll_wait_has_socket(vm_ptr: u32) -> i32 {
    match state(vm_ptr) {
        Ok(vm) => i32::from(poll_wait_has_socket_for_vm(vm)),
        Err(errno) => -errno,
    }
}

pub(super) fn pipe_wait_has_ready_events(vm_ptr: u32) -> i32 {
    match state(vm_ptr) {
        Ok(vm) => i32::from(pipe_wait_ready_count_for_vm(vm) > 0),
        Err(errno) => -errno,
    }
}

pub(super) fn blocked_wait_may_depend_on_network(vm_ptr: u32) -> i32 {
    match state(vm_ptr) {
        Ok(vm) => i32::from(blocked_wait_may_depend_on_network_for_vm(vm)),
        Err(errno) => -errno,
    }
}

pub(super) fn blocked_wait_should_pump_network(vm_ptr: u32) -> i32 {
    match state(vm_ptr) {
        Ok(vm) => i32::from(blocked_wait_should_pump_network_for_vm(vm)),
        Err(errno) => -errno,
    }
}

fn pipe_wait_should_remain_passive(vm_ptr: u32, vm: &ThreadState) -> bool {
    if vm.status != crate::abi::STATUS_PIPE_WAIT {
        return false;
    }
    if !poll_like_syscall(vm) {
        return false;
    }
    if vm.epoll_timeout_ms >= 0 {
        return false;
    }
    if crate::syscall::poll::wait_set_has_socket(vm, vm.guest_base) {
        return false;
    }
    if !crate::syscall::poll::wait_set_has_no_watched_fds(vm, vm.guest_base) {
        return false;
    }
    if crate::syscall::poll::wait_set_ready_count(vm, vm.guest_base) > 0 {
        return false;
    }
    if crate::exports::thread::thread_blocked_pipe_read_ready(vm_ptr) == 1
        || crate::exports::thread::thread_blocked_pipe_write_ready(vm_ptr) == 1
    {
        return false;
    }
    if vm.fault_addr == crate::syscall::fs::PIPE_READ_EOF_SYNC_RETRY_MARKER {
        return false;
    }
    !crate::syscall::poll::poll_hup_sync_pending(vm)
}

pub(super) fn blocked_wait_active_child_pid(vm_ptr: u32) -> i32 {
    match state(vm_ptr) {
        Ok(vm) => active_child_pid_for_blocked_wait(vm),
        Err(errno) => -errno,
    }
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
    let vm = match state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
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
    if active_child_pid_for_blocked_wait(vm) > 0 {
        return RETRY_REASON_ACTIVE_CHILD as i32;
    }
    if pipe_wait_should_remain_passive(vm_ptr, vm) {
        return RETRY_REASON_PASSIVE_WAIT as i32;
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
