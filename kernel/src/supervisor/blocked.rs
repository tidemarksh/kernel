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
pub(super) const RETRY_ACTION_FLAG_SUPERVISOR_TIMER_ARMED: u32 = 1;
pub(super) const RETRY_ACTION_FLAG_RPC_PENDING: u32 = 1 << 1;
pub(super) const RETRY_ACTION_FLAG_OWNER_ASYNC: u32 = 1 << 2;
pub(super) const RETRY_ACTION_FLAG_THREAD_INIT_PENDING: u32 = 1 << 3;
pub(super) const RETRY_ACTION_FLAG_FORK_SHARED_SYNC_PENDING: u32 = 1 << 4;
pub(super) const RETRY_ACTION_FLAG_RUNNING_WORKER: u32 = 1 << 5;
pub(super) const RETRY_ACTION_FLAG_KERNEL_WORKER_AVAILABLE: u32 = 1 << 6;
pub(super) const RETRY_ACTION_FLAG_PIPE_STATE_KERNEL_WORKER_OWNS: u32 = 1 << 7;
pub(super) const RETRY_ACTION_FLAG_NETWORK_CONNECTIONS_AVAILABLE: u32 = 1 << 8;
pub(super) const RETRY_ACTION_FLAG_WAIT_TIMER_ALREADY_CHECKED: u32 = 1 << 9;
pub(super) const RETRY_ACTION_DEFER_SUPERVISOR_TIMER: u32 = 0;
pub(super) const RETRY_ACTION_DEFER_RPC_PENDING: u32 = 1;
pub(super) const RETRY_ACTION_DEFER_OWNER_ASYNC: u32 = 2;
pub(super) const RETRY_ACTION_DEFER_THREAD_INIT_PENDING: u32 = 3;
pub(super) const RETRY_ACTION_ARM_WAIT_TIMER: u32 = 4;
pub(super) const RETRY_ACTION_PARK_ACTIVE_CHILD: u32 = 5;
pub(super) const RETRY_ACTION_RESUME_WAIT4: u32 = 6;
pub(super) const RETRY_ACTION_DEFER_FORK_SHARED_SYNC: u32 = 7;
pub(super) const RETRY_ACTION_DEFER_RUNNING_WORKER: u32 = 8;
pub(super) const RETRY_ACTION_DEFER_PROCESS_GATE: u32 = 9;
pub(super) const RETRY_ACTION_PUMP_NETWORK: u32 = 10;
pub(super) const RETRY_ACTION_EPOLL_KERNEL_WORKER: u32 = 11;
pub(super) const RETRY_ACTION_REQUEST_PIPE_SYNC: u32 = 12;
pub(super) const RETRY_ACTION_REQUEST_PIPE_SYNC_AND_DRAIN_OUTPUT: u32 = 13;
pub(super) const RETRY_ACTION_SCHEDULE_PIPE_SYNC_RETRY: u32 = 14;
pub(super) const RETRY_ACTION_RESUME_FS: u32 = 15;
pub(super) const RETRY_ACTION_DEFER_PASSIVE_WAIT: u32 = 16;
pub(super) const RETRY_ACTION_RESUME_KERNEL_WORKER: u32 = 17;
pub(super) const RETRY_ACTION_RESUME_WAIT4_KERNEL_WORKER: u32 = 18;
pub(super) const RETRY_ACTION_RESUME_EPOLL_DIRECT: u32 = 19;
pub(super) const RETRY_ACTION_RESUME_DIRECT: u32 = 20;
pub(super) const RETRY_ACTION_UNSUPPORTED: u32 = 21;
pub(super) const INITIAL_BLOCKED_ACTION_NONE: u32 = 0;
pub(super) const INITIAL_BLOCKED_ACTION_DEFER_SUPERVISOR_TIMER: u32 = 1;
pub(super) const INITIAL_BLOCKED_ACTION_DEFER_RPC_PENDING: u32 = 2;
pub(super) const INITIAL_BLOCKED_ACTION_ARM_WAIT_TIMER: u32 = 3;
pub(super) const INITIAL_BLOCKED_ACTION_RETRY_NOW: u32 = 4;
pub(super) const INITIAL_BLOCKED_ACTION_SCHEDULE_RETRY: u32 = 5;
pub(super) const RESUME_DELEGATION_FLAG_KERNEL_WORKER_AVAILABLE: u32 = 1;
pub(super) const RESUME_DELEGATION_DIRECT: u32 = 0;
pub(super) const RESUME_DELEGATION_KERNEL_WORKER: u32 = 1;
pub(super) const RESUME_DELEGATION_WAIT4_KERNEL_WORKER: u32 = 2;
pub(super) const RESUME_DELEGATION_UNSUPPORTED: u32 = 3;
pub(super) const RESUME_DELEGATION_EPOLL_DIRECT: u32 = 4;
pub(super) const STATUS_TRANSITION_ACTION_BLOCK: u32 = 0;
pub(super) const STATUS_TRANSITION_ACTION_SYNC_SOCKET: u32 = 1;
pub(super) const STATUS_TRANSITION_ACTION_SYNC_PIPE: u32 = 2;
pub(super) const STATUS_TRANSITION_ACTION_SYNC_FORK_SHARED: u32 = 3;
pub(super) const STATUS_TRANSITION_ACTION_SYNC_PIPE_AND_FORK_SHARED: u32 = 4;
pub(super) const STATUS_TRANSITION_ACTION_SYNC_SOCKET_AND_FORK_SHARED: u32 = 5;
pub(super) const STATUS_TRANSITION_FLAG_KERNEL_WORKER_AVAILABLE: u32 = 1;
pub(super) const STATUS_TRANSITION_FLAG_NETWORK_CONNECTIONS_AVAILABLE: u32 = 1 << 1;

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

pub(super) fn status_is_socket_wait(status: i32) -> i32 {
    i32::from(matches!(
        status,
        crate::abi::STATUS_SOCKET_RECV | crate::abi::STATUS_SOCKET_SEND
    ))
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

pub(super) fn status_transition_action_block() -> u32 {
    STATUS_TRANSITION_ACTION_BLOCK
}

pub(super) fn status_transition_action_sync_socket() -> u32 {
    STATUS_TRANSITION_ACTION_SYNC_SOCKET
}

pub(super) fn status_transition_action_sync_pipe() -> u32 {
    STATUS_TRANSITION_ACTION_SYNC_PIPE
}

pub(super) fn status_transition_action_sync_fork_shared() -> u32 {
    STATUS_TRANSITION_ACTION_SYNC_FORK_SHARED
}

pub(super) fn status_transition_action_sync_pipe_and_fork_shared() -> u32 {
    STATUS_TRANSITION_ACTION_SYNC_PIPE_AND_FORK_SHARED
}

pub(super) fn status_transition_action_sync_socket_and_fork_shared() -> u32 {
    STATUS_TRANSITION_ACTION_SYNC_SOCKET_AND_FORK_SHARED
}

pub(super) fn status_transition_flag_kernel_worker_available() -> u32 {
    STATUS_TRANSITION_FLAG_KERNEL_WORKER_AVAILABLE
}

pub(super) fn status_transition_flag_network_connections_available() -> u32 {
    STATUS_TRANSITION_FLAG_NETWORK_CONNECTIONS_AVAILABLE
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

fn vfork_process_gate_blocks(vm: &ThreadState) -> bool {
    if !crate::syscall::process::vfork_active() {
        return false;
    }
    let child_pid = crate::syscall::process::vfork_child_pid();
    if child_pid <= 0 {
        return false;
    }
    crate::syscall::process::current_process_pid(vm, vm.guest_base) != child_pid
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

pub(super) fn status_transition_action(vm_ptr: u32, status: i32, flags: u32) -> i32 {
    let vm = match state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    let kernel_worker_available = (flags & STATUS_TRANSITION_FLAG_KERNEL_WORKER_AVAILABLE) != 0;
    if !kernel_worker_available {
        return STATUS_TRANSITION_ACTION_BLOCK as i32;
    }

    let pipe_wait_status = status == crate::abi::STATUS_PIPE_WAIT;
    let network_connections_available =
        (flags & STATUS_TRANSITION_FLAG_NETWORK_CONNECTIONS_AVAILABLE) != 0;
    let pipe_wait_has_socket =
        pipe_wait_status && network_connections_available && poll_wait_has_socket_for_vm(vm);
    if pipe_wait_has_socket {
        return STATUS_TRANSITION_ACTION_SYNC_SOCKET as i32;
    }

    if status == crate::abi::STATUS_WAIT4 {
        return STATUS_TRANSITION_ACTION_SYNC_PIPE as i32;
    }

    let finite_poll_timeout = pipe_wait_status && poll_wait_timeout_ms_for_vm(vm) >= 0;
    if status_uses_fork_shared_state_sync(status) == 0 || finite_poll_timeout {
        return STATUS_TRANSITION_ACTION_BLOCK as i32;
    }

    match status {
        crate::abi::STATUS_PIPE_WAIT => STATUS_TRANSITION_ACTION_SYNC_PIPE_AND_FORK_SHARED as i32,
        crate::abi::STATUS_SOCKET_RECV | crate::abi::STATUS_SOCKET_SEND => {
            STATUS_TRANSITION_ACTION_SYNC_SOCKET_AND_FORK_SHARED as i32
        }
        _ => STATUS_TRANSITION_ACTION_SYNC_FORK_SHARED as i32,
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

pub(super) fn resume_flag_timeout_expired() -> u32 {
    RESUME_FLAG_TIMEOUT_EXPIRED
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

pub(super) fn retry_action_flag_supervisor_timer_armed() -> u32 {
    RETRY_ACTION_FLAG_SUPERVISOR_TIMER_ARMED
}

pub(super) fn retry_action_flag_rpc_pending() -> u32 {
    RETRY_ACTION_FLAG_RPC_PENDING
}

pub(super) fn retry_action_flag_owner_async() -> u32 {
    RETRY_ACTION_FLAG_OWNER_ASYNC
}

pub(super) fn retry_action_flag_thread_init_pending() -> u32 {
    RETRY_ACTION_FLAG_THREAD_INIT_PENDING
}

pub(super) fn retry_action_flag_fork_shared_sync_pending() -> u32 {
    RETRY_ACTION_FLAG_FORK_SHARED_SYNC_PENDING
}

pub(super) fn retry_action_flag_running_worker() -> u32 {
    RETRY_ACTION_FLAG_RUNNING_WORKER
}

pub(super) fn retry_action_flag_kernel_worker_available() -> u32 {
    RETRY_ACTION_FLAG_KERNEL_WORKER_AVAILABLE
}

pub(super) fn retry_action_flag_pipe_state_kernel_worker_owns() -> u32 {
    RETRY_ACTION_FLAG_PIPE_STATE_KERNEL_WORKER_OWNS
}

pub(super) fn retry_action_flag_network_connections_available() -> u32 {
    RETRY_ACTION_FLAG_NETWORK_CONNECTIONS_AVAILABLE
}

pub(super) fn retry_action_flag_wait_timer_already_checked() -> u32 {
    RETRY_ACTION_FLAG_WAIT_TIMER_ALREADY_CHECKED
}

pub(super) fn retry_action_defer_supervisor_timer() -> u32 {
    RETRY_ACTION_DEFER_SUPERVISOR_TIMER
}

pub(super) fn retry_action_defer_rpc_pending() -> u32 {
    RETRY_ACTION_DEFER_RPC_PENDING
}

pub(super) fn retry_action_defer_owner_async() -> u32 {
    RETRY_ACTION_DEFER_OWNER_ASYNC
}

pub(super) fn retry_action_defer_thread_init_pending() -> u32 {
    RETRY_ACTION_DEFER_THREAD_INIT_PENDING
}

pub(super) fn retry_action_arm_wait_timer() -> u32 {
    RETRY_ACTION_ARM_WAIT_TIMER
}

pub(super) fn retry_action_park_active_child() -> u32 {
    RETRY_ACTION_PARK_ACTIVE_CHILD
}

pub(super) fn retry_action_resume_wait4() -> u32 {
    RETRY_ACTION_RESUME_WAIT4
}

pub(super) fn retry_action_defer_fork_shared_sync() -> u32 {
    RETRY_ACTION_DEFER_FORK_SHARED_SYNC
}

pub(super) fn retry_action_defer_running_worker() -> u32 {
    RETRY_ACTION_DEFER_RUNNING_WORKER
}

pub(super) fn retry_action_defer_process_gate() -> u32 {
    RETRY_ACTION_DEFER_PROCESS_GATE
}

pub(super) fn retry_action_pump_network() -> u32 {
    RETRY_ACTION_PUMP_NETWORK
}

pub(super) fn retry_action_epoll_kernel_worker() -> u32 {
    RETRY_ACTION_EPOLL_KERNEL_WORKER
}

pub(super) fn retry_action_request_pipe_sync() -> u32 {
    RETRY_ACTION_REQUEST_PIPE_SYNC
}

pub(super) fn retry_action_request_pipe_sync_and_drain_output() -> u32 {
    RETRY_ACTION_REQUEST_PIPE_SYNC_AND_DRAIN_OUTPUT
}

pub(super) fn retry_action_schedule_pipe_sync_retry() -> u32 {
    RETRY_ACTION_SCHEDULE_PIPE_SYNC_RETRY
}

pub(super) fn retry_action_resume_fs() -> u32 {
    RETRY_ACTION_RESUME_FS
}

pub(super) fn retry_action_defer_passive_wait() -> u32 {
    RETRY_ACTION_DEFER_PASSIVE_WAIT
}

pub(super) fn retry_action_resume_kernel_worker() -> u32 {
    RETRY_ACTION_RESUME_KERNEL_WORKER
}

pub(super) fn retry_action_resume_wait4_kernel_worker() -> u32 {
    RETRY_ACTION_RESUME_WAIT4_KERNEL_WORKER
}

pub(super) fn retry_action_resume_epoll_direct() -> u32 {
    RETRY_ACTION_RESUME_EPOLL_DIRECT
}

pub(super) fn retry_action_resume_direct() -> u32 {
    RETRY_ACTION_RESUME_DIRECT
}

pub(super) fn retry_action_unsupported() -> u32 {
    RETRY_ACTION_UNSUPPORTED
}

pub(super) fn initial_action_none() -> u32 {
    INITIAL_BLOCKED_ACTION_NONE
}

pub(super) fn initial_action_defer_supervisor_timer() -> u32 {
    INITIAL_BLOCKED_ACTION_DEFER_SUPERVISOR_TIMER
}

pub(super) fn initial_action_defer_rpc_pending() -> u32 {
    INITIAL_BLOCKED_ACTION_DEFER_RPC_PENDING
}

pub(super) fn initial_action_arm_wait_timer() -> u32 {
    INITIAL_BLOCKED_ACTION_ARM_WAIT_TIMER
}

pub(super) fn initial_action_retry_now() -> u32 {
    INITIAL_BLOCKED_ACTION_RETRY_NOW
}

pub(super) fn initial_action_schedule_retry() -> u32 {
    INITIAL_BLOCKED_ACTION_SCHEDULE_RETRY
}

pub(super) fn initial_action(vm_ptr: u32, blocked_status: i32, flags: u32) -> i32 {
    if let Err(errno) = state(vm_ptr) {
        return -errno;
    }

    if !matches!(
        blocked_status,
        crate::abi::STATUS_WAIT4
            | crate::abi::STATUS_PIPE_WAIT
            | crate::abi::STATUS_EPOLL_WAIT
            | crate::abi::STATUS_SOCKET_RECV
            | crate::abi::STATUS_SOCKET_SEND
            | crate::abi::STATUS_FLOCK_WAIT
            | crate::abi::STATUS_CONNECT
            | crate::abi::STATUS_FS
    ) {
        return INITIAL_BLOCKED_ACTION_NONE as i32;
    }

    if (flags & RETRY_ACTION_FLAG_SUPERVISOR_TIMER_ARMED) != 0 {
        return INITIAL_BLOCKED_ACTION_DEFER_SUPERVISOR_TIMER as i32;
    }
    if (flags & RETRY_ACTION_FLAG_RPC_PENDING) != 0 {
        return INITIAL_BLOCKED_ACTION_DEFER_RPC_PENDING as i32;
    }

    let wait_timer_required = super::timer::blocked_wait_timer_required_for_vm(vm_ptr);
    if wait_timer_required < 0 {
        return wait_timer_required;
    }
    if wait_timer_required != 0 {
        return INITIAL_BLOCKED_ACTION_ARM_WAIT_TIMER as i32;
    }

    match blocked_status {
        crate::abi::STATUS_EPOLL_WAIT => match epoll_wait_retry_required(vm_ptr) {
            retry_required if retry_required < 0 => retry_required,
            0 => INITIAL_BLOCKED_ACTION_NONE as i32,
            _ => INITIAL_BLOCKED_ACTION_SCHEDULE_RETRY as i32,
        },
        crate::abi::STATUS_WAIT4 => INITIAL_BLOCKED_ACTION_RETRY_NOW as i32,
        _ => INITIAL_BLOCKED_ACTION_SCHEDULE_RETRY as i32,
    }
}

pub(super) fn retry_reason(vm_ptr: u32, flags: u32) -> i32 {
    let vm = match state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    if (flags & RETRY_FLAG_PROCESS_GATE) != 0 {
        return RETRY_REASON_PROCESS_GATE as i32;
    }
    if vfork_process_gate_blocks(vm) {
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

fn retry_action_pipe_sync(vm_ptr: u32, flags: u32) -> i32 {
    let pipe_flags = if (flags & RETRY_ACTION_FLAG_PIPE_STATE_KERNEL_WORKER_OWNS) != 0 {
        super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_FLAG_KERNEL_WORKER_AVAILABLE
    } else {
        0
    };
    match super::pipe::blocked_pipe_sync_before_retry_action(vm_ptr, pipe_flags) {
        action if action == super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_REQUEST_SYNC as i32 => {
            RETRY_ACTION_REQUEST_PIPE_SYNC as i32
        }
        action
            if action
                == super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_REQUEST_SYNC_AND_DRAIN_OUTPUT
                    as i32 =>
        {
            RETRY_ACTION_REQUEST_PIPE_SYNC_AND_DRAIN_OUTPUT as i32
        }
        action
            if action == super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_SCHEDULE_RETRY as i32 =>
        {
            RETRY_ACTION_SCHEDULE_PIPE_SYNC_RETRY as i32
        }
        action if action == super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_NONE as i32 => {
            RETRY_ACTION_RESUME_DIRECT as i32
        }
        errno if errno < 0 => errno,
        _ => -(crate::abi::EINVAL as i32),
    }
}

fn retry_action_resume_delegation(vm_ptr: u32, flags: u32) -> i32 {
    let resume_flags = if (flags & RETRY_ACTION_FLAG_KERNEL_WORKER_AVAILABLE) != 0 {
        RESUME_DELEGATION_FLAG_KERNEL_WORKER_AVAILABLE
    } else {
        0
    };
    match resume_delegation(vm_ptr, resume_flags) {
        action if action == RESUME_DELEGATION_KERNEL_WORKER as i32 => {
            RETRY_ACTION_RESUME_KERNEL_WORKER as i32
        }
        action if action == RESUME_DELEGATION_WAIT4_KERNEL_WORKER as i32 => {
            RETRY_ACTION_RESUME_WAIT4_KERNEL_WORKER as i32
        }
        action if action == RESUME_DELEGATION_EPOLL_DIRECT as i32 => {
            RETRY_ACTION_RESUME_EPOLL_DIRECT as i32
        }
        action if action == RESUME_DELEGATION_DIRECT as i32 => RETRY_ACTION_RESUME_DIRECT as i32,
        action if action == RESUME_DELEGATION_UNSUPPORTED as i32 => RETRY_ACTION_UNSUPPORTED as i32,
        errno if errno < 0 => errno,
        _ => -(crate::abi::EINVAL as i32),
    }
}

pub(super) fn retry_action(vm_ptr: u32, flags: u32) -> i32 {
    let vm = match state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };

    if (flags & RETRY_ACTION_FLAG_SUPERVISOR_TIMER_ARMED) != 0 {
        return RETRY_ACTION_DEFER_SUPERVISOR_TIMER as i32;
    }
    if (flags & RETRY_ACTION_FLAG_RPC_PENDING) != 0 {
        return RETRY_ACTION_DEFER_RPC_PENDING as i32;
    }
    if (flags & RETRY_ACTION_FLAG_OWNER_ASYNC) != 0 {
        return RETRY_ACTION_DEFER_OWNER_ASYNC as i32;
    }
    if vm.status == crate::abi::STATUS_EPOLL_WAIT
        && (flags & RETRY_ACTION_FLAG_THREAD_INIT_PENDING) != 0
    {
        return RETRY_ACTION_DEFER_THREAD_INIT_PENDING as i32;
    }
    if (flags & RETRY_ACTION_FLAG_WAIT_TIMER_ALREADY_CHECKED) == 0 {
        let wait_timer_required = super::timer::blocked_wait_timer_required_for_vm(vm_ptr);
        if wait_timer_required < 0 {
            return wait_timer_required;
        }
        if wait_timer_required != 0 {
            return RETRY_ACTION_ARM_WAIT_TIMER as i32;
        }
    }
    if active_child_pid_for_blocked_wait(vm) > 0 {
        return RETRY_ACTION_PARK_ACTIVE_CHILD as i32;
    }
    if vm.status == crate::abi::STATUS_WAIT4 {
        if (flags & RETRY_ACTION_FLAG_KERNEL_WORKER_AVAILABLE) != 0 {
            return RETRY_ACTION_RESUME_WAIT4_KERNEL_WORKER as i32;
        }
        return RETRY_ACTION_RESUME_WAIT4 as i32;
    }
    if (flags & RETRY_ACTION_FLAG_FORK_SHARED_SYNC_PENDING) != 0
        && poll_wait_timeout_ms_for_vm(vm) < 0
    {
        return RETRY_ACTION_DEFER_FORK_SHARED_SYNC as i32;
    }
    if (flags & RETRY_ACTION_FLAG_RUNNING_WORKER) != 0 {
        return RETRY_ACTION_DEFER_RUNNING_WORKER as i32;
    }
    let reason = retry_reason(vm_ptr, 0);
    if reason < 0 {
        return reason;
    }
    if reason == RETRY_REASON_PROCESS_GATE as i32 {
        return RETRY_ACTION_DEFER_PROCESS_GATE as i32;
    }
    if (flags & RETRY_ACTION_FLAG_NETWORK_CONNECTIONS_AVAILABLE) != 0
        && blocked_wait_should_pump_network_for_vm(vm)
    {
        match super::network::blocked_wait_pump_action(vm_ptr) {
            action if action == super::network::pump_action_pump() as i32 => {
                return RETRY_ACTION_PUMP_NETWORK as i32;
            }
            action if action == super::network::pump_action_skip() as i32 => {}
            errno if errno < 0 => return errno,
            _ => return -(crate::abi::EINVAL as i32),
        }
    }
    if vm.status == crate::abi::STATUS_EPOLL_WAIT
        && (flags & RETRY_ACTION_FLAG_KERNEL_WORKER_AVAILABLE) != 0
    {
        return RETRY_ACTION_EPOLL_KERNEL_WORKER as i32;
    }
    if vm.status == crate::abi::STATUS_PIPE_WAIT {
        let pipe_action = retry_action_pipe_sync(vm_ptr, flags);
        if pipe_action < 0 || pipe_action != RETRY_ACTION_RESUME_DIRECT as i32 {
            return pipe_action;
        }
    }
    if vm.status == crate::abi::STATUS_FS {
        return RETRY_ACTION_RESUME_FS as i32;
    }
    let reason = retry_reason(vm_ptr, 0);
    if reason < 0 {
        return reason;
    }
    if reason == RETRY_REASON_PASSIVE_WAIT as i32 {
        return RETRY_ACTION_DEFER_PASSIVE_WAIT as i32;
    }
    retry_action_resume_delegation(vm_ptr, flags)
}

pub(super) fn epoll_wait_retry_required(vm_ptr: u32) -> i32 {
    let vm = match state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    i32::from(
        vm.status == crate::abi::STATUS_EPOLL_WAIT
            && super::thread::process_thread_count(vm_ptr, vm.guest_base) > 1,
    )
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
