macro_rules! export_u32_const {
    ($name:ident, $value:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $name() -> u32 {
            $value
        }
    };
}

export_u32_const!(supervisor_abi_version, super::SUPERVISOR_ABI_VERSION);
export_u32_const!(
    supervisor_debug_snapshot_bytes,
    super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES
);
export_u32_const!(
    supervisor_thread_event_record_bytes,
    super::SUPERVISOR_THREAD_EVENT_RECORD_BYTES
);
export_u32_const!(
    supervisor_thread_event_kind_blocked,
    super::SUPERVISOR_THREAD_EVENT_KIND_BLOCKED
);
export_u32_const!(
    supervisor_thread_event_kind_ready,
    super::SUPERVISOR_THREAD_EVENT_KIND_READY
);
export_u32_const!(
    supervisor_thread_event_kind_faulted,
    super::SUPERVISOR_THREAD_EVENT_KIND_FAULTED
);
export_u32_const!(
    supervisor_thread_event_kind_exited,
    super::SUPERVISOR_THREAD_EVENT_KIND_EXITED
);
export_u32_const!(
    supervisor_thread_event_kind_host_completion_arrived,
    super::SUPERVISOR_THREAD_EVENT_KIND_HOST_COMPLETION_ARRIVED
);
export_u32_const!(
    supervisor_thread_event_kind_timer_fired,
    super::SUPERVISOR_THREAD_EVENT_KIND_TIMER_FIRED
);
export_u32_const!(
    supervisor_thread_event_kind_network_readable,
    super::SUPERVISOR_THREAD_EVENT_KIND_NETWORK_READABLE
);
export_u32_const!(
    supervisor_thread_event_kind_backing_store_ready,
    super::SUPERVISOR_THREAD_EVENT_KIND_BACKING_STORE_READY
);
export_u32_const!(
    supervisor_thread_state_snapshot_bytes,
    super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES
);
export_u32_const!(
    supervisor_resume_record_bytes,
    super::SUPERVISOR_RESUME_RECORD_BYTES
);
export_u32_const!(
    supervisor_host_completion_record_bytes,
    super::SUPERVISOR_HOST_COMPLETION_RECORD_BYTES
);
export_u32_const!(
    supervisor_host_completion_outcome_success,
    super::SUPERVISOR_HOST_COMPLETION_OUTCOME_SUCCESS
);
export_u32_const!(
    supervisor_host_completion_outcome_failure,
    super::SUPERVISOR_HOST_COMPLETION_OUTCOME_FAILURE
);
export_u32_const!(
    supervisor_host_op_record_bytes,
    super::SUPERVISOR_HOST_OP_RECORD_BYTES
);
export_u32_const!(
    supervisor_host_op_kind_spawn_thread_worker,
    super::SUPERVISOR_HOST_OP_KIND_SPAWN_THREAD_WORKER
);
export_u32_const!(
    supervisor_host_op_kind_spawn_process_worker,
    super::SUPERVISOR_HOST_OP_KIND_SPAWN_PROCESS_WORKER
);
export_u32_const!(
    supervisor_host_op_kind_create_process_memory,
    super::SUPERVISOR_HOST_OP_KIND_CREATE_PROCESS_MEMORY
);
export_u32_const!(
    supervisor_host_op_kind_copy_memory_ranges,
    super::SUPERVISOR_HOST_OP_KIND_COPY_MEMORY_RANGES
);
export_u32_const!(
    supervisor_host_op_kind_fill_page_from_backing,
    super::SUPERVISOR_HOST_OP_KIND_FILL_PAGE_FROM_BACKING
);
export_u32_const!(
    supervisor_host_op_kind_flush_dirty_page,
    super::SUPERVISOR_HOST_OP_KIND_FLUSH_DIRTY_PAGE
);
export_u32_const!(
    supervisor_host_op_kind_process_fs_request,
    super::SUPERVISOR_HOST_OP_KIND_PROCESS_FS_REQUEST
);
export_u32_const!(
    supervisor_host_op_kind_host_network_connect,
    super::SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_CONNECT
);
export_u32_const!(
    supervisor_host_op_kind_host_network_read,
    super::SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_READ
);
export_u32_const!(
    supervisor_host_op_kind_host_network_write,
    super::SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_WRITE
);
export_u32_const!(
    supervisor_host_op_kind_host_network_close,
    super::SUPERVISOR_HOST_OP_KIND_HOST_NETWORK_CLOSE
);
export_u32_const!(
    supervisor_host_op_kind_arm_host_timer,
    super::SUPERVISOR_HOST_OP_KIND_ARM_HOST_TIMER
);
export_u32_const!(
    supervisor_host_op_kind_resume_thread,
    super::SUPERVISOR_HOST_OP_KIND_RESUME_THREAD
);
export_u32_const!(
    supervisor_host_op_kind_terminate_worker,
    super::SUPERVISOR_HOST_OP_KIND_TERMINATE_WORKER
);
export_u32_const!(
    supervisor_process_host_op_record_bytes,
    super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES
);
export_u32_const!(
    supervisor_process_host_op_kind_spawn_process_worker,
    super::SUPERVISOR_PROCESS_HOST_OP_KIND_SPAWN_PROCESS_WORKER
);
export_u32_const!(
    supervisor_fault_exit_decision_bytes,
    super::SUPERVISOR_FAULT_EXIT_DECISION_BYTES
);
export_u32_const!(
    supervisor_fault_exit_kind_thread_exit,
    super::SUPERVISOR_FAULT_EXIT_KIND_THREAD_EXIT
);
export_u32_const!(
    supervisor_fault_exit_kind_process_exit,
    super::SUPERVISOR_FAULT_EXIT_KIND_PROCESS_EXIT
);
export_u32_const!(
    supervisor_thread_exit_cleanup_record_bytes,
    super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES
);
export_u32_const!(
    supervisor_thread_exit_cleanup_kind_thread_exit,
    super::SUPERVISOR_THREAD_EXIT_CLEANUP_KIND_THREAD_EXIT
);
export_u32_const!(
    supervisor_process_lifecycle_record_bytes,
    super::SUPERVISOR_PROCESS_LIFECYCLE_BYTES
);
export_u32_const!(
    supervisor_process_lifecycle_kind_child_exit_published,
    super::SUPERVISOR_PROCESS_LIFECYCLE_KIND_CHILD_EXIT_PUBLISHED
);
export_u32_const!(
    supervisor_process_lifecycle_kind_wait4_completed,
    super::SUPERVISOR_PROCESS_LIFECYCLE_KIND_WAIT4_COMPLETED
);
export_u32_const!(
    supervisor_fd_control_record_bytes,
    super::SUPERVISOR_FD_CONTROL_RECORD_BYTES
);
export_u32_const!(
    supervisor_fd_control_kind_pipe_created,
    super::SUPERVISOR_FD_CONTROL_KIND_PIPE_CREATED
);
export_u32_const!(
    supervisor_fd_control_kind_fd_closed,
    super::SUPERVISOR_FD_CONTROL_KIND_FD_CLOSED
);
export_u32_const!(
    supervisor_fd_control_kind_fd_duplicated,
    super::SUPERVISOR_FD_CONTROL_KIND_FD_DUPLICATED
);
export_u32_const!(
    supervisor_fd_control_kind_fd_flags_updated,
    super::SUPERVISOR_FD_CONTROL_KIND_FD_FLAGS_UPDATED
);
export_u32_const!(
    supervisor_fd_control_kind_epoll_created,
    super::SUPERVISOR_FD_CONTROL_KIND_EPOLL_CREATED
);
export_u32_const!(
    supervisor_fd_control_kind_epoll_ctl_add,
    super::SUPERVISOR_FD_CONTROL_KIND_EPOLL_CTL_ADD
);
export_u32_const!(
    supervisor_fd_control_kind_epoll_ctl_del,
    super::SUPERVISOR_FD_CONTROL_KIND_EPOLL_CTL_DEL
);
export_u32_const!(
    supervisor_fd_control_kind_epoll_ctl_mod,
    super::SUPERVISOR_FD_CONTROL_KIND_EPOLL_CTL_MOD
);
export_u32_const!(
    supervisor_fd_control_kind_socket_created,
    super::SUPERVISOR_FD_CONTROL_KIND_SOCKET_CREATED
);
export_u32_const!(
    supervisor_fd_control_kind_socketpair_created,
    super::SUPERVISOR_FD_CONTROL_KIND_SOCKETPAIR_CREATED
);
export_u32_const!(
    supervisor_fd_control_kind_socket_bound,
    super::SUPERVISOR_FD_CONTROL_KIND_SOCKET_BOUND
);
export_u32_const!(
    supervisor_fd_control_kind_socket_listening,
    super::SUPERVISOR_FD_CONTROL_KIND_SOCKET_LISTENING
);
export_u32_const!(
    supervisor_fd_control_kind_socket_connect_started,
    super::SUPERVISOR_FD_CONTROL_KIND_SOCKET_CONNECT_STARTED
);
export_u32_const!(
    supervisor_fd_control_kind_socket_connected,
    super::SUPERVISOR_FD_CONTROL_KIND_SOCKET_CONNECTED
);
export_u32_const!(
    supervisor_fd_control_kind_socket_connect_failed,
    super::SUPERVISOR_FD_CONTROL_KIND_SOCKET_CONNECT_FAILED
);
export_u32_const!(
    supervisor_fd_control_kind_socket_accepted,
    super::SUPERVISOR_FD_CONTROL_KIND_SOCKET_ACCEPTED
);
export_u32_const!(
    supervisor_fs_control_record_bytes,
    super::SUPERVISOR_FS_CONTROL_RECORD_BYTES
);
export_u32_const!(
    supervisor_fs_control_kind_page_cache_miss,
    super::SUPERVISOR_FS_CONTROL_KIND_PAGE_CACHE_MISS
);
export_u32_const!(
    supervisor_fs_control_kind_page_cache_fill,
    super::SUPERVISOR_FS_CONTROL_KIND_PAGE_CACHE_FILL
);
export_u32_const!(
    supervisor_fs_control_kind_dirty_page_published,
    super::SUPERVISOR_FS_CONTROL_KIND_DIRTY_PAGE_PUBLISHED
);
export_u32_const!(
    supervisor_fs_control_kind_dirty_page_flushed,
    super::SUPERVISOR_FS_CONTROL_KIND_DIRTY_PAGE_FLUSHED
);
export_u32_const!(
    supervisor_signal_control_record_bytes,
    super::SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES
);
export_u32_const!(
    supervisor_signal_control_kind_boundary_check,
    super::SUPERVISOR_SIGNAL_CONTROL_KIND_BOUNDARY_CHECK
);
export_u32_const!(
    supervisor_signal_control_kind_signal_delivered,
    super::SUPERVISOR_SIGNAL_CONTROL_KIND_SIGNAL_DELIVERED
);
export_u32_const!(
    supervisor_signal_control_kind_blocked_wait_interrupted,
    super::SUPERVISOR_SIGNAL_CONTROL_KIND_BLOCKED_WAIT_INTERRUPTED
);
export_u32_const!(
    supervisor_resume_kind_futex_wake,
    super::SUPERVISOR_RESUME_KIND_FUTEX_WAKE
);
export_u32_const!(
    supervisor_resume_kind_runnable_thread,
    super::SUPERVISOR_RESUME_KIND_RUNNABLE_THREAD
);
export_u32_const!(
    supervisor_futex_wait_completion_woken,
    super::SUPERVISOR_FUTEX_WAIT_COMPLETION_WOKEN
);
export_u32_const!(
    supervisor_futex_wait_completion_not_equal,
    super::SUPERVISOR_FUTEX_WAIT_COMPLETION_NOT_EQUAL
);
export_u32_const!(
    supervisor_futex_wait_completion_timed_out,
    super::SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT
);
export_u32_const!(
    supervisor_futex_wait_completion_invalid_address,
    super::SUPERVISOR_FUTEX_WAIT_COMPLETION_INVALID_ADDRESS
);
export_u32_const!(
    supervisor_futex_wait_completion_signal_check,
    super::SUPERVISOR_FUTEX_WAIT_COMPLETION_SIGNAL_CHECK
);

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_reset_shadow_log() {
    super::init();
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_thread_event_count() -> u64 {
    super::thread_event_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_completion_count() -> u64 {
    super::host_completion_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_poll_count() -> u64 {
    super::host_op_poll_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_emit_count() -> u64 {
    super::host_op_emit_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_overflow_count() -> u64 {
    super::host_op_overflow_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_thread_exit_cleanup_count() -> u64 {
    super::thread_exit_cleanup_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_process_lifecycle_count() -> u64 {
    super::process_lifecycle_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_fd_control_count() -> u64 {
    super::fd_control_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_fs_control_count() -> u64 {
    super::fs_control_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_signal_control_count() -> u64 {
    super::signal_control_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_resume_poll_count() -> u64 {
    super::resume_poll_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_resume_enqueue_count() -> u64 {
    super::resume_enqueue_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_resume_overflow_count() -> u64 {
    super::resume_overflow_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_thread_event_log_hash() -> u64 {
    super::thread_event_log_hash()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_completion_log_hash() -> u64 {
    super::host_completion_log_hash()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_log_hash() -> u64 {
    super::host_op_log_hash()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_last_hash() -> u64 {
    super::log::last_host_op_hash()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_shadow_host_op_last_len() -> u32 {
    super::log::last_host_op_len()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_submit_thread_event(event_ptr: u32, event_len: u32) -> i32 {
    super::event::submit(event_ptr, event_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_complete_host_op(completion_ptr: u32, completion_len: u32) -> i32 {
    let bytes = match super::read_shadow_bytes(completion_ptr, completion_len) {
        Ok(bytes) => bytes,
        Err(errno) => return errno,
    };
    super::log::record_host_completion(bytes, completion_len);
    super::host_op::complete_host_op(bytes)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_complete_futex_wait(vm_ptr: u32, completion: u32) -> i32 {
    super::futex::complete_wait(vm_ptr, completion)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_signal_pending_for_blocked_wait(vm_ptr: u32) -> i32 {
    super::futex::blocked_wait_signal_decision(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_next_host_op(out_ptr: u32, out_len: u32) -> i32 {
    super::host_op::write_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_host_op(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    super::host_op::write_process_record(vm_ptr, out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_next_resume(out_ptr: u32, out_len: u32) -> i32 {
    super::resume::write_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_resume(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    super::resume::write_process_record(vm_ptr, out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fault_exit_decision(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    super::fault::write_decision(vm_ptr, out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_exit_cleanup_record(out_ptr: u32, out_len: u32) -> i32 {
    super::write_thread_exit_cleanup_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_lifecycle_record(out_ptr: u32, out_len: u32) -> i32 {
    super::write_process_lifecycle_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_record(out_ptr: u32, out_len: u32) -> i32 {
    super::write_fd_control_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_control_record(out_ptr: u32, out_len: u32) -> i32 {
    super::write_fs_control_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_signal_control_record(out_ptr: u32, out_len: u32) -> i32 {
    super::write_signal_control_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_debug_snapshot(out_ptr: u32, out_len: u32) -> i32 {
    super::debug::write_snapshot(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_state_snapshot(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    super::thread::write_state_snapshot(vm_ptr, out_ptr, out_len)
}
