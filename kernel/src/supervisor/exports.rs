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
    supervisor_thread_event_record_magic,
    super::SUPERVISOR_THREAD_EVENT_RECORD_MAGIC
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
    supervisor_thread_state_snapshot_magic,
    super::SUPERVISOR_THREAD_STATE_SNAPSHOT_MAGIC
);
export_u32_const!(
    supervisor_resume_record_bytes,
    super::SUPERVISOR_RESUME_RECORD_BYTES
);
export_u32_const!(
    supervisor_resume_record_magic,
    super::SUPERVISOR_RESUME_RECORD_MAGIC
);
export_u32_const!(
    supervisor_host_completion_record_bytes,
    super::SUPERVISOR_HOST_COMPLETION_RECORD_BYTES
);
export_u32_const!(
    supervisor_host_completion_record_magic,
    super::SUPERVISOR_HOST_COMPLETION_RECORD_MAGIC
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
    supervisor_host_op_record_magic,
    super::SUPERVISOR_HOST_OP_RECORD_MAGIC
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
    supervisor_host_op_kind_retry_blocked_worker,
    super::SUPERVISOR_HOST_OP_KIND_RETRY_BLOCKED_WORKER
);
export_u32_const!(
    supervisor_process_host_op_record_bytes,
    super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES
);
export_u32_const!(
    supervisor_process_host_op_record_magic,
    super::SUPERVISOR_PROCESS_HOST_OP_RECORD_MAGIC
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
    supervisor_fault_exit_decision_magic,
    super::SUPERVISOR_FAULT_EXIT_DECISION_MAGIC
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
    supervisor_thread_exit_cleanup_record_magic,
    super::SUPERVISOR_THREAD_EXIT_CLEANUP_MAGIC
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
    supervisor_process_lifecycle_record_magic,
    super::SUPERVISOR_PROCESS_LIFECYCLE_MAGIC
);
export_u32_const!(
    supervisor_process_lifecycle_kind_child_exit_published,
    super::SUPERVISOR_PROCESS_LIFECYCLE_KIND_CHILD_EXIT_PUBLISHED
);
export_u32_const!(
    supervisor_process_lifecycle_kind_wait4_completed,
    super::SUPERVISOR_PROCESS_LIFECYCLE_KIND_WAIT4_COMPLETED
);

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_status_is_lifecycle_handoff(status: i32) -> i32 {
    super::process::status_is_lifecycle_handoff(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_status_is_execve_spawn(status: i32) -> i32 {
    super::process::status_is_execve_spawn(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_status_is_clone_spawn(status: i32) -> i32 {
    super::process::status_is_clone_spawn(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_status_is_vfork_wait(status: i32) -> i32 {
    super::process::status_is_vfork_wait(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_status_allows_pid_mismatch(status: i32) -> i32 {
    super::process::status_allows_pid_mismatch(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_status_defers_kernel_state_adoption(status: i32) -> i32 {
    super::process::status_defers_kernel_state_adoption(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_vfork_child_owner_mismatch(vm_ptr: u32, runtime_pid: i32) -> i32 {
    super::process::vfork_child_owner_mismatch(vm_ptr, runtime_pid)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_owner_matches(vm_ptr: u32, runtime_pid: i32) -> i32 {
    super::process::owner_matches(vm_ptr, runtime_pid)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_owner_mismatch(vm_ptr: u32, runtime_pid: i32) -> i32 {
    super::process::owner_mismatch(vm_ptr, runtime_pid)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_owner_absent(vm_ptr: u32) -> i32 {
    super::process::owner_absent(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_owner_live_matches(vm_ptr: u32, runtime_pid: i32) -> i32 {
    super::process::owner_live_matches(vm_ptr, runtime_pid)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_owner_missing_or_invalid(vm_ptr: u32) -> i32 {
    super::process::owner_missing_or_invalid(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_identity_matches(
    vm_ptr: u32,
    runtime_pid: i32,
    process_ptr: u32,
) -> i32 {
    super::process::process_identity_matches(vm_ptr, runtime_pid, process_ptr)
}

export_u32_const!(
    supervisor_fd_control_record_bytes,
    super::SUPERVISOR_FD_CONTROL_RECORD_BYTES
);
export_u32_const!(
    supervisor_fd_control_record_magic,
    super::SUPERVISOR_FD_CONTROL_RECORD_MAGIC
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
    supervisor_fd_entry_restore_action_apply,
    super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_APPLY
);
export_u32_const!(
    supervisor_fd_entry_restore_action_skip,
    super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_SKIP
);
export_u32_const!(
    supervisor_fd_entry_restore_flag_preserve_live_regular_file,
    super::SUPERVISOR_FD_ENTRY_RESTORE_FLAG_PRESERVE_LIVE_REGULAR_FILE
);
export_u32_const!(
    supervisor_fd_entry_restore_flag_preserve_live_epoll_dependent,
    super::SUPERVISOR_FD_ENTRY_RESTORE_FLAG_PRESERVE_LIVE_EPOLL_DEPENDENT
);
export_u32_const!(
    supervisor_ofd_slot_restore_flag_referenced_by_fd_entry,
    super::SUPERVISOR_OFD_SLOT_RESTORE_FLAG_REFERENCED_BY_FD_ENTRY
);
export_u32_const!(
    supervisor_ofd_slot_restore_flag_trust_regular_file_offset,
    super::SUPERVISOR_OFD_SLOT_RESTORE_FLAG_TRUST_REGULAR_FILE_OFFSET
);
export_u32_const!(
    supervisor_pipe_slot_mode_read,
    super::SUPERVISOR_PIPE_SLOT_MODE_READ
);
export_u32_const!(
    supervisor_pipe_slot_mode_write,
    super::SUPERVISOR_PIPE_SLOT_MODE_WRITE
);
export_u32_const!(
    supervisor_pipe_slot_mode_control,
    super::SUPERVISOR_PIPE_SLOT_MODE_CONTROL
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_context_shared_state,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_SHARED_STATE
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_context_thread_step,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_THREAD_STEP
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_context_kernel_worker_apply,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_KERNEL_WORKER_APPLY
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_context_kernel_worker_process,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_KERNEL_WORKER_PROCESS
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_context_kernel_worker_canonical,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_KERNEL_WORKER_CANONICAL
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_skip,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SKIP
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_apply_slot,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_APPLY_SLOT
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_apply_control,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_APPLY_CONTROL
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_set_head_to_source,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_HEAD_TO_SOURCE
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_set_tail_to_source,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_TAIL_TO_SOURCE
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_set_head_zero,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_HEAD_ZERO
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_copy_full,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_copy_tail_delta,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_TAIL_DELTA
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_sync_generation,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION
);
export_u32_const!(
    supervisor_pipe_slot_snapshot_action_stop,
    super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_STOP
);
export_u32_const!(
    supervisor_blocked_pipe_resume_action_defer,
    super::SUPERVISOR_BLOCKED_PIPE_RESUME_ACTION_DEFER
);
export_u32_const!(
    supervisor_blocked_pipe_resume_action_direct,
    super::SUPERVISOR_BLOCKED_PIPE_RESUME_ACTION_DIRECT
);
export_u32_const!(
    supervisor_blocked_pipe_sync_before_retry_action_none,
    super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_NONE
);
export_u32_const!(
    supervisor_blocked_pipe_sync_before_retry_action_request_sync,
    super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_REQUEST_SYNC
);
export_u32_const!(
    supervisor_blocked_pipe_sync_before_retry_action_request_sync_and_drain_output,
    super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_REQUEST_SYNC_AND_DRAIN_OUTPUT
);
export_u32_const!(
    supervisor_blocked_pipe_sync_before_retry_action_schedule_retry,
    super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_SCHEDULE_RETRY
);
export_u32_const!(
    supervisor_blocked_pipe_sync_before_retry_flag_kernel_worker_available,
    super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_FLAG_KERNEL_WORKER_AVAILABLE
);
export_u32_const!(
    supervisor_resume_flag_timeout_expired,
    super::blocked::resume_flag_timeout_expired()
);
export_u32_const!(
    supervisor_blocked_wait_network_pump_action_skip,
    super::network::pump_action_skip()
);
export_u32_const!(
    supervisor_blocked_wait_network_pump_action_pump,
    super::network::pump_action_pump()
);
export_u32_const!(
    supervisor_state_sync_kind_pipe,
    super::SUPERVISOR_STATE_SYNC_KIND_PIPE
);
export_u32_const!(
    supervisor_state_sync_kind_epoll,
    super::SUPERVISOR_STATE_SYNC_KIND_EPOLL
);
export_u32_const!(
    supervisor_state_sync_kind_socket,
    super::SUPERVISOR_STATE_SYNC_KIND_SOCKET
);
export_u32_const!(
    supervisor_state_sync_request_flag_wake_waiters,
    super::SUPERVISOR_STATE_SYNC_REQUEST_FLAG_WAKE_WAITERS
);
export_u32_const!(
    supervisor_state_sync_run_flag_run,
    super::SUPERVISOR_STATE_SYNC_RUN_FLAG_RUN
);
export_u32_const!(
    supervisor_state_sync_run_flag_wake_waiters,
    super::SUPERVISOR_STATE_SYNC_RUN_FLAG_WAKE_WAITERS
);
export_u32_const!(
    supervisor_blocked_wait_wake_source_pipe_sync,
    super::state_sync::wake_source_pipe_sync()
);
export_u32_const!(
    supervisor_blocked_wait_wake_source_epoll_sync,
    super::state_sync::wake_source_epoll_sync()
);
export_u32_const!(
    supervisor_blocked_wait_wake_source_socket_sync,
    super::state_sync::wake_source_socket_sync()
);
export_u32_const!(
    supervisor_blocked_wait_wake_source_pipe_and_epoll_sync,
    super::state_sync::wake_source_pipe_and_epoll_sync()
);
export_u32_const!(
    supervisor_blocked_wait_wake_target_pipe_wait,
    super::state_sync::wake_target_pipe_wait()
);
export_u32_const!(
    supervisor_blocked_wait_wake_target_epoll_wait,
    super::state_sync::wake_target_epoll_wait()
);
export_u32_const!(
    supervisor_blocked_wait_wake_target_socket_recv,
    super::state_sync::wake_target_socket_recv()
);
export_u32_const!(
    supervisor_blocked_wait_wake_target_socket_send,
    super::state_sync::wake_target_socket_send()
);
export_u32_const!(
    supervisor_stdio_output_settle_kind_visible,
    super::stdio::output_settle_kind_visible()
);
export_u32_const!(
    supervisor_stdio_output_settle_kind_inherited_child,
    super::stdio::output_settle_kind_inherited_child()
);
export_u32_const!(
    supervisor_stdio_pipe_read_progress_action_none,
    super::stdio::pipe_read_progress_action_none()
);
export_u32_const!(
    supervisor_stdio_pipe_read_progress_action_snapshot,
    super::stdio::pipe_read_progress_action_snapshot()
);
export_u32_const!(
    supervisor_fs_control_record_bytes,
    super::SUPERVISOR_FS_CONTROL_RECORD_BYTES
);
export_u32_const!(
    supervisor_fs_control_record_magic,
    super::SUPERVISOR_FS_CONTROL_RECORD_MAGIC
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
    supervisor_fs_completion_flag_memfs_dirty,
    super::SUPERVISOR_FS_COMPLETION_FLAG_MEMFS_DIRTY
);
export_u32_const!(
    supervisor_fs_completion_flag_memfs_publish_ready,
    super::SUPERVISOR_FS_COMPLETION_FLAG_MEMFS_PUBLISH_READY
);
export_u32_const!(
    supervisor_fs_completion_flag_ofd_state_changed,
    super::SUPERVISOR_FS_COMPLETION_FLAG_OFD_STATE_CHANGED
);
export_u32_const!(
    supervisor_fs_completion_flag_regular_file_request,
    super::SUPERVISOR_FS_COMPLETION_FLAG_REGULAR_FILE_REQUEST
);
export_u32_const!(
    supervisor_fs_response_flag_adopt_kernel_state,
    super::SUPERVISOR_FS_RESPONSE_FLAG_ADOPT_KERNEL_STATE
);
export_u32_const!(
    supervisor_fs_response_flag_apply_guest_memory_writes,
    super::SUPERVISOR_FS_RESPONSE_FLAG_APPLY_GUEST_MEMORY_WRITES
);
export_u32_const!(
    supervisor_fs_response_flag_queue_thread_worker_writes,
    super::SUPERVISOR_FS_RESPONSE_FLAG_QUEUE_THREAD_WORKER_WRITES
);
export_u32_const!(
    supervisor_fs_response_flag_apply_local_metadata,
    super::SUPERVISOR_FS_RESPONSE_FLAG_APPLY_LOCAL_METADATA
);
export_u32_const!(
    supervisor_fs_response_flag_clear_tombstones,
    super::SUPERVISOR_FS_RESPONSE_FLAG_CLEAR_TOMBSTONES
);
export_u32_const!(
    supervisor_fs_response_flag_fd_response_may_clear_live_fds,
    super::SUPERVISOR_FS_RESPONSE_FLAG_FD_RESPONSE_MAY_CLEAR_LIVE_FDS
);
export_u32_const!(
    supervisor_fs_response_flag_store_pending_kernel_state,
    super::SUPERVISOR_FS_RESPONSE_FLAG_STORE_PENDING_KERNEL_STATE
);
export_u32_const!(
    supervisor_fs_response_flag_resolved_to_execve_spawn,
    super::SUPERVISOR_FS_RESPONSE_FLAG_RESOLVED_TO_EXECVE_SPAWN
);
export_u32_const!(
    supervisor_fs_response_flag_process_owner_matches,
    super::SUPERVISOR_FS_RESPONSE_FLAG_PROCESS_OWNER_MATCHES
);
export_u32_const!(
    supervisor_fs_pipe_refresh_action_none,
    super::SUPERVISOR_FS_PIPE_REFRESH_ACTION_NONE
);
export_u32_const!(
    supervisor_fs_pipe_refresh_action_request_sync,
    super::SUPERVISOR_FS_PIPE_REFRESH_ACTION_REQUEST_SYNC
);
export_u32_const!(
    supervisor_fs_pipe_refresh_flag_kernel_worker_available,
    super::SUPERVISOR_FS_PIPE_REFRESH_FLAG_KERNEL_WORKER_AVAILABLE
);
export_u32_const!(
    supervisor_fs_local_metadata_action_none,
    super::SUPERVISOR_FS_LOCAL_METADATA_ACTION_NONE
);
export_u32_const!(
    supervisor_fs_local_metadata_action_tombstone_primary,
    super::SUPERVISOR_FS_LOCAL_METADATA_ACTION_TOMBSTONE_PRIMARY
);
export_u32_const!(
    supervisor_fs_local_metadata_action_forget_primary,
    super::SUPERVISOR_FS_LOCAL_METADATA_ACTION_FORGET_PRIMARY
);
export_u32_const!(
    supervisor_fs_local_metadata_action_forget_secondary,
    super::SUPERVISOR_FS_LOCAL_METADATA_ACTION_FORGET_SECONDARY
);
export_u32_const!(
    supervisor_fs_resident_page_evict_not_found,
    super::SUPERVISOR_FS_RESIDENT_PAGE_EVICT_NOT_FOUND
);
export_u32_const!(
    supervisor_fs_resident_page_evict_dirty_pinned,
    super::SUPERVISOR_FS_RESIDENT_PAGE_EVICT_DIRTY_PINNED
);
export_u32_const!(
    supervisor_fs_resident_page_evict_evicted,
    super::SUPERVISOR_FS_RESIDENT_PAGE_EVICT_EVICTED
);
export_u32_const!(
    supervisor_fs_dirty_page_op_write,
    super::SUPERVISOR_FS_DIRTY_PAGE_OP_WRITE
);
export_u32_const!(
    supervisor_fs_dirty_page_op_truncate,
    super::SUPERVISOR_FS_DIRTY_PAGE_OP_TRUNCATE
);
export_u32_const!(
    supervisor_fs_dirty_page_op_flush,
    super::SUPERVISOR_FS_DIRTY_PAGE_OP_FLUSH
);
export_u32_const!(
    supervisor_fs_dirty_page_flag_update_inode,
    super::SUPERVISOR_FS_DIRTY_PAGE_FLAG_UPDATE_INODE
);
export_u32_const!(
    supervisor_fs_dirty_page_flag_publish_dirty,
    super::SUPERVISOR_FS_DIRTY_PAGE_FLAG_PUBLISH_DIRTY
);
export_u32_const!(
    supervisor_fs_dirty_page_flag_writeback_required,
    super::SUPERVISOR_FS_DIRTY_PAGE_FLAG_WRITEBACK_REQUIRED
);
export_u32_const!(
    supervisor_fs_dirty_prepare_publish_none,
    super::SUPERVISOR_FS_DIRTY_PREPARE_PUBLISH_NONE
);
export_u32_const!(
    supervisor_fs_dirty_prepare_publish_missing,
    super::SUPERVISOR_FS_DIRTY_PREPARE_PUBLISH_MISSING
);
export_u32_const!(
    supervisor_fs_dirty_prepare_publish_size_update,
    super::SUPERVISOR_FS_DIRTY_PREPARE_PUBLISH_SIZE_UPDATE
);
export_u32_const!(
    supervisor_fs_data_sync_kind_export,
    super::SUPERVISOR_FS_DATA_SYNC_KIND_EXPORT
);
export_u32_const!(
    supervisor_fs_data_sync_kind_restore,
    super::SUPERVISOR_FS_DATA_SYNC_KIND_RESTORE
);
export_u32_const!(
    supervisor_fs_sync_action_none,
    super::SUPERVISOR_FS_SYNC_ACTION_NONE
);
export_u32_const!(
    supervisor_fs_sync_action_externalize,
    super::SUPERVISOR_FS_SYNC_ACTION_EXTERNALIZE
);
export_u32_const!(
    supervisor_fs_metadata_sync_action_none,
    super::SUPERVISOR_FS_METADATA_SYNC_ACTION_NONE
);
export_u32_const!(
    supervisor_fs_metadata_sync_action_remove,
    super::SUPERVISOR_FS_METADATA_SYNC_ACTION_REMOVE
);
export_u32_const!(
    supervisor_fs_metadata_sync_action_ensure,
    super::SUPERVISOR_FS_METADATA_SYNC_ACTION_ENSURE
);
export_u32_const!(
    supervisor_fs_metadata_sync_action_publish_ensure,
    super::SUPERVISOR_FS_METADATA_SYNC_ACTION_PUBLISH_ENSURE
);
export_u32_const!(
    supervisor_fs_metadata_full_sync_action_none,
    super::SUPERVISOR_FS_METADATA_FULL_SYNC_ACTION_NONE
);
export_u32_const!(
    supervisor_fs_metadata_full_sync_action_required,
    super::SUPERVISOR_FS_METADATA_FULL_SYNC_ACTION_REQUIRED
);
export_u32_const!(
    supervisor_fs_metadata_backing_none,
    super::SUPERVISOR_FS_METADATA_BACKING_NONE
);
export_u32_const!(
    supervisor_fs_metadata_backing_published,
    super::SUPERVISOR_FS_METADATA_BACKING_PUBLISHED
);
export_u32_const!(
    supervisor_fs_metadata_backing_backing,
    super::SUPERVISOR_FS_METADATA_BACKING_BACKING
);
export_u32_const!(
    supervisor_fs_backing_object_op_source,
    super::SUPERVISOR_FS_BACKING_OBJECT_OP_SOURCE
);
export_u32_const!(
    supervisor_fs_backing_object_op_materialize,
    super::SUPERVISOR_FS_BACKING_OBJECT_OP_MATERIALIZE
);
export_u32_const!(
    supervisor_fs_backing_object_op_replace,
    super::SUPERVISOR_FS_BACKING_OBJECT_OP_REPLACE
);
export_u32_const!(
    supervisor_fs_backing_object_op_flush_write,
    super::SUPERVISOR_FS_BACKING_OBJECT_OP_FLUSH_WRITE
);
export_u32_const!(
    supervisor_fs_backing_object_op_flush_truncate,
    super::SUPERVISOR_FS_BACKING_OBJECT_OP_FLUSH_TRUNCATE
);
export_u32_const!(
    supervisor_fs_backing_retry_min_attempts,
    super::SUPERVISOR_FS_BACKING_RETRY_MIN_ATTEMPTS
);
export_u32_const!(
    supervisor_fs_backing_retry_max_attempts,
    super::SUPERVISOR_FS_BACKING_RETRY_MAX_ATTEMPTS
);
export_u32_const!(
    supervisor_fs_backing_retry_final_scan_attempts,
    super::SUPERVISOR_FS_BACKING_RETRY_FINAL_SCAN_ATTEMPTS
);
export_u32_const!(
    supervisor_fs_backing_fill_mode_resident,
    super::SUPERVISOR_FS_BACKING_FILL_MODE_RESIDENT
);
export_u32_const!(
    supervisor_fs_backing_fill_mode_direct,
    super::SUPERVISOR_FS_BACKING_FILL_MODE_DIRECT
);
export_u32_const!(
    supervisor_fs_backing_source_range_none,
    super::SUPERVISOR_FS_BACKING_SOURCE_RANGE_NONE
);
export_u32_const!(
    supervisor_fs_backing_source_range_read,
    super::SUPERVISOR_FS_BACKING_SOURCE_RANGE_READ
);
export_u32_const!(
    supervisor_fs_clean_backing_range_none,
    super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_NONE
);
export_u32_const!(
    supervisor_fs_clean_backing_range_read,
    super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_READ
);
export_u32_const!(
    supervisor_fs_clean_backing_range_read_zero_tail,
    super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_READ_ZERO_TAIL
);
export_u32_const!(
    supervisor_fs_clean_backing_range_zero,
    super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_ZERO
);
export_u32_const!(
    supervisor_fs_page_table_source_backing,
    super::SUPERVISOR_FS_PAGE_TABLE_SOURCE_BACKING
);
export_u32_const!(
    supervisor_fs_page_table_source_resident,
    super::SUPERVISOR_FS_PAGE_TABLE_SOURCE_RESIDENT
);
export_u32_const!(
    supervisor_signal_control_record_bytes,
    super::SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES
);
export_u32_const!(
    supervisor_signal_control_record_magic,
    super::SUPERVISOR_SIGNAL_CONTROL_RECORD_MAGIC
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
    supervisor_signal_boundary_step,
    super::SUPERVISOR_SIGNAL_BOUNDARY_STEP
);
export_u32_const!(
    supervisor_signal_boundary_fault,
    super::SUPERVISOR_SIGNAL_BOUNDARY_FAULT
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
pub extern "C" fn supervisor_signal_boundary_check(vm_ptr: u32) -> i32 {
    super::signal::boundary_check(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_resume_blocked_syscall(vm_ptr: u32, flags: u32) -> i64 {
    super::blocked::resume_blocked_syscall(vm_ptr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_writeback_count(
    vm_ptr: u32,
    blocked_status: i32,
    resume_result: i64,
) -> i32 {
    super::blocked::resume_writeback_count(vm_ptr, blocked_status, resume_result)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_writeback_ptr(
    vm_ptr: u32,
    blocked_status: i32,
    resume_result: i64,
    index: u32,
) -> u64 {
    super::blocked::resume_writeback_ptr(vm_ptr, blocked_status, resume_result, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_writeback_len(
    vm_ptr: u32,
    blocked_status: i32,
    resume_result: i64,
    index: u32,
) -> u64 {
    super::blocked::resume_writeback_len(vm_ptr, blocked_status, resume_result, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_is_host_wait(status: i32) -> i32 {
    super::blocked::status_is_host_wait(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_is_connect_wait(status: i32) -> i32 {
    super::blocked::status_is_connect_wait(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_is_epoll_wait(status: i32) -> i32 {
    super::blocked::status_is_epoll_wait(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_epoll_wait_retry_required(vm_ptr: u32) -> i32 {
    super::blocked::epoll_wait_retry_required(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_is_pipe_wait(status: i32) -> i32 {
    super::blocked::status_is_pipe_wait(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_is_wait4(status: i32) -> i32 {
    super::blocked::status_is_wait4(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_is_socket_wait(status: i32) -> i32 {
    super::blocked::status_is_socket_wait(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_needs_network_sidecar_restore(status: i32) -> i32 {
    super::blocked::status_needs_network_sidecar_restore(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_syncs_socket_after_resume(status: i32) -> i32 {
    super::blocked::status_syncs_socket_after_resume(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_uses_fork_shared_state_sync(status: i32) -> i32 {
    super::blocked::status_uses_fork_shared_state_sync(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_transition_action_block() -> u32 {
    super::blocked::status_transition_action_block()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_transition_action_sync_socket() -> u32 {
    super::blocked::status_transition_action_sync_socket()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_transition_action_sync_pipe() -> u32 {
    super::blocked::status_transition_action_sync_pipe()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_transition_action_sync_fork_shared() -> u32 {
    super::blocked::status_transition_action_sync_fork_shared()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_transition_action_sync_pipe_and_fork_shared() -> u32 {
    super::blocked::status_transition_action_sync_pipe_and_fork_shared()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_transition_action_sync_socket_and_fork_shared() -> u32 {
    super::blocked::status_transition_action_sync_socket_and_fork_shared()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_transition_flag_kernel_worker_available() -> u32 {
    super::blocked::status_transition_flag_kernel_worker_available()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_transition_flag_network_connections_available() -> u32 {
    super::blocked::status_transition_flag_network_connections_available()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_status_transition_action(
    vm_ptr: u32,
    status: i32,
    flags: u32,
) -> i32 {
    super::blocked::status_transition_action(vm_ptr, status, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_network_pump_action(vm_ptr: u32) -> i32 {
    super::network::blocked_wait_pump_action(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_complete_blocked_wait_network_pump(vm_ptr: u32, changed: u32) -> i32 {
    super::network::complete_blocked_wait_pump(vm_ptr, changed)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_clear_blocked_wait_network_pump(vm_ptr: u32) -> i32 {
    super::network::clear_blocked_wait_pump(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_poll_wait_timeout_ms(vm_ptr: u32) -> i64 {
    super::blocked::poll_wait_timeout_ms(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_poll_wait_has_socket(vm_ptr: u32) -> i32 {
    super::blocked::poll_wait_has_socket(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_pipe_wait_has_ready_events(vm_ptr: u32) -> i32 {
    super::blocked::pipe_wait_has_ready_events(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_may_depend_on_network(vm_ptr: u32) -> i32 {
    super::blocked::blocked_wait_may_depend_on_network(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_should_pump_network(vm_ptr: u32) -> i32 {
    super::blocked::blocked_wait_should_pump_network(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_delay_ms(vm_ptr: u32, reason: u32) -> i32 {
    super::blocked::retry_delay_ms(vm_ptr, reason)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_reason(vm_ptr: u32, flags: u32) -> i32 {
    super::blocked::retry_reason(vm_ptr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_active_child_pid(vm_ptr: u32) -> i32 {
    super::blocked::blocked_wait_active_child_pid(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_delegation(vm_ptr: u32, flags: u32) -> i32 {
    super::blocked::resume_delegation(vm_ptr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_delegation_flag_kernel_worker_available() -> u32 {
    super::blocked::resume_delegation_flag_kernel_worker_available()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_delegation_direct() -> u32 {
    super::blocked::resume_delegation_direct()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_delegation_kernel_worker() -> u32 {
    super::blocked::resume_delegation_kernel_worker()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_delegation_wait4_kernel_worker() -> u32 {
    super::blocked::resume_delegation_wait4_kernel_worker()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_delegation_unsupported() -> u32 {
    super::blocked::resume_delegation_unsupported()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_resume_delegation_epoll_direct() -> u32 {
    super::blocked::resume_delegation_epoll_direct()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_reason_default() -> u32 {
    super::blocked::retry_reason_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_reason_immediate() -> u32 {
    super::blocked::retry_reason_immediate()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_reason_standard_defer() -> u32 {
    super::blocked::retry_reason_standard_defer()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_reason_active_child() -> u32 {
    super::blocked::retry_reason_active_child()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_reason_passive_wait() -> u32 {
    super::blocked::retry_reason_passive_wait()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_reason_process_gate() -> u32 {
    super::blocked::retry_reason_process_gate()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_flag_host_progress() -> u32 {
    super::blocked::retry_flag_host_progress()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_flag_active_child() -> u32 {
    super::blocked::retry_flag_active_child()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_flag_passive_wait() -> u32 {
    super::blocked::retry_flag_passive_wait()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_flag_process_gate() -> u32 {
    super::blocked::retry_flag_process_gate()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_retry_flag_thread_init_pending() -> u32 {
    super::blocked::retry_flag_thread_init_pending()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_supervisor_timer_armed() -> u32 {
    super::blocked::retry_action_flag_supervisor_timer_armed()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_rpc_pending() -> u32 {
    super::blocked::retry_action_flag_rpc_pending()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_owner_async() -> u32 {
    super::blocked::retry_action_flag_owner_async()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_thread_init_pending() -> u32 {
    super::blocked::retry_action_flag_thread_init_pending()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_fork_shared_sync_pending() -> u32 {
    super::blocked::retry_action_flag_fork_shared_sync_pending()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_running_worker() -> u32 {
    super::blocked::retry_action_flag_running_worker()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_kernel_worker_available() -> u32 {
    super::blocked::retry_action_flag_kernel_worker_available()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_pipe_state_kernel_worker_owns() -> u32 {
    super::blocked::retry_action_flag_pipe_state_kernel_worker_owns()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_network_connections_available() -> u32 {
    super::blocked::retry_action_flag_network_connections_available()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_flag_wait_timer_already_checked() -> u32 {
    super::blocked::retry_action_flag_wait_timer_already_checked()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_defer_supervisor_timer() -> u32 {
    super::blocked::retry_action_defer_supervisor_timer()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_defer_rpc_pending() -> u32 {
    super::blocked::retry_action_defer_rpc_pending()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_defer_owner_async() -> u32 {
    super::blocked::retry_action_defer_owner_async()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_defer_thread_init_pending() -> u32 {
    super::blocked::retry_action_defer_thread_init_pending()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_arm_wait_timer() -> u32 {
    super::blocked::retry_action_arm_wait_timer()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_park_active_child() -> u32 {
    super::blocked::retry_action_park_active_child()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_resume_wait4() -> u32 {
    super::blocked::retry_action_resume_wait4()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_defer_fork_shared_sync() -> u32 {
    super::blocked::retry_action_defer_fork_shared_sync()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_defer_running_worker() -> u32 {
    super::blocked::retry_action_defer_running_worker()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_defer_process_gate() -> u32 {
    super::blocked::retry_action_defer_process_gate()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_pump_network() -> u32 {
    super::blocked::retry_action_pump_network()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_epoll_kernel_worker() -> u32 {
    super::blocked::retry_action_epoll_kernel_worker()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_request_pipe_sync() -> u32 {
    super::blocked::retry_action_request_pipe_sync()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_request_pipe_sync_and_drain_output() -> u32 {
    super::blocked::retry_action_request_pipe_sync_and_drain_output()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_schedule_pipe_sync_retry() -> u32 {
    super::blocked::retry_action_schedule_pipe_sync_retry()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_resume_fs() -> u32 {
    super::blocked::retry_action_resume_fs()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_defer_passive_wait() -> u32 {
    super::blocked::retry_action_defer_passive_wait()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_resume_kernel_worker() -> u32 {
    super::blocked::retry_action_resume_kernel_worker()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_resume_wait4_kernel_worker() -> u32 {
    super::blocked::retry_action_resume_wait4_kernel_worker()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_resume_epoll_direct() -> u32 {
    super::blocked::retry_action_resume_epoll_direct()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_resume_direct() -> u32 {
    super::blocked::retry_action_resume_direct()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action_unsupported() -> u32 {
    super::blocked::retry_action_unsupported()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_initial_action_none() -> u32 {
    super::blocked::initial_action_none()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_initial_action_defer_supervisor_timer() -> u32 {
    super::blocked::initial_action_defer_supervisor_timer()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_initial_action_defer_rpc_pending() -> u32 {
    super::blocked::initial_action_defer_rpc_pending()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_initial_action_arm_wait_timer() -> u32 {
    super::blocked::initial_action_arm_wait_timer()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_initial_action_retry_now() -> u32 {
    super::blocked::initial_action_retry_now()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_initial_action_schedule_retry() -> u32 {
    super::blocked::initial_action_schedule_retry()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_initial_action(
    vm_ptr: u32,
    blocked_status: i32,
    flags: u32,
) -> i32 {
    super::blocked::initial_action(vm_ptr, blocked_status, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_result_action_none() -> u32 {
    super::blocked::retry_result_action_none()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_result_action_arm_wait_timer() -> u32 {
    super::blocked::retry_result_action_arm_wait_timer()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_result_action_schedule_retry() -> u32 {
    super::blocked::retry_result_action_schedule_retry()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_result_action_schedule_retry_and_pump() -> u32 {
    super::blocked::retry_result_action_schedule_retry_and_pump()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_result_action(vm_ptr: u32, result_status: i32) -> i32 {
    super::blocked::retry_result_action(vm_ptr, result_status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_post_network_pump_action_schedule_retry() -> u32 {
    super::blocked::post_network_pump_action_schedule_retry()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_post_network_pump_action_schedule_retry_with_host_progress()
-> u32 {
    super::blocked::post_network_pump_action_schedule_retry_with_host_progress()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_post_network_pump_action(
    vm_ptr: u32,
    changed: u32,
    flags: u32,
) -> i32 {
    super::blocked::post_network_pump_action(vm_ptr, changed, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_stale_retry_result_action_none() -> u32 {
    super::blocked::stale_retry_result_action_none()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_stale_retry_result_action_handle_current_result() -> u32 {
    super::blocked::stale_retry_result_action_handle_current_result()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_stale_retry_result_action_handle_current_result_wait4() -> u32
{
    super::blocked::stale_retry_result_action_handle_current_result_wait4()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_stale_retry_result_action(
    vm_ptr: u32,
    blocked_status: i32,
) -> i32 {
    super::blocked::stale_retry_result_action(vm_ptr, blocked_status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_pipe_sync_action_not_pipe() -> u32 {
    super::blocked::rpc_pipe_sync_action_not_pipe()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_pipe_sync_action_none() -> u32 {
    super::blocked::rpc_pipe_sync_action_none()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_pipe_sync_action_sync_socket() -> u32 {
    super::blocked::rpc_pipe_sync_action_sync_socket()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_pipe_sync_action(vm_ptr: u32, blocked_status: i32) -> i32 {
    super::blocked::rpc_pipe_sync_action(vm_ptr, blocked_status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_preserve_canonical_eof(blocked_status: i32) -> i32 {
    super::blocked::rpc_preserve_canonical_eof(blocked_status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_post_resume_sync_flag_kernel_worker_available() -> u32 {
    super::blocked::rpc_post_resume_sync_flag_kernel_worker_available()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_post_resume_sync_flag_process_owner_mismatch() -> u32 {
    super::blocked::rpc_post_resume_sync_flag_process_owner_mismatch()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_post_resume_sync_action_none() -> u32 {
    super::blocked::rpc_post_resume_sync_action_none()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_post_resume_sync_action_fork_shared() -> u32 {
    super::blocked::rpc_post_resume_sync_action_fork_shared()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_post_resume_sync_action_socket() -> u32 {
    super::blocked::rpc_post_resume_sync_action_socket()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_rpc_post_resume_sync_action(
    blocked_status: i32,
    flags: u32,
) -> i32 {
    super::blocked::rpc_post_resume_sync_action(blocked_status, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_retry_action(vm_ptr: u32, flags: u32) -> i32 {
    super::blocked::retry_action(vm_ptr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_enqueue_blocked_wait_timer(vm_ptr: u32) -> i32 {
    super::enqueue_blocked_wait_timer_for_vm(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_enqueue_blocked_retry_timer(vm_ptr: u32, flags: u32) -> i32 {
    super::timer::enqueue_blocked_retry_timer_for_vm(vm_ptr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_timer_required(vm_ptr: u32) -> i32 {
    super::timer::blocked_wait_timer_required_for_vm(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_epoll_wait_timeout_ms(vm_ptr: u32) -> i64 {
    super::timer::epoll_wait_timeout_ms_for_vm(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_wake_mask_for_sync(source: u32) -> i32 {
    super::state_sync::wake_mask_for_sync(source)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_wait_status_matches_wake_source(
    status: i32,
    source: u32,
) -> i32 {
    super::state_sync::status_matches_wake_source(status, source)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_state_sync_request(vm_ptr: u32, kind: u32, flags: u32) -> i32 {
    super::state_sync::request(vm_ptr, kind, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_state_sync_next_run_flags(vm_ptr: u32, kind: u32) -> i32 {
    super::state_sync::next_run_flags(vm_ptr, kind)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_state_sync_complete(vm_ptr: u32, kind: u32) -> i32 {
    super::state_sync::complete(vm_ptr, kind)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_state_sync_clear(vm_ptr: u32, kind: u32) -> i32 {
    super::state_sync::clear(vm_ptr, kind)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_stdio_output_settle_max_passes(kind: u32) -> i32 {
    super::stdio::output_settle_max_passes(kind)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_stdio_output_settle_stable_passes(kind: u32) -> i32 {
    super::stdio::output_settle_stable_passes(kind)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_stdio_pipe_read_progress_action(
    vm_ptr: u32,
    pipe_slot: u32,
    drained: u32,
) -> i32 {
    super::stdio::pipe_read_progress_action(vm_ptr, pipe_slot, drained)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_next_host_op(out_ptr: u32, out_len: u32) -> i32 {
    super::host_op::write_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_next_host_op_kind(kind: u32, out_ptr: u32, out_len: u32) -> i32 {
    super::host_op::write_record_kind(kind, out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_host_op(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    super::host_op::write_process_record(vm_ptr, out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_memory_host_op(
    vm_ptr: u32,
    index: u32,
    out_ptr: u32,
    out_len: u32,
) -> i32 {
    super::process_memory::write_record(vm_ptr, index, out_ptr, out_len)
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
    super::thread_exit::write_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_lifecycle_record(out_ptr: u32, out_len: u32) -> i32 {
    super::process::write_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_vfork_execve_handoff_failure_wait_status() -> i32 {
    super::process_vfork::vfork_execve_handoff_failure_wait_status()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_vfork_execve_rollback(vm_ptr: u32, child_pid: i32) -> i32 {
    if vm_ptr == 0 {
        return -(crate::abi::EFAULT as i32);
    }
    let vm = unsafe { &mut *(vm_ptr as *mut crate::types::ThreadState) };
    super::process_vfork::rollback_execve_handoff(vm, child_pid)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_control_record(out_ptr: u32, out_len: u32) -> i32 {
    super::fd::write_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_held_ofd_refcount(vm_ptr: u32, ofd_id: u32) -> i32 {
    super::fd::process_held_ofd_refcount(vm_ptr, ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_holds_regular_file_ofd(vm_ptr: u32, ofd_id: u32) -> i32 {
    super::fd::process_holds_regular_file_ofd(vm_ptr, ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_ofd_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    super::fd::process_ofd_for_fd(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_fd_flags_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    super::fd::process_fd_flags_for_fd(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_fd_is_open(vm_ptr: u32, fd: u32) -> i32 {
    super::fd::process_fd_is_open(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_fd_type(ofd_id: u32) -> i32 {
    super::fd::ofd_fd_type(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_host_fd(ofd_id: u32) -> i32 {
    super::fd::ofd_host_fd(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_status_flags(ofd_id: u32) -> i32 {
    super::fd::ofd_status_flags(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_ino(ofd_id: u32) -> u32 {
    super::fd::ofd_ino(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_refcount(ofd_id: u32) -> i32 {
    super::fd::ofd_refcount(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_reconcile_refcount(ofd_id: u32, expected_refcount: i32) -> i32 {
    super::fd::ofd_reconcile_refcount(ofd_id, expected_refcount)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_offset(ofd_id: u32) -> i64 {
    super::fd::ofd_offset(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_is_regular_file(ofd_id: u32) -> i32 {
    super::fd::ofd_is_regular_file(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_pipe_sync_ofd_candidate(ofd_id: u32) -> i32 {
    super::fd::pipe_sync_ofd_candidate(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_pipe_slot_mask(ofd_id: u32) -> u64 {
    super::pipe::ofd_pipe_slot_mask(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_pipe_slot_mode(ofd_id: u32, pipe_slot: u32) -> u32 {
    super::pipe::ofd_pipe_slot_mode(ofd_id, pipe_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_pipe_generation_slot(ofd_id: u32) -> u32 {
    super::pipe::ofd_pipe_generation_slot(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_peer_flag_compatible() -> u32 {
    super::fork_shared::peer_flag_compatible()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_peer_flag_incompatible() -> u32 {
    super::fork_shared::peer_flag_incompatible()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_peer_flag_pipe_peer() -> u32 {
    super::fork_shared::peer_flag_pipe_peer()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_held_ofd_track_flag_shared() -> u32 {
    super::fork_shared::held_ofd_track_flag_shared()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_held_ofd_track_flag_host_stdio_pipe() -> u32 {
    super::fork_shared::held_ofd_track_flag_host_stdio_pipe()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_held_ofd_track_flag_stdio_fd() -> u32 {
    super::fork_shared::held_ofd_track_flag_stdio_fd()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_held_ofd_track_flag_fd_entry_source() -> u32 {
    super::fork_shared::held_ofd_track_flag_fd_entry_source()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_sync_target_action_reject() -> i32 {
    super::fork_shared::sync_target_action_reject()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_sync_target_action_defer() -> i32 {
    super::fork_shared::sync_target_action_defer()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_sync_target_action_use() -> i32 {
    super::fork_shared::sync_target_action_use()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_ofd_action_include() -> i32 {
    super::fork_shared::ofd_action_include()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_ofd_action_add_shared() -> i32 {
    super::fork_shared::ofd_action_add_shared()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_ofd_action_rehydrate() -> i32 {
    super::fork_shared::ofd_action_rehydrate()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_held_ofd_track_action(ofd_id: u32, flags: u32) -> i32 {
    super::fork_shared::held_ofd_track_action(ofd_id, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_ofd_identity_key(ofd_id: u32) -> u64 {
    super::fork_shared::ofd_identity_key(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_ofd_publish_action(ofd_id: u32, peer_flags: u32) -> i32 {
    super::fork_shared::ofd_publish_action(ofd_id, peer_flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_effect_sync_action(
    has_effect: i32,
    has_tracked_state: i32,
    source_holds_regular_file: i32,
    regular_file_has_peer: i32,
) -> i32 {
    super::fork_shared::effect_sync_action(
        has_effect,
        has_tracked_state,
        source_holds_regular_file,
        regular_file_has_peer,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_sync_target_action(
    invalid_pid: i32,
    running_worker: i32,
    vfork_ready_worker: i32,
    has_host_blocked_worker: i32,
    rpc_pending: i32,
    process_exit: i32,
    registered_process_exit: i32,
    registered_mismatch: i32,
    incompatible_ofd: i32,
    require_host_blocked: i32,
    include_memfs: i32,
    runtime_network_state: i32,
) -> i32 {
    super::fork_shared::sync_target_action(
        invalid_pid,
        running_worker,
        vfork_ready_worker,
        has_host_blocked_worker,
        rpc_pending,
        process_exit,
        registered_process_exit,
        registered_mismatch,
        incompatible_ofd,
        require_host_blocked,
        include_memfs,
        runtime_network_state,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_syncable_ofd_action(
    syncable: i32,
    source_conflicting: i32,
    allowed: i32,
    regular_file: i32,
    source_published: i32,
    runtime_network_socket: i32,
) -> i32 {
    super::fork_shared::syncable_ofd_action(
        syncable,
        source_conflicting,
        allowed,
        regular_file,
        source_published,
        runtime_network_socket,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_delta_source_ofd_action(
    allowed: i32,
    source_published: i32,
    source_held: i32,
    pipe_peer: i32,
) -> i32 {
    super::fork_shared::delta_source_ofd_action(allowed, source_published, source_held, pipe_peer)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_tracked_source_ofd_action(
    kernel_shared: i32,
    source_fd_entry: i32,
    syncable: i32,
    type_none: i32,
    incompatible_peer: i32,
) -> i32 {
    super::fork_shared::tracked_source_ofd_action(
        kernel_shared,
        source_fd_entry,
        syncable,
        type_none,
        incompatible_peer,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_pipe_peer_ofd_action(stale: i32, syncable: i32) -> i32 {
    super::fork_shared::pipe_peer_ofd_action(stale, syncable)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fork_shared_rehydrate_ofd_action(
    active: i32,
    source_held: i32,
    allowed: i32,
) -> i32 {
    super::fork_shared::rehydrate_ofd_action(active, source_held, allowed)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_entry_restore_action(
    vm_ptr: u32,
    fd: u32,
    snapshot_ofd_id: u32,
    syscall_nr: u64,
    flags: u32,
) -> i32 {
    super::fd::fd_entry_restore_action(vm_ptr, fd, snapshot_ofd_id, syscall_nr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fd_entry_guest_write_action(
    vm_ptr: u32,
    fd: u32,
    candidate_ofd_id: u32,
    explicit_ofd_id: u32,
) -> i32 {
    super::fd::fd_entry_guest_write_action(vm_ptr, fd, candidate_ofd_id, explicit_ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_slot_write_action(
    ofd_id: u32,
    candidate_type: i32,
    candidate_host_fd: i32,
    candidate_ino: u32,
    candidate_offset: i64,
) -> i32 {
    super::fd::ofd_slot_write_action(
        ofd_id,
        candidate_type,
        candidate_host_fd,
        candidate_ino,
        candidate_offset,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_ofd_slot_restore_action(
    ofd_id: u32,
    candidate_type: i32,
    candidate_host_fd: i32,
    candidate_ino: u32,
    candidate_offset: i64,
    syscall_nr: u64,
    flags: u32,
) -> i32 {
    super::fd::ofd_slot_restore_action(
        ofd_id,
        candidate_type,
        candidate_host_fd,
        candidate_ino,
        candidate_offset,
        syscall_nr,
        flags,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_regular_file_offset_restore_action(
    ofd_id: u32,
    snapshot_host_fd: i32,
    snapshot_ino: u32,
    snapshot_offset: i64,
) -> i32 {
    super::fd::regular_file_offset_restore_action(
        ofd_id,
        snapshot_host_fd,
        snapshot_ino,
        snapshot_offset,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_take_completed_sync_effects(vm_ptr: u32, status: i32) -> u32 {
    super::sync_effects::take_completed_sync_effects(vm_ptr, status)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_private_pipe_slot_mask(vm_ptr: u32) -> u64 {
    super::pipe::process_private_pipe_slot_mask(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_private_pipe_source_mode(vm_ptr: u32, pipe_slot: u32) -> u32 {
    super::pipe::process_private_pipe_source_mode(vm_ptr, pipe_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_private_pipe_target_mode(vm_ptr: u32, pipe_slot: u32) -> u32 {
    super::pipe::process_private_pipe_target_mode(vm_ptr, pipe_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_held_pipe_slot_mask(vm_ptr: u32) -> u64 {
    super::pipe::process_held_pipe_slot_mask(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_pipe_used_mask(vm_ptr: u32) -> u64 {
    super::pipe::process_pipe_used_mask(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_pipe_slot_mode(vm_ptr: u32, pipe_slot: u32) -> u32 {
    super::pipe::process_pipe_slot_mode(vm_ptr, pipe_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_pipe_slot_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    super::pipe::process_pipe_slot_for_fd(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_pipe_ofd_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    super::pipe::process_pipe_ofd_for_fd(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_pipe_host_fd_for_fd(vm_ptr: u32, fd: u32) -> i32 {
    super::pipe::process_pipe_host_fd_for_fd(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_pipe_read_open_count(vm_ptr: u32, pipe_slot: u32) -> i32 {
    super::pipe::process_pipe_read_open_count(vm_ptr, pipe_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_pipe_write_open_count(vm_ptr: u32, pipe_slot: u32) -> i32 {
    super::pipe::process_pipe_write_open_count(vm_ptr, pipe_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_pipe_reconcile_control(
    pipe_slot: u32,
    read_open: i32,
    write_open: i32,
) -> i32 {
    super::pipe::pipe_reconcile_control(pipe_slot, read_open, write_open)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_pipe_slot_snapshot_merge_action(
    context: u32,
    mode: u32,
    fresh: u32,
    source_head: u32,
    source_tail: u32,
    source_read_open: i32,
    source_write_open: i32,
    source_generation: u32,
    target_head: u32,
    target_tail: u32,
    target_read_open: i32,
    target_write_open: i32,
    target_generation: u32,
) -> u32 {
    super::pipe::pipe_slot_snapshot_merge_action(
        context,
        mode,
        fresh,
        source_head,
        source_tail,
        source_read_open,
        source_write_open,
        source_generation,
        target_head,
        target_tail,
        target_read_open,
        target_write_open,
        target_generation,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_pipe_resume_action(vm_ptr: u32) -> i32 {
    super::pipe::blocked_pipe_resume_action(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_pipe_sync_before_retry_action(vm_ptr: u32, flags: u32) -> i32 {
    super::pipe::blocked_pipe_sync_before_retry_action(vm_ptr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_pipe_sync_before_retry_requested(vm_ptr: u32) -> i32 {
    super::pipe::blocked_pipe_sync_before_retry_requested(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_pipe_sync_before_retry_clear(vm_ptr: u32) -> i32 {
    super::pipe::blocked_pipe_sync_before_retry_clear(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_epoll_held_ofd(vm_ptr: u32, index: u32) -> u32 {
    super::epoll::process_epoll_held_ofd(vm_ptr, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_epoll_dependent_ofd(vm_ptr: u32, index: u32) -> u32 {
    super::epoll::process_epoll_dependent_ofd(vm_ptr, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_sync_dependent_ofd(vm_ptr: u32, index: u32) -> u32 {
    super::epoll::process_sync_dependent_ofd(vm_ptr, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_epoll_dependent_sync_ofd(vm_ptr: u32, index: u32) -> u32 {
    super::epoll::process_epoll_dependent_sync_ofd(vm_ptr, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_epoll_depends_on_ofd(vm_ptr: u32, ofd_id: u32) -> u32 {
    super::epoll::process_epoll_depends_on_ofd(vm_ptr, ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_epoll_watched_ofd(vm_ptr: u32, index: u32) -> u32 {
    super::epoll::blocked_epoll_watched_ofd(vm_ptr, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_epoll_dependent_sync_ofd(vm_ptr: u32, index: u32) -> u32 {
    super::epoll::blocked_epoll_dependent_sync_ofd(vm_ptr, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_blocked_epoll_watches_pipe(vm_ptr: u32) -> u32 {
    super::epoll::blocked_epoll_watches_pipe(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_socket_held_ofd(vm_ptr: u32, index: u32) -> u32 {
    super::socket::process_socket_held_ofd(vm_ptr, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_socket_ofd_is_socket(ofd_id: u32) -> i32 {
    super::socket::socket_ofd_is_socket(ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_socket_ofd_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    super::socket::process_socket_ofd_for_fd(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_process_socket_drain_fd(
    vm_ptr: u32,
    connected_fd: u32,
    index: u32,
) -> i32 {
    super::socket::process_socket_drain_fd(vm_ptr, connected_fd, index)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_socket_connect_fd(vm_ptr: u32) -> i32 {
    super::socket::connect_fd(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_socket_connect_peer_addr(
    vm_ptr: u32,
    dst_ptr: u32,
    dst_len: u32,
) -> i32 {
    super::socket::connect_peer_addr(vm_ptr, dst_ptr, dst_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_socket_connect_peer_addr_for_fd(
    vm_ptr: u32,
    fd: u32,
    dst_ptr: u32,
    dst_len: u32,
) -> i32 {
    super::socket::connect_peer_addr_for_fd(vm_ptr, fd, dst_ptr, dst_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_socket_prepare_external_peer(vm_ptr: u32, fd: u32) -> i32 {
    super::socket::prepare_external_peer(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_socket_commit_external_connect_result(
    vm_ptr: u32,
    fd: u32,
    result: i64,
) -> i32 {
    super::socket::commit_external_connect_result(vm_ptr, fd, result)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_socket_close_external_peer(vm_ptr: u32, fd: u32) -> i32 {
    super::socket::close_external_peer(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_socket_force_shutdown(vm_ptr: u32, fd: u32) -> i32 {
    super::socket::force_shutdown(vm_ptr, fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_socket_bridge_active_fd(
    vm_ptr: u32,
    preferred_fd: u32,
    expected_ofd: u32,
    pending_connect: u32,
) -> i32 {
    super::socket::bridge_active_fd(vm_ptr, preferred_fd, expected_ofd, pending_connect)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_control_record(out_ptr: u32, out_len: u32) -> i32 {
    super::fs::write_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_ring_request(vm_ptr: u32) -> u32 {
    super::fs::pending_ring_request(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_regular_file_fd(vm_ptr: u32) -> i32 {
    super::fs::pending_regular_file_fd(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_regular_file_ofd(vm_ptr: u32) -> u32 {
    super::fs::pending_regular_file_ofd(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pipe_refresh_before_resume_action(vm_ptr: u32, flags: u32) -> i32 {
    super::fs::pipe_refresh_before_resume_action(vm_ptr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_backing_fill_ino(vm_ptr: u32) -> u32 {
    super::fs::pending_backing_fill_ino(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_backing_fill_offset(vm_ptr: u32) -> u64 {
    super::fs::pending_backing_fill_offset(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_backing_fill_length(vm_ptr: u32) -> u64 {
    super::fs::pending_backing_fill_length(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_backing_fill_expected_size(vm_ptr: u32) -> u64 {
    super::fs::pending_backing_fill_expected_size(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_backing_fill_opcode(vm_ptr: u32) -> u32 {
    super::fs::pending_backing_fill_opcode(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_clear_pending_backing_fill(vm_ptr: u32) -> i32 {
    super::fs::clear_pending_backing_fill(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_retry_limit(
    opcode: u32,
    offset: u64,
    length: u64,
    expected_size: u64,
) -> u32 {
    super::fs::backing_retry_limit(opcode, offset, length, expected_size)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_fill_span_decision(
    opcode: u32,
    offset: i64,
    length: i64,
    expected_size: i64,
) -> i32 {
    super::fs::backing_fill_span_decision(opcode, offset, length, expected_size)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_fill_span_offset() -> u64 {
    super::fs::backing_fill_span_offset()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_fill_span_end() -> u64 {
    super::fs::backing_fill_span_end()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_fill_span_length() -> u64 {
    super::fs::backing_fill_span_length()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_mmap_guest_write_ptr(vm_ptr: u32) -> u64 {
    super::fs::pending_mmap_guest_write_ptr(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_mmap_guest_write_len(vm_ptr: u32) -> u64 {
    super::fs::pending_mmap_guest_write_len(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_pending_mmap_guest_write_snapshot_len(vm_ptr: u32) -> u64 {
    super::fs::pending_mmap_guest_write_snapshot_len(vm_ptr)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_dirty_page_decision(
    op: u32,
    ino: u32,
    offset: u64,
    length_or_size: u64,
    current_size: u64,
    current_file_object_id: u64,
    current_generation: u64,
    existing_dirty_pages: u32,
    delta_dirty_pages: u32,
    resident_page_capacity: u32,
    page_map_newer: u32,
) -> i64 {
    super::fs::dirty_page_decision(
        op,
        ino,
        offset,
        length_or_size,
        current_size,
        current_file_object_id,
        current_generation,
        existing_dirty_pages,
        delta_dirty_pages,
        resident_page_capacity,
        page_map_newer,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_dirty_page_decision_next_size() -> u64 {
    super::fs::dirty_page_decision_next_size()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_dirty_page_decision_file_object_id() -> u64 {
    super::fs::dirty_page_decision_file_object_id()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_dirty_page_decision_generation() -> u64 {
    super::fs::dirty_page_decision_generation()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_dirty_page_decision_flags() -> u32 {
    super::fs::dirty_page_decision_flags()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_page_table_source_decision(
    ino: u32,
    has_dirty_pages: u32,
    published_file_object_id: u64,
    published_generation: u64,
    published_size: u64,
    backing_file_object_id: u64,
    backing_generation: u64,
    backing_size: u64,
) -> i32 {
    super::fs::page_table_source_decision(
        ino,
        has_dirty_pages,
        published_file_object_id,
        published_generation,
        published_size,
        backing_file_object_id,
        backing_generation,
        backing_size,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_fill_probe_direct(opcode: u32, aligned_length: u64) -> i32 {
    super::fs::backing_fill_probe_direct(opcode, aligned_length)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_fill_mode_decision(
    opcode: u32,
    aligned_length: u64,
    head_probe_readable: u32,
    tail_probe_readable: u32,
) -> i32 {
    super::fs::backing_fill_mode_decision(
        opcode,
        aligned_length,
        head_probe_readable,
        tail_probe_readable,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_source_range_decision(
    ino: u32,
    file_offset: i64,
    length: i64,
    expected_size: i64,
    extent_offset: i64,
    extent_length: i64,
    source_byte_length: i64,
    require_source_bounds: u32,
) -> i32 {
    super::fs::backing_source_range_decision(
        ino,
        file_offset,
        length,
        expected_size,
        extent_offset,
        extent_length,
        source_byte_length,
        require_source_bounds,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_source_range_source_byte_length() -> u64 {
    super::fs::backing_source_range_source_byte_length()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_source_range_source_offset() -> u64 {
    super::fs::backing_source_range_source_offset()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_source_range_read_length() -> u64 {
    super::fs::backing_source_range_read_length()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_clean_backing_range_decision(
    ino: u32,
    offset: i64,
    length: i64,
    published_size: i64,
    backing_size: i64,
) -> i32 {
    super::fs::clean_backing_range_decision(ino, offset, length, published_size, backing_size)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_clean_backing_range_read_offset() -> u64 {
    super::fs::clean_backing_range_read_offset()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_clean_backing_range_read_length() -> u64 {
    super::fs::clean_backing_range_read_length()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_clean_backing_range_output_length() -> u64 {
    super::fs::clean_backing_range_output_length()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_dirty_prepare_decision(
    ino: u32,
    op: u32,
    expected_size: i64,
    published_present: u32,
    published_size: i64,
    published_file_object_id: u64,
    published_data_off: u64,
    source_is_regular: u32,
    source_file_object_id: u64,
    has_dirty_resident_pages: u32,
) -> i32 {
    super::fs::dirty_prepare_decision(
        ino,
        op,
        expected_size,
        published_present,
        published_size,
        published_file_object_id,
        published_data_off,
        source_is_regular,
        source_file_object_id,
        has_dirty_resident_pages,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_dirty_prepare_publish_mode() -> u32 {
    super::fs::dirty_prepare_publish_mode()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_data_sync_decision(
    kind: u32,
    ino: u32,
    source_mode: u32,
    source_size: i64,
    target_mode: u32,
    target_size: i64,
    published_present: u32,
    published_mode: u32,
    published_size: i64,
    published_file_object_id: u64,
    has_dirty_resident_pages: u32,
    page_map_newer: u32,
    has_backing_file: u32,
) -> i32 {
    super::fs::data_sync_decision(
        kind,
        ino,
        source_mode,
        source_size,
        target_mode,
        target_size,
        published_present,
        published_mode,
        published_size,
        published_file_object_id,
        has_dirty_resident_pages,
        page_map_newer,
        has_backing_file,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_metadata_sync_decision(
    ino: u32,
    source_present: u32,
    source_mode: u32,
    source_size: i64,
    parent_present: u32,
    parent_ino: u32,
    published_present: u32,
    published_mode: u32,
    published_size: i64,
    published_parent_ino: u32,
    published_name_matches: u32,
    has_dirty_resident_pages: u32,
    backing_present: u32,
) -> i32 {
    super::fs::metadata_sync_decision(
        ino,
        source_present,
        source_mode,
        source_size,
        parent_present,
        parent_ino,
        published_present,
        published_mode,
        published_size,
        published_parent_ino,
        published_name_matches,
        has_dirty_resident_pages,
        backing_present,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_metadata_sync_size() -> u64 {
    super::fs::metadata_sync_size()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_metadata_sync_backing_source() -> u32 {
    super::fs::metadata_sync_backing_source()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_metadata_full_sync_decision(
    tree_mutated: u32,
    handled_metadata_mutation: u32,
) -> i32 {
    super::fs::metadata_full_sync_decision(tree_mutated, handled_metadata_mutation)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_object_decision(
    op: u32,
    ino: u32,
    published_file_object_id: u64,
    published_generation: u64,
    backing_file_object_id: u64,
    backing_generation: u64,
) -> i32 {
    super::fs::backing_object_decision(
        op,
        ino,
        published_file_object_id,
        published_generation,
        backing_file_object_id,
        backing_generation,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_object_file_object_id() -> u64 {
    super::fs::backing_object_file_object_id()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_backing_object_generation() -> u64 {
    super::fs::backing_object_generation()
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_completion_decision(
    vm_ptr: u32,
    opcode: u32,
    effects: u32,
    result: i64,
    host_memfs_mutated: u32,
    host_ofd_state_changed: u32,
    pending_ring_request: u32,
    regular_file_request: u32,
) -> u32 {
    super::fs::completion_decision(
        vm_ptr,
        opcode,
        effects,
        result,
        host_memfs_mutated,
        host_ofd_state_changed,
        pending_ring_request,
        regular_file_request,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_response_disposition(
    vm_ptr: u32,
    runtime_pid: i32,
    opcode: u32,
    result: i64,
    owner_async_status: i32,
    last_status: i32,
) -> u32 {
    super::fs::response_disposition(
        vm_ptr,
        runtime_pid,
        opcode,
        result,
        owner_async_status,
        last_status,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_local_metadata_action(
    opcode: u32,
    effects: u32,
    result: i64,
    has_primary_path: u32,
    has_secondary_path: u32,
) -> u32 {
    super::fs::local_metadata_action(
        opcode,
        effects,
        result,
        has_primary_path,
        has_secondary_path,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_resident_page_slot_decision(
    existing_slot: i32,
    empty_slot: i32,
    clean_evict_slot: i32,
) -> i32 {
    super::fs::resident_page_slot_decision(existing_slot, empty_slot, clean_evict_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_fs_resident_page_evict_status(record_found: u32, dirty: u32) -> u32 {
    super::fs::resident_page_evict_status(record_found, dirty)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_signal_control_record(out_ptr: u32, out_len: u32) -> i32 {
    super::signal::write_record(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_debug_snapshot(out_ptr: u32, out_len: u32) -> i32 {
    super::debug::write_snapshot(out_ptr, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn supervisor_thread_state_snapshot(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    super::thread::write_state_snapshot(vm_ptr, out_ptr, out_len)
}
