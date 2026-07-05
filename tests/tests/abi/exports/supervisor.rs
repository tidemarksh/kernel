use super::support::*;

use core::sync::atomic::Ordering;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn fnv_hash(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fold_log_hash(previous: u64, entry_hash: u64, entry_len: u32) -> u64 {
    let mut next = previous ^ entry_hash;
    next = next.wrapping_mul(FNV_PRIME);
    next ^= u64::from(entry_len);
    next = next.wrapping_mul(FNV_PRIME);
    next
}

#[test]
fn supervisor_pipe_slot_snapshot_merge_actions_are_kernel_owned() {
    let shared = supervisor_pipe_slot_snapshot_context_shared_state();
    let thread = supervisor_pipe_slot_snapshot_context_thread_step();
    let kernel_worker_apply = supervisor_pipe_slot_snapshot_context_kernel_worker_apply();
    let kernel_worker_process = supervisor_pipe_slot_snapshot_context_kernel_worker_process();
    let kernel_worker_canonical = supervisor_pipe_slot_snapshot_context_kernel_worker_canonical();
    let read = supervisor_pipe_slot_mode_read();
    let write = supervisor_pipe_slot_mode_write();
    let control = supervisor_pipe_slot_mode_control();
    let skip = supervisor_pipe_slot_snapshot_action_skip();
    let apply = supervisor_pipe_slot_snapshot_action_apply_slot();
    let head = supervisor_pipe_slot_snapshot_action_set_head_to_source();
    let tail = supervisor_pipe_slot_snapshot_action_set_tail_to_source();
    let copy_full = supervisor_pipe_slot_snapshot_action_copy_full();
    let copy_delta = supervisor_pipe_slot_snapshot_action_copy_tail_delta();
    let sync = supervisor_pipe_slot_snapshot_action_sync_generation();
    let stop = supervisor_pipe_slot_snapshot_action_stop();

    assert_eq!(
        supervisor_pipe_slot_snapshot_merge_action(
            shared,
            read | write,
            0,
            0,
            0,
            1,
            1,
            1,
            4,
            8,
            1,
            1,
            2,
        ),
        skip | stop,
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_merge_action(
            shared,
            read | write | control,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            1,
            1,
            0,
        ),
        apply | sync | stop,
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_merge_action(shared, read, 0, 5, 8, 1, 1, 0, 1, 2, 1, 1, 0,),
        head | tail | copy_full | sync,
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_merge_action(thread, write, 0, 2, 10, 1, 1, 0, 2, 3, 1, 1, 0,),
        tail | copy_delta | sync,
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_merge_action(
            thread, control, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        ),
        apply | sync | stop,
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_merge_action(
            kernel_worker_apply,
            read | write,
            0,
            0,
            0,
            0,
            0,
            0,
            7,
            9,
            0,
            0,
            0,
        ),
        apply | sync | stop,
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_merge_action(
            kernel_worker_process,
            read | write,
            0,
            5,
            9,
            1,
            1,
            0,
            1,
            3,
            1,
            1,
            0,
        ),
        head | tail | copy_full | sync,
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_merge_action(
            kernel_worker_canonical,
            write,
            0,
            5,
            9,
            1,
            1,
            0,
            1,
            9,
            1,
            1,
            0,
        ),
        head | tail | copy_full | sync,
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_merge_action(
            kernel_worker_canonical,
            read | write,
            0,
            0,
            0,
            1,
            1,
            1,
            4,
            8,
            1,
            1,
            2,
        ),
        skip | stop,
    );
}

fn write_pollfd(t: &mut TestVm, addr: u64, fd: i32, events: u16) {
    let mut bytes = [0u8; 8];
    bytes[0..4].copy_from_slice(&fd.to_le_bytes());
    bytes[4..6].copy_from_slice(&events.to_le_bytes());
    t.write_mem(addr, &bytes);
}

#[test]
fn supervisor_shadow_exports_are_additive_and_deterministic() {
    supervisor_reset_shadow_log();

    assert_eq!(supervisor_abi_version(), 1);
    assert_eq!(supervisor_debug_snapshot_bytes(), 112);
    assert_eq!(supervisor_debug_snapshot(0, 0), 112);
    assert_eq!(supervisor_thread_event_record_bytes(), 80);
    assert_eq!(supervisor_thread_event_record_magic(), 0x5645_5354);
    assert_eq!(supervisor_thread_event_kind_blocked(), 1);
    assert_eq!(supervisor_thread_event_kind_ready(), 2);
    assert_eq!(supervisor_thread_event_kind_faulted(), 3);
    assert_eq!(supervisor_thread_event_kind_exited(), 4);
    assert_eq!(supervisor_thread_event_kind_host_completion_arrived(), 5);
    assert_eq!(supervisor_thread_event_kind_timer_fired(), 6);
    assert_eq!(supervisor_thread_event_kind_network_readable(), 7);
    assert_eq!(supervisor_thread_event_kind_backing_store_ready(), 8);
    assert_eq!(
        supervisor_thread_state_snapshot_bytes(),
        32 + abi_max_threads() as u32 * 32
    );
    assert_eq!(supervisor_thread_state_snapshot_magic(), 0x4854_5354);
    assert_eq!(
        supervisor_thread_state_snapshot(0, 0, 0),
        supervisor_thread_state_snapshot_bytes() as i32
    );
    assert_eq!(supervisor_resume_record_magic(), 0x5255_5354);
    assert_eq!(supervisor_host_op_record_bytes(), 64);
    assert_eq!(supervisor_host_op_record_magic(), 0x4f48_5354);
    assert_eq!(supervisor_host_op_kind_spawn_thread_worker(), 1);
    assert_eq!(supervisor_host_op_kind_spawn_process_worker(), 2);
    assert_eq!(supervisor_host_op_kind_create_process_memory(), 3);
    assert_eq!(supervisor_host_op_kind_copy_memory_ranges(), 4);
    assert_eq!(supervisor_host_op_kind_fill_page_from_backing(), 5);
    assert_eq!(supervisor_host_op_kind_flush_dirty_page(), 6);
    assert_eq!(supervisor_host_op_kind_process_fs_request(), 7);
    assert_eq!(supervisor_host_op_kind_host_network_connect(), 8);
    assert_eq!(supervisor_host_op_kind_host_network_read(), 9);
    assert_eq!(supervisor_host_op_kind_host_network_write(), 10);
    assert_eq!(supervisor_host_op_kind_host_network_close(), 11);
    assert_eq!(supervisor_host_op_kind_arm_host_timer(), 12);
    assert_eq!(supervisor_host_op_kind_resume_thread(), 13);
    assert_eq!(supervisor_host_op_kind_terminate_worker(), 14);
    assert_eq!(supervisor_host_op_kind_retry_blocked_worker(), 15);
    assert_eq!(supervisor_host_completion_record_bytes(), 64);
    assert_eq!(supervisor_host_completion_record_magic(), 0x4348_5354);
    assert_eq!(supervisor_host_completion_outcome_success(), 1);
    assert_eq!(supervisor_host_completion_outcome_failure(), 2);
    assert_eq!(supervisor_process_host_op_record_bytes(), 96);
    assert_eq!(supervisor_process_host_op_record_magic(), 0x4850_5354);
    assert_eq!(supervisor_process_host_op_kind_spawn_process_worker(), 1);
    assert_eq!(supervisor_fault_exit_decision_bytes(), 88);
    assert_eq!(supervisor_fault_exit_decision_magic(), 0x5846_5354);
    assert_eq!(supervisor_fault_exit_kind_thread_exit(), 1);
    assert_eq!(supervisor_fault_exit_kind_process_exit(), 2);
    assert_eq!(supervisor_thread_exit_cleanup_record_bytes(), 96);
    assert_eq!(supervisor_thread_exit_cleanup_record_magic(), 0x4358_5354);
    assert_eq!(supervisor_thread_exit_cleanup_kind_thread_exit(), 1);
    assert_eq!(supervisor_process_lifecycle_record_bytes(), 96);
    assert_eq!(supervisor_process_lifecycle_record_magic(), 0x4350_5354);
    assert_eq!(supervisor_process_lifecycle_kind_child_exit_published(), 1);
    assert_eq!(supervisor_process_lifecycle_kind_wait4_completed(), 2);
    assert_eq!(supervisor_fd_control_record_bytes(), 96);
    assert_eq!(supervisor_fd_control_record_magic(), 0x4446_5354);
    assert_eq!(supervisor_fd_control_kind_pipe_created(), 1);
    assert_eq!(supervisor_fd_control_kind_fd_closed(), 2);
    assert_eq!(supervisor_fd_control_kind_fd_duplicated(), 3);
    assert_eq!(supervisor_fd_control_kind_fd_flags_updated(), 4);
    assert_eq!(supervisor_fd_control_kind_epoll_created(), 5);
    assert_eq!(supervisor_fd_control_kind_epoll_ctl_add(), 6);
    assert_eq!(supervisor_fd_control_kind_epoll_ctl_del(), 7);
    assert_eq!(supervisor_fd_control_kind_epoll_ctl_mod(), 8);
    assert_eq!(supervisor_fd_control_kind_socket_created(), 9);
    assert_eq!(supervisor_fd_control_kind_socketpair_created(), 10);
    assert_eq!(supervisor_fd_control_kind_socket_bound(), 11);
    assert_eq!(supervisor_fd_control_kind_socket_listening(), 12);
    assert_eq!(supervisor_fd_control_kind_socket_connect_started(), 13);
    assert_eq!(supervisor_fd_control_kind_socket_connected(), 14);
    assert_eq!(supervisor_fd_control_kind_socket_connect_failed(), 15);
    assert_eq!(supervisor_fd_control_kind_socket_accepted(), 16);
    assert_eq!(supervisor_fd_entry_restore_action_apply(), 1);
    assert_eq!(supervisor_fd_entry_restore_action_skip(), 2);
    assert_eq!(
        supervisor_fd_entry_restore_flag_preserve_live_regular_file(),
        1
    );
    assert_eq!(
        supervisor_fd_entry_restore_flag_preserve_live_epoll_dependent(),
        2
    );
    assert_eq!(supervisor_ofd_slot_restore_flag_referenced_by_fd_entry(), 1);
    assert_eq!(
        supervisor_ofd_slot_restore_flag_trust_regular_file_offset(),
        2
    );
    assert_eq!(
        supervisor_regular_file_offset_restore_action(0, 0, 0, 0),
        supervisor_fd_entry_restore_action_skip() as i32
    );
    assert_eq!(supervisor_fork_shared_peer_flag_compatible(), 1);
    assert_eq!(supervisor_fork_shared_peer_flag_incompatible(), 2);
    assert_eq!(supervisor_fork_shared_peer_flag_pipe_peer(), 4);
    assert_eq!(supervisor_fork_shared_held_ofd_track_flag_shared(), 1);
    assert_eq!(
        supervisor_fork_shared_held_ofd_track_flag_host_stdio_pipe(),
        2
    );
    assert_eq!(supervisor_fork_shared_held_ofd_track_flag_stdio_fd(), 4);
    assert_eq!(
        supervisor_fork_shared_held_ofd_track_flag_fd_entry_source(),
        8
    );
    assert_eq!(supervisor_fork_shared_sync_target_action_reject(), 0);
    assert_eq!(supervisor_fork_shared_sync_target_action_defer(), 1);
    assert_eq!(supervisor_fork_shared_sync_target_action_use(), 2);
    assert_eq!(supervisor_fork_shared_ofd_action_include(), 1);
    assert_eq!(supervisor_fork_shared_ofd_action_add_shared(), 2);
    assert_eq!(supervisor_fork_shared_ofd_action_rehydrate(), 4);
    assert_eq!(supervisor_thread_take_completed_sync_effects(0, 0), 0);
    assert_eq!(supervisor_pipe_slot_mode_read(), 1);
    assert_eq!(supervisor_pipe_slot_mode_write(), 2);
    assert_eq!(supervisor_pipe_slot_mode_control(), 4);
    assert_eq!(supervisor_pipe_slot_snapshot_context_shared_state(), 1);
    assert_eq!(supervisor_pipe_slot_snapshot_context_thread_step(), 2);
    assert_eq!(
        supervisor_pipe_slot_snapshot_context_kernel_worker_apply(),
        3
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_context_kernel_worker_process(),
        4
    );
    assert_eq!(
        supervisor_pipe_slot_snapshot_context_kernel_worker_canonical(),
        5
    );
    assert_eq!(supervisor_pipe_slot_snapshot_action_skip(), 1);
    assert_eq!(supervisor_pipe_slot_snapshot_action_apply_slot(), 2);
    assert_eq!(supervisor_pipe_slot_snapshot_action_apply_control(), 4);
    assert_eq!(supervisor_pipe_slot_snapshot_action_set_head_to_source(), 8);
    assert_eq!(
        supervisor_pipe_slot_snapshot_action_set_tail_to_source(),
        16
    );
    assert_eq!(supervisor_pipe_slot_snapshot_action_set_head_zero(), 32);
    assert_eq!(supervisor_pipe_slot_snapshot_action_copy_full(), 64);
    assert_eq!(supervisor_pipe_slot_snapshot_action_copy_tail_delta(), 128);
    assert_eq!(supervisor_pipe_slot_snapshot_action_sync_generation(), 256);
    assert_eq!(supervisor_pipe_slot_snapshot_action_stop(), 512);
    assert_eq!(supervisor_blocked_pipe_resume_action_defer(), 0);
    assert_eq!(supervisor_blocked_pipe_resume_action_direct(), 1);
    assert_eq!(supervisor_blocked_pipe_sync_before_retry_action_none(), 0);
    assert_eq!(
        supervisor_blocked_pipe_sync_before_retry_action_request_sync(),
        1
    );
    assert_eq!(
        supervisor_blocked_pipe_sync_before_retry_action_request_sync_and_drain_output(),
        2
    );
    assert_eq!(
        supervisor_blocked_pipe_sync_before_retry_action_schedule_retry(),
        3
    );
    assert_eq!(
        supervisor_blocked_pipe_sync_before_retry_flag_kernel_worker_available(),
        1
    );
    assert_eq!(supervisor_resume_flag_timeout_expired(), 1);
    assert_eq!(supervisor_blocked_wait_network_pump_action_skip(), 0);
    assert_eq!(supervisor_blocked_wait_network_pump_action_pump(), 1);
    assert_eq!(supervisor_state_sync_kind_pipe(), 1);
    assert_eq!(supervisor_state_sync_kind_epoll(), 2);
    assert_eq!(supervisor_state_sync_kind_socket(), 3);
    assert_eq!(supervisor_state_sync_request_flag_wake_waiters(), 1);
    assert_eq!(supervisor_state_sync_run_flag_run(), 1);
    assert_eq!(supervisor_state_sync_run_flag_wake_waiters(), 2);
    assert_eq!(supervisor_blocked_wait_wake_source_pipe_sync(), 1);
    assert_eq!(supervisor_blocked_wait_wake_source_epoll_sync(), 2);
    assert_eq!(supervisor_blocked_wait_wake_source_socket_sync(), 3);
    assert_eq!(supervisor_blocked_wait_wake_source_pipe_and_epoll_sync(), 4);
    assert_eq!(supervisor_blocked_wait_wake_target_pipe_wait(), 1);
    assert_eq!(supervisor_blocked_wait_wake_target_epoll_wait(), 2);
    assert_eq!(supervisor_blocked_wait_wake_target_socket_recv(), 4);
    assert_eq!(supervisor_blocked_wait_wake_target_socket_send(), 8);
    assert_eq!(supervisor_blocked_wait_wake_flag_rpc_pending(), 1);
    assert_eq!(supervisor_blocked_wait_wake_action_skip(), 0);
    assert_eq!(supervisor_blocked_wait_wake_action_retry(), 1);
    assert_eq!(
        supervisor_blocked_wait_wake_action_clear_pipe_sync_and_retry(),
        2
    );
    assert_eq!(supervisor_blocked_wait_wake_action_log_epoll_and_retry(), 3);
    assert_eq!(supervisor_wait_in_worker_status_action_none(), 0);
    assert_eq!(
        supervisor_wait_in_worker_status_action_block_epoll_timeout(),
        1
    );
    assert_eq!(supervisor_wait_in_worker_status_action_park_futex(), 2);
    assert_eq!(
        supervisor_wait_in_worker_status_action_block_wait4_and_sync_pipe(),
        4
    );
    assert_eq!(supervisor_wait_in_worker_status_action_sync_socket(), 8);
    assert_eq!(supervisor_wait_in_worker_status_action_sync_epoll(), 16);
    assert_eq!(supervisor_wait_in_worker_status_action_sync_pipe(), 32);
    assert_eq!(
        supervisor_wait_in_worker_status_action_flag_running_worker(),
        1
    );
    assert_eq!(
        supervisor_wait_in_worker_status_action_flag_kernel_worker_available(),
        2
    );
    assert_eq!(
        supervisor_wait_in_worker_status_action_flag_epoll_state_kernel_owns(),
        4
    );
    assert_eq!(supervisor_wait4_child_exit_blocked_parent_action_none(), 0);
    assert_eq!(
        supervisor_wait4_child_exit_blocked_parent_action_invalidate_rpc(),
        1
    );
    assert_eq!(
        supervisor_wait4_child_exit_blocked_parent_action_clear_pipe_sync_before_retry(),
        2
    );
    assert_eq!(supervisor_wait4_rpc_local_status_action_skip(), 0);
    assert_eq!(supervisor_wait4_rpc_local_status_action_start(), 1);
    assert_eq!(supervisor_scheduler_clear_blocked_action_none(), 0);
    assert_eq!(
        supervisor_scheduler_clear_blocked_action_clear_pipe_sync_before_retry(),
        1
    );
    assert_eq!(
        supervisor_scheduler_clear_blocked_flag_clear_pipe_sync_before_retry(),
        1
    );
    assert_eq!(supervisor_scheduler_block_worker_action_record_blocked(), 0);
    assert_eq!(supervisor_scheduler_block_worker_action_park_futex(), 1);
    assert_eq!(supervisor_scheduler_futex_waiter_action_not_waiter(), 0);
    assert_eq!(supervisor_scheduler_futex_waiter_action_waiter(), 1);
    assert_eq!(supervisor_worker_status_transition_action_enqueue(), 0);
    assert_eq!(supervisor_worker_status_transition_action_connect_wait(), 1);
    assert_eq!(supervisor_worker_status_transition_action_park_futex(), 2);
    assert_eq!(supervisor_worker_status_transition_action_host_wait(), 3);
    assert_eq!(supervisor_stdio_output_settle_kind_visible(), 1);
    assert_eq!(supervisor_stdio_output_settle_kind_inherited_child(), 2);
    assert_eq!(supervisor_stdio_pipe_read_progress_action_none(), 0);
    assert_eq!(supervisor_stdio_pipe_read_progress_action_snapshot(), 1);
    assert_eq!(
        supervisor_stdio_output_settle_max_passes(supervisor_stdio_output_settle_kind_visible()),
        4
    );
    assert_eq!(
        supervisor_stdio_output_settle_max_passes(
            supervisor_stdio_output_settle_kind_inherited_child()
        ),
        6
    );
    assert_eq!(
        supervisor_stdio_output_settle_stable_passes(supervisor_stdio_output_settle_kind_visible()),
        2
    );
    assert_eq!(
        supervisor_stdio_output_settle_stable_passes(
            supervisor_stdio_output_settle_kind_inherited_child()
        ),
        2
    );
    assert_eq!(
        supervisor_stdio_output_settle_max_passes(0),
        -(EINVAL as i32)
    );
    assert_eq!(
        supervisor_stdio_output_settle_stable_passes(0),
        -(EINVAL as i32)
    );
    assert_eq!(
        supervisor_stdio_pipe_read_progress_action(0, 1, 1),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_wait_wake_mask_for_sync(supervisor_blocked_wait_wake_source_pipe_sync()),
        supervisor_blocked_wait_wake_target_pipe_wait() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_mask_for_sync(supervisor_blocked_wait_wake_source_epoll_sync()),
        supervisor_blocked_wait_wake_target_epoll_wait() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_mask_for_sync(
            supervisor_blocked_wait_wake_source_socket_sync()
        ),
        (supervisor_blocked_wait_wake_target_pipe_wait()
            | supervisor_blocked_wait_wake_target_epoll_wait()
            | supervisor_blocked_wait_wake_target_socket_recv()
            | supervisor_blocked_wait_wake_target_socket_send()) as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_mask_for_sync(
            supervisor_blocked_wait_wake_source_pipe_and_epoll_sync()
        ),
        (supervisor_blocked_wait_wake_target_pipe_wait()
            | supervisor_blocked_wait_wake_target_epoll_wait()) as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_mask_for_sync(0),
        -(EINVAL as i32)
    );
    assert_eq!(
        supervisor_blocked_wait_status_matches_wake_source(
            STATUS_PIPE_WAIT,
            supervisor_blocked_wait_wake_source_pipe_sync()
        ),
        1
    );
    assert_eq!(
        supervisor_blocked_wait_status_matches_wake_source(
            STATUS_EPOLL_WAIT,
            supervisor_blocked_wait_wake_source_pipe_sync()
        ),
        0
    );
    assert_eq!(
        supervisor_blocked_wait_status_matches_wake_source(
            STATUS_EPOLL_WAIT,
            supervisor_blocked_wait_wake_source_epoll_sync()
        ),
        1
    );
    assert_eq!(
        supervisor_blocked_wait_status_matches_wake_source(
            STATUS_SOCKET_RECV,
            supervisor_blocked_wait_wake_source_socket_sync()
        ),
        1
    );
    assert_eq!(
        supervisor_blocked_wait_status_matches_wake_source(
            STATUS_SOCKET_SEND,
            supervisor_blocked_wait_wake_source_socket_sync()
        ),
        1
    );
    assert_eq!(
        supervisor_blocked_wait_status_matches_wake_source(STATUS_OK, 0),
        -(EINVAL as i32)
    );
    assert_eq!(
        supervisor_blocked_wait_wake_action(
            STATUS_PIPE_WAIT,
            supervisor_blocked_wait_wake_source_pipe_sync(),
            0
        ),
        supervisor_blocked_wait_wake_action_clear_pipe_sync_and_retry() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_action(
            STATUS_PIPE_WAIT,
            supervisor_blocked_wait_wake_source_pipe_sync(),
            supervisor_blocked_wait_wake_flag_rpc_pending()
        ),
        supervisor_blocked_wait_wake_action_skip() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_action(
            STATUS_EPOLL_WAIT,
            supervisor_blocked_wait_wake_source_epoll_sync(),
            0
        ),
        supervisor_blocked_wait_wake_action_log_epoll_and_retry() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_action(
            STATUS_EPOLL_WAIT,
            supervisor_blocked_wait_wake_source_socket_sync(),
            supervisor_blocked_wait_wake_flag_rpc_pending()
        ),
        supervisor_blocked_wait_wake_action_skip() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_action(
            STATUS_SOCKET_RECV,
            supervisor_blocked_wait_wake_source_socket_sync(),
            0
        ),
        supervisor_blocked_wait_wake_action_retry() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_action(
            STATUS_SOCKET_SEND,
            supervisor_blocked_wait_wake_source_pipe_sync(),
            0
        ),
        supervisor_blocked_wait_wake_action_skip() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_wake_action(STATUS_OK, 0, 0),
        -(EINVAL as i32)
    );
    assert_eq!(
        supervisor_state_sync_request(0, supervisor_state_sync_kind_pipe(), 0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_state_sync_request(0x1000, 0, 0),
        -(EINVAL as i32)
    );
    assert_eq!(
        supervisor_state_sync_request(
            0x1000,
            supervisor_state_sync_kind_pipe(),
            supervisor_state_sync_request_flag_wake_waiters()
        ),
        1
    );
    assert_eq!(
        supervisor_state_sync_next_run_flags(0x1000, supervisor_state_sync_kind_pipe()),
        (supervisor_state_sync_run_flag_run() | supervisor_state_sync_run_flag_wake_waiters())
            as i32
    );
    assert_eq!(
        supervisor_state_sync_complete(0x1000, supervisor_state_sync_kind_pipe()),
        0
    );
    assert_eq!(
        supervisor_state_sync_request(0x1000, supervisor_state_sync_kind_epoll(), 0),
        1
    );
    assert_eq!(
        supervisor_state_sync_request(
            0x1000,
            supervisor_state_sync_kind_epoll(),
            supervisor_state_sync_request_flag_wake_waiters()
        ),
        0
    );
    assert_eq!(
        supervisor_state_sync_next_run_flags(0x1000, supervisor_state_sync_kind_epoll()),
        (supervisor_state_sync_run_flag_run() | supervisor_state_sync_run_flag_wake_waiters())
            as i32
    );
    assert_eq!(
        supervisor_state_sync_clear(0x1000, supervisor_state_sync_kind_epoll()),
        0
    );
    assert_eq!(
        supervisor_state_sync_next_run_flags(0x1000, supervisor_state_sync_kind_epoll()),
        0
    );
    assert_eq!(supervisor_process_held_ofd_refcount(0, 1), 0);
    assert_eq!(supervisor_process_holds_regular_file_ofd(0, 1), 0);
    assert_eq!(supervisor_process_ofd_for_fd(0, 1), 0);
    assert_eq!(supervisor_process_fd_flags_for_fd(0, 1), 0);
    assert_eq!(supervisor_process_fd_is_open(0, 1), 0);
    assert_eq!(supervisor_ofd_fd_type(0), 0);
    assert_eq!(supervisor_ofd_host_fd(0), -1);
    assert_eq!(supervisor_ofd_status_flags(0), 0);
    assert_eq!(supervisor_ofd_ino(0), 0);
    assert_eq!(supervisor_ofd_refcount(0), 0);
    assert_eq!(supervisor_ofd_reconcile_refcount(0, 1), 0);
    assert_eq!(supervisor_ofd_offset(0), 0);
    assert_eq!(supervisor_ofd_is_regular_file(0), 0);
    assert_eq!(supervisor_pipe_sync_ofd_candidate(0), 0);
    assert_eq!(supervisor_ofd_pipe_generation_slot(0), 0);
    assert_eq!(supervisor_ofd_pipe_slot_mask(0), 0);
    assert_eq!(supervisor_ofd_pipe_slot_mode(0, 1), 0);
    assert_eq!(supervisor_fork_shared_held_ofd_track_action(0, 0), 0);
    assert_eq!(supervisor_fork_shared_ofd_identity_key(0), 0);
    assert_eq!(supervisor_fork_shared_ofd_publish_action(0, 0), 0);
    assert_eq!(supervisor_fork_shared_effect_sync_action(0, 1, 0, 0), 0);
    assert_eq!(supervisor_process_private_pipe_slot_mask(0), 0);
    assert_eq!(supervisor_process_private_pipe_source_mode(0, 1), 0);
    assert_eq!(supervisor_process_private_pipe_target_mode(0, 1), 0);
    assert_eq!(supervisor_process_held_pipe_slot_mask(0), 0);
    assert_eq!(supervisor_process_pipe_used_mask(0), 1);
    assert_eq!(supervisor_process_pipe_slot_mode(0, 1), 0);
    assert_eq!(supervisor_process_pipe_slot_for_fd(0, 1), 0);
    assert_eq!(supervisor_process_pipe_ofd_for_fd(0, 1), 0);
    assert_eq!(supervisor_process_pipe_host_fd_for_fd(0, 1), -1);
    assert_eq!(supervisor_process_pipe_read_open_count(0, 1), 0);
    assert_eq!(supervisor_process_pipe_write_open_count(0, 1), 0);
    assert_eq!(supervisor_pipe_reconcile_control(0, 1, 1), 0);
    assert_eq!(supervisor_blocked_pipe_resume_action(0), -(EFAULT as i32));
    assert_eq!(
        supervisor_blocked_pipe_sync_before_retry_action(0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_pipe_sync_before_retry_requested(0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_pipe_sync_before_retry_clear(0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_wait_network_pump_action(0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_complete_blocked_wait_network_pump(0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_clear_blocked_wait_network_pump(0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_wait_network_pump_action(0x2000),
        supervisor_blocked_wait_network_pump_action_pump() as i32
    );
    assert_eq!(supervisor_complete_blocked_wait_network_pump(0x2000, 0), 0);
    assert_eq!(
        supervisor_blocked_wait_network_pump_action(0x2000),
        supervisor_blocked_wait_network_pump_action_skip() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_network_pump_action(0x2000),
        supervisor_blocked_wait_network_pump_action_pump() as i32
    );
    assert_eq!(supervisor_complete_blocked_wait_network_pump(0x2000, 0), 0);
    assert_eq!(supervisor_clear_blocked_wait_network_pump(0x2000), 0);
    assert_eq!(
        supervisor_blocked_wait_network_pump_action(0x2000),
        supervisor_blocked_wait_network_pump_action_pump() as i32
    );
    assert_eq!(supervisor_complete_blocked_wait_network_pump(0x2000, 1), 0);
    assert_eq!(
        supervisor_blocked_wait_network_pump_action(0x2000),
        supervisor_blocked_wait_network_pump_action_pump() as i32
    );
    assert_eq!(supervisor_process_epoll_held_ofd(0, 0), 0);
    assert_eq!(supervisor_process_epoll_dependent_ofd(0, 0), 0);
    assert_eq!(supervisor_process_sync_dependent_ofd(0, 0), 0);
    assert_eq!(supervisor_process_epoll_dependent_sync_ofd(0, 0), 0);
    assert_eq!(supervisor_process_epoll_depends_on_ofd(0, 1), 0);
    assert_eq!(
        supervisor_fd_entry_restore_action(
            0,
            1,
            0,
            u64::MAX,
            supervisor_fd_entry_restore_flag_preserve_live_regular_file()
                | supervisor_fd_entry_restore_flag_preserve_live_epoll_dependent(),
        ),
        supervisor_fd_entry_restore_action_skip() as i32
    );
    assert_eq!(supervisor_blocked_epoll_watched_ofd(0, 0), 0);
    assert_eq!(supervisor_blocked_epoll_dependent_sync_ofd(0, 0), 0);
    assert_eq!(supervisor_blocked_epoll_watches_pipe(0), 0);
    assert_eq!(supervisor_process_socket_held_ofd(0, 0), 0);
    assert_eq!(supervisor_socket_ofd_is_socket(0), 0);
    assert_eq!(supervisor_process_socket_ofd_for_fd(0, 0), 0);
    assert_eq!(
        supervisor_process_socket_drain_fd(0, 0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(supervisor_socket_connect_fd(0), -(EFAULT as i32));
    assert_eq!(
        supervisor_socket_connect_peer_addr(0, 0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_socket_connect_peer_addr_for_fd(0, 0, 0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_socket_prepare_external_peer(0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_socket_commit_external_connect_result(0, 0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_socket_close_external_peer(0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(supervisor_socket_force_shutdown(0, 0), -(EFAULT as i32));
    assert_eq!(
        supervisor_socket_bridge_active_fd(0, 0, 0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(supervisor_fs_control_record_bytes(), 112);
    assert_eq!(supervisor_fs_control_record_magic(), 0x5346_5354);
    assert_eq!(supervisor_fs_control_record(0, 0), 112);
    assert_eq!(supervisor_fs_control_kind_page_cache_miss(), 1);
    assert_eq!(supervisor_fs_control_kind_page_cache_fill(), 2);
    assert_eq!(supervisor_fs_control_kind_dirty_page_published(), 3);
    assert_eq!(supervisor_fs_control_kind_dirty_page_flushed(), 4);
    assert_eq!(supervisor_fs_completion_flag_memfs_dirty(), 1);
    assert_eq!(supervisor_fs_completion_flag_memfs_publish_ready(), 2);
    assert_eq!(supervisor_fs_completion_flag_ofd_state_changed(), 4);
    assert_eq!(supervisor_fs_completion_flag_regular_file_request(), 8);
    assert_eq!(supervisor_fs_response_flag_adopt_kernel_state(), 1);
    assert_eq!(supervisor_fs_response_flag_apply_guest_memory_writes(), 2);
    assert_eq!(supervisor_fs_response_flag_queue_thread_worker_writes(), 4);
    assert_eq!(supervisor_fs_response_flag_apply_local_metadata(), 8);
    assert_eq!(supervisor_fs_response_flag_clear_tombstones(), 16);
    assert_eq!(
        supervisor_fs_response_flag_fd_response_may_clear_live_fds(),
        32
    );
    assert_eq!(supervisor_fs_response_flag_store_pending_kernel_state(), 64);
    assert_eq!(supervisor_fs_response_flag_resolved_to_execve_spawn(), 128);
    assert_eq!(supervisor_fs_response_flag_process_owner_matches(), 256);
    assert_eq!(supervisor_fs_local_metadata_action_none(), 0);
    assert_eq!(supervisor_fs_local_metadata_action_tombstone_primary(), 1);
    assert_eq!(supervisor_fs_local_metadata_action_forget_primary(), 2);
    assert_eq!(supervisor_fs_local_metadata_action_forget_secondary(), 4);
    assert_eq!(supervisor_fs_resident_page_evict_not_found(), 0);
    assert_eq!(supervisor_fs_resident_page_evict_dirty_pinned(), 1);
    assert_eq!(supervisor_fs_resident_page_evict_evicted(), 2);
    assert_eq!(supervisor_fs_dirty_page_op_write(), 1);
    assert_eq!(supervisor_fs_dirty_page_op_truncate(), 2);
    assert_eq!(supervisor_fs_dirty_page_op_flush(), 3);
    assert_eq!(supervisor_fs_dirty_page_flag_update_inode(), 1);
    assert_eq!(supervisor_fs_dirty_page_flag_publish_dirty(), 2);
    assert_eq!(supervisor_fs_dirty_page_flag_writeback_required(), 4);
    assert_eq!(supervisor_fs_dirty_prepare_publish_none(), 0);
    assert_eq!(supervisor_fs_dirty_prepare_publish_missing(), 1);
    assert_eq!(supervisor_fs_dirty_prepare_publish_size_update(), 2);
    assert_eq!(supervisor_fs_data_sync_kind_export(), 1);
    assert_eq!(supervisor_fs_data_sync_kind_restore(), 2);
    assert_eq!(supervisor_fs_sync_action_none(), 0);
    assert_eq!(supervisor_fs_sync_action_externalize(), 1);
    assert_eq!(supervisor_fs_metadata_sync_action_none(), 0);
    assert_eq!(supervisor_fs_metadata_sync_action_remove(), 1);
    assert_eq!(supervisor_fs_metadata_sync_action_ensure(), 2);
    assert_eq!(supervisor_fs_metadata_sync_action_publish_ensure(), 3);
    assert_eq!(supervisor_fs_metadata_full_sync_action_none(), 0);
    assert_eq!(supervisor_fs_metadata_full_sync_action_required(), 1);
    assert_eq!(supervisor_fs_metadata_backing_none(), 0);
    assert_eq!(supervisor_fs_metadata_backing_published(), 1);
    assert_eq!(supervisor_fs_metadata_backing_backing(), 2);
    assert_eq!(supervisor_fs_backing_object_op_source(), 1);
    assert_eq!(supervisor_fs_backing_object_op_materialize(), 2);
    assert_eq!(supervisor_fs_backing_object_op_replace(), 3);
    assert_eq!(supervisor_fs_backing_object_op_flush_write(), 4);
    assert_eq!(supervisor_fs_backing_object_op_flush_truncate(), 5);
    assert_eq!(supervisor_fs_backing_retry_min_attempts(), 256);
    assert_eq!(supervisor_fs_backing_retry_max_attempts(), 16 * 1024);
    assert_eq!(supervisor_fs_backing_retry_final_scan_attempts(), 2);
    assert_eq!(supervisor_fs_backing_fill_mode_resident(), 0);
    assert_eq!(supervisor_fs_backing_fill_mode_direct(), 1);
    assert_eq!(supervisor_fs_backing_source_range_none(), 0);
    assert_eq!(supervisor_fs_backing_source_range_read(), 1);
    assert_eq!(supervisor_fs_clean_backing_range_none(), 0);
    assert_eq!(supervisor_fs_clean_backing_range_read(), 1);
    assert_eq!(supervisor_fs_clean_backing_range_read_zero_tail(), 2);
    assert_eq!(supervisor_fs_clean_backing_range_zero(), 3);
    assert_eq!(supervisor_fs_page_table_source_backing(), 0);
    assert_eq!(supervisor_fs_page_table_source_resident(), 1);
    assert_eq!(supervisor_fs_pending_ring_request(0), 0);
    assert_eq!(supervisor_fs_pending_regular_file_fd(0), -1);
    assert_eq!(supervisor_fs_pending_regular_file_ofd(0), 0);
    assert_eq!(supervisor_fs_pipe_refresh_action_none(), 0);
    assert_eq!(supervisor_fs_pipe_refresh_action_request_sync(), 1);
    assert_eq!(supervisor_fs_pipe_refresh_flag_kernel_worker_available(), 1);
    assert_eq!(
        supervisor_fs_pipe_refresh_before_resume_action(
            0,
            supervisor_fs_pipe_refresh_flag_kernel_worker_available(),
        ),
        -(EFAULT as i32)
    );
    assert_eq!(supervisor_fs_pending_backing_fill_ino(0), 0);
    assert_eq!(supervisor_fs_pending_backing_fill_offset(0), 0);
    assert_eq!(supervisor_fs_pending_backing_fill_length(0), 0);
    assert_eq!(supervisor_fs_pending_backing_fill_expected_size(0), 0);
    assert_eq!(supervisor_fs_pending_backing_fill_opcode(0), 0);
    assert_eq!(supervisor_fs_clear_pending_backing_fill(0), 0);
    assert_eq!(
        supervisor_fs_backing_retry_limit(
            tidemark_kernel::fs::ring_buffer::FS_OP_EXECVE,
            0,
            4096,
            4096 * 260,
        ),
        262
    );
    assert_eq!(
        supervisor_fs_backing_retry_limit(
            tidemark_kernel::fs::ring_buffer::FS_OP_EXECVE,
            128,
            16,
            8192,
        ),
        supervisor_fs_backing_retry_min_attempts()
    );
    assert_eq!(
        supervisor_fs_backing_retry_limit(
            tidemark_kernel::fs::ring_buffer::FS_OP_EXECVE,
            0,
            0,
            8192,
        ),
        0
    );
    assert_eq!(
        supervisor_fs_backing_fill_span_decision(
            tidemark_kernel::fs::ring_buffer::FS_OP_EXECVE,
            128,
            16,
            8192,
        ),
        0
    );
    assert_eq!(supervisor_fs_backing_fill_span_offset(), 0);
    assert_eq!(supervisor_fs_backing_fill_span_end(), 4096);
    assert_eq!(supervisor_fs_backing_fill_span_length(), 4096);
    assert_eq!(
        supervisor_fs_backing_fill_span_decision(
            tidemark_kernel::fs::ring_buffer::FS_OP_EXECVE,
            8191,
            16,
            8200,
        ),
        0
    );
    assert_eq!(supervisor_fs_backing_fill_span_offset(), 4096);
    assert_eq!(supervisor_fs_backing_fill_span_end(), 8200);
    assert_eq!(supervisor_fs_backing_fill_span_length(), 4104);
    assert_eq!(
        supervisor_fs_backing_fill_span_decision(
            tidemark_kernel::fs::ring_buffer::FS_OP_READ,
            128,
            16,
            2 * 1024 * 1024,
        ),
        0
    );
    assert_eq!(supervisor_fs_backing_fill_span_offset(), 0);
    assert_eq!(supervisor_fs_backing_fill_span_end(), 1024 * 1024);
    assert_eq!(supervisor_fs_backing_fill_span_length(), 1024 * 1024);
    assert_eq!(
        supervisor_fs_backing_fill_span_decision(
            tidemark_kernel::fs::ring_buffer::FS_OP_READ,
            8191,
            16,
            8200,
        ),
        0
    );
    assert_eq!(supervisor_fs_backing_fill_span_offset(), 4096);
    assert_eq!(supervisor_fs_backing_fill_span_end(), 8200);
    assert_eq!(supervisor_fs_backing_fill_span_length(), 4104);
    assert_eq!(supervisor_fs_pending_mmap_guest_write_ptr(0), 0);
    assert_eq!(supervisor_fs_pending_mmap_guest_write_len(0), 0);
    assert_eq!(supervisor_fs_pending_mmap_guest_write_snapshot_len(0), 0);
    assert_eq!(
        supervisor_fs_response_disposition(0, 7, 0, 0, 0, 0)
            & (supervisor_fs_response_flag_adopt_kernel_state()
                | supervisor_fs_response_flag_apply_guest_memory_writes()
                | supervisor_fs_response_flag_queue_thread_worker_writes()
                | supervisor_fs_response_flag_apply_local_metadata()
                | supervisor_fs_response_flag_clear_tombstones()
                | supervisor_fs_response_flag_process_owner_matches()),
        supervisor_fs_response_flag_adopt_kernel_state()
            | supervisor_fs_response_flag_apply_guest_memory_writes()
            | supervisor_fs_response_flag_queue_thread_worker_writes()
            | supervisor_fs_response_flag_apply_local_metadata()
            | supervisor_fs_response_flag_clear_tombstones()
            | supervisor_fs_response_flag_process_owner_matches()
    );
    assert_ne!(
        supervisor_fs_response_disposition(
            0,
            7,
            tidemark_kernel::fs::ring_buffer::FS_OP_CLOSE,
            0,
            0,
            0,
        ) & supervisor_fs_response_flag_fd_response_may_clear_live_fds(),
        0
    );
    assert_eq!(
        supervisor_fs_local_metadata_action(
            tidemark_kernel::fs::ring_buffer::FS_OP_UNLINK,
            tidemark_kernel::syscall::fs::FS_EFFECT_MEMFS_MUTATION,
            0,
            1,
            0,
        ),
        supervisor_fs_local_metadata_action_tombstone_primary()
    );
    assert_eq!(
        supervisor_fs_local_metadata_action(
            tidemark_kernel::fs::ring_buffer::FS_OP_OPENAT,
            tidemark_kernel::syscall::fs::FS_EFFECT_MEMFS_MUTATION,
            0,
            1,
            0,
        ),
        supervisor_fs_local_metadata_action_forget_primary()
    );
    assert_eq!(
        supervisor_fs_local_metadata_action(
            tidemark_kernel::fs::ring_buffer::FS_OP_RENAME,
            tidemark_kernel::syscall::fs::FS_EFFECT_MEMFS_MUTATION,
            0,
            1,
            1,
        ),
        supervisor_fs_local_metadata_action_forget_secondary()
    );
    assert_eq!(
        supervisor_fs_local_metadata_action(
            tidemark_kernel::fs::ring_buffer::FS_OP_UNLINK,
            tidemark_kernel::syscall::fs::FS_EFFECT_MEMFS_MUTATION,
            -1,
            1,
            0,
        ),
        supervisor_fs_local_metadata_action_none()
    );
    assert_eq!(supervisor_fs_resident_page_slot_decision(4, 5, 6), 4);
    assert_eq!(supervisor_fs_resident_page_slot_decision(-1, 5, 6), 5);
    assert_eq!(supervisor_fs_resident_page_slot_decision(-1, -1, 6), 6);
    assert_eq!(supervisor_fs_resident_page_slot_decision(-1, -1, -1), -1);
    assert_eq!(
        supervisor_fs_resident_page_evict_status(0, 0),
        supervisor_fs_resident_page_evict_not_found()
    );
    assert_eq!(
        supervisor_fs_resident_page_evict_status(1, 1),
        supervisor_fs_resident_page_evict_dirty_pinned()
    );
    assert_eq!(
        supervisor_fs_resident_page_evict_status(1, 0),
        supervisor_fs_resident_page_evict_evicted()
    );
    {
        let mut t = TestVm::new();
        let vm_ptr = &mut t.vm as *mut _ as u32;
        let flags = supervisor_fs_pipe_refresh_flag_kernel_worker_available();
        assert_eq!(
            supervisor_fs_pipe_refresh_before_resume_action(vm_ptr, flags),
            supervisor_fs_pipe_refresh_action_none() as i32
        );

        let pipefd_addr = t.scratch + 0x1380;
        assert_eq!(
            tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
            0
        );
        let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) };
        let ps = unsafe {
            &*((t.base as u64 + t.vm.process_ptr as u64)
                as *const tidemark_kernel::types::ProcessState)
        };
        let idx = tidemark_kernel::fs::ring_buffer::submit_request(
            ps.fs_ring_base,
            tidemark_kernel::fs::ring_buffer::FS_OP_CLOSE,
            read_fd as i32,
            0,
            0,
            0,
            0,
            0,
            0,
            vm_ptr,
        );
        assert!(idx >= 0);
        assert_eq!(
            supervisor_fs_pipe_refresh_before_resume_action(vm_ptr, flags),
            supervisor_fs_pipe_refresh_action_none() as i32
        );

        ps.thread_count.store(2, Ordering::Release);
        assert_eq!(
            supervisor_fs_pipe_refresh_before_resume_action(vm_ptr, 0),
            supervisor_fs_pipe_refresh_action_none() as i32
        );
        assert_eq!(
            supervisor_fs_pipe_refresh_before_resume_action(vm_ptr, flags),
            supervisor_fs_pipe_refresh_action_request_sync() as i32
        );
    }
    assert_eq!(
        supervisor_fs_completion_decision(
            0,
            tidemark_kernel::fs::ring_buffer::FS_OP_WRITE,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        0
    );
    assert_eq!(
        supervisor_fs_dirty_page_decision(
            supervisor_fs_dirty_page_op_write(),
            2,
            32,
            64,
            16,
            0,
            1,
            0,
            1,
            2,
            0,
        ),
        64
    );
    assert_eq!(supervisor_fs_dirty_page_decision_next_size(), 96);
    assert_eq!(supervisor_fs_dirty_page_decision_file_object_id(), 2);
    assert_eq!(supervisor_fs_dirty_page_decision_generation(), 2);
    assert_eq!(
        supervisor_fs_dirty_page_decision_flags(),
        supervisor_fs_dirty_page_flag_update_inode()
            | supervisor_fs_dirty_page_flag_publish_dirty()
    );
    assert_eq!(
        supervisor_fs_dirty_page_decision(
            supervisor_fs_dirty_page_op_write(),
            2,
            0,
            1,
            0,
            2,
            2,
            2,
            1,
            2,
            0,
        ),
        ENOSPC
    );
    assert_eq!(
        supervisor_fs_dirty_page_decision(
            supervisor_fs_dirty_page_op_truncate(),
            2,
            0,
            4,
            16,
            2,
            2,
            0,
            1,
            2,
            0,
        ),
        0
    );
    assert_eq!(supervisor_fs_dirty_page_decision_next_size(), 4);
    assert_eq!(supervisor_fs_dirty_page_decision_generation(), 3);
    assert_eq!(
        supervisor_fs_dirty_page_decision(
            supervisor_fs_dirty_page_op_flush(),
            2,
            0,
            0,
            4,
            2,
            3,
            0,
            1,
            2,
            0,
        ),
        0
    );
    assert_eq!(
        supervisor_fs_dirty_page_decision_flags(),
        supervisor_fs_dirty_page_flag_writeback_required()
    );
    assert_eq!(
        supervisor_fs_dirty_prepare_decision(
            2,
            supervisor_fs_dirty_page_op_write(),
            6,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
        ),
        EOPNOTSUPP as i32
    );
    assert_eq!(
        supervisor_fs_dirty_prepare_publish_mode(),
        supervisor_fs_dirty_prepare_publish_none()
    );
    assert_eq!(
        supervisor_fs_dirty_prepare_decision(
            2,
            supervisor_fs_dirty_page_op_write(),
            6,
            0,
            0,
            0,
            0,
            1,
            2,
            0,
        ),
        0
    );
    assert_eq!(
        supervisor_fs_dirty_prepare_publish_mode(),
        supervisor_fs_dirty_prepare_publish_missing()
    );
    assert_eq!(
        supervisor_fs_dirty_prepare_decision(
            2,
            supervisor_fs_dirty_page_op_write(),
            6,
            1,
            3,
            2,
            0,
            1,
            2,
            0,
        ),
        0
    );
    assert_eq!(
        supervisor_fs_dirty_prepare_publish_mode(),
        supervisor_fs_dirty_prepare_publish_size_update()
    );
    assert_eq!(
        supervisor_fs_dirty_prepare_decision(
            2,
            supervisor_fs_dirty_page_op_truncate(),
            6,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
        ),
        0
    );
    assert_eq!(
        supervisor_fs_dirty_prepare_publish_mode(),
        supervisor_fs_dirty_prepare_publish_missing()
    );
    assert_eq!(
        supervisor_fs_dirty_prepare_decision(
            0,
            supervisor_fs_dirty_page_op_write(),
            6,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
        ),
        EINVAL as i32
    );
    assert_eq!(
        supervisor_fs_data_sync_decision(
            supervisor_fs_data_sync_kind_export(),
            2,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            128,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            128,
            1,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            128,
            2,
            0,
            0,
            0,
        ),
        supervisor_fs_sync_action_externalize() as i32
    );
    assert_eq!(
        supervisor_fs_data_sync_decision(
            supervisor_fs_data_sync_kind_export(),
            2,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            128,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            128,
            1,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            64,
            0,
            0,
            0,
            0,
        ),
        supervisor_fs_sync_action_none() as i32
    );
    assert_eq!(
        supervisor_fs_data_sync_decision(
            supervisor_fs_data_sync_kind_restore(),
            2,
            0,
            0,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            64,
            1,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            64,
            0,
            1,
            0,
            0,
        ),
        supervisor_fs_sync_action_externalize() as i32
    );
    assert_eq!(
        supervisor_fs_data_sync_decision(
            99,
            2,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            128,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            128,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        EINVAL as i32
    );
    assert_eq!(
        supervisor_fs_metadata_sync_decision(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        supervisor_fs_metadata_sync_action_remove() as i32
    );
    assert_eq!(
        supervisor_fs_metadata_sync_decision(
            2,
            1,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            0,
            1,
            1,
            1,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            4096,
            1,
            0,
            1,
            1,
        ),
        supervisor_fs_metadata_sync_action_publish_ensure() as i32
    );
    assert_eq!(supervisor_fs_metadata_sync_size(), 4096);
    assert_eq!(
        supervisor_fs_metadata_sync_backing_source(),
        supervisor_fs_metadata_backing_published()
    );
    assert_eq!(
        supervisor_fs_metadata_sync_decision(
            2,
            1,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            256,
            1,
            1,
            1,
            tidemark_kernel::fs::memfs::S_IFREG | 0o644,
            256,
            1,
            1,
            0,
            1,
        ),
        supervisor_fs_metadata_sync_action_ensure() as i32
    );
    assert_eq!(supervisor_fs_metadata_sync_size(), 256);
    assert_eq!(
        supervisor_fs_metadata_sync_backing_source(),
        supervisor_fs_metadata_backing_backing()
    );
    assert_eq!(
        supervisor_fs_metadata_full_sync_decision(1, 0),
        supervisor_fs_metadata_full_sync_action_required() as i32
    );
    assert_eq!(
        supervisor_fs_metadata_full_sync_decision(1, 1),
        supervisor_fs_metadata_full_sync_action_none() as i32
    );
    assert_eq!(
        supervisor_fs_metadata_full_sync_decision(0, 0),
        supervisor_fs_metadata_full_sync_action_none() as i32
    );
    assert_eq!(
        supervisor_fs_backing_object_decision(
            supervisor_fs_backing_object_op_source(),
            7,
            0,
            0,
            0,
            0,
        ),
        0
    );
    assert_eq!(supervisor_fs_backing_object_file_object_id(), 7);
    assert_eq!(supervisor_fs_backing_object_generation(), 1);
    assert_eq!(
        supervisor_fs_backing_object_decision(
            supervisor_fs_backing_object_op_materialize(),
            7,
            7,
            3,
            0,
            0,
        ),
        0
    );
    assert_eq!(supervisor_fs_backing_object_file_object_id(), 7);
    assert_eq!(supervisor_fs_backing_object_generation(), 3);
    assert_eq!(
        supervisor_fs_backing_object_decision(
            supervisor_fs_backing_object_op_replace(),
            7,
            7,
            3,
            0,
            0,
        ),
        0
    );
    assert_eq!(supervisor_fs_backing_object_file_object_id(), 7);
    assert_eq!(supervisor_fs_backing_object_generation(), 4);
    assert_eq!(
        supervisor_fs_backing_object_decision(
            supervisor_fs_backing_object_op_flush_write(),
            7,
            7,
            9,
            3,
            4,
        ),
        0
    );
    assert_eq!(supervisor_fs_backing_object_file_object_id(), 7);
    assert_eq!(supervisor_fs_backing_object_generation(), 9);
    assert_eq!(
        supervisor_fs_backing_object_decision(
            supervisor_fs_backing_object_op_flush_truncate(),
            0,
            7,
            9,
            7,
            8,
        ),
        EINVAL as i32
    );
    assert_eq!(supervisor_fs_backing_object_file_object_id(), 0);
    assert_eq!(supervisor_fs_backing_object_generation(), 0);
    assert_eq!(
        supervisor_fs_page_table_source_decision(2, 0, 2, 3, 128, 2, 3, 128),
        supervisor_fs_page_table_source_backing() as i32
    );
    assert_eq!(
        supervisor_fs_page_table_source_decision(2, 1, 2, 3, 128, 2, 3, 128),
        supervisor_fs_page_table_source_resident() as i32
    );
    assert_eq!(
        supervisor_fs_page_table_source_decision(2, 0, 2, 4, 128, 2, 3, 128),
        supervisor_fs_page_table_source_resident() as i32
    );
    assert_eq!(
        supervisor_fs_page_table_source_decision(2, 0, 4, 3, 128, 2, 3, 128),
        supervisor_fs_page_table_source_resident() as i32
    );
    assert_eq!(
        supervisor_fs_page_table_source_decision(2, 0, 0, 0, 0, 2, 3, 128),
        supervisor_fs_page_table_source_backing() as i32
    );
    assert_eq!(
        supervisor_fs_page_table_source_decision(0, 0, 2, 3, 128, 2, 3, 128),
        EINVAL as i32
    );
    assert_eq!(
        supervisor_fs_backing_fill_probe_direct(
            tidemark_kernel::fs::ring_buffer::FS_OP_MMAP,
            16 * 1024 * 1024,
        ),
        1
    );
    assert_eq!(
        supervisor_fs_backing_fill_probe_direct(
            tidemark_kernel::fs::ring_buffer::FS_OP_MMAP,
            16 * 1024 * 1024 - 1,
        ),
        0
    );
    assert_eq!(
        supervisor_fs_backing_fill_probe_direct(
            tidemark_kernel::fs::ring_buffer::FS_OP_READ,
            16 * 1024 * 1024,
        ),
        0
    );
    assert_eq!(
        supervisor_fs_backing_fill_probe_direct(tidemark_kernel::fs::ring_buffer::FS_OP_MMAP, 0),
        EINVAL as i32
    );
    assert_eq!(
        supervisor_fs_backing_fill_mode_decision(
            tidemark_kernel::fs::ring_buffer::FS_OP_MMAP,
            16 * 1024 * 1024,
            1,
            1,
        ),
        supervisor_fs_backing_fill_mode_direct() as i32
    );
    assert_eq!(
        supervisor_fs_backing_fill_mode_decision(
            tidemark_kernel::fs::ring_buffer::FS_OP_MMAP,
            16 * 1024 * 1024,
            1,
            0,
        ),
        supervisor_fs_backing_fill_mode_resident() as i32
    );
    assert_eq!(
        supervisor_fs_backing_fill_mode_decision(
            tidemark_kernel::fs::ring_buffer::FS_OP_READ,
            16 * 1024 * 1024,
            1,
            1,
        ),
        supervisor_fs_backing_fill_mode_resident() as i32
    );
    assert_eq!(
        supervisor_fs_backing_source_range_decision(2, 3, 5, 14, 7, 14, 21, 1),
        supervisor_fs_backing_source_range_read() as i32
    );
    assert_eq!(supervisor_fs_backing_source_range_source_byte_length(), 21);
    assert_eq!(supervisor_fs_backing_source_range_source_offset(), 10);
    assert_eq!(supervisor_fs_backing_source_range_read_length(), 5);
    assert_eq!(
        supervisor_fs_backing_source_range_decision(2, 9, 10, 14, 7, 14, 21, 1),
        supervisor_fs_backing_source_range_read() as i32
    );
    assert_eq!(supervisor_fs_backing_source_range_source_offset(), 16);
    assert_eq!(supervisor_fs_backing_source_range_read_length(), 5);
    assert_eq!(
        supervisor_fs_backing_source_range_decision(2, 3, 5, 14, 7, 14, 20, 1),
        supervisor_fs_backing_source_range_none() as i32
    );
    assert_eq!(supervisor_fs_backing_source_range_source_offset(), 0);
    assert_eq!(supervisor_fs_backing_source_range_read_length(), 0);
    assert_eq!(
        supervisor_fs_backing_source_range_decision(2, 3, 5, 14, 7, 13, 20, 1),
        supervisor_fs_backing_source_range_none() as i32
    );
    assert_eq!(
        supervisor_fs_backing_source_range_decision(0, 3, 5, 14, 7, 14, 21, 1),
        supervisor_fs_backing_source_range_none() as i32
    );
    assert_eq!(
        supervisor_fs_clean_backing_range_decision(2, 3, 5, 14, 10),
        supervisor_fs_clean_backing_range_read() as i32
    );
    assert_eq!(supervisor_fs_clean_backing_range_read_offset(), 3);
    assert_eq!(supervisor_fs_clean_backing_range_read_length(), 5);
    assert_eq!(supervisor_fs_clean_backing_range_output_length(), 5);
    assert_eq!(
        supervisor_fs_clean_backing_range_decision(2, 8, 6, 14, 10),
        supervisor_fs_clean_backing_range_read_zero_tail() as i32
    );
    assert_eq!(supervisor_fs_clean_backing_range_read_offset(), 8);
    assert_eq!(supervisor_fs_clean_backing_range_read_length(), 2);
    assert_eq!(supervisor_fs_clean_backing_range_output_length(), 6);
    assert_eq!(
        supervisor_fs_clean_backing_range_decision(2, 11, 3, 14, 10),
        supervisor_fs_clean_backing_range_zero() as i32
    );
    assert_eq!(supervisor_fs_clean_backing_range_read_length(), 0);
    assert_eq!(supervisor_fs_clean_backing_range_output_length(), 3);
    assert_eq!(
        supervisor_fs_clean_backing_range_decision(2, 8, 6, 9, 10),
        supervisor_fs_clean_backing_range_read() as i32
    );
    assert_eq!(supervisor_fs_clean_backing_range_read_length(), 2);
    assert_eq!(supervisor_fs_clean_backing_range_output_length(), 2);
    assert_eq!(
        supervisor_fs_clean_backing_range_decision(2, 11, 4, 14, 10),
        supervisor_fs_clean_backing_range_none() as i32
    );
    assert_eq!(supervisor_fs_clean_backing_range_read_offset(), 0);
    assert_eq!(supervisor_fs_clean_backing_range_output_length(), 0);
    assert_eq!(
        supervisor_fs_clean_backing_range_decision(0, 3, 5, 14, 10),
        supervisor_fs_clean_backing_range_none() as i32
    );
    assert_eq!(supervisor_shadow_fs_control_count(), 3);
    supervisor_reset_shadow_log();
    assert_eq!(supervisor_signal_control_record_bytes(), 120);
    assert_eq!(supervisor_signal_control_record_magic(), 0x4753_5354);
    assert_eq!(supervisor_signal_control_record(0, 0), 120);
    assert_eq!(supervisor_signal_control_kind_boundary_check(), 1);
    assert_eq!(supervisor_signal_control_kind_signal_delivered(), 2);
    assert_eq!(supervisor_signal_control_kind_blocked_wait_interrupted(), 3);
    assert_eq!(supervisor_signal_boundary_step(), 3);
    assert_eq!(supervisor_signal_boundary_fault(), 4);
    assert_eq!(supervisor_signal_boundary_check(0), EFAULT as i32);
    assert_eq!(supervisor_resume_kind_runnable_thread(), 2);
    assert_eq!(supervisor_resume_blocked_syscall(0, 0), -(EFAULT as i64));
    assert_eq!(
        supervisor_blocked_resume_writeback_count(0, abi_status_pipe_wait(), 1),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_ptr(0, abi_status_pipe_wait(), 1, 0),
        0
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_len(0, abi_status_pipe_wait(), 1, 0),
        0
    );
    assert_eq!(supervisor_blocked_resume_delegation_direct(), 0);
    assert_eq!(supervisor_blocked_resume_delegation_kernel_worker(), 1);
    assert_eq!(
        supervisor_blocked_resume_delegation_wait4_kernel_worker(),
        2
    );
    assert_eq!(supervisor_blocked_resume_delegation_unsupported(), 3);
    assert_eq!(supervisor_blocked_resume_delegation_epoll_direct(), 4);
    assert_eq!(
        supervisor_blocked_resume_delegation_flag_kernel_worker_available(),
        1
    );
    assert_eq!(supervisor_blocked_resume_delegation(0, 0), -(EFAULT as i32));
    assert_eq!(supervisor_blocked_wait_retry_reason_default(), 0);
    assert_eq!(supervisor_blocked_wait_retry_reason_immediate(), 1);
    assert_eq!(supervisor_blocked_wait_retry_reason_standard_defer(), 2);
    assert_eq!(supervisor_blocked_wait_retry_reason_active_child(), 3);
    assert_eq!(supervisor_blocked_wait_retry_reason_passive_wait(), 4);
    assert_eq!(supervisor_blocked_wait_retry_reason_process_gate(), 5);
    assert_eq!(supervisor_blocked_wait_retry_flag_host_progress(), 1);
    assert_eq!(supervisor_blocked_wait_retry_flag_active_child(), 2);
    assert_eq!(supervisor_blocked_wait_retry_flag_passive_wait(), 4);
    assert_eq!(supervisor_blocked_wait_retry_flag_process_gate(), 8);
    assert_eq!(supervisor_blocked_wait_retry_flag_thread_init_pending(), 16);
    assert_eq!(
        supervisor_blocked_retry_action_flag_supervisor_timer_armed(),
        1
    );
    assert_eq!(supervisor_blocked_retry_action_flag_rpc_pending(), 2);
    assert_eq!(supervisor_blocked_retry_action_flag_owner_async(), 4);
    assert_eq!(
        supervisor_blocked_retry_action_flag_thread_init_pending(),
        8
    );
    assert_eq!(
        supervisor_blocked_retry_action_flag_fork_shared_sync_pending(),
        16
    );
    assert_eq!(supervisor_blocked_retry_action_flag_running_worker(), 32);
    assert_eq!(
        supervisor_blocked_retry_action_flag_kernel_worker_available(),
        64
    );
    assert_eq!(
        supervisor_blocked_retry_action_flag_pipe_state_kernel_worker_owns(),
        128
    );
    assert_eq!(
        supervisor_blocked_retry_action_flag_network_connections_available(),
        256
    );
    assert_eq!(
        supervisor_blocked_retry_action_flag_wait_timer_already_checked(),
        512
    );
    assert_eq!(supervisor_blocked_retry_action_defer_supervisor_timer(), 0);
    assert_eq!(supervisor_blocked_retry_action_defer_rpc_pending(), 1);
    assert_eq!(supervisor_blocked_retry_action_defer_owner_async(), 2);
    assert_eq!(
        supervisor_blocked_retry_action_defer_thread_init_pending(),
        3
    );
    assert_eq!(supervisor_blocked_retry_action_arm_wait_timer(), 4);
    assert_eq!(supervisor_blocked_retry_action_park_active_child(), 5);
    assert_eq!(supervisor_blocked_retry_action_resume_wait4(), 6);
    assert_eq!(supervisor_blocked_retry_action_defer_fork_shared_sync(), 7);
    assert_eq!(supervisor_blocked_retry_action_defer_running_worker(), 8);
    assert_eq!(supervisor_blocked_retry_action_defer_process_gate(), 9);
    assert_eq!(supervisor_blocked_retry_action_pump_network(), 10);
    assert_eq!(supervisor_blocked_retry_action_epoll_kernel_worker(), 11);
    assert_eq!(supervisor_blocked_retry_action_request_pipe_sync(), 12);
    assert_eq!(
        supervisor_blocked_retry_action_request_pipe_sync_and_drain_output(),
        13
    );
    assert_eq!(
        supervisor_blocked_retry_action_schedule_pipe_sync_retry(),
        14
    );
    assert_eq!(supervisor_blocked_retry_action_resume_fs(), 15);
    assert_eq!(supervisor_blocked_retry_action_defer_passive_wait(), 16);
    assert_eq!(supervisor_blocked_retry_action_resume_kernel_worker(), 17);
    assert_eq!(
        supervisor_blocked_retry_action_resume_wait4_kernel_worker(),
        18
    );
    assert_eq!(supervisor_blocked_retry_action_resume_epoll_direct(), 19);
    assert_eq!(supervisor_blocked_retry_action_resume_direct(), 20);
    assert_eq!(supervisor_blocked_retry_action_unsupported(), 21);
    assert_eq!(supervisor_blocked_retry_status_action_none(), 0);
    assert_eq!(
        supervisor_blocked_retry_status_action_pipe_retry_diagnostics(),
        1
    );
    assert_eq!(
        supervisor_blocked_retry_status_action_pump_blocked_outcome(),
        2
    );
    assert_eq!(
        supervisor_blocked_retry_status_action_active_child_pipe(),
        4
    );
    assert_eq!(
        supervisor_blocked_retry_status_action_active_child_wait4(),
        8
    );
    assert_eq!(
        supervisor_blocked_retry_status_action_success_log_epoll_ready(),
        16
    );
    assert_eq!(
        supervisor_blocked_retry_status_action_success_log_wait4_resumed(),
        32
    );
    assert_eq!(
        supervisor_blocked_retry_status_action_wake_runtime_bridge_while_running(),
        64
    );
    assert_eq!(
        supervisor_blocked_retry_status_action(STATUS_PIPE_WAIT),
        (supervisor_blocked_retry_status_action_pipe_retry_diagnostics()
            | supervisor_blocked_retry_status_action_pump_blocked_outcome()
            | supervisor_blocked_retry_status_action_active_child_pipe()) as i32
    );
    assert_eq!(
        supervisor_blocked_retry_status_action(STATUS_EPOLL_WAIT),
        (supervisor_blocked_retry_status_action_success_log_epoll_ready()
            | supervisor_blocked_retry_status_action_wake_runtime_bridge_while_running())
            as i32
    );
    assert_eq!(
        supervisor_blocked_retry_status_action(STATUS_WAIT4),
        (supervisor_blocked_retry_status_action_active_child_wait4()
            | supervisor_blocked_retry_status_action_success_log_wait4_resumed()) as i32
    );
    assert_eq!(
        supervisor_blocked_retry_status_action(STATUS_OK),
        supervisor_blocked_retry_status_action_none() as i32
    );
    let wait_in_worker_kernel_flag =
        supervisor_wait_in_worker_status_action_flag_kernel_worker_available();
    let wait_in_worker_running_flag = supervisor_wait_in_worker_status_action_flag_running_worker();
    let wait_in_worker_epoll_owns_flag =
        supervisor_wait_in_worker_status_action_flag_epoll_state_kernel_owns();
    assert_eq!(
        supervisor_wait_in_worker_status_action(
            0,
            STATUS_OK,
            wait_in_worker_kernel_flag
                | wait_in_worker_running_flag
                | wait_in_worker_epoll_owns_flag,
        ),
        supervisor_wait_in_worker_status_action_none() as i32
    );
    assert_eq!(
        supervisor_wait_in_worker_status_action(0, STATUS_FUTEX_WAIT, 0),
        supervisor_wait_in_worker_status_action_park_futex() as i32
    );
    assert_eq!(
        supervisor_wait_in_worker_status_action(0, STATUS_WAIT4, wait_in_worker_kernel_flag),
        supervisor_wait_in_worker_status_action_block_wait4_and_sync_pipe() as i32
    );
    assert_eq!(
        supervisor_wait_in_worker_status_action(
            0,
            STATUS_SOCKET_RECV,
            wait_in_worker_kernel_flag | wait_in_worker_running_flag,
        ),
        supervisor_wait_in_worker_status_action_sync_socket() as i32
    );
    assert_eq!(
        supervisor_wait_in_worker_status_action(
            0,
            STATUS_SOCKET_SEND,
            wait_in_worker_kernel_flag
                | wait_in_worker_running_flag
                | wait_in_worker_epoll_owns_flag,
        ),
        (supervisor_wait_in_worker_status_action_sync_socket()
            | supervisor_wait_in_worker_status_action_sync_epoll()) as i32
    );
    assert_eq!(
        supervisor_wait_in_worker_status_action(
            0,
            STATUS_PIPE_WAIT,
            wait_in_worker_kernel_flag | wait_in_worker_running_flag,
        ),
        supervisor_wait_in_worker_status_action_sync_pipe() as i32
    );
    assert_eq!(
        supervisor_wait_in_worker_status_action(
            0,
            STATUS_EPOLL_WAIT,
            wait_in_worker_running_flag | wait_in_worker_epoll_owns_flag,
        ),
        EFAULT as i32
    );
    let mut wait_in_worker_vm = TestVm::new();
    wait_in_worker_vm.vm.status = STATUS_EPOLL_WAIT;
    wait_in_worker_vm.vm.epoll_timeout_ms = 0;
    let wait_in_worker_vm_ptr =
        &mut wait_in_worker_vm.vm as *mut tidemark_kernel::types::ThreadState as u32;
    assert_eq!(
        supervisor_wait_in_worker_status_action(
            wait_in_worker_vm_ptr,
            STATUS_EPOLL_WAIT,
            wait_in_worker_running_flag | wait_in_worker_epoll_owns_flag,
        ),
        supervisor_wait_in_worker_status_action_block_epoll_timeout() as i32
    );
    let mut wait_in_worker_timeout_vm = TestVm::new();
    wait_in_worker_timeout_vm.vm.status = STATUS_EPOLL_WAIT;
    wait_in_worker_timeout_vm.vm.epoll_timeout_ms = 25;
    let wait_in_worker_timeout_vm_ptr =
        &mut wait_in_worker_timeout_vm.vm as *mut tidemark_kernel::types::ThreadState as u32;
    assert_eq!(
        supervisor_wait_in_worker_status_action(
            wait_in_worker_timeout_vm_ptr,
            STATUS_EPOLL_WAIT,
            wait_in_worker_running_flag | wait_in_worker_epoll_owns_flag,
        ),
        supervisor_wait_in_worker_status_action_sync_epoll() as i32
    );
    assert_eq!(
        supervisor_wait4_child_exit_blocked_parent_action(STATUS_WAIT4),
        supervisor_wait4_child_exit_blocked_parent_action_invalidate_rpc() as i32
    );
    assert_eq!(
        supervisor_wait4_child_exit_blocked_parent_action(STATUS_PIPE_WAIT),
        (supervisor_wait4_child_exit_blocked_parent_action_invalidate_rpc()
            | supervisor_wait4_child_exit_blocked_parent_action_clear_pipe_sync_before_retry())
            as i32
    );
    assert_eq!(
        supervisor_wait4_child_exit_blocked_parent_action(STATUS_OK),
        supervisor_wait4_child_exit_blocked_parent_action_none() as i32
    );
    assert_eq!(
        supervisor_wait4_rpc_local_status_action(STATUS_WAIT4),
        supervisor_wait4_rpc_local_status_action_start() as i32
    );
    assert_eq!(
        supervisor_wait4_rpc_local_status_action(STATUS_OK),
        supervisor_wait4_rpc_local_status_action_skip() as i32
    );
    let scheduler_clear_pipe_flag =
        supervisor_scheduler_clear_blocked_flag_clear_pipe_sync_before_retry();
    assert_eq!(
        supervisor_scheduler_clear_blocked_action(STATUS_PIPE_WAIT, scheduler_clear_pipe_flag),
        supervisor_scheduler_clear_blocked_action_clear_pipe_sync_before_retry() as i32
    );
    assert_eq!(
        supervisor_scheduler_clear_blocked_action(STATUS_PIPE_WAIT, 0),
        supervisor_scheduler_clear_blocked_action_none() as i32
    );
    assert_eq!(
        supervisor_scheduler_clear_blocked_action(STATUS_WAIT4, scheduler_clear_pipe_flag),
        supervisor_scheduler_clear_blocked_action_none() as i32
    );
    assert_eq!(
        supervisor_scheduler_block_worker_action(STATUS_FUTEX_WAIT),
        supervisor_scheduler_block_worker_action_park_futex() as i32
    );
    assert_eq!(
        supervisor_scheduler_block_worker_action(STATUS_PIPE_WAIT),
        supervisor_scheduler_block_worker_action_record_blocked() as i32
    );
    assert_eq!(
        supervisor_scheduler_futex_waiter_action(STATUS_FUTEX_WAIT),
        supervisor_scheduler_futex_waiter_action_waiter() as i32
    );
    assert_eq!(
        supervisor_scheduler_futex_waiter_action(STATUS_OK),
        supervisor_scheduler_futex_waiter_action_not_waiter() as i32
    );
    assert_eq!(
        supervisor_worker_status_transition_action(STATUS_CONNECT),
        supervisor_worker_status_transition_action_connect_wait() as i32
    );
    assert_eq!(
        supervisor_worker_status_transition_action(STATUS_FUTEX_WAIT),
        supervisor_worker_status_transition_action_park_futex() as i32
    );
    assert_eq!(
        supervisor_worker_status_transition_action(STATUS_PIPE_WAIT),
        supervisor_worker_status_transition_action_host_wait() as i32
    );
    assert_eq!(
        supervisor_worker_status_transition_action(STATUS_OK),
        supervisor_worker_status_transition_action_enqueue() as i32
    );
    assert_eq!(supervisor_blocked_initial_action_none(), 0);
    assert_eq!(
        supervisor_blocked_initial_action_defer_supervisor_timer(),
        1
    );
    assert_eq!(supervisor_blocked_initial_action_defer_rpc_pending(), 2);
    assert_eq!(supervisor_blocked_initial_action_arm_wait_timer(), 3);
    assert_eq!(supervisor_blocked_initial_action_retry_now(), 4);
    assert_eq!(supervisor_blocked_initial_action_schedule_retry(), 5);
    assert_eq!(supervisor_blocked_retry_result_action_none(), 0);
    assert_eq!(supervisor_blocked_retry_result_action_arm_wait_timer(), 1);
    assert_eq!(supervisor_blocked_retry_result_action_schedule_retry(), 2);
    assert_eq!(
        supervisor_blocked_retry_result_action_schedule_retry_and_pump(),
        3
    );
    assert_eq!(
        supervisor_blocked_post_network_pump_action_schedule_retry(),
        22
    );
    assert_eq!(
        supervisor_blocked_post_network_pump_action_schedule_retry_with_host_progress(),
        23
    );
    assert_eq!(supervisor_blocked_stale_retry_result_action_none(), 0);
    assert_eq!(
        supervisor_blocked_stale_retry_result_action_handle_current_result(),
        1
    );
    assert_eq!(
        supervisor_blocked_stale_retry_result_action_handle_current_result_wait4(),
        2
    );
    assert_eq!(supervisor_blocked_rpc_pipe_sync_action_not_pipe(), 0);
    assert_eq!(supervisor_blocked_rpc_pipe_sync_action_none(), 1);
    assert_eq!(supervisor_blocked_rpc_pipe_sync_action_sync_socket(), 2);
    assert_eq!(
        supervisor_blocked_rpc_post_resume_sync_flag_kernel_worker_available(),
        1
    );
    assert_eq!(
        supervisor_blocked_rpc_post_resume_sync_flag_process_owner_mismatch(),
        2
    );
    assert_eq!(supervisor_blocked_rpc_post_resume_sync_action_none(), 0);
    assert_eq!(
        supervisor_blocked_rpc_post_resume_sync_action_fork_shared(),
        1
    );
    assert_eq!(supervisor_blocked_rpc_post_resume_sync_action_socket(), 2);
    assert_eq!(
        supervisor_blocked_initial_action(0, STATUS_OK, 0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_retry_result_action(0, STATUS_OK),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_post_network_pump_action(0, 0, 0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_stale_retry_result_action(0, STATUS_WAIT4),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_rpc_pipe_sync_action(0, STATUS_OK),
        supervisor_blocked_rpc_pipe_sync_action_not_pipe() as i32
    );
    assert_eq!(
        supervisor_blocked_rpc_pipe_sync_action(0, STATUS_PIPE_WAIT),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_rpc_preserve_canonical_eof(STATUS_PIPE_WAIT),
        1
    );
    assert_eq!(supervisor_blocked_rpc_preserve_canonical_eof(STATUS_OK), 0);
    assert_eq!(supervisor_blocked_retry_action(0, 0), -(EFAULT as i32));
    assert_eq!(supervisor_blocked_wait_retry_reason(0, 0), -(EFAULT as i32));
    assert_eq!(
        supervisor_blocked_epoll_wait_retry_required(0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_wait_active_child_pid(0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_wait_retry_delay_ms(0, supervisor_blocked_wait_retry_reason_default()),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_vfork_execve_handoff_failure_wait_status(),
        127 << 8
    );
    assert_eq!(supervisor_process_status_is_lifecycle_handoff(STATUS_OK), 0);
    assert_eq!(
        supervisor_process_status_is_lifecycle_handoff(STATUS_VFORK_WAIT),
        1
    );
    assert_eq!(
        supervisor_process_status_is_lifecycle_handoff(STATUS_EXECVE_SPAWN),
        1
    );
    assert_eq!(
        supervisor_process_status_is_lifecycle_handoff(STATUS_CLONE_SPAWN),
        1
    );
    assert_eq!(supervisor_process_status_is_execve_spawn(STATUS_OK), 0);
    assert_eq!(
        supervisor_process_status_is_execve_spawn(STATUS_EXECVE_SPAWN),
        1
    );
    assert_eq!(
        supervisor_process_status_is_execve_spawn(STATUS_CLONE_SPAWN),
        0
    );
    assert_eq!(supervisor_process_status_is_clone_spawn(STATUS_OK), 0);
    assert_eq!(
        supervisor_process_status_is_clone_spawn(STATUS_CLONE_SPAWN),
        1
    );
    assert_eq!(
        supervisor_process_status_is_clone_spawn(STATUS_EXECVE_SPAWN),
        0
    );
    assert_eq!(supervisor_process_status_is_vfork_wait(STATUS_OK), 0);
    assert_eq!(
        supervisor_process_status_is_vfork_wait(STATUS_VFORK_WAIT),
        1
    );
    assert_eq!(
        supervisor_process_status_is_vfork_wait(STATUS_CLONE_SPAWN),
        0
    );
    assert_eq!(supervisor_process_status_allows_pid_mismatch(STATUS_OK), 0);
    assert_eq!(
        supervisor_process_status_allows_pid_mismatch(STATUS_VFORK_WAIT),
        1
    );
    assert_eq!(
        supervisor_process_status_allows_pid_mismatch(STATUS_EXECVE_SPAWN),
        1
    );
    assert_eq!(
        supervisor_process_status_allows_pid_mismatch(STATUS_CLONE_SPAWN),
        0
    );
    assert_eq!(
        supervisor_process_status_defers_kernel_state_adoption(STATUS_OK),
        0
    );
    assert_eq!(
        supervisor_process_status_defers_kernel_state_adoption(STATUS_CLONE_SPAWN),
        1
    );
    assert_eq!(
        supervisor_process_status_defers_kernel_state_adoption(STATUS_EXECVE_SPAWN),
        0
    );
    assert_eq!(supervisor_process_owner_absent(0), 0);
    assert_eq!(supervisor_process_owner_live_matches(0, 1), 0);
    assert_eq!(supervisor_process_owner_missing_or_invalid(0), 1);
    assert_eq!(supervisor_process_identity_matches(0, 1, 1), 0);
    assert_eq!(supervisor_vfork_execve_rollback(0, 1), -(EFAULT as i32));
    assert_eq!(supervisor_enqueue_blocked_wait_timer(0), EFAULT as i32);
    assert_eq!(supervisor_enqueue_blocked_retry_timer(0, 0), EFAULT as i32);
    assert_eq!(supervisor_blocked_wait_timer_required(0), EFAULT as i32);
    assert_eq!(
        supervisor_blocked_epoll_wait_timeout_ms(0),
        -(EFAULT as i64)
    );
    assert_eq!(supervisor_blocked_status_is_host_wait(STATUS_OK), 0);
    assert_eq!(supervisor_blocked_status_is_host_wait(STATUS_FS), 0);
    assert_eq!(supervisor_blocked_status_is_host_wait(STATUS_WAIT4), 1);
    assert_eq!(supervisor_blocked_status_is_host_wait(STATUS_PIPE_WAIT), 1);
    assert_eq!(supervisor_blocked_status_is_host_wait(STATUS_EPOLL_WAIT), 1);
    assert_eq!(supervisor_blocked_status_is_host_wait(STATUS_CONNECT), 1);
    assert_eq!(
        supervisor_blocked_status_is_host_wait(STATUS_SOCKET_RECV),
        1
    );
    assert_eq!(
        supervisor_blocked_status_is_host_wait(STATUS_SOCKET_SEND),
        1
    );
    assert_eq!(supervisor_blocked_status_is_host_wait(STATUS_FLOCK_WAIT), 1);
    assert_eq!(supervisor_blocked_status_is_connect_wait(STATUS_CONNECT), 1);
    assert_eq!(
        supervisor_blocked_status_is_connect_wait(STATUS_SOCKET_RECV),
        0
    );
    assert_eq!(
        supervisor_blocked_status_is_epoll_wait(STATUS_EPOLL_WAIT),
        1
    );
    assert_eq!(supervisor_blocked_status_is_epoll_wait(STATUS_PIPE_WAIT), 0);
    assert_eq!(supervisor_blocked_status_is_pipe_wait(STATUS_PIPE_WAIT), 1);
    assert_eq!(supervisor_blocked_status_is_pipe_wait(STATUS_WAIT4), 0);
    assert_eq!(supervisor_blocked_status_is_wait4(STATUS_WAIT4), 1);
    assert_eq!(supervisor_blocked_status_is_wait4(STATUS_PIPE_WAIT), 0);
    assert_eq!(
        supervisor_blocked_status_is_socket_wait(STATUS_SOCKET_RECV),
        1
    );
    assert_eq!(
        supervisor_blocked_status_is_socket_wait(STATUS_SOCKET_SEND),
        1
    );
    assert_eq!(
        supervisor_blocked_status_is_socket_wait(STATUS_PIPE_WAIT),
        0
    );
    assert_eq!(
        supervisor_blocked_status_needs_network_sidecar_restore(STATUS_CONNECT),
        1
    );
    assert_eq!(
        supervisor_blocked_status_needs_network_sidecar_restore(STATUS_SOCKET_RECV),
        1
    );
    assert_eq!(
        supervisor_blocked_status_needs_network_sidecar_restore(STATUS_SOCKET_SEND),
        1
    );
    assert_eq!(
        supervisor_blocked_status_needs_network_sidecar_restore(STATUS_PIPE_WAIT),
        1
    );
    assert_eq!(
        supervisor_blocked_status_needs_network_sidecar_restore(STATUS_EPOLL_WAIT),
        1
    );
    assert_eq!(
        supervisor_blocked_status_needs_network_sidecar_restore(STATUS_WAIT4),
        0
    );
    assert_eq!(
        supervisor_blocked_status_syncs_socket_after_resume(STATUS_CONNECT),
        1
    );
    assert_eq!(
        supervisor_blocked_status_syncs_socket_after_resume(STATUS_SOCKET_RECV),
        1
    );
    assert_eq!(
        supervisor_blocked_status_syncs_socket_after_resume(STATUS_SOCKET_SEND),
        1
    );
    assert_eq!(
        supervisor_blocked_status_syncs_socket_after_resume(STATUS_PIPE_WAIT),
        0
    );
    assert_eq!(
        supervisor_blocked_status_uses_fork_shared_state_sync(STATUS_PIPE_WAIT),
        1
    );
    assert_eq!(
        supervisor_blocked_status_uses_fork_shared_state_sync(STATUS_SOCKET_RECV),
        1
    );
    assert_eq!(
        supervisor_blocked_status_uses_fork_shared_state_sync(STATUS_SOCKET_SEND),
        1
    );
    assert_eq!(
        supervisor_blocked_status_uses_fork_shared_state_sync(STATUS_FLOCK_WAIT),
        1
    );
    assert_eq!(
        supervisor_blocked_status_uses_fork_shared_state_sync(STATUS_CONNECT),
        0
    );
    assert_eq!(supervisor_blocked_poll_wait_timeout_ms(0), -(EFAULT as i64));
    assert_eq!(supervisor_blocked_poll_wait_has_socket(0), -(EFAULT as i32));
    assert_eq!(
        supervisor_blocked_pipe_wait_has_ready_events(0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_wait_may_depend_on_network(0),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_wait_should_pump_network(0),
        -(EFAULT as i32)
    );

    let empty_hash = supervisor_shadow_thread_event_log_hash();
    assert_eq!(supervisor_shadow_thread_event_count(), 0);
    assert_eq!(supervisor_submit_thread_event(0, 0), 0);
    assert_eq!(supervisor_shadow_thread_event_count(), 1);
    assert_ne!(supervisor_shadow_thread_event_log_hash(), empty_hash);

    assert_eq!(supervisor_shadow_host_completion_count(), 0);
    assert_eq!(supervisor_complete_host_op(0, 0), 0);
    assert_eq!(supervisor_shadow_host_completion_count(), 1);

    let empty_host_op_hash = supervisor_shadow_host_op_log_hash();
    assert_eq!(supervisor_shadow_host_op_last_hash(), 0);
    assert_eq!(supervisor_shadow_host_op_last_len(), 0);
    let mut t = TestVm::new();
    t.vm.guest_memory_policy_limit = 5 * 1024 * 1024;
    t.vm.process_max_memory_pages = 96;
    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(supervisor_blocked_poll_wait_has_socket(vm_ptr), 0);
    assert_eq!(supervisor_blocked_pipe_wait_has_ready_events(vm_ptr), 0);
    assert_eq!(supervisor_blocked_wait_may_depend_on_network(vm_ptr), 0);
    assert_eq!(supervisor_blocked_wait_should_pump_network(vm_ptr), 0);
    assert_eq!(supervisor_blocked_epoll_wait_retry_required(vm_ptr), 0);
    t.vm.status = STATUS_EPOLL_WAIT;
    assert_eq!(supervisor_blocked_epoll_wait_retry_required(vm_ptr), 0);
    let process_state = unsafe {
        &*((u64::from(t.base) + u64::from(t.vm.process_ptr))
            as *const tidemark_kernel::types::ProcessState)
    };
    process_state.thread_count.store(2, Ordering::Release);
    assert_eq!(supervisor_blocked_epoll_wait_retry_required(vm_ptr), 1);
    assert_eq!(
        supervisor_blocked_initial_action(vm_ptr, STATUS_EPOLL_WAIT, 0),
        supervisor_blocked_initial_action_arm_wait_timer() as i32
    );
    assert_eq!(
        supervisor_blocked_retry_result_action(vm_ptr, STATUS_EPOLL_WAIT),
        supervisor_blocked_retry_result_action_arm_wait_timer() as i32
    );
    t.vm.epoll_timeout_ms = -1;
    assert_eq!(
        supervisor_blocked_initial_action(vm_ptr, STATUS_EPOLL_WAIT, 0),
        supervisor_blocked_initial_action_schedule_retry() as i32
    );
    assert_eq!(
        supervisor_blocked_retry_result_action(vm_ptr, STATUS_EPOLL_WAIT),
        supervisor_blocked_retry_result_action_schedule_retry_and_pump() as i32
    );
    t.vm.status = STATUS_PIPE_WAIT;
    assert_eq!(supervisor_blocked_epoll_wait_retry_required(vm_ptr), 0);
    assert_eq!(
        supervisor_blocked_initial_action(vm_ptr, STATUS_PIPE_WAIT, 0),
        supervisor_blocked_initial_action_schedule_retry() as i32
    );
    assert_eq!(
        supervisor_blocked_retry_result_action(vm_ptr, STATUS_PIPE_WAIT),
        supervisor_blocked_retry_result_action_schedule_retry() as i32
    );
    assert_eq!(
        supervisor_blocked_post_network_pump_action(vm_ptr, 0, 0),
        supervisor_blocked_post_network_pump_action_schedule_retry_with_host_progress() as i32
    );
    assert_eq!(
        supervisor_blocked_post_network_pump_action(vm_ptr, 1, 0),
        supervisor_blocked_post_network_pump_action_schedule_retry() as i32
    );
    t.vm.status = STATUS_WAIT4;
    assert_eq!(
        supervisor_blocked_initial_action(vm_ptr, STATUS_WAIT4, 0),
        supervisor_blocked_initial_action_retry_now() as i32
    );
    assert_eq!(
        supervisor_blocked_stale_retry_result_action(vm_ptr, STATUS_WAIT4),
        supervisor_blocked_stale_retry_result_action_none() as i32
    );
    t.vm.status = STATUS_OK;
    assert_eq!(
        supervisor_blocked_stale_retry_result_action(vm_ptr, STATUS_WAIT4),
        supervisor_blocked_stale_retry_result_action_handle_current_result_wait4() as i32
    );
    t.vm.status = STATUS_FAULT;
    assert_eq!(
        supervisor_blocked_stale_retry_result_action(vm_ptr, STATUS_PIPE_WAIT),
        supervisor_blocked_stale_retry_result_action_handle_current_result() as i32
    );
    t.vm.status = STATUS_EPOLL_WAIT;
    assert_eq!(
        supervisor_blocked_stale_retry_result_action(vm_ptr, STATUS_PIPE_WAIT),
        supervisor_blocked_stale_retry_result_action_none() as i32
    );
    t.vm.status = STATUS_EPOLL_WAIT;
    process_state.thread_count.store(1, Ordering::Release);
    assert_eq!(
        supervisor_blocked_initial_action(vm_ptr, STATUS_EPOLL_WAIT, 0),
        supervisor_blocked_initial_action_none() as i32
    );
    assert_eq!(
        supervisor_blocked_retry_result_action(vm_ptr, STATUS_EPOLL_WAIT),
        supervisor_blocked_retry_result_action_none() as i32
    );
    assert_eq!(
        supervisor_blocked_initial_action(
            vm_ptr,
            STATUS_EPOLL_WAIT,
            supervisor_blocked_retry_action_flag_supervisor_timer_armed()
        ),
        supervisor_blocked_initial_action_defer_supervisor_timer() as i32
    );
    assert_eq!(
        supervisor_blocked_initial_action(
            vm_ptr,
            STATUS_EPOLL_WAIT,
            supervisor_blocked_retry_action_flag_rpc_pending()
        ),
        supervisor_blocked_initial_action_defer_rpc_pending() as i32
    );
    t.vm.status = STATUS_OK;
    assert_eq!(
        supervisor_blocked_wait_retry_reason(vm_ptr, 0),
        supervisor_blocked_wait_retry_reason_default() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_retry_reason(
            vm_ptr,
            supervisor_blocked_wait_retry_flag_host_progress()
        ),
        supervisor_blocked_wait_retry_reason_immediate() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_retry_reason(
            vm_ptr,
            supervisor_blocked_wait_retry_flag_active_child()
        ),
        supervisor_blocked_wait_retry_reason_active_child() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_retry_reason(
            vm_ptr,
            supervisor_blocked_wait_retry_flag_passive_wait()
        ),
        supervisor_blocked_wait_retry_reason_passive_wait() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_retry_reason(
            vm_ptr,
            supervisor_blocked_wait_retry_flag_process_gate()
        ),
        supervisor_blocked_wait_retry_reason_process_gate() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_retry_reason(
            vm_ptr,
            supervisor_blocked_wait_retry_flag_thread_init_pending()
        ),
        supervisor_blocked_wait_retry_reason_standard_defer() as i32
    );
    assert_eq!(
        supervisor_blocked_wait_retry_delay_ms(
            vm_ptr,
            supervisor_blocked_wait_retry_reason_immediate()
        ),
        0
    );
    assert_eq!(
        supervisor_blocked_wait_retry_delay_ms(
            vm_ptr,
            supervisor_blocked_wait_retry_reason_standard_defer()
        ),
        10
    );
    assert_eq!(
        supervisor_blocked_wait_retry_delay_ms(
            vm_ptr,
            supervisor_blocked_wait_retry_reason_active_child()
        ),
        5
    );
    assert_eq!(
        supervisor_blocked_wait_retry_delay_ms(
            vm_ptr,
            supervisor_blocked_wait_retry_reason_passive_wait()
        ),
        25
    );
    assert_eq!(
        supervisor_blocked_wait_retry_delay_ms(
            vm_ptr,
            supervisor_blocked_wait_retry_reason_process_gate()
        ),
        50
    );
    assert_eq!(
        supervisor_blocked_wait_retry_delay_ms(
            vm_ptr,
            supervisor_blocked_wait_retry_reason_default()
        ),
        1
    );
    let initial_status = t.vm.status;
    let status_transition_kernel_worker =
        supervisor_blocked_status_transition_flag_kernel_worker_available();
    let status_transition_network =
        supervisor_blocked_status_transition_flag_network_connections_available();
    assert_eq!(supervisor_blocked_status_transition_action_block(), 0);
    assert_eq!(supervisor_blocked_status_transition_action_sync_socket(), 1);
    assert_eq!(supervisor_blocked_status_transition_action_sync_pipe(), 2);
    assert_eq!(
        supervisor_blocked_status_transition_action_sync_fork_shared(),
        3
    );
    assert_eq!(
        supervisor_blocked_status_transition_action_sync_pipe_and_fork_shared(),
        4
    );
    assert_eq!(
        supervisor_blocked_status_transition_action_sync_socket_and_fork_shared(),
        5
    );
    assert_eq!(
        supervisor_blocked_status_transition_action(
            0,
            STATUS_PIPE_WAIT,
            status_transition_kernel_worker
        ),
        -(EFAULT as i32)
    );
    assert_eq!(
        supervisor_blocked_resume_delegation(vm_ptr, 0),
        supervisor_blocked_resume_delegation_direct() as i32
    );
    t.vm.status = STATUS_WAIT4;
    assert_eq!(supervisor_blocked_wait_timer_required(vm_ptr), 0);
    assert_eq!(
        supervisor_blocked_wait_retry_delay_ms(
            vm_ptr,
            supervisor_blocked_wait_retry_reason_default()
        ),
        10
    );
    assert_eq!(
        supervisor_blocked_resume_delegation(vm_ptr, 0),
        supervisor_blocked_resume_delegation_direct() as i32
    );
    assert_eq!(
        supervisor_blocked_resume_delegation(
            vm_ptr,
            supervisor_blocked_resume_delegation_flag_kernel_worker_available()
        ),
        supervisor_blocked_resume_delegation_wait4_kernel_worker() as i32
    );
    assert_eq!(
        supervisor_blocked_status_transition_action(
            vm_ptr,
            STATUS_WAIT4,
            status_transition_kernel_worker
        ),
        supervisor_blocked_status_transition_action_sync_pipe() as i32
    );
    assert_eq!(
        supervisor_blocked_rpc_post_resume_sync_action(
            STATUS_WAIT4,
            supervisor_blocked_rpc_post_resume_sync_flag_kernel_worker_available()
        ),
        supervisor_blocked_rpc_post_resume_sync_action_fork_shared() as i32
    );
    t.vm.status = STATUS_PIPE_WAIT;
    t.vm.epoll_timeout_ms = -1;
    set_blocked_resume_syscall(&mut t.vm, SYS_READ, [3, 0x1000, 1, 0, 0, 0]);
    assert_eq!(supervisor_blocked_epoll_wait_timeout_ms(vm_ptr), -1);
    assert_eq!(supervisor_blocked_poll_wait_timeout_ms(vm_ptr), -1);
    assert_eq!(supervisor_blocked_poll_wait_has_socket(vm_ptr), 0);
    assert_eq!(
        supervisor_blocked_rpc_pipe_sync_action(vm_ptr, STATUS_OK),
        supervisor_blocked_rpc_pipe_sync_action_not_pipe() as i32
    );
    assert_eq!(
        supervisor_blocked_rpc_pipe_sync_action(vm_ptr, STATUS_PIPE_WAIT),
        supervisor_blocked_rpc_pipe_sync_action_none() as i32
    );
    assert_eq!(supervisor_blocked_pipe_wait_has_ready_events(vm_ptr), 0);
    assert_eq!(supervisor_blocked_wait_may_depend_on_network(vm_ptr), 0);
    assert_eq!(supervisor_blocked_wait_should_pump_network(vm_ptr), 1);
    assert_eq!(
        supervisor_blocked_status_transition_action(vm_ptr, STATUS_PIPE_WAIT, 0),
        supervisor_blocked_status_transition_action_block() as i32
    );
    assert_eq!(
        supervisor_blocked_status_transition_action(
            vm_ptr,
            STATUS_PIPE_WAIT,
            status_transition_kernel_worker
        ),
        supervisor_blocked_status_transition_action_sync_pipe_and_fork_shared() as i32
    );
    set_blocked_resume_syscall(&mut t.vm, SYS_PPOLL, [0x1000, 2, 0, 0, 0, 0]);
    assert_eq!(supervisor_blocked_poll_wait_timeout_ms(vm_ptr), -1);
    assert_eq!(supervisor_blocked_wait_timer_required(vm_ptr), 0);
    t.vm.epoll_timeout_ms = 1;
    assert_eq!(supervisor_blocked_poll_wait_timeout_ms(vm_ptr), 1);
    assert_eq!(supervisor_blocked_poll_wait_has_socket(vm_ptr), 0);
    set_blocked_resume_syscall(&mut t.vm, SYS_PSELECT6, [8, 0x2000, 0, 0, 0, 0]);
    t.vm.epoll_timeout_ms = 25;
    assert_eq!(supervisor_blocked_poll_wait_timeout_ms(vm_ptr), 25);
    assert_eq!(supervisor_blocked_wait_timer_required(vm_ptr), 1);
    let socket_fd = tidemark_kernel::syscall::socket::sys_socket(
        &mut t.vm,
        t.base,
        AF_INET as u64,
        SOCK_STREAM as u64,
        0,
    );
    assert!(socket_fd >= 0);
    let pollfd = t.scratch + 0x980;
    write_pollfd(&mut t, pollfd, socket_fd as i32, 0x001);
    set_blocked_resume_syscall(&mut t.vm, SYS_PPOLL, [pollfd, 1, 0, 0, 0, 0]);
    assert_eq!(supervisor_blocked_poll_wait_timeout_ms(vm_ptr), 25);
    assert_eq!(supervisor_blocked_poll_wait_has_socket(vm_ptr), 1);
    assert_eq!(
        supervisor_blocked_rpc_pipe_sync_action(vm_ptr, STATUS_PIPE_WAIT),
        supervisor_blocked_rpc_pipe_sync_action_sync_socket() as i32
    );
    assert_eq!(supervisor_blocked_wait_may_depend_on_network(vm_ptr), 1);
    assert_eq!(supervisor_blocked_wait_should_pump_network(vm_ptr), 1);
    assert_eq!(
        supervisor_blocked_status_transition_action(
            vm_ptr,
            STATUS_PIPE_WAIT,
            status_transition_kernel_worker
        ),
        supervisor_blocked_status_transition_action_block() as i32
    );
    assert_eq!(
        supervisor_blocked_status_transition_action(
            vm_ptr,
            STATUS_PIPE_WAIT,
            status_transition_kernel_worker | status_transition_network
        ),
        supervisor_blocked_status_transition_action_sync_socket() as i32
    );
    assert_eq!(
        supervisor_blocked_post_network_pump_action(
            vm_ptr,
            1,
            supervisor_blocked_retry_action_flag_running_worker()
        ),
        supervisor_blocked_retry_action_defer_running_worker() as i32
    );
    assert_eq!(
        supervisor_blocked_resume_delegation(
            vm_ptr,
            supervisor_blocked_resume_delegation_flag_kernel_worker_available()
        ),
        supervisor_blocked_resume_delegation_kernel_worker() as i32
    );
    t.vm.status = STATUS_SOCKET_RECV;
    t.vm.socket_timeout_ms = -1;
    assert_eq!(supervisor_blocked_poll_wait_has_socket(vm_ptr), 0);
    assert_eq!(supervisor_blocked_pipe_wait_has_ready_events(vm_ptr), 0);
    assert_eq!(supervisor_blocked_wait_may_depend_on_network(vm_ptr), 1);
    assert_eq!(supervisor_blocked_wait_should_pump_network(vm_ptr), 1);
    assert_eq!(supervisor_blocked_wait_timer_required(vm_ptr), 0);
    assert_eq!(
        supervisor_blocked_status_transition_action(
            vm_ptr,
            STATUS_SOCKET_RECV,
            status_transition_kernel_worker
        ),
        supervisor_blocked_status_transition_action_sync_socket_and_fork_shared() as i32
    );
    assert_eq!(
        supervisor_blocked_rpc_post_resume_sync_action(STATUS_SOCKET_RECV, 0),
        supervisor_blocked_rpc_post_resume_sync_action_socket() as i32
    );
    assert_eq!(
        supervisor_blocked_rpc_post_resume_sync_action(
            STATUS_SOCKET_RECV,
            supervisor_blocked_rpc_post_resume_sync_flag_kernel_worker_available()
        ),
        (supervisor_blocked_rpc_post_resume_sync_action_fork_shared()
            | supervisor_blocked_rpc_post_resume_sync_action_socket()) as i32
    );
    assert_eq!(
        supervisor_blocked_rpc_post_resume_sync_action(
            STATUS_SOCKET_RECV,
            supervisor_blocked_rpc_post_resume_sync_flag_kernel_worker_available()
                | supervisor_blocked_rpc_post_resume_sync_flag_process_owner_mismatch()
        ),
        supervisor_blocked_rpc_post_resume_sync_action_none() as i32
    );
    t.vm.socket_timeout_ms = 1;
    assert_eq!(supervisor_blocked_wait_timer_required(vm_ptr), 1);
    assert_eq!(
        supervisor_blocked_resume_delegation(
            vm_ptr,
            supervisor_blocked_resume_delegation_flag_kernel_worker_available()
        ),
        supervisor_blocked_resume_delegation_kernel_worker() as i32
    );
    t.vm.status = STATUS_FLOCK_WAIT;
    assert_eq!(
        supervisor_blocked_resume_delegation(
            vm_ptr,
            supervisor_blocked_resume_delegation_flag_kernel_worker_available()
        ),
        supervisor_blocked_resume_delegation_kernel_worker() as i32
    );
    t.vm.status = STATUS_EPOLL_WAIT;
    t.vm.epoll_timeout_ms = -1;
    assert_eq!(supervisor_blocked_epoll_wait_timeout_ms(vm_ptr), -1);
    assert_eq!(supervisor_blocked_wait_timer_required(vm_ptr), 0);
    assert_eq!(
        supervisor_blocked_rpc_post_resume_sync_action(
            STATUS_EPOLL_WAIT,
            supervisor_blocked_rpc_post_resume_sync_flag_kernel_worker_available()
        ),
        supervisor_blocked_rpc_post_resume_sync_action_none() as i32
    );
    assert_eq!(
        supervisor_blocked_status_transition_action(
            vm_ptr,
            STATUS_EPOLL_WAIT,
            status_transition_kernel_worker
        ),
        supervisor_blocked_status_transition_action_block() as i32
    );
    t.vm.epoll_timeout_ms = 1;
    assert_eq!(supervisor_blocked_epoll_wait_timeout_ms(vm_ptr), 1);
    assert_eq!(supervisor_blocked_wait_timer_required(vm_ptr), 1);
    assert_eq!(
        supervisor_blocked_resume_delegation(vm_ptr, 0),
        supervisor_blocked_resume_delegation_epoll_direct() as i32
    );
    assert_eq!(
        supervisor_blocked_resume_delegation(
            vm_ptr,
            supervisor_blocked_resume_delegation_flag_kernel_worker_available()
        ),
        supervisor_blocked_resume_delegation_unsupported() as i32
    );
    t.vm.epoll_timeout_ms = -1;
    t.vm.socket_timeout_ms = -1;
    t.vm.status = initial_status;
    let child_pid = tidemark_kernel::syscall::process::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0);
    assert!(child_pid > 0);
    assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

    assert_eq!(
        supervisor_process_host_op(vm_ptr, 0, supervisor_process_host_op_record_bytes()),
        EFAULT as i32
    );
    assert_eq!(supervisor_shadow_host_op_emit_count(), 0);
    assert_eq!(supervisor_shadow_host_op_last_hash(), 0);
    assert_eq!(supervisor_shadow_host_op_last_len(), 0);
    assert_eq!(supervisor_shadow_host_op_log_hash(), empty_host_op_hash);
    let mut too_small_host_op = vec![0u8; supervisor_process_host_op_record_bytes() as usize - 1];
    assert_eq!(
        supervisor_process_host_op(
            vm_ptr,
            too_small_host_op.as_mut_ptr() as u32,
            too_small_host_op.len() as u32
        ),
        ENOSPC as i32
    );
    assert_eq!(supervisor_shadow_host_op_emit_count(), 0);
    assert_eq!(supervisor_shadow_host_op_last_hash(), 0);
    assert_eq!(supervisor_shadow_host_op_last_len(), 0);
    assert_eq!(supervisor_shadow_host_op_log_hash(), empty_host_op_hash);

    let mut host_op = vec![0u8; supervisor_process_host_op_record_bytes() as usize];
    assert_eq!(
        supervisor_process_host_op(vm_ptr, host_op.as_mut_ptr() as u32, host_op.len() as u32),
        supervisor_process_host_op_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&host_op, 0), 0x4850_5354);
    assert_eq!(read_u32_le(&host_op, 4), supervisor_abi_version());
    assert_eq!(
        read_u32_le(&host_op, 8),
        supervisor_process_host_op_record_bytes()
    );
    assert_eq!(
        read_u32_le(&host_op, 12),
        supervisor_process_host_op_kind_spawn_process_worker()
    );
    assert_eq!(read_u64_le(&host_op, 16), 1);
    assert_eq!(read_u32_le(&host_op, 24), vm_ptr);
    assert_eq!(read_u32_le(&host_op, 28), SPAWN_KIND_FORK);
    assert_eq!(read_u32_le(&host_op, 32), child_pid as u32);
    let host_op_entry_hash = fnv_hash(&host_op);
    assert_eq!(supervisor_shadow_host_op_emit_count(), 1);
    assert_eq!(
        supervisor_shadow_host_op_last_len(),
        supervisor_process_host_op_record_bytes()
    );
    assert_eq!(supervisor_shadow_host_op_last_hash(), host_op_entry_hash);
    assert_eq!(
        supervisor_shadow_host_op_log_hash(),
        fold_log_hash(
            empty_host_op_hash,
            host_op_entry_hash,
            supervisor_process_host_op_record_bytes(),
        )
    );
    assert_ne!(supervisor_shadow_host_op_log_hash(), empty_host_op_hash);

    let host_op_log_after_first_read = supervisor_shadow_host_op_log_hash();
    let mut repeated_host_op = vec![0u8; supervisor_process_host_op_record_bytes() as usize];
    assert_eq!(
        supervisor_process_host_op(
            vm_ptr,
            repeated_host_op.as_mut_ptr() as u32,
            repeated_host_op.len() as u32
        ),
        supervisor_process_host_op_record_bytes() as i32
    );
    assert_eq!(repeated_host_op, host_op);
    assert_eq!(read_u64_le(&repeated_host_op, 16), 1);
    assert_eq!(supervisor_shadow_host_op_emit_count(), 1);
    assert_eq!(supervisor_shadow_host_op_last_hash(), host_op_entry_hash);
    assert_eq!(
        supervisor_shadow_host_op_log_hash(),
        host_op_log_after_first_read
    );

    assert_eq!(supervisor_next_host_op(0, 0), 0);
    assert_eq!(supervisor_shadow_host_op_poll_count(), 5);
    assert_eq!(supervisor_shadow_host_op_emit_count(), 1);
    assert_eq!(supervisor_shadow_host_op_overflow_count(), 0);
    assert_eq!(supervisor_shadow_thread_exit_cleanup_count(), 0);
    assert_eq!(supervisor_shadow_process_lifecycle_count(), 0);
    assert_eq!(supervisor_shadow_fs_control_count(), 0);
    assert_eq!(supervisor_shadow_signal_control_count(), 0);
    assert_eq!(supervisor_next_resume(0, 0), 0);
    assert_eq!(supervisor_shadow_resume_poll_count(), 1);

    let mut snapshot = [0u8; 112];
    assert_eq!(
        supervisor_debug_snapshot(snapshot.as_mut_ptr() as u32, snapshot.len() as u32),
        112
    );
    assert_eq!(read_u32_le(&snapshot, 0), 0x5055_5354);
    assert_eq!(read_u32_le(&snapshot, 4), 1);
    assert_eq!(read_u32_le(&snapshot, 8), 112);
    assert_eq!(read_u32_le(&snapshot, 12), 0);
    assert_eq!(read_u64_le(&snapshot, 16), 1);
    assert_eq!(read_u64_le(&snapshot, 24), 1);
    assert_eq!(read_u64_le(&snapshot, 32), 5);
    assert_eq!(read_u64_le(&snapshot, 40), 1);
    assert_eq!(
        read_u64_le(&snapshot, 48),
        supervisor_shadow_thread_event_log_hash()
    );
    assert_eq!(
        read_u64_le(&snapshot, 56),
        supervisor_shadow_host_completion_log_hash()
    );
    assert_eq!(read_u32_le(&snapshot, 64), 0);
    assert_eq!(read_u32_le(&snapshot, 68), 0);
    assert_ne!(read_u64_le(&snapshot, 72), 0);
    assert_ne!(read_u64_le(&snapshot, 80), 0);
    assert_eq!(
        read_u64_le(&snapshot, 88),
        supervisor_shadow_host_op_log_hash()
    );
    assert_eq!(read_u64_le(&snapshot, 96), host_op_entry_hash);
    assert_eq!(
        read_u32_le(&snapshot, 104),
        supervisor_process_host_op_record_bytes()
    );
    assert_eq!(read_u32_le(&snapshot, 108), 0);

    let mut too_small = [0u8; 111];
    assert_eq!(
        supervisor_debug_snapshot(too_small.as_mut_ptr() as u32, too_small.len() as u32),
        ENOSPC as i32
    );
}

fn set_blocked_resume_syscall(
    vm: &mut tidemark_kernel::types::ThreadState,
    syscall_nr: u64,
    args: [u64; 6],
) {
    vm.blocked_syscall_nr = syscall_nr;
    vm.blocked_syscall_args = args;
}

#[test]
fn supervisor_blocked_resume_writeback_ranges_follow_blocked_syscall() {
    let mut vm: tidemark_kernel::types::ThreadState = unsafe { core::mem::zeroed() };
    let vm_ptr = &mut vm as *mut tidemark_kernel::types::ThreadState as u32;

    set_blocked_resume_syscall(&mut vm, SYS_PPOLL, [0x1000, 4, 0, 0, 0, 0]);
    assert_eq!(
        supervisor_blocked_resume_writeback_count(vm_ptr, abi_status_pipe_wait(), 1),
        1
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_ptr(vm_ptr, abi_status_pipe_wait(), 1, 0),
        0x1000
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_len(vm_ptr, abi_status_pipe_wait(), 1, 0),
        32
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_ptr(vm_ptr, abi_status_pipe_wait(), 1, 1),
        0
    );

    set_blocked_resume_syscall(&mut vm, SYS_PSELECT6, [130, 0x2000, 0x3000, 0x4000, 0, 0]);
    assert_eq!(
        supervisor_blocked_resume_writeback_count(vm_ptr, abi_status_pipe_wait(), 1),
        3
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_ptr(vm_ptr, abi_status_pipe_wait(), 1, 0),
        0x2000
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_ptr(vm_ptr, abi_status_pipe_wait(), 1, 1),
        0x3000
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_ptr(vm_ptr, abi_status_pipe_wait(), 1, 2),
        0x4000
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_len(vm_ptr, abi_status_pipe_wait(), 1, 2),
        24
    );

    set_blocked_resume_syscall(&mut vm, SYS_PSELECT6, [130, 0x2000, 0, 0, 0, 0]);
    assert_eq!(
        supervisor_blocked_resume_writeback_count(vm_ptr, abi_status_pipe_wait(), 1),
        1
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_ptr(vm_ptr, abi_status_pipe_wait(), 1, 0),
        0x2000
    );

    set_blocked_resume_syscall(&mut vm, SYS_READ, [3, 0x5000, 99, 0, 0, 0]);
    assert_eq!(
        supervisor_blocked_resume_writeback_count(vm_ptr, abi_status_pipe_wait(), 7),
        1
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_ptr(vm_ptr, abi_status_pipe_wait(), 7, 0),
        0x5000
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_len(vm_ptr, abi_status_pipe_wait(), 7, 0),
        7
    );

    set_blocked_resume_syscall(&mut vm, SYS_RECVFROM, [4, 0x6000, 64, 0, 0, 0]);
    assert_eq!(
        supervisor_blocked_resume_writeback_count(vm_ptr, abi_status_socket_recv(), 9),
        1
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_ptr(vm_ptr, abi_status_socket_recv(), 9, 0),
        0x6000
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_len(vm_ptr, abi_status_socket_recv(), 9, 0),
        9
    );
    assert_eq!(
        supervisor_blocked_resume_writeback_count(vm_ptr, abi_status_socket_recv(), 0),
        0
    );
}

#[test]
fn supervisor_shadow_rejects_non_empty_null_records() {
    supervisor_reset_shadow_log();

    assert_eq!(supervisor_submit_thread_event(0, 1), EFAULT as i32);
    assert_eq!(supervisor_complete_host_op(0, 1), EFAULT as i32);
    assert_eq!(supervisor_process_host_op(0, 0, 1), EFAULT as i32);
    assert_eq!(supervisor_process_resume(0, 0, 1), EFAULT as i32);
    assert_eq!(supervisor_shadow_thread_event_count(), 0);
    assert_eq!(supervisor_shadow_host_completion_count(), 0);
}

#[test]
fn supervisor_fd_entry_restore_action_preserves_live_regular_file_fds() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    let fd = t.sys_openat(b"/fd-entry-restore-action", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    let live_ofd = process_fd_ofd_id(vm_ptr, fd as u32);
    assert_ne!(live_ofd, 0);

    assert_eq!(
        supervisor_fd_entry_restore_action(
            vm_ptr,
            fd as u32,
            0,
            u64::MAX,
            supervisor_fd_entry_restore_flag_preserve_live_regular_file(),
        ),
        supervisor_fd_entry_restore_action_skip() as i32
    );
    assert_eq!(
        supervisor_fd_entry_restore_action(
            vm_ptr,
            fd as u32,
            live_ofd,
            u64::MAX,
            supervisor_fd_entry_restore_flag_preserve_live_regular_file(),
        ),
        supervisor_fd_entry_restore_action_apply() as i32
    );
    assert_eq!(
        supervisor_fd_entry_restore_action(
            vm_ptr,
            fd as u32,
            0,
            SYS_CLOSE,
            supervisor_fd_entry_restore_flag_preserve_live_regular_file(),
        ),
        supervisor_fd_entry_restore_action_apply() as i32
    );
}

#[test]
fn supervisor_fd_and_ofd_slot_restore_actions_are_kernel_owned() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    let high_fd = t.sys_openat(b"/ofd-slot-restore-action", O_CREAT | O_RDWR);
    let low_fd = t.sys_openat(b"/ofd-slot-restore-action", O_CREAT | O_RDWR);
    assert!(high_fd >= 3);
    assert!(low_fd >= 3);
    assert_eq!(t.sys_lseek(high_fd, 4096, 0), 4096);
    assert_eq!(t.sys_lseek(low_fd, 64, 0), 64);
    let high_ofd = process_fd_ofd_id(vm_ptr, high_fd as u32);
    let low_ofd = process_fd_ofd_id(vm_ptr, low_fd as u32);
    assert_ne!(high_ofd, 0);
    assert_ne!(low_ofd, 0);
    assert_ne!(high_ofd, low_ofd);
    assert_eq!(kernel_ofd_fd_type(high_ofd), FD_TYPE_FILE);
    assert_eq!(kernel_ofd_fd_type(low_ofd), FD_TYPE_FILE);
    assert_eq!(kernel_ofd_host_fd(high_ofd), kernel_ofd_host_fd(low_ofd));
    assert_eq!(kernel_ofd_ino(high_ofd), kernel_ofd_ino(low_ofd));

    assert_eq!(
        supervisor_fd_entry_guest_write_action(vm_ptr, high_fd as u32, low_ofd, 0),
        supervisor_fd_entry_restore_action_skip() as i32
    );
    assert_eq!(
        supervisor_fd_entry_guest_write_action(vm_ptr, high_fd as u32, high_ofd, 0),
        supervisor_fd_entry_restore_action_apply() as i32
    );

    let pipefd_addr = 0x2300;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
        0
    );
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) };
    let read_ofd = process_fd_ofd_id(vm_ptr, read_fd);
    assert_ne!(read_ofd, 0);
    assert_eq!(
        supervisor_fd_entry_guest_write_action(vm_ptr, read_fd, 0, read_ofd),
        supervisor_fd_entry_restore_action_skip() as i32
    );

    let high_host_fd = kernel_ofd_host_fd(high_ofd);
    let high_ino = kernel_ofd_ino(high_ofd);
    assert_eq!(
        supervisor_ofd_slot_write_action(high_ofd, FD_TYPE_FILE, high_host_fd, high_ino, 64),
        supervisor_fd_entry_restore_action_skip() as i32
    );
    assert_eq!(
        supervisor_ofd_slot_write_action(high_ofd, FD_TYPE_FILE, high_host_fd, high_ino, 8192),
        supervisor_fd_entry_restore_action_apply() as i32
    );
    assert_eq!(
        supervisor_ofd_slot_write_action(high_ofd, 0, high_host_fd, high_ino, 4096),
        supervisor_fd_entry_restore_action_skip() as i32
    );
    assert_eq!(
        supervisor_regular_file_offset_restore_action(high_ofd, high_host_fd, high_ino, 8192),
        supervisor_fd_entry_restore_action_apply() as i32
    );
    assert_eq!(
        supervisor_regular_file_offset_restore_action(high_ofd, high_host_fd, high_ino, 64),
        supervisor_fd_entry_restore_action_skip() as i32
    );
    assert_eq!(
        supervisor_regular_file_offset_restore_action(high_ofd, high_host_fd, high_ino + 1, 8192),
        supervisor_fd_entry_restore_action_skip() as i32
    );

    let referenced = supervisor_ofd_slot_restore_flag_referenced_by_fd_entry();
    let trusted = supervisor_ofd_slot_restore_flag_trust_regular_file_offset();
    assert_eq!(
        supervisor_ofd_slot_restore_action(high_ofd, 0, 0, 0, 0, u64::MAX, referenced),
        supervisor_fd_entry_restore_action_apply() as i32
    );
    assert_eq!(
        supervisor_ofd_slot_restore_action(high_ofd, 0, 0, 0, 0, u64::MAX, 0),
        supervisor_fd_entry_restore_action_skip() as i32
    );
    assert_eq!(
        supervisor_ofd_slot_restore_action(
            high_ofd,
            FD_TYPE_FILE,
            high_host_fd,
            high_ino,
            64,
            u64::MAX,
            referenced,
        ),
        supervisor_fd_entry_restore_action_skip() as i32
    );
    assert_eq!(
        supervisor_ofd_slot_restore_action(
            high_ofd,
            FD_TYPE_FILE,
            high_host_fd,
            high_ino,
            64,
            u64::MAX,
            referenced | trusted,
        ),
        supervisor_fd_entry_restore_action_apply() as i32
    );
}

#[test]
fn supervisor_fork_shared_ofd_identity_and_publish_policy_are_kernel_owned() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    let file_fd = t.sys_openat(b"/fork-shared-policy", O_CREAT | O_RDWR);
    assert!(file_fd >= 3);
    let file_ofd = process_fd_ofd_id(vm_ptr, file_fd as u32);
    assert_ne!(file_ofd, 0);
    assert_eq!(
        supervisor_process_holds_regular_file_ofd(vm_ptr, file_ofd),
        1
    );
    assert_eq!(supervisor_ofd_is_regular_file(file_ofd), 1);
    assert_eq!(supervisor_pipe_sync_ofd_candidate(file_ofd), 0);
    assert_eq!(supervisor_fork_shared_held_ofd_track_action(file_ofd, 0), 0);
    assert_eq!(
        supervisor_fork_shared_held_ofd_track_action(
            file_ofd,
            supervisor_fork_shared_held_ofd_track_flag_shared()
        ),
        1
    );
    assert_eq!(
        supervisor_fork_shared_held_ofd_track_action(
            file_ofd,
            supervisor_fork_shared_held_ofd_track_flag_stdio_fd()
        ),
        1
    );
    assert_eq!(
        supervisor_fork_shared_held_ofd_track_action(
            file_ofd,
            supervisor_fork_shared_held_ofd_track_flag_fd_entry_source()
        ),
        1
    );
    let file_key = supervisor_fork_shared_ofd_identity_key(file_ofd);
    assert_ne!(file_key, 0);
    assert_eq!(supervisor_fork_shared_ofd_publish_action(file_ofd, 0), 0);
    assert_eq!(
        supervisor_fork_shared_ofd_publish_action(
            file_ofd,
            supervisor_fork_shared_peer_flag_compatible(),
        ),
        1
    );
    assert_eq!(
        supervisor_fork_shared_ofd_publish_action(
            file_ofd,
            supervisor_fork_shared_peer_flag_compatible()
                | supervisor_fork_shared_peer_flag_incompatible(),
        ),
        0
    );

    let pipefd_addr = 0x2200;
    assert_eq!(
        tidemark_kernel::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
        0
    );
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) };
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) };
    let read_ofd = process_fd_ofd_id(vm_ptr, read_fd);
    let write_ofd = process_fd_ofd_id(vm_ptr, write_fd);
    assert_ne!(read_ofd, 0);
    assert_ne!(write_ofd, 0);
    assert_eq!(
        supervisor_process_holds_regular_file_ofd(vm_ptr, read_ofd),
        0
    );
    assert_eq!(supervisor_ofd_is_regular_file(read_ofd), 0);
    assert_eq!(supervisor_pipe_sync_ofd_candidate(read_ofd), 1);
    assert_eq!(supervisor_fork_shared_held_ofd_track_action(read_ofd, 0), 1);
    assert_eq!(
        supervisor_fork_shared_held_ofd_track_action(
            read_ofd,
            supervisor_fork_shared_held_ofd_track_flag_host_stdio_pipe()
        ),
        0
    );
    assert_eq!(
        supervisor_fork_shared_held_ofd_track_action(
            read_ofd,
            supervisor_fork_shared_held_ofd_track_flag_host_stdio_pipe()
                | supervisor_fork_shared_held_ofd_track_flag_fd_entry_source()
        ),
        0
    );
    let read_key = supervisor_fork_shared_ofd_identity_key(read_ofd);
    let write_key = supervisor_fork_shared_ofd_identity_key(write_ofd);
    assert_ne!(read_key, 0);
    assert_ne!(write_key, 0);
    assert_ne!(read_key, write_key);
    assert_eq!(supervisor_fork_shared_ofd_publish_action(read_ofd, 0), 0);
    assert_eq!(
        supervisor_fork_shared_ofd_publish_action(
            read_ofd,
            supervisor_fork_shared_peer_flag_pipe_peer(),
        ),
        1
    );
    assert_eq!(
        supervisor_fork_shared_ofd_publish_action(
            read_ofd,
            supervisor_fork_shared_peer_flag_incompatible()
                | supervisor_fork_shared_peer_flag_pipe_peer(),
        ),
        0
    );
}

#[test]
fn supervisor_fork_shared_effect_sync_action_is_kernel_owned() {
    assert_eq!(supervisor_fork_shared_effect_sync_action(0, 1, 0, 0), 0);
    assert_eq!(supervisor_fork_shared_effect_sync_action(1, 0, 0, 0), 0);
    assert_eq!(supervisor_fork_shared_effect_sync_action(1, 1, 0, 0), 1);
    assert_eq!(supervisor_fork_shared_effect_sync_action(1, 1, 1, 0), 0);
    assert_eq!(supervisor_fork_shared_effect_sync_action(1, 1, 1, 1), 1);
}

#[test]
fn supervisor_fork_shared_sync_planning_actions_are_kernel_owned() {
    assert_eq!(
        supervisor_fork_shared_sync_target_action(0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0),
        supervisor_fork_shared_sync_target_action_use()
    );
    assert_eq!(
        supervisor_fork_shared_sync_target_action(0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0),
        supervisor_fork_shared_sync_target_action_defer()
    );
    assert_eq!(
        supervisor_fork_shared_sync_target_action(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0),
        supervisor_fork_shared_sync_target_action_defer()
    );
    assert_eq!(
        supervisor_fork_shared_sync_target_action(0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0),
        supervisor_fork_shared_sync_target_action_reject()
    );
    assert_eq!(
        supervisor_fork_shared_sync_target_action(0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1),
        supervisor_fork_shared_sync_target_action_reject()
    );

    assert_eq!(
        supervisor_fork_shared_syncable_ofd_action(1, 0, 1, 0, 0, 0),
        supervisor_fork_shared_ofd_action_include()
    );
    assert_eq!(
        supervisor_fork_shared_syncable_ofd_action(1, 1, 1, 0, 0, 0),
        0
    );
    assert_eq!(
        supervisor_fork_shared_syncable_ofd_action(1, 0, 1, 1, 0, 0),
        0
    );
    assert_eq!(
        supervisor_fork_shared_syncable_ofd_action(1, 0, 1, 1, 1, 0),
        supervisor_fork_shared_ofd_action_include()
    );
    assert_eq!(
        supervisor_fork_shared_syncable_ofd_action(1, 0, 1, 0, 0, 1),
        0
    );

    assert_eq!(
        supervisor_fork_shared_delta_source_ofd_action(1, 1, 0, 0),
        supervisor_fork_shared_ofd_action_include()
    );
    assert_eq!(
        supervisor_fork_shared_delta_source_ofd_action(1, 0, 1, 1),
        supervisor_fork_shared_ofd_action_include()
            | supervisor_fork_shared_ofd_action_add_shared()
    );
    assert_eq!(
        supervisor_fork_shared_delta_source_ofd_action(0, 1, 1, 1),
        0
    );

    assert_eq!(
        supervisor_fork_shared_tracked_source_ofd_action(1, 0, 1, 0, 0),
        supervisor_fork_shared_ofd_action_include()
    );
    assert_eq!(
        supervisor_fork_shared_tracked_source_ofd_action(1, 0, 1, 0, 1),
        0
    );
    assert_eq!(
        supervisor_fork_shared_tracked_source_ofd_action(0, 1, 1, 0, 1),
        supervisor_fork_shared_ofd_action_include()
    );

    assert_eq!(
        supervisor_fork_shared_pipe_peer_ofd_action(0, 1),
        supervisor_fork_shared_ofd_action_include()
            | supervisor_fork_shared_ofd_action_add_shared()
    );
    assert_eq!(supervisor_fork_shared_pipe_peer_ofd_action(1, 1), 0);
    assert_eq!(
        supervisor_fork_shared_rehydrate_ofd_action(1, 0, 1),
        supervisor_fork_shared_ofd_action_rehydrate()
    );
    assert_eq!(supervisor_fork_shared_rehydrate_ofd_action(1, 1, 1), 0);
}
