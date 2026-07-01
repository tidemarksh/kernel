use super::support::*;

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
fn supervisor_shadow_exports_are_additive_and_deterministic() {
    supervisor_reset_shadow_log();

    assert_eq!(supervisor_abi_version(), 1);
    assert_eq!(supervisor_debug_snapshot_bytes(), 112);
    assert_eq!(supervisor_debug_snapshot(0, 0), 112);
    assert_eq!(supervisor_thread_event_record_bytes(), 80);
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
    assert_eq!(
        supervisor_thread_state_snapshot(0, 0, 0),
        supervisor_thread_state_snapshot_bytes() as i32
    );
    assert_eq!(supervisor_runnable_selection_bytes(), 48);
    assert_eq!(
        supervisor_select_runnable(0, 0, 0, 0, 0),
        supervisor_runnable_selection_bytes() as i32
    );
    assert_eq!(supervisor_host_op_record_bytes(), 64);
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
    assert_eq!(supervisor_host_completion_record_bytes(), 64);
    assert_eq!(supervisor_host_completion_outcome_success(), 1);
    assert_eq!(supervisor_host_completion_outcome_failure(), 2);
    assert_eq!(supervisor_process_host_op_record_bytes(), 96);
    assert_eq!(supervisor_process_host_op_kind_spawn_process_worker(), 1);
    assert_eq!(supervisor_fault_exit_decision_bytes(), 88);
    assert_eq!(supervisor_fault_exit_kind_thread_exit(), 1);
    assert_eq!(supervisor_fault_exit_kind_process_exit(), 2);
    assert_eq!(supervisor_thread_exit_cleanup_record_bytes(), 96);
    assert_eq!(supervisor_thread_exit_cleanup_kind_thread_exit(), 1);
    assert_eq!(supervisor_process_lifecycle_record_bytes(), 96);
    assert_eq!(supervisor_process_lifecycle_kind_child_exit_published(), 1);
    assert_eq!(supervisor_process_lifecycle_kind_wait4_completed(), 2);
    assert_eq!(supervisor_fd_control_record_bytes(), 96);
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
    assert_eq!(supervisor_fs_control_record_bytes(), 112);
    assert_eq!(supervisor_fs_control_record(0, 0), 112);
    assert_eq!(supervisor_fs_control_kind_page_cache_miss(), 1);
    assert_eq!(supervisor_fs_control_kind_page_cache_fill(), 2);
    assert_eq!(supervisor_fs_control_kind_dirty_page_published(), 3);
    assert_eq!(supervisor_fs_control_kind_dirty_page_flushed(), 4);
    assert_eq!(supervisor_signal_control_record_bytes(), 120);
    assert_eq!(supervisor_signal_control_record(0, 0), 120);
    assert_eq!(supervisor_signal_control_kind_boundary_check(), 1);
    assert_eq!(supervisor_signal_control_kind_signal_delivered(), 2);
    assert_eq!(supervisor_signal_control_kind_blocked_wait_interrupted(), 3);

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

#[test]
fn supervisor_shadow_rejects_non_empty_null_records() {
    supervisor_reset_shadow_log();

    assert_eq!(supervisor_submit_thread_event(0, 1), EFAULT as i32);
    assert_eq!(supervisor_complete_host_op(0, 1), EFAULT as i32);
    assert_eq!(supervisor_process_host_op(0, 0, 1), EFAULT as i32);
    assert_eq!(supervisor_shadow_thread_event_count(), 0);
    assert_eq!(supervisor_shadow_host_completion_count(), 0);
}
