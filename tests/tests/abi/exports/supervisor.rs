use super::support::*;

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

#[test]
fn supervisor_shadow_exports_are_additive_and_deterministic() {
    supervisor_reset_shadow_log();

    assert_eq!(supervisor_abi_version(), 1);
    assert_eq!(supervisor_debug_snapshot_bytes(), 88);
    assert_eq!(supervisor_debug_snapshot(0, 0), 88);
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
    assert_eq!(supervisor_fault_exit_decision_bytes(), 88);
    assert_eq!(supervisor_fault_exit_kind_thread_exit(), 1);
    assert_eq!(supervisor_fault_exit_kind_process_exit(), 2);

    let empty_hash = supervisor_shadow_thread_event_log_hash();
    assert_eq!(supervisor_shadow_thread_event_count(), 0);
    assert_eq!(supervisor_submit_thread_event(0, 0), 0);
    assert_eq!(supervisor_shadow_thread_event_count(), 1);
    assert_ne!(supervisor_shadow_thread_event_log_hash(), empty_hash);

    assert_eq!(supervisor_shadow_host_completion_count(), 0);
    assert_eq!(supervisor_complete_host_op(0, 0), 0);
    assert_eq!(supervisor_shadow_host_completion_count(), 1);

    assert_eq!(supervisor_next_host_op(0, 0), 0);
    assert_eq!(supervisor_shadow_host_op_poll_count(), 1);
    assert_eq!(supervisor_shadow_host_op_emit_count(), 0);
    assert_eq!(supervisor_shadow_host_op_overflow_count(), 0);
    assert_eq!(supervisor_next_resume(0, 0), 0);
    assert_eq!(supervisor_shadow_resume_poll_count(), 1);

    let mut snapshot = [0u8; 88];
    assert_eq!(
        supervisor_debug_snapshot(snapshot.as_mut_ptr() as u32, snapshot.len() as u32),
        88
    );
    assert_eq!(read_u32_le(&snapshot, 0), 0x5055_5354);
    assert_eq!(read_u32_le(&snapshot, 4), 1);
    assert_eq!(read_u32_le(&snapshot, 8), 88);
    assert_eq!(read_u32_le(&snapshot, 12), 0);
    assert_eq!(read_u64_le(&snapshot, 16), 1);
    assert_eq!(read_u64_le(&snapshot, 24), 1);
    assert_eq!(read_u64_le(&snapshot, 32), 1);
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

    let mut too_small = [0u8; 87];
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
    assert_eq!(supervisor_shadow_thread_event_count(), 0);
    assert_eq!(supervisor_shadow_host_completion_count(), 0);
}
