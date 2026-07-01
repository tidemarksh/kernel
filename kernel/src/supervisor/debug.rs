const SNAPSHOT_MAGIC: u32 = 0x5055_5354; // "TSUP" little-endian.

pub(super) fn write_snapshot(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES {
        return crate::abi::ENOSPC as i32;
    }

    let mut snapshot = [0u8; super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES as usize];
    super::write_u32(&mut snapshot, 0, SNAPSHOT_MAGIC);
    super::write_u32(&mut snapshot, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut snapshot, 8, super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES);
    super::write_u32(&mut snapshot, 12, 0);
    super::write_u64(&mut snapshot, 16, super::thread_event_count());
    super::write_u64(&mut snapshot, 24, super::host_completion_count());
    super::write_u64(&mut snapshot, 32, super::host_op_poll_count());
    super::write_u64(&mut snapshot, 40, super::resume_poll_count());
    super::write_u64(&mut snapshot, 48, super::thread_event_log_hash());
    super::write_u64(&mut snapshot, 56, super::host_completion_log_hash());
    super::write_u32(&mut snapshot, 64, super::log::last_thread_event_len());
    super::write_u32(&mut snapshot, 68, super::log::last_host_completion_len());
    super::write_u64(&mut snapshot, 72, super::log::last_thread_event_hash());
    super::write_u64(&mut snapshot, 80, super::log::last_host_completion_hash());
    super::write_u64(&mut snapshot, 88, super::host_op_log_hash());
    super::write_u64(&mut snapshot, 96, super::log::last_host_op_hash());
    super::write_u32(&mut snapshot, 104, super::log::last_host_op_len());
    super::write_u32(&mut snapshot, 108, 0);

    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES as usize,
        )
    };
    out.copy_from_slice(&snapshot);
    super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES as i32
}
