const SNAPSHOT_MAGIC: u32 = 0x5055_5354; // "TSUP" little-endian.

fn write_base_snapshot(snapshot: &mut [u8], snapshot_bytes: u32) {
    super::write_u32(snapshot, 0, SNAPSHOT_MAGIC);
    super::write_u32(snapshot, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(snapshot, 8, snapshot_bytes);
    super::write_u32(snapshot, 12, 0);
    super::write_u64(snapshot, 16, super::thread_event_count());
    super::write_u64(snapshot, 24, super::host_completion_count());
    super::write_u64(snapshot, 32, super::host_op_poll_count());
    super::write_u64(snapshot, 40, super::resume_poll_count());
    super::write_u64(snapshot, 48, super::thread_event_log_hash());
    super::write_u64(snapshot, 56, super::host_completion_log_hash());
    super::write_u32(snapshot, 64, super::log::last_thread_event_len());
    super::write_u32(snapshot, 68, super::log::last_host_completion_len());
    super::write_u64(snapshot, 72, super::log::last_thread_event_hash());
    super::write_u64(snapshot, 80, super::log::last_host_completion_hash());
    super::write_u64(snapshot, 88, super::host_op_log_hash());
    super::write_u64(snapshot, 96, super::log::last_host_op_hash());
    super::write_u32(snapshot, 104, super::log::last_host_op_len());
    super::write_u32(snapshot, 108, 0);
}

fn write_replay_snapshot(snapshot: &mut [u8]) {
    let mut entries =
        [super::log::ReplayLogEntry::empty(); super::SUPERVISOR_REPLAY_LOG_CAPACITY as usize];
    let replay_count = super::log::copy_replay_log_entries(&mut entries);

    super::write_u32(
        snapshot,
        super::SUPERVISOR_DEBUG_BASE_SNAPSHOT_BYTES as usize,
        super::SUPERVISOR_REPLAY_LOG_RECORD_BYTES,
    );
    super::write_u32(
        snapshot,
        super::SUPERVISOR_DEBUG_BASE_SNAPSHOT_BYTES as usize + 4,
        super::SUPERVISOR_REPLAY_LOG_PAYLOAD_BYTES,
    );
    super::write_u32(
        snapshot,
        super::SUPERVISOR_DEBUG_BASE_SNAPSHOT_BYTES as usize + 8,
        super::SUPERVISOR_REPLAY_LOG_CAPACITY,
    );
    super::write_u32(
        snapshot,
        super::SUPERVISOR_DEBUG_BASE_SNAPSHOT_BYTES as usize + 12,
        replay_count,
    );
    super::write_u64(
        snapshot,
        super::SUPERVISOR_DEBUG_BASE_SNAPSHOT_BYTES as usize + 16,
        super::log::replay_log_total_count(),
    );
    super::write_u64(
        snapshot,
        super::SUPERVISOR_DEBUG_BASE_SNAPSHOT_BYTES as usize + 24,
        0,
    );

    for (idx, entry) in entries.iter().take(replay_count as usize).enumerate() {
        let offset = super::SUPERVISOR_DEBUG_REPLAY_OFFSET as usize
            + idx * super::SUPERVISOR_REPLAY_LOG_RECORD_BYTES as usize;
        super::write_u32(snapshot, offset, entry.source);
        super::write_u32(snapshot, offset + 4, entry.payload_len);
        super::write_u64(snapshot, offset + 8, entry.log_seq);
        super::write_u64(snapshot, offset + 16, entry.record_seq);
        super::write_u64(snapshot, offset + 24, entry.entry_hash);
        let payload_len = entry
            .payload_len
            .min(super::SUPERVISOR_REPLAY_LOG_PAYLOAD_BYTES);
        snapshot[offset + 32..offset + 32 + payload_len as usize]
            .copy_from_slice(&entry.payload[..payload_len as usize]);
    }
}

pub(super) fn write_snapshot(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }

    let copy_len = if out_len >= super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES {
        super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES
    } else if out_len >= super::SUPERVISOR_DEBUG_BASE_SNAPSHOT_BYTES {
        super::SUPERVISOR_DEBUG_BASE_SNAPSHOT_BYTES
    } else {
        return crate::abi::ENOSPC as i32;
    };

    let mut snapshot = [0u8; super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES as usize];
    write_base_snapshot(&mut snapshot, copy_len);
    if copy_len == super::SUPERVISOR_DEBUG_SNAPSHOT_BYTES {
        write_replay_snapshot(&mut snapshot);
    }

    let out =
        unsafe { core::slice::from_raw_parts_mut(out_ptr as usize as *mut u8, copy_len as usize) };
    out.copy_from_slice(&snapshot[..copy_len as usize]);
    copy_len as i32
}
