pub(super) fn validated_thread_from_record(
    record: &crate::types::ThreadRecord,
    base: u32,
    process_ptr: u32,
) -> Option<&'static crate::types::ThreadState> {
    let thread = super::thread_state_from_ptr(record.thread_ptr)?;
    if thread.guest_base != base || thread.process_ptr != process_ptr || thread.tid != record.tid {
        return None;
    }
    Some(thread)
}

pub(super) fn validated_thread_status_from_record(
    record: &crate::types::ThreadRecord,
    base: u32,
    process_ptr: u32,
) -> Option<u32> {
    validated_thread_from_record(record, base, process_ptr).map(|thread| thread.status as u32)
}
