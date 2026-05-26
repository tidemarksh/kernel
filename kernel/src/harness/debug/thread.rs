pub(crate) fn record_thread_count(
    kind: u32,
    vm_ptr: u32,
    tid: i32,
    process_ptr: u32,
    before: u32,
    after: u32,
) {
    let _ = (kind, vm_ptr, tid, process_ptr, before, after);
}

pub(crate) fn record_futex_resume_trace(vm: &crate::types::ThreadState, phase: u32) {
    let _ = (vm, phase);
}
