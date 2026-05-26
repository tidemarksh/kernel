pub(crate) fn record_sync_signal_trace(
    vm: &crate::types::ThreadState,
    local_pc: u64,
    local_ra: u64,
    local_sp: u64,
    local_s11: u64,
    local_a0: u64,
    fault_addr: u64,
) {
    let _ = (
        vm, local_pc, local_ra, local_sp, local_s11, local_a0, fault_addr,
    );
}
