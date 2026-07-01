pub(super) fn complete_arm_host_timer(parent_vm_ptr: u32, deadline_ticks: u64) -> i32 {
    if parent_vm_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    let vm = unsafe { &mut *(parent_vm_ptr as *mut crate::types::ThreadState) };
    match vm.status {
        crate::abi::STATUS_SLEEP => {
            crate::syscall::time::sync_monotonic_ticks_floor(deadline_ticks);
            vm.fault_addr = 0;
            vm.fault_pc = 0;
            vm.status = crate::abi::STATUS_OK;
            super::resume::enqueue_runnable_thread(vm);
            crate::abi::STATUS_OK
        }
        crate::abi::STATUS_FUTEX_WAIT => super::futex::complete_wait(
            parent_vm_ptr,
            super::SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT,
        ),
        _ => vm.status,
    }
}

pub(super) fn enqueue_futex_wait_timer(vm: &crate::types::ThreadState) -> bool {
    if vm.futex_wait_timeout == 0 {
        return false;
    }
    let delay_ticks = crate::syscall::time::timeout_timespec_delta_ticks(
        vm.guest_base,
        vm.futex_wait_timeout,
        vm.futex_wait_absolute != 0,
        (vm.futex_wait_flags & crate::abi::FUTEX_CLOCK_REALTIME) != 0,
    )
    .unwrap_or(0);
    let delay_ms = crate::syscall::time::ticks_to_millis_ceil(delay_ticks);
    super::host_op::push_request(super::SupervisorHostOpRequest {
        kind: super::SUPERVISOR_HOST_OP_KIND_ARM_HOST_TIMER,
        parent_vm_ptr: vm as *const crate::types::ThreadState as u32,
        child_vm_ptr: 0,
        tid: vm.tid as u32,
        process_ptr: vm.process_ptr,
        status: vm.status as u32,
        detail0: delay_ms,
        detail1: delay_ticks,
    })
}

pub(super) fn enqueue_sleep_timer(vm: &crate::types::ThreadState) -> bool {
    if vm.fault_addr == 0 && vm.fault_pc == 0 {
        return false;
    }
    let deadline_ticks = crate::syscall::time::sleep_deadline_ticks(vm.fault_addr, vm.fault_pc);
    let delay_ticks =
        deadline_ticks.saturating_sub(crate::syscall::time::monotonic_ticks_current());
    let delay_ms = crate::syscall::time::ticks_to_millis_ceil(delay_ticks);
    super::host_op::push_request(super::SupervisorHostOpRequest {
        kind: super::SUPERVISOR_HOST_OP_KIND_ARM_HOST_TIMER,
        parent_vm_ptr: vm as *const crate::types::ThreadState as u32,
        child_vm_ptr: 0,
        tid: vm.tid as u32,
        process_ptr: vm.process_ptr,
        status: vm.status as u32,
        detail0: delay_ms,
        detail1: deadline_ticks,
    })
}
