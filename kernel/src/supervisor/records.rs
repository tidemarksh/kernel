#[derive(Clone, Copy)]
pub(super) struct SupervisorResumeRecord {
    pub(super) kind: u32,
    pub(super) seq: u64,
    pub(super) vm_ptr: u32,
    pub(super) tid: u32,
    pub(super) process_ptr: u32,
    pub(super) status: u32,
    pub(super) detail0: u64,
}

#[derive(Clone, Copy)]
pub(super) struct SupervisorHostOpRequest {
    pub(super) kind: u32,
    pub(super) parent_vm_ptr: u32,
    pub(super) child_vm_ptr: u32,
    pub(super) tid: u32,
    pub(super) process_ptr: u32,
    pub(super) status: u32,
    pub(super) detail0: u64,
    pub(super) detail1: u64,
}

#[derive(Clone, Copy)]
pub(super) struct SupervisorHostOpRecord {
    pub(super) kind: u32,
    pub(super) seq: u64,
    pub(super) parent_vm_ptr: u32,
    pub(super) child_vm_ptr: u32,
    pub(super) tid: u32,
    pub(super) process_ptr: u32,
    pub(super) status: u32,
    pub(super) flags: u64,
    pub(super) child_tidptr: u64,
}

#[derive(Clone, Copy)]
pub(super) struct SupervisorProcessHostOpRecord {
    pub(super) kind: u32,
    pub(super) seq: u64,
    pub(super) log_emission: bool,
    pub(super) parent_vm_ptr: u32,
    pub(super) spawn_kind: u32,
    pub(super) child_pid: i32,
    pub(super) process_ptr: u32,
    pub(super) status: u32,
    pub(super) address_profile: u32,
    pub(super) guest_memory_policy_limit: u64,
    pub(super) process_max_memory_pages: u32,
    pub(super) path: u64,
    pub(super) argv: u64,
    pub(super) envp: u64,
}

#[derive(Clone, Copy)]
pub(super) struct SupervisorFaultExitDecision {
    pub(super) kind: u32,
    pub(super) seq: u64,
    pub(super) vm_ptr: u32,
    pub(super) exit_vm_ptr: u32,
    pub(super) tid: u32,
    pub(super) process_ptr: u32,
    pub(super) remaining_threads: u32,
    pub(super) live_threads: u32,
    pub(super) exit_code: i32,
    pub(super) term_signal: i32,
    pub(super) status: u32,
    pub(super) fault_signal: u32,
    pub(super) fault_kind: u32,
    pub(super) fault_pc: u64,
    pub(super) fault_addr: u64,
}

#[derive(Clone, Copy)]
pub struct SupervisorThreadExitCleanupRecord {
    pub(super) kind: u32,
    pub(super) seq: u64,
    pub(super) vm_ptr: u32,
    pub(super) tid: u32,
    pub(super) process_ptr: u32,
    pub(super) status: u32,
    pub(super) robust_marked: u32,
    pub(super) robust_woken: u32,
    pub(super) clear_child_tid_woken: u32,
    pub(super) robust_order: u32,
    pub(super) clear_child_tid_order: u32,
    pub(super) clear_child_tid: u64,
    pub(super) robust_head: u64,
    pub(super) robust_pending: u64,
    pub(super) first_robust_futex_addr: u64,
}

impl SupervisorThreadExitCleanupRecord {
    pub(super) const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            tid: 0,
            process_ptr: 0,
            status: 0,
            robust_marked: 0,
            robust_woken: 0,
            clear_child_tid_woken: 0,
            robust_order: 0,
            clear_child_tid_order: 0,
            clear_child_tid: 0,
            robust_head: 0,
            robust_pending: 0,
            first_robust_futex_addr: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SupervisorProcessLifecycleRecord {
    pub(super) kind: u32,
    pub(super) seq: u64,
    pub(super) vm_ptr: u32,
    pub(super) parent_pid: u32,
    pub(super) child_pid: u32,
    pub(super) wait_status: u32,
    pub(super) wait_kind: u32,
    pub(super) vm_status: u32,
    pub(super) result: i64,
    pub(super) wait_target: i64,
    pub(super) options: u64,
    pub(super) wstatus_addr: u64,
    pub(super) rusage_addr: u64,
    pub(super) detail: u64,
}

impl SupervisorProcessLifecycleRecord {
    pub(super) const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            parent_pid: 0,
            child_pid: 0,
            wait_status: 0,
            wait_kind: 0,
            vm_status: 0,
            result: 0,
            wait_target: 0,
            options: 0,
            wstatus_addr: 0,
            rusage_addr: 0,
            detail: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SupervisorFdControlRecord {
    pub(super) kind: u32,
    pub(super) seq: u64,
    pub(super) vm_ptr: u32,
    pub(super) process_ptr: u32,
    pub(super) pid: u32,
    pub(super) fd: u32,
    pub(super) fd2: u32,
    pub(super) ofd_id: u32,
    pub(super) ofd2_id: u32,
    pub(super) fd_type: u32,
    pub(super) resource_slot: u32,
    pub(super) resource_generation: u32,
    pub(super) result: i64,
    pub(super) flags: u64,
    pub(super) detail0: u64,
    pub(super) detail1: u64,
}

impl SupervisorFdControlRecord {
    pub(super) const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            process_ptr: 0,
            pid: 0,
            fd: 0,
            fd2: 0,
            ofd_id: 0,
            ofd2_id: 0,
            fd_type: 0,
            resource_slot: 0,
            resource_generation: 0,
            result: 0,
            flags: 0,
            detail0: 0,
            detail1: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SupervisorFsControlRecord {
    pub(super) kind: u32,
    pub(super) seq: u64,
    pub(super) vm_ptr: u32,
    pub(super) process_ptr: u32,
    pub(super) pid: u32,
    pub(super) fd: u32,
    pub(super) ino: u32,
    pub(super) opcode: u32,
    pub(super) file_object_id: u64,
    pub(super) page_index: u64,
    pub(super) offset: u64,
    pub(super) length: u64,
    pub(super) result: i64,
    pub(super) flags: u64,
    pub(super) detail0: u64,
    pub(super) detail1: u64,
}

impl SupervisorFsControlRecord {
    pub(super) const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            process_ptr: 0,
            pid: 0,
            fd: 0,
            ino: 0,
            opcode: 0,
            file_object_id: 0,
            page_index: 0,
            offset: 0,
            length: 0,
            result: 0,
            flags: 0,
            detail0: 0,
            detail1: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SupervisorSignalControlRecord {
    pub(super) kind: u32,
    pub(super) seq: u64,
    pub(super) vm_ptr: u32,
    pub(super) process_ptr: u32,
    pub(super) pid: u32,
    pub(super) tid: u32,
    pub(super) sig: u32,
    pub(super) status: u32,
    pub(super) sig_info_code: i32,
    pub(super) boundary: u32,
    pub(super) thread_pending: u64,
    pub(super) process_pending: u64,
    pub(super) record_pending: u64,
    pub(super) deliverable: u64,
    pub(super) mask: u64,
    pub(super) pc: u64,
    pub(super) detail0: u64,
    pub(super) detail1: u64,
}

impl SupervisorSignalControlRecord {
    pub(super) const fn empty() -> Self {
        Self {
            kind: 0,
            seq: 0,
            vm_ptr: 0,
            process_ptr: 0,
            pid: 0,
            tid: 0,
            sig: 0,
            status: 0,
            sig_info_code: 0,
            boundary: 0,
            thread_pending: 0,
            process_pending: 0,
            record_pending: 0,
            deliverable: 0,
            mask: 0,
            pc: 0,
            detail0: 0,
            detail1: 0,
        }
    }
}
