pub(super) const STDIO_OUTPUT_SETTLE_KIND_VISIBLE: u32 = 1;
pub(super) const STDIO_OUTPUT_SETTLE_KIND_INHERITED_CHILD: u32 = 2;

pub(super) const STDIO_PIPE_READ_PROGRESS_ACTION_NONE: u32 = 0;
pub(super) const STDIO_PIPE_READ_PROGRESS_ACTION_SNAPSHOT: u32 = 1;

pub(super) fn output_settle_kind_visible() -> u32 {
    STDIO_OUTPUT_SETTLE_KIND_VISIBLE
}

pub(super) fn output_settle_kind_inherited_child() -> u32 {
    STDIO_OUTPUT_SETTLE_KIND_INHERITED_CHILD
}

pub(super) fn pipe_read_progress_action_none() -> u32 {
    STDIO_PIPE_READ_PROGRESS_ACTION_NONE
}

pub(super) fn pipe_read_progress_action_snapshot() -> u32 {
    STDIO_PIPE_READ_PROGRESS_ACTION_SNAPSHOT
}

pub(super) fn output_settle_max_passes(kind: u32) -> i32 {
    match kind {
        STDIO_OUTPUT_SETTLE_KIND_VISIBLE => 4,
        STDIO_OUTPUT_SETTLE_KIND_INHERITED_CHILD => 6,
        _ => -(crate::abi::EINVAL as i32),
    }
}

pub(super) fn output_settle_stable_passes(kind: u32) -> i32 {
    match kind {
        STDIO_OUTPUT_SETTLE_KIND_VISIBLE | STDIO_OUTPUT_SETTLE_KIND_INHERITED_CHILD => 2,
        _ => -(crate::abi::EINVAL as i32),
    }
}

pub(super) fn pipe_read_progress_action(vm_ptr: u32, pipe_slot: u32, drained: u32) -> i32 {
    if drained == 0 {
        return STDIO_PIPE_READ_PROGRESS_ACTION_NONE as i32;
    }
    let Some(_) = super::fd::process_state_from_vm_ptr(vm_ptr) else {
        return -(crate::abi::EFAULT as i32);
    };
    let mode = super::pipe::process_private_pipe_target_mode(vm_ptr, pipe_slot)
        | super::pipe::process_pipe_slot_mode(vm_ptr, pipe_slot);
    if (mode & super::SUPERVISOR_PIPE_SLOT_MODE_READ) == 0 {
        return STDIO_PIPE_READ_PROGRESS_ACTION_NONE as i32;
    }
    STDIO_PIPE_READ_PROGRESS_ACTION_SNAPSHOT as i32
}
