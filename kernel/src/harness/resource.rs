#[derive(Clone, Copy)]
pub(crate) struct ProcessResourceSnapshot {
    state: crate::syscall::resource::ProcessResourceStateImage,
}

impl ProcessResourceSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            state: crate::syscall::resource::ProcessResourceStateImage::empty(),
        }
    }
}

pub(crate) fn snapshot_process_context_into(snapshot: &mut ProcessResourceSnapshot) {
    crate::syscall::resource::capture_process_resource_state_into(&mut snapshot.state);
}

pub(crate) fn restore_process_context(snapshot: &ProcessResourceSnapshot) {
    crate::syscall::resource::restore_process_resource_state_from(&snapshot.state);
}
