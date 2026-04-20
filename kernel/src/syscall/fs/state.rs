use crate::types::{ProcessState, ThreadState};

fn process_state(base: u32, vm: &ThreadState) -> Option<&'static mut ProcessState> {
    let ptr = (base as u64 + vm.process_ptr as u64) as *mut ProcessState;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &mut *ptr })
    }
}

pub(super) fn current_dir_ino(base: u32, vm: &ThreadState) -> u32 {
    match process_state(base, vm) {
        Some(ps) if ps.cwd_ino != 0 => ps.cwd_ino,
        _ => 1,
    }
}

pub(super) fn process_fs_ring_base(base: u32, vm: &ThreadState) -> u32 {
    process_state(base, vm)
        .map(|ps| ps.fs_ring_base)
        .unwrap_or(0)
}

pub(super) fn set_current_dir_ino(base: u32, vm: &ThreadState, ino: u32) {
    if let Some(ps) = process_state(base, vm) {
        ps.cwd_ino = ino;
    }
}
