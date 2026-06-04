use crate::types::{ProcessState, ThreadState};

const DEFAULT_UMASK: u32 = 0o022;

fn process_state(base: u32, vm: &ThreadState) -> Option<&'static mut ProcessState> {
    if !crate::syscall::memory::guest_range_accessible(
        base,
        vm.process_ptr as u64,
        core::mem::size_of::<ProcessState>() as u64,
    ) {
        return None;
    }
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
    let ring_base = process_state(base, vm)
        .map(|ps| ps.fs_ring_base)
        .unwrap_or(0);
    if crate::fs::ring_buffer::ring_backed(ring_base) {
        ring_base
    } else {
        0
    }
}

pub(super) fn set_current_dir_ino(base: u32, vm: &ThreadState, ino: u32) {
    if let Some(ps) = process_state(base, vm) {
        ps.cwd_ino = ino;
    }
}

pub(super) fn current_umask(base: u32, vm: &ThreadState) -> u32 {
    process_state(base, vm)
        .map(|ps| ps.umask & 0o777)
        .unwrap_or(DEFAULT_UMASK)
}

pub(super) fn apply_umask(base: u32, vm: &ThreadState, mode: u32) -> u32 {
    mode & !current_umask(base, vm)
}

pub(crate) fn sys_umask(vm: &mut ThreadState, base: u32, mask: u64) -> i64 {
    let Some(ps) = process_state(base, vm) else {
        return crate::abi::ESRCH;
    };
    let previous = ps.umask & 0o777;
    ps.umask = (mask as u32) & 0o777;
    previous as i64
}
