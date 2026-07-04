use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static PROCESS_LIFECYCLE_COUNT: AtomicU64 = AtomicU64::new(0);
static PROCESS_LIFECYCLE_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_PROCESS_LIFECYCLE: super::SupervisorProcessLifecycleRecord =
    super::SupervisorProcessLifecycleRecord::empty();

pub(super) fn init() {
    PROCESS_LIFECYCLE_COUNT.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&PROCESS_LIFECYCLE_LOCK, || unsafe {
        LAST_PROCESS_LIFECYCLE = super::SupervisorProcessLifecycleRecord::empty();
    });
}

pub fn process_lifecycle_count() -> u64 {
    PROCESS_LIFECYCLE_COUNT.load(Ordering::Relaxed)
}

pub(super) fn status_is_lifecycle_handoff(status: i32) -> i32 {
    i32::from(matches!(
        status,
        crate::abi::STATUS_VFORK_WAIT
            | crate::abi::STATUS_EXECVE_SPAWN
            | crate::abi::STATUS_CLONE_SPAWN
    ))
}

pub(super) fn status_is_execve_spawn(status: i32) -> i32 {
    i32::from(status == crate::abi::STATUS_EXECVE_SPAWN)
}

pub(super) fn status_is_clone_spawn(status: i32) -> i32 {
    i32::from(status == crate::abi::STATUS_CLONE_SPAWN)
}

pub(super) fn status_is_vfork_wait(status: i32) -> i32 {
    i32::from(status == crate::abi::STATUS_VFORK_WAIT)
}

pub(super) fn status_allows_pid_mismatch(status: i32) -> i32 {
    i32::from(matches!(
        status,
        crate::abi::STATUS_VFORK_WAIT | crate::abi::STATUS_EXECVE_SPAWN
    ))
}

pub(super) fn status_defers_kernel_state_adoption(status: i32) -> i32 {
    i32::from(status == crate::abi::STATUS_CLONE_SPAWN)
}

pub(super) fn vfork_child_owner_mismatch(vm_ptr: u32, runtime_pid: i32) -> i32 {
    if vm_ptr == 0 || runtime_pid <= 0 || !crate::syscall::process::vfork_active() {
        return 0;
    }
    let child_pid = crate::syscall::process::vfork_child_pid();
    if child_pid <= 0 {
        return 0;
    }
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return 0;
    };
    let current_pid = crate::syscall::process::current_process_pid(vm, vm.guest_base);
    i32::from(current_pid == child_pid && current_pid != runtime_pid)
}

pub(super) fn owner_matches(vm_ptr: u32, runtime_pid: i32) -> i32 {
    if vm_ptr == 0 || runtime_pid <= 0 {
        return 0;
    }
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return 0;
    };
    let current_pid = crate::syscall::process::current_process_pid(vm, vm.guest_base);
    i32::from(current_pid == runtime_pid)
}

pub(super) fn owner_mismatch(vm_ptr: u32, runtime_pid: i32) -> i32 {
    if vm_ptr == 0 || runtime_pid <= 0 {
        return 0;
    }
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return 0;
    };
    let current_pid = crate::syscall::process::current_process_pid(vm, vm.guest_base);
    i32::from(current_pid > 0 && current_pid != runtime_pid)
}

#[allow(clippy::too_many_arguments)]
pub fn record_process_lifecycle(
    kind: u32,
    vm_ptr: u32,
    parent_pid: i32,
    child_pid: i32,
    wait_status: i32,
    wait_kind: u32,
    vm_status: u32,
    result: i64,
    wait_target: i64,
    options: u64,
    wstatus_addr: u64,
    rusage_addr: u64,
    detail: u64,
) {
    let seq = PROCESS_LIFECYCLE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = super::SupervisorProcessLifecycleRecord {
        kind,
        seq,
        vm_ptr,
        parent_pid: parent_pid as u32,
        child_pid: child_pid as u32,
        wait_status: wait_status as u32,
        wait_kind,
        vm_status,
        result,
        wait_target,
        options,
        wstatus_addr,
        rusage_addr,
        detail,
    };
    super::lock::with_spin_lock(&PROCESS_LIFECYCLE_LOCK, || unsafe {
        LAST_PROCESS_LIFECYCLE = record;
    });
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_PROCESS_LIFECYCLE_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_PROCESS_LIFECYCLE_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = super::lock::with_spin_lock(&PROCESS_LIFECYCLE_LOCK, || unsafe {
        LAST_PROCESS_LIFECYCLE
    });
    let mut encoded = [0u8; super::SUPERVISOR_PROCESS_LIFECYCLE_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_PROCESS_LIFECYCLE_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_PROCESS_LIFECYCLE_BYTES);
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.vm_ptr);
    super::write_u32(&mut encoded, 28, record.parent_pid);
    super::write_u32(&mut encoded, 32, record.child_pid);
    super::write_u32(&mut encoded, 36, record.wait_status);
    super::write_u32(&mut encoded, 40, record.wait_kind);
    super::write_u32(&mut encoded, 44, record.vm_status);
    super::write_u64(&mut encoded, 48, record.result as u64);
    super::write_u64(&mut encoded, 56, record.wait_target as u64);
    super::write_u64(&mut encoded, 64, record.options);
    super::write_u64(&mut encoded, 72, record.wstatus_addr);
    super::write_u64(&mut encoded, 80, record.rusage_addr);
    super::write_u64(&mut encoded, 88, record.detail);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_PROCESS_LIFECYCLE_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_PROCESS_LIFECYCLE_BYTES as i32
}
