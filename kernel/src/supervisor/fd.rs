use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static FD_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static FD_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_FD_CONTROL: super::SupervisorFdControlRecord =
    super::SupervisorFdControlRecord::empty();

pub(super) fn init() {
    FD_CONTROL_COUNT.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&FD_CONTROL_LOCK, || unsafe {
        LAST_FD_CONTROL = super::SupervisorFdControlRecord::empty();
    });
}

pub fn fd_control_count() -> u64 {
    FD_CONTROL_COUNT.load(Ordering::Relaxed)
}

#[allow(clippy::too_many_arguments)]
pub fn record_fd_control(
    kind: u32,
    vm_ptr: u32,
    process_ptr: u32,
    pid: i32,
    fd: u32,
    fd2: u32,
    ofd_id: u32,
    ofd2_id: u32,
    fd_type: u32,
    resource_slot: u32,
    resource_generation: u32,
    result: i64,
    flags: u64,
    detail0: u64,
    detail1: u64,
) {
    let seq = FD_CONTROL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = super::SupervisorFdControlRecord {
        kind,
        seq,
        vm_ptr,
        process_ptr,
        pid: pid as u32,
        fd,
        fd2,
        ofd_id,
        ofd2_id,
        fd_type,
        resource_slot,
        resource_generation,
        result,
        flags,
        detail0,
        detail1,
    };
    super::lock::with_spin_lock(&FD_CONTROL_LOCK, || unsafe {
        LAST_FD_CONTROL = record;
    });
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_FD_CONTROL_RECORD_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_FD_CONTROL_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = super::lock::with_spin_lock(&FD_CONTROL_LOCK, || unsafe { LAST_FD_CONTROL });
    let mut encoded = [0u8; super::SUPERVISOR_FD_CONTROL_RECORD_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_FD_CONTROL_RECORD_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_FD_CONTROL_RECORD_BYTES);
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.vm_ptr);
    super::write_u32(&mut encoded, 28, record.process_ptr);
    super::write_u32(&mut encoded, 32, record.pid);
    super::write_u32(&mut encoded, 36, record.fd);
    super::write_u32(&mut encoded, 40, record.fd2);
    super::write_u32(&mut encoded, 44, record.ofd_id);
    super::write_u32(&mut encoded, 48, record.ofd2_id);
    super::write_u32(&mut encoded, 52, record.fd_type);
    super::write_u32(&mut encoded, 56, record.resource_slot);
    super::write_u32(&mut encoded, 60, record.resource_generation);
    super::write_u64(&mut encoded, 64, record.result as u64);
    super::write_u64(&mut encoded, 72, record.flags);
    super::write_u64(&mut encoded, 80, record.detail0);
    super::write_u64(&mut encoded, 88, record.detail1);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_FD_CONTROL_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_FD_CONTROL_RECORD_BYTES as i32
}
