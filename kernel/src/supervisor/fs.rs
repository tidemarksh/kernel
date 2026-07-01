use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static FS_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static FS_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_FS_CONTROL: super::SupervisorFsControlRecord =
    super::SupervisorFsControlRecord::empty();

pub(super) fn init() {
    FS_CONTROL_COUNT.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&FS_CONTROL_LOCK, || unsafe {
        LAST_FS_CONTROL = super::SupervisorFsControlRecord::empty();
    });
}

pub fn fs_control_count() -> u64 {
    FS_CONTROL_COUNT.load(Ordering::Relaxed)
}

#[allow(clippy::too_many_arguments)]
pub fn record_fs_control(
    kind: u32,
    vm_ptr: u32,
    process_ptr: u32,
    pid: i32,
    fd: u32,
    ino: u32,
    opcode: u32,
    file_object_id: u64,
    page_index: u64,
    offset: u64,
    length: u64,
    result: i64,
    flags: u64,
    detail0: u64,
    detail1: u64,
) {
    let seq = FS_CONTROL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = super::SupervisorFsControlRecord {
        kind,
        seq,
        vm_ptr,
        process_ptr,
        pid: pid as u32,
        fd,
        ino,
        opcode,
        file_object_id,
        page_index,
        offset,
        length,
        result,
        flags,
        detail0,
        detail1,
    };
    super::lock::with_spin_lock(&FS_CONTROL_LOCK, || unsafe {
        LAST_FS_CONTROL = record;
    });
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_FS_CONTROL_RECORD_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_FS_CONTROL_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = super::lock::with_spin_lock(&FS_CONTROL_LOCK, || unsafe { LAST_FS_CONTROL });
    let mut encoded = [0u8; super::SUPERVISOR_FS_CONTROL_RECORD_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_FS_CONTROL_RECORD_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_FS_CONTROL_RECORD_BYTES);
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.vm_ptr);
    super::write_u32(&mut encoded, 28, record.process_ptr);
    super::write_u32(&mut encoded, 32, record.pid);
    super::write_u32(&mut encoded, 36, record.fd);
    super::write_u32(&mut encoded, 40, record.ino);
    super::write_u32(&mut encoded, 44, record.opcode);
    super::write_u64(&mut encoded, 48, record.file_object_id);
    super::write_u64(&mut encoded, 56, record.page_index);
    super::write_u64(&mut encoded, 64, record.offset);
    super::write_u64(&mut encoded, 72, record.length);
    super::write_u64(&mut encoded, 80, record.result as u64);
    super::write_u64(&mut encoded, 88, record.flags);
    super::write_u64(&mut encoded, 96, record.detail0);
    super::write_u64(&mut encoded, 104, record.detail1);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_FS_CONTROL_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_FS_CONTROL_RECORD_BYTES as i32
}
