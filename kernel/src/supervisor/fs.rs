use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::abi::{FD_TYPE_FILE, MAX_FDS};
use crate::fs::{fd_table, ring_buffer};
use crate::types::ThreadState;

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

fn pending_fs_request(vm_ptr: u32) -> Option<(&'static ThreadState, ring_buffer::FsRequestInfo)> {
    let vm = super::thread::state_from_ptr(vm_ptr)?;
    let ps = super::fd::process_state_from_vm_ptr(vm_ptr)?;
    if !ring_buffer::ring_backed(ps.fs_ring_base) {
        return None;
    }
    ring_buffer::peek_request_info_for_vm(ps.fs_ring_base, vm_ptr).map(|request| (vm, request))
}

pub fn pending_ring_request(vm_ptr: u32) -> u32 {
    pending_fs_request(vm_ptr).is_some() as u32
}

fn pending_regular_file_request(vm_ptr: u32) -> Option<(i32, u32)> {
    let (vm, request) = pending_fs_request(vm_ptr)?;
    match request.opcode {
        ring_buffer::FS_OP_READ
        | ring_buffer::FS_OP_WRITE
        | ring_buffer::FS_OP_FSTAT
        | ring_buffer::FS_OP_LSEEK
        | ring_buffer::FS_OP_MMAP => {}
        _ => return None,
    }
    if request.fd < 0 || request.fd as usize >= MAX_FDS {
        return None;
    }
    let entry = fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, request.fd as usize);
    if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS {
        return None;
    }
    let ofd = fd_table::get_ofd(vm.guest_base, vm, request.fd as u64)?;
    (ofd.fd_type == FD_TYPE_FILE).then_some((request.fd, entry.ofd_id))
}

pub fn pending_regular_file_fd(vm_ptr: u32) -> i32 {
    pending_regular_file_request(vm_ptr).map_or(-1, |(fd, _)| fd)
}

pub fn pending_regular_file_ofd(vm_ptr: u32) -> u32 {
    pending_regular_file_request(vm_ptr).map_or(0, |(_, ofd_id)| ofd_id)
}

#[allow(clippy::too_many_arguments)]
pub fn completion_decision(
    _vm_ptr: u32,
    opcode: u32,
    effects: u32,
    result: i64,
    host_memfs_mutated: u32,
    host_ofd_state_changed: u32,
    pending_ring_request: u32,
    regular_file_request: u32,
) -> u32 {
    let fs_succeeded = result >= 0;
    let memfs_state_may_change = (effects
        & (crate::syscall::fs::FS_EFFECT_MEMFS_MUTATION
            | crate::syscall::fs::FS_EFFECT_MEMFS_FILE_DATA))
        != 0;
    let memfs_publish_may_be_ready = (effects & crate::syscall::fs::FS_EFFECT_MEMFS_MUTATION) != 0
        || ((effects & crate::syscall::fs::FS_EFFECT_MEMFS_FILE_DATA) != 0
            && opcode == ring_buffer::FS_OP_WRITE);
    let ofd_state_may_change = (effects & crate::syscall::fs::FS_EFFECT_SHARED_OFD_STATE) != 0;

    let mut flags = 0u32;
    if host_memfs_mutated != 0
        || (fs_succeeded && (memfs_state_may_change || pending_ring_request != 0))
    {
        flags |= super::SUPERVISOR_FS_COMPLETION_FLAG_MEMFS_DIRTY;
    }
    if fs_succeeded && memfs_publish_may_be_ready {
        flags |= super::SUPERVISOR_FS_COMPLETION_FLAG_MEMFS_PUBLISH_READY;
    }
    if host_ofd_state_changed != 0
        || (fs_succeeded && (ofd_state_may_change || pending_ring_request != 0))
    {
        flags |= super::SUPERVISOR_FS_COMPLETION_FLAG_OFD_STATE_CHANGED;
    }
    if regular_file_request != 0 {
        flags |= super::SUPERVISOR_FS_COMPLETION_FLAG_REGULAR_FILE_REQUEST;
    }
    flags
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
