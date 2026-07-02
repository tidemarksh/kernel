use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::abi::{FD_TYPE_FILE, MAX_FDS};
use crate::fs::{fd_table, memfs, ring_buffer};
use crate::types::ThreadState;

static FS_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static FS_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_FS_CONTROL: super::SupervisorFsControlRecord =
    super::SupervisorFsControlRecord::empty();
static DIRTY_PAGE_DECISION_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_DIRTY_PAGE_DECISION: DirtyPageDecision = DirtyPageDecision::empty();
const MAX_SUPERVISOR_FS_INODES: u32 = 65_536;

#[derive(Clone, Copy)]
struct DirtyPageDecision {
    result: i64,
    next_size: u64,
    file_object_id: u64,
    generation: u64,
    flags: u32,
}

impl DirtyPageDecision {
    const fn empty() -> Self {
        Self {
            result: 0,
            next_size: 0,
            file_object_id: 0,
            generation: 0,
            flags: 0,
        }
    }
}

pub(super) fn init() {
    FS_CONTROL_COUNT.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&FS_CONTROL_LOCK, || unsafe {
        LAST_FS_CONTROL = super::SupervisorFsControlRecord::empty();
    });
    super::lock::with_spin_lock(&DIRTY_PAGE_DECISION_LOCK, || unsafe {
        LAST_DIRTY_PAGE_DECISION = DirtyPageDecision::empty();
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

#[derive(Clone, Copy)]
struct PendingBackingFillRequest {
    ino: u32,
    offset: u64,
    length: u64,
    expected_size: u64,
    opcode: u32,
}

fn pending_request_file_context(
    vm: &ThreadState,
    vm_ptr: u32,
    request: &ring_buffer::FsRequestInfo,
) -> Option<(u32, u32)> {
    if request.opcode == ring_buffer::FS_OP_TRUNCATE && request.path_ptr != 0 {
        let ino = crate::syscall::fs::pending_request_target_ino(vm_ptr, vm.guest_base);
        return (ino > 0).then_some((0, ino));
    }

    if request.fd >= 0 && (request.fd as usize) < MAX_FDS {
        let entry =
            fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, request.fd as usize);
        if entry.ofd_id != 0 && (entry.ofd_id as usize) < MAX_FDS {
            if let Some(ofd) = fd_table::get_ofd(vm.guest_base, vm, request.fd as u64) {
                if ofd.fd_type == FD_TYPE_FILE && ofd.ino > 0 {
                    return Some((entry.ofd_id, ofd.ino));
                }
            }
        }
    }

    if request.opcode == ring_buffer::FS_OP_TRUNCATE {
        let ino = crate::syscall::fs::pending_request_target_ino(vm_ptr, vm.guest_base);
        return (ino > 0).then_some((0, ino));
    }

    None
}

fn pending_backing_fill_request(vm_ptr: u32) -> Option<PendingBackingFillRequest> {
    let (vm, request) = pending_fs_request(vm_ptr)?;
    match request.opcode {
        ring_buffer::FS_OP_READ
        | ring_buffer::FS_OP_WRITE
        | ring_buffer::FS_OP_MMAP
        | ring_buffer::FS_OP_TRUNCATE => {}
        _ => return None,
    }

    if request.opcode != ring_buffer::FS_OP_TRUNCATE && request.len == 0 {
        return None;
    }

    let (ofd_id, ino) = pending_request_file_context(vm, vm_ptr, &request)?;
    let expected_size = memfs::stat(ino)?.size;
    if expected_size == 0 {
        return None;
    }

    if request.opcode == ring_buffer::FS_OP_TRUNCATE {
        let truncate_size = request.offset;
        if truncate_size == 0 {
            return None;
        }
        let surviving_last_byte = core::cmp::min(truncate_size, expected_size).checked_sub(1)?;
        return Some(PendingBackingFillRequest {
            ino,
            offset: surviving_last_byte,
            length: 1,
            expected_size,
            opcode: request.opcode,
        });
    }

    let offset = if request.opcode == ring_buffer::FS_OP_MMAP
        || (request.flags & ring_buffer::FS_REQ_FLAG_PWRITE) != 0
    {
        request.offset
    } else {
        fd_table::get_offset_by_id(ofd_id)
    };

    if request.opcode == ring_buffer::FS_OP_WRITE && offset >= expected_size {
        return Some(PendingBackingFillRequest {
            ino,
            offset: expected_size - 1,
            length: 1,
            expected_size,
            opcode: request.opcode,
        });
    }

    if offset >= expected_size {
        return None;
    }

    Some(PendingBackingFillRequest {
        ino,
        offset,
        length: core::cmp::min(request.len, expected_size - offset),
        expected_size,
        opcode: request.opcode,
    })
}

pub fn pending_backing_fill_ino(vm_ptr: u32) -> u32 {
    pending_backing_fill_request(vm_ptr).map_or(0, |request| request.ino)
}

pub fn pending_backing_fill_offset(vm_ptr: u32) -> u64 {
    pending_backing_fill_request(vm_ptr).map_or(0, |request| request.offset)
}

pub fn pending_backing_fill_length(vm_ptr: u32) -> u64 {
    pending_backing_fill_request(vm_ptr).map_or(0, |request| request.length)
}

pub fn pending_backing_fill_expected_size(vm_ptr: u32) -> u64 {
    pending_backing_fill_request(vm_ptr).map_or(0, |request| request.expected_size)
}

pub fn pending_backing_fill_opcode(vm_ptr: u32) -> u32 {
    pending_backing_fill_request(vm_ptr).map_or(0, |request| request.opcode)
}

fn pending_mmap_guest_write_request(vm_ptr: u32) -> Option<(u64, u64)> {
    let (_, request) = pending_fs_request(vm_ptr)?;
    if request.opcode != ring_buffer::FS_OP_MMAP || request.len == 0 {
        return None;
    }
    Some((request.buf_ptr, request.len))
}

pub fn pending_mmap_guest_write_ptr(vm_ptr: u32) -> u64 {
    pending_mmap_guest_write_request(vm_ptr).map_or(0, |(ptr, _)| ptr)
}

pub fn pending_mmap_guest_write_len(vm_ptr: u32) -> u64 {
    pending_mmap_guest_write_request(vm_ptr).map_or(0, |(_, len)| len)
}

fn store_dirty_page_decision(decision: DirtyPageDecision) {
    super::lock::with_spin_lock(&DIRTY_PAGE_DECISION_LOCK, || unsafe {
        LAST_DIRTY_PAGE_DECISION = decision;
    });
}

fn latest_dirty_page_decision() -> DirtyPageDecision {
    super::lock::with_spin_lock(&DIRTY_PAGE_DECISION_LOCK, || unsafe {
        LAST_DIRTY_PAGE_DECISION
    })
}

fn invalid_dirty_page_decision() -> DirtyPageDecision {
    DirtyPageDecision {
        result: crate::abi::EINVAL,
        ..DirtyPageDecision::empty()
    }
}

fn enospc_dirty_page_decision() -> DirtyPageDecision {
    DirtyPageDecision {
        result: crate::abi::ENOSPC,
        ..DirtyPageDecision::empty()
    }
}

fn valid_ino(ino: u32) -> bool {
    ino > 0 && ino < MAX_SUPERVISOR_FS_INODES
}

#[allow(clippy::too_many_arguments)]
pub fn dirty_page_decision(
    op: u32,
    ino: u32,
    offset: u64,
    length_or_size: u64,
    current_size: u64,
    current_file_object_id: u64,
    current_generation: u64,
    existing_dirty_pages: u32,
    delta_dirty_pages: u32,
    resident_page_capacity: u32,
    page_map_newer: u32,
) -> i64 {
    let decision = match op {
        super::SUPERVISOR_FS_DIRTY_PAGE_OP_WRITE => {
            if !valid_ino(ino) || length_or_size == 0 {
                invalid_dirty_page_decision()
            } else if let Some(end) = offset.checked_add(length_or_size) {
                if end > u32::MAX as u64
                    || existing_dirty_pages.saturating_add(delta_dirty_pages)
                        > resident_page_capacity
                {
                    enospc_dirty_page_decision()
                } else {
                    let next_size = core::cmp::max(current_size, end);
                    let file_object_id = if current_file_object_id == 0 {
                        ino as u64
                    } else {
                        current_file_object_id
                    };
                    let generation = if current_file_object_id == 0 {
                        current_generation.saturating_add(1)
                    } else {
                        current_generation
                    };
                    DirtyPageDecision {
                        result: length_or_size as i64,
                        next_size,
                        file_object_id,
                        generation,
                        flags: super::SUPERVISOR_FS_DIRTY_PAGE_FLAG_UPDATE_INODE
                            | super::SUPERVISOR_FS_DIRTY_PAGE_FLAG_PUBLISH_DIRTY,
                    }
                }
            } else {
                enospc_dirty_page_decision()
            }
        }
        super::SUPERVISOR_FS_DIRTY_PAGE_OP_TRUNCATE => {
            if !valid_ino(ino) || length_or_size > u32::MAX as u64 {
                invalid_dirty_page_decision()
            } else if delta_dirty_pages > resident_page_capacity {
                enospc_dirty_page_decision()
            } else {
                DirtyPageDecision {
                    result: 0,
                    next_size: length_or_size,
                    file_object_id: if current_file_object_id == 0 {
                        ino as u64
                    } else {
                        current_file_object_id
                    },
                    generation: current_generation.saturating_add(1),
                    flags: super::SUPERVISOR_FS_DIRTY_PAGE_FLAG_UPDATE_INODE
                        | super::SUPERVISOR_FS_DIRTY_PAGE_FLAG_PUBLISH_DIRTY,
                }
            }
        }
        super::SUPERVISOR_FS_DIRTY_PAGE_OP_FLUSH => {
            if !valid_ino(ino) {
                invalid_dirty_page_decision()
            } else {
                let writeback_required = delta_dirty_pages != 0 || page_map_newer != 0;
                DirtyPageDecision {
                    result: 0,
                    next_size: current_size,
                    file_object_id: current_file_object_id,
                    generation: current_generation,
                    flags: if writeback_required {
                        super::SUPERVISOR_FS_DIRTY_PAGE_FLAG_WRITEBACK_REQUIRED
                    } else {
                        0
                    },
                }
            }
        }
        _ => invalid_dirty_page_decision(),
    };

    store_dirty_page_decision(decision);
    if decision.result >= 0
        && (op == super::SUPERVISOR_FS_DIRTY_PAGE_OP_WRITE
            || op == super::SUPERVISOR_FS_DIRTY_PAGE_OP_TRUNCATE)
    {
        record_fs_control(
            super::SUPERVISOR_FS_CONTROL_KIND_DIRTY_PAGE_PUBLISHED,
            0,
            0,
            0,
            0,
            ino,
            op,
            decision.file_object_id,
            0,
            offset,
            length_or_size,
            decision.result,
            decision.flags as u64,
            decision.next_size,
            decision.generation,
        );
    } else if op == super::SUPERVISOR_FS_DIRTY_PAGE_OP_FLUSH
        && (decision.flags & super::SUPERVISOR_FS_DIRTY_PAGE_FLAG_WRITEBACK_REQUIRED) != 0
    {
        record_fs_control(
            super::SUPERVISOR_FS_CONTROL_KIND_DIRTY_PAGE_FLUSHED,
            0,
            0,
            0,
            0,
            ino,
            op,
            current_file_object_id,
            0,
            offset,
            length_or_size,
            decision.result,
            decision.flags as u64,
            delta_dirty_pages as u64,
            current_generation,
        );
    }
    decision.result
}

pub fn dirty_page_decision_next_size() -> u64 {
    latest_dirty_page_decision().next_size
}

pub fn dirty_page_decision_file_object_id() -> u64 {
    latest_dirty_page_decision().file_object_id
}

pub fn dirty_page_decision_generation() -> u64 {
    latest_dirty_page_decision().generation
}

pub fn dirty_page_decision_flags() -> u32 {
    latest_dirty_page_decision().flags
}

#[allow(clippy::too_many_arguments)]
pub fn page_table_source_decision(
    ino: u32,
    has_dirty_pages: u32,
    published_file_object_id: u64,
    published_generation: u64,
    published_size: u64,
    backing_file_object_id: u64,
    backing_generation: u64,
    backing_size: u64,
) -> i32 {
    if !valid_ino(ino) {
        return crate::abi::EINVAL as i32;
    }
    if has_dirty_pages != 0 {
        return super::SUPERVISOR_FS_PAGE_TABLE_SOURCE_RESIDENT as i32;
    }
    if published_file_object_id == 0 || backing_file_object_id == 0 {
        return super::SUPERVISOR_FS_PAGE_TABLE_SOURCE_BACKING as i32;
    }
    if published_file_object_id != backing_file_object_id
        || published_generation != backing_generation
        || published_size != backing_size
    {
        return super::SUPERVISOR_FS_PAGE_TABLE_SOURCE_RESIDENT as i32;
    }
    super::SUPERVISOR_FS_PAGE_TABLE_SOURCE_BACKING as i32
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
