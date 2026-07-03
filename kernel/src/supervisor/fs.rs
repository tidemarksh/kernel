use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::abi::{EFAULT, FD_TYPE_FILE, FD_TYPE_PIPE, MAX_FDS};
use crate::fs::{fd_table, memfs, ring_buffer};
use crate::types::ThreadState;

static FS_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static FS_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_FS_CONTROL: super::SupervisorFsControlRecord =
    super::SupervisorFsControlRecord::empty();
static DIRTY_PAGE_DECISION_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_DIRTY_PAGE_DECISION: DirtyPageDecision = DirtyPageDecision::empty();
static BACKING_FILL_SPAN_DECISION_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_BACKING_FILL_SPAN_DECISION: BackingFillSpanDecision =
    BackingFillSpanDecision::empty();
static BACKING_SOURCE_RANGE_DECISION_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_BACKING_SOURCE_RANGE_DECISION: BackingSourceRangeDecision =
    BackingSourceRangeDecision::empty();
static CLEAN_BACKING_RANGE_DECISION_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_CLEAN_BACKING_RANGE_DECISION: CleanBackingRangeDecision =
    CleanBackingRangeDecision::empty();
static DIRTY_PREPARE_DECISION_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_DIRTY_PREPARE_DECISION: DirtyPrepareDecision = DirtyPrepareDecision::empty();
static METADATA_SYNC_DECISION_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_METADATA_SYNC_DECISION: MetadataSyncDecision = MetadataSyncDecision::empty();
static BACKING_OBJECT_DECISION_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_BACKING_OBJECT_DECISION: BackingObjectDecision = BackingObjectDecision::empty();
const MAX_SUPERVISOR_FS_INODES: u32 = 65_536;
const DIRECT_BACKING_MMAP_MIN_BYTES: u64 = 16 * 1024 * 1024;
const READ_BACKING_FILL_PREFETCH_BYTES: u64 = 1024 * 1024;

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

#[derive(Clone, Copy)]
struct BackingFillSpanDecision {
    offset: u64,
    end: u64,
    length: u64,
}

impl BackingFillSpanDecision {
    const fn empty() -> Self {
        Self {
            offset: 0,
            end: 0,
            length: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct BackingSourceRangeDecision {
    source_byte_length: u64,
    source_offset: u64,
    read_length: u64,
}

impl BackingSourceRangeDecision {
    const fn empty() -> Self {
        Self {
            source_byte_length: 0,
            source_offset: 0,
            read_length: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct CleanBackingRangeDecision {
    read_offset: u64,
    read_length: u64,
    output_length: u64,
}

impl CleanBackingRangeDecision {
    const fn empty() -> Self {
        Self {
            read_offset: 0,
            read_length: 0,
            output_length: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct DirtyPrepareDecision {
    publish_mode: u32,
}

impl DirtyPrepareDecision {
    const fn empty() -> Self {
        Self {
            publish_mode: super::SUPERVISOR_FS_DIRTY_PREPARE_PUBLISH_NONE,
        }
    }
}

#[derive(Clone, Copy)]
struct MetadataSyncDecision {
    size: u64,
    backing_source: u32,
}

impl MetadataSyncDecision {
    const fn empty() -> Self {
        Self {
            size: 0,
            backing_source: super::SUPERVISOR_FS_METADATA_BACKING_NONE,
        }
    }
}

#[derive(Clone, Copy)]
struct BackingObjectDecision {
    file_object_id: u64,
    generation: u64,
}

impl BackingObjectDecision {
    const fn empty() -> Self {
        Self {
            file_object_id: 0,
            generation: 0,
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
    super::lock::with_spin_lock(&BACKING_FILL_SPAN_DECISION_LOCK, || unsafe {
        LAST_BACKING_FILL_SPAN_DECISION = BackingFillSpanDecision::empty();
    });
    super::lock::with_spin_lock(&BACKING_SOURCE_RANGE_DECISION_LOCK, || unsafe {
        LAST_BACKING_SOURCE_RANGE_DECISION = BackingSourceRangeDecision::empty();
    });
    super::lock::with_spin_lock(&CLEAN_BACKING_RANGE_DECISION_LOCK, || unsafe {
        LAST_CLEAN_BACKING_RANGE_DECISION = CleanBackingRangeDecision::empty();
    });
    super::lock::with_spin_lock(&DIRTY_PREPARE_DECISION_LOCK, || unsafe {
        LAST_DIRTY_PREPARE_DECISION = DirtyPrepareDecision::empty();
    });
    super::lock::with_spin_lock(&METADATA_SYNC_DECISION_LOCK, || unsafe {
        LAST_METADATA_SYNC_DECISION = MetadataSyncDecision::empty();
    });
    super::lock::with_spin_lock(&BACKING_OBJECT_DECISION_LOCK, || unsafe {
        LAST_BACKING_OBJECT_DECISION = BackingObjectDecision::empty();
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

fn process_has_pipe_fd(vm: &ThreadState) -> bool {
    for fd in 0..MAX_FDS {
        let entry = fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, fd);
        let ofd_id = entry.ofd_id;
        if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
            continue;
        }
        if fd_table::get_ofd_by_id(ofd_id).is_some_and(|ofd| ofd.fd_type == FD_TYPE_PIPE) {
            return true;
        }
    }
    false
}

pub fn pipe_refresh_before_resume_action(vm_ptr: u32, flags: u32) -> i32 {
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return -(EFAULT as i32);
    };

    if (flags & super::SUPERVISOR_FS_PIPE_REFRESH_FLAG_KERNEL_WORKER_AVAILABLE) == 0
        || super::thread::process_thread_count(vm_ptr, vm.guest_base) <= 1
        || pending_fs_request(vm_ptr).is_none()
        || pending_regular_file_request(vm_ptr).is_some()
        || !process_has_pipe_fd(vm)
    {
        return super::SUPERVISOR_FS_PIPE_REFRESH_ACTION_NONE as i32;
    }

    super::SUPERVISOR_FS_PIPE_REFRESH_ACTION_REQUEST_SYNC as i32
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

fn pending_execve_backing_fill_request(vm_ptr: u32) -> Option<PendingBackingFillRequest> {
    super::thread::state_from_ptr(vm_ptr)?;
    let len = crate::syscall::process::execve_backing_miss_len(vm_ptr);
    if len == 0 {
        return None;
    }
    let ino = crate::syscall::process::execve_backing_miss_ino(vm_ptr);
    let expected_size = crate::syscall::process::execve_backing_miss_expected_size(vm_ptr);
    if ino == 0 || expected_size == 0 {
        return None;
    }
    Some(PendingBackingFillRequest {
        ino,
        offset: crate::syscall::process::execve_backing_miss_offset(vm_ptr),
        length: len as u64,
        expected_size: expected_size as u64,
        opcode: ring_buffer::FS_OP_EXECVE,
    })
}

fn pending_backing_fill_request(vm_ptr: u32) -> Option<PendingBackingFillRequest> {
    if let Some(request) = pending_execve_backing_fill_request(vm_ptr) {
        return Some(request);
    }

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

pub fn clear_pending_backing_fill(vm_ptr: u32) -> i32 {
    if pending_execve_backing_fill_request(vm_ptr).is_none() {
        return 0;
    }
    crate::syscall::process::clear_execve_backing_miss(vm_ptr);
    1
}

pub fn backing_retry_limit(_opcode: u32, offset: u64, length: u64, expected_size: u64) -> u32 {
    if length == 0 || expected_size == 0 {
        return 0;
    }
    let page_size = crate::abi::PAGE_SIZE;
    let aligned_offset = offset / page_size * page_size;
    let requested_end = offset.saturating_add(length);
    let aligned_end = core::cmp::min(
        expected_size,
        requested_end
            .saturating_add(page_size - 1)
            .saturating_div(page_size)
            .saturating_mul(page_size),
    );
    let aligned_length = core::cmp::max(page_size, aligned_end.saturating_sub(aligned_offset));
    let source_chunks = expected_size
        .saturating_add(aligned_length - 1)
        .saturating_div(aligned_length);
    let attempts =
        source_chunks.saturating_add(super::SUPERVISOR_FS_BACKING_RETRY_FINAL_SCAN_ATTEMPTS as u64);
    core::cmp::min(
        super::SUPERVISOR_FS_BACKING_RETRY_MAX_ATTEMPTS,
        core::cmp::max(
            super::SUPERVISOR_FS_BACKING_RETRY_MIN_ATTEMPTS,
            core::cmp::min(attempts, u32::MAX as u64) as u32,
        ),
    )
}

pub fn backing_fill_span_decision(
    opcode: u32,
    offset: i64,
    length: i64,
    expected_size: i64,
) -> i32 {
    let mut decision = BackingFillSpanDecision::empty();
    let result = if offset < 0 || length <= 0 || expected_size <= 0 {
        crate::abi::EINVAL as i32
    } else {
        let page_size = crate::abi::PAGE_SIZE;
        let offset = offset as u64;
        let length = length as u64;
        let expected_size = expected_size as u64;
        if offset >= expected_size {
            crate::abi::EINVAL as i32
        } else if let Some(requested_end) = offset.checked_add(length) {
            let aligned_offset = offset / page_size * page_size;
            let fill_end = if opcode == ring_buffer::FS_OP_READ {
                core::cmp::max(
                    requested_end,
                    aligned_offset.saturating_add(READ_BACKING_FILL_PREFETCH_BYTES),
                )
            } else {
                requested_end
            };
            let aligned_end = core::cmp::min(
                expected_size,
                fill_end
                    .saturating_add(page_size - 1)
                    .saturating_div(page_size)
                    .saturating_mul(page_size),
            );
            if aligned_end <= aligned_offset {
                crate::abi::EINVAL as i32
            } else {
                decision = BackingFillSpanDecision {
                    offset: aligned_offset,
                    end: aligned_end,
                    length: aligned_end - aligned_offset,
                };
                0
            }
        } else {
            crate::abi::EINVAL as i32
        }
    };
    store_backing_fill_span_decision(decision);
    result
}

pub fn backing_fill_span_offset() -> u64 {
    latest_backing_fill_span_decision().offset
}

pub fn backing_fill_span_end() -> u64 {
    latest_backing_fill_span_decision().end
}

pub fn backing_fill_span_length() -> u64 {
    latest_backing_fill_span_decision().length
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

pub fn pending_mmap_guest_write_snapshot_len(vm_ptr: u32) -> u64 {
    pending_mmap_guest_write_request(vm_ptr)
        .and_then(|(_, len)| page_aligned_len(len))
        .unwrap_or(0)
}

fn page_aligned_len(len: u64) -> Option<u64> {
    len.checked_add(crate::abi::PAGE_SIZE - 1)
        .map(|value| value & !(crate::abi::PAGE_SIZE - 1))
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

fn store_backing_fill_span_decision(decision: BackingFillSpanDecision) {
    super::lock::with_spin_lock(&BACKING_FILL_SPAN_DECISION_LOCK, || unsafe {
        LAST_BACKING_FILL_SPAN_DECISION = decision;
    });
}

fn latest_backing_fill_span_decision() -> BackingFillSpanDecision {
    super::lock::with_spin_lock(&BACKING_FILL_SPAN_DECISION_LOCK, || unsafe {
        LAST_BACKING_FILL_SPAN_DECISION
    })
}

fn store_backing_source_range_decision(decision: BackingSourceRangeDecision) {
    super::lock::with_spin_lock(&BACKING_SOURCE_RANGE_DECISION_LOCK, || unsafe {
        LAST_BACKING_SOURCE_RANGE_DECISION = decision;
    });
}

fn latest_backing_source_range_decision() -> BackingSourceRangeDecision {
    super::lock::with_spin_lock(&BACKING_SOURCE_RANGE_DECISION_LOCK, || unsafe {
        LAST_BACKING_SOURCE_RANGE_DECISION
    })
}

fn store_clean_backing_range_decision(decision: CleanBackingRangeDecision) {
    super::lock::with_spin_lock(&CLEAN_BACKING_RANGE_DECISION_LOCK, || unsafe {
        LAST_CLEAN_BACKING_RANGE_DECISION = decision;
    });
}

fn latest_clean_backing_range_decision() -> CleanBackingRangeDecision {
    super::lock::with_spin_lock(&CLEAN_BACKING_RANGE_DECISION_LOCK, || unsafe {
        LAST_CLEAN_BACKING_RANGE_DECISION
    })
}

fn store_dirty_prepare_decision(decision: DirtyPrepareDecision) {
    super::lock::with_spin_lock(&DIRTY_PREPARE_DECISION_LOCK, || unsafe {
        LAST_DIRTY_PREPARE_DECISION = decision;
    });
}

fn latest_dirty_prepare_decision() -> DirtyPrepareDecision {
    super::lock::with_spin_lock(&DIRTY_PREPARE_DECISION_LOCK, || unsafe {
        LAST_DIRTY_PREPARE_DECISION
    })
}

fn store_metadata_sync_decision(decision: MetadataSyncDecision) {
    super::lock::with_spin_lock(&METADATA_SYNC_DECISION_LOCK, || unsafe {
        LAST_METADATA_SYNC_DECISION = decision;
    });
}

fn latest_metadata_sync_decision() -> MetadataSyncDecision {
    super::lock::with_spin_lock(&METADATA_SYNC_DECISION_LOCK, || unsafe {
        LAST_METADATA_SYNC_DECISION
    })
}

fn store_backing_object_decision(decision: BackingObjectDecision) {
    super::lock::with_spin_lock(&BACKING_OBJECT_DECISION_LOCK, || unsafe {
        LAST_BACKING_OBJECT_DECISION = decision;
    });
}

fn latest_backing_object_decision() -> BackingObjectDecision {
    super::lock::with_spin_lock(&BACKING_OBJECT_DECISION_LOCK, || unsafe {
        LAST_BACKING_OBJECT_DECISION
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

fn valid_backing_identity(file_object_id: u64, generation: u64) -> bool {
    file_object_id > 0 && file_object_id <= u32::MAX as u64 && generation > 0
}

fn next_generation(generation: u64) -> u64 {
    if generation == 0 {
        1
    } else {
        generation.saturating_add(1)
    }
}

fn preserved_backing_generation(
    published_file_object_id: u64,
    published_generation: u64,
    backing_file_object_id: u64,
    backing_generation: u64,
) -> Option<BackingObjectDecision> {
    if published_file_object_id != 0 {
        return valid_backing_identity(published_file_object_id, published_generation).then_some(
            BackingObjectDecision {
                file_object_id: published_file_object_id,
                generation: published_generation,
            },
        );
    }
    if backing_file_object_id != 0 {
        return valid_backing_identity(backing_file_object_id, backing_generation).then_some(
            BackingObjectDecision {
                file_object_id: backing_file_object_id,
                generation: backing_generation,
            },
        );
    }
    None
}

fn regular_mode(mode: u32) -> bool {
    mode & memfs::S_IFMT == memfs::S_IFREG
}

fn dir_mode(mode: u32) -> bool {
    mode & memfs::S_IFMT == memfs::S_IFDIR
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

pub fn backing_fill_probe_direct(opcode: u32, aligned_length: u64) -> i32 {
    if aligned_length == 0 {
        return crate::abi::EINVAL as i32;
    }
    (opcode == ring_buffer::FS_OP_MMAP && aligned_length >= DIRECT_BACKING_MMAP_MIN_BYTES) as i32
}

pub fn backing_fill_mode_decision(
    opcode: u32,
    aligned_length: u64,
    head_probe_readable: u32,
    tail_probe_readable: u32,
) -> i32 {
    let probe_direct = backing_fill_probe_direct(opcode, aligned_length);
    if probe_direct < 0 {
        return probe_direct;
    }
    if probe_direct == 0 {
        return super::SUPERVISOR_FS_BACKING_FILL_MODE_RESIDENT as i32;
    }
    if head_probe_readable != 0 && tail_probe_readable != 0 {
        return super::SUPERVISOR_FS_BACKING_FILL_MODE_DIRECT as i32;
    }
    super::SUPERVISOR_FS_BACKING_FILL_MODE_RESIDENT as i32
}

#[allow(clippy::too_many_arguments)]
pub fn backing_source_range_decision(
    ino: u32,
    file_offset: i64,
    length: i64,
    expected_size: i64,
    extent_offset: i64,
    extent_length: i64,
    source_byte_length: i64,
    require_source_bounds: u32,
) -> i32 {
    let mut decision = BackingSourceRangeDecision::empty();
    let mode = if !valid_ino(ino)
        || file_offset < 0
        || length <= 0
        || expected_size < 0
        || extent_offset < 0
        || extent_length < 0
        || file_offset >= expected_size
        || extent_length != expected_size
    {
        super::SUPERVISOR_FS_BACKING_SOURCE_RANGE_NONE as i32
    } else {
        let extent_offset = extent_offset as u64;
        let extent_length = extent_length as u64;
        let file_offset = file_offset as u64;
        let length = length as u64;
        let expected_size = expected_size as u64;
        if let (Some(source_end), Some(source_offset)) = (
            extent_offset.checked_add(extent_length),
            extent_offset.checked_add(file_offset),
        ) {
            if require_source_bounds != 0
                && (source_byte_length < 0 || source_end > source_byte_length as u64)
            {
                super::SUPERVISOR_FS_BACKING_SOURCE_RANGE_NONE as i32
            } else {
                decision = BackingSourceRangeDecision {
                    source_byte_length: source_end,
                    source_offset,
                    read_length: core::cmp::min(length, expected_size - file_offset),
                };
                super::SUPERVISOR_FS_BACKING_SOURCE_RANGE_READ as i32
            }
        } else {
            super::SUPERVISOR_FS_BACKING_SOURCE_RANGE_NONE as i32
        }
    };
    store_backing_source_range_decision(decision);
    mode
}

pub fn backing_source_range_source_byte_length() -> u64 {
    latest_backing_source_range_decision().source_byte_length
}

pub fn backing_source_range_source_offset() -> u64 {
    latest_backing_source_range_decision().source_offset
}

pub fn backing_source_range_read_length() -> u64 {
    latest_backing_source_range_decision().read_length
}

pub fn clean_backing_range_decision(
    ino: u32,
    offset: i64,
    length: i64,
    published_size: i64,
    backing_size: i64,
) -> i32 {
    let mut decision = CleanBackingRangeDecision::empty();
    let mode =
        if !valid_ino(ino) || offset < 0 || length <= 0 || published_size < 0 || backing_size < 0 {
            super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_NONE as i32
        } else {
            let offset = offset as u64;
            let length = length as u64;
            let published_size = published_size as u64;
            let backing_size = backing_size as u64;
            if let Some(end) = offset.checked_add(length) {
                if offset >= published_size {
                    super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_NONE as i32
                } else if offset >= backing_size {
                    if published_size > backing_size && end <= published_size {
                        decision = CleanBackingRangeDecision {
                            read_offset: offset,
                            read_length: 0,
                            output_length: length,
                        };
                        super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_ZERO as i32
                    } else {
                        super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_NONE as i32
                    }
                } else {
                    let read_length = core::cmp::min(length, backing_size - offset);
                    if read_length == length || published_size <= backing_size {
                        decision = CleanBackingRangeDecision {
                            read_offset: offset,
                            read_length,
                            output_length: read_length,
                        };
                        super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_READ as i32
                    } else if end > published_size {
                        super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_NONE as i32
                    } else {
                        decision = CleanBackingRangeDecision {
                            read_offset: offset,
                            read_length,
                            output_length: length,
                        };
                        super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_READ_ZERO_TAIL as i32
                    }
                }
            } else {
                super::SUPERVISOR_FS_CLEAN_BACKING_RANGE_NONE as i32
            }
        };
    store_clean_backing_range_decision(decision);
    mode
}

pub fn clean_backing_range_read_offset() -> u64 {
    latest_clean_backing_range_decision().read_offset
}

pub fn clean_backing_range_read_length() -> u64 {
    latest_clean_backing_range_decision().read_length
}

pub fn clean_backing_range_output_length() -> u64 {
    latest_clean_backing_range_decision().output_length
}

#[allow(clippy::too_many_arguments)]
pub fn dirty_prepare_decision(
    ino: u32,
    op: u32,
    expected_size: i64,
    published_present: u32,
    published_size: i64,
    published_file_object_id: u64,
    published_data_off: u64,
    source_is_regular: u32,
    source_file_object_id: u64,
    has_dirty_resident_pages: u32,
) -> i32 {
    let mut decision = DirtyPrepareDecision::empty();
    let result = if !valid_ino(ino)
        || expected_size < 0
        || published_size < 0
        || (op != super::SUPERVISOR_FS_DIRTY_PAGE_OP_WRITE
            && op != super::SUPERVISOR_FS_DIRTY_PAGE_OP_TRUNCATE)
    {
        crate::abi::EINVAL as i32
    } else {
        let expected_size = expected_size as u64;
        let published_size = if published_present != 0 {
            published_size as u64
        } else {
            expected_size
        };
        let source_truncated_empty = source_is_regular != 0 && expected_size == 0;
        let missing_source_object = source_file_object_id == 0;
        let unsupported_write_source = op == super::SUPERVISOR_FS_DIRTY_PAGE_OP_WRITE
            && missing_source_object
            && has_dirty_resident_pages == 0
            && published_file_object_id == 0
            && published_data_off == 0
            && published_size > 0
            && !source_truncated_empty;
        if unsupported_write_source {
            crate::abi::EOPNOTSUPP as i32
        } else {
            decision.publish_mode = if published_present == 0 {
                super::SUPERVISOR_FS_DIRTY_PREPARE_PUBLISH_MISSING
            } else if op == super::SUPERVISOR_FS_DIRTY_PAGE_OP_WRITE
                && source_is_regular != 0
                && published_size != expected_size
            {
                super::SUPERVISOR_FS_DIRTY_PREPARE_PUBLISH_SIZE_UPDATE
            } else {
                super::SUPERVISOR_FS_DIRTY_PREPARE_PUBLISH_NONE
            };
            0
        }
    };
    store_dirty_prepare_decision(decision);
    result
}

pub fn dirty_prepare_publish_mode() -> u32 {
    latest_dirty_prepare_decision().publish_mode
}

#[allow(clippy::too_many_arguments)]
pub fn data_sync_decision(
    kind: u32,
    ino: u32,
    source_mode: u32,
    source_size: i64,
    target_mode: u32,
    target_size: i64,
    published_present: u32,
    published_mode: u32,
    published_size: i64,
    published_file_object_id: u64,
    has_dirty_resident_pages: u32,
    page_map_newer: u32,
    has_backing_file: u32,
) -> i32 {
    if !valid_ino(ino) || source_size < 0 || target_size < 0 || published_size < 0 {
        return crate::abi::EINVAL as i32;
    }

    match kind {
        super::SUPERVISOR_FS_DATA_SYNC_KIND_EXPORT => {
            if !regular_mode(source_mode) || !regular_mode(target_mode) {
                return super::SUPERVISOR_FS_SYNC_ACTION_NONE as i32;
            }
            if published_present != 0 && !regular_mode(published_mode) {
                return super::SUPERVISOR_FS_SYNC_ACTION_NONE as i32;
            }
            let published_resident_file =
                published_file_object_id != 0 && published_size == source_size;
            if page_map_newer != 0 || published_resident_file {
                super::SUPERVISOR_FS_SYNC_ACTION_EXTERNALIZE as i32
            } else {
                super::SUPERVISOR_FS_SYNC_ACTION_NONE as i32
            }
        }
        super::SUPERVISOR_FS_DATA_SYNC_KIND_RESTORE => {
            if published_present == 0
                || !regular_mode(published_mode)
                || published_size <= 0
                || !regular_mode(target_mode)
                || target_size != published_size
            {
                return super::SUPERVISOR_FS_SYNC_ACTION_NONE as i32;
            }
            if has_backing_file != 0
                || has_dirty_resident_pages != 0
                || published_file_object_id != 0
            {
                super::SUPERVISOR_FS_SYNC_ACTION_EXTERNALIZE as i32
            } else {
                super::SUPERVISOR_FS_SYNC_ACTION_NONE as i32
            }
        }
        _ => crate::abi::EINVAL as i32,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn metadata_sync_decision(
    ino: u32,
    source_present: u32,
    source_mode: u32,
    source_size: i64,
    parent_present: u32,
    parent_ino: u32,
    published_present: u32,
    published_mode: u32,
    published_size: i64,
    published_parent_ino: u32,
    published_name_matches: u32,
    has_dirty_resident_pages: u32,
    backing_present: u32,
) -> i32 {
    store_metadata_sync_decision(MetadataSyncDecision::empty());
    if source_present == 0 {
        return super::SUPERVISOR_FS_METADATA_SYNC_ACTION_REMOVE as i32;
    }
    if !valid_ino(ino) || source_size < 0 || published_size < 0 {
        return crate::abi::EINVAL as i32;
    }
    if parent_present == 0 || parent_ino == 0 {
        return super::SUPERVISOR_FS_METADATA_SYNC_ACTION_NONE as i32;
    }
    let file_type_supported = regular_mode(source_mode) || dir_mode(source_mode);
    if !file_type_supported {
        return super::SUPERVISOR_FS_METADATA_SYNC_ACTION_NONE as i32;
    }

    let published_size = if published_present != 0 {
        published_size as u64
    } else {
        0
    };
    let size = if regular_mode(source_mode) {
        if has_dirty_resident_pages != 0 && published_present != 0 {
            published_size
        } else {
            source_size as u64
        }
    } else {
        0
    };
    let published_meta_valid =
        published_present != 0 && (published_size == size || has_dirty_resident_pages != 0);
    let backing_source = if has_dirty_resident_pages != 0 {
        if published_meta_valid {
            super::SUPERVISOR_FS_METADATA_BACKING_PUBLISHED
        } else {
            super::SUPERVISOR_FS_METADATA_BACKING_NONE
        }
    } else if backing_present != 0 {
        super::SUPERVISOR_FS_METADATA_BACKING_BACKING
    } else if published_meta_valid {
        super::SUPERVISOR_FS_METADATA_BACKING_PUBLISHED
    } else {
        super::SUPERVISOR_FS_METADATA_BACKING_NONE
    };
    store_metadata_sync_decision(MetadataSyncDecision {
        size,
        backing_source,
    });

    let publish_required = published_present == 0
        || published_mode != source_mode
        || published_size != size
        || published_parent_ino != parent_ino
        || published_name_matches == 0;
    if publish_required {
        super::SUPERVISOR_FS_METADATA_SYNC_ACTION_PUBLISH_ENSURE as i32
    } else {
        super::SUPERVISOR_FS_METADATA_SYNC_ACTION_ENSURE as i32
    }
}

pub fn metadata_sync_size() -> u64 {
    latest_metadata_sync_decision().size
}

pub fn metadata_sync_backing_source() -> u32 {
    latest_metadata_sync_decision().backing_source
}

pub fn metadata_full_sync_decision(tree_mutated: u32, handled_metadata_mutation: u32) -> i32 {
    if tree_mutated != 0 && handled_metadata_mutation == 0 {
        super::SUPERVISOR_FS_METADATA_FULL_SYNC_ACTION_REQUIRED as i32
    } else {
        super::SUPERVISOR_FS_METADATA_FULL_SYNC_ACTION_NONE as i32
    }
}

pub fn backing_object_decision(
    op: u32,
    ino: u32,
    published_file_object_id: u64,
    published_generation: u64,
    backing_file_object_id: u64,
    backing_generation: u64,
) -> i32 {
    store_backing_object_decision(BackingObjectDecision::empty());
    if !valid_ino(ino)
        || (published_file_object_id == 0 && published_generation != 0)
        || (published_file_object_id != 0
            && !valid_backing_identity(published_file_object_id, published_generation))
        || (backing_file_object_id == 0 && backing_generation != 0)
        || (backing_file_object_id != 0
            && !valid_backing_identity(backing_file_object_id, backing_generation))
    {
        return crate::abi::EINVAL as i32;
    }

    let decision = match op {
        super::SUPERVISOR_FS_BACKING_OBJECT_OP_SOURCE
        | super::SUPERVISOR_FS_BACKING_OBJECT_OP_MATERIALIZE => preserved_backing_generation(
            published_file_object_id,
            published_generation,
            backing_file_object_id,
            backing_generation,
        )
        .unwrap_or(BackingObjectDecision {
            file_object_id: ino as u64,
            generation: 1,
        }),
        super::SUPERVISOR_FS_BACKING_OBJECT_OP_REPLACE => {
            let file_object_id = if backing_file_object_id != 0 {
                backing_file_object_id
            } else if published_file_object_id != 0 {
                published_file_object_id
            } else {
                ino as u64
            };
            let base_generation = if backing_generation != 0 {
                backing_generation
            } else {
                published_generation
            };
            BackingObjectDecision {
                file_object_id,
                generation: next_generation(base_generation),
            }
        }
        super::SUPERVISOR_FS_BACKING_OBJECT_OP_FLUSH_WRITE
        | super::SUPERVISOR_FS_BACKING_OBJECT_OP_FLUSH_TRUNCATE => {
            if !valid_backing_identity(published_file_object_id, published_generation) {
                return crate::abi::EINVAL as i32;
            }
            BackingObjectDecision {
                file_object_id: published_file_object_id,
                generation: published_generation,
            }
        }
        _ => return crate::abi::EINVAL as i32,
    };

    if !valid_backing_identity(decision.file_object_id, decision.generation) {
        return crate::abi::EINVAL as i32;
    }
    store_backing_object_decision(decision);
    0
}

pub fn backing_object_file_object_id() -> u64 {
    latest_backing_object_decision().file_object_id
}

pub fn backing_object_generation() -> u64 {
    latest_backing_object_decision().generation
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

pub fn response_disposition(
    vm_ptr: u32,
    runtime_pid: i32,
    opcode: u32,
    result: i64,
    owner_async_status: i32,
    last_status: i32,
) -> u32 {
    let fs_succeeded = result >= 0;
    let current_pid = super::thread::state_from_ptr(vm_ptr)
        .map(|vm| crate::syscall::process::current_process_pid(vm, vm.guest_base))
        .unwrap_or(runtime_pid);
    let process_owner_matches = current_pid <= 0 || runtime_pid <= 0 || current_pid == runtime_pid;
    let failed_execve_child_owner =
        opcode == ring_buffer::FS_OP_EXECVE && !fs_succeeded && !process_owner_matches;
    let resolved_to_execve_spawn = opcode == ring_buffer::FS_OP_EXECVE
        && (super::thread::state_from_ptr(vm_ptr)
            .map(|vm| vm.status == crate::abi::STATUS_EXECVE_SPAWN)
            .unwrap_or(false)
            || owner_async_status == crate::abi::STATUS_EXECVE_SPAWN
            || last_status == crate::abi::STATUS_EXECVE_SPAWN);

    let mut flags = 0u32;
    if process_owner_matches {
        flags |= super::SUPERVISOR_FS_RESPONSE_FLAG_PROCESS_OWNER_MATCHES;
    }
    if failed_execve_child_owner {
        flags |= super::SUPERVISOR_FS_RESPONSE_FLAG_STORE_PENDING_KERNEL_STATE;
    } else {
        flags |= super::SUPERVISOR_FS_RESPONSE_FLAG_ADOPT_KERNEL_STATE;
        flags |= super::SUPERVISOR_FS_RESPONSE_FLAG_APPLY_GUEST_MEMORY_WRITES;
        flags |= super::SUPERVISOR_FS_RESPONSE_FLAG_CLEAR_TOMBSTONES;
    }
    if !failed_execve_child_owner && process_owner_matches {
        flags |= super::SUPERVISOR_FS_RESPONSE_FLAG_APPLY_LOCAL_METADATA;
    }
    if !failed_execve_child_owner && opcode != ring_buffer::FS_OP_MMAP {
        flags |= super::SUPERVISOR_FS_RESPONSE_FLAG_QUEUE_THREAD_WORKER_WRITES;
    }
    if opcode == ring_buffer::FS_OP_CLOSE || opcode == ring_buffer::FS_OP_EXECVE {
        flags |= super::SUPERVISOR_FS_RESPONSE_FLAG_FD_RESPONSE_MAY_CLEAR_LIVE_FDS;
    }
    if resolved_to_execve_spawn {
        flags |= super::SUPERVISOR_FS_RESPONSE_FLAG_RESOLVED_TO_EXECVE_SPAWN;
    }
    flags
}

pub fn local_metadata_action(
    opcode: u32,
    effects: u32,
    result: i64,
    has_primary_path: u32,
    has_secondary_path: u32,
) -> u32 {
    if result < 0
        || has_primary_path == 0
        || (effects & crate::syscall::fs::FS_EFFECT_MEMFS_MUTATION) == 0
    {
        return super::SUPERVISOR_FS_LOCAL_METADATA_ACTION_NONE;
    }
    match opcode {
        ring_buffer::FS_OP_UNLINK => super::SUPERVISOR_FS_LOCAL_METADATA_ACTION_TOMBSTONE_PRIMARY,
        ring_buffer::FS_OP_OPENAT | ring_buffer::FS_OP_MKDIR => {
            super::SUPERVISOR_FS_LOCAL_METADATA_ACTION_FORGET_PRIMARY
        }
        ring_buffer::FS_OP_RENAME if has_secondary_path != 0 => {
            super::SUPERVISOR_FS_LOCAL_METADATA_ACTION_FORGET_SECONDARY
        }
        _ => super::SUPERVISOR_FS_LOCAL_METADATA_ACTION_NONE,
    }
}

pub fn resident_page_slot_decision(
    existing_slot: i32,
    empty_slot: i32,
    clean_evict_slot: i32,
) -> i32 {
    if existing_slot >= 0 {
        existing_slot
    } else if empty_slot >= 0 {
        empty_slot
    } else if clean_evict_slot >= 0 {
        clean_evict_slot
    } else {
        -1
    }
}

pub fn resident_page_evict_status(record_found: u32, dirty: u32) -> u32 {
    if record_found == 0 {
        super::SUPERVISOR_FS_RESIDENT_PAGE_EVICT_NOT_FOUND
    } else if dirty != 0 {
        super::SUPERVISOR_FS_RESIDENT_PAGE_EVICT_DIRTY_PINNED
    } else {
        super::SUPERVISOR_FS_RESIDENT_PAGE_EVICT_EVICTED
    }
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
