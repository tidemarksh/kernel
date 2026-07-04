use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::abi::{
    FD_TYPE_FILE, FD_TYPE_PIPE, FD_TYPE_PTY_MASTER, FD_TYPE_PTY_SLAVE, FD_TYPE_SOCKET, MAX_FDS,
    SYS_CLOSE, SYS_CLOSE_RANGE, SYS_EXECVE, SYS_LSEEK,
};
use crate::fs::fd_table;
use crate::types::{FdEntry, OpenFileDesc, ProcessState};

static FD_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static FD_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_FD_CONTROL: super::SupervisorFdControlRecord =
    super::SupervisorFdControlRecord::empty();
static OFD_RESTORE_OFFSET_LOCK: AtomicU32 = AtomicU32::new(0);
#[derive(Clone, Copy)]
struct OfdRestoreOffsetFloor {
    host_fd: i32,
    ino: u32,
    offset: i64,
    valid: bool,
}
const EMPTY_OFD_RESTORE_OFFSET_FLOOR: OfdRestoreOffsetFloor = OfdRestoreOffsetFloor {
    host_fd: 0,
    ino: 0,
    offset: 0,
    valid: false,
};
static mut OFD_RESTORE_OFFSET_FLOORS: [OfdRestoreOffsetFloor; MAX_FDS] =
    [EMPTY_OFD_RESTORE_OFFSET_FLOOR; MAX_FDS];
const FORK_SHARED_PEER_FLAG_COMPATIBLE: u32 = 1;
const FORK_SHARED_PEER_FLAG_INCOMPATIBLE: u32 = 1 << 1;
const FORK_SHARED_PEER_FLAG_PIPE_PEER: u32 = 1 << 2;
const FORK_SHARED_HELD_OFD_TRACK_FLAG_SHARED: u32 = 1;
const FORK_SHARED_HELD_OFD_TRACK_FLAG_HOST_STDIO_PIPE: u32 = 1 << 1;
const FORK_SHARED_HELD_OFD_TRACK_FLAG_STDIO_FD: u32 = 1 << 2;
const FORK_SHARED_HELD_OFD_TRACK_FLAG_FD_ENTRY_SOURCE: u32 = 1 << 3;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

pub(super) fn init() {
    FD_CONTROL_COUNT.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&FD_CONTROL_LOCK, || unsafe {
        LAST_FD_CONTROL = super::SupervisorFdControlRecord::empty();
    });
    super::lock::with_spin_lock(&OFD_RESTORE_OFFSET_LOCK, || unsafe {
        OFD_RESTORE_OFFSET_FLOORS = [EMPTY_OFD_RESTORE_OFFSET_FLOOR; MAX_FDS];
    });
}

pub fn fd_control_count() -> u64 {
    FD_CONTROL_COUNT.load(Ordering::Relaxed)
}

pub(super) fn process_state_from_vm_ptr(vm_ptr: u32) -> Option<&'static ProcessState> {
    let vm = super::thread::state_from_ptr(vm_ptr)?;
    if vm.process_ptr == 0 {
        return None;
    }
    let absolute = (vm.guest_base as u64).checked_add(vm.process_ptr as u64)?;
    let align = core::mem::align_of::<ProcessState>() as u64;
    if (absolute & (align - 1)) != 0 {
        return None;
    }
    let end = absolute.checked_add(core::mem::size_of::<ProcessState>() as u64)?;
    let memory_size = crate::wasm::memory_size_bytes();
    if memory_size == 0 || end > memory_size {
        return None;
    }
    Some(unsafe { &*(absolute as *const ProcessState) })
}

pub(super) fn for_each_process_held_ofd<F>(vm_ptr: u32, mut f: F)
where
    F: FnMut(u32, OpenFileDesc),
{
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return;
    };
    let Some(ps) = process_state_from_vm_ptr(vm_ptr) else {
        return;
    };

    for fd in 0..MAX_FDS {
        let entry = fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, fd);
        let ofd_id = entry.ofd_id;
        if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
            continue;
        }
        if let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) {
            f(ofd_id, ofd);
        }
    }

    for thread in ps.threads.iter() {
        let Some(thread_vm) = super::thread::state_from_ptr(thread.thread_ptr) else {
            continue;
        };
        if thread_vm.guest_base != vm.guest_base
            || thread_vm.process_ptr != vm.process_ptr
            || thread_vm.tid != thread.tid
        {
            continue;
        }
        let ofd_id = thread_vm.blocked_ofd_id;
        if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
            continue;
        }
        if let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) {
            f(ofd_id, ofd);
        }
    }
}

pub fn process_held_ofd_refcount(vm_ptr: u32, ofd_id: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let mut refcount = 0i32;
    for_each_process_held_ofd(vm_ptr, |held_ofd_id, _| {
        if held_ofd_id == ofd_id {
            refcount = refcount.saturating_add(1);
        }
    });
    refcount
}

pub fn process_holds_regular_file_ofd(vm_ptr: u32, ofd_id: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    if process_held_ofd_refcount(vm_ptr, ofd_id) <= 0 {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    if ofd.fd_type != FD_TYPE_FILE {
        return 0;
    }
    1
}

fn process_fd_entry(vm_ptr: u32, fd: u32) -> Option<FdEntry> {
    if fd as usize >= MAX_FDS {
        return None;
    }
    let vm = super::thread::state_from_ptr(vm_ptr)?;
    process_state_from_vm_ptr(vm_ptr)?;
    Some(fd_table::load_process_fd_entry(
        vm.guest_base,
        vm.process_ptr,
        fd as usize,
    ))
}

pub fn process_ofd_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    process_fd_entry(vm_ptr, fd).map_or(0, |entry| {
        if entry.ofd_id > 0 && (entry.ofd_id as usize) < MAX_FDS {
            entry.ofd_id
        } else {
            0
        }
    })
}

pub fn process_fd_flags_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    process_fd_entry(vm_ptr, fd).map_or(0, |entry| entry.fd_flags)
}

pub fn process_fd_is_open(vm_ptr: u32, fd: u32) -> i32 {
    i32::from(process_ofd_for_fd(vm_ptr, fd) != 0)
}

pub(super) fn process_fd_ofd(vm_ptr: u32, fd: u32) -> Option<(u32, OpenFileDesc)> {
    let ofd_id = process_ofd_for_fd(vm_ptr, fd);
    if ofd_id == 0 {
        return None;
    }
    fd_table::get_ofd_by_id(ofd_id).map(|ofd| (ofd_id, ofd))
}

fn ofd_by_id(ofd_id: u32) -> Option<OpenFileDesc> {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return None;
    }
    fd_table::get_ofd_by_id(ofd_id)
}

pub fn ofd_fd_type(ofd_id: u32) -> i32 {
    ofd_by_id(ofd_id).map_or(0, |ofd| ofd.fd_type)
}

pub fn ofd_host_fd(ofd_id: u32) -> i32 {
    ofd_by_id(ofd_id).map_or(-1, |ofd| ofd.host_fd)
}

pub fn ofd_status_flags(ofd_id: u32) -> i32 {
    ofd_by_id(ofd_id).map_or(0, |ofd| ofd.status_flags)
}

pub fn ofd_ino(ofd_id: u32) -> u32 {
    ofd_by_id(ofd_id).map_or(0, |ofd| ofd.ino)
}

pub fn ofd_refcount(ofd_id: u32) -> i32 {
    ofd_by_id(ofd_id).map_or(0, |ofd| ofd.refcount)
}

pub fn ofd_offset(ofd_id: u32) -> i64 {
    ofd_by_id(ofd_id).map_or(0, |ofd| ofd.offset)
}

pub fn ofd_is_regular_file(ofd_id: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    if ofd.fd_type == FD_TYPE_FILE {
        return 1;
    }
    0
}

pub fn pipe_sync_ofd_candidate(ofd_id: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    match ofd.fd_type {
        FD_TYPE_PIPE | FD_TYPE_PTY_MASTER | FD_TYPE_PTY_SLAVE => 1,
        _ => 0,
    }
}

pub fn fork_shared_peer_flag_compatible() -> u32 {
    FORK_SHARED_PEER_FLAG_COMPATIBLE
}

pub fn fork_shared_peer_flag_incompatible() -> u32 {
    FORK_SHARED_PEER_FLAG_INCOMPATIBLE
}

pub fn fork_shared_peer_flag_pipe_peer() -> u32 {
    FORK_SHARED_PEER_FLAG_PIPE_PEER
}

pub fn fork_shared_held_ofd_track_flag_shared() -> u32 {
    FORK_SHARED_HELD_OFD_TRACK_FLAG_SHARED
}

pub fn fork_shared_held_ofd_track_flag_host_stdio_pipe() -> u32 {
    FORK_SHARED_HELD_OFD_TRACK_FLAG_HOST_STDIO_PIPE
}

pub fn fork_shared_held_ofd_track_flag_stdio_fd() -> u32 {
    FORK_SHARED_HELD_OFD_TRACK_FLAG_STDIO_FD
}

pub fn fork_shared_held_ofd_track_flag_fd_entry_source() -> u32 {
    FORK_SHARED_HELD_OFD_TRACK_FLAG_FD_ENTRY_SOURCE
}

pub fn fork_shared_held_ofd_track_action(ofd_id: u32, flags: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    if (flags & FORK_SHARED_HELD_OFD_TRACK_FLAG_HOST_STDIO_PIPE) != 0 {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    if (flags
        & (FORK_SHARED_HELD_OFD_TRACK_FLAG_SHARED
            | FORK_SHARED_HELD_OFD_TRACK_FLAG_STDIO_FD
            | FORK_SHARED_HELD_OFD_TRACK_FLAG_FD_ENTRY_SOURCE))
        != 0
    {
        return 1;
    }
    if ofd.fd_type == FD_TYPE_FILE {
        return 0;
    }
    1
}

fn fold_identity_part(hash: u64, value: u64) -> u64 {
    let mut next = hash ^ value;
    next = next.wrapping_mul(FNV_PRIME);
    next
}

pub fn fork_shared_ofd_identity_key(ofd_id: u32) -> u64 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    if ofd.fd_type <= 0 {
        return 0;
    }
    let endpoint_or_host_fd = match ofd.fd_type {
        FD_TYPE_PIPE => {
            if ofd.host_fd >= 0 {
                1
            } else {
                2
            }
        }
        FD_TYPE_SOCKET => ofd.host_fd as u64,
        _ => 0,
    };
    let hash = fold_identity_part(FNV_OFFSET, ofd.fd_type as u64);
    let hash = fold_identity_part(hash, ofd.ino as u64);
    let hash = fold_identity_part(hash, endpoint_or_host_fd);
    if hash == 0 { FNV_OFFSET } else { hash }
}

pub fn fork_shared_ofd_publish_action(ofd_id: u32, peer_flags: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    if ofd.fd_type <= 0 {
        return 0;
    }
    if (peer_flags & FORK_SHARED_PEER_FLAG_INCOMPATIBLE) != 0 {
        return 0;
    }
    let compatible_peer = (peer_flags & FORK_SHARED_PEER_FLAG_COMPATIBLE) != 0;
    let pipe_peer = (peer_flags & FORK_SHARED_PEER_FLAG_PIPE_PEER) != 0;
    match ofd.fd_type {
        FD_TYPE_FILE => i32::from(compatible_peer),
        FD_TYPE_PIPE => i32::from(compatible_peer || pipe_peer),
        _ => 1,
    }
}

pub fn fork_shared_effect_sync_action(
    has_effect: i32,
    has_tracked_state: i32,
    source_holds_regular_file: i32,
    regular_file_has_peer: i32,
) -> i32 {
    if has_effect == 0 || has_tracked_state == 0 {
        return 0;
    }
    if source_holds_regular_file != 0 && regular_file_has_peer == 0 {
        return 0;
    }
    1
}

fn syscall_may_clear_fd_entries(syscall_nr: u64) -> bool {
    matches!(syscall_nr, SYS_CLOSE | SYS_CLOSE_RANGE | SYS_EXECVE)
}

fn restore_apply() -> i32 {
    super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_APPLY as i32
}

fn restore_skip() -> i32 {
    super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_SKIP as i32
}

fn fd_type_is_pipe_like(fd_type: i32) -> bool {
    matches!(
        fd_type,
        FD_TYPE_PIPE | FD_TYPE_PTY_MASTER | FD_TYPE_PTY_SLAVE
    )
}

fn regular_file_ofds_share_identity(current: OpenFileDesc, candidate: OpenFileDesc) -> bool {
    current.fd_type == FD_TYPE_FILE
        && candidate.fd_type == FD_TYPE_FILE
        && current.host_fd == candidate.host_fd
        && current.ino == candidate.ino
}

fn ofd_restore_offset_floor(
    ofd_id: u32,
    host_fd: i32,
    ino: u32,
    current_offset: i64,
    candidate_offset: i64,
) -> i64 {
    super::lock::with_spin_lock(&OFD_RESTORE_OFFSET_LOCK, || unsafe {
        let floor = &mut OFD_RESTORE_OFFSET_FLOORS[ofd_id as usize];
        if !floor.valid || floor.host_fd != host_fd || floor.ino != ino {
            *floor = OfdRestoreOffsetFloor {
                host_fd,
                ino,
                offset: current_offset,
                valid: true,
            };
        }
        let max_seen = floor.offset;
        let next_max = current_offset.max(candidate_offset);
        if next_max > floor.offset {
            floor.offset = next_max;
        }
        max_seen
    })
}

pub fn fd_entry_guest_write_action(
    vm_ptr: u32,
    fd: u32,
    candidate_ofd_id: u32,
    explicit_ofd_id: u32,
) -> i32 {
    if fd as usize >= MAX_FDS || candidate_ofd_id as usize >= MAX_FDS {
        return restore_apply();
    }
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return restore_apply();
    };
    let current_ofd_id =
        fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, fd as usize).ofd_id;
    if current_ofd_id == 0
        || current_ofd_id as usize >= MAX_FDS
        || current_ofd_id == candidate_ofd_id
    {
        return restore_apply();
    }
    let Some(current) = fd_table::get_ofd_by_id(current_ofd_id) else {
        return restore_apply();
    };
    if explicit_ofd_id == current_ofd_id && fd_type_is_pipe_like(current.fd_type) {
        return restore_skip();
    }
    let Some(candidate) = fd_table::get_ofd_by_id(candidate_ofd_id) else {
        return restore_apply();
    };
    if current.refcount > 0
        && regular_file_ofds_share_identity(current, candidate)
        && candidate.offset < current.offset
    {
        return restore_skip();
    }
    restore_apply()
}

pub fn ofd_slot_write_action(
    ofd_id: u32,
    candidate_type: i32,
    candidate_host_fd: i32,
    candidate_ino: u32,
    candidate_offset: i64,
) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return restore_skip();
    }
    let Some(current) = fd_table::get_ofd_by_id(ofd_id) else {
        return restore_apply();
    };
    if current.fd_type == 0 || current.refcount <= 0 {
        return restore_apply();
    }
    if candidate_type == 0 || candidate_type != current.fd_type {
        return restore_skip();
    }
    if candidate_host_fd != current.host_fd || candidate_ino != current.ino {
        return restore_skip();
    }
    if current.fd_type == FD_TYPE_FILE && candidate_offset < current.offset {
        return restore_skip();
    }
    restore_apply()
}

pub fn ofd_slot_restore_action(
    ofd_id: u32,
    candidate_type: i32,
    candidate_host_fd: i32,
    candidate_ino: u32,
    candidate_offset: i64,
    syscall_nr: u64,
    flags: u32,
) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return restore_skip();
    }
    let Some(current) = fd_table::get_ofd_by_id(ofd_id) else {
        return restore_apply();
    };
    if current.fd_type == 0 || current.refcount <= 0 {
        return restore_apply();
    }
    let referenced_by_fd_entry =
        (flags & super::SUPERVISOR_OFD_SLOT_RESTORE_FLAG_REFERENCED_BY_FD_ENTRY) != 0;
    if !referenced_by_fd_entry {
        if candidate_type == 0 || candidate_type != current.fd_type {
            return restore_skip();
        }
        if candidate_host_fd != current.host_fd || candidate_ino != current.ino {
            return restore_skip();
        }
    }
    let trust_regular_file_offset =
        (flags & super::SUPERVISOR_OFD_SLOT_RESTORE_FLAG_TRUST_REGULAR_FILE_OFFSET) != 0;
    if trust_regular_file_offset
        || current.fd_type != FD_TYPE_FILE
        || candidate_type != FD_TYPE_FILE
    {
        return restore_apply();
    }
    if candidate_host_fd != current.host_fd || candidate_ino != current.ino {
        return restore_apply();
    }
    let max_seen = ofd_restore_offset_floor(
        ofd_id,
        current.host_fd,
        current.ino,
        current.offset,
        candidate_offset,
    );
    if candidate_offset < max_seen {
        return restore_skip();
    }
    if candidate_offset >= current.offset {
        return restore_apply();
    }
    if syscall_nr == SYS_LSEEK {
        return restore_apply();
    }
    restore_skip()
}

pub fn regular_file_offset_restore_action(
    ofd_id: u32,
    snapshot_host_fd: i32,
    snapshot_ino: u32,
    snapshot_offset: i64,
) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return restore_skip();
    }
    let Some(current) = fd_table::get_ofd_by_id(ofd_id) else {
        return restore_skip();
    };
    if current.fd_type != FD_TYPE_FILE
        || current.refcount <= 0
        || current.host_fd != snapshot_host_fd
        || current.ino != snapshot_ino
        || current.offset >= snapshot_offset
    {
        return restore_skip();
    }
    restore_apply()
}

pub fn fd_entry_restore_action(
    vm_ptr: u32,
    fd: u32,
    snapshot_ofd_id: u32,
    syscall_nr: u64,
    flags: u32,
) -> i32 {
    if fd as usize >= MAX_FDS {
        return restore_skip();
    }
    if syscall_may_clear_fd_entries(syscall_nr) {
        return restore_apply();
    }
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return restore_skip();
    };
    let current_ofd_id =
        fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, fd as usize).ofd_id;
    if current_ofd_id == 0
        || current_ofd_id as usize >= MAX_FDS
        || current_ofd_id == snapshot_ofd_id
    {
        return restore_apply();
    }
    if (flags & super::SUPERVISOR_FD_ENTRY_RESTORE_FLAG_PRESERVE_LIVE_REGULAR_FILE) != 0
        && fd_table::get_ofd_by_id(current_ofd_id)
            .is_some_and(|ofd| ofd.fd_type == FD_TYPE_FILE && ofd.refcount > 0)
    {
        return restore_skip();
    }
    if (flags & super::SUPERVISOR_FD_ENTRY_RESTORE_FLAG_PRESERVE_LIVE_EPOLL_DEPENDENT) != 0
        && super::epoll::process_epoll_depends_on_ofd(vm_ptr, current_ofd_id) != 0
    {
        return restore_skip();
    }
    restore_apply()
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
