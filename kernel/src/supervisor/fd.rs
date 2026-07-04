use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::abi::{
    FD_TYPE_FILE, FD_TYPE_PIPE, FD_TYPE_SOCKET, MAX_FDS, SYS_CLOSE, SYS_CLOSE_RANGE, SYS_EXECVE,
};
use crate::fs::fd_table;
use crate::types::{OpenFileDesc, ProcessState};

static FD_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static FD_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_FD_CONTROL: super::SupervisorFdControlRecord =
    super::SupervisorFdControlRecord::empty();
const FORK_SHARED_PEER_FLAG_COMPATIBLE: u32 = 1;
const FORK_SHARED_PEER_FLAG_INCOMPATIBLE: u32 = 1 << 1;
const FORK_SHARED_PEER_FLAG_PIPE_PEER: u32 = 1 << 2;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

pub(super) fn init() {
    FD_CONTROL_COUNT.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&FD_CONTROL_LOCK, || unsafe {
        LAST_FD_CONTROL = super::SupervisorFdControlRecord::empty();
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

pub fn fork_shared_peer_flag_compatible() -> u32 {
    FORK_SHARED_PEER_FLAG_COMPATIBLE
}

pub fn fork_shared_peer_flag_incompatible() -> u32 {
    FORK_SHARED_PEER_FLAG_INCOMPATIBLE
}

pub fn fork_shared_peer_flag_pipe_peer() -> u32 {
    FORK_SHARED_PEER_FLAG_PIPE_PEER
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

pub fn fd_entry_restore_action(
    vm_ptr: u32,
    fd: u32,
    snapshot_ofd_id: u32,
    syscall_nr: u64,
    flags: u32,
) -> i32 {
    if fd as usize >= MAX_FDS {
        return super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_SKIP as i32;
    }
    if syscall_may_clear_fd_entries(syscall_nr) {
        return super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_APPLY as i32;
    }
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_SKIP as i32;
    };
    let current_ofd_id =
        fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, fd as usize).ofd_id;
    if current_ofd_id == 0
        || current_ofd_id as usize >= MAX_FDS
        || current_ofd_id == snapshot_ofd_id
    {
        return super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_APPLY as i32;
    }
    if (flags & super::SUPERVISOR_FD_ENTRY_RESTORE_FLAG_PRESERVE_LIVE_REGULAR_FILE) != 0
        && fd_table::get_ofd_by_id(current_ofd_id)
            .is_some_and(|ofd| ofd.fd_type == FD_TYPE_FILE && ofd.refcount > 0)
    {
        return super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_SKIP as i32;
    }
    if (flags & super::SUPERVISOR_FD_ENTRY_RESTORE_FLAG_PRESERVE_LIVE_EPOLL_DEPENDENT) != 0
        && super::epoll::process_epoll_depends_on_ofd(vm_ptr, current_ofd_id) != 0
    {
        return super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_SKIP as i32;
    }
    super::SUPERVISOR_FD_ENTRY_RESTORE_ACTION_APPLY as i32
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
