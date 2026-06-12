use super::backend_cleanup::{self, BackendCleanup};
use super::entry::{
    clear_process_fd_entry_ptr, get_process_state, load_fd_entry_ptr, store_process_fd_entry_ptr,
};
use super::ofd::{clear as clear_ofd, is_ofd_reserved, set_offset_floor_by_id, table as ofd_table};
use crate::abi::*;
use crate::types::{FdEntry, ThreadState};

const CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;

pub(super) fn clear_pipe_eof_marker_for_fd(vm: &mut ThreadState, fd: u64) {
    if vm.fault_addr == crate::syscall::fs::PIPE_READ_EOF_SYNC_RETRY_MARKER && vm.fault_pc == fd {
        vm.fault_addr = 0;
        vm.fault_pc = 0;
    }
}

/// Drop one fd reference to an OFD and report the backend cleanup that must run
/// when this was the final fd hold.
///
/// The OFD slot itself is cleared immediately; callers may run the returned
/// backend cleanup locally today or defer it to the canonical owner kernel.
pub fn release_ofd_id_deferred(ofd_id: u32) -> Option<BackendCleanup> {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return None;
    }
    let slot = ofd_id as usize;
    let ofd = &mut ofd_table()[slot];
    if ofd.refcount <= 0 {
        return None;
    }
    ofd.refcount -= 1;
    if ofd.refcount > 0 {
        return None;
    }
    if is_ofd_reserved(ofd_id) {
        return None;
    }

    crate::syscall::epoll::release_interest_for_ofd(ofd_id);
    let cleanup = backend_cleanup::for_ofd(ofd_id, ofd);
    clear_ofd(ofd);
    set_offset_floor_by_id(ofd_id, 0);
    cleanup
}

/// Drop one fd reference to an OFD and run backend cleanup on last close.
pub fn release_ofd_id(ofd_id: u32) {
    if let Some(cleanup) = release_ofd_id_deferred(ofd_id) {
        backend_cleanup::run(cleanup);
    }
}

fn count_process_fd_refs(base: u32, vm: &ThreadState, ofd_id: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    unsafe {
        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return 0;
        }

        let mut refs = 0;
        for fd in 0..MAX_FDS {
            let entry = load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[fd]));
            if entry.ofd_id == ofd_id {
                refs += 1;
            }
        }
        refs
    }
}

pub(in crate::fs) fn release_process_fd_ref(base: u32, vm: &ThreadState, ofd_id: u32) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    let remaining_refs = count_process_fd_refs(base, vm, ofd_id);
    if remaining_refs > 0 {
        let ofd = &mut ofd_table()[ofd_id as usize];
        if ofd.fd_type != 0 && ofd.refcount <= remaining_refs {
            ofd.refcount = remaining_refs + 1;
        }
    }
    release_ofd_id(ofd_id);
}

/// close(fd)
pub fn sys_close(vm: &mut ThreadState, base: u32, fd: u64) -> i64 {
    unsafe {
        if fd as usize >= MAX_FDS {
            return EBADF;
        }

        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return EBADF;
        }

        let entry_ptr = core::ptr::addr_of_mut!((*ps).fd_table[fd as usize]);
        let entry = load_fd_entry_ptr(entry_ptr);
        if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS {
            return EBADF;
        }

        let ofd_id = entry.ofd_id;
        clear_process_fd_entry_ptr(ps, fd as usize);
        release_process_fd_ref(base, vm, ofd_id);
        clear_pipe_eof_marker_for_fd(vm, fd);

        vm.socket_timeout_ms = -1;
        0
    }
}

/// close_range(first, last, flags) closes or marks close-on-exec for an fd range.
///
/// Tidemark does not have per-thread fd-table sharing, so CLOSE_RANGE_UNSHARE
/// has no extra work here beyond applying the requested range operation.
pub fn sys_close_range(vm: &mut ThreadState, base: u32, first: u64, last: u64, flags: u64) -> i64 {
    if first > last {
        return EINVAL;
    }
    let supported_flags = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
    if flags & !supported_flags != 0 {
        return EINVAL;
    }

    unsafe {
        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return EBADF;
        }

        let start = first.min(MAX_FDS as u64) as usize;
        let end = last.min((MAX_FDS - 1) as u64) as usize;
        if start >= MAX_FDS {
            return 0;
        }

        for fd in start..=end {
            let entry_ptr = core::ptr::addr_of_mut!((*ps).fd_table[fd]);
            let entry = load_fd_entry_ptr(entry_ptr);
            if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS {
                continue;
            }
            if flags & CLOSE_RANGE_CLOEXEC != 0 {
                store_process_fd_entry_ptr(
                    ps,
                    fd,
                    FdEntry {
                        ofd_id: entry.ofd_id,
                        fd_flags: entry.fd_flags | crate::fs::fd_table::FD_CLOEXEC,
                    },
                );
                continue;
            }
            clear_process_fd_entry_ptr(ps, fd);
            release_process_fd_ref(base, vm, entry.ofd_id);
            clear_pipe_eof_marker_for_fd(vm, fd as u64);
        }
    }

    vm.socket_timeout_ms = -1;
    0
}

/// Drop every fd reference still held by this process.
pub fn close_all_for_process(base: u32, vm: &ThreadState) {
    unsafe {
        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return;
        }

        for index in 0..MAX_FDS {
            let entry_ptr = core::ptr::addr_of_mut!((*ps).fd_table[index]);
            let entry = load_fd_entry_ptr(entry_ptr);
            let ofd_id = entry.ofd_id;
            clear_process_fd_entry_ptr(ps, index);
            let ofd_idx = ofd_id as usize;
            if ofd_id == 0 || ofd_idx >= MAX_FDS {
                continue;
            }
            release_ofd_id(ofd_id);
        }
    }
}

/// Drop every fd reference still held by this process without
/// mutating backend control planes. Used by runtime-owned vfork restore paths:
/// the canonical owner kernel already accounts for pipe/epoll/socket cleanup,
/// but the local kernel must still forget the transient child fd holds so later
/// parent-local close semantics do not retain stale references.
pub fn close_all_for_process_without_backend_cleanup(base: u32, vm: &ThreadState) {
    unsafe {
        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return;
        }

        for index in 0..MAX_FDS {
            let entry_ptr = core::ptr::addr_of_mut!((*ps).fd_table[index]);
            let entry = load_fd_entry_ptr(entry_ptr);
            let ofd_id = entry.ofd_id;
            clear_process_fd_entry_ptr(ps, index);
            let ofd_idx = ofd_id as usize;
            if ofd_id == 0 || ofd_idx >= MAX_FDS {
                continue;
            }
            let _ = release_ofd_id_deferred(ofd_id);
        }
    }
}
