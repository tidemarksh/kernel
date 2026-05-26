use crate::abi::*;
use crate::types::{FdEntry, ProcessState, ThreadState};
use core::sync::atomic::{AtomicU32, Ordering};

pub(in crate::fs) fn get_process_state(base: u32, vm: &ThreadState) -> *mut ProcessState {
    (base as u64 + vm.process_ptr as u64) as *mut ProcessState
}

pub fn load_process_fd_entry(base: u32, process_ptr: u32, fd: usize) -> FdEntry {
    if process_ptr == 0 || fd >= MAX_FDS {
        return FdEntry {
            ofd_id: 0,
            fd_flags: 0,
        };
    }
    let ps = (base as u64 + process_ptr as u64) as *const ProcessState;
    unsafe { load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[fd])) }
}

pub fn store_process_fd_entry(base: u32, process_ptr: u32, fd: usize, entry: FdEntry) {
    if process_ptr == 0 || fd >= MAX_FDS {
        return;
    }
    let ps = (base as u64 + process_ptr as u64) as *mut ProcessState;
    unsafe {
        store_fd_entry_ptr(core::ptr::addr_of_mut!((*ps).fd_table[fd]), entry);
    }
}

#[inline(always)]
pub(in crate::fs) unsafe fn load_fd_entry_ptr(entry: *const FdEntry) -> FdEntry {
    unsafe {
        let ofd_id =
            (&*(core::ptr::addr_of!((*entry).ofd_id) as *const AtomicU32)).load(Ordering::Acquire);
        let fd_flags = (&*(core::ptr::addr_of!((*entry).fd_flags) as *const AtomicU32))
            .load(Ordering::Relaxed);
        FdEntry { ofd_id, fd_flags }
    }
}

#[inline(always)]
pub(in crate::fs) unsafe fn store_fd_entry_ptr(entry: *mut FdEntry, value: FdEntry) {
    unsafe {
        (&*(core::ptr::addr_of!((*entry).fd_flags) as *const AtomicU32))
            .store(value.fd_flags, Ordering::Relaxed);
        (&*(core::ptr::addr_of!((*entry).ofd_id) as *const AtomicU32))
            .store(value.ofd_id, Ordering::Release);
    }
}

#[inline(always)]
pub(in crate::fs) unsafe fn clear_fd_entry_ptr(entry: *mut FdEntry) {
    unsafe {
        (&*(core::ptr::addr_of!((*entry).ofd_id) as *const AtomicU32)).store(0, Ordering::Release);
        (&*(core::ptr::addr_of!((*entry).fd_flags) as *const AtomicU32))
            .store(0, Ordering::Relaxed);
    }
}

/// Get FD entry from ProcessState. Returns None if out of range or unused.
pub(in crate::fs) unsafe fn get_fd_entry(base: u32, vm: &ThreadState, fd: u64) -> Option<FdEntry> {
    if fd as usize >= MAX_FDS {
        return None;
    }
    let ps = get_process_state(base, vm);
    if ps.is_null() {
        return None;
    }
    unsafe {
        let entry = load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[fd as usize]));
        if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS {
            return None;
        }
        Some(entry)
    }
}

/// Find the lowest available FD >= min_fd.
pub(in crate::fs) unsafe fn find_free_fd(
    base: u32,
    vm: &ThreadState,
    min_fd: usize,
) -> Option<usize> {
    let ps = get_process_state(base, vm);
    if ps.is_null() {
        return None;
    }
    unsafe {
        for i in min_fd..MAX_FDS {
            if load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[i])).ofd_id == 0 {
                return Some(i);
            }
        }
    }
    None
}
