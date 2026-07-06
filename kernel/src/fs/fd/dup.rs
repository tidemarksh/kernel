use super::entry::{
    clear_process_fd_entry_ptr, find_free_fd, get_fd_entry, get_process_state, load_fd_entry_ptr,
    store_process_fd_entry_ptr,
};
use super::ofd::table as ofd_table;
use crate::abi::*;
use crate::types::{FdEntry, ThreadState};

fn record_fd_duplicated(
    vm: &ThreadState,
    base: u32,
    oldfd: u64,
    newfd: u64,
    ofd_id: u32,
    fd_flags: u32,
) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    let ofd = ofd_table()[ofd_id as usize];
    crate::supervisor::record_fd_control(
        crate::supervisor::SUPERVISOR_FD_CONTROL_KIND_FD_DUPLICATED,
        vm as *const ThreadState as u32,
        vm.process_ptr,
        crate::syscall::process::current_process_pid(vm, base),
        oldfd as u32,
        newfd as u32,
        ofd_id,
        ofd_id,
        ofd.fd_type as u32,
        ofd.ino,
        ofd.offset as u32,
        newfd as i64,
        fd_flags as u64,
        ofd.refcount as u64,
        0,
    );
}

/// dup(oldfd) -> newfd
pub fn sys_dup(vm: &mut ThreadState, base: u32, oldfd: u64) -> i64 {
    unsafe {
        let entry = match get_fd_entry(base, vm, oldfd) {
            Some(entry) => entry,
            None => return EBADF,
        };
        let newfd = match find_free_fd(base, vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(base, vm);
        crate::fs::fd_table::retain_ofd_id(entry.ofd_id);
        store_process_fd_entry_ptr(
            ps,
            newfd,
            FdEntry {
                ofd_id: entry.ofd_id,
                fd_flags: 0, // dup clears FD_CLOEXEC
            },
        );
        record_fd_duplicated(vm, base, oldfd, newfd as u64, entry.ofd_id, 0);
        newfd as i64
    }
}

/// dup3(oldfd, newfd, flags) -> newfd
pub fn sys_dup3(vm: &mut ThreadState, base: u32, oldfd: u64, newfd: u64, flags: u64) -> i64 {
    unsafe {
        if flags & !(O_CLOEXEC as u64) != 0 {
            return EINVAL;
        }
        if oldfd == newfd {
            return EINVAL;
        }
        if newfd as usize >= MAX_FDS {
            return EBADF;
        }

        let entry = match get_fd_entry(base, vm, oldfd) {
            Some(entry) => entry,
            None => return EBADF,
        };

        let ps = get_process_state(base, vm);

        // dup3 atomically replaces newfd. Retain oldfd's OFD before closing
        // newfd so aliasing descriptors do not drop the shared OFD to zero.
        let old_new_ptr = core::ptr::addr_of_mut!((*ps).fd_table[newfd as usize]);
        let old_new = load_fd_entry_ptr(old_new_ptr);
        let old_new_ofd = if old_new.ofd_id != 0 && (old_new.ofd_id as usize) < MAX_FDS {
            Some(ofd_table()[old_new.ofd_id as usize])
        } else {
            None
        };
        crate::fs::fd_table::retain_ofd_id(entry.ofd_id);
        if old_new.ofd_id != 0 {
            clear_process_fd_entry_ptr(ps, newfd as usize);
            super::close::release_process_fd_ref(base, vm, old_new.ofd_id);
            super::close::clear_pipe_eof_marker_for_fd(vm, newfd);
            if let Some(ofd) = old_new_ofd {
                super::close::record_fd_closed(vm, base, newfd, old_new.ofd_id, ofd);
            }
        }

        let cloexec = if (flags as i32 & O_CLOEXEC) != 0 {
            crate::fs::fd_table::FD_CLOEXEC
        } else {
            0
        };
        store_process_fd_entry_ptr(
            ps,
            newfd as usize,
            FdEntry {
                ofd_id: entry.ofd_id,
                fd_flags: cloexec,
            },
        );
        record_fd_duplicated(vm, base, oldfd, newfd, entry.ofd_id, cloexec);
        newfd as i64
    }
}
