//! FD table and OFD (Open File Description) table management.
//!
//! FD table lives in guest Memory (ProcessState) — dup/close(refcount>1)/fcntl
//! operate without kernel Worker.
//!
//! OFD table lives in kernel Worker (the kernel Worker model). For the current single-process model, we use a static
//! table and operate directly.
//!
//! fcntl commands (https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/fcntl.h):
//!   F_DUPFD    = 0   dup to >= arg
//!   F_GETFD    = 1   get close_on_exec
//!   F_SETFD    = 2   set close_on_exec
//!   F_GETFL    = 3   get file status flags
//!   F_SETFL    = 4   set file status flags
//!   FD_CLOEXEC = 1

use crate::abi::*;
use crate::types::{ThreadState, ProcessState, FdEntry, OpenFileDesc};

// fcntl commands
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;

const FD_CLOEXEC: u32 = 1;

/// Pointer to OFD table in kernel Worker linear memory.
static mut OFD_TABLE_PTR: *mut [OpenFileDesc; MAX_FDS] = core::ptr::null_mut();

fn ofd_table() -> &'static mut [OpenFileDesc; MAX_FDS] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(OFD_TABLE_PTR));
        &mut *p
    }
}

/// Initialize OFD table. Allocates via alloc.rs.
pub fn init() {
    unsafe {
        let size = core::mem::size_of::<[OpenFileDesc; MAX_FDS]>() as u32;
        let align = core::mem::align_of::<OpenFileDesc>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 { core::arch::wasm32::unreachable(); }
        core::ptr::write(core::ptr::addr_of_mut!(OFD_TABLE_PTR), ptr as *mut [OpenFileDesc; MAX_FDS]);
    }
}

/// Get the ProcessState from guest memory.
unsafe fn get_process_state(vm: &ThreadState) -> *mut ProcessState {
    vm.process_ptr as *mut ProcessState
}

/// Get FD entry from ProcessState. Returns None if out of range or unused.
unsafe fn get_fd_entry(vm: &ThreadState, fd: u64) -> Option<&mut FdEntry> {
    if fd as usize >= MAX_FDS { return None; }
    let ps = get_process_state(vm);
    if ps.is_null() { return None; }
    let entry = &mut (*ps).fd_table[fd as usize];
    if entry.ofd_id == 0 { return None; }
    Some(entry)
}

/// Find the lowest available FD >= min_fd.
unsafe fn find_free_fd(vm: &ThreadState, min_fd: usize) -> Option<usize> {
    let ps = get_process_state(vm);
    if ps.is_null() { return None; }
    for i in min_fd..MAX_FDS {
        if (*ps).fd_table[i].ofd_id == 0 {
            return Some(i);
        }
    }
    None
}

/// Allocate a new OFD slot. Returns ofd_id (1-based), or 0 on failure.
unsafe fn alloc_ofd(fd_type: i32, status_flags: i32) -> u32 {
    for i in 1..MAX_FDS {
        if ofd_table()[i].refcount == 0 {
            ofd_table()[i] = OpenFileDesc {
                fd_type,
                host_fd: -1,
                status_flags,
                refcount: 1,
                offset: 0,
                ino: 0,
                _pad: 0,
            };
            return i as u32;
        }
    }
    0
}

// =========================================================================
// syscall implementations
// =========================================================================

/// dup(oldfd) → newfd
pub fn sys_dup(vm: &mut ThreadState, _base: u32, oldfd: u64) -> i64 {
    unsafe {
        let entry = match get_fd_entry(vm, oldfd) {
            Some(e) => *e,
            None => return EBADF,
        };
        let newfd = match find_free_fd(vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(vm);
        (*ps).fd_table[newfd] = FdEntry {
            ofd_id: entry.ofd_id,
            fd_flags: 0, // dup clears FD_CLOEXEC
        };
        ofd_table()[entry.ofd_id as usize].refcount += 1;
        newfd as i64
    }
}

/// dup3(oldfd, newfd, flags) → newfd
pub fn sys_dup3(vm: &mut ThreadState, _base: u32, oldfd: u64, newfd: u64, flags: u64) -> i64 {
    unsafe {
        if oldfd == newfd { return EINVAL; }
        if newfd as usize >= MAX_FDS { return EBADF; }

        let entry = match get_fd_entry(vm, oldfd) {
            Some(e) => *e,
            None => return EBADF,
        };

        let ps = get_process_state(vm);

        // Close newfd if it's open
        let old_new = &(*ps).fd_table[newfd as usize];
        if old_new.ofd_id != 0 {
            let ofd = &mut ofd_table()[old_new.ofd_id as usize];
            ofd.refcount -= 1;
            // If refcount reaches 0, the kernel Worker model would send to kernel Worker for cleanup
        }

        let cloexec = if (flags as i32 & O_CLOEXEC) != 0 { FD_CLOEXEC } else { 0 };
        (*ps).fd_table[newfd as usize] = FdEntry {
            ofd_id: entry.ofd_id,
            fd_flags: cloexec,
        };
        ofd_table()[entry.ofd_id as usize].refcount += 1;
        newfd as i64
    }
}

/// fcntl(fd, cmd, arg)
pub fn sys_fcntl(vm: &mut ThreadState, _base: u32, fd: u64, cmd: u64, arg: u64) -> i64 {
    unsafe {
        match cmd {
            F_DUPFD => {
                let entry = match get_fd_entry(vm, fd) {
                    Some(e) => *e,
                    None => return EBADF,
                };
                let newfd = match find_free_fd(vm, arg as usize) {
                    Some(fd) => fd,
                    None => return EMFILE,
                };
                let ps = get_process_state(vm);
                (*ps).fd_table[newfd] = FdEntry {
                    ofd_id: entry.ofd_id,
                    fd_flags: 0,
                };
                ofd_table()[entry.ofd_id as usize].refcount += 1;
                newfd as i64
            }
            F_DUPFD_CLOEXEC => {
                let entry = match get_fd_entry(vm, fd) {
                    Some(e) => *e,
                    None => return EBADF,
                };
                let newfd = match find_free_fd(vm, arg as usize) {
                    Some(fd) => fd,
                    None => return EMFILE,
                };
                let ps = get_process_state(vm);
                (*ps).fd_table[newfd] = FdEntry {
                    ofd_id: entry.ofd_id,
                    fd_flags: FD_CLOEXEC,
                };
                ofd_table()[entry.ofd_id as usize].refcount += 1;
                newfd as i64
            }
            F_GETFD => {
                match get_fd_entry(vm, fd) {
                    Some(e) => e.fd_flags as i64,
                    None => EBADF,
                }
            }
            F_SETFD => {
                match get_fd_entry(vm, fd) {
                    Some(e) => { e.fd_flags = arg as u32 & FD_CLOEXEC; 0 }
                    None => EBADF,
                }
            }
            F_GETFL => {
                let entry = match get_fd_entry(vm, fd) {
                    Some(e) => e,
                    None => return EBADF,
                };
                ofd_table()[entry.ofd_id as usize].status_flags as i64
            }
            F_SETFL => {
                let entry = match get_fd_entry(vm, fd) {
                    Some(e) => e,
                    None => return EBADF,
                };
                // Only O_APPEND, O_NONBLOCK, O_DSYNC, O_ASYNC can be changed
                let changeable = O_APPEND | O_NONBLOCK;
                let ofd = &mut ofd_table()[entry.ofd_id as usize];
                ofd.status_flags = (ofd.status_flags & !changeable) | (arg as i32 & changeable);
                0
            }
            _ => EINVAL,
        }
    }
}

/// close(fd)
pub fn sys_close(vm: &mut ThreadState, _base: u32, fd: u64) -> i64 {
    unsafe {
        if fd as usize >= MAX_FDS { return EBADF; }

        let ps = get_process_state(vm);
        if ps.is_null() { return EBADF; }

        let entry = &mut (*ps).fd_table[fd as usize];
        if entry.ofd_id == 0 { return EBADF; }

        let ofd_id = entry.ofd_id as usize;
        entry.ofd_id = 0;
        entry.fd_flags = 0;

        let ofd = &mut ofd_table()[ofd_id];
        ofd.refcount -= 1;

        if ofd.refcount <= 0 {
            // Last reference: release OFD.
            // In the kernel Worker model, this would send STATUS_FS to kernel Worker for cleanup.
            ofd.fd_type = 0;
            ofd.refcount = 0;
        }

        0
    }
}

// =========================================================================
// FS integration: open_file, get_ofd, advance_offset, set_offset
// =========================================================================

/// Open a file by inode number. Allocates OFD and FD. Returns FD or error.
pub fn open_file(vm: &mut ThreadState, _base: u32, ino: u32, flags: i32) -> i64 {
    unsafe {
        let fd_type = FD_TYPE_FILE;
        let ofd_id = alloc_ofd(fd_type, flags & (O_APPEND | O_NONBLOCK));
        if ofd_id == 0 { return EMFILE; }
        ofd_table()[ofd_id as usize].ino = ino;

        let cloexec = if flags & O_CLOEXEC != 0 { FD_CLOEXEC } else { 0 };
        let newfd = match find_free_fd(vm, 0) {
            Some(fd) => fd,
            None => return EMFILE,
        };
        let ps = get_process_state(vm);
        (*ps).fd_table[newfd] = FdEntry { ofd_id, fd_flags: cloexec };
        newfd as i64
    }
}

/// Get OFD for a file descriptor (read-only snapshot).
pub fn get_ofd(vm: &ThreadState, fd: u64) -> Option<OpenFileDesc> {
    unsafe {
        let entry = get_fd_entry(vm, fd)?;
        let ofd = &ofd_table()[entry.ofd_id as usize];
        Some(*ofd)
    }
}

/// Advance the offset of the OFD associated with fd.
pub fn advance_offset(vm: &ThreadState, fd: u64, delta: u64) {
    unsafe {
        if let Some(entry) = get_fd_entry(vm, fd) {
            ofd_table()[entry.ofd_id as usize].offset += delta as i64;
        }
    }
}

/// Set the offset of the OFD associated with fd.
pub fn set_offset(vm: &ThreadState, fd: u64, offset: u64) {
    unsafe {
        if let Some(entry) = get_fd_entry(vm, fd) {
            ofd_table()[entry.ofd_id as usize].offset = offset as i64;
        }
    }
}

/// Initialize stdin/stdout/stderr FDs for a new process.
pub unsafe fn init_stdio(vm: &ThreadState) {
    let ps = get_process_state(vm);
    if ps.is_null() { return; }

    // FD 0: stdin (placeholder, type DEVNULL for now)
    let ofd0 = alloc_ofd(FD_TYPE_DEVNULL, 0);
    (*ps).fd_table[0] = FdEntry { ofd_id: ofd0, fd_flags: 0 };

    // FD 1: stdout
    let ofd1 = alloc_ofd(FD_TYPE_STDOUT, 0);
    (*ps).fd_table[1] = FdEntry { ofd_id: ofd1, fd_flags: 0 };

    // FD 2: stderr
    let ofd2 = alloc_ofd(FD_TYPE_STDERR, 0);
    (*ps).fd_table[2] = FdEntry { ofd_id: ofd2, fd_flags: 0 };
}
