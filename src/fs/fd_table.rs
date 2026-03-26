//! FD table and OFD (Open File Description) table management.
//!
//! Two-layer design:
//!
//! FD table lives in guest Memory (ProcessState.fd_table) — dup/close(refcount>1)/fcntl
//! operate without kernel Worker.
//!
//! OFD table lives in kernel Worker linear memory (alloc.rs) — shared by FDs via
//! refcount. Last close triggers OFD cleanup via kernel Worker.
//!
//! Struct layouts (RV64):
//!
//! struct FdEntry {                      // 8 bytes total
//!     ofd_id:   u32,                    // offset 0  — index into kernel Worker OFD table (0=unused)
//!     fd_flags: u32,                    // offset 4  — FD_CLOEXEC
//! };
//!
//! struct OpenFileDesc {                 // 32 bytes total
//!     fd_type:      i32,               // offset 0  — FD_TYPE_FILE, FD_TYPE_PIPE, etc.
//!     host_fd:      i32,               // offset 4  — pipe: idx or -(idx+1)
//!     status_flags: i32,               // offset 8  — O_APPEND, O_NONBLOCK
//!     refcount:     i32,               // offset 12 — dup/fork increment, close decrement
//!     offset:       i64,               // offset 16 — current file offset
//!     ino:          u32,               // offset 24 — inode number (MemFS)
//!     _pad:         u32,               // offset 28
//! };
//!
//! fcntl commands (https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/fcntl.h):
//!   F_DUPFD         = 0     dup to >= arg
//!   F_GETFD         = 1     get close_on_exec
//!   F_SETFD         = 2     set close_on_exec
//!   F_GETFL         = 3     get file status flags
//!   F_SETFL         = 4     set file status flags
//!   F_DUPFD_CLOEXEC = 1030  dup with CLOEXEC
//!   FD_CLOEXEC      = 1

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
// Pipe FD creation
// =========================================================================

/// Open a pipe FD. `is_read_end` determines if this is the read or write end.
/// pipe_idx is the index into the pipe table.
pub fn open_pipe(vm: &mut ThreadState, _base: u32, pipe_idx: u32, is_read_end: bool, flags: i32) -> i64 {
    unsafe {
        let fd_type = FD_TYPE_PIPE;
        // Encode pipe_idx and read/write flag in host_fd field
        let host_fd = if is_read_end { pipe_idx as i32 } else { -(pipe_idx as i32) - 1 };
        let ofd_id = alloc_ofd(fd_type, flags & O_NONBLOCK);
        if ofd_id == 0 { return EMFILE; }
        ofd_table()[ofd_id as usize].host_fd = host_fd;
        ofd_table()[ofd_id as usize].ino = pipe_idx;

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

/// Check if an OFD is a pipe read-end (host_fd >= 0 and fd_type == PIPE).
pub fn is_pipe_read(ofd: &OpenFileDesc) -> bool {
    ofd.fd_type == FD_TYPE_PIPE && ofd.host_fd >= 0
}

/// Check if an OFD is a pipe write-end (host_fd < 0 and fd_type == PIPE).
pub fn is_pipe_write(ofd: &OpenFileDesc) -> bool {
    ofd.fd_type == FD_TYPE_PIPE && ofd.host_fd < 0
}

// =========================================================================
// Epoll FD creation
// =========================================================================

/// Open an epoll FD. epoll_idx is the index into the epoll instance table.
pub fn open_epoll(vm: &mut ThreadState, _base: u32, epoll_idx: u32, flags: i32) -> i64 {
    unsafe {
        let ofd_id = alloc_ofd(FD_TYPE_EPOLL, 0);
        if ofd_id == 0 { return EMFILE; }
        ofd_table()[ofd_id as usize].ino = epoll_idx;

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

        // POSIX dup3: silently close newfd if it's already open
        let old_new = &mut (*ps).fd_table[newfd as usize];
        if old_new.ofd_id != 0 {
            let old_ofd_id = old_new.ofd_id as usize;
            old_new.ofd_id = 0;
            old_new.fd_flags = 0;

            let ofd = &mut ofd_table()[old_ofd_id];
            ofd.refcount -= 1;

            if ofd.refcount <= 0 {
                // Last reference: backend-specific cleanup before releasing OFD.
                if ofd.fd_type == FD_TYPE_PIPE {
                    let pipe_idx = ofd.ino;
                    let is_read = ofd.host_fd >= 0;
                    crate::syscall::pipe::pipe_close(pipe_idx, is_read);
                }
                ofd.fd_type = 0;
                ofd.refcount = 0;
            }
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
            // Last reference: backend-specific cleanup before releasing OFD.
            if ofd.fd_type == FD_TYPE_PIPE {
                let pipe_idx = ofd.ino;
                let is_read = ofd.host_fd >= 0;
                crate::syscall::pipe::pipe_close(pipe_idx, is_read);
            }
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

/// Get OFD by internal OFD id (for mmap file-backed without FD context).
pub fn get_ofd_by_id(ofd_id: u32) -> Option<OpenFileDesc> {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS { return None; }
    unsafe {
        let ofd = &ofd_table()[ofd_id as usize];
        if ofd.fd_type == FD_TYPE_NONE { return None; }
        Some(*ofd)
    }
}

/// Get the current offset of the OFD associated with fd.
pub fn get_offset(vm: &ThreadState, fd: u64) -> u64 {
    unsafe {
        if let Some(entry) = get_fd_entry(vm, fd) {
            ofd_table()[entry.ofd_id as usize].offset as u64
        } else {
            0
        }
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

#[cfg(test)]
mod tests {
    use crate::abi::*;
    use crate::test_helpers::TestVm;

    #[test]
    fn fd_table_syscalls() {
        let mut t = TestVm::new();

        // dup(1) -> should return 3 (next free fd)
        let newfd = t.sys_dup(1);
        assert_eq!(newfd, 3);

        // fcntl F_GETFD on new fd -> should be 0 (no CLOEXEC)
        let flags = t.sys_fcntl(3, 1, 0); // F_GETFD=1
        assert_eq!(flags, 0);

        // fcntl F_SETFD to set CLOEXEC
        let ret = t.sys_fcntl(3, 2, 1); // F_SETFD=2, FD_CLOEXEC=1
        assert_eq!(ret, 0);
        let flags2 = t.sys_fcntl(3, 1, 0);
        assert_eq!(flags2, 1);

        // close(3)
        let ret2 = t.sys_close(3);
        assert_eq!(ret2, 0);

        // close again -> EBADF
        let ret3 = t.sys_close(3);
        assert_eq!(ret3, EBADF);

        // dup3(1, 10, O_CLOEXEC)
        let ret4 = t.sys_dup3(1, 10, O_CLOEXEC as u64);
        assert_eq!(ret4, 10);
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
