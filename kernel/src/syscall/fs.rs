//! FS syscalls: openat, read, write, stat, mkdir, unlink, rename, getdents64.
//!
//! Struct layouts (RV64):
//!
//! struct stat {                         // 128 bytes total
//!     st_dev:       u64,                // offset 0
//!     st_ino:       u64,                // offset 8
//!     st_mode:      u32,                // offset 16
//!     st_nlink:     u32,                // offset 20
//!     st_uid:       u32,                // offset 24
//!     st_gid:       u32,                // offset 28
//!     st_rdev:      u64,                // offset 32
//!     __pad1:       u64,                // offset 40
//!     st_size:      i64,                // offset 48
//!     st_blksize:   i32,                // offset 56
//!     __pad2:       i32,                // offset 60
//!     st_blocks:    i64,                // offset 64
//!     st_atime:     i64,                // offset 72
//!     st_atime_nsec:u64,                // offset 80
//!     st_mtime:     i64,                // offset 88
//!     st_mtime_nsec:u64,                // offset 96
//!     st_ctime:     i64,                // offset 104
//!     st_ctime_nsec:u64,                // offset 112
//!     __unused4:    u32,                // offset 120
//!     __unused5:    u32,                // offset 124
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/stat.h
//!
//! struct linux_dirent64 {               // variable size
//!     d_ino:    u64,                    // offset 0
//!     d_off:    i64,                    // offset 8
//!     d_reclen: u16,                    // offset 16
//!     d_type:   u8,                     // offset 18
//!     d_name:   [u8],                   // offset 19 (null-terminated)
//! };
//! https://man7.org/linux/man-pages/man2/getdents.2.html

use crate::abi::*;
use crate::fs::{fd_table, memfs, ring_buffer};
use crate::guest_mem;
use crate::syscall::signal;
use crate::types::OpenFileDesc;
use crate::types::{ProcessState, ThreadState};

const AT_FDCWD: i32 = -100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const PENDING_FS_PATH_MAX: usize = 4096;
const DT_UNKNOWN: u8 = 0;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const EVENTFD_COUNTER_MAX: u64 = u64::MAX - 1;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;
const MAX_PATH_SYMLINK_FOLLOWS: u32 = 40;
pub const FS_EFFECT_MEMFS_MUTATION: u32 = 1 << 0;
pub const FS_EFFECT_SHARED_OFD_STATE: u32 = 1 << 1;
pub const FS_EFFECT_MEMFS_FILE_DATA: u32 = 1 << 2;

// =========================================================================
// Path resolution helper
// =========================================================================

fn process_state(base: u32, vm: &ThreadState) -> Option<&'static mut ProcessState> {
    let ptr = (base as u64 + vm.process_ptr as u64) as *mut ProcessState;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &mut *ptr })
    }
}

fn current_dir_ino(base: u32, vm: &ThreadState) -> u32 {
    match process_state(base, vm) {
        Some(ps) if ps.cwd_ino != 0 => ps.cwd_ino,
        _ => 1,
    }
}

fn process_fs_ring_base(base: u32, vm: &ThreadState) -> u32 {
    process_state(base, vm)
        .map(|ps| ps.fs_ring_base)
        .unwrap_or(0)
}

fn set_current_dir_ino(base: u32, vm: &ThreadState, ino: u32) {
    if let Some(ps) = process_state(base, vm) {
        ps.cwd_ino = ino;
    }
}

#[allow(clippy::too_many_arguments)]
fn submit_fs_request(
    vm: &mut ThreadState,
    base: u32,
    opcode: u32,
    fd: i32,
    offset: u64,
    len: u64,
    buf_ptr: u64,
    path_ptr: u64,
    flags: u32,
    mode: u32,
) -> i64 {
    let ring_base = process_fs_ring_base(base, vm);
    if ring_base == 0 {
        return ENOMEM;
    }

    let idx = ring_buffer::submit_request(
        ring_base, opcode, fd, offset, len, buf_ptr, path_ptr, flags, mode,
    );
    if idx < 0 {
        return EAGAIN;
    }

    vm.status = STATUS_FS;
    0
}

pub fn process_pending_requests(vm_ptr: u32, base: u32) {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base != 0 {
            ring_buffer::process_requests(ring_base, vm_ptr, base);
        }
    }
}

fn classify_pending_request_effects(request: &ring_buffer::FsRequestInfo) -> u32 {
    match request.opcode {
        ring_buffer::FS_OP_OPENAT => {
            if request.flags & (O_CREAT as u32) != 0 {
                FS_EFFECT_MEMFS_MUTATION
            } else if request.flags & (O_TRUNC as u32) != 0 {
                FS_EFFECT_MEMFS_FILE_DATA
            } else {
                0
            }
        }
        ring_buffer::FS_OP_WRITE => {
            let mut effects = FS_EFFECT_MEMFS_FILE_DATA;
            if request.flags & ring_buffer::FS_REQ_FLAG_PWRITE == 0 {
                effects |= FS_EFFECT_SHARED_OFD_STATE;
            }
            effects
        }
        ring_buffer::FS_OP_CLOSE => FS_EFFECT_SHARED_OFD_STATE,
        ring_buffer::FS_OP_GETDENTS | ring_buffer::FS_OP_LSEEK => FS_EFFECT_SHARED_OFD_STATE,
        ring_buffer::FS_OP_TRUNCATE => FS_EFFECT_MEMFS_FILE_DATA,
        ring_buffer::FS_OP_MKDIR | ring_buffer::FS_OP_UNLINK => FS_EFFECT_MEMFS_MUTATION,
        _ => 0,
    }
}

pub fn pending_request_effects(vm_ptr: u32, base: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 {
            return 0;
        }
        match ring_buffer::peek_request_info(ring_base) {
            Some(request) => classify_pending_request_effects(&request),
            None => 0,
        }
    }
}

fn pending_request_target_ino_inner(
    vm: &ThreadState,
    base: u32,
    request: &ring_buffer::FsRequestInfo,
) -> u32 {
    match request.opcode {
        ring_buffer::FS_OP_WRITE => {
            if request.fd <= 0 {
                return 0;
            }
            fd_table::get_ofd(base, vm, request.fd as u64).map_or(0, |ofd| ofd.ino)
        }
        ring_buffer::FS_OP_CLOSE | ring_buffer::FS_OP_GETDENTS | ring_buffer::FS_OP_LSEEK => 0,
        ring_buffer::FS_OP_TRUNCATE => {
            if request.fd > 0 {
                return fd_table::get_ofd(base, vm, request.fd as u64).map_or(0, |ofd| ofd.ino);
            }
            if request.path_ptr == 0 {
                return 0;
            }
            resolve_at(vm, AT_FDCWD as u64, request.path_ptr, base).unwrap_or(0)
        }
        ring_buffer::FS_OP_OPENAT => {
            if request.flags & (O_TRUNC as u32) == 0 || request.flags & (O_CREAT as u32) != 0 {
                return 0;
            }
            if request.path_ptr == 0 {
                return 0;
            }
            resolve_at(vm, request.fd as u64, request.path_ptr, base).unwrap_or(0)
        }
        _ => 0,
    }
}

pub fn pending_request_target_ino(vm_ptr: u32, base: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 {
            return 0;
        }
        match ring_buffer::peek_request_info(ring_base) {
            Some(request) => pending_request_target_ino_inner(vm, base, &request),
            None => 0,
        }
    }
}

pub fn pending_request_opcode(vm_ptr: u32, base: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 {
            return 0;
        }
        match ring_buffer::peek_request_info(ring_base) {
            Some(request) => request.opcode,
            None => 0,
        }
    }
}

fn pending_request_path_ptr_inner(request: &ring_buffer::FsRequestInfo) -> u64 {
    match request.opcode {
        ring_buffer::FS_OP_OPENAT
        | ring_buffer::FS_OP_MKDIR
        | ring_buffer::FS_OP_UNLINK
        | ring_buffer::FS_OP_TRUNCATE => request.path_ptr,
        _ => 0,
    }
}

pub fn pending_request_path_ptr(vm_ptr: u32, base: u32) -> u64 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 {
            return 0;
        }
        match ring_buffer::peek_request_info(ring_base) {
            Some(request) => pending_request_path_ptr_inner(&request),
            None => 0,
        }
    }
}

pub fn pending_request_path_len(vm_ptr: u32, base: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 {
            return 0;
        }
        let Some(request) = ring_buffer::peek_request_info(ring_base) else {
            return 0;
        };
        let path_ptr = pending_request_path_ptr_inner(&request);
        if path_ptr == 0 {
            return 0;
        }
        let guest_limit =
            ((core::arch::wasm32::memory_size(0) as u64) * 65536).saturating_sub(base as u64);
        if path_ptr >= guest_limit || path_ptr > u32::MAX as u64 {
            return 0;
        }
        let mut len = 0u32;
        while (len as usize) < PENDING_FS_PATH_MAX {
            let Some(cur) = path_ptr.checked_add(len as u64) else {
                return 0;
            };
            if cur >= guest_limit || cur > u32::MAX as u64 {
                return 0;
            }
            if crate::syscall::memory::range_has_prot_none(cur, 1) {
                return 0;
            }
            let byte = guest_mem::read_u8(base, cur);
            if byte == 0 {
                return len;
            }
            len += 1;
        }
        len
    }
}

pub fn pending_request_absolute_path(vm_ptr: u32, base: u32, out_ptr: u32, out_len: u32) -> i64 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 || out_ptr == 0 || out_len == 0 {
            return 0;
        }
        let Some(request) = ring_buffer::peek_request_info(ring_base) else {
            return 0;
        };
        let path_ptr = pending_request_path_ptr_inner(&request);
        if path_ptr == 0 {
            return 0;
        }

        let mut path_buf = [0u8; 513];
        let len = guest_mem::read_cstr(base, path_ptr, &mut path_buf[1..]);
        let raw_path = &path_buf[1..1 + len];
        let path = trim_trailing_slashes(raw_path);
        if path.is_empty() {
            return 0;
        }

        let mut absolute = [0u8; 512];
        let absolute_len = if path[0] == b'/' {
            if path.len() > absolute.len() {
                return ENAMETOOLONG;
            }
            absolute[..path.len()].copy_from_slice(path);
            path.len()
        } else {
            let base_ino = match dirfd_base_ino(vm, request.fd as u64, base) {
                Ok(ino) => ino,
                Err(errno) => return errno,
            };
            let (parent_rel, name) = split_relative_parent_name(path);
            let parent_ino = if name.is_empty() {
                if parent_rel.is_empty() {
                    base_ino
                } else {
                    match resolve_path_with_symlink_policy(
                        base_ino,
                        parent_rel,
                        true,
                        MAX_PATH_SYMLINK_FOLLOWS,
                    ) {
                        Ok(ino) => ino,
                        Err(errno) => return errno,
                    }
                }
            } else if parent_rel.is_empty() {
                base_ino
            } else {
                match resolve_path_with_symlink_policy(
                    base_ino,
                    parent_rel,
                    true,
                    MAX_PATH_SYMLINK_FOLLOWS,
                ) {
                    Ok(ino) => ino,
                    Err(errno) => return errno,
                }
            };

            let parent_len = memfs::write_path(parent_ino, &mut absolute);
            if parent_len == 0 {
                return ENOENT;
            }
            if name.is_empty() {
                parent_len
            } else {
                let sep_len = usize::from(parent_len > 1);
                let total = parent_len + sep_len + name.len();
                if total > absolute.len() {
                    return ENAMETOOLONG;
                }
                if sep_len != 0 {
                    absolute[parent_len] = b'/';
                }
                absolute[parent_len + sep_len..total].copy_from_slice(name);
                total
            }
        };

        if absolute_len > out_len as usize {
            return ENOSPC;
        }
        let out = core::slice::from_raw_parts_mut(out_ptr as *mut u8, out_len as usize);
        out[..absolute_len].copy_from_slice(&absolute[..absolute_len]);
        absolute_len as i64
    }
}

pub fn resume_from_fs(vm_ptr: u32, base: u32) -> i64 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 {
            vm.x[10] = ENOMEM as u64;
            vm.status = STATUS_OK;
            return ENOMEM;
        }

        let result = ring_buffer::read_completion(ring_base);
        vm.x[10] = result as u64;
        vm.status = STATUS_OK;
        result
    }
}

pub fn dispatch_openat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    flags: u64,
    mode: u64,
) -> i64 {
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_OPENAT,
        dirfd as i32,
        0,
        0,
        0,
        path_addr,
        flags as u32,
        mode as u32,
    )
}

pub fn dispatch_pwrite64(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    count: u64,
    offset: u64,
) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if ofd.fd_type == FD_TYPE_PIPE {
        return ESPIPE;
    }

    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_WRITE,
        fd as i32,
        offset,
        count,
        buf,
        0,
        ring_buffer::FS_REQ_FLAG_PWRITE,
        0,
    )
}

pub fn dispatch_write(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    count: u64,
    nr: u64,
) -> i64 {
    if nr == SYS_WRITEV || fd == 1 || fd == 2 {
        return sys_write(vm, base, fd, buf, count, nr);
    }

    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if ofd.fd_type == FD_TYPE_PIPE {
        return sys_write(vm, base, fd, buf, count, nr);
    }
    if ofd.fd_type == FD_TYPE_EVENTFD {
        return sys_write(vm, base, fd, buf, count, nr);
    }
    if ofd.fd_type == FD_TYPE_PTY_MASTER || ofd.fd_type == FD_TYPE_PTY_SLAVE {
        return sys_write(vm, base, fd, buf, count, nr);
    }

    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_WRITE,
        fd as i32,
        0,
        count,
        buf,
        0,
        0,
        0,
    )
}

pub fn dispatch_fstat(vm: &mut ThreadState, base: u32, fd: u64, stat_buf: u64) -> i64 {
    if fd <= 2 {
        return sys_fstat(vm, base, fd, stat_buf);
    }
    if let Some(ofd) = fd_table::get_ofd(base, vm, fd)
        && matches!(
            ofd.fd_type,
            FD_TYPE_DEVNULL
                | FD_TYPE_PIPE
                | FD_TYPE_SOCKET
                | FD_TYPE_EVENTFD
                | FD_TYPE_EPOLL
                | FD_TYPE_PTY_MASTER
                | FD_TYPE_PTY_SLAVE
        )
    {
        return sys_fstat(vm, base, fd, stat_buf);
    }
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_FSTAT,
        fd as i32,
        0,
        0,
        stat_buf,
        0,
        0,
        0,
    )
}

pub fn dispatch_mkdirat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    mode: u64,
) -> i64 {
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_MKDIR,
        dirfd as i32,
        0,
        0,
        0,
        path_addr,
        0,
        mode as u32,
    )
}

pub fn dispatch_unlinkat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    flags: u64,
) -> i64 {
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_UNLINK,
        dirfd as i32,
        0,
        0,
        0,
        path_addr,
        flags as u32,
        0,
    )
}

pub fn dispatch_getdents64(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    buf_size: u64,
) -> i64 {
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_GETDENTS,
        fd as i32,
        0,
        buf_size,
        buf,
        0,
        0,
        0,
    )
}

pub fn dispatch_lseek(vm: &mut ThreadState, base: u32, fd: u64, offset: i64, whence: u64) -> i64 {
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_LSEEK,
        fd as i32,
        offset as u64,
        0,
        0,
        0,
        whence as u32,
        0,
    )
}

pub fn dispatch_ftruncate(vm: &mut ThreadState, base: u32, fd: u64, length: u64) -> i64 {
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_TRUNCATE,
        fd as i32,
        length,
        0,
        0,
        0,
        0,
        0,
    )
}

pub fn dispatch_truncate(vm: &mut ThreadState, base: u32, path_addr: u64, length: u64) -> i64 {
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_TRUNCATE,
        0,
        length,
        0,
        0,
        path_addr,
        0,
        0,
    )
}

fn dirfd_base_ino(vm: &ThreadState, dirfd: u64, base: u32) -> Result<u32, i64> {
    if dirfd as i32 == AT_FDCWD {
        return Ok(current_dir_ino(base, vm));
    }

    let ofd = fd_table::get_ofd(base, vm, dirfd).ok_or(EBADF)?;
    let dir_ino = ofd.ino;
    let st = memfs::stat(dir_ino).ok_or(ENOENT)?;
    if st.mode & memfs::S_IFMT != memfs::S_IFDIR {
        return Err(ENOTDIR);
    }

    Ok(dir_ino)
}

fn trim_trailing_slashes(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    &path[..end]
}

fn path_has_trailing_slash(path: &[u8]) -> bool {
    path.len() > 1 && path[path.len() - 1] == b'/'
}

fn concat_symlink_target_and_rest<'a>(
    target: &[u8],
    rest: &[u8],
    buf: &'a mut [u8; 512],
) -> Result<&'a [u8], i64> {
    let total = target.len().checked_add(rest.len()).ok_or(ENAMETOOLONG)?;
    if total > buf.len() {
        return Err(ENAMETOOLONG);
    }
    buf[..target.len()].copy_from_slice(target);
    buf[target.len()..total].copy_from_slice(rest);
    Ok(&buf[..total])
}

fn resolve_path_with_symlink_policy(
    start_ino: u32,
    path: &[u8],
    follow_trailing_symlink: bool,
    depth_left: u32,
) -> Result<u32, i64> {
    if depth_left == 0 {
        return Err(ELOOP);
    }

    let mut ino = start_ino;
    let mut cursor = 0usize;
    if path.first() == Some(&b'/') {
        ino = 1;
        cursor = 1;
    }

    while cursor < path.len() {
        while cursor < path.len() && path[cursor] == b'/' {
            cursor += 1;
        }
        if cursor >= path.len() {
            break;
        }

        let component_start = cursor;
        while cursor < path.len() && path[cursor] != b'/' {
            cursor += 1;
        }
        let component = &path[component_start..cursor];
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            ino = memfs::parent_ino(ino);
            continue;
        }

        let st = memfs::stat(ino).ok_or(ENOENT)?;
        if st.mode & memfs::S_IFMT != memfs::S_IFDIR {
            return Err(ENOTDIR);
        }

        let next_ino = memfs::lookup(ino, component);
        if next_ino == 0 {
            return Err(ENOENT);
        }

        let rest = &path[cursor..];
        let has_more_components = rest.iter().any(|byte| *byte != b'/');
        let next_st = memfs::stat(next_ino).ok_or(ENOENT)?;
        if next_st.mode & memfs::S_IFMT == memfs::S_IFLNK
            && (has_more_components || follow_trailing_symlink)
        {
            let mut link_target = [0u8; 512];
            let target_len = memfs::read_link(next_ino, &mut link_target);
            if target_len == 0 {
                return Err(ENOENT);
            }
            let target = &link_target[..target_len];
            let mut combined = [0u8; 512];
            let combined_path = concat_symlink_target_and_rest(target, rest, &mut combined)?;
            let restart_ino = if target.first() == Some(&b'/') { 1 } else { ino };
            return resolve_path_with_symlink_policy(
                restart_ino,
                combined_path,
                follow_trailing_symlink,
                depth_left - 1,
            );
        }

        ino = next_ino;
    }

    Ok(ino)
}

fn resolve_path_with_errno(start_ino: u32, path: &[u8]) -> Result<u32, i64> {
    resolve_path_with_symlink_policy(start_ino, path, false, MAX_PATH_SYMLINK_FOLLOWS)
}

fn resolve_at(vm: &ThreadState, dirfd: u64, path_addr: u64, base: u32) -> Result<u32, i64> {
    let mut path_buf = [0u8; 512];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf) };
    let path = trim_trailing_slashes(&path_buf[..len]);

    if path.is_empty() {
        return Err(ENOENT);
    }

    if path[0] == b'/' {
        return resolve_path_with_errno(1, path);
    }

    let dir_ino = dirfd_base_ino(vm, dirfd, base)?;
    resolve_path_with_errno(dir_ino, path)
}

pub fn sys_getcwd(vm: &ThreadState, base: u32, buf: u64, size: u64) -> i64 {
    let mut path = [0u8; 512];
    let len = memfs::write_path(current_dir_ino(base, vm), &mut path);
    if len == 0 {
        return ENOENT;
    }
    if len as u64 + 1 > size {
        return ERANGE;
    }
    unsafe {
        guest_mem::write_bytes(base, buf, &path[..len]);
        guest_mem::write_u8(base, buf + len as u64, 0);
    }
    (len as i64) + 1
}

pub fn sys_chdir(vm: &mut ThreadState, base: u32, path_addr: u64) -> i64 {
    let ino = match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(ino) => ino,
        Err(errno) => return errno,
    };
    let st = match memfs::stat(ino) {
        Some(st) => st,
        None => return ENOENT,
    };
    if st.mode & memfs::S_IFMT != memfs::S_IFDIR {
        return ENOTDIR;
    }
    set_current_dir_ino(base, vm, ino);
    0
}

pub fn sys_statfs(vm: &ThreadState, base: u32, path_addr: u64, buf: u64) -> i64 {
    let ino = match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(ino) => ino,
        Err(errno) => return errno,
    };

    if memfs::stat(ino).is_none() {
        return ENOENT;
    }

    unsafe {
        guest_mem::zero_mem(base, buf, 120);
        guest_mem::write_u64(base, buf, TMPFS_MAGIC);
        guest_mem::write_u64(base, buf + 8, 4096);
        guest_mem::write_u64(base, buf + 16, 0);
        guest_mem::write_u64(base, buf + 24, 0);
        guest_mem::write_u64(base, buf + 32, 0);
        guest_mem::write_u64(base, buf + 40, 0);
        guest_mem::write_u64(base, buf + 48, 0);
        guest_mem::write_u32(base, buf + 56, 0);
        guest_mem::write_u32(base, buf + 60, 0);
        guest_mem::write_u64(base, buf + 64, 255);
        guest_mem::write_u64(base, buf + 72, 4096);
        guest_mem::write_u64(base, buf + 80, 0);
    }

    0
}

// =========================================================================
// openat
// =========================================================================

/// openat: open or create a file. Supports O_CREAT, O_TRUNC.
/// Path resolution via MemFS (absolute, AT_FDCWD-relative, or dirfd-relative).
pub fn sys_openat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    flags: u64,
    mode: u64,
) -> i64 {
    let oflags = flags as i32;
    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let raw_path = &path_buf[1..1 + len];
    let require_directory = path_has_trailing_slash(raw_path);
    let path = trim_trailing_slashes(raw_path);
    let result = if path.is_empty() {
        ENOENT
    } else if path == b"/dev/tty" {
        if require_directory || oflags & O_DIRECTORY != 0 {
            ENOTDIR
        } else {
            crate::syscall::pty::open_controlling_tty(vm, base, oflags)
        }
    } else if path == b"/dev/null" {
        if require_directory || oflags & O_DIRECTORY != 0 {
            ENOTDIR
        } else {
            fd_table::open_devnull(vm, base, oflags)
        }
    } else if oflags & O_CREAT == 0 {
        let follow_trailing_symlink = oflags & O_NOFOLLOW == 0;
        let ino_result = if path[0] == b'/' {
            resolve_path_with_symlink_policy(
                1,
                path,
                follow_trailing_symlink,
                MAX_PATH_SYMLINK_FOLLOWS,
            )
        } else {
            let base_ino = match dirfd_base_ino(vm, dirfd, base) {
                Ok(ino) => ino,
                Err(errno) => {
                    crate::harness_hooks::record_path_syscall(
                        vm as *const ThreadState as u32,
                        crate::abi::SYS_OPENAT,
                        dirfd as i64,
                        raw_path,
                        errno,
                        vm.status,
                    );
                    return errno;
                }
            };
            resolve_path_with_symlink_policy(
                base_ino,
                path,
                follow_trailing_symlink,
                MAX_PATH_SYMLINK_FOLLOWS,
            )
        };
        match ino_result {
            Ok(ino) => open_existing_inode(vm, base, ino, oflags, require_directory),
            Err(errno) => errno,
        }
    } else if path[0] == b'/' {
        let (parent_ino, name) = split_parent_name(path);
        if parent_ino == 0 && name.is_empty() {
            fd_table::open_file(vm, base, 1, oflags)
        } else if parent_ino == 0 {
            ENOENT
        } else {
            openat_with_parent(vm, base, parent_ino, name, oflags, mode, require_directory)
        }
    } else {
        let base_ino = match dirfd_base_ino(vm, dirfd, base) {
            Ok(ino) => ino,
            Err(errno) => {
                crate::harness_hooks::record_path_syscall(
                    vm as *const ThreadState as u32,
                    crate::abi::SYS_OPENAT,
                    dirfd as i64,
                    raw_path,
                    errno,
                    vm.status,
                );
                return errno;
            }
        };
        {
            let (parent_rel, name) = split_relative_parent_name(path);
            if name.is_empty() {
                let ino = if parent_rel.is_empty() {
                    base_ino
                } else {
                    resolve_path_with_symlink_policy(
                        base_ino,
                        parent_rel,
                        true,
                        MAX_PATH_SYMLINK_FOLLOWS,
                    )
                    .unwrap_or(0)
                };
                if ino == 0 {
                    ENOENT
                } else {
                    fd_table::open_file(vm, base, ino, oflags)
                }
            } else {
                let parent_ino = if parent_rel.is_empty() {
                    base_ino
                } else {
                    resolve_path_with_symlink_policy(
                        base_ino,
                        parent_rel,
                        true,
                        MAX_PATH_SYMLINK_FOLLOWS,
                    )
                    .unwrap_or(0)
                };
                if parent_ino == 0 {
                    ENOENT
                } else {
                    openat_with_parent(vm, base, parent_ino, name, oflags, mode, require_directory)
                }
            }
        }
    };
    crate::harness_hooks::record_path_syscall(
        vm as *const ThreadState as u32,
        crate::abi::SYS_OPENAT,
        dirfd as i64,
        raw_path,
        result,
        vm.status,
    );
    result
}

fn open_existing_inode(
    vm: &mut ThreadState,
    base: u32,
    ino: u32,
    oflags: i32,
    require_directory: bool,
) -> i64 {
    let st = match memfs::stat(ino) {
        Some(st) => st,
        None => return ENOENT,
    };
    if st.mode & memfs::S_IFMT == memfs::S_IFLNK && oflags & O_NOFOLLOW != 0 {
        return ELOOP;
    }
    if require_directory || oflags & O_DIRECTORY != 0 {
        if st.mode & memfs::S_IFMT != memfs::S_IFDIR {
            return ENOTDIR;
        }
    }

    if oflags & O_TRUNC != 0 {
        memfs::truncate(ino, 0);
    }

    fd_table::open_file(vm, base, ino, oflags)
}

fn openat_with_parent(
    vm: &mut ThreadState,
    base: u32,
    parent_ino: u32,
    name: &[u8],
    oflags: i32,
    mode: u64,
    require_directory: bool,
) -> i64 {
    let mut ino = memfs::lookup(parent_ino, name);

    if ino == 0 {
        if oflags & O_CREAT != 0 {
            ino = memfs::create_file(parent_ino, name, mode as u32 & 0o7777);
            if ino == 0 {
                return ENOSPC;
            }
        } else {
            return ENOENT;
        }
    } else if oflags & O_CREAT != 0 && oflags & O_EXCL != 0 {
        return EEXIST;
    } else if let Some(st) = memfs::stat(ino)
        && st.mode & memfs::S_IFMT == memfs::S_IFLNK
    {
        if oflags & O_NOFOLLOW != 0 {
            return ELOOP;
        }
        let mut link_target = [0u8; 512];
        let target_len = memfs::read_link(ino, &mut link_target);
        if target_len == 0 {
            return ENOENT;
        }
        let target = &link_target[..target_len];
        ino = match resolve_path_with_symlink_policy(
            if target.first() == Some(&b'/') {
                1
            } else {
                parent_ino
            },
            target,
            true,
            MAX_PATH_SYMLINK_FOLLOWS,
        ) {
            Ok(resolved) => resolved,
            Err(errno) => return errno,
        };
    }

    open_existing_inode(vm, base, ino, oflags, require_directory)
}

fn split_parent_name(path: &[u8]) -> (u32, &[u8]) {
    if path == b"/" {
        return (0, &[]);
    }

    // Find last '/'
    let mut last_slash = 0;
    for i in (0..path.len()).rev() {
        if path[i] == b'/' {
            last_slash = i;
            break;
        }
    }

    let parent_path = if last_slash == 0 {
        b"/" as &[u8]
    } else {
        &path[..last_slash]
    };
    let name = &path[last_slash + 1..];

    let parent_ino = memfs::resolve_path(parent_path);
    (parent_ino, name)
}

/// Split a relative path into (parent_relative_path, leaf_name).
/// For "a/b/c.txt" returns ("a/b", "c.txt").
/// For "c.txt" returns ("", "c.txt").
fn split_relative_parent_name(path: &[u8]) -> (&[u8], &[u8]) {
    if path.is_empty() {
        return (&[], &[]);
    }

    // Find last '/'
    for i in (0..path.len()).rev() {
        if path[i] == b'/' {
            return (&path[..i], &path[i + 1..]);
        }
    }
    // No slash: parent is empty, name is the whole path
    (&[], path)
}

// =========================================================================
// read / pread64
// =========================================================================

/// read: read from file or pipe FD. Advances OFD offset for files.
pub fn sys_read(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return 0;
    }

    if ofd.fd_type == FD_TYPE_PTY_SLAVE || ofd.fd_type == FD_TYPE_PTY_MASTER {
        let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
        if access_mode == O_WRONLY {
            return EBADF;
        }
        let mut tmp = [0u8; 4096];
        let to_read = (count as usize).min(tmp.len());
        let n = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
            crate::syscall::pty::slave_read(ofd.ino, &mut tmp[..to_read])
        } else {
            crate::syscall::pty::master_read(ofd.ino, &mut tmp[..to_read])
        };
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        if n > 0 {
            if !crate::syscall::memory::guest_range_accessible(base, buf, n as u64) {
                return EFAULT;
            }
            unsafe {
                guest_mem::write_bytes(base, buf, &tmp[..n as usize]);
            }
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_PIPE {
        if !fd_table::is_pipe_read(&ofd) {
            return EBADF;
        }
        let mut tmp = [0u8; 4096];
        let to_read = (count as usize).min(tmp.len());
        let n = super::pipe::pipe_read(ofd.ino, &mut tmp[..to_read]);
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }
        if n > 0 {
            if !crate::syscall::memory::guest_range_accessible(base, buf, n as u64) {
                return EFAULT;
            }
            unsafe {
                guest_mem::write_bytes(base, buf, &tmp[..n as usize]);
            }
        }
        return n;
    }

    if ofd.fd_type == FD_TYPE_EVENTFD {
        if count < 8 {
            return EINVAL;
        }
        let counter = fd_table::get_offset(base, vm, fd);
        if counter == 0 {
            if ofd.status_flags & O_NONBLOCK != 0 {
                return EAGAIN;
            }
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return 0;
        }

        let value = if ofd.host_fd != 0 { 1 } else { counter };
        let next = if ofd.host_fd != 0 { counter - 1 } else { 0 };
        if !crate::syscall::memory::guest_range_accessible(base, buf, 8) {
            return EFAULT;
        }
        unsafe {
            guest_mem::write_u64(base, buf, value);
        }
        fd_table::set_offset(base, vm, fd, next);
        return 8;
    }

    if ofd.fd_type == FD_TYPE_SOCKET {
        let n = super::socket::socket_read(vm, base, fd, buf, count);
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_SOCKET_RECV;
            return 0;
        }
        return n;
    }

    let mut tmp = [0u8; 4096];
    let to_read = (count as usize).min(tmp.len());
    let n = memfs::read_file(ofd.ino, ofd.offset as u64, &mut tmp[..to_read]);
    if n > 0 {
        if !crate::syscall::memory::guest_range_accessible(base, buf, n as u64) {
            return EFAULT;
        }
        unsafe {
            guest_mem::write_bytes(base, buf, &tmp[..n as usize]);
        }
        fd_table::advance_offset(base, vm, fd, n as u64);
    }
    n
}

/// pread64: read at specified offset without changing OFD offset.
pub fn sys_pread64(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    count: u64,
    offset: u64,
) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return 0;
    }

    let mut tmp = [0u8; 4096];
    let to_read = (count as usize).min(tmp.len());
    let n = memfs::read_file(ofd.ino, offset, &mut tmp[..to_read]);
    if n > 0 {
        if !crate::syscall::memory::guest_range_accessible(base, buf, n as u64) {
            return EFAULT;
        }
        unsafe {
            guest_mem::write_bytes(base, buf, &tmp[..n as usize]);
        }
    }
    n
}

// =========================================================================
// pwrite64
// =========================================================================

/// pwrite64: write at specified offset without changing OFD offset.
pub fn sys_pwrite64(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    count: u64,
    offset: u64,
) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return count as i64;
    }

    write_regular_file_from_guest(base, buf, count, ofd.ino, offset)
}

fn write_regular_file_from_guest(
    base: u32,
    guest_addr: u64,
    len: u64,
    ino: u32,
    start_offset: u64,
) -> i64 {
    let mut tmp = [0u8; 4096];
    let mut total = 0u64;
    while total < len {
        let to_write = ((len - total) as usize).min(tmp.len());
        unsafe {
            guest_mem::read_bytes(base, guest_addr + total, &mut tmp[..to_write]);
        }
        let n = memfs::write_file(ino, start_offset + total, &tmp[..to_write]);
        if n < 0 {
            return if total > 0 { total as i64 } else { n };
        }
        if n == 0 {
            break;
        }
        total += n as u64;
        if (n as usize) < to_write {
            break;
        }
    }
    total as i64
}

// =========================================================================
// write / writev
// =========================================================================

/// write: write to file or pipe FD. Sends SIGPIPE on broken pipe.
/// Also handles writev (dispatched by nr == SYS_WRITEV).
#[allow(clippy::too_many_arguments)]
fn trace_write_attempt(
    fd: u64,
    nr: u64,
    buf_addr: u64,
    count: u64,
    result: i64,
    ofd_id: u32,
    ofd_type: i32,
    ofd_ino: u32,
    status_flags: i32,
    pipe_read_open: i32,
    pipe_write_open: i32,
    bytes: Option<&[u8]>,
) -> i64 {
    crate::harness_hooks::record_write_attempt(
        fd,
        nr,
        buf_addr,
        count,
        result,
        ofd_id,
        ofd_type,
        ofd_ino,
        status_flags,
        pipe_read_open,
        pipe_write_open,
        bytes,
    );
    result
}

fn trace_pipe_open_state(ofd: &OpenFileDesc) -> (i32, i32) {
    if ofd.fd_type == FD_TYPE_PIPE {
        (
            super::pipe::debug_read_open(ofd.ino),
            super::pipe::debug_write_open(ofd.ino),
        )
    } else {
        (0, 0)
    }
}

pub fn sys_write(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64, nr: u64) -> i64 {
    if nr == SYS_WRITEV {
        return sys_writev(vm, base, fd, buf, count);
    }

    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                0,
                FD_TYPE_NONE,
                0,
                0,
                0,
                0,
                None,
            );
        }
    };
    let ofd_id = fd_table::get_ofd_id(base, vm, fd).unwrap_or(0);
    let (pipe_read_open, pipe_write_open) = trace_pipe_open_state(&ofd);

    if ofd.fd_type == FD_TYPE_DEVNULL {
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            count as i64,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_STDOUT || ofd.fd_type == FD_TYPE_STDERR {
        #[cfg(target_os = "wasi")]
        {
            let mut tmp = [0u8; 4096];
            let to_write = (count as usize).min(tmp.len());
            unsafe {
                guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
            }
            crate::harness_support::append_guest_output(&tmp[..to_write]);
            if let Ok(s) = core::str::from_utf8(&tmp[..to_write]) {
                eprint!("{s}");
            } else {
                eprintln!("guest-fd{} {:?}", fd, &tmp[..to_write]);
            }
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                to_write as i64,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                Some(&tmp[..to_write]),
            );
        }
    }

    if ofd.fd_type == FD_TYPE_PTY_SLAVE || ofd.fd_type == FD_TYPE_PTY_MASTER {
        let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
        if access_mode == O_RDONLY {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        let mut tmp = [0u8; 4096];
        let to_write = (count as usize).min(tmp.len());
        unsafe {
            guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
        }
        let n = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
            crate::syscall::pty::slave_write(ofd.ino, &tmp[..to_write])
        } else {
            crate::syscall::pty::master_write_from_thread(ofd.ino, &tmp[..to_write], vm, base)
        };
        if n == EPIPE {
            signal::send_signal(vm, SIGPIPE);
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                Some(&tmp[..to_write]),
            );
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            n,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            Some(&tmp[..to_write]),
        );
    }

    if ofd.fd_type == FD_TYPE_PIPE {
        if !fd_table::is_pipe_write(&ofd) {
            let mut tmp = [0u8; 64];
            let to_trace = (count as usize).min(tmp.len());
            if to_trace > 0
                && crate::syscall::memory::guest_range_accessible(base, buf, to_trace as u64)
            {
                unsafe {
                    guest_mem::read_bytes(base, buf, &mut tmp[..to_trace]);
                }
                return trace_write_attempt(
                    fd,
                    nr,
                    buf,
                    count,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    Some(&tmp[..to_trace]),
                );
            }
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EBADF,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                pipe_read_open,
                pipe_write_open,
                None,
            );
        }
        let mut tmp = [0u8; 4096];
        let to_write = (count as usize).min(tmp.len());
        unsafe {
            guest_mem::read_bytes(base, buf, &mut tmp[..to_write]);
        }
        let n = super::pipe::pipe_write(ofd.ino, &tmp[..to_write]);
        if n == EPIPE {
            signal::send_signal(vm, SIGPIPE);
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                pipe_read_open,
                pipe_write_open,
                Some(&tmp[..to_write]),
            );
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            n,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            pipe_read_open,
            pipe_write_open,
            Some(&tmp[..to_write]),
        );
    }

    if ofd.fd_type == FD_TYPE_EVENTFD {
        if count < 8 {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EINVAL,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        let value = unsafe { guest_mem::read_u64(base, buf) };
        if value == u64::MAX {
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                EINVAL,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }

        let counter = fd_table::get_offset(base, vm, fd);
        if counter > EVENTFD_COUNTER_MAX.saturating_sub(value) {
            if ofd.status_flags & O_NONBLOCK != 0 {
                return trace_write_attempt(
                    fd,
                    nr,
                    buf,
                    count,
                    EAGAIN,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_PIPE_WAIT;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }

        fd_table::set_offset(base, vm, fd, counter + value);
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            8,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_SOCKET {
        let n = super::socket::socket_write(vm, base, fd, buf, count);
        if n == EPIPE {
            signal::send_signal(vm, SIGPIPE);
        }
        if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
            fd_table::pin_blocked_fd(base, vm, fd);
            vm.status = STATUS_SOCKET_SEND;
            return trace_write_attempt(
                fd,
                nr,
                buf,
                count,
                0,
                ofd_id,
                ofd.fd_type,
                ofd.ino,
                ofd.status_flags,
                0,
                0,
                None,
            );
        }
        return trace_write_attempt(
            fd,
            nr,
            buf,
            count,
            n,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    let mut trace = [0u8; 64];
    let to_trace = (count as usize).min(trace.len());
    if to_trace > 0 {
        unsafe {
            guest_mem::read_bytes(base, buf, &mut trace[..to_trace]);
        }
    }
    let n = write_regular_file_from_guest(base, buf, count, ofd.ino, ofd.offset as u64);
    if n > 0 {
        fd_table::advance_offset(base, vm, fd, n as u64);
    }
    trace_write_attempt(
        fd,
        nr,
        buf,
        count,
        n,
        ofd_id,
        ofd.fd_type,
        ofd.ino,
        ofd.status_flags,
        0,
        0,
        Some(&trace[..to_trace]),
    )
}

fn sys_writev(vm: &mut ThreadState, base: u32, fd: u64, iov_addr: u64, iovcnt: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => {
            return trace_write_attempt(
                fd,
                SYS_WRITEV,
                iov_addr,
                iovcnt,
                EBADF,
                0,
                FD_TYPE_NONE,
                0,
                0,
                0,
                0,
                None,
            );
        }
    };
    let ofd_id = fd_table::get_ofd_id(base, vm, fd).unwrap_or(0);
    let (pipe_read_open, pipe_write_open) = trace_pipe_open_state(&ofd);

    if ofd.fd_type == FD_TYPE_DEVNULL {
        let mut total = 0u64;
        for i in 0..iovcnt {
            total += unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
        }
        return trace_write_attempt(
            fd,
            SYS_WRITEV,
            iov_addr,
            iovcnt,
            total as i64,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    if ofd.fd_type == FD_TYPE_STDOUT || ofd.fd_type == FD_TYPE_STDERR {
        let mut total = 0u64;
        for i in 0..iovcnt {
            #[cfg(target_os = "wasi")]
            {
                let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * 16) };
                let len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
                let mut tmp = [0u8; 4096];
                let to_write = (len as usize).min(tmp.len());
                unsafe {
                    guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]);
                }
                crate::harness_support::append_guest_output(&tmp[..to_write]);
                if let Ok(s) = core::str::from_utf8(&tmp[..to_write]) {
                    eprint!("{s}");
                } else {
                    eprintln!("guest-fd{} {:?}", fd, &tmp[..to_write]);
                }
            }
            let len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
            total += len;
        }
        return trace_write_attempt(
            fd,
            SYS_WRITEV,
            iov_addr,
            iovcnt,
            total as i64,
            ofd_id,
            ofd.fd_type,
            ofd.ino,
            ofd.status_flags,
            0,
            0,
            None,
        );
    }

    let mut total = 0i64;
    for i in 0..iovcnt {
        let iov_base = unsafe { guest_mem::read_u64(base, iov_addr + i * 16) };
        let iov_len = unsafe { guest_mem::read_u64(base, iov_addr + i * 16 + 8) };
        if iov_len == 0 {
            continue;
        }

        if ofd.fd_type == FD_TYPE_PTY_SLAVE || ofd.fd_type == FD_TYPE_PTY_MASTER {
            let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
            if access_mode == O_RDONLY {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            let mut tmp = [0u8; 4096];
            let to_write = (iov_len as usize).min(tmp.len());
            unsafe {
                guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]);
            }
            let n = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
                crate::syscall::pty::slave_write(ofd.ino, &tmp[..to_write])
            } else {
                crate::syscall::pty::master_write_from_thread(
                    ofd.ino,
                    &tmp[..to_write],
                    vm,
                    base,
                )
            };
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                if total == 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        EPIPE,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        0,
                        0,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.status = STATUS_PIPE_WAIT;
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { 0 },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n < 0 {
                if total > 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        total,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        0,
                        0,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    n,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            total += n;
        } else if ofd.fd_type == FD_TYPE_PIPE {
            if !fd_table::is_pipe_write(&ofd) {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    EBADF,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            let mut tmp = [0u8; 4096];
            let to_write = (iov_len as usize).min(tmp.len());
            unsafe {
                guest_mem::read_bytes(base, iov_base, &mut tmp[..to_write]);
            }
            let n = super::pipe::pipe_write(ofd.ino, &tmp[..to_write]);
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                if total == 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        EPIPE,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        pipe_read_open,
                        pipe_write_open,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    total,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.status = STATUS_PIPE_WAIT;
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { 0 },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            if n < 0 {
                if total > 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        total,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        pipe_read_open,
                        pipe_write_open,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    n,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    pipe_read_open,
                    pipe_write_open,
                    None,
                );
            }
            total += n;
        } else if ofd.fd_type == FD_TYPE_SOCKET {
            let n = super::socket::socket_write(vm, base, fd, iov_base, iov_len);
            if n == EPIPE {
                signal::send_signal(vm, SIGPIPE);
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { EPIPE },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n == EAGAIN && ofd.status_flags & O_NONBLOCK == 0 {
                fd_table::pin_blocked_fd(base, vm, fd);
                vm.status = STATUS_SOCKET_SEND;
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { 0 },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            if n < 0 {
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    if total > 0 { total } else { n },
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            total += n;
        } else {
            let current_offset = fd_table::get_offset(base, vm, fd);
            let n = write_regular_file_from_guest(base, iov_base, iov_len, ofd.ino, current_offset);
            if n > 0 {
                fd_table::advance_offset(base, vm, fd, n as u64);
            }
            if n < 0 {
                if total > 0 {
                    return trace_write_attempt(
                        fd,
                        SYS_WRITEV,
                        iov_addr,
                        iovcnt,
                        total,
                        ofd_id,
                        ofd.fd_type,
                        ofd.ino,
                        ofd.status_flags,
                        0,
                        0,
                        None,
                    );
                }
                return trace_write_attempt(
                    fd,
                    SYS_WRITEV,
                    iov_addr,
                    iovcnt,
                    n,
                    ofd_id,
                    ofd.fd_type,
                    ofd.ino,
                    ofd.status_flags,
                    0,
                    0,
                    None,
                );
            }
            total += n;
        }
    }
    trace_write_attempt(
        fd,
        SYS_WRITEV,
        iov_addr,
        iovcnt,
        total,
        ofd_id,
        ofd.fd_type,
        ofd.ino,
        ofd.status_flags,
        0,
        0,
        None,
    )
}

// =========================================================================
// fstat / newfstatat
// =========================================================================

/// fstat: get file status by FD. Writes 128-byte struct stat to guest memory.
pub fn sys_fstat(vm: &mut ThreadState, base: u32, fd: u64, stat_buf: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if ofd.fd_type == FD_TYPE_DEVNULL {
        write_devnull_stat(base, stat_buf, vm.uid, vm.gid);
        return 0;
    }
    match ofd.fd_type {
        FD_TYPE_PIPE => {
            write_synthetic_stat(
                base,
                stat_buf,
                ofd.ino as u64,
                S_IFIFO | 0o600,
                vm.uid,
                vm.gid,
                0,
            );
            return 0;
        }
        FD_TYPE_PTY_MASTER | FD_TYPE_PTY_SLAVE => {
            write_synthetic_stat(
                base,
                stat_buf,
                ofd.ino as u64,
                memfs::S_IFCHR | 0o620,
                vm.uid,
                vm.gid,
                0,
            );
            return 0;
        }
        FD_TYPE_SOCKET => {
            write_synthetic_stat(
                base,
                stat_buf,
                ofd.ino as u64,
                S_IFSOCK | 0o600,
                vm.uid,
                vm.gid,
                0,
            );
            return 0;
        }
        FD_TYPE_EVENTFD | FD_TYPE_EPOLL => {
            write_synthetic_stat(base, stat_buf, fd, S_IFIFO | 0o600, vm.uid, vm.gid, 0);
            return 0;
        }
        _ => {}
    }
    write_stat(base, stat_buf, ofd.ino)
}

/// newfstatat: get file status by path. Writes 128-byte struct stat to guest memory.
pub fn sys_newfstatat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    stat_buf: u64,
    flags: u64,
) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return EINVAL;
    }

    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let raw_path = &path_buf[1..1 + len];
    let path = trim_trailing_slashes(raw_path);
    let result = if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            ENOENT
        } else if dirfd as i64 == AT_FDCWD as i64 {
            write_stat(base, stat_buf, current_dir_ino(base, vm))
        } else {
            sys_fstat(vm, base, dirfd, stat_buf)
        }
    } else if path == b"/dev/null" {
        write_devnull_stat(base, stat_buf, vm.uid, vm.gid);
        0
    } else if path == b"/dev/tty" {
        if crate::syscall::pty::has_controlling_tty(vm, base) {
            write_synthetic_stat(base, stat_buf, 1, memfs::S_IFCHR | 0o620, vm.uid, vm.gid, 0);
            0
        } else {
            ENXIO
        }
    } else {
        match resolve_at(vm, dirfd, path_addr, base) {
            Ok(ino) => write_stat(base, stat_buf, ino),
            Err(errno) => errno,
        }
    };
    crate::harness_hooks::record_path_syscall(
        vm as *const ThreadState as u32,
        crate::abi::SYS_NEWFSTATAT,
        dirfd as i64,
        raw_path,
        result,
        vm.status,
    );
    result
}

fn write_stat(base: u32, stat_buf: u64, ino: u32) -> i64 {
    let st = match memfs::stat(ino) {
        Some(s) => s,
        None => return ENOENT,
    };
    unsafe {
        guest_mem::zero_mem(base, stat_buf, 128);
        guest_mem::write_u64(base, stat_buf, 1); // st_dev
        guest_mem::write_u64(base, stat_buf + 8, st.ino); // st_ino
        guest_mem::write_u32(base, stat_buf + 16, st.mode); // st_mode
        guest_mem::write_u32(base, stat_buf + 20, st.nlink); // st_nlink
        guest_mem::write_u32(base, stat_buf + 24, st.uid); // st_uid
        guest_mem::write_u32(base, stat_buf + 28, st.gid); // st_gid
        guest_mem::write_u64(base, stat_buf + 48, st.size); // st_size
        guest_mem::write_u32(base, stat_buf + 56, 4096u32); // st_blksize
        let blocks = st.size.div_ceil(512);
        guest_mem::write_u64(base, stat_buf + 64, blocks); // st_blocks
    }
    0
}

fn write_devnull_stat(base: u32, stat_buf: u64, uid: u32, gid: u32) {
    write_synthetic_stat(base, stat_buf, 1, memfs::S_IFCHR | 0o666, uid, gid, 0);
}

fn write_synthetic_stat(
    base: u32,
    stat_buf: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
) {
    unsafe {
        guest_mem::zero_mem(base, stat_buf, 128);
        guest_mem::write_u64(base, stat_buf, 1); // st_dev
        guest_mem::write_u64(base, stat_buf + 8, ino); // st_ino
        guest_mem::write_u32(base, stat_buf + 16, mode); // st_mode
        guest_mem::write_u32(base, stat_buf + 20, 1); // st_nlink
        guest_mem::write_u32(base, stat_buf + 24, uid); // st_uid
        guest_mem::write_u32(base, stat_buf + 28, gid); // st_gid
        guest_mem::write_u64(base, stat_buf + 48, size); // st_size
        guest_mem::write_u32(base, stat_buf + 56, 4096u32); // st_blksize
        guest_mem::write_u64(base, stat_buf + 64, size.div_ceil(512)); // st_blocks
    }
}

// =========================================================================
// mkdir / unlink / rename
// =========================================================================

/// mkdirat: create a directory.
pub fn sys_mkdirat(vm: &mut ThreadState, base: u32, dirfd: u64, path_addr: u64, mode: u64) -> i64 {
    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let path = trim_trailing_slashes(&path_buf[1..1 + len]);
    if path.is_empty() {
        return ENOENT;
    }

    if path[0] == b'/' {
        // Absolute path
        let (parent_ino, name) = split_parent_name(path);
        if parent_ino == 0 || name.is_empty() {
            return ENOENT;
        }
        let ino = memfs::create_dir(parent_ino, name, mode as u32 & 0o7777);
        if ino == 0 {
            return EEXIST;
        }
        0
    } else {
        // Relative path
        let base_ino = match dirfd_base_ino(vm, dirfd, base) {
            Ok(ino) => ino,
            Err(errno) => return errno,
        };

        let (parent_rel, name) = split_relative_parent_name(path);
        if name.is_empty() {
            return ENOENT;
        }

        let parent_ino = if parent_rel.is_empty() {
            base_ino
        } else {
            memfs::resolve_path_from(base_ino, parent_rel)
        };
        if parent_ino == 0 {
            return ENOENT;
        }
        let ino = memfs::create_dir(parent_ino, name, mode as u32 & 0o7777);
        if ino == 0 {
            return EEXIST;
        }
        0
    }
}

/// unlinkat: remove a file entry from its parent directory.
pub fn sys_unlinkat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    flags: u64,
) -> i64 {
    if flags & !AT_REMOVEDIR != 0 {
        return EINVAL;
    }

    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let path = trim_trailing_slashes(&path_buf[1..1 + len]);
    if path.is_empty() {
        return ENOENT;
    }

    if path[0] == b'/' {
        // Absolute path
        let (parent_ino, name) = split_parent_name(path);
        if parent_ino == 0 || name.is_empty() {
            return ENOENT;
        }
        if flags & AT_REMOVEDIR != 0 {
            memfs::rmdir(parent_ino, name)
        } else {
            memfs::unlink(parent_ino, name)
        }
    } else {
        // Relative path: find parent and leaf name
        let (parent_rel, name) = split_relative_parent_name(path);
        if name.is_empty() {
            return ENOENT;
        }

        let base_ino = match dirfd_base_ino(vm, dirfd, base) {
            Ok(ino) => ino,
            Err(errno) => return errno,
        };

        let parent_ino = if parent_rel.is_empty() {
            base_ino
        } else {
            memfs::resolve_path_from(base_ino, parent_rel)
        };
        if parent_ino == 0 {
            return ENOENT;
        }
        if flags & AT_REMOVEDIR != 0 {
            memfs::rmdir(parent_ino, name)
        } else {
            memfs::unlink(parent_ino, name)
        }
    }
}

// =========================================================================
// getdents64
// =========================================================================

/// getdents64: read directory entries into guest buffer.
/// Writes linux_dirent64 records (variable-size, 8-byte aligned).
pub fn sys_getdents64(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, buf_size: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let dir_ino = ofd.ino;
    let start_index = ofd.offset.max(0) as u64;
    let mut offset = 0u64;
    let max = buf_size;
    let mut entry_index = 0u64;
    let mut buffer_full = false;

    memfs::readdir(dir_ino, |name, ino| {
        if buffer_full {
            return;
        }
        if entry_index < start_index {
            entry_index += 1;
            return;
        }

        // d_reclen = 19 + name_len + 1 (null) + padding to 8-byte align
        let reclen = ((19 + name.len() + 1) + 7) & !7;
        if offset + reclen as u64 > max {
            buffer_full = true;
            return;
        }

        let entry_addr = buf + offset;
        unsafe {
            guest_mem::zero_mem(base, entry_addr, reclen);
            guest_mem::write_u64(base, entry_addr, ino as u64); // d_ino
            guest_mem::write_u64(base, entry_addr + 8, offset + reclen as u64); // d_off
            guest_mem::write_u16(base, entry_addr + 16, reclen as u16); // d_reclen

            let st = memfs::stat(ino);
            let d_type = match st {
                Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFDIR => DT_DIR,
                Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFREG => DT_REG,
                _ => DT_UNKNOWN,
            };
            guest_mem::write_u8(base, entry_addr + 18, d_type); // d_type
            guest_mem::write_bytes(base, entry_addr + 19, name); // d_name
            guest_mem::write_u8(base, entry_addr + 19 + name.len() as u64, 0); // null terminator
        }
        offset += reclen as u64;
        entry_index += 1;
    });

    fd_table::set_offset(base, vm, fd, entry_index);
    offset as i64
}

// =========================================================================
// lseek
// =========================================================================

/// lseek: reposition OFD offset. Supports SEEK_SET (0), SEEK_CUR (1), SEEK_END (2).
pub fn sys_lseek(vm: &mut ThreadState, base: u32, fd: u64, offset: i64, whence: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let new_offset = match whence {
        0 => offset as u64,                // SEEK_SET
        1 => (ofd.offset + offset) as u64, // SEEK_CUR
        2 => {
            // SEEK_END
            let st = memfs::stat(ofd.ino);
            match st {
                Some(s) => (s.size as i64 + offset) as u64,
                None => return EINVAL,
            }
        }
        _ => return EINVAL,
    };

    fd_table::set_offset(base, vm, fd, new_offset);
    new_offset as i64
}

// =========================================================================
// faccessat / readlinkat / ftruncate
// =========================================================================

/// faccessat: check file accessibility (existence check only).
pub fn sys_faccessat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    _mode: u64,
) -> i64 {
    let mut path_buf = [0u8; 512];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf) };
    let raw_path = &path_buf[..len];
    let result = match resolve_at(vm, dirfd, path_addr, base) {
        Ok(_) => 0,
        Err(errno) => errno,
    };
    crate::harness_hooks::record_path_syscall(
        vm as *const ThreadState as u32,
        crate::abi::SYS_FACCESSAT,
        dirfd as i64,
        raw_path,
        result,
        vm.status,
    );
    result
}

pub fn sys_fchmodat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    mode: u64,
    _flags: u64,
) -> i64 {
    let ino = match resolve_at(vm, dirfd, path_addr, base) {
        Ok(ino) => ino,
        Err(errno) => return errno,
    };

    memfs::set_mode(ino, mode as u32)
}

pub fn sys_fchownat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    owner: u64,
    group: u64,
    flags: u64,
) -> i64 {
    if flags != 0 && flags != AT_SYMLINK_NOFOLLOW {
        return EINVAL;
    }

    let ino = match resolve_at(vm, dirfd, path_addr, base) {
        Ok(ino) => ino,
        Err(errno) => return errno,
    };

    let uid = if owner as i64 == -1 {
        None
    } else {
        Some(owner as u32)
    };
    let gid = if group as i64 == -1 {
        None
    } else {
        Some(group as u32)
    };

    memfs::set_owner(ino, uid, gid)
}

/// readlinkat: read symbolic link.
/// https://man7.org/linux/man-pages/man2/readlinkat.2.html
pub fn sys_readlinkat(
    vm: &mut ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
    buf: u64,
    bufsiz: u64,
) -> i64 {
    if bufsiz == 0 {
        return EINVAL;
    }

    let mut path_buf = [0u8; 512];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf) };
    let path = trim_trailing_slashes(&path_buf[..len]);
    let result = if path.is_empty() {
        if dirfd as i32 == AT_FDCWD {
            ENOENT
        } else {
            match fd_table::get_ofd(base, vm, dirfd) {
                Some(ofd) => {
                    let mut link_buf = [0u8; 512];
                    let n = memfs::read_link(ofd.ino, &mut link_buf);
                    if n == 0 {
                        EINVAL
                    } else {
                        let out = n.min(bufsiz as usize);
                        unsafe {
                            guest_mem::write_bytes(base, buf, &link_buf[..out]);
                        }
                        out as i64
                    }
                }
                None => EBADF,
            }
        }
    } else {
        let ino = match resolve_at(vm, dirfd, path_addr, base) {
            Ok(ino) => ino,
            Err(errno) => {
                crate::harness_hooks::record_path_syscall(
                    vm as *const ThreadState as u32,
                    crate::abi::SYS_READLINKAT,
                    dirfd as i64,
                    &path_buf[..len],
                    errno,
                    vm.status,
                );
                return errno;
            }
        };

        let mut link_buf = [0u8; 512];
        let n = memfs::read_link(ino, &mut link_buf);
        if n == 0 {
            EINVAL
        } else {
            let out = n.min(bufsiz as usize);
            unsafe {
                guest_mem::write_bytes(base, buf, &link_buf[..out]);
            }
            out as i64
        }
    };
    crate::harness_hooks::record_path_syscall(
        vm as *const ThreadState as u32,
        crate::abi::SYS_READLINKAT,
        dirfd as i64,
        &path_buf[..len],
        result,
        vm.status,
    );
    result
}

/// ftruncate: truncate file to specified length.
pub fn sys_ftruncate(vm: &mut ThreadState, base: u32, fd: u64, length: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    memfs::truncate(ofd.ino, length)
}

/// truncate: truncate file at path to specified length.
/// Signature: truncate(const char *path, off_t length)
///   a0 = path pointer, a1 = length
/// https://man7.org/linux/man-pages/man2/truncate.2.html
pub fn sys_truncate(_vm: &mut ThreadState, base: u32, path_addr: u64, length: u64) -> i64 {
    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let path = trim_trailing_slashes(&path_buf[1..1 + len]);

    if path.is_empty() {
        return ENOENT;
    }

    let ino = if path[0] == b'/' {
        memfs::resolve_path(path)
    } else {
        memfs::resolve_path_from(current_dir_ino(base, _vm), path)
    };
    if ino == 0 {
        return ENOENT;
    }

    // Check that the target is a regular file (not a directory)
    match memfs::stat(ino) {
        Some(st) if st.mode & memfs::S_IFMT == memfs::S_IFDIR => return EISDIR,
        Some(_) => {}
        None => return ENOENT,
    }

    memfs::truncate(ino, length)
}
