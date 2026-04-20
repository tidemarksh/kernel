use super::path::{
    dirfd_base_ino, resolve_at, resolve_path_with_symlink_policy, split_relative_parent_name,
    trim_trailing_slashes,
};
use super::state::process_fs_ring_base;
use super::{
    AT_FDCWD, FS_EFFECT_MEMFS_FILE_DATA, FS_EFFECT_MEMFS_MUTATION, FS_EFFECT_SHARED_OFD_STATE,
    MAX_PATH_SYMLINK_FOLLOWS, PENDING_FS_PATH_MAX, sys_fstat, sys_write,
};
use crate::abi::*;
use crate::fs::{fd_table, memfs, ring_buffer};
use crate::guest_mem;
use crate::types::ThreadState;

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
            let mut effects = 0;
            if request.flags & (O_CREAT as u32) != 0 {
                effects |= FS_EFFECT_MEMFS_MUTATION;
            }
            if request.flags & (O_TRUNC as u32) != 0 {
                effects |= FS_EFFECT_MEMFS_FILE_DATA;
            }
            effects
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
        ring_buffer::FS_OP_MKDIR | ring_buffer::FS_OP_UNLINK | ring_buffer::FS_OP_RENAME => {
            FS_EFFECT_MEMFS_MUTATION
        }
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
        | ring_buffer::FS_OP_RENAME
        | ring_buffer::FS_OP_TRUNCATE => request.path_ptr,
        _ => 0,
    }
}

fn pending_request_secondary_path_ptr_inner(request: &ring_buffer::FsRequestInfo) -> u64 {
    match request.opcode {
        ring_buffer::FS_OP_RENAME => request.buf_ptr,
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
    pending_request_absolute_path_impl(vm_ptr, base, out_ptr, out_len, false)
}

pub fn pending_request_secondary_absolute_path(
    vm_ptr: u32,
    base: u32,
    out_ptr: u32,
    out_len: u32,
) -> i64 {
    pending_request_absolute_path_impl(vm_ptr, base, out_ptr, out_len, true)
}

fn pending_request_absolute_path_impl(
    vm_ptr: u32,
    base: u32,
    out_ptr: u32,
    out_len: u32,
    secondary: bool,
) -> i64 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 || out_ptr == 0 || out_len == 0 {
            return 0;
        }
        let Some(request) = ring_buffer::peek_request_info(ring_base) else {
            return 0;
        };
        let path_ptr = if secondary {
            pending_request_secondary_path_ptr_inner(&request)
        } else {
            pending_request_path_ptr_inner(&request)
        };
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
            let dirfd = if secondary {
                request.offset
            } else {
                request.fd as u64
            };
            let base_ino = match dirfd_base_ino(vm, dirfd, base) {
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
    if ofd.fd_type == FD_TYPE_PIPE
        || ofd.fd_type == FD_TYPE_EVENTFD
        || ofd.fd_type == FD_TYPE_PTY_MASTER
        || ofd.fd_type == FD_TYPE_PTY_SLAVE
    {
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

pub fn dispatch_renameat2(
    vm: &mut ThreadState,
    base: u32,
    olddirfd: u64,
    oldpath_addr: u64,
    newdirfd: u64,
    newpath_addr: u64,
    flags: u64,
) -> i64 {
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_RENAME,
        olddirfd as i32,
        newdirfd,
        0,
        newpath_addr,
        oldpath_addr,
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
