use super::path::{
    dirfd_base_ino, resolve_at, resolve_path_with_symlink_policy, split_relative_parent_name,
    trim_trailing_slashes,
};
use super::state::process_fs_ring_base;
use super::{AT_FDCWD, MAX_PATH_SYMLINK_FOLLOWS, PENDING_FS_PATH_MAX, sys_fstat, sys_write};
use crate::abi::*;
use crate::fs::{fd_table, memfs, ring_buffer};
use crate::guest_mem;
use crate::syscall::sync_effects::mark_fork_shared_ofd_sync_effect;
use crate::types::{OpenFileDesc, ThreadState};

pub const FS_EFFECT_MEMFS_MUTATION: u32 = 1 << 0;
pub const FS_EFFECT_SHARED_OFD_STATE: u32 = 1 << 1;
pub const FS_EFFECT_MEMFS_FILE_DATA: u32 = 1 << 2;

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

    let vm_ptr = vm as *mut ThreadState as u32;
    while ring_buffer::read_completion_for_vm(ring_base, vm_ptr).is_some() {}
    let (request_ofd_id, request_ino) = request_fd_identity(base, vm, fd);

    let idx = ring_buffer::submit_request(
        ring_base,
        opcode,
        fd,
        offset,
        len,
        buf_ptr,
        path_ptr,
        flags,
        mode,
        vm_ptr,
        request_ofd_id,
        request_ino,
    );
    if idx < 0 {
        return EAGAIN;
    }

    vm.pending_fs_request_id = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr)
        .map_or(0, |request| request.request_id);

    if request_ofd_id != 0 {
        fd_table::pin_blocked_fd(base, vm, fd as u64);
    }
    vm.status = STATUS_FS;
    0
}

fn request_fd_identity(base: u32, vm: &ThreadState, fd: i32) -> (u32, u32) {
    if fd < 0 || fd as usize >= MAX_FDS {
        return (0, 0);
    }
    let Some(ofd_id) = fd_table::get_ofd_id(base, vm, fd as u64) else {
        return (0, 0);
    };
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return (ofd_id, 0);
    };
    (ofd_id, ofd.ino)
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

fn with_pending_request<T>(
    vm_ptr: u32,
    base: u32,
    default: T,
    f: impl FnOnce(&ThreadState, &ring_buffer::FsRequestInfo) -> T,
) -> T {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 {
            return default;
        }
        let Some(request) = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr) else {
            return default;
        };
        f(vm, &request)
    }
}

fn classify_pending_request_effects(request: &ring_buffer::FsRequestInfo) -> u32 {
    match request.opcode {
        ring_buffer::FS_OP_OPENAT => {
            let mut effects = FS_EFFECT_SHARED_OFD_STATE;
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
        ring_buffer::FS_OP_TRUNCATE | ring_buffer::FS_OP_FSYNC => FS_EFFECT_MEMFS_FILE_DATA,
        ring_buffer::FS_OP_MKDIR | ring_buffer::FS_OP_UNLINK | ring_buffer::FS_OP_RENAME => {
            FS_EFFECT_MEMFS_MUTATION
        }
        _ => 0,
    }
}

fn openat_can_run_locally(flags: u32) -> bool {
    let access_mode = (flags as i32) & fd_table::OPEN_ACCESS_MODE_MASK;
    access_mode == O_RDONLY && flags & ((O_CREAT | O_TRUNC) as u32) == 0
}

fn openat_targets_kernel_local_device(base: u32, path_addr: u64) -> bool {
    let mut path_buf = [0u8; 512];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf) };
    let path = trim_trailing_slashes(&path_buf[..len]);
    matches!(path, b"/dev/null" | b"/dev/tty")
}

fn regular_file_write_offset(ofd: &OpenFileDesc, ofd_id: u32) -> u64 {
    if ofd.status_flags & O_APPEND != 0 {
        return memfs::stat(ofd.ino).map(|stat| stat.size).unwrap_or(0);
    }
    fd_table::get_offset_by_id(ofd_id)
        .max(fd_table::get_offset_floor_by_id(ofd_id))
        .max(ofd.offset as u64)
}

pub fn pending_request_effects(vm_ptr: u32, base: u32) -> u32 {
    with_pending_request(vm_ptr, base, 0, |_, request| {
        classify_pending_request_effects(request)
    })
}

fn pending_request_target_ino_inner(
    vm: &ThreadState,
    base: u32,
    request: &ring_buffer::FsRequestInfo,
) -> u32 {
    match request.opcode {
        ring_buffer::FS_OP_READ
        | ring_buffer::FS_OP_WRITE
        | ring_buffer::FS_OP_GETDENTS
        | ring_buffer::FS_OP_LSEEK
        | ring_buffer::FS_OP_MMAP => {
            if request.ino > 0 {
                return request.ino;
            }
            if request.fd <= 0 {
                return 0;
            }
            fd_table::get_ofd(base, vm, request.fd as u64).map_or(0, |ofd| ofd.ino)
        }
        ring_buffer::FS_OP_CLOSE => 0,
        ring_buffer::FS_OP_TRUNCATE => {
            if request.fd > 0 {
                if request.ino > 0 {
                    return request.ino;
                }
                return fd_table::get_ofd(base, vm, request.fd as u64).map_or(0, |ofd| ofd.ino);
            }
            if request.path_ptr == 0 {
                return 0;
            }
            resolve_at(vm, AT_FDCWD as u64, request.path_ptr, base).unwrap_or(0)
        }
        ring_buffer::FS_OP_FSYNC => {
            if request.ino > 0 {
                return request.ino;
            }
            if request.fd <= 0 {
                return 0;
            }
            fd_table::get_ofd(base, vm, request.fd as u64).map_or(0, |ofd| ofd.ino)
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
    with_pending_request(vm_ptr, base, 0, |vm, request| {
        pending_request_target_ino_inner(vm, base, request)
    })
}

pub fn pending_request_opcode(vm_ptr: u32, base: u32) -> u32 {
    with_pending_request(vm_ptr, base, 0, |_, request| request.opcode)
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

fn pending_request_selected_path_ptr(request: &ring_buffer::FsRequestInfo, secondary: bool) -> u64 {
    if secondary {
        pending_request_secondary_path_ptr_inner(request)
    } else {
        pending_request_path_ptr_inner(request)
    }
}

fn pending_request_path_len_inner(base: u32, path_ptr: u64) -> u32 {
    let guest_limit = crate::wasm::memory_size_bytes().saturating_sub(base as u64);
    if path_ptr >= guest_limit {
        return 0;
    }
    let mut len = 0u32;
    while (len as usize) < PENDING_FS_PATH_MAX {
        let Some(cur) = path_ptr.checked_add(len as u64) else {
            return 0;
        };
        if cur >= guest_limit {
            return 0;
        }
        if crate::syscall::memory::range_has_prot_none(cur, 1) {
            return 0;
        }
        if unsafe { guest_mem::read_u8(base, cur) } == 0 {
            return len;
        }
        len += 1;
    }
    len
}

pub fn pending_request_path_ptr(vm_ptr: u32, base: u32) -> u64 {
    with_pending_request(vm_ptr, base, 0, |_, request| {
        pending_request_path_ptr_inner(request)
    })
}

pub fn pending_request_path_len(vm_ptr: u32, base: u32) -> u32 {
    with_pending_request(vm_ptr, base, 0, |_, request| {
        let path_ptr = pending_request_path_ptr_inner(request);
        if path_ptr == 0 {
            return 0;
        }
        pending_request_path_len_inner(base, path_ptr)
    })
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
    if out_ptr == 0 || out_len == 0 {
        return 0;
    }
    with_pending_request(vm_ptr, base, 0, |vm, request| {
        let path_ptr = pending_request_selected_path_ptr(request, secondary);
        if path_ptr == 0 {
            return 0;
        }

        let mut path_buf = [0u8; 513];
        let len = unsafe { guest_mem::read_cstr(base, path_ptr, &mut path_buf[1..]) };
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
        let out = unsafe { core::slice::from_raw_parts_mut(out_ptr as *mut u8, out_len as usize) };
        out[..absolute_len].copy_from_slice(&absolute[..absolute_len]);
        absolute_len as i64
    })
}

pub fn resume_from_fs(vm_ptr: u32, base: u32) -> i64 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        let ring_base = process_fs_ring_base(base, vm);
        if ring_base == 0 {
            vm.x[10] = ENOMEM as u64;
            fd_table::clear_blocked_ofd_pin(vm);
            vm.status = STATUS_OK;
            return ENOMEM;
        }

        let Some(result) = ring_buffer::read_completion_for_vm(ring_base, vm_ptr) else {
            if !ring_buffer::has_pending_request_for_vm(ring_base, vm_ptr) {
                fd_table::clear_blocked_ofd_pin(vm);
                vm.status = STATUS_OK;
                return vm.x[10] as i64;
            }
            vm.status = STATUS_FS;
            return EAGAIN;
        };
        vm.x[10] = result as u64;
        vm.pending_fs_request_id = 0;
        fd_table::clear_blocked_ofd_pin(vm);
        if vm.status == STATUS_EXECVE_SPAWN {
            return result;
        }
        vm.status = STATUS_OK;
        result
    }
}

pub fn resume_from_fs_result(vm_ptr: u32, result: i64) -> i64 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        vm.x[10] = result as u64;
        vm.pending_fs_request_id = 0;
        fd_table::clear_blocked_ofd_pin(vm);
        if vm.status != STATUS_EXECVE_SPAWN {
            vm.status = STATUS_OK;
        }
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
    if openat_can_run_locally(flags as u32) || openat_targets_kernel_local_device(base, path_addr) {
        return crate::syscall::fs::sys_openat(vm, base, dirfd, path_addr, flags, mode);
    }

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

#[cfg(test)]
mod tests {
    use super::{
        dispatch_ftruncate, dispatch_getdents64, dispatch_lseek, dispatch_mmap, dispatch_openat,
        dispatch_pread64, dispatch_read, dispatch_write, pending_request_target_ino,
        process_fs_ring_base, process_pending_requests, resume_from_fs, resume_from_fs_result,
    };
    use crate::abi::{
        AF_UNIX, CLONE_THREAD, CLONE_VM, EAGAIN, EINVAL, ENOENT, MAP_PRIVATE, O_APPEND, O_CREAT,
        O_RDONLY, O_TRUNC, O_WRONLY, PROT_READ, SOCK_STREAM, STATUS_FS, STATUS_OK, SYS_WRITE,
        SYS_WRITEV,
    };
    use crate::fs::{memfs, ring_buffer};
    use crate::harness::TestVm;
    use crate::syscall::fd_table;
    use crate::syscall::socket::sys_socketpair;
    use crate::types::ThreadState;

    const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;

    #[test]
    fn dispatch_openat_runs_read_only_existing_files_locally() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"hello.txt", b"hello");
        let path_addr = vm.write_path(0x400, b"/hello.txt");

        let fd = dispatch_openat(
            &mut vm.vm,
            vm.base,
            (-100i64) as u64,
            path_addr,
            O_RDONLY as u64,
            0,
        );

        assert!(fd >= 3);
        assert_eq!(vm.vm.status, STATUS_OK);

        let mut buf = [0u8; 5];
        assert_eq!(vm.sys_read(fd, &mut buf), 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn dispatch_read_uses_local_resident_file_hit() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"resident.txt", b"abcdef");
        let fd = vm.sys_openat(b"/resident.txt", O_RDONLY);
        assert!(fd >= 3);
        let buf_addr = vm.scratch + 0x5000;

        let result = dispatch_read(&mut vm.vm, vm.base, fd as u64, buf_addr, 3);

        assert_eq!(result, 3);
        assert_eq!(vm.vm.status, STATUS_OK);
        assert_eq!(vm.guest_mem(buf_addr, 3), b"abc".to_vec());
        assert_eq!(vm.sys_lseek(fd, 0, 1), 3);
    }

    #[test]
    fn dispatch_read_falls_back_to_fs_ring_on_external_file_miss() {
        let mut vm = TestVm::new();
        let ino = memfs::create_file(1, b"external.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(memfs::set_file_external(ino, 6), 0);
        assert_eq!(memfs::stat(ino).map(|st| st.size), Some(6));
        let fd = vm.sys_openat(b"/external.txt", O_RDONLY);
        assert!(fd >= 3);
        let buf_addr = vm.scratch + 0x5100;

        let result = dispatch_read(&mut vm.vm, vm.base, fd as u64, buf_addr, 3);

        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);
    }

    #[test]
    fn dispatch_read_completes_when_local_hit_satisfies_count() {
        let mut vm = TestVm::new();
        let ino = memfs::create_file(1, b"external-full-page.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(memfs::set_file_external(ino, 8192), 0);
        let resident = [b'x'; 4096];
        assert_eq!(memfs::write_file(ino, 0, &resident), 4096);
        let fd = vm.sys_openat(b"/external-full-page.txt", O_RDONLY);
        assert!(fd >= 3);
        let buf_addr = vm.scratch + 0x5120;

        let result = dispatch_read(&mut vm.vm, vm.base, fd as u64, buf_addr, 4096);

        assert_eq!(result, 4096);
        assert_eq!(vm.vm.status, STATUS_OK);
        assert_eq!(vm.guest_mem(buf_addr, 4), b"xxxx".to_vec());
        assert_eq!(fd_table::get_offset(vm.base, &vm.vm, fd as u64), 4096);
        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        assert!(ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr).is_none());
    }

    #[test]
    fn dispatch_read_requests_backing_after_partial_resident_hit() {
        let mut vm = TestVm::new();
        let ino = memfs::create_file(1, b"external-partial-page.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(memfs::set_file_external(ino, 8192), 0);
        assert_eq!(memfs::write_file(ino, 0, b"x"), 1);
        let fd = vm.sys_openat(b"/external-partial-page.txt", O_RDONLY);
        assert!(fd >= 3);
        let buf_addr = vm.scratch + 0x5140;

        let result = dispatch_read(&mut vm.vm, vm.base, fd as u64, buf_addr, 4095);

        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);
        assert_eq!(vm.guest_mem(buf_addr, 1), b"x".to_vec());
        assert_eq!(fd_table::get_offset(vm.base, &vm.vm, fd as u64), 0);
        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        assert!(ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr).is_some());
    }

    #[test]
    fn dispatch_read_preserves_current_offset_in_fs_ring_request() {
        let mut vm = TestVm::new();
        let ino = memfs::create_file(1, b"external-offset.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(memfs::set_file_external(ino, 21), 0);
        let fd = vm.sys_openat(b"/external-offset.txt", O_RDONLY);
        assert!(fd >= 3);
        assert_eq!(vm.sys_lseek(fd, 7, 0), 7);
        let buf_addr = vm.scratch + 0x5150;

        let result = dispatch_read(&mut vm.vm, vm.base, fd as u64, buf_addr, 8);

        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);
        assert_eq!(fd_table::get_offset(vm.base, &vm.vm, fd as u64), 7);
        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let request = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr)
            .expect("read should submit a host FS request");
        assert_eq!(request.opcode, ring_buffer::FS_OP_READ);
        assert_eq!(request.fd, fd as i32);
        assert_eq!(request.offset, 7);
        assert_eq!(request.len, 8);
        assert_eq!(request.buf_ptr, buf_addr);
    }

    #[test]
    fn fs_ring_read_completion_uses_submit_inode_after_fd_reuse() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"read-original.txt", b"abcdef");
        vm.memfs.create_file(b"read-reused.txt", b"uvwxyz");
        let original_ino = memfs::resolve_path(b"/read-original.txt");
        let reused_ino = memfs::resolve_path(b"/read-reused.txt");
        assert_ne!(original_ino, 0);
        assert_ne!(reused_ino, 0);
        assert_ne!(original_ino, reused_ino);

        let fd = vm.sys_openat(b"/read-original.txt", O_RDONLY);
        assert!(fd >= 3);
        let original_ofd = fd_table::get_ofd_id(vm.base, &vm.vm, fd as u64).unwrap_or(0);
        assert_ne!(original_ofd, 0);
        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let buf_addr = vm.scratch + 0x5180;
        assert!(
            ring_buffer::submit_request(
                ring_base,
                ring_buffer::FS_OP_READ,
                fd as i32,
                2,
                3,
                buf_addr,
                0,
                0,
                0,
                vm_ptr,
                original_ofd,
                original_ino,
            ) >= 0
        );
        vm.vm.pending_fs_request_id = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr)
            .map_or(0, |request| request.request_id);
        vm.vm.status = STATUS_FS;

        assert_eq!(fd_table::sys_close(&mut vm.vm, vm.base, fd as u64), 0);
        let reused_fd = vm.sys_openat(b"/read-reused.txt", O_RDONLY);
        assert_eq!(reused_fd, fd);
        assert_eq!(
            fd_table::get_ofd(vm.base, &vm.vm, fd as u64).map(|ofd| ofd.ino),
            Some(reused_ino),
        );

        process_pending_requests(vm_ptr, vm.base);
        assert_eq!(resume_from_fs(vm_ptr, vm.base), 3);
        assert_eq!(vm.guest_mem(buf_addr, 3), b"cde".to_vec());
        assert_eq!(fd_table::get_offset(vm.base, &vm.vm, fd as u64), 0);
    }

    #[test]
    fn dispatch_getdents64_runs_through_kernel_worker_and_advances_offset() {
        let mut vm = TestVm::new();
        assert_eq!(vm.sys_mkdirat(b"/getdents-dir"), 0);
        let fd_a = vm.sys_openat(b"/getdents-dir/a", O_CREAT | O_WRONLY);
        assert!(fd_a >= 3);
        assert_eq!(vm.sys_close(fd_a), 0);
        let fd_b = vm.sys_openat(b"/getdents-dir/b", O_CREAT | O_WRONLY);
        assert!(fd_b >= 3);
        assert_eq!(vm.sys_close(fd_b), 0);

        let dir_fd = vm.sys_openat(b"/getdents-dir", O_RDONLY);
        assert!(dir_fd >= 3);
        let dir_ino = memfs::resolve_path(b"/getdents-dir");
        assert_ne!(dir_ino, 0);
        let buf_addr = vm.scratch + 0x51c0;

        let result = dispatch_getdents64(&mut vm.vm, vm.base, dir_fd as u64, buf_addr, 24);

        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);
        assert_eq!(fd_table::get_offset(vm.base, &vm.vm, dir_fd as u64), 0);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        process_pending_requests(vm_ptr, vm.base);
        assert_eq!(resume_from_fs(vm_ptr, vm.base), 24);
        assert_eq!(vm.vm.status, STATUS_OK);
        assert_eq!(fd_table::get_offset(vm.base, &vm.vm, dir_fd as u64), 1);
        assert_eq!(
            pending_request_target_ino(&mut vm.vm as *mut _ as u32, vm.base),
            0
        );
    }

    #[test]
    fn fs_ring_getdents_completion_uses_submit_directory_after_fd_reuse() {
        let mut vm = TestVm::new();
        assert_eq!(vm.sys_mkdirat(b"/getdents-original"), 0);
        let fd_a = vm.sys_openat(b"/getdents-original/a", O_CREAT | O_WRONLY);
        assert!(fd_a >= 3);
        assert_eq!(vm.sys_close(fd_a), 0);
        let fd_b = vm.sys_openat(b"/getdents-original/b", O_CREAT | O_WRONLY);
        assert!(fd_b >= 3);
        assert_eq!(vm.sys_close(fd_b), 0);
        assert_eq!(vm.sys_mkdirat(b"/getdents-reused"), 0);
        let fd_x = vm.sys_openat(b"/getdents-reused/x", O_CREAT | O_WRONLY);
        assert!(fd_x >= 3);
        assert_eq!(vm.sys_close(fd_x), 0);

        let fd = vm.sys_openat(b"/getdents-original", O_RDONLY);
        assert!(fd >= 3);
        let original_ino = memfs::resolve_path(b"/getdents-original");
        let reused_ino = memfs::resolve_path(b"/getdents-reused");
        assert_ne!(original_ino, 0);
        assert_ne!(reused_ino, 0);
        assert_ne!(original_ino, reused_ino);
        let original_ofd = fd_table::get_ofd_id(vm.base, &vm.vm, fd as u64).unwrap_or(0);
        assert_ne!(original_ofd, 0);

        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let buf_addr = vm.scratch + 0x5200;
        assert!(
            ring_buffer::submit_request(
                ring_base,
                ring_buffer::FS_OP_GETDENTS,
                fd as i32,
                1,
                24,
                buf_addr,
                0,
                0,
                0,
                vm_ptr,
                original_ofd,
                original_ino,
            ) >= 0
        );
        vm.vm.pending_fs_request_id = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr)
            .map_or(0, |request| request.request_id);
        vm.vm.status = STATUS_FS;

        assert_eq!(vm.sys_close(fd), 0);
        let reused_fd = vm.sys_openat(b"/getdents-reused", O_RDONLY);
        assert_eq!(reused_fd, fd);
        assert_eq!(
            fd_table::get_ofd_id(vm.base, &vm.vm, reused_fd as u64),
            Some(original_ofd),
        );
        assert_eq!(
            fd_table::get_ofd(vm.base, &vm.vm, reused_fd as u64).map(|ofd| ofd.ino),
            Some(reused_ino),
        );

        process_pending_requests(vm_ptr, vm.base);
        assert_eq!(resume_from_fs(vm_ptr, vm.base), 24);
        assert_eq!(vm.guest_mem(buf_addr + 19, 1), b"a".to_vec());
        assert_eq!(vm.guest_mem(buf_addr + 20, 1), [0u8].to_vec());
        assert_eq!(fd_table::get_offset(vm.base, &vm.vm, reused_fd as u64), 0);
    }

    #[test]
    fn fs_ring_getdents_completion_marks_shared_ofd_sync_effect() {
        let mut vm = TestVm::new();
        assert_eq!(vm.sys_mkdirat(b"/getdents-sync"), 0);
        let fd_a = vm.sys_openat(b"/getdents-sync/a", O_CREAT | O_WRONLY);
        assert!(fd_a >= 3);
        assert_eq!(vm.sys_close(fd_a), 0);

        let dir_fd = vm.sys_openat(b"/getdents-sync", O_RDONLY);
        assert!(dir_fd >= 3);
        let dir_ino = memfs::resolve_path(b"/getdents-sync");
        assert_ne!(dir_ino, 0);
        let ofd_id = fd_table::get_ofd_id(vm.base, &vm.vm, dir_fd as u64).unwrap_or(0);
        assert_ne!(ofd_id, 0);

        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let buf_addr = vm.scratch + 0x5300;
        assert!(
            ring_buffer::submit_request(
                ring_base,
                ring_buffer::FS_OP_GETDENTS,
                dir_fd as i32,
                0,
                24,
                buf_addr,
                0,
                0,
                0,
                vm_ptr,
                ofd_id,
                dir_ino,
            ) >= 0
        );
        vm.vm.pending_fs_request_id = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr)
            .map_or(0, |request| request.request_id);
        vm.vm.status = STATUS_FS;

        process_pending_requests(vm_ptr, vm.base);
        assert_eq!(resume_from_fs(vm_ptr, vm.base), 24);
        assert_eq!(fd_table::get_offset(vm.base, &vm.vm, dir_fd as u64), 1);
        assert_ne!(
            vm.vm.completed_sync_effects & SYNC_EFFECT_FORK_SHARED_OFD_STATE,
            0,
        );
    }

    #[test]
    fn dispatch_pread64_falls_back_to_fs_ring_on_external_file_miss() {
        let mut vm = TestVm::new();
        let ino = memfs::create_file(1, b"external-pread.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(memfs::set_file_external(ino, 6), 0);
        assert_eq!(memfs::stat(ino).map(|st| st.size), Some(6));
        let fd = vm.sys_openat(b"/external-pread.txt", O_RDONLY);
        assert!(fd >= 3);
        let buf_addr = vm.scratch + 0x5200;

        let result = dispatch_pread64(&mut vm.vm, vm.base, fd as u64, buf_addr, 3, 2);

        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);
        assert_eq!(vm.sys_lseek(fd, 0, 1), 0);
    }

    #[test]
    fn dispatch_mmap_uses_local_resident_file_hit() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"resident-map.txt", b"map-data");
        let fd = vm.sys_openat(b"/resident-map.txt", O_RDONLY);
        assert!(fd >= 3);

        let result = dispatch_mmap(
            &mut vm.vm,
            vm.base,
            0,
            4096,
            PROT_READ as u64,
            MAP_PRIVATE,
            fd,
            0,
        );

        assert!(result > 0);
        assert_eq!(vm.vm.status, STATUS_OK);
        assert_eq!(vm.guest_mem(result as u64, 8), b"map-data".to_vec());
    }

    #[test]
    fn dispatch_mmap_falls_back_to_fs_ring_on_external_file_miss() {
        let mut vm = TestVm::new();
        let ino = memfs::create_file(1, b"external-map.txt", 0o644);
        assert!(ino > 0);
        assert_eq!(memfs::set_file_external(ino, 8192), 0);
        let fd = vm.sys_openat(b"/external-map.txt", O_RDONLY);
        assert!(fd >= 3);

        let result = dispatch_mmap(
            &mut vm.vm,
            vm.base,
            0,
            4096,
            PROT_READ as u64,
            MAP_PRIVATE,
            fd,
            0,
        );

        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);
    }

    #[test]
    fn dispatch_openat_keeps_creating_opens_on_fs_ring() {
        let mut vm = TestVm::new();
        let path_addr = vm.write_path(0x400, b"/created.txt");

        let result = dispatch_openat(
            &mut vm.vm,
            vm.base,
            (-100i64) as u64,
            path_addr,
            (O_RDONLY | O_CREAT) as u64,
            0o644,
        );

        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);
    }

    #[test]
    fn resume_from_fs_openat_result_is_usable_fd() {
        let mut vm = TestVm::new();
        let path_addr = vm.write_path(0x400, b"/created.txt");

        let result = dispatch_openat(
            &mut vm.vm,
            vm.base,
            (-100i64) as u64,
            path_addr,
            (O_RDONLY | O_CREAT) as u64,
            0o644,
        );

        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);

        process_pending_requests(&mut vm.vm as *mut _ as u32, vm.base);
        let fd = resume_from_fs(&mut vm.vm as *mut _ as u32, vm.base);

        assert!(fd >= 3);
        assert_eq!(vm.vm.status, STATUS_OK);
        assert_eq!(fd_table::sys_fcntl(&mut vm.vm, vm.base, fd as u64, 2, 1), 0,);
    }

    #[test]
    fn process_pending_requests_openat_installs_fd_for_cloned_thread_process_table() {
        let mut vm = TestVm::new();
        let parent_vm_ptr = &mut vm.vm as *mut _ as u32;
        let clone_result = crate::syscall::thread::sys_clone(
            &mut vm.vm,
            vm.base,
            CLONE_VM | CLONE_THREAD,
            vm.scratch + 0x7000,
            0,
            0,
            0,
        );
        assert!(clone_result > 0);

        let child_vm_ptr = crate::supervisor::spawn_from_clone(parent_vm_ptr, vm.base);
        assert_ne!(child_vm_ptr, 0);
        let child = unsafe { &mut *(child_vm_ptr as *mut ThreadState) };
        assert_eq!(child.process_ptr, vm.vm.process_ptr);

        let path_addr = vm.write_path(0x500, b"/child-created.txt");
        let result = dispatch_openat(
            child,
            vm.base,
            (-100i64) as u64,
            path_addr,
            (O_RDONLY | O_CREAT) as u64,
            0o644,
        );
        assert_eq!(result, 0);
        assert_eq!(child.status, STATUS_FS);

        process_pending_requests(child_vm_ptr, vm.base);
        let fd = resume_from_fs(child_vm_ptr, vm.base);

        assert!(fd >= 3);
        assert_eq!(child.status, STATUS_OK);
        assert_eq!(fd_table::sys_fcntl(child, vm.base, fd as u64, 2, 1), 0,);
        assert_ne!(
            fd_table::load_process_fd_entry(vm.base, vm.vm.process_ptr, fd as usize).ofd_id,
            0,
        );
    }

    #[test]
    fn submit_fs_request_drops_stale_completion_before_queueing_next_request() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let mut vm = TestVm::new();
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        assert_ne!(ring_base, 0);

        let cq_off = ring_base + ring_buffer::OFF_CQ_BASE;
        vm.vm.pending_fs_request_id = 1;
        unsafe {
            *((cq_off as *mut u8) as *mut i64) = ENOENT;
            *((cq_off as *mut u8).add(8) as *mut u32) = vm_ptr;
            *((cq_off as *mut u8).add(12) as *mut u32) = 1;
            let cq_head = (ring_base + ring_buffer::OFF_COMPLETE_HEAD) as *const AtomicU32;
            (*cq_head).store(1, Ordering::Release);
        }

        let path_addr = vm.write_path(0x400, b"/created-after-stale.txt");
        let result = dispatch_openat(
            &mut vm.vm,
            vm.base,
            (-100i64) as u64,
            path_addr,
            (O_RDONLY | O_CREAT) as u64,
            0o644,
        );

        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);

        process_pending_requests(vm_ptr, vm.base);
        let fd = resume_from_fs(vm_ptr, vm.base);

        assert!(fd >= 3);
        assert_eq!(vm.vm.status, STATUS_OK);
    }

    #[test]
    fn resume_from_fs_with_pending_request_without_completion_keeps_thread_blocked() {
        let mut vm = TestVm::new();
        let path_addr = vm.write_path(0x400, b"/created.txt");
        let result = dispatch_openat(
            &mut vm.vm,
            vm.base,
            (-100i64) as u64,
            path_addr,
            (O_RDONLY | O_CREAT) as u64,
            0o644,
        );

        assert_eq!(result, 0);
        vm.vm.x[10] = 0xfeed;
        vm.vm.status = STATUS_FS;

        let result = resume_from_fs(&mut vm.vm as *mut _ as u32, vm.base);

        assert_eq!(result, EAGAIN);
        assert_eq!(vm.vm.status, STATUS_FS);
        assert_eq!(vm.vm.x[10], 0xfeed);
    }

    #[test]
    fn resume_from_fs_without_request_or_completion_clears_stale_status() {
        let mut vm = TestVm::new();
        vm.vm.x[10] = 0xfeed;
        vm.vm.status = STATUS_FS;

        let result = resume_from_fs(&mut vm.vm as *mut _ as u32, vm.base);

        assert_eq!(result, 0xfeed);
        assert_eq!(vm.vm.status, STATUS_OK);
        assert_eq!(vm.vm.x[10], 0xfeed);
    }

    #[test]
    fn resume_from_fs_result_applies_external_completion_to_local_thread() {
        let mut vm = TestVm::new();
        vm.vm.x[10] = 4095;
        vm.vm.pending_fs_request_id = 77;
        vm.vm.status = STATUS_FS;

        let result = resume_from_fs_result(&mut vm.vm as *mut _ as u32, 2945);

        assert_eq!(result, 2945);
        assert_eq!(vm.vm.x[10], 2945);
        assert_eq!(vm.vm.pending_fs_request_id, 0);
        assert_eq!(vm.vm.status, STATUS_OK);
    }

    #[test]
    fn resume_from_fs_preserves_eagain_completion_as_syscall_result() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let mut vm = TestVm::new();
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        vm.vm.status = STATUS_FS;

        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        assert_ne!(ring_base, 0);
        let cq_off = ring_base
            + ring_buffer::HEADER_SIZE as u32
            + (ring_buffer::SQ_SIZE * ring_buffer::REQ_SIZE) as u32;
        vm.vm.pending_fs_request_id = 1;
        unsafe {
            *((cq_off as *mut u8) as *mut i64) = EAGAIN;
            *((cq_off as *mut u8).add(8) as *mut u32) = vm_ptr;
            *((cq_off as *mut u8).add(12) as *mut u32) = 1;
            let cq_head = (ring_base + 8) as *const AtomicU32;
            (*cq_head).store(1, Ordering::Release);
        }

        let result = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(result, EAGAIN);
        assert_eq!(vm.vm.status, STATUS_OK);
        assert_eq!(vm.vm.x[10] as i64, EAGAIN);
    }

    #[test]
    fn resume_from_fs_consumes_only_the_expected_request_completion() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let mut vm = TestVm::new();
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        vm.vm.status = STATUS_FS;

        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        assert_ne!(ring_base, 0);
        let cq_off = ring_base + ring_buffer::OFF_CQ_BASE;
        vm.vm.pending_fs_request_id = 2;
        unsafe {
            *((cq_off as *mut u8) as *mut i64) = 7;
            *((cq_off as *mut u8).add(8) as *mut u32) = vm_ptr;
            *((cq_off as *mut u8).add(12) as *mut u32) = 1;
            *((cq_off as *mut u8).add(ring_buffer::RESP_SIZE) as *mut i64) = 0;
            *((cq_off as *mut u8).add(ring_buffer::RESP_SIZE + 8) as *mut u32) = vm_ptr;
            *((cq_off as *mut u8).add(ring_buffer::RESP_SIZE + 12) as *mut u32) = 2;
            let cq_head = (ring_base + ring_buffer::OFF_COMPLETE_HEAD) as *const AtomicU32;
            (*cq_head).store(2, Ordering::Release);
        }

        let result = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(result, 0);
        assert_eq!(vm.vm.x[10], 0);
        unsafe {
            let cq_head = (ring_base + ring_buffer::OFF_COMPLETE_HEAD) as *const AtomicU32;
            let cq_tail = (ring_base + ring_buffer::OFF_COMPLETE_TAIL) as *const AtomicU32;
            assert_eq!((*cq_head).load(Ordering::Acquire), 1);
            assert_eq!((*cq_tail).load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn resume_from_fs_does_not_consume_same_vm_completion_from_another_request() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let mut vm = TestVm::new();
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        vm.vm.status = STATUS_FS;

        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        assert_ne!(ring_base, 0);
        let cq_off = ring_base + ring_buffer::OFF_CQ_BASE;
        vm.vm.pending_fs_request_id = 2;
        unsafe {
            *((cq_off as *mut u8) as *mut i64) = 199;
            *((cq_off as *mut u8).add(8) as *mut u32) = vm_ptr;
            *((cq_off as *mut u8).add(12) as *mut u32) = 1;
            *((cq_off as *mut u8).add(ring_buffer::RESP_SIZE) as *mut i64) = 192;
            *((cq_off as *mut u8).add(ring_buffer::RESP_SIZE + 8) as *mut u32) = vm_ptr;
            *((cq_off as *mut u8).add(ring_buffer::RESP_SIZE + 12) as *mut u32) = 2;
            let cq_head = (ring_base + ring_buffer::OFF_COMPLETE_HEAD) as *const AtomicU32;
            (*cq_head).store(2, Ordering::Release);
        }

        assert_eq!(resume_from_fs(vm_ptr, vm.base), 192);
        assert_eq!(vm.vm.x[10], 192);
        unsafe {
            let cq_head = (ring_base + ring_buffer::OFF_COMPLETE_HEAD) as *const AtomicU32;
            let cq_tail = (ring_base + ring_buffer::OFF_COMPLETE_TAIL) as *const AtomicU32;
            assert_eq!((*cq_head).load(Ordering::Acquire), 1);
            assert_eq!((*cq_tail).load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn dispatch_write_routes_regular_files_to_fs_ring() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"write.txt", b"seed");
        let fd = vm.sys_openat(b"/write.txt", O_WRONLY);
        assert!(fd >= 3);

        let data_addr = vm.scratch + 0x800;
        vm.write_mem(data_addr, b"hello");
        let written = dispatch_write(&mut vm.vm, vm.base, fd as u64, data_addr, 5, SYS_WRITE);

        assert_eq!(written, 0);
        assert_eq!(vm.vm.status, STATUS_FS);

        let vm_ptr = &mut vm.vm as *mut _ as u32;
        process_pending_requests(vm_ptr, vm.base);
        let written = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(written, 5);
        assert_eq!(vm.vm.status, STATUS_OK);

        let read_fd = vm.sys_openat(b"/write.txt", O_RDONLY);
        assert!(read_fd >= 3);
        let mut buf = [0u8; 5];
        assert_eq!(vm.sys_read(read_fd, &mut buf), 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn dispatch_zero_length_write_to_regular_file_returns_without_fs_request() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"write-empty.txt", b"seed");
        let fd = vm.sys_openat(b"/write-empty.txt", O_WRONLY);
        assert!(fd >= 3);

        let written = dispatch_write(&mut vm.vm, vm.base, fd as u64, 0, 0, SYS_WRITE);

        assert_eq!(written, 0);
        assert_eq!(vm.vm.status, STATUS_OK);
        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        assert!(ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr).is_none());
    }

    #[test]
    fn dispatch_write_preserves_current_offset_in_fs_ring_request() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"write-offset.txt", b"seed-data");
        let fd = vm.sys_openat(b"/write-offset.txt", O_WRONLY);
        assert!(fd >= 3);
        assert_eq!(vm.sys_lseek(fd, 4, 0), 4);

        let data_addr = vm.scratch + 0x850;
        vm.write_mem(data_addr, b"XY");
        let written = dispatch_write(&mut vm.vm, vm.base, fd as u64, data_addr, 2, SYS_WRITE);

        assert_eq!(written, 0);
        assert_eq!(vm.vm.status, STATUS_FS);
        assert_eq!(fd_table::get_offset(vm.base, &vm.vm, fd as u64), 4);
        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let request = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr)
            .expect("write should submit a host FS request");
        assert_eq!(request.opcode, ring_buffer::FS_OP_WRITE);
        assert_eq!(request.fd, fd as i32);
        assert_eq!(request.offset, 4);
        assert_eq!(request.len, 2);
        assert_eq!(request.buf_ptr, data_addr);
    }

    #[test]
    fn dispatch_write_preserves_submit_inode_after_fd_reuse() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"write-original.txt", b"seed-data");
        vm.memfs.create_file(b"write-reused.txt", b"other-data");
        let original_ino = memfs::resolve_path(b"/write-original.txt");
        let reused_ino = memfs::resolve_path(b"/write-reused.txt");
        assert_ne!(original_ino, 0);
        assert_ne!(reused_ino, 0);
        assert_ne!(original_ino, reused_ino);

        let fd = vm.sys_openat(b"/write-original.txt", O_WRONLY);
        assert!(fd >= 3);
        let original_ofd = fd_table::get_ofd_id(vm.base, &vm.vm, fd as u64).unwrap_or(0);
        assert_ne!(original_ofd, 0);

        let data_addr = vm.scratch + 0x860;
        vm.write_mem(data_addr, b"XY");
        let written = dispatch_write(&mut vm.vm, vm.base, fd as u64, data_addr, 2, SYS_WRITE);
        assert_eq!(written, 0);
        assert_eq!(vm.vm.status, STATUS_FS);

        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let request = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr)
            .expect("write should submit a host FS request");
        assert_eq!(request.opcode, ring_buffer::FS_OP_WRITE);
        assert_eq!(request.fd, fd as i32);
        assert_eq!(request.ofd_id, original_ofd);
        assert_eq!(request.ino, original_ino);

        assert_eq!(fd_table::sys_close(&mut vm.vm, vm.base, fd as u64), 0);
        let reused_fd = vm.sys_openat(b"/write-reused.txt", O_WRONLY);
        assert_eq!(reused_fd, fd);
        assert_eq!(
            fd_table::get_ofd(vm.base, &vm.vm, fd as u64).map(|ofd| ofd.ino),
            Some(reused_ino),
        );

        assert_eq!(pending_request_target_ino(vm_ptr, vm.base), original_ino);

        process_pending_requests(vm_ptr, vm.base);
        let written = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(written, 2);
        assert_eq!(vm.vm.status, STATUS_OK);

        let read_original = vm.sys_openat(b"/write-original.txt", O_RDONLY);
        assert!(read_original >= 3);
        let mut original_buf = [0u8; 9];
        assert_eq!(vm.sys_read(read_original, &mut original_buf), 9);
        assert_eq!(&original_buf, b"XYed-data");

        let read_reused = vm.sys_openat(b"/write-reused.txt", O_RDONLY);
        assert!(read_reused >= 3);
        let mut reused_buf = [0u8; 10];
        assert_eq!(vm.sys_read(read_reused, &mut reused_buf), 10);
        assert_eq!(&reused_buf, b"other-data");
    }

    #[test]
    fn dispatch_ftruncate_preserves_submit_inode_after_fd_reuse() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"truncate-original.txt", b"seed-data");
        vm.memfs.create_file(b"truncate-reused.txt", b"other-data");
        let original_ino = memfs::resolve_path(b"/truncate-original.txt");
        let reused_ino = memfs::resolve_path(b"/truncate-reused.txt");
        assert_ne!(original_ino, 0);
        assert_ne!(reused_ino, 0);
        assert_ne!(original_ino, reused_ino);

        let fd = vm.sys_openat(b"/truncate-original.txt", O_WRONLY);
        assert!(fd >= 3);
        let original_ofd = fd_table::get_ofd_id(vm.base, &vm.vm, fd as u64).unwrap_or(0);
        assert_ne!(original_ofd, 0);

        let result = dispatch_ftruncate(&mut vm.vm, vm.base, fd as u64, 4);
        assert_eq!(result, 0);
        assert_eq!(vm.vm.status, STATUS_FS);

        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let request = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr)
            .expect("ftruncate should submit a host FS request");
        assert_eq!(request.opcode, ring_buffer::FS_OP_TRUNCATE);
        assert_eq!(request.fd, fd as i32);
        assert_eq!(request.offset, 4);
        assert_eq!(request.ofd_id, original_ofd);
        assert_eq!(request.ino, original_ino);

        assert_eq!(fd_table::sys_close(&mut vm.vm, vm.base, fd as u64), 0);
        let reused_fd = vm.sys_openat(b"/truncate-reused.txt", O_WRONLY);
        assert_eq!(reused_fd, fd);
        assert_eq!(
            fd_table::get_ofd(vm.base, &vm.vm, fd as u64).map(|ofd| ofd.ino),
            Some(reused_ino),
        );

        assert_eq!(pending_request_target_ino(vm_ptr, vm.base), original_ino);

        process_pending_requests(vm_ptr, vm.base);
        assert_eq!(resume_from_fs(vm_ptr, vm.base), 0);
        assert_eq!(vm.vm.status, STATUS_OK);
        assert_eq!(memfs::stat(original_ino).map(|stat| stat.size), Some(4));
        assert_eq!(memfs::stat(reused_ino).map(|stat| stat.size), Some(10));

        let read_original = vm.sys_openat(b"/truncate-original.txt", O_RDONLY);
        assert!(read_original >= 3);
        let mut original_buf = [0u8; 4];
        assert_eq!(vm.sys_read(read_original, &mut original_buf), 4);
        assert_eq!(&original_buf, b"seed");

        let read_reused = vm.sys_openat(b"/truncate-reused.txt", O_RDONLY);
        assert!(read_reused >= 3);
        let mut reused_buf = [0u8; 10];
        assert_eq!(vm.sys_read(read_reused, &mut reused_buf), 10);
        assert_eq!(&reused_buf, b"other-data");
    }

    #[test]
    fn dispatch_write_uses_append_offset_in_fs_ring_request() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"write-append-offset.txt", b"seed");
        let fd = vm.sys_openat(b"/write-append-offset.txt", O_WRONLY | O_APPEND);
        assert!(fd >= 3);
        assert_eq!(vm.sys_lseek(fd, 1, 0), 1);

        let data_addr = vm.scratch + 0x870;
        vm.write_mem(data_addr, b"++");
        let written = dispatch_write(&mut vm.vm, vm.base, fd as u64, data_addr, 2, SYS_WRITE);

        assert_eq!(written, 0);
        assert_eq!(vm.vm.status, STATUS_FS);
        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let request = ring_buffer::peek_request_info_for_vm(ring_base, vm_ptr)
            .expect("append write should submit a host FS request");
        assert_eq!(request.opcode, ring_buffer::FS_OP_WRITE);
        assert_eq!(request.fd, fd as i32);
        assert_eq!(request.offset, 4);
        assert_eq!(request.len, 2);
        assert_eq!(request.buf_ptr, data_addr);
    }

    #[test]
    fn dispatch_write_routes_regular_stdout_to_fs_ring() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"stdout.txt", b"seed");
        let fd = vm.sys_openat(b"/stdout.txt", O_WRONLY | O_TRUNC);
        assert!(fd >= 3);
        assert_eq!(vm.sys_dup3(fd as u64, 1, 0), 1);

        let data_addr = vm.scratch + 0x880;
        vm.write_mem(data_addr, b"hello");
        let written = dispatch_write(&mut vm.vm, vm.base, 1, data_addr, 5, SYS_WRITE);

        assert_eq!(written, 0);
        assert_eq!(vm.vm.status, STATUS_FS);

        let vm_ptr = &mut vm.vm as *mut _ as u32;
        process_pending_requests(vm_ptr, vm.base);
        let written = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(written, 5);
        assert_eq!(vm.vm.status, STATUS_OK);

        let read_fd = vm.sys_openat(b"/stdout.txt", O_RDONLY);
        assert!(read_fd >= 3);
        let mut buf = [0u8; 5];
        assert_eq!(vm.sys_read(read_fd, &mut buf), 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn dispatch_writev_routes_regular_files_to_fs_ring() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"writev.txt", b"seed");
        let fd = vm.sys_openat(b"/writev.txt", O_WRONLY);
        assert!(fd >= 3);

        let part_a = vm.scratch + 0x900;
        let part_b = vm.scratch + 0x940;
        let iov_addr = vm.scratch + 0x980;
        vm.write_mem(part_a, b"he");
        vm.write_mem(part_b, b"llo");
        unsafe {
            crate::guest_mem::write_u64(vm.base, iov_addr, part_a);
            crate::guest_mem::write_u64(vm.base, iov_addr + 8, 2);
            crate::guest_mem::write_u64(vm.base, iov_addr + 16, part_b);
            crate::guest_mem::write_u64(vm.base, iov_addr + 24, 3);
        }

        let written = dispatch_write(&mut vm.vm, vm.base, fd as u64, iov_addr, 2, SYS_WRITEV);

        assert_eq!(written, 0);
        assert_eq!(vm.vm.status, STATUS_FS);

        let vm_ptr = &mut vm.vm as *mut _ as u32;
        process_pending_requests(vm_ptr, vm.base);
        let written = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(written, 5);
        assert_eq!(vm.vm.status, STATUS_OK);

        let read_fd = vm.sys_openat(b"/writev.txt", O_RDONLY);
        assert!(read_fd >= 3);
        let mut buf = [0u8; 5];
        assert_eq!(vm.sys_read(read_fd, &mut buf), 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn regular_file_write_honors_o_append_after_fs_round_trip() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"append.txt", b"seed");
        let fd = vm.sys_openat(b"/append.txt", O_WRONLY | O_APPEND);
        assert!(fd >= 3);
        assert_eq!(vm.sys_lseek(fd, 1, 0), 1);

        let data_addr = vm.scratch + 0xa00;
        vm.write_mem(data_addr, b"++");
        let written = dispatch_write(&mut vm.vm, vm.base, fd as u64, data_addr, 2, SYS_WRITE);

        assert_eq!(written, 0);
        assert_eq!(vm.vm.status, STATUS_FS);

        let vm_ptr = &mut vm.vm as *mut _ as u32;
        process_pending_requests(vm_ptr, vm.base);
        let written = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(written, 2);
        assert_eq!(vm.sys_lseek(fd, 0, 1), 6);

        let read_fd = vm.sys_openat(b"/append.txt", O_RDONLY);
        assert!(read_fd >= 3);
        let mut buf = [0u8; 6];
        assert_eq!(vm.sys_read(read_fd, &mut buf), 6);
        assert_eq!(&buf, b"seed++");
    }

    #[test]
    fn regular_file_writev_rejects_invalid_iov_len_after_fs_round_trip() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"bad-iov.txt", b"seed");
        let fd = vm.sys_openat(b"/bad-iov.txt", O_WRONLY);
        assert!(fd >= 3);

        let data_addr = vm.scratch + 0xb00;
        let iov_addr = vm.scratch + 0xb80;
        vm.write_mem(data_addr, b"bad");
        unsafe {
            crate::guest_mem::write_u64(vm.base, iov_addr, data_addr);
            crate::guest_mem::write_u64(vm.base, iov_addr + 8, u64::MAX);
        }

        let written = dispatch_write(&mut vm.vm, vm.base, fd as u64, iov_addr, 1, SYS_WRITEV);

        assert_eq!(written, 0);
        assert_eq!(vm.vm.status, STATUS_FS);

        let vm_ptr = &mut vm.vm as *mut _ as u32;
        process_pending_requests(vm_ptr, vm.base);
        let written = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(written, EINVAL);
        let read_fd = vm.sys_openat(b"/bad-iov.txt", O_RDONLY);
        assert!(read_fd >= 3);
        let mut buf = [0u8; 4];
        assert_eq!(vm.sys_read(read_fd, &mut buf), 4);
        assert_eq!(&buf, b"seed");
    }

    #[test]
    fn dispatch_write_runs_sockets_locally() {
        let mut vm = TestVm::new();
        let sv_addr = vm.scratch + 0x700;
        assert_eq!(
            sys_socketpair(
                &mut vm.vm,
                vm.base,
                AF_UNIX as u64,
                SOCK_STREAM as u64,
                0,
                sv_addr,
            ),
            0,
        );
        let left = unsafe { crate::guest_mem::read_u32(vm.base, sv_addr) };
        let right = unsafe { crate::guest_mem::read_u32(vm.base, sv_addr + 4) };
        let data_addr = vm.scratch + 0x800;
        vm.write_mem(data_addr, b"hello");

        let written = dispatch_write(&mut vm.vm, vm.base, left as u64, data_addr, 5, SYS_WRITE);

        assert_eq!(written, 5);
        assert_eq!(vm.vm.status, STATUS_OK);
        let mut buf = [0u8; 5];
        assert_eq!(vm.sys_read(right as i64, &mut buf), 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn dispatch_lseek_runs_locally() {
        let mut vm = TestVm::new();
        vm.memfs.create_file(b"seek.txt", b"abcdef");
        let fd = vm.sys_openat(b"/seek.txt", O_RDONLY);
        assert!(fd >= 3);

        let seeked = dispatch_lseek(&mut vm.vm, vm.base, fd as u64, 2, 0);

        assert_eq!(seeked, 2);
        assert_eq!(vm.vm.status, STATUS_OK);

        let mut buf = [0u8; 4];
        assert_eq!(vm.sys_read(fd, &mut buf), 4);
        assert_eq!(&buf, b"cdef");
    }
}

pub fn dispatch_pwrite64(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    buf: u64,
    count: u64,
    offset: u64,
) -> i64 {
    if (offset as i64) < 0 {
        return EINVAL;
    }
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if ofd.fd_type == FD_TYPE_FILE && ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK == O_RDONLY
    {
        return EBADF;
    }
    if ofd.fd_type == FD_TYPE_PIPE {
        return ESPIPE;
    }
    let request_offset = if ofd.fd_type == FD_TYPE_FILE && ofd.status_flags & O_APPEND != 0 {
        memfs::stat(ofd.ino).map(|stat| stat.size).unwrap_or(0)
    } else {
        offset
    };

    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_WRITE,
        fd as i32,
        request_offset,
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
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if ofd.fd_type == FD_TYPE_FILE {
        if ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK == O_RDONLY {
            return EBADF;
        }
        if count == 0 {
            return 0;
        }
        let ofd_id = fd_table::get_ofd_id(base, vm, fd).unwrap_or(0);
        let offset = regular_file_write_offset(&ofd, ofd_id);
        let flags = if nr == SYS_WRITEV {
            ring_buffer::FS_REQ_FLAG_WRITEV
        } else {
            0
        };
        return submit_fs_request(
            vm,
            base,
            ring_buffer::FS_OP_WRITE,
            fd as i32,
            offset,
            count,
            buf,
            0,
            flags,
            0,
        );
    }
    if fd == 1 || fd == 2 {
        return sys_write(vm, base, fd, buf, count, nr);
    }
    if ofd.fd_type == FD_TYPE_PIPE
        || ofd.fd_type == FD_TYPE_SOCKET
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
                | FD_TYPE_FILE
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
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(ofd) => ofd,
        None => return EBADF,
    };
    if !matches!(memfs::stat(ofd.ino), Some(st) if st.mode & memfs::S_IFMT == memfs::S_IFDIR) {
        return ENOTDIR;
    }
    let ofd_id = fd_table::get_ofd_id(base, vm, fd).unwrap_or(0);
    let offset = fd_table::get_offset_by_id(ofd_id).max(fd_table::get_offset_floor_by_id(ofd_id));
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_GETDENTS,
        fd as i32,
        offset,
        buf_size,
        buf,
        0,
        0,
        0,
    )
}

pub fn dispatch_lseek(vm: &mut ThreadState, base: u32, fd: u64, offset: i64, whence: u64) -> i64 {
    crate::syscall::fs::sys_lseek(vm, base, fd, offset, whence)
}

fn regular_file_read_needs_fs_request(ino: u32, offset: u64, count: u64, local: i64) -> bool {
    if local == ENOENT {
        return true;
    }
    if count == 0 || local < 0 {
        return false;
    }
    memfs::stat(ino).is_some_and(|st| {
        st.mode & memfs::S_IFMT == memfs::S_IFREG
            && offset.saturating_add(local as u64) < st.size
            && (local as u64) < count
    })
}

fn record_page_cache_miss(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    ino: u32,
    offset: u64,
    count: u64,
    flags: u64,
    local: i64,
) {
    let size = memfs::stat(ino).map_or(0, |stat| stat.size);
    crate::supervisor::record_fs_control(
        crate::supervisor::SUPERVISOR_FS_CONTROL_KIND_PAGE_CACHE_MISS,
        vm as *mut ThreadState as u32,
        vm.process_ptr,
        crate::syscall::process::current_process_pid(vm, base),
        fd as u32,
        ino,
        ring_buffer::FS_OP_READ,
        0,
        offset / PAGE_SIZE,
        offset,
        count,
        local,
        flags,
        size,
        0,
    );
}

pub fn dispatch_read(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, count: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if ofd.fd_type != FD_TYPE_FILE {
        return crate::syscall::fs::sys_read(vm, base, fd, buf, count);
    }
    let offset = fd_table::get_offset(base, vm, fd);
    let local = crate::syscall::fs::sys_pread64(vm, base, fd, buf, count, offset);
    if !regular_file_read_needs_fs_request(ofd.ino, offset, count, local) {
        if local > 0 {
            fd_table::advance_offset(base, vm, fd, local as u64);
            mark_fork_shared_ofd_sync_effect(vm);
        }
        return local;
    }
    record_page_cache_miss(vm, base, fd, ofd.ino, offset, count, 0, local);
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_READ,
        fd as i32,
        offset,
        count,
        buf,
        0,
        0,
        0,
    )
}

pub fn dispatch_pread64(
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
    if ofd.fd_type != FD_TYPE_FILE {
        return crate::syscall::fs::sys_pread64(vm, base, fd, buf, count, offset);
    }
    let local = crate::syscall::fs::sys_pread64(vm, base, fd, buf, count, offset);
    if !regular_file_read_needs_fs_request(ofd.ino, offset, count, local) {
        return local;
    }
    record_page_cache_miss(
        vm,
        base,
        fd,
        ofd.ino,
        offset,
        count,
        ring_buffer::FS_REQ_FLAG_PWRITE as u64,
        local,
    );
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_READ,
        fd as i32,
        offset,
        count,
        buf,
        0,
        ring_buffer::FS_REQ_FLAG_PWRITE,
        0,
    )
}

pub fn dispatch_mmap(
    vm: &mut ThreadState,
    base: u32,
    addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    fd: i64,
    offset: u64,
) -> i64 {
    if flags & MAP_ANONYMOUS != 0 {
        return crate::syscall::memory::sys_mmap(vm, base, addr, length, prot, flags, fd, offset);
    }
    let ofd = match fd_table::get_ofd(base, vm, fd as u64) {
        Some(o) => o,
        None => return EBADF,
    };
    if ofd.fd_type != FD_TYPE_FILE {
        return crate::syscall::memory::sys_mmap(vm, base, addr, length, prot, flags, fd, offset);
    }
    let local = crate::syscall::memory::sys_mmap(vm, base, addr, length, prot, flags, fd, offset);
    if local != ENOENT && local != EIO {
        return local;
    }
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_MMAP,
        fd as i32,
        offset,
        length,
        addr,
        0,
        flags as u32,
        prot as u32,
    )
}

pub fn dispatch_execve(
    vm: &mut ThreadState,
    base: u32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
) -> i64 {
    submit_fs_request(
        vm,
        base,
        ring_buffer::FS_OP_EXECVE,
        AT_FDCWD,
        envp_addr,
        0,
        argv_addr,
        path_addr,
        0,
        0,
    )
}

pub fn dispatch_fsync(vm: &mut ThreadState, base: u32, fd: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    match ofd.fd_type {
        FD_TYPE_FILE => submit_fs_request(
            vm,
            base,
            ring_buffer::FS_OP_FSYNC,
            fd as i32,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        FD_TYPE_DIR => 0,
        _ => EINVAL,
    }
}

pub fn dispatch_ftruncate(vm: &mut ThreadState, base: u32, fd: u64, length: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if (length as i64) < 0 || ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK == O_RDONLY {
        return EINVAL;
    }
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
