use super::path::{
    dirfd_base_ino, resolve_at, resolve_path_with_symlink_policy, split_relative_parent_name,
    trim_trailing_slashes,
};
use super::state::process_fs_ring_base;
use super::{AT_FDCWD, MAX_PATH_SYMLINK_FOLLOWS, PENDING_FS_PATH_MAX, sys_fstat, sys_write};
use crate::abi::*;
use crate::fs::{fd_table, memfs, ring_buffer};
use crate::guest_mem;
use crate::types::ThreadState;

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

    let idx = ring_buffer::submit_request(
        ring_base, opcode, fd, offset, len, buf_ptr, path_ptr, flags, mode, vm_ptr,
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
        ring_buffer::FS_OP_TRUNCATE => FS_EFFECT_MEMFS_FILE_DATA,
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
            vm.status = STATUS_OK;
            return ENOMEM;
        }

        let Some(result) = ring_buffer::read_completion_for_vm(ring_base, vm_ptr) else {
            if !ring_buffer::has_pending_request_for_vm(ring_base, vm_ptr) {
                vm.status = STATUS_OK;
                return vm.x[10] as i64;
            }
            vm.status = STATUS_FS;
            return EAGAIN;
        };
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
        dispatch_lseek, dispatch_openat, dispatch_write, process_fs_ring_base,
        process_pending_requests, resume_from_fs,
    };
    use crate::abi::{
        AF_UNIX, EAGAIN, ENOENT, O_CREAT, O_RDONLY, O_WRONLY, SOCK_STREAM, STATUS_FS, STATUS_OK,
        SYS_WRITE, SYS_WRITEV,
    };
    use crate::fs::ring_buffer;
    use crate::harness::TestVm;
    use crate::syscall::fd_table;
    use crate::syscall::socket::sys_socketpair;

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
    fn submit_fs_request_drops_stale_completion_before_queueing_next_request() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let mut vm = TestVm::new();
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        assert_ne!(ring_base, 0);

        let cq_off = ring_base + ring_buffer::OFF_CQ_BASE;
        unsafe {
            *((cq_off as *mut u8) as *mut i64) = ENOENT;
            *((cq_off as *mut u8).add(8) as *mut u32) = vm_ptr;
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
        unsafe {
            *((cq_off as *mut u8) as *mut i64) = EAGAIN;
            *((cq_off as *mut u8).add(8) as *mut u32) = vm_ptr;
            let cq_head = (ring_base + 8) as *const AtomicU32;
            (*cq_head).store(1, Ordering::Release);
        }

        let result = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(result, EAGAIN);
        assert_eq!(vm.vm.status, STATUS_OK);
        assert_eq!(vm.vm.x[10] as i64, EAGAIN);
    }

    #[test]
    fn resume_from_fs_preserves_extra_completions_for_same_vm() {
        use core::sync::atomic::{AtomicU32, Ordering};

        let mut vm = TestVm::new();
        let vm_ptr = &mut vm.vm as *mut _ as u32;
        vm.vm.status = STATUS_FS;

        let ring_base = process_fs_ring_base(vm.base, &vm.vm);
        assert_ne!(ring_base, 0);
        let cq_off = ring_base + ring_buffer::OFF_CQ_BASE;
        unsafe {
            *((cq_off as *mut u8) as *mut i64) = 7;
            *((cq_off as *mut u8).add(8) as *mut u32) = vm_ptr;
            *((cq_off as *mut u8).add(ring_buffer::RESP_SIZE) as *mut i64) = 0;
            *((cq_off as *mut u8).add(ring_buffer::RESP_SIZE + 8) as *mut u32) = vm_ptr;
            let cq_head = (ring_base + ring_buffer::OFF_COMPLETE_HEAD) as *const AtomicU32;
            (*cq_head).store(2, Ordering::Release);
        }

        let result = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(result, 7);
        assert_eq!(vm.vm.x[10], 7);
        unsafe {
            let cq_head = (ring_base + ring_buffer::OFF_COMPLETE_HEAD) as *const AtomicU32;
            let cq_tail = (ring_base + ring_buffer::OFF_COMPLETE_TAIL) as *const AtomicU32;
            assert_eq!((*cq_head).load(Ordering::Acquire), 1);
            assert_eq!((*cq_tail).load(Ordering::Acquire), 0);
        }

        vm.vm.status = STATUS_FS;
        let second = resume_from_fs(vm_ptr, vm.base);

        assert_eq!(second, 0);
        assert_eq!(vm.vm.x[10], 0);
        unsafe {
            let cq_head = (ring_base + ring_buffer::OFF_COMPLETE_HEAD) as *const AtomicU32;
            let cq_tail = (ring_base + ring_buffer::OFF_COMPLETE_TAIL) as *const AtomicU32;
            assert_eq!((*cq_head).load(Ordering::Acquire), 0);
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
    if fd == 1 || fd == 2 {
        return sys_write(vm, base, fd, buf, count, nr);
    }

    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if ofd.fd_type == FD_TYPE_FILE {
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
            0,
            count,
            buf,
            0,
            flags,
            0,
        );
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
    crate::syscall::fs::sys_lseek(vm, base, fd, offset, whence)
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
