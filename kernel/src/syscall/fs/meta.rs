use super::path::{resolve_at, trim_trailing_slashes};
use super::state::current_dir_ino;
use super::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, S_IFIFO, S_IFSOCK, TMPFS_MAGIC};
use crate::abi::*;
use crate::fs::{fd_table, memfs};
use crate::guest_mem;
use crate::types::ThreadState;

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
        FD_TYPE_EVENTFD | FD_TYPE_EPOLL | FD_TYPE_TIMERFD | FD_TYPE_SIGNALFD => {
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
    crate::tracepoints::record_path_syscall(
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
        guest_mem::write_u64(base, stat_buf, 1);
        guest_mem::write_u64(base, stat_buf + 8, st.ino);
        guest_mem::write_u32(base, stat_buf + 16, st.mode);
        guest_mem::write_u32(base, stat_buf + 20, st.nlink);
        guest_mem::write_u32(base, stat_buf + 24, st.uid);
        guest_mem::write_u32(base, stat_buf + 28, st.gid);
        guest_mem::write_u64(base, stat_buf + 48, st.size);
        guest_mem::write_u32(base, stat_buf + 56, 4096u32);
        let blocks = st.size.div_ceil(512);
        guest_mem::write_u64(base, stat_buf + 64, blocks);
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
        guest_mem::write_u64(base, stat_buf, 1);
        guest_mem::write_u64(base, stat_buf + 8, ino);
        guest_mem::write_u32(base, stat_buf + 16, mode);
        guest_mem::write_u32(base, stat_buf + 20, 1);
        guest_mem::write_u32(base, stat_buf + 24, uid);
        guest_mem::write_u32(base, stat_buf + 28, gid);
        guest_mem::write_u64(base, stat_buf + 48, size);
        guest_mem::write_u32(base, stat_buf + 56, 4096u32);
        guest_mem::write_u64(base, stat_buf + 64, size.div_ceil(512));
    }
}

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
    crate::tracepoints::record_path_syscall(
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
                crate::tracepoints::record_path_syscall(
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
    crate::tracepoints::record_path_syscall(
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
pub fn sys_truncate(vm: &mut ThreadState, base: u32, path_addr: u64, length: u64) -> i64 {
    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let path = trim_trailing_slashes(&path_buf[1..1 + len]);

    if path.is_empty() {
        return ENOENT;
    }

    let ino = if path[0] == b'/' {
        memfs::resolve_path(path)
    } else {
        memfs::resolve_path_from(current_dir_ino(base, vm), path)
    };
    if ino == 0 {
        return ENOENT;
    }

    match memfs::stat(ino) {
        Some(st) if st.mode & memfs::S_IFMT == memfs::S_IFDIR => return EISDIR,
        Some(_) => {}
        None => return ENOENT,
    }

    memfs::truncate(ino, length)
}
