use super::{AT_FDCWD, resolve_at};
use crate::abi::*;
use crate::fs::fd_table;
use crate::types::ThreadState;

/// xattr syscalls.
/// https://man7.org/linux/man-pages/man7/xattr.7.html
/// https://man7.org/linux/man-pages/man2/setxattr.2.html
/// https://man7.org/linux/man-pages/man2/getxattr.2.html
/// https://man7.org/linux/man-pages/man2/listxattr.2.html
/// https://man7.org/linux/man-pages/man2/removexattr.2.html
///
/// MemFS does not store extended attributes. Existing objects behave like a
/// filesystem without xattr support: setting is not supported, getting/removing
/// a missing attribute reports ENODATA, and listing returns an empty list.
pub fn sys_setxattr(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => EOPNOTSUPP,
        Err(errno) => errno,
    }
}

pub fn sys_fsetxattr(vm: &ThreadState, base: u32, fd: u64) -> i64 {
    if fd_table::get_ofd(base, vm, fd).is_none() {
        return EBADF;
    }
    EOPNOTSUPP
}

pub fn sys_getxattr(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => ENODATA,
        Err(errno) => errno,
    }
}

pub fn sys_fgetxattr(vm: &ThreadState, base: u32, fd: u64) -> i64 {
    if fd_table::get_ofd(base, vm, fd).is_none() {
        return EBADF;
    }
    ENODATA
}

pub fn sys_listxattr(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => 0,
        Err(errno) => errno,
    }
}

pub fn sys_flistxattr(vm: &ThreadState, base: u32, fd: u64) -> i64 {
    if fd_table::get_ofd(base, vm, fd).is_none() {
        return EBADF;
    }
    0
}

pub fn sys_removexattr(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => ENODATA,
        Err(errno) => errno,
    }
}

pub fn sys_fremovexattr(vm: &ThreadState, base: u32, fd: u64) -> i64 {
    if fd_table::get_ofd(base, vm, fd).is_none() {
        return EBADF;
    }
    ENODATA
}
