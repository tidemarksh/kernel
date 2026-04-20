use super::AT_REMOVEDIR;
use super::path::{
    dirfd_base_ino, resolve_parent_and_name, split_parent_name, split_relative_parent_name,
    trim_trailing_slashes,
};
use crate::abi::*;
use crate::fs::memfs;
use crate::guest_mem;
use crate::types::ThreadState;

/// mkdirat: create a directory.
pub fn sys_mkdirat(vm: &mut ThreadState, base: u32, dirfd: u64, path_addr: u64, mode: u64) -> i64 {
    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let path = trim_trailing_slashes(&path_buf[1..1 + len]);
    if path.is_empty() {
        return ENOENT;
    }

    if path[0] == b'/' {
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

pub fn sys_renameat2(
    vm: &mut ThreadState,
    base: u32,
    olddirfd: u64,
    oldpath_addr: u64,
    newdirfd: u64,
    newpath_addr: u64,
    flags: u64,
) -> i64 {
    if flags != 0 {
        return EINVAL;
    }

    let (old_parent_ino, old_name_buf, old_name_len) =
        match resolve_parent_and_name(vm, base, olddirfd, oldpath_addr) {
            Ok(parts) => parts,
            Err(errno) => return errno,
        };
    let (new_parent_ino, new_name_buf, new_name_len) =
        match resolve_parent_and_name(vm, base, newdirfd, newpath_addr) {
            Ok(parts) => parts,
            Err(errno) => return errno,
        };

    memfs::rename(
        old_parent_ino,
        &old_name_buf[..old_name_len],
        new_parent_ino,
        &new_name_buf[..new_name_len],
    )
}
