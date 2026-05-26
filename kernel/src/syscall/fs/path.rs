use super::state::{current_dir_ino, set_current_dir_ino};
use super::{AT_FDCWD, MAX_PATH_SYMLINK_FOLLOWS};
use crate::abi::*;
use crate::fs::{fd_table, memfs};
use crate::guest_mem;
use crate::types::ThreadState;

pub(super) fn dirfd_base_ino(vm: &ThreadState, dirfd: u64, base: u32) -> Result<u32, i64> {
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

pub(super) fn trim_trailing_slashes(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    &path[..end]
}

pub(super) fn path_has_trailing_slash(path: &[u8]) -> bool {
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

pub(super) fn resolve_path_with_symlink_policy(
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
            let restart_ino = if target.first() == Some(&b'/') {
                1
            } else {
                ino
            };
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

pub(super) fn resolve_at(
    vm: &ThreadState,
    dirfd: u64,
    path_addr: u64,
    base: u32,
) -> Result<u32, i64> {
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

pub(super) fn split_parent_name(path: &[u8]) -> (u32, &[u8]) {
    if path == b"/" {
        return (0, &[]);
    }

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

pub(super) fn split_relative_parent_name(path: &[u8]) -> (&[u8], &[u8]) {
    if path.is_empty() {
        return (&[], &[]);
    }

    for i in (0..path.len()).rev() {
        if path[i] == b'/' {
            return (&path[..i], &path[i + 1..]);
        }
    }
    (&[], path)
}

fn ensure_directory_inode(ino: u32) -> Result<u32, i64> {
    let st = memfs::stat(ino).ok_or(ENOENT)?;
    if st.mode & memfs::S_IFMT != memfs::S_IFDIR {
        return Err(ENOTDIR);
    }
    Ok(ino)
}

pub(super) fn resolve_parent_and_name(
    vm: &ThreadState,
    base: u32,
    dirfd: u64,
    path_addr: u64,
) -> Result<(u32, [u8; 513], usize), i64> {
    let mut path_buf = [0u8; 513];
    let len = unsafe { guest_mem::read_cstr(base, path_addr, &mut path_buf[1..]) };
    let path = trim_trailing_slashes(&path_buf[1..1 + len]);
    if path.is_empty() {
        return Err(ENOENT);
    }
    let mut name_buf = [0u8; 513];

    if path[0] == b'/' {
        let mut last_slash = 0usize;
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
        if name.is_empty() {
            return Err(ENOENT);
        }
        let parent_ino =
            resolve_path_with_symlink_policy(1, parent_path, true, MAX_PATH_SYMLINK_FOLLOWS)?;
        let parent_ino = ensure_directory_inode(parent_ino)?;
        name_buf[..name.len()].copy_from_slice(name);
        return Ok((parent_ino, name_buf, name.len()));
    }

    let base_ino = dirfd_base_ino(vm, dirfd, base)?;
    let (parent_rel, name) = split_relative_parent_name(path);
    if name.is_empty() {
        return Err(ENOENT);
    }
    let parent_ino = if parent_rel.is_empty() {
        base_ino
    } else {
        resolve_path_with_symlink_policy(base_ino, parent_rel, true, MAX_PATH_SYMLINK_FOLLOWS)?
    };
    let parent_ino = ensure_directory_inode(parent_ino)?;
    name_buf[..name.len()].copy_from_slice(name);
    Ok((parent_ino, name_buf, name.len()))
}
