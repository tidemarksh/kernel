use super::MAX_PATH_SYMLINK_FOLLOWS;
use super::path::{
    dirfd_base_ino, path_has_trailing_slash, resolve_path_with_symlink_policy, split_parent_name,
    split_relative_parent_name, trim_trailing_slashes,
};
use crate::abi::*;
use crate::fs::{fd_table, memfs};
use crate::guest_mem;
use crate::types::ThreadState;

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
                    crate::tracepoints::record_path_syscall(
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
                crate::tracepoints::record_path_syscall(
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
    };
    crate::tracepoints::record_path_syscall(
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
