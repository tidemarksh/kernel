use super::{AT_FDCWD, resolve_at};
use crate::abi::*;
use crate::fs::memfs;
use crate::types::ThreadState;

/// chroot(2) changes the process root directory.
/// https://man7.org/linux/man-pages/man2/chroot.2.html
///
/// Tidemark does not currently track per-process root directories. Returning
/// success would lie about path resolution semantics, so expose the syscall as
/// unavailable after normal path/type validation.
pub fn sys_chroot(vm: &ThreadState, base: u32, path_addr: u64) -> i64 {
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
    ENOSYS
}

/// umount2(2) unmounts a mount point.
/// https://man7.org/linux/man-pages/man2/umount.2.html
///
/// Tidemark has no guest mount table yet. Existing paths are therefore not
/// mount points; Linux reports EINVAL for a target that is not mounted.
pub fn sys_umount2(vm: &ThreadState, base: u32, path_addr: u64, _flags: u64) -> i64 {
    match resolve_at(vm, AT_FDCWD as u64, path_addr, base) {
        Ok(_) => EINVAL,
        Err(errno) => errno,
    }
}

/// mount(2) mounts a filesystem.
/// https://man7.org/linux/man-pages/man2/mount.2.html
///
/// Tidemark has no guest mount table or CAP_SYS_ADMIN model. Linux rejects
/// unprivileged mount attempts with EPERM, which lets feature probes continue
/// without pretending the syscall number is absent.
pub fn sys_mount(
    _vm: &ThreadState,
    _base: u32,
    _source_addr: u64,
    _target_addr: u64,
    _filesystemtype_addr: u64,
    _mountflags: u64,
    _data_addr: u64,
) -> i64 {
    EPERM
}
