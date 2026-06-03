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

mod getdents;
mod lseek;
mod meta;
mod mount;
mod mutation;
mod open;
mod path;
mod pending;
mod read_write;
mod state;
mod xattr;

const AT_FDCWD: i32 = -100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const PENDING_FS_PATH_MAX: usize = 4096;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;
const MAX_PATH_SYMLINK_FOLLOWS: u32 = 40;
pub use getdents::sys_getdents64;
pub use lseek::sys_lseek;
pub use meta::{
    sys_faccessat, sys_fchmod, sys_fchmodat, sys_fchown, sys_fchownat, sys_fstat, sys_ftruncate,
    sys_newfstatat, sys_readlinkat, sys_statfs, sys_truncate, sys_utimensat,
};
pub use mount::{sys_chroot, sys_mount, sys_umount2};
pub use mutation::{sys_mkdirat, sys_renameat, sys_renameat2, sys_unlinkat};
pub use open::sys_openat;
use path::resolve_at;
pub use path::{sys_chdir, sys_getcwd};
pub use pending::{
    FS_EFFECT_MEMFS_FILE_DATA, FS_EFFECT_MEMFS_MUTATION, FS_EFFECT_SHARED_OFD_STATE,
    dispatch_fstat, dispatch_ftruncate, dispatch_getdents64, dispatch_lseek, dispatch_mkdirat,
    dispatch_mmap, dispatch_openat, dispatch_pread64, dispatch_pwrite64, dispatch_read,
    dispatch_renameat2, dispatch_truncate, dispatch_unlinkat, dispatch_write,
    pending_request_absolute_path, pending_request_effects, pending_request_opcode,
    pending_request_path_len, pending_request_path_ptr, pending_request_secondary_absolute_path,
    pending_request_target_ino, process_pending_requests, resume_from_fs,
};
pub(crate) use read_write::PIPE_READ_EOF_SYNC_RETRY_MARKER;
pub use read_write::{sys_pread64, sys_pwrite64, sys_read, sys_readv, sys_write};
pub(crate) use state::sys_umask;
pub use xattr::{
    sys_fgetxattr, sys_flistxattr, sys_fremovexattr, sys_fsetxattr, sys_getxattr, sys_listxattr,
    sys_removexattr, sys_setxattr,
};
