pub(super) use std::string::String;
pub(super) use std::sync::atomic::Ordering;
pub(super) use std::vec::Vec;
pub(super) use tidemark_kernel::abi::*;
pub(super) use tidemark_kernel::fs::{fd_table, memfs};
pub(super) use tidemark_kernel::harness::TestVm;
pub(super) use tidemark_kernel::syscall::fs;
pub(super) use tidemark_kernel::syscall::process as process_impl;

pub(super) const AT_FDCWD: u64 = (-100i64) as u64;
pub(super) const AT_REMOVEDIR: u64 = 0x200;
pub(super) const AT_EMPTY_PATH: u64 = 0x1000;
pub(super) const S_IFIFO: u32 = 0o010000;
pub(super) const TCGETS: u64 = 0x5401;
pub(super) const TIOCGWINSZ: u64 = 0x5413;
pub(super) const SYNC_EFFECT_PIPE_STATE: u32 = 1 << 0;
pub(super) const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;
