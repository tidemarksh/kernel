pub(super) use core::sync::atomic::Ordering;
pub(super) use tidemark_kernel::abi::*;
pub(super) use tidemark_kernel::fs::fd_table::{self, BackendCleanup, FD_CLOEXEC};
pub(super) use tidemark_kernel::harness::TestVm;
pub(super) use tidemark_kernel::syscall::{epoll, pipe};

pub(super) const LOCK_SH: u64 = 0x1;
pub(super) const LOCK_EX: u64 = 0x2;
pub(super) const LOCK_NB: u64 = 0x4;
pub(super) const LOCK_UN: u64 = 0x8;
