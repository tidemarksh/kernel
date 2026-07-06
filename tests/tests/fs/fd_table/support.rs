pub(super) use core::sync::atomic::Ordering;
pub(super) use tidemark_kernel::abi::*;
pub(super) use tidemark_kernel::fs::fd_table::{self, BackendCleanup, FD_CLOEXEC};
pub(super) use tidemark_kernel::harness::TestVm;
pub(super) use tidemark_kernel::syscall::{epoll, pipe};

pub(super) const LOCK_SH: u64 = 0x1;
pub(super) const LOCK_EX: u64 = 0x2;
pub(super) const LOCK_NB: u64 = 0x4;
pub(super) const LOCK_UN: u64 = 0x8;

pub(super) fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

pub(super) fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}
