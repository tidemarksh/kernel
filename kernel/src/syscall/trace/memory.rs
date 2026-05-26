use crate::abi::*;
use crate::types::ThreadState;

#[inline(always)]
pub(in crate::syscall) fn record_trace(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, result: i64) {
    match nr {
        SYS_BRK | SYS_MMAP | SYS_MUNMAP | SYS_MSYNC | SYS_MREMAP | SYS_MPROTECT | SYS_MADVISE => {
            crate::tracepoints::record_memory_syscall(nr, a0, a1, a2, a3, result);
        }
        _ => {}
    }
}

#[inline(always)]
pub(in crate::syscall) fn record_debug(
    vm: &ThreadState,
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    result: i64,
) {
    match nr {
        SYS_BRK | SYS_MMAP | SYS_MUNMAP | SYS_MSYNC | SYS_MREMAP | SYS_MPROTECT | SYS_MADVISE => {
            crate::syscall::memory::record_debug_syscall(vm, nr, a0, a1, a2, a3, a4, a5, result);
        }
        _ => {}
    }
}
