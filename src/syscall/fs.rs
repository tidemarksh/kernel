//! FS syscall stubs for stdout/stderr write.
//! Full FS implementation is in the kernel Worker (later phase).

use crate::abi::*;
use crate::guest_mem;
use crate::types::ThreadState;

/// Write callback for capturing output in tests.
/// Set by test harness; null = no capture.
static mut WRITE_CAPTURE: Option<fn(u32, u64, usize)> = None;

/// Register a capture callback for write syscalls (test use only).
pub fn set_write_capture(cb: Option<fn(u32, u64, usize)>) {
    unsafe { WRITE_CAPTURE = cb; }
}

/// Stub for write/writev: stdout (fd 1) and stderr (fd 2) return the
/// requested length. Other FDs return EBADF.
pub fn sys_write_stub(
    _vm: &mut ThreadState, base: u32,
    fd: u64, buf_or_iov: u64, count: u64, nr: u64,
) -> i64 {
    if nr == SYS_WRITEV {
        return sys_writev_stub(base, fd, buf_or_iov, count);
    }
    // SYS_WRITE: fd, buf, count
    match fd {
        1 | 2 => {
            unsafe {
                if let Some(cb) = WRITE_CAPTURE {
                    cb(base, buf_or_iov, count as usize);
                }
            }
            count as i64
        }
        _ => EBADF,
    }
}

/// writev stub: sum up iov_len fields and return total.
/// struct iovec { iov_base: u64, iov_len: u64 } — 16 bytes each.
fn sys_writev_stub(base: u32, fd: u64, iov_addr: u64, iovcnt: u64) -> i64 {
    match fd {
        1 | 2 => {
            let mut total = 0u64;
            for i in 0..iovcnt {
                let len = unsafe {
                    guest_mem::read_u64(base, iov_addr + i * 16 + 8)
                };
                total += len;
            }
            total as i64
        }
        _ => EBADF,
    }
}
