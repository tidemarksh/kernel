//! Pipe and eventfd syscalls.
//!
//! Semantics: https://man7.org/linux/man-pages/man2/pipe.2.html
//!            https://man7.org/linux/man-pages/man7/pipe.7.html
//!
//! Data structure is implementation-specific (not based on Linux kernel internals).
//! Pipe slots are allocated on the SAB page cache (shared memory).
//! thread-workers access data plane directly via Atomics.
//! kernel Worker manages control plane (refcount changes).
//!
//! Struct layout (RV64):
//!
//! struct PipeSlot {                     // 4128 bytes total
//!     head:       AtomicU32,            // offset 0   — reader updates
//!     tail:       AtomicU32,            // offset 4   — writer updates
//!     read_open:  AtomicI32,            // offset 8   — kernel Worker only
//!     write_open: AtomicI32,            // offset 12  — kernel Worker only
//!     notify:     AtomicI32,            // offset 16  — Atomics.wait/notify target
//!     _pad:       [u8; 12],             // offset 20
//!     data:       [u8; 4096],           // offset 32  — circular buffer
//! };

use crate::abi::*;
use crate::alloc;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::ThreadState;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

const PIPE_BUF_SIZE: u32 = 4096;
const PIPE_SLOT_SIZE: u32 = 32 + PIPE_BUF_SIZE; // 4128 bytes
const EFD_SEMAPHORE: u64 = 0x1;

// Field offsets within a pipe slot
const OFF_HEAD: u32 = 0;
const OFF_TAIL: u32 = 4;
const OFF_READ_OPEN: u32 = 8;
const OFF_WRITE_OPEN: u32 = 12;
const OFF_NOTIFY: u32 = 16;
const OFF_DATA: u32 = 32;

/// SAB page cache base address for pipe slots.
/// Set by init() — points to a region in SAB (shared memory).
/// In the current single-instance config, this is allocated via alloc.rs
/// in the shared WASM Memory, matching the design where SAB = shared memory.
static mut SAB_PIPE_BASE: u32 = 0;

/// Pipe slot allocation bitmap (1 = in use).
static mut PIPE_USED: u64 = 0;

/// Initialize pipe subsystem. Allocates pipe slot region on shared memory.
pub fn init() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(SAB_PIPE_BASE), 0);
        // Slot 0 stays reserved as the ABI-level "no pipe" sentinel.
        core::ptr::write(core::ptr::addr_of_mut!(PIPE_USED), 1);

        let total = MAX_PIPES as u32 * PIPE_SLOT_SIZE;
        // Allocate from shared memory (in production, this is SAB;
        // in single-instance, alloc.rs allocates from the same shared WASM Memory)
        let base = alloc::alloc_zeroed(total, 8);
        if base == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(core::ptr::addr_of_mut!(SAB_PIPE_BASE), base);
    }
}

fn sab_base() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(SAB_PIPE_BASE)) }
}

pub fn pipe_state() -> (u32, u64) {
    unsafe {
        (
            core::ptr::read(core::ptr::addr_of!(SAB_PIPE_BASE)),
            core::ptr::read(core::ptr::addr_of!(PIPE_USED)),
        )
    }
}

pub fn pipe_region_bytes() -> u32 {
    MAX_PIPES as u32 * PIPE_SLOT_SIZE
}

pub fn attach_pipe_state(base: u32, used: u64) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(SAB_PIPE_BASE), base);
        core::ptr::write(core::ptr::addr_of_mut!(PIPE_USED), used);
    }
}

pub fn slot_addr(idx: u32) -> u32 {
    sab_base() + idx * PIPE_SLOT_SIZE
}

fn head_ptr(slot: u32) -> &'static AtomicU32 {
    unsafe { &*((slot + OFF_HEAD) as *const AtomicU32) }
}
fn tail_ptr(slot: u32) -> &'static AtomicU32 {
    unsafe { &*((slot + OFF_TAIL) as *const AtomicU32) }
}
pub fn read_open_ptr(slot: u32) -> &'static AtomicI32 {
    unsafe { &*((slot + OFF_READ_OPEN) as *const AtomicI32) }
}
fn write_open_ptr(slot: u32) -> &'static AtomicI32 {
    unsafe { &*((slot + OFF_WRITE_OPEN) as *const AtomicI32) }
}
pub fn debug_read_open(idx: u32) -> i32 {
    read_open_ptr(slot_addr(idx)).load(Ordering::Acquire)
}
pub fn debug_write_open(idx: u32) -> i32 {
    write_open_ptr(slot_addr(idx)).load(Ordering::Acquire)
}
fn data_ptr(slot: u32) -> *mut u8 {
    (slot + OFF_DATA) as *mut u8
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipeCloseOutcome {
    pub read_open: i32,
    pub write_open: i32,
    pub slot_released: bool,
}

pub fn alloc_pipe_slot() -> Option<u32> {
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(PIPE_USED));
        for i in 1..MAX_PIPES {
            if used & (1u64 << i) == 0 {
                core::ptr::write(core::ptr::addr_of_mut!(PIPE_USED), used | (1u64 << i));
                let addr = slot_addr(i as u32);
                // Zero the slot
                core::ptr::write_bytes(addr as *mut u8, 0, PIPE_SLOT_SIZE as usize);
                // Initialize refcounts
                read_open_ptr(addr).store(1, Ordering::Release);
                write_open_ptr(addr).store(1, Ordering::Release);
                return Some(i as u32);
            }
        }
        None
    }
}

fn free_pipe_slot(idx: u32) {
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(PIPE_USED));
        core::ptr::write(core::ptr::addr_of_mut!(PIPE_USED), used & !(1u64 << idx));
    }
}

// =========================================================================
// pipe2
// =========================================================================

/// pipe2: create a pipe with read/write FDs. Supports O_CLOEXEC and O_NONBLOCK flags.
pub fn sys_pipe2(vm: &mut ThreadState, base: u32, pipefd_addr: u64, flags: u64) -> i64 {
    let pipe_idx = match alloc_pipe_slot() {
        Some(i) => i,
        None => return ENOMEM,
    };

    let read_fd = fd_table::open_pipe(vm, base, pipe_idx, true, flags as i32);
    if read_fd < 0 {
        return read_fd;
    }

    let write_fd = fd_table::open_pipe(vm, base, pipe_idx, false, flags as i32);
    if write_fd < 0 {
        fd_table::sys_close(vm, base, read_fd as u64);
        return write_fd;
    }

    unsafe {
        guest_mem::write_u32(base, pipefd_addr, read_fd as u32);
        guest_mem::write_u32(base, pipefd_addr + 4, write_fd as u32);
    }
    0
}

// =========================================================================
// Pipe data plane: read/write via Atomics on SAB
// =========================================================================

/// Read from pipe's circular buffer via Atomics. Returns bytes read, 0 (EOF), or EAGAIN.
pub fn pipe_read(pipe_idx: u32, buf: &mut [u8]) -> i64 {
    let addr = slot_addr(pipe_idx);
    let head = head_ptr(addr).load(Ordering::Acquire);
    let tail = tail_ptr(addr).load(Ordering::Acquire);

    if head == tail {
        if write_open_ptr(addr).load(Ordering::Acquire) <= 0 {
            return 0; // EOF
        }
        return EAGAIN;
    }

    let cap = PIPE_BUF_SIZE as usize;
    let available = if tail >= head {
        (tail - head) as usize
    } else {
        cap - head as usize + tail as usize
    };
    let to_read = buf.len().min(available);
    let h = head as usize;
    let dp = data_ptr(addr);

    for i in 0..to_read {
        buf[i] = unsafe { *dp.add((h + i) % cap) };
    }
    head_ptr(addr).store(((h + to_read) % cap) as u32, Ordering::Release);

    to_read as i64
}

/// Write to pipe's circular buffer via Atomics. Returns bytes written, EPIPE, or EAGAIN.
pub fn pipe_write(pipe_idx: u32, data: &[u8]) -> i64 {
    let addr = slot_addr(pipe_idx);

    if read_open_ptr(addr).load(Ordering::Acquire) <= 0 {
        return EPIPE;
    }

    let head = head_ptr(addr).load(Ordering::Acquire) as usize;
    let tail = tail_ptr(addr).load(Ordering::Acquire) as usize;
    let cap = PIPE_BUF_SIZE as usize;

    let used = if tail >= head {
        tail - head
    } else {
        cap - head + tail
    };
    let free = cap - 1 - used;
    if free == 0 {
        return EAGAIN;
    }

    let to_write = data.len().min(free);
    let dp = data_ptr(addr);

    for i in 0..to_write {
        unsafe {
            *dp.add((tail + i) % cap) = data[i];
        }
    }
    tail_ptr(addr).store(((tail + to_write) % cap) as u32, Ordering::Release);

    to_write as i64
}

/// Peek at pipe state without consuming data. Returns:
///   > 0: number of bytes available to read
///   0:   EOF (write end closed, no data)
///   EAGAIN: empty but write end still open (would block)
pub fn pipe_peek(pipe_idx: u32) -> i64 {
    let addr = slot_addr(pipe_idx);
    let head = head_ptr(addr).load(Ordering::Acquire);
    let tail = tail_ptr(addr).load(Ordering::Acquire);

    if head == tail {
        if write_open_ptr(addr).load(Ordering::Acquire) <= 0 {
            return 0; // EOF
        }
        return EAGAIN;
    }

    let cap = PIPE_BUF_SIZE as usize;
    let available = if tail >= head {
        (tail - head) as usize
    } else {
        cap - head as usize + tail as usize
    };
    available as i64
}

/// Check if the write side of a pipe has capacity.
/// Returns true if at least 1 byte can be written.
pub fn pipe_writable(pipe_idx: u32) -> bool {
    let addr = slot_addr(pipe_idx);
    if read_open_ptr(addr).load(Ordering::Acquire) <= 0 {
        return true; // writable in the sense that write() will return (EPIPE)
    }
    let head = head_ptr(addr).load(Ordering::Acquire) as usize;
    let tail = tail_ptr(addr).load(Ordering::Acquire) as usize;
    let cap = PIPE_BUF_SIZE as usize;
    let used = if tail >= head {
        tail - head
    } else {
        cap - head + tail
    };
    let free = cap - 1 - used;
    free > 0
}

/// Close one end of a pipe (kernel Worker control plane).
pub fn pipe_close_outcome(pipe_idx: u32, is_read_end: bool) -> PipeCloseOutcome {
    let addr = slot_addr(pipe_idx);

    if is_read_end {
        read_open_ptr(addr).fetch_sub(1, Ordering::Release);
    } else {
        write_open_ptr(addr).fetch_sub(1, Ordering::Release);
    }

    let read_open = read_open_ptr(addr).load(Ordering::Acquire);
    let write_open = write_open_ptr(addr).load(Ordering::Acquire);
    let slot_released = read_open <= 0 && write_open <= 0;
    if slot_released {
        free_pipe_slot(pipe_idx);
    }

    PipeCloseOutcome {
        read_open,
        write_open,
        slot_released,
    }
}

/// Close one end of a pipe (kernel Worker control plane).
pub fn pipe_close(pipe_idx: u32, is_read_end: bool) {
    let _ = pipe_close_outcome(pipe_idx, is_read_end);
}

// =========================================================================
// eventfd2
// =========================================================================

pub fn sys_eventfd2(vm: &mut ThreadState, base: u32, initval: u64, flags: u64) -> i64 {
    let supported = EFD_SEMAPHORE | O_NONBLOCK as u64 | O_CLOEXEC as u64;
    if flags & !supported != 0 {
        return EINVAL;
    }
    fd_table::open_eventfd(vm, base, initval & 0xffff_ffff, flags as i32)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::fd_table::OPEN_ACCESS_MODE_MASK;
    use crate::test_helpers::TestVm;

    #[test]
    fn write_read_roundtrip() {
        let _ = TestVm::new();
        let idx = alloc_pipe_slot().unwrap();
        assert_eq!(pipe_write(idx, b"hello pipe"), 10);
        let mut buf = [0u8; 32];
        assert_eq!(pipe_read(idx, &mut buf), 10);
        assert_eq!(&buf[..10], b"hello pipe");
    }

    #[test]
    fn eof_on_writer_close() {
        let _ = TestVm::new();
        let idx = alloc_pipe_slot().unwrap();
        pipe_close(idx, false); // close write end
        let mut buf = [0u8; 16];
        assert_eq!(pipe_read(idx, &mut buf), 0); // EOF
    }

    #[test]
    fn epipe_on_reader_close() {
        let _ = TestVm::new();
        let idx = alloc_pipe_slot().unwrap();
        pipe_close(idx, true); // close read end
        assert_eq!(pipe_write(idx, b"data"), EPIPE);
    }

    #[test]
    fn pipe_close_outcome_reports_remaining_open_ends() {
        let _ = TestVm::new();
        let idx = alloc_pipe_slot().unwrap();

        let first = pipe_close_outcome(idx, true);
        assert_eq!(
            first,
            PipeCloseOutcome {
                read_open: 0,
                write_open: 1,
                slot_released: false,
            }
        );

        let second = pipe_close_outcome(idx, false);
        assert_eq!(
            second,
            PipeCloseOutcome {
                read_open: 0,
                write_open: 0,
                slot_released: true,
            }
        );
    }

    #[test]
    fn pipe_slot_zero_is_reserved() {
        let _ = TestVm::new();
        let idx = alloc_pipe_slot().unwrap();
        assert_ne!(idx, 0);
    }

    #[test]
    fn circular_wrap() {
        let _ = TestVm::new();
        let idx = alloc_pipe_slot().unwrap();
        let big = [0xABu8; 4000];
        assert_eq!(pipe_write(idx, &big), 4000);
        let mut tmp = [0u8; 3000];
        assert_eq!(pipe_read(idx, &mut tmp), 3000);
        let w2 = pipe_write(idx, &big[..3000]);
        assert!(w2 > 0);
        let mut out = [0u8; 4095];
        let r2 = pipe_read(idx, &mut out);
        assert!(r2 > 0);
    }

    #[test]
    fn sys_pipe2_sets_cloexec_and_nonblock_flags() {
        let mut t = TestVm::new();
        let pipefd_addr = t.scratch + 0x1000;

        assert_eq!(
            super::sys_pipe2(
                &mut t.vm,
                t.base,
                pipefd_addr,
                (O_CLOEXEC | O_NONBLOCK) as u64,
            ),
            0
        );

        let read_fd = unsafe { crate::guest_mem::read_u32(t.base, pipefd_addr) } as i64;
        let write_fd = unsafe { crate::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
        assert!(read_fd >= 3);
        assert!(write_fd >= 3);

        assert_eq!(t.sys_fcntl(read_fd as u64, 1, 0), 1);
        assert_eq!(t.sys_fcntl(write_fd as u64, 1, 0), 1);
        assert_ne!(t.sys_fcntl(read_fd as u64, 3, 0) & O_NONBLOCK as i64, 0);
        assert_ne!(t.sys_fcntl(write_fd as u64, 3, 0) & O_NONBLOCK as i64, 0);

        assert_eq!(t.sys_write_data(write_fd, b"ok"), 2);
        let mut buf = [0u8; 2];
        assert_eq!(t.sys_read(read_fd, &mut buf), 2);
        assert_eq!(&buf, b"ok");
    }

    #[test]
    fn sys_pipe2_reports_read_write_access_modes() {
        let mut t = TestVm::new();
        let pipefd_addr = t.scratch + 0x1400;

        assert_eq!(super::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);

        let read_fd = unsafe { crate::guest_mem::read_u32(t.base, pipefd_addr) } as i64;
        let write_fd = unsafe { crate::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;

        assert_eq!(
            t.sys_fcntl(read_fd as u64, 3, 0) & OPEN_ACCESS_MODE_MASK as i64,
            O_RDONLY as i64,
        );
        assert_eq!(
            t.sys_fcntl(write_fd as u64, 3, 0) & OPEN_ACCESS_MODE_MASK as i64,
            O_WRONLY as i64,
        );
    }

    #[test]
    fn eventfd_roundtrip_and_nonblock_flags() {
        let mut t = TestVm::new();
        let fd = super::sys_eventfd2(
            &mut t.vm,
            t.base,
            2,
            (O_CLOEXEC | O_NONBLOCK) as u64,
        );
        assert!(fd >= 3);
        assert_eq!(t.sys_fcntl(fd as u64, 1, 0), 1);
        assert_ne!(t.sys_fcntl(fd as u64, 3, 0) & O_NONBLOCK as i64, 0);

        let buf_addr = t.scratch + 0x1800;
        unsafe {
            crate::guest_mem::write_u64(t.base, buf_addr, 3);
        }
        assert_eq!(
            crate::syscall::fs::sys_write(&mut t.vm, t.base, fd as u64, buf_addr, 8, SYS_WRITE),
            8
        );
        assert_eq!(
            crate::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
            8
        );
        assert_eq!(unsafe { crate::guest_mem::read_u64(t.base, buf_addr) }, 5);
        assert_eq!(
            crate::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
            EAGAIN
        );
    }
}
