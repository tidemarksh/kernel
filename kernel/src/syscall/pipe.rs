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
//! struct PipeSlot {                     // 65568 bytes total
//!     head:       AtomicU32,            // offset 0   — reader updates
//!     tail:       AtomicU32,            // offset 4   — writer updates
//!     read_open:  AtomicI32,            // offset 8   — kernel Worker only
//!     write_open: AtomicI32,            // offset 12  — kernel Worker only
//!     notify:     AtomicI32,            // offset 16  — Atomics.wait/notify target
//!     generation: AtomicU32,            // offset 20  — internal slot reuse guard
//!     _pad:       [u8; 8],              // offset 24
//!     data:       [u8; 65536],          // offset 32  — circular buffer
//! };

use crate::abi::*;
use crate::alloc;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::ThreadState;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

pub const PIPE_BUF_SIZE: usize = 65_536;
const PIPE_SLOT_SIZE: u32 = 32 + PIPE_BUF_SIZE as u32; // 65568 bytes
const EFD_SEMAPHORE: u64 = 0x1;

// Field offsets within a pipe slot
const OFF_HEAD: u32 = 0;
const OFF_TAIL: u32 = 4;
const OFF_READ_OPEN: u32 = 8;
const OFF_WRITE_OPEN: u32 = 12;
const OFF_GENERATION: u32 = 20;
const OFF_DATA: u32 = 32;

/// SAB page cache base address for pipe slots.
/// Set by init() — points to a region in SAB (shared memory).
/// In the current single-instance config, this is allocated via alloc.rs
/// in the shared WASM Memory, matching the design where SAB = shared memory.
static mut SAB_PIPE_BASE: u32 = 0;

/// Pipe slot allocation bitmap (1 = in use).
static mut PIPE_USED: u64 = 0;
static mut PIPE_GENERATION: u32 = 1;

/// Initialize pipe subsystem. Allocates pipe slot region on shared memory.
pub fn init() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(SAB_PIPE_BASE), 0);
        // Slot 0 stays reserved as the ABI-level "no pipe" sentinel.
        core::ptr::write(core::ptr::addr_of_mut!(PIPE_USED), 1);
        core::ptr::write(core::ptr::addr_of_mut!(PIPE_GENERATION), 1);

        let total = MAX_PIPES as u32 * PIPE_SLOT_SIZE;
        // Allocate from shared memory (in production, this is SAB;
        // in single-instance, alloc.rs allocates from the same shared WASM Memory)
        let base = alloc::alloc_zeroed(total, 8);
        if base == 0 {
            crate::wasm::unreachable();
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

fn max_pipe_generation() -> u32 {
    let mut max_generation = 0;
    for i in 1..MAX_PIPES {
        let generation = pipe_generation(i as u32);
        if generation > max_generation {
            max_generation = generation;
        }
    }
    max_generation
}

pub fn attach_pipe_state(base: u32, used: u64) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(SAB_PIPE_BASE), base);
        core::ptr::write(core::ptr::addr_of_mut!(PIPE_USED), used);
        let current_generation = core::ptr::read(core::ptr::addr_of!(PIPE_GENERATION));
        let max_generation = max_pipe_generation();
        if max_generation > current_generation {
            core::ptr::write(core::ptr::addr_of_mut!(PIPE_GENERATION), max_generation);
        }
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
fn generation_ptr(slot: u32) -> &'static AtomicU32 {
    unsafe { &*((slot + OFF_GENERATION) as *const AtomicU32) }
}
pub fn pipe_generation(idx: u32) -> u32 {
    generation_ptr(slot_addr(idx)).load(Ordering::Acquire)
}
pub fn pipe_generation_matches(idx: u32, expected_generation: u32) -> bool {
    expected_generation == 0 || pipe_generation(idx) == expected_generation
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

unsafe fn copy_into_ring(dst: *mut u8, tail: usize, cap: usize, data: &[u8], len: usize) {
    let first = len.min(cap - tail);
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), dst.add(tail), first);
    }
    if len > first {
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr().add(first), dst, len - first);
        }
    }
}

unsafe fn copy_from_ring(src: *const u8, head: usize, cap: usize, out: &mut [u8], len: usize) {
    let first = len.min(cap - head);
    unsafe {
        core::ptr::copy_nonoverlapping(src.add(head), out.as_mut_ptr(), first);
    }
    if len > first {
        unsafe {
            core::ptr::copy_nonoverlapping(src, out.as_mut_ptr().add(first), len - first);
        }
    }
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
                let current_generation = core::ptr::read(core::ptr::addr_of!(PIPE_GENERATION));
                let max_generation = max_pipe_generation();
                let mut generation = current_generation.max(max_generation).wrapping_add(1);
                if generation == 0 {
                    generation = 1;
                }
                core::ptr::write(core::ptr::addr_of_mut!(PIPE_GENERATION), generation);
                // Zero the slot
                core::ptr::write_bytes(addr as *mut u8, 0, PIPE_SLOT_SIZE as usize);
                // Initialize refcounts
                read_open_ptr(addr).store(1, Ordering::Release);
                write_open_ptr(addr).store(1, Ordering::Release);
                generation_ptr(addr).store(generation, Ordering::Release);
                return Some(i as u32);
            }
        }
        None
    }
}

// =========================================================================
// pipe2
// =========================================================================

/// pipe2: create a pipe with read/write FDs. Supports O_CLOEXEC and O_NONBLOCK flags.
pub fn sys_pipe2(vm: &mut ThreadState, base: u32, pipefd_addr: u64, flags: u64) -> i64 {
    if pipefd_addr == 0 || !crate::syscall::memory::guest_range_accessible(base, pipefd_addr, 8) {
        return EFAULT;
    }

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

    let cap = PIPE_BUF_SIZE;
    let available = if tail >= head {
        (tail - head) as usize
    } else {
        cap - head as usize + tail as usize
    };
    let to_read = buf.len().min(available);
    let h = head as usize;
    let dp = data_ptr(addr);

    unsafe {
        copy_from_ring(dp, h, cap, buf, to_read);
    }
    head_ptr(addr).store(((h + to_read) % cap) as u32, Ordering::Release);

    to_read as i64
}

pub fn pipe_buffered_len(pipe_idx: u32) -> u32 {
    let addr = slot_addr(pipe_idx);
    let head = head_ptr(addr).load(Ordering::Acquire);
    let tail = tail_ptr(addr).load(Ordering::Acquire);
    if tail >= head {
        tail - head
    } else {
        PIPE_BUF_SIZE as u32 - head + tail
    }
}

/// Write to pipe's circular buffer via Atomics. Returns bytes written, EPIPE, or EAGAIN.
pub fn pipe_write(pipe_idx: u32, data: &[u8]) -> i64 {
    let addr = slot_addr(pipe_idx);

    if read_open_ptr(addr).load(Ordering::Acquire) <= 0 {
        return EPIPE;
    }

    let head = head_ptr(addr).load(Ordering::Acquire) as usize;
    let tail = tail_ptr(addr).load(Ordering::Acquire) as usize;
    let cap = PIPE_BUF_SIZE;

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

    unsafe {
        copy_into_ring(dp, tail, cap, data, to_write);
    }
    tail_ptr(addr).store(((tail + to_write) % cap) as u32, Ordering::Release);

    to_write as i64
}

/// Peek at pipe state without consuming data. Returns:
/// - `> 0`: number of bytes available to read
/// - `0`: EOF (write end closed, no data)
/// - `EAGAIN`: empty but write end still open (would block)
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

    let cap = PIPE_BUF_SIZE;
    let available = if tail >= head {
        (tail - head) as usize
    } else {
        cap - head as usize + tail as usize
    };
    available as i64
}

/// Check if the write side of a pipe should report writable to poll/epoll.
///
/// Level-triggered readiness follows `write(2)`: any free byte means writable.
/// Edge-triggered readiness uses a stricter threshold so `EPOLLOUT|EPOLLET`
/// only re-arms once the pipe becomes fully writable again after backpressure.
pub fn pipe_writable(pipe_idx: u32, edge_triggered: bool) -> bool {
    let addr = slot_addr(pipe_idx);
    if read_open_ptr(addr).load(Ordering::Acquire) <= 0 {
        return true; // writable in the sense that write() will return (EPIPE)
    }
    let head = head_ptr(addr).load(Ordering::Acquire) as usize;
    let tail = tail_ptr(addr).load(Ordering::Acquire) as usize;
    let cap = PIPE_BUF_SIZE;
    let used = if tail >= head {
        tail - head
    } else {
        cap - head + tail
    };
    let free = cap - 1 - used;
    if edge_triggered {
        free == cap - 1
    } else {
        free > 0
    }
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
    // Do not clear PIPE_USED from a process-local close path. In the runtime,
    // forked processes have separate kernel instances and a local endpoint count
    // may be stale until the kernel-worker reconciles all process-held FDs.
    // Reuse is made visible by attach_pipe_state after that global reconcile.

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
    use crate::fs::fd_table;
    use crate::harness::TestVm;

    const F_SETFD: u64 = 2;
    const FD_CLOEXEC: u64 = 1;

    fn read_pipe_fds(vm: &TestVm, addr: u64) -> (u32, u32) {
        unsafe {
            (
                crate::guest_mem::read_u32(vm.base, addr),
                crate::guest_mem::read_u32(vm.base, addr + 4),
            )
        }
    }

    #[test]
    fn pipe2_fds_survive_close_on_exec_updates_for_adjacent_descriptors() {
        let mut vm = TestVm::new();
        let first = vm.scratch;
        let second = vm.scratch + 8;

        assert_eq!(sys_pipe2(&mut vm.vm, vm.base, first, 0), 0);
        assert_eq!(sys_pipe2(&mut vm.vm, vm.base, second, 0), 0);
        let (first_read, first_write) = read_pipe_fds(&vm, first);
        let (second_read, second_write) = read_pipe_fds(&vm, second);
        assert_eq!(
            (first_read, first_write, second_read, second_write),
            (3, 4, 5, 6)
        );

        assert_eq!(
            fd_table::sys_fcntl(&mut vm.vm, vm.base, first_read as u64, F_SETFD, FD_CLOEXEC),
            0
        );
        assert_eq!(
            fd_table::sys_fcntl(&mut vm.vm, vm.base, first_write as u64, F_SETFD, FD_CLOEXEC),
            0
        );
        assert_eq!(
            fd_table::sys_fcntl(&mut vm.vm, vm.base, second_read as u64, F_SETFD, FD_CLOEXEC),
            0
        );
        assert_eq!(
            fd_table::sys_fcntl(
                &mut vm.vm,
                vm.base,
                second_write as u64,
                F_SETFD,
                FD_CLOEXEC
            ),
            0
        );
    }
}
