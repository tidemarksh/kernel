//! Pipe and eventfd syscalls.
//!
//! Pipe slots are allocated on the SAB page cache (shared memory).
//! thread-workers access data plane directly via Atomics.
//! kernel Worker manages control plane (refcount changes).
//!
//! Per-pipe slot layout on SAB (from the design):
//!
//! offset  type        field        accessed by
//! +0      AtomicU32   head         reader (Atomics.store)
//! +4      AtomicU32   tail         writer (Atomics.store)
//! +8      AtomicI32   read_open    kernel Worker only
//! +12     AtomicI32   write_open   kernel Worker only
//! +16     AtomicI32   notify       writer/kernel (Atomics.wait/notify target)
//! +20     [u8; 12]    _pad
//! +32     [u8; 4096]  data         writer/reader directly

use core::sync::atomic::{AtomicU32, AtomicI32, Ordering};
use crate::abi::*;
use crate::alloc;
use crate::guest_mem;
use crate::fs::fd_table;
use crate::types::ThreadState;

const PIPE_BUF_SIZE: u32 = 4096;
const PIPE_SLOT_SIZE: u32 = 32 + PIPE_BUF_SIZE; // 4128 bytes

// Field offsets within a pipe slot
const OFF_HEAD: u32       = 0;
const OFF_TAIL: u32       = 4;
const OFF_READ_OPEN: u32  = 8;
const OFF_WRITE_OPEN: u32 = 12;
const OFF_NOTIFY: u32     = 16;
const OFF_DATA: u32       = 32;

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
        let total = MAX_PIPES as u32 * PIPE_SLOT_SIZE;
        // Allocate from shared memory (in production, this is SAB;
        // in single-instance, alloc.rs allocates from the same shared WASM Memory)
        let base = alloc::alloc_zeroed(total, 8);
        if base == 0 { core::arch::wasm32::unreachable(); }
        core::ptr::write(core::ptr::addr_of_mut!(SAB_PIPE_BASE), base);
        core::ptr::write(core::ptr::addr_of_mut!(PIPE_USED), 0);
    }
}

fn sab_base() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(SAB_PIPE_BASE)) }
}

fn slot_addr(idx: u32) -> u32 {
    sab_base() + idx * PIPE_SLOT_SIZE
}

fn head_ptr(slot: u32) -> &'static AtomicU32 {
    unsafe { &*((slot + OFF_HEAD) as *const AtomicU32) }
}
fn tail_ptr(slot: u32) -> &'static AtomicU32 {
    unsafe { &*((slot + OFF_TAIL) as *const AtomicU32) }
}
fn read_open_ptr(slot: u32) -> &'static AtomicI32 {
    unsafe { &*((slot + OFF_READ_OPEN) as *const AtomicI32) }
}
fn write_open_ptr(slot: u32) -> &'static AtomicI32 {
    unsafe { &*((slot + OFF_WRITE_OPEN) as *const AtomicI32) }
}
fn data_ptr(slot: u32) -> *mut u8 {
    (slot + OFF_DATA) as *mut u8
}

fn alloc_pipe_slot() -> Option<u32> {
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(PIPE_USED));
        for i in 0..MAX_PIPES {
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

pub fn sys_pipe2(vm: &mut ThreadState, base: u32, pipefd_addr: u64, flags: u64) -> i64 {
    let pipe_idx = match alloc_pipe_slot() {
        Some(i) => i,
        None => return ENOMEM,
    };

    let read_fd = fd_table::open_pipe(vm, base, pipe_idx, true, flags as i32);
    if read_fd < 0 { return read_fd; }

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

pub fn pipe_write(pipe_idx: u32, data: &[u8]) -> i64 {
    let addr = slot_addr(pipe_idx);

    if read_open_ptr(addr).load(Ordering::Acquire) <= 0 {
        return EPIPE;
    }

    let head = head_ptr(addr).load(Ordering::Acquire) as usize;
    let tail = tail_ptr(addr).load(Ordering::Acquire) as usize;
    let cap = PIPE_BUF_SIZE as usize;

    let used = if tail >= head { tail - head } else { cap - head + tail };
    let free = cap - 1 - used;
    if free == 0 { return EAGAIN; }

    let to_write = data.len().min(free);
    let dp = data_ptr(addr);

    for i in 0..to_write {
        unsafe { *dp.add((tail + i) % cap) = data[i]; }
    }
    tail_ptr(addr).store(((tail + to_write) % cap) as u32, Ordering::Release);

    to_write as i64
}

/// Close one end of a pipe (kernel Worker control plane).
pub fn pipe_close(pipe_idx: u32, is_read_end: bool) {
    let addr = slot_addr(pipe_idx);

    if is_read_end {
        read_open_ptr(addr).fetch_sub(1, Ordering::Release);
    } else {
        write_open_ptr(addr).fetch_sub(1, Ordering::Release);
    }

    if read_open_ptr(addr).load(Ordering::Acquire) <= 0
        && write_open_ptr(addr).load(Ordering::Acquire) <= 0
    {
        free_pipe_slot(pipe_idx);
    }
}

// =========================================================================
// eventfd2
// =========================================================================

pub fn sys_eventfd2(_vm: &mut ThreadState, _base: u32, _initval: u64, _flags: u64) -> i64 {
    ENOSYS
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        unsafe {
            let current_pages = core::arch::wasm32::memory_size(0);
            if current_pages < 256 {
                core::arch::wasm32::memory_grow(0, 256 - current_pages);
            }
            crate::alloc::init(0x80_0000);
        }
        init();
    }

    #[test]
    fn write_read_roundtrip() {
        setup();
        let idx = alloc_pipe_slot().unwrap();
        assert_eq!(pipe_write(idx, b"hello pipe"), 10);
        let mut buf = [0u8; 32];
        assert_eq!(pipe_read(idx, &mut buf), 10);
        assert_eq!(&buf[..10], b"hello pipe");
    }

    #[test]
    fn eof_on_writer_close() {
        setup();
        let idx = alloc_pipe_slot().unwrap();
        pipe_close(idx, false); // close write end
        let mut buf = [0u8; 16];
        assert_eq!(pipe_read(idx, &mut buf), 0); // EOF
    }

    #[test]
    fn epipe_on_reader_close() {
        setup();
        let idx = alloc_pipe_slot().unwrap();
        pipe_close(idx, true); // close read end
        assert_eq!(pipe_write(idx, b"data"), EPIPE);
    }

    #[test]
    fn circular_wrap() {
        setup();
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
}
