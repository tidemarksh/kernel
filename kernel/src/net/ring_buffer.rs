//! Socket recv/send ring buffer.
//!
//! Shared circular buffer for socket data plane. Each socket gets two
//! buffers (send + recv). Producer writes via `write()`, consumer reads
//! via `read()`, using head/tail indices.
//! Socket ownership, accept/connect lifecycle, and cross-process wakeups stay
//! in `syscall::socket`; this module is intentionally limited to the payload
//! data plane plus attach/export of the backing pool pointer/bitmap.
//!
//! Reference: https://man7.org/linux/man-pages/man7/socket.7.html
//!
//! Struct layout:
//!
//! struct NetBuffer {                       // 8204 bytes total
//!     head:     u32,                       // offset 0   — consumer updates
//!     tail:     u32,                       // offset 4   — producer updates
//!     capacity: u32,                       // offset 8   — always BUF_SIZE
//!     _pad:     u32,                       // offset 12  — alignment padding
//!     data:     [u8; 8192],                // offset 16  — circular buffer
//! };

use crate::abi::MAX_SOCKETS;
use crate::alloc;

/// Per-buffer data area size (8 KiB, larger than pipe's 4 KiB for network data).
const BUF_SIZE: u32 = 8192;

/// Total size of one NetBuffer in memory.
const NET_BUF_SIZE: u32 = 16 + BUF_SIZE; // header (16) + data

/// Maximum number of net buffers: 2 per socket (send + recv).
const MAX_NET_BUFFERS: usize = MAX_SOCKETS * 2; // 64

/// Pointer to the net buffer pool in kernel Worker linear memory.
static mut NET_BUF_BASE: u32 = 0;

/// Allocation bitmap (1 = in use). 64 bits covers MAX_NET_BUFFERS.
static mut NET_BUF_USED: u64 = 0;

// Field offsets within a NetBuffer
const OFF_HEAD: u32 = 0;
const OFF_TAIL: u32 = 4;
const OFF_CAP: u32 = 8;
const OFF_DATA: u32 = 16;

/// Initialize net buffer subsystem. Allocates buffer pool via alloc.rs.
pub fn init() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(NET_BUF_BASE), 0);
        core::ptr::write(core::ptr::addr_of_mut!(NET_BUF_USED), 0);

        let total = MAX_NET_BUFFERS as u32 * NET_BUF_SIZE;
        let base = alloc::alloc_zeroed(total, 8);
        if base == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(core::ptr::addr_of_mut!(NET_BUF_BASE), base);
    }
}

fn buf_base() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(NET_BUF_BASE)) }
}

pub fn net_buffer_state() -> (u32, u64) {
    unsafe {
        (
            core::ptr::read(core::ptr::addr_of!(NET_BUF_BASE)),
            core::ptr::read(core::ptr::addr_of!(NET_BUF_USED)),
        )
    }
}

pub fn net_buffer_pool_bytes() -> u32 {
    MAX_NET_BUFFERS as u32 * NET_BUF_SIZE
}

pub fn attach_net_buffer_state(base: u32, used: u64) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(NET_BUF_BASE), base);
        core::ptr::write(core::ptr::addr_of_mut!(NET_BUF_USED), used);
    }
}

/// Byte address of buffer `idx` in linear memory.
fn buf_addr(idx: u32) -> u32 {
    buf_base() + idx * NET_BUF_SIZE
}

fn head_val(addr: u32) -> u32 {
    unsafe { *((addr + OFF_HEAD) as *const u32) }
}

fn set_head(addr: u32, v: u32) {
    unsafe {
        *((addr + OFF_HEAD) as *mut u32) = v;
    }
}

fn tail_val(addr: u32) -> u32 {
    unsafe { *((addr + OFF_TAIL) as *const u32) }
}

fn set_tail(addr: u32, v: u32) {
    unsafe {
        *((addr + OFF_TAIL) as *mut u32) = v;
    }
}

fn data_ptr(addr: u32) -> *mut u8 {
    (addr + OFF_DATA) as *mut u8
}

/// Allocate a free net buffer. Returns the buffer index, or `None` if full.
pub fn alloc_buffer() -> Option<u32> {
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(NET_BUF_USED));
        for i in 0..MAX_NET_BUFFERS {
            if used & (1u64 << i) == 0 {
                core::ptr::write(core::ptr::addr_of_mut!(NET_BUF_USED), used | (1u64 << i));
                let addr = buf_addr(i as u32);
                // Zero the buffer slot
                core::ptr::write_bytes(addr as *mut u8, 0, NET_BUF_SIZE as usize);
                // Set capacity
                *((addr + OFF_CAP) as *mut u32) = BUF_SIZE;
                return Some(i as u32);
            }
        }
        None
    }
}

/// Release a previously allocated buffer.
pub fn free_buffer(idx: u32) {
    unsafe {
        let used = core::ptr::read(core::ptr::addr_of!(NET_BUF_USED));
        core::ptr::write(core::ptr::addr_of_mut!(NET_BUF_USED), used & !(1u64 << idx));
    }
}

/// Write data into buffer `idx`. Returns number of bytes written (0 if full).
pub fn write(idx: u32, data: &[u8]) -> usize {
    let addr = buf_addr(idx);
    let head = head_val(addr) as usize;
    let tail = tail_val(addr) as usize;
    let cap = BUF_SIZE as usize;

    let used = if tail >= head {
        tail - head
    } else {
        cap - head + tail
    };
    let free = cap - 1 - used; // one slot reserved to distinguish full from empty
    if free == 0 {
        return 0;
    }

    let to_write = data.len().min(free);
    let dp = data_ptr(addr);

    for (i, byte) in data.iter().enumerate().take(to_write) {
        unsafe {
            *dp.add((tail + i) % cap) = *byte;
        }
    }
    set_tail(addr, ((tail + to_write) % cap) as u32);

    to_write
}

/// Read data from buffer `idx` into `buf`. Returns number of bytes read (0 if empty).
pub fn read(idx: u32, buf: &mut [u8]) -> usize {
    let addr = buf_addr(idx);
    let head = head_val(addr) as usize;
    let tail = tail_val(addr) as usize;
    let cap = BUF_SIZE as usize;

    if head == tail {
        return 0;
    }

    let avail = if tail >= head {
        tail - head
    } else {
        cap - head + tail
    };
    let to_read = buf.len().min(avail);
    let dp = data_ptr(addr);

    for (i, slot) in buf.iter_mut().enumerate().take(to_read) {
        *slot = unsafe { *dp.add((head + i) % cap) };
    }
    set_head(addr, ((head + to_read) % cap) as u32);

    to_read
}

/// Return number of bytes available for reading in buffer `idx`.
pub fn available(idx: u32) -> usize {
    let addr = buf_addr(idx);
    let head = head_val(addr) as usize;
    let tail = tail_val(addr) as usize;
    let cap = BUF_SIZE as usize;

    if tail >= head {
        tail - head
    } else {
        cap - head + tail
    }
}

/// Return number of bytes of free space for writing in buffer `idx`.
pub fn space(idx: u32) -> usize {
    let addr = buf_addr(idx);
    let head = head_val(addr) as usize;
    let tail = tail_val(addr) as usize;
    let cap = BUF_SIZE as usize;

    let used = if tail >= head {
        tail - head
    } else {
        cap - head + tail
    };
    cap - 1 - used
}

// =========================================================================
// Tests
// =========================================================================
