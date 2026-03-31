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

    for i in 0..to_write {
        unsafe {
            *dp.add((tail + i) % cap) = data[i];
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

    for i in 0..to_read {
        buf[i] = unsafe { *dp.add((head + i) % cap) };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::TestVm;

    #[test]
    fn write_read_roundtrip() {
        let _ = TestVm::new();
        let idx = alloc_buffer().unwrap();
        let written = write(idx, b"hello network");
        assert_eq!(written, 13);
        let mut buf = [0u8; 32];
        let n = read(idx, &mut buf);
        assert_eq!(n, 13);
        assert_eq!(&buf[..13], b"hello network");
        free_buffer(idx);
    }

    #[test]
    fn buffer_full_returns_zero() {
        let _ = TestVm::new();
        let idx = alloc_buffer().unwrap();

        // Fill the buffer to capacity (BUF_SIZE - 1 usable bytes)
        let cap = BUF_SIZE as usize;
        let max_usable = cap - 1; // one slot reserved
        let chunk = [0xAAu8; 4096];
        let mut total_written = 0usize;
        while total_written < max_usable {
            let remain = max_usable - total_written;
            let to_write = remain.min(chunk.len());
            let w = write(idx, &chunk[..to_write]);
            assert!(w > 0, "should write while space remains");
            total_written += w;
        }
        assert_eq!(available(idx), max_usable);
        assert_eq!(space(idx), 0);

        // Now write should return 0
        assert_eq!(write(idx, b"more"), 0);

        free_buffer(idx);
    }

    #[test]
    fn circular_wrap_around() {
        let _ = TestVm::new();
        let idx = alloc_buffer().unwrap();
        let cap = BUF_SIZE as usize;

        // Write a large chunk to advance tail near end of buffer
        let big = [0xBBu8; 7000];
        let w1 = write(idx, &big);
        assert_eq!(w1, 7000);

        // Read most of it to advance head
        let mut tmp = [0u8; 6000];
        let r1 = read(idx, &mut tmp);
        assert_eq!(r1, 6000);
        // head is now at 6000, tail at 7000, 1000 bytes in buffer

        // Write enough to wrap around the end
        let wrap_data = [0xCCu8; 7000];
        let w2 = write(idx, &wrap_data);
        // free = cap - 1 - 1000 = 7191, so should write all 7000
        assert_eq!(w2, 7000);

        // Verify the tail has wrapped: tail = (7000 + 7000) % 8192 = 5808
        // Read everything back and verify data integrity
        let mut out = [0u8; 8000];
        let r2 = read(idx, &mut out);
        assert_eq!(r2, 8000); // 1000 remaining from first write + 7000 new

        // First 1000 bytes should be 0xBB (leftover from first write)
        for i in 0..1000 {
            assert_eq!(out[i], 0xBB, "byte {} should be 0xBB", i);
        }
        // Next 7000 bytes should be 0xCC (wrap-around data)
        for i in 1000..8000 {
            assert_eq!(out[i], 0xCC, "byte {} should be 0xCC", i);
        }

        free_buffer(idx);
    }
}
