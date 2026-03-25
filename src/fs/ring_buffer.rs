//! SAB ring buffer for FS request/response between thread-worker and kernel Worker.
//!
//! Struct layouts (RV64):
//!
//! struct FsRingBuffer {                 // 5152 bytes total
//!     submit_head:   AtomicU32,         // offset 0   — thread-worker writes
//!     submit_tail:   AtomicU32,         // offset 4   — kernel Worker reads
//!     complete_head: AtomicU32,         // offset 8   — kernel Worker writes
//!     complete_tail: AtomicU32,         // offset 12  — thread-worker reads
//!     notify:        AtomicI32,         // offset 16  — Atomics.wait/notify target
//!     _pad:          [u8; 12],          // offset 20
//!     sq_entries:    [FsRequest; 64],   // offset 32  — submission queue
//!     cq_entries:    [FsResponse; 64],  // offset 4128 — completion queue
//! };
//!
//! struct FsRequest {                    // 64 bytes total
//!     opcode:  u32,                     // offset 0
//!     fd:      i32,                     // offset 4
//!     offset:  u64,                     // offset 8
//!     len:     u64,                     // offset 16
//!     buf_ptr: u64,                     // offset 24
//!     path_ptr:u64,                     // offset 32
//!     flags:   u32,                     // offset 40
//!     mode:    u32,                     // offset 44
//!     _pad:    [u8; 16],               // offset 48
//! };
//!
//! struct FsResponse {                   // 16 bytes total
//!     result:  i64,                     // offset 0
//!     _pad:    u64,                     // offset 8
//! };

use crate::abi::*;

pub const SQ_SIZE: usize = 64;
pub const CQ_SIZE: usize = 64;
pub const REQ_SIZE: usize = 64;
pub const RESP_SIZE: usize = 16;
pub const HEADER_SIZE: usize = 32;
pub const RING_BUFFER_SIZE: usize = HEADER_SIZE + SQ_SIZE * REQ_SIZE + CQ_SIZE * RESP_SIZE;

// FS operation codes
pub const FS_OP_READ: u32      = 1;
pub const FS_OP_WRITE: u32     = 2;
pub const FS_OP_OPENAT: u32    = 3;
pub const FS_OP_CLOSE: u32     = 4;
pub const FS_OP_FSTAT: u32     = 5;
pub const FS_OP_MKDIR: u32     = 6;
pub const FS_OP_UNLINK: u32    = 7;
pub const FS_OP_RENAME: u32    = 8;
pub const FS_OP_GETDENTS: u32  = 9;
pub const FS_OP_TRUNCATE: u32  = 10;
pub const FS_OP_LSEEK: u32     = 11;

// Offsets within the ring buffer header
pub const OFF_SUBMIT_HEAD: u32   = 0;
pub const OFF_SUBMIT_TAIL: u32   = 4;
pub const OFF_COMPLETE_HEAD: u32 = 8;
pub const OFF_COMPLETE_TAIL: u32 = 12;
pub const OFF_NOTIFY: u32        = 16;
pub const OFF_SQ_BASE: u32      = HEADER_SIZE as u32;
pub const OFF_CQ_BASE: u32      = (HEADER_SIZE + SQ_SIZE * REQ_SIZE) as u32;

/// Submit a FS request to the ring buffer.
/// `ring_base` is the SAB offset where the ring buffer starts.
/// Returns the submission index, or -1 if the queue is full.
///
/// In the current single-instance model, this is a no-op placeholder.
/// The actual Atomics-based submit will be used when thread-worker
/// and kernel Worker are separate WASM instances.
pub fn submit_request(
    ring_base: u32,
    opcode: u32,
    fd: i32,
    offset: u64,
    len: u64,
    buf_ptr: u64,
    path_ptr: u64,
    flags: u32,
    mode: u32,
) -> i32 {
    unsafe {
        use core::sync::atomic::{AtomicU32, Ordering};

        let head_ptr = ring_base as *const AtomicU32;
        let tail_ptr = (ring_base + OFF_SUBMIT_TAIL) as *const AtomicU32;

        let head = (*head_ptr).load(Ordering::Acquire);
        let tail = (*tail_ptr).load(Ordering::Relaxed);

        let used = head.wrapping_sub(tail);
        if used as usize >= SQ_SIZE { return -1; } // full

        let idx = (head as usize) % SQ_SIZE;
        let entry_off = ring_base + OFF_SQ_BASE + (idx as u32) * (REQ_SIZE as u32);
        let p = entry_off as *mut u8;

        // Write request fields
        (p as *mut u32).write(opcode);
        (p.add(4) as *mut i32).write(fd);
        (p.add(8) as *mut u64).write(offset);
        (p.add(16) as *mut u64).write(len);
        (p.add(24) as *mut u64).write(buf_ptr);
        (p.add(32) as *mut u64).write(path_ptr);
        (p.add(40) as *mut u32).write(flags);
        (p.add(44) as *mut u32).write(mode);

        // Advance head
        (*head_ptr).store(head.wrapping_add(1), Ordering::Release);

        idx as i32
    }
}

/// Read a completion from the ring buffer.
/// Returns the result value, or EAGAIN if no completions available.
pub fn read_completion(ring_base: u32) -> i64 {
    unsafe {
        use core::sync::atomic::{AtomicU32, Ordering};

        let head_ptr = (ring_base + OFF_COMPLETE_HEAD) as *const AtomicU32;
        let tail_ptr = (ring_base + OFF_COMPLETE_TAIL) as *const AtomicU32;

        let head = (*head_ptr).load(Ordering::Relaxed);
        let tail = (*tail_ptr).load(Ordering::Acquire);

        if head == tail { return EAGAIN; } // empty

        let idx = (tail as usize) % CQ_SIZE;
        let entry_off = ring_base + OFF_CQ_BASE + (idx as u32) * (RESP_SIZE as u32);
        let result = *((entry_off as *const u8).add(0) as *const i64);

        // Advance tail
        (*((ring_base + OFF_COMPLETE_TAIL) as *const AtomicU32))
            .store(tail.wrapping_add(1), Ordering::Release);

        result
    }
}

/// Process pending FS requests from the submission queue.
/// Called by the kernel Worker (or in single-instance mode, synchronously).
/// Reads requests, dispatches to MemFS, writes completions.
pub fn process_requests(ring_base: u32, vm_ptr: u32) {
    unsafe {
        use core::sync::atomic::{AtomicU32, Ordering};

        let head_ptr = ring_base as *const AtomicU32;
        let tail_ptr = (ring_base + OFF_SUBMIT_TAIL) as *const AtomicU32;
        let cq_head_ptr = (ring_base + OFF_COMPLETE_HEAD) as *const AtomicU32;

        loop {
            let head = (*head_ptr).load(Ordering::Acquire);
            let tail = (*tail_ptr).load(Ordering::Relaxed);
            if head == tail { break; } // no more requests

            let idx = (tail as usize) % SQ_SIZE;
            let entry_off = ring_base + OFF_SQ_BASE + (idx as u32) * (REQ_SIZE as u32);
            let p = entry_off as *const u8;

            let opcode = *(p as *const u32);
            let fd = *(p.add(4) as *const i32);
            let offset = *(p.add(8) as *const u64);
            let len = *(p.add(16) as *const u64);
            let _buf_ptr = *(p.add(24) as *const u64);
            let _path_ptr = *(p.add(32) as *const u64);
            let _flags = *(p.add(40) as *const u32);
            let _mode = *(p.add(44) as *const u32);

            // Dispatch (simplified — full dispatch will use vm_ptr for syscall context)
            let result: i64 = match opcode {
                FS_OP_READ => {
                    let mut tmp = [0u8; 4096];
                    let n = len.min(4096) as usize;
                    crate::fs::memfs::read_file(fd as u32, offset, &mut tmp[..n])
                }
                FS_OP_WRITE => {
                    // Data is at buf_ptr in guest memory — would read from there
                    len as i64 // stub
                }
                _ => ENOSYS,
            };

            // Write completion
            let cq_head = (*cq_head_ptr).load(Ordering::Relaxed);
            let cq_idx = (cq_head as usize) % CQ_SIZE;
            let cq_off = ring_base + OFF_CQ_BASE + (cq_idx as u32) * (RESP_SIZE as u32);
            *((cq_off as *mut u8) as *mut i64) = result;
            (*cq_head_ptr).store(cq_head.wrapping_add(1), Ordering::Release);

            // Advance submit tail
            (*tail_ptr).store(tail.wrapping_add(1), Ordering::Release);
        }

        // Notify waiting thread-worker
        let notify_ptr = (ring_base + OFF_NOTIFY) as *const core::sync::atomic::AtomicI32;
        (*notify_ptr).store(1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_size() {
        // Verify sizes are reasonable
        assert_eq!(HEADER_SIZE, 32);
        assert_eq!(REQ_SIZE, 64);
        assert_eq!(RESP_SIZE, 16);
        assert_eq!(RING_BUFFER_SIZE, 32 + 64 * 64 + 64 * 16); // 5152 bytes
    }
}
