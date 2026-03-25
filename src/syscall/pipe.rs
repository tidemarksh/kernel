//! Pipe and eventfd syscalls.
//!
//! Pipe slot layout (per the design, later migrated to SAB page cache):
//!
//! struct PipeSlot {                     // 4128 bytes total
//!     head:       u32,                  // offset 0   (read position)
//!     tail:       u32,                  // offset 4   (write position)
//!     read_open:  i32,                  // offset 8   (reader refcount, 0 = EPIPE)
//!     write_open: i32,                  // offset 12  (writer refcount, 0 = EOF)
//!     notify:     i32,                  // offset 16  (Atomics.wait/notify target)
//!     _pad:       [u8; 12],             // offset 20
//!     data:       [u8; PIPE_BUF_SIZE],  // offset 32
//! };

use crate::abi::*;
use crate::alloc;
use crate::guest_mem;
use crate::fs::fd_table;
use crate::types::ThreadState;

const PIPE_BUF_SIZE: u32 = 4096;
const PIPE_SLOT_SIZE: u32 = 32 + PIPE_BUF_SIZE;

#[repr(C)]
struct PipeSlot {
    head: u32,
    tail: u32,
    read_open: i32,
    write_open: i32,
    notify: i32,
    _pad: [u8; 12],
    data: [u8; PIPE_BUF_SIZE as usize],
}

/// Pipe table: pointers to PipeSlots allocated via alloc.rs.
static mut PIPE_PTRS: [*mut PipeSlot; MAX_PIPES] = [core::ptr::null_mut(); MAX_PIPES];

fn pipe_ptr(idx: usize) -> *mut PipeSlot {
    unsafe { core::ptr::read((core::ptr::addr_of!(PIPE_PTRS) as *const *mut PipeSlot).add(idx)) }
}

fn set_pipe_ptr(idx: usize, val: *mut PipeSlot) {
    unsafe { core::ptr::write((core::ptr::addr_of_mut!(PIPE_PTRS) as *mut *mut PipeSlot).add(idx), val); }
}

fn alloc_pipe_slot() -> Option<(usize, *mut PipeSlot)> {
    for i in 0..MAX_PIPES {
        if pipe_ptr(i).is_null() {
            unsafe {
                let ptr = alloc::alloc_zeroed(PIPE_SLOT_SIZE, 8);
                if ptr == 0 { return None; }
                let slot = ptr as *mut PipeSlot;
                (*slot).read_open = 1;
                (*slot).write_open = 1;
                set_pipe_ptr(i, slot);
                return Some((i, slot));
            }
        }
    }
    None
}

// =========================================================================
// pipe2
// =========================================================================

pub fn sys_pipe2(vm: &mut ThreadState, base: u32, pipefd_addr: u64, flags: u64) -> i64 {
    let (pipe_idx, _slot) = match alloc_pipe_slot() {
        Some(v) => v,
        None => return ENOMEM,
    };

    let read_fd = fd_table::open_pipe(vm, base, pipe_idx as u32, true, flags as i32);
    if read_fd < 0 { return read_fd; }

    let write_fd = fd_table::open_pipe(vm, base, pipe_idx as u32, false, flags as i32);
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
// Pipe read/write
// =========================================================================

pub fn pipe_read(pipe_idx: u32, buf: &mut [u8]) -> i64 {
    let slot = unsafe { &mut *pipe_ptr(pipe_idx as usize) };
    let head = slot.head;
    let tail = slot.tail;

    if head == tail {
        if slot.write_open <= 0 { return 0; } // EOF
        return EAGAIN;
    }

    let available = if tail >= head {
        (tail - head) as usize
    } else {
        (PIPE_BUF_SIZE - head + tail) as usize
    };
    let to_read = buf.len().min(available);
    let h = head as usize;
    let cap = PIPE_BUF_SIZE as usize;

    for i in 0..to_read {
        buf[i] = slot.data[(h + i) % cap];
    }
    slot.head = ((h + to_read) % cap) as u32;
    to_read as i64
}

pub fn pipe_write(pipe_idx: u32, data: &[u8]) -> i64 {
    let slot = unsafe { &mut *pipe_ptr(pipe_idx as usize) };

    if slot.read_open <= 0 { return EPIPE; }

    let head = slot.head as usize;
    let tail = slot.tail as usize;
    let cap = PIPE_BUF_SIZE as usize;

    let used = if tail >= head { tail - head } else { cap - head + tail };
    let free = cap - 1 - used;
    if free == 0 { return EAGAIN; }

    let to_write = data.len().min(free);
    for i in 0..to_write {
        slot.data[(tail + i) % cap] = data[i];
    }
    slot.tail = ((tail + to_write) % cap) as u32;
    to_write as i64
}

pub fn pipe_close(pipe_idx: u32, is_read_end: bool) {
    let idx = pipe_idx as usize;
    if idx >= MAX_PIPES || pipe_ptr(idx).is_null() { return; }
    let slot = unsafe { &mut *pipe_ptr(idx) };

    if is_read_end {
        slot.read_open -= 1;
    } else {
        slot.write_open -= 1;
    }

    if slot.read_open <= 0 && slot.write_open <= 0 {
        set_pipe_ptr(idx, core::ptr::null_mut());
    }
}

// =========================================================================
// eventfd2
// =========================================================================

pub fn sys_eventfd2(_vm: &mut ThreadState, _base: u32, _initval: u64, _flags: u64) -> i64 {
    ENOSYS // not yet implemented
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
            for i in 0..MAX_PIPES {
                set_pipe_ptr(i, core::ptr::null_mut());
            }
        }
    }

    #[test]
    fn write_read_roundtrip() {
        setup();
        let (idx, _) = alloc_pipe_slot().unwrap();
        assert_eq!(pipe_write(idx as u32, b"hello pipe"), 10);
        let mut buf = [0u8; 32];
        assert_eq!(pipe_read(idx as u32, &mut buf), 10);
        assert_eq!(&buf[..10], b"hello pipe");
    }

    #[test]
    fn eof_on_writer_close() {
        setup();
        let (idx, _) = alloc_pipe_slot().unwrap();
        pipe_close(idx as u32, false);
        let mut buf = [0u8; 16];
        assert_eq!(pipe_read(idx as u32, &mut buf), 0);
    }

    #[test]
    fn epipe_on_reader_close() {
        setup();
        let (idx, _) = alloc_pipe_slot().unwrap();
        pipe_close(idx as u32, true);
        assert_eq!(pipe_write(idx as u32, b"data"), EPIPE);
    }

    #[test]
    fn circular_wrap() {
        setup();
        let (idx, _) = alloc_pipe_slot().unwrap();
        let big = [0xABu8; 4000];
        assert_eq!(pipe_write(idx as u32, &big), 4000);
        let mut tmp = [0u8; 3000];
        assert_eq!(pipe_read(idx as u32, &mut tmp), 3000);
        let w2 = pipe_write(idx as u32, &big[..3000]);
        assert!(w2 > 0);
        let mut out = [0u8; 4095];
        let r2 = pipe_read(idx as u32, &mut out);
        assert!(r2 > 0);
    }
}
