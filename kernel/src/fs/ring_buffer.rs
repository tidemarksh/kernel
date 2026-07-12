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
//!     request_clock: AtomicU32,         // offset 20
//!     cq_lock:       AtomicU32,         // offset 24
//!     sq_lock:       AtomicU32,         // offset 28
//!     sq_entries:    [FsRequest; 64],   // offset 32  — submission queue
//!     cq_entries:    [FsResponse; 64],  // offset 4128 — completion queue
//! };
//!
//! struct FsRequest {                    // 64 bytes total
//!     opcode:  u32,                     // offset 0
//!     fd:      i32,                     // offset 4
//!     offset:  u64,                     // offset 8    — generic arg (e.g. rename newdirfd)
//!     len:     u64,                     // offset 16
//!     buf_ptr: u64,                     // offset 24   — generic arg (e.g. rename newpath_ptr)
//!     path_ptr:u64,                     // offset 32   — primary path pointer
//!     flags:   u32,                     // offset 40
//!     mode:    u32,                     // offset 44
//!     vm_ptr:  u32,                     // offset 48   — owning ThreadState
//!     ofd_id:  u32,                     // offset 52   — submitting fd's OFD id
//!     ino:     u32,                     // offset 56   — submitting fd's inode
//!     request_id: u32,                  // offset 60   — ring-local request identity
//! };
//!
//! struct FsResponse {                   // 16 bytes total
//!     result:  i64,                     // offset 0
//!     vm_ptr:  u32,                     // offset 8    — owning ThreadState
//!     request_id: u32,                  // offset 12   — completed request identity
//! };

use crate::abi::*;

pub const SQ_SIZE: usize = 64;
pub const CQ_SIZE: usize = 64;
pub const REQ_SIZE: usize = 64;
pub const RESP_SIZE: usize = 16;
pub const HEADER_SIZE: usize = 32;
pub const RING_BUFFER_SIZE: usize = HEADER_SIZE + SQ_SIZE * REQ_SIZE + CQ_SIZE * RESP_SIZE;

// FS operation codes
pub const FS_OP_READ: u32 = 1;
pub const FS_OP_WRITE: u32 = 2;
pub const FS_OP_OPENAT: u32 = 3;
pub const FS_OP_CLOSE: u32 = 4;
pub const FS_OP_FSTAT: u32 = 5;
pub const FS_OP_MKDIR: u32 = 6;
pub const FS_OP_UNLINK: u32 = 7;
pub const FS_OP_RENAME: u32 = 8;
pub const FS_OP_GETDENTS: u32 = 9;
pub const FS_OP_TRUNCATE: u32 = 10;
pub const FS_OP_LSEEK: u32 = 11;
pub const FS_OP_MMAP: u32 = 12;
pub const FS_OP_EXECVE: u32 = 13;
pub const FS_OP_FSYNC: u32 = 14;
pub const FS_REQ_FLAG_PWRITE: u32 = 1 << 0;
pub const FS_REQ_FLAG_WRITEV: u32 = 1 << 1;

// Offsets within the ring buffer header
pub const OFF_SUBMIT_HEAD: u32 = 0;
pub const OFF_SUBMIT_TAIL: u32 = 4;
pub const OFF_COMPLETE_HEAD: u32 = 8;
pub const OFF_COMPLETE_TAIL: u32 = 12;
pub const OFF_NOTIFY: u32 = 16;
pub const OFF_REQUEST_CLOCK: u32 = 20;
pub const OFF_CQ_LOCK: u32 = 24;
pub const OFF_SQ_LOCK: u32 = 28;
pub const OFF_SQ_BASE: u32 = HEADER_SIZE as u32;
pub const OFF_CQ_BASE: u32 = (HEADER_SIZE + SQ_SIZE * REQ_SIZE) as u32;

pub fn ring_backed(ring_base: u32) -> bool {
    if ring_base == 0 {
        return false;
    }
    let Some(end) = (ring_base as u64).checked_add(RING_BUFFER_SIZE as u64) else {
        return false;
    };
    end <= crate::wasm::memory_size_bytes()
}

pub fn reset(ring_base: u32) {
    if !ring_backed(ring_base) {
        return;
    }
    unsafe {
        use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

        (*(ring_base as *const AtomicU32)).store(0, Ordering::Release);
        (*((ring_base + OFF_SUBMIT_TAIL) as *const AtomicU32)).store(0, Ordering::Release);
        (*((ring_base + OFF_COMPLETE_HEAD) as *const AtomicU32)).store(0, Ordering::Release);
        (*((ring_base + OFF_COMPLETE_TAIL) as *const AtomicU32)).store(0, Ordering::Release);
        (*((ring_base + OFF_NOTIFY) as *const AtomicI32)).store(0, Ordering::Release);
        (*((ring_base + OFF_REQUEST_CLOCK) as *const AtomicU32)).store(0, Ordering::Release);
        (*((ring_base + OFF_CQ_LOCK) as *const AtomicU32)).store(0, Ordering::Release);
        (*((ring_base + OFF_SQ_LOCK) as *const AtomicU32)).store(0, Ordering::Release);
    }
}

struct RingLockGuard(*const core::sync::atomic::AtomicU32);

impl Drop for RingLockGuard {
    fn drop(&mut self) {
        unsafe {
            (*self.0).store(0, core::sync::atomic::Ordering::Release);
        }
    }
}

unsafe fn try_ring_lock(ring_base: u32, offset: u32) -> Option<RingLockGuard> {
    use core::sync::atomic::{AtomicU32, Ordering};

    let lock = (ring_base + offset) as *const AtomicU32;
    unsafe {
        (*lock)
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| RingLockGuard(lock))
    }
}

#[derive(Clone, Copy)]
pub struct FsRequestInfo {
    pub opcode: u32,
    pub fd: i32,
    pub offset: u64,
    pub len: u64,
    pub buf_ptr: u64,
    pub path_ptr: u64,
    pub flags: u32,
    pub mode: u32,
    pub vm_ptr: u32,
    pub ofd_id: u32,
    pub ino: u32,
    pub request_id: u32,
}

/// Submit a FS request to the ring buffer.
/// `ring_base` is the SAB offset where the ring buffer starts.
/// Returns the submission index, or -1 if the queue is full.
///
/// This updates the shared submission ring in place via atomics.
/// The same path is used both in today's single-instance mode and when
/// thread-worker and kernel Worker live in separate WASM instances.
#[allow(clippy::too_many_arguments)]
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
    vm_ptr: u32,
    ofd_id: u32,
    ino: u32,
) -> i32 {
    unsafe {
        use core::sync::atomic::{AtomicU32, Ordering};

        let Some(_sq_guard) = try_ring_lock(ring_base, OFF_SQ_LOCK) else {
            return -1;
        };

        let head_ptr = ring_base as *const AtomicU32;
        let tail_ptr = (ring_base + OFF_SUBMIT_TAIL) as *const AtomicU32;

        let head = (*head_ptr).load(Ordering::Acquire);
        let tail = (*tail_ptr).load(Ordering::Relaxed);

        let used = head.wrapping_sub(tail);
        if used as usize >= SQ_SIZE {
            return -1;
        } // full

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
        (p.add(48) as *mut u32).write(vm_ptr);
        (p.add(52) as *mut u32).write(ofd_id);
        (p.add(56) as *mut u32).write(ino);
        let clock_ptr = (ring_base + OFF_REQUEST_CLOCK) as *const AtomicU32;
        let mut request_id = (*clock_ptr).fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        if request_id == 0 {
            request_id = (*clock_ptr).fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        }
        (p.add(60) as *mut u32).write(request_id);

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

        let Some(_cq_guard) = try_ring_lock(ring_base, OFF_CQ_LOCK) else {
            return EAGAIN;
        };

        let head_ptr = (ring_base + OFF_COMPLETE_HEAD) as *const AtomicU32;
        let tail_ptr = (ring_base + OFF_COMPLETE_TAIL) as *const AtomicU32;

        let head = (*head_ptr).load(Ordering::Relaxed);
        let tail = (*tail_ptr).load(Ordering::Acquire);

        if head == tail {
            return EAGAIN;
        } // empty

        let idx = (tail as usize) % CQ_SIZE;
        let entry_off = ring_base + OFF_CQ_BASE + (idx as u32) * (RESP_SIZE as u32);
        let result = *((entry_off as *const u8).add(0) as *const i64);

        // Advance tail
        (*((ring_base + OFF_COMPLETE_TAIL) as *const AtomicU32))
            .store(tail.wrapping_add(1), Ordering::Release);

        result
    }
}

pub fn read_completion_for_vm(ring_base: u32, vm_ptr: u32) -> Option<i64> {
    unsafe {
        use core::sync::atomic::{AtomicU32, Ordering};

        let _cq_guard = try_ring_lock(ring_base, OFF_CQ_LOCK)?;

        let head_ptr = (ring_base + OFF_COMPLETE_HEAD) as *const AtomicU32;
        let tail_ptr = (ring_base + OFF_COMPLETE_TAIL) as *const AtomicU32;

        let head = (*head_ptr).load(Ordering::Relaxed);
        let tail = (*tail_ptr).load(Ordering::Acquire);
        if head == tail {
            return None;
        }

        let request_id = (*(vm_ptr as *const crate::types::ThreadState)).pending_fs_request_id;
        if request_id == 0 {
            return None;
        }
        let mut result = None;
        for pos in tail..head {
            let idx = (pos as usize) % CQ_SIZE;
            let entry_off = ring_base + OFF_CQ_BASE + (idx as u32) * (RESP_SIZE as u32);
            let entry_vm_ptr = *((entry_off as *const u8).add(8) as *const u32);
            let entry_request_id = *((entry_off as *const u8).add(12) as *const u32);
            if entry_vm_ptr == vm_ptr && entry_request_id == request_id {
                result = Some(*((entry_off as *const u8).add(0) as *const i64));
            }
        }

        let Some(result) = result else {
            return None;
        };

        let mut write_pos = tail;
        for pos in tail..head {
            let src_idx = (pos as usize) % CQ_SIZE;
            let src_off = ring_base + OFF_CQ_BASE + (src_idx as u32) * (RESP_SIZE as u32);
            let entry_vm_ptr = *((src_off as *const u8).add(8) as *const u32);
            let entry_request_id = *((src_off as *const u8).add(12) as *const u32);
            if entry_vm_ptr == vm_ptr && entry_request_id == request_id {
                continue;
            }
            let dst_idx = (write_pos as usize) % CQ_SIZE;
            let dst_off = ring_base + OFF_CQ_BASE + (dst_idx as u32) * (RESP_SIZE as u32);
            if dst_off != src_off {
                core::ptr::copy(src_off as *const u8, dst_off as *mut u8, RESP_SIZE);
            }
            write_pos = write_pos.wrapping_add(1);
        }

        (*head_ptr).store(write_pos, Ordering::Release);
        Some(result)
    }
}

/// Peek the next queued request without consuming it.
/// Returns `(opcode, flags)` or `None` when the submission queue is empty.
pub fn peek_request(ring_base: u32) -> Option<(u32, u32)> {
    peek_request_info(ring_base).map(|request| (request.opcode, request.flags))
}

/// Peek the next queued request without consuming it.
pub fn peek_request_info(ring_base: u32) -> Option<FsRequestInfo> {
    unsafe {
        use core::sync::atomic::{AtomicU32, Ordering};

        let head_ptr = ring_base as *const AtomicU32;
        let tail_ptr = (ring_base + OFF_SUBMIT_TAIL) as *const AtomicU32;

        let head = (*head_ptr).load(Ordering::Acquire);
        let tail = (*tail_ptr).load(Ordering::Relaxed);
        if head == tail {
            return None;
        }

        let idx = (tail as usize) % SQ_SIZE;
        let entry_off = ring_base + OFF_SQ_BASE + (idx as u32) * (REQ_SIZE as u32);
        let p = entry_off as *const u8;
        Some(FsRequestInfo {
            opcode: *(p as *const u32),
            fd: *(p.add(4) as *const i32),
            offset: *(p.add(8) as *const u64),
            len: *(p.add(16) as *const u64),
            buf_ptr: *(p.add(24) as *const u64),
            path_ptr: *(p.add(32) as *const u64),
            flags: *(p.add(40) as *const u32),
            mode: *(p.add(44) as *const u32),
            vm_ptr: *(p.add(48) as *const u32),
            ofd_id: *(p.add(52) as *const u32),
            ino: *(p.add(56) as *const u32),
            request_id: *(p.add(60) as *const u32),
        })
    }
}

pub fn peek_request_info_for_vm(ring_base: u32, vm_ptr: u32) -> Option<FsRequestInfo> {
    unsafe {
        use core::sync::atomic::{AtomicU32, Ordering};

        let head_ptr = ring_base as *const AtomicU32;
        let tail_ptr = (ring_base + OFF_SUBMIT_TAIL) as *const AtomicU32;

        let head = (*head_ptr).load(Ordering::Acquire);
        let tail = (*tail_ptr).load(Ordering::Relaxed);
        if head == tail {
            return None;
        }

        for pos in tail..head {
            let idx = (pos as usize) % SQ_SIZE;
            let entry_off = ring_base + OFF_SQ_BASE + (idx as u32) * (REQ_SIZE as u32);
            let p = entry_off as *const u8;
            let request = FsRequestInfo {
                opcode: *(p as *const u32),
                fd: *(p.add(4) as *const i32),
                offset: *(p.add(8) as *const u64),
                len: *(p.add(16) as *const u64),
                buf_ptr: *(p.add(24) as *const u64),
                path_ptr: *(p.add(32) as *const u64),
                flags: *(p.add(40) as *const u32),
                mode: *(p.add(44) as *const u32),
                vm_ptr: *(p.add(48) as *const u32),
                ofd_id: *(p.add(52) as *const u32),
                ino: *(p.add(56) as *const u32),
                request_id: *(p.add(60) as *const u32),
            };
            if request.vm_ptr == vm_ptr {
                return Some(request);
            }
        }

        None
    }
}

pub fn has_pending_request_for_vm(ring_base: u32, vm_ptr: u32) -> bool {
    peek_request_info_for_vm(ring_base, vm_ptr).is_some()
}

/// Process pending FS requests from the submission queue.
/// Called by the kernel Worker (or in single-instance mode, synchronously).
/// Reads requests, dispatches to MemFS, writes completions.
pub fn process_requests(ring_base: u32, vm_ptr: u32, base: u32) {
    unsafe {
        use core::sync::atomic::{AtomicU32, Ordering};

        let head_ptr = ring_base as *const AtomicU32;
        let tail_ptr = (ring_base + OFF_SUBMIT_TAIL) as *const AtomicU32;
        let cq_head_ptr = (ring_base + OFF_COMPLETE_HEAD) as *const AtomicU32;

        loop {
            let head = (*head_ptr).load(Ordering::Acquire);
            let tail = (*tail_ptr).load(Ordering::Relaxed);
            if head == tail {
                break;
            } // no more requests

            let Some(_cq_guard) = try_ring_lock(ring_base, OFF_CQ_LOCK) else {
                break;
            };

            let cq_head = (*cq_head_ptr).load(Ordering::Relaxed);
            let cq_tail =
                (*((ring_base + OFF_COMPLETE_TAIL) as *const AtomicU32)).load(Ordering::Acquire);
            if cq_head.wrapping_sub(cq_tail) as usize >= CQ_SIZE {
                break;
            }

            let idx = (tail as usize) % SQ_SIZE;
            let entry_off = ring_base + OFF_SQ_BASE + (idx as u32) * (REQ_SIZE as u32);
            let p = entry_off as *const u8;

            let opcode = *(p as *const u32);
            let fd = *(p.add(4) as *const i32);
            let offset = *(p.add(8) as *const u64);
            let len = *(p.add(16) as *const u64);
            let buf_ptr = *(p.add(24) as *const u64);
            let path_ptr = *(p.add(32) as *const u64);
            let flags = *(p.add(40) as *const u32);
            let mode = *(p.add(44) as *const u32);
            let request_ofd_id = *(p.add(52) as *const u32);
            let request_ino = *(p.add(56) as *const u32);
            let request_id = *(p.add(60) as *const u32);

            let request_vm_ptr = *(p.add(48) as *const u32);
            let target_vm_ptr = if request_vm_ptr != 0 {
                request_vm_ptr
            } else {
                vm_ptr
            };
            let vm = &mut *(target_vm_ptr as *mut crate::types::ThreadState);

            let result: i64 = match opcode {
                FS_OP_READ => crate::syscall::fs::complete_submitted_regular_file_read(
                    vm,
                    base,
                    fd as u64,
                    buf_ptr,
                    len,
                    offset,
                    flags & FS_REQ_FLAG_PWRITE != 0,
                    request_ofd_id,
                    request_ino,
                ),
                FS_OP_WRITE => crate::syscall::fs::complete_submitted_regular_file_write(
                    vm,
                    base,
                    fd as u64,
                    buf_ptr,
                    len,
                    offset,
                    flags & FS_REQ_FLAG_PWRITE != 0,
                    flags & FS_REQ_FLAG_WRITEV != 0,
                    request_ofd_id,
                    request_ino,
                ),
                FS_OP_OPENAT => {
                    if path_ptr == 0 {
                        EINVAL
                    } else {
                        crate::syscall::fs::sys_openat(
                            vm,
                            base,
                            fd as u64, // dirfd
                            path_ptr,  // path address in guest memory
                            flags as u64,
                            mode as u64,
                        )
                    }
                }
                FS_OP_CLOSE => crate::fs::fd_table::sys_close(vm, base, fd as u64),
                FS_OP_FSTAT => {
                    if buf_ptr == 0 {
                        EINVAL
                    } else {
                        crate::syscall::fs::sys_fstat(vm, base, fd as u64, buf_ptr)
                    }
                }
                FS_OP_MKDIR => {
                    if path_ptr == 0 {
                        EINVAL
                    } else {
                        crate::syscall::fs::sys_mkdirat(vm, base, fd as u64, path_ptr, mode as u64)
                    }
                }
                FS_OP_UNLINK => {
                    if path_ptr == 0 {
                        EINVAL
                    } else {
                        crate::syscall::fs::sys_unlinkat(
                            vm,
                            base,
                            fd as u64,
                            path_ptr,
                            flags as u64,
                        )
                    }
                }
                FS_OP_RENAME => {
                    if path_ptr == 0 || buf_ptr == 0 {
                        EINVAL
                    } else {
                        crate::syscall::fs::sys_renameat2(
                            vm,
                            base,
                            fd as u64,
                            path_ptr,
                            offset,
                            buf_ptr,
                            flags as u64,
                        )
                    }
                }
                FS_OP_GETDENTS => {
                    if buf_ptr == 0 {
                        EINVAL
                    } else {
                        crate::syscall::fs::complete_submitted_getdents64(
                            vm,
                            base,
                            fd as u64,
                            buf_ptr,
                            len,
                            offset,
                            request_ofd_id,
                            request_ino,
                        )
                    }
                }
                FS_OP_TRUNCATE => {
                    if path_ptr != 0 {
                        crate::syscall::fs::sys_truncate(vm, base, path_ptr, offset)
                    } else {
                        crate::syscall::fs::complete_submitted_ftruncate(
                            vm,
                            base,
                            fd as u64,
                            offset,
                            request_ino,
                        )
                    }
                }
                FS_OP_LSEEK => {
                    crate::syscall::fs::sys_lseek(
                        vm,
                        base,
                        fd as u64,
                        offset as i64,
                        flags as u64, // whence
                    )
                }
                FS_OP_MMAP => crate::syscall::memory::sys_mmap(
                    vm,
                    base,
                    buf_ptr,
                    len,
                    mode as u64,
                    flags as u64,
                    fd as i64,
                    offset,
                ),
                FS_OP_EXECVE => {
                    if path_ptr == 0 {
                        EINVAL
                    } else {
                        crate::syscall::process::sys_execve(vm, base, path_ptr, buf_ptr, offset)
                    }
                }
                FS_OP_FSYNC => crate::syscall::fs::sys_fsync(vm, base, fd as u64),
                _ => ENOSYS,
            };

            if opcode == FS_OP_EXECVE
                && result == EAGAIN
                && crate::syscall::process::execve_backing_miss_len(target_vm_ptr) != 0
            {
                vm.status = STATUS_FS;
                break;
            }
            if opcode == FS_OP_EXECVE {
                crate::syscall::process::clear_execve_backing_state(target_vm_ptr);
            }

            // Write completion
            let cq_idx = (cq_head as usize) % CQ_SIZE;
            let cq_off = ring_base + OFF_CQ_BASE + (cq_idx as u32) * (RESP_SIZE as u32);
            *((cq_off as *mut u8) as *mut i64) = result;
            *((cq_off as *mut u8).add(8) as *mut u32) = target_vm_ptr;
            *((cq_off as *mut u8).add(12) as *mut u32) = request_id;
            (*cq_head_ptr).store(cq_head.wrapping_add(1), Ordering::Release);

            // Advance submit tail
            (*tail_ptr).store(tail.wrapping_add(1), Ordering::Release);
            if target_vm_ptr == vm_ptr {
                break;
            }
        }

        // Notify waiting thread-worker
        let notify_ptr = (ring_base + OFF_NOTIFY) as *const core::sync::atomic::AtomicI32;
        (*notify_ptr).store(1, Ordering::Release);
    }
}
