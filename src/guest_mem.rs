//! Guest memory access with unsafe concentrated here.
//!
//! All guest memory reads/writes go through this module.
//! Seqlock: when thread_count > 1, stores bump a generation counter
//! for LR/SC reservation invalidation. When thread_count == 1, plain writes.

use core::sync::atomic::{AtomicU32, Ordering};

/// Reservation table pointers (set once during process init).
static mut RESERVATION_GEN: *const AtomicU32 = core::ptr::null();
/// Pointer to thread_count in ProcessState. null = single-thread (skip seqlock).
static mut THREAD_COUNT: *const AtomicU32 = core::ptr::null();

/// Initialize reservation table pointers.
///
/// # Safety
/// Must be called once before any guest memory access.
pub unsafe fn init(reservation_gen: *const AtomicU32, thread_count: *const AtomicU32) {
    unsafe {
        RESERVATION_GEN = reservation_gen;
        THREAD_COUNT = thread_count;
    }
}

#[inline(always)]
unsafe fn is_multi_threaded() -> bool {
    let p = unsafe { THREAD_COUNT };
    !p.is_null() && unsafe { (*p).load(Ordering::Relaxed) } > 1
}

// ---------------------------------------------------------------------------
// Reads — no locking needed
// ---------------------------------------------------------------------------

#[inline(always)]
pub unsafe fn read_u8(base: u32, addr: u64) -> u8 {
    unsafe { *((base + addr as u32) as *const u8) }
}

#[inline(always)]
pub unsafe fn read_u16(base: u32, addr: u64) -> u16 {
    unsafe { ((base + addr as u32) as *const u16).read_unaligned() }
}

#[inline(always)]
pub unsafe fn read_u32(base: u32, addr: u64) -> u32 {
    let ptr = (base + addr as u32) as usize;
    if (ptr & 3) == 0 {
        unsafe { (*(ptr as *const AtomicU32)).load(Ordering::Relaxed) }
    } else {
        unsafe { (ptr as *const u32).read_unaligned() }
    }
}

#[inline(always)]
pub unsafe fn read_u64(base: u32, addr: u64) -> u64 {
    let ptr = (base + addr as u32) as usize;
    if (ptr & 7) == 0 {
        unsafe { (*(ptr as *const core::sync::atomic::AtomicU64)).load(Ordering::Relaxed) }
    } else {
        unsafe { (ptr as *const u64).read_unaligned() }
    }
}

#[inline(always)]
pub unsafe fn read_i8(base: u32, addr: u64) -> i8 { (unsafe { read_u8(base, addr) }) as i8 }
#[inline(always)]
pub unsafe fn read_i16(base: u32, addr: u64) -> i16 { (unsafe { read_u16(base, addr) }) as i16 }
#[inline(always)]
pub unsafe fn read_i32(base: u32, addr: u64) -> i32 { (unsafe { read_u32(base, addr) }) as i32 }
#[inline(always)]
pub unsafe fn read_i64(base: u32, addr: u64) -> i64 { (unsafe { read_u64(base, addr) }) as i64 }

pub unsafe fn read_bytes(base: u32, addr: u64, buf: &mut [u8]) {
    let src = (base + addr as u32) as *const u8;
    unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len()) };
}

// ---------------------------------------------------------------------------
// Writes — seqlock when multi-threaded, plain when single-threaded
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn bump_gen(slot: usize) {
    let p = unsafe { RESERVATION_GEN };
    if !p.is_null() {
        unsafe { (*p.add(slot)).fetch_add(1, Ordering::SeqCst) };
    }
}

#[inline(always)]
pub unsafe fn write_u8(base: u32, addr: u64, val: u8) {
    unsafe { *((base + addr as u32) as *mut u8) = val };
    if unsafe { is_multi_threaded() } {
        unsafe { bump_gen(((addr >> 3) & 63) as usize) };
    }
}

#[inline(always)]
pub unsafe fn write_u16(base: u32, addr: u64, val: u16) {
    unsafe { ((base + addr as u32) as *mut u16).write_unaligned(val) };
    if unsafe { is_multi_threaded() } {
        unsafe { bump_gen(((addr >> 3) & 63) as usize) };
    }
}

#[inline(always)]
pub unsafe fn write_u32(base: u32, addr: u64, val: u32) {
    let ptr = (base + addr as u32) as usize;
    if (ptr & 3) == 0 {
        unsafe { (*(ptr as *const AtomicU32)).store(val, Ordering::Relaxed) };
    } else {
        unsafe { (ptr as *mut u32).write_unaligned(val) };
    }
    if unsafe { is_multi_threaded() } {
        unsafe { bump_gen(((addr >> 3) & 63) as usize) };
    }
}

#[inline(always)]
pub unsafe fn write_u64(base: u32, addr: u64, val: u64) {
    let ptr = (base + addr as u32) as usize;
    if (ptr & 7) == 0 {
        unsafe { (*(ptr as *const core::sync::atomic::AtomicU64)).store(val, Ordering::Relaxed) };
    } else {
        unsafe { (ptr as *mut u64).write_unaligned(val) };
    }
    if unsafe { is_multi_threaded() } {
        unsafe { bump_gen(((addr >> 3) & 63) as usize) };
    }
}

pub unsafe fn write_bytes(base: u32, addr: u64, data: &[u8]) {
    let dst = (base + addr as u32) as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
}

pub unsafe fn zero_mem(base: u32, addr: u64, len: usize) {
    let dst = (base + addr as u32) as *mut u8;
    unsafe { core::ptr::write_bytes(dst, 0, len) };
}

/// Read null-terminated string from guest memory. Returns length (excluding null).
pub unsafe fn read_cstr(base: u32, addr: u64, buf: &mut [u8]) -> usize {
    let src = (base + addr as u32) as *const u8;
    let max = buf.len() - 1;
    let mut i = 0;
    while i < max {
        let b = unsafe { src.add(i).read() };
        if b == 0 { break; }
        buf[i] = b;
        i += 1;
    }
    buf[i] = 0;
    i
}

// Note: Atomics.wait/notify are handled by the JS runtime layer (thread-worker.ts),
// not by Rust. Futex wake/wait go through STATUS codes.
