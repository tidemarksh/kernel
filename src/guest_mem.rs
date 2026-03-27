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
// Reads — plain reads for single-threaded, seqlock-guarded reads available
// ---------------------------------------------------------------------------

/// Read a u32 with seqlock protection. Checks generation slot before and after
/// the read; retries if the slot was bumped (indicates concurrent write).
/// Returns the read value. For single-threaded execution, skips the check.
#[inline(always)]
pub unsafe fn read_u32_seqlock(base: u32, addr: u64) -> u32 {
    if !unsafe { is_multi_threaded() } {
        return unsafe { read_u32(base, addr) };
    }
    let slot = ((addr >> 3) & 63) as usize;
    loop {
        let gen_before = unsafe { read_gen(slot) };
        if gen_before & 1 != 0 {
            core::hint::spin_loop();
            continue;
        } // odd = write in progress
        let val = unsafe { read_u32(base, addr) };
        let gen_after = unsafe { read_gen(slot) };
        if gen_before == gen_after {
            return val;
        }
    }
}

/// Read a u64 with seqlock protection.
#[inline(always)]
pub unsafe fn read_u64_seqlock(base: u32, addr: u64) -> u64 {
    if !unsafe { is_multi_threaded() } {
        return unsafe { read_u64(base, addr) };
    }
    let slot = ((addr >> 3) & 63) as usize;
    loop {
        let gen_before = unsafe { read_gen(slot) };
        if gen_before & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let val = unsafe { read_u64(base, addr) };
        let gen_after = unsafe { read_gen(slot) };
        if gen_before == gen_after {
            return val;
        }
    }
}

#[inline(always)]
unsafe fn read_gen(slot: usize) -> u32 {
    let p = unsafe { RESERVATION_GEN };
    if p.is_null() {
        return 0;
    }
    unsafe { (*p.add(slot)).load(Ordering::Acquire) }
}

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
pub unsafe fn read_i8(base: u32, addr: u64) -> i8 {
    (unsafe { read_u8(base, addr) }) as i8
}
#[inline(always)]
pub unsafe fn read_i16(base: u32, addr: u64) -> i16 {
    (unsafe { read_u16(base, addr) }) as i16
}
#[inline(always)]
pub unsafe fn read_i32(base: u32, addr: u64) -> i32 {
    (unsafe { read_u32(base, addr) }) as i32
}
#[inline(always)]
pub unsafe fn read_i64(base: u32, addr: u64) -> i64 {
    (unsafe { read_u64(base, addr) }) as i64
}

pub unsafe fn read_bytes(base: u32, addr: u64, buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    let src = (base + addr as u32) as *const u8;
    debug_assert!(
        !src.is_null(),
        "guest_mem::read_bytes null src: base=0x{base:x} addr=0x{addr:x} len={}",
        buf.len()
    );
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
    if unsafe { is_multi_threaded() } {
        let slot = ((addr >> 3) & 63) as usize;
        unsafe { bump_gen(slot) }; // odd  → write-in-progress
        unsafe { *((base + addr as u32) as *mut u8) = val };
        unsafe { bump_gen(slot) }; // even → write-complete
    } else {
        unsafe { *((base + addr as u32) as *mut u8) = val };
    }
}

#[inline(always)]
pub unsafe fn write_u16(base: u32, addr: u64, val: u16) {
    if unsafe { is_multi_threaded() } {
        let slot = ((addr >> 3) & 63) as usize;
        unsafe { bump_gen(slot) }; // odd  → write-in-progress
        unsafe { ((base + addr as u32) as *mut u16).write_unaligned(val) };
        unsafe { bump_gen(slot) }; // even → write-complete
    } else {
        unsafe { ((base + addr as u32) as *mut u16).write_unaligned(val) };
    }
}

#[inline(always)]
pub unsafe fn write_u32(base: u32, addr: u64, val: u32) {
    let ptr = (base + addr as u32) as usize;
    if unsafe { is_multi_threaded() } {
        let slot = ((addr >> 3) & 63) as usize;
        unsafe { bump_gen(slot) }; // odd  → write-in-progress
        if (ptr & 3) == 0 {
            unsafe { (*(ptr as *const AtomicU32)).store(val, Ordering::Relaxed) };
        } else {
            unsafe { (ptr as *mut u32).write_unaligned(val) };
        }
        unsafe { bump_gen(slot) }; // even → write-complete
    } else {
        if (ptr & 3) == 0 {
            unsafe { (*(ptr as *const AtomicU32)).store(val, Ordering::Relaxed) };
        } else {
            unsafe { (ptr as *mut u32).write_unaligned(val) };
        }
    }
}

#[inline(always)]
pub unsafe fn write_u64(base: u32, addr: u64, val: u64) {
    let ptr = (base + addr as u32) as usize;
    if unsafe { is_multi_threaded() } {
        let slot = ((addr >> 3) & 63) as usize;
        unsafe { bump_gen(slot) }; // odd  → write-in-progress
        if (ptr & 7) == 0 {
            unsafe {
                (*(ptr as *const core::sync::atomic::AtomicU64)).store(val, Ordering::Relaxed)
            };
        } else {
            unsafe { (ptr as *mut u64).write_unaligned(val) };
        }
        unsafe { bump_gen(slot) }; // even → write-complete
    } else {
        if (ptr & 7) == 0 {
            unsafe {
                (*(ptr as *const core::sync::atomic::AtomicU64)).store(val, Ordering::Relaxed)
            };
        } else {
            unsafe { (ptr as *mut u64).write_unaligned(val) };
        }
    }
}

pub unsafe fn write_bytes(base: u32, addr: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let dst = (base + addr as u32) as *mut u8;
    debug_assert!(
        !dst.is_null(),
        "guest_mem::write_bytes null dst: base=0x{base:x} addr=0x{addr:x} len={}",
        data.len()
    );
    if unsafe { is_multi_threaded() } && !data.is_empty() {
        let start_slot = ((addr >> 3) & 63) as usize;
        let end_slot = (((addr + data.len() as u64 - 1) >> 3) & 63) as usize;
        // bump all slots to odd → write-in-progress
        if start_slot <= end_slot {
            for s in start_slot..=end_slot {
                unsafe { bump_gen(s) };
            }
        } else {
            for s in start_slot..64 {
                unsafe { bump_gen(s) };
            }
            for s in 0..=end_slot {
                unsafe { bump_gen(s) };
            }
        }
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
        // bump all slots to even → write-complete
        if start_slot <= end_slot {
            for s in start_slot..=end_slot {
                unsafe { bump_gen(s) };
            }
        } else {
            for s in start_slot..64 {
                unsafe { bump_gen(s) };
            }
            for s in 0..=end_slot {
                unsafe { bump_gen(s) };
            }
        }
    } else {
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
    }
}

pub unsafe fn zero_mem(base: u32, addr: u64, len: usize) {
    if len == 0 {
        return;
    }
    if unsafe { is_multi_threaded() } && len > 0 {
        let start_slot = ((addr >> 3) & 63) as usize;
        let end_slot = (((addr + len as u64 - 1) >> 3) & 63) as usize;
        // bump all slots to odd → write-in-progress
        if start_slot <= end_slot {
            for s in start_slot..=end_slot {
                unsafe { bump_gen(s) };
            }
        } else {
            for s in start_slot..64 {
                unsafe { bump_gen(s) };
            }
            for s in 0..=end_slot {
                unsafe { bump_gen(s) };
            }
        }
        let dst = (base + addr as u32) as *mut u8;
        unsafe { core::ptr::write_bytes(dst, 0, len) };
        // bump all slots to even → write-complete
        if start_slot <= end_slot {
            for s in start_slot..=end_slot {
                unsafe { bump_gen(s) };
            }
        } else {
            for s in start_slot..64 {
                unsafe { bump_gen(s) };
            }
            for s in 0..=end_slot {
                unsafe { bump_gen(s) };
            }
        }
    } else {
        let dst = (base + addr as u32) as *mut u8;
        unsafe { core::ptr::write_bytes(dst, 0, len) };
    }
}

/// Read null-terminated string from guest memory. Returns length (excluding null).
pub unsafe fn read_cstr(base: u32, addr: u64, buf: &mut [u8]) -> usize {
    let src = (base + addr as u32) as *const u8;
    let max = buf.len() - 1;
    let mut i = 0;
    while i < max {
        let b = unsafe { src.add(i).read() };
        if b == 0 {
            break;
        }
        buf[i] = b;
        i += 1;
    }
    buf[i] = 0;
    i
}

// Note: Atomics.wait/notify are handled by the JS runtime layer (thread-worker.ts),
// not by Rust. Futex wake/wait go through STATUS codes.

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// Test that write_u32 in multi-threaded mode bumps the generation counter
    /// twice (odd then even), and that read_u32_seqlock returns the correct value.
    #[test]
    fn seqlock_write_bumps_generation_twice() {
        unsafe {
            // Allocate a generation table (64 AtomicU32 slots) and a thread_count.
            let gen_table: [AtomicU32; 64] = core::array::from_fn(|_| AtomicU32::new(0));
            let thread_count = AtomicU32::new(2); // >1 enables multi-threaded path

            // Initialize guest_mem with our reservation table and thread count.
            super::init(gen_table.as_ptr(), &thread_count as *const AtomicU32);

            let base: u32 = 0;
            // Pick an address that maps to a known slot.
            // slot = (addr >> 3) & 63
            let addr: u64 = 0x1000;
            let slot = ((addr >> 3) & 63) as usize;

            let gen_before = gen_table[slot].load(Ordering::SeqCst);
            assert_eq!(gen_before, 0, "generation should start at 0");

            // Write a value in multi-threaded mode.
            super::write_u32(base, addr, 0xDEAD_BEEF);

            // Generation should have been bumped twice (odd then even).
            let gen_after = gen_table[slot].load(Ordering::SeqCst);
            assert_eq!(
                gen_after, 2,
                "generation should be bumped by 2 after one write"
            );
            assert_eq!(
                gen_after & 1,
                0,
                "generation should be even (write complete)"
            );

            // Verify read_u32_seqlock returns the correct value.
            let val = super::read_u32_seqlock(base, addr);
            assert_eq!(
                val, 0xDEAD_BEEF,
                "seqlock read should return the written value"
            );

            // Reset to single-threaded so subsequent tests are not affected.
            super::init(core::ptr::null(), core::ptr::null());
        }
    }
}
