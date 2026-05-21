//! Guest memory access with unsafe concentrated here.
//!
//! All guest memory reads/writes go through this module.
//! Seqlock: when thread_count > 1, stores bump a generation counter
//! for LR/SC reservation invalidation. When thread_count == 1, plain writes.

use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy)]
pub struct GuestMemorySyncContext {
    pub(crate) reservation_gen: *const AtomicU32,
    pub(crate) reservation_lock: *const AtomicU32,
    pub(crate) thread_count: *const AtomicU32,
}

impl GuestMemorySyncContext {
    #[inline(always)]
    pub const fn new(
        reservation_gen: *const AtomicU32,
        reservation_lock: *const AtomicU32,
        thread_count: *const AtomicU32,
    ) -> Self {
        Self {
            reservation_gen,
            reservation_lock,
            thread_count,
        }
    }
}

/// Reservation table pointers (set once during process init).
static mut RESERVATION_GEN: *const AtomicU32 = core::ptr::null();
/// Granule spinlocks for LR/SC + ordinary store serialization.
static mut RESERVATION_LOCK: *const AtomicU32 = core::ptr::null();
/// Pointer to thread_count in ProcessState. null = single-thread (skip seqlock).
static mut THREAD_COUNT: *const AtomicU32 = core::ptr::null();
const ACCESS_READ: u32 = 1;
const ACCESS_WRITE: u32 = 2;
const ACCESS_ZERO: u32 = 3;
const WRITE_OP_U8: u32 = 1;
const WRITE_OP_U16: u32 = 2;
const WRITE_OP_U32: u32 = 3;
const WRITE_OP_U64: u32 = 4;
const WRITE_OP_BYTES: u32 = 5;
const WRITE_OP_ZERO: u32 = 6;

#[inline(always)]
fn sample_u64(bytes: &[u8]) -> (u64, u32) {
    let sample_len = bytes.len().min(core::mem::size_of::<u64>());
    let mut sample = [0u8; core::mem::size_of::<u64>()];
    sample[..sample_len].copy_from_slice(&bytes[..sample_len]);
    (u64::from_le_bytes(sample), sample_len as u32)
}

#[inline(always)]
fn check_range(base: u32, addr: u64, len: usize, op: &str) {
    #[cfg(any(test, feature = "harness"))]
    {
        let absolute = (base as u64).checked_add(addr).unwrap_or_else(|| {
            panic!("{op}: address overflow base=0x{base:x} addr=0x{addr:x} len=0x{len:x}")
        });
        let end = absolute
            .checked_add(len as u64)
            .unwrap_or_else(|| panic!("{op}: end overflow absolute=0x{absolute:x} len=0x{len:x}"));
        let mem_size = (core::arch::wasm32::memory_size(0) as u64).saturating_mul(65536);
        if end > mem_size {
            panic!(
                "{op}: out of bounds base=0x{base:x} addr=0x{addr:x} absolute=0x{absolute:x} end=0x{end:x} len=0x{len:x} mem_size=0x{mem_size:x}"
            );
        }
    }

    #[cfg(not(any(test, feature = "harness")))]
    let _ = (base, addr, len, op);
}

#[inline(always)]
fn record_access(addr: u64, len: u32, kind: u32) {
    let _ = (addr, len, kind);
}

/// Initialize reservation table pointers.
///
/// # Safety
/// Must be called once before any guest memory access.
pub unsafe fn init(
    reservation_gen: *const AtomicU32,
    reservation_lock: *const AtomicU32,
    thread_count: *const AtomicU32,
) {
    unsafe {
        RESERVATION_GEN = reservation_gen;
        RESERVATION_LOCK = reservation_lock;
        THREAD_COUNT = thread_count;
    }
}

pub fn init_single_threaded() {
    unsafe {
        init(core::ptr::null(), core::ptr::null(), core::ptr::null());
    }
}

#[inline(always)]
unsafe fn is_multi_threaded() -> bool {
    unsafe { is_multi_threaded_with(THREAD_COUNT) }
}

#[inline(always)]
unsafe fn is_multi_threaded_with(thread_count: *const AtomicU32) -> bool {
    !thread_count.is_null() && unsafe { (*thread_count).load(Ordering::Relaxed) } > 1
}

#[inline(always)]
unsafe fn debug_thread_count() -> u64 {
    let thread_count = unsafe { THREAD_COUNT };
    if thread_count.is_null() {
        0
    } else {
        unsafe { (*thread_count).load(Ordering::Relaxed) as u64 }
    }
}

// ---------------------------------------------------------------------------
// Reads — plain reads for single-threaded, seqlock-guarded reads available
// ---------------------------------------------------------------------------

/// Read a u32 with seqlock protection. Checks generation slot before and after
/// the read; retries if the slot was bumped (indicates concurrent write).
/// Returns the read value. For single-threaded execution, skips the check.
///
/// # Safety
/// `base + addr` must point to a readable 4-byte guest location in the current
/// WASM linear memory for the duration of the call.
#[inline(always)]
pub unsafe fn read_u32_seqlock(base: u32, addr: u64) -> u32 {
    if !unsafe { is_multi_threaded() } {
        return unsafe { read_u32(base, addr) };
    }
    let (first_slot, last_slot) = seqlock_slots(addr, 4);
    loop {
        let gen_before_first = unsafe { read_gen(first_slot) };
        let gen_before_last = if last_slot == first_slot {
            gen_before_first
        } else {
            unsafe { read_gen(last_slot) }
        };
        if (gen_before_first | gen_before_last) & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let val = unsafe { read_u32(base, addr) };
        let gen_after_first = unsafe { read_gen(first_slot) };
        let gen_after_last = if last_slot == first_slot {
            gen_after_first
        } else {
            unsafe { read_gen(last_slot) }
        };
        if gen_before_first == gen_after_first && gen_before_last == gen_after_last {
            return val;
        }
    }
}

/// Read a u16 with seqlock protection.
///
/// # Safety
/// `base + addr` must point to a readable 2-byte guest location in the current
/// WASM linear memory for the duration of the call.
#[inline(always)]
pub unsafe fn read_u16_seqlock(base: u32, addr: u64) -> u16 {
    if !unsafe { is_multi_threaded() } {
        return unsafe { read_u16(base, addr) };
    }
    let (first_slot, last_slot) = seqlock_slots(addr, 2);
    loop {
        let gen_before_first = unsafe { read_gen(first_slot) };
        let gen_before_last = if last_slot == first_slot {
            gen_before_first
        } else {
            unsafe { read_gen(last_slot) }
        };
        if (gen_before_first | gen_before_last) & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let val = unsafe { read_u16(base, addr) };
        let gen_after_first = unsafe { read_gen(first_slot) };
        let gen_after_last = if last_slot == first_slot {
            gen_after_first
        } else {
            unsafe { read_gen(last_slot) }
        };
        if gen_before_first == gen_after_first && gen_before_last == gen_after_last {
            return val;
        }
    }
}

/// Read a u64 with seqlock protection.
///
/// # Safety
/// `base + addr` must point to a readable 8-byte guest location in the current
/// WASM linear memory for the duration of the call.
#[inline(always)]
pub unsafe fn read_u64_seqlock(base: u32, addr: u64) -> u64 {
    if !unsafe { is_multi_threaded() } {
        return unsafe { read_u64(base, addr) };
    }
    let (first_slot, last_slot) = seqlock_slots(addr, 8);
    loop {
        let gen_before_first = unsafe { read_gen(first_slot) };
        let gen_before_last = if last_slot == first_slot {
            gen_before_first
        } else {
            unsafe { read_gen(last_slot) }
        };
        if (gen_before_first | gen_before_last) & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let val = unsafe { read_u64(base, addr) };
        let gen_after_first = unsafe { read_gen(first_slot) };
        let gen_after_last = if last_slot == first_slot {
            gen_after_first
        } else {
            unsafe { read_gen(last_slot) }
        };
        if gen_before_first == gen_after_first && gen_before_last == gen_after_last {
            return val;
        }
    }
}

#[inline(always)]
fn seqlock_slots(addr: u64, len: usize) -> (usize, usize) {
    let first = ((addr >> 3) & 63) as usize;
    let last = (((addr + len as u64 - 1) >> 3) & 63) as usize;
    (first, last)
}

#[inline(always)]
unsafe fn read_gen(slot: usize) -> u32 {
    let p = unsafe { RESERVATION_GEN };
    if p.is_null() {
        return 0;
    }
    unsafe { (*p.add(slot)).load(Ordering::Acquire) }
}

/// Read one byte from guest memory.
///
/// # Safety
/// `base + addr` must point to a readable guest byte in the current WASM
/// linear memory.
#[inline(always)]
pub unsafe fn read_u8(base: u32, addr: u64) -> u8 {
    record_access(addr, 1, ACCESS_READ);
    check_range(base, addr, 1, "guest_mem::read_u8");
    unsafe { *((base + addr as u32) as *const u8) }
}

/// Read an unaligned little-endian `u16` from guest memory.
///
/// # Safety
/// `base + addr..base + addr + 2` must be readable guest memory.
#[inline(always)]
pub unsafe fn read_u16(base: u32, addr: u64) -> u16 {
    record_access(addr, 2, ACCESS_READ);
    check_range(base, addr, 2, "guest_mem::read_u16");
    unsafe { ((base + addr as u32) as *const u16).read_unaligned() }
}

/// Read a `u32` from guest memory.
///
/// # Safety
/// `base + addr..base + addr + 4` must be readable guest memory.
#[inline(always)]
pub unsafe fn read_u32(base: u32, addr: u64) -> u32 {
    record_access(addr, 4, ACCESS_READ);
    check_range(base, addr, 4, "guest_mem::read_u32");
    let ptr = (base + addr as u32) as usize;
    unsafe { (ptr as *const u32).read_unaligned() }
}

/// Read a `u64` from guest memory.
///
/// # Safety
/// `base + addr..base + addr + 8` must be readable guest memory.
#[inline(always)]
pub unsafe fn read_u64(base: u32, addr: u64) -> u64 {
    record_access(addr, 8, ACCESS_READ);
    check_range(base, addr, 8, "guest_mem::read_u64");
    let ptr = (base + addr as u32) as usize;
    unsafe { (ptr as *const u64).read_unaligned() }
}

/// Read an `i8` from guest memory.
///
/// # Safety
/// Inherits the safety requirements of [`read_u8`].
#[inline(always)]
pub unsafe fn read_i8(base: u32, addr: u64) -> i8 {
    (unsafe { read_u8(base, addr) }) as i8
}
/// Read an `i16` from guest memory.
///
/// # Safety
/// Inherits the safety requirements of [`read_u16`].
#[inline(always)]
pub unsafe fn read_i16(base: u32, addr: u64) -> i16 {
    (unsafe { read_u16(base, addr) }) as i16
}
/// Read an `i32` from guest memory.
///
/// # Safety
/// Inherits the safety requirements of [`read_u32`].
#[inline(always)]
pub unsafe fn read_i32(base: u32, addr: u64) -> i32 {
    (unsafe { read_u32(base, addr) }) as i32
}
/// Read an `i64` from guest memory.
///
/// # Safety
/// Inherits the safety requirements of [`read_u64`].
#[inline(always)]
pub unsafe fn read_i64(base: u32, addr: u64) -> i64 {
    (unsafe { read_u64(base, addr) }) as i64
}

/// Copy bytes from guest memory into `buf`.
///
/// # Safety
/// `base + addr..base + addr + buf.len()` must be readable guest memory.
pub unsafe fn read_bytes(base: u32, addr: u64, buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    record_access(addr, buf.len() as u32, ACCESS_READ);
    check_range(base, addr, buf.len(), "guest_mem::read_bytes");
    let src = (base + addr as u32) as *const u8;
    debug_assert!(
        !src.is_null(),
        "guest_mem::read_bytes null src: base=0x{base:x} addr=0x{addr:x} len={}",
        buf.len()
    );
    unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len()) };
}

/// Borrow a contiguous readable range from guest memory.
///
/// # Safety
/// `base + addr..base + addr + len` must be readable guest memory and the
/// returned slice must not outlive the current linear-memory instance.
pub unsafe fn read_slice<'a>(base: u32, addr: u64, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    record_access(addr, len as u32, ACCESS_READ);
    check_range(base, addr, len, "guest_mem::read_slice");
    let src = (base + addr as u32) as *const u8;
    debug_assert!(
        !src.is_null(),
        "guest_mem::read_slice null src: base=0x{base:x} addr=0x{addr:x} len={len}"
    );
    unsafe { core::slice::from_raw_parts(src, len) }
}

// ---------------------------------------------------------------------------
// Writes — seqlock when multi-threaded, plain when single-threaded
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn bump_gen(slot: usize) {
    unsafe { bump_gen_with(RESERVATION_GEN, slot) };
}

#[inline(always)]
unsafe fn bump_gen_with(reservation_gen: *const AtomicU32, slot: usize) {
    let p = reservation_gen;
    if !p.is_null() {
        unsafe { (*p.add(slot)).fetch_add(1, Ordering::SeqCst) };
    }
}

#[inline(always)]
unsafe fn lock_slot(slot: usize) {
    unsafe { lock_slot_with(RESERVATION_LOCK, slot) };
}

#[inline(always)]
unsafe fn lock_slot_with(reservation_lock: *const AtomicU32, slot: usize) {
    let p = reservation_lock;
    if p.is_null() {
        return;
    }
    let lock = unsafe { &*p.add(slot) };
    while lock
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline(always)]
unsafe fn unlock_slot(slot: usize) {
    unsafe { unlock_slot_with(RESERVATION_LOCK, slot) };
}

#[inline(always)]
unsafe fn unlock_slot_with(reservation_lock: *const AtomicU32, slot: usize) {
    let p = reservation_lock;
    if p.is_null() {
        return;
    }
    unsafe { (&*p.add(slot)).store(0, Ordering::Release) };
}

#[inline(always)]
fn stripe_mask(addr: u64, len: usize) -> u64 {
    if len == 0 {
        return 0;
    }
    let granules = ((addr + len as u64 - 1) >> 3) - (addr >> 3) + 1;
    if granules >= 64 {
        return u64::MAX;
    }
    let start = ((addr >> 3) & 63) as u32;
    let end = (((addr + len as u64 - 1) >> 3) & 63) as u32;
    let start_mask = if start == 0 {
        u64::MAX
    } else {
        !((1u64 << start) - 1)
    };
    let end_mask = if end >= 63 {
        u64::MAX
    } else {
        (1u64 << (end + 1)) - 1
    };
    if start <= end {
        start_mask & end_mask
    } else {
        start_mask | end_mask
    }
}

#[inline(always)]
unsafe fn lock_mask(mask: u64) {
    unsafe { lock_mask_with(RESERVATION_LOCK, mask) };
}

#[inline(always)]
unsafe fn lock_mask_with(reservation_lock: *const AtomicU32, mask: u64) {
    for slot in 0..64 {
        if mask & (1u64 << slot) != 0 {
            unsafe { lock_slot_with(reservation_lock, slot) };
        }
    }
}

#[inline(always)]
unsafe fn unlock_mask(mask: u64) {
    unsafe { unlock_mask_with(RESERVATION_LOCK, mask) };
}

#[inline(always)]
unsafe fn unlock_mask_with(reservation_lock: *const AtomicU32, mask: u64) {
    for slot in (0..64).rev() {
        if mask & (1u64 << slot) != 0 {
            unsafe { unlock_slot_with(reservation_lock, slot) };
        }
    }
}

#[inline(always)]
unsafe fn seqlock_begin_mask(mask: u64) {
    unsafe { seqlock_begin_mask_with(RESERVATION_GEN, mask) };
}

#[inline(always)]
unsafe fn seqlock_begin_mask_with(reservation_gen: *const AtomicU32, mask: u64) {
    for slot in 0..64 {
        if mask & (1u64 << slot) != 0 {
            unsafe { bump_gen_with(reservation_gen, slot) };
        }
    }
}

#[inline(always)]
unsafe fn seqlock_end_mask(mask: u64) {
    unsafe { seqlock_end_mask_with(RESERVATION_GEN, mask) };
}

#[inline(always)]
unsafe fn seqlock_end_mask_with(reservation_gen: *const AtomicU32, mask: u64) {
    for slot in 0..64 {
        if mask & (1u64 << slot) != 0 {
            unsafe { bump_gen_with(reservation_gen, slot) };
        }
    }
}

#[inline(always)]
unsafe fn write_scalar_with_mode(
    base: u32,
    addr: u64,
    bytes: &[u8],
    use_lock: bool,
    use_gen: bool,
    bytewise: bool,
) {
    unsafe {
        write_scalar_with_mode_and_sync(base, addr, bytes, use_lock, use_gen, bytewise, None)
    };
}

#[inline(always)]
unsafe fn write_scalar_with_mode_and_sync(
    base: u32,
    addr: u64,
    bytes: &[u8],
    use_lock: bool,
    use_gen: bool,
    bytewise: bool,
    sync: Option<GuestMemorySyncContext>,
) {
    let dst = (base + addr as u32) as *mut u8;
    let reservation_gen = sync.map_or(unsafe { RESERVATION_GEN }, |ctx| ctx.reservation_gen);
    let reservation_lock = sync.map_or(unsafe { RESERVATION_LOCK }, |ctx| ctx.reservation_lock);
    let thread_count = sync.map_or(unsafe { THREAD_COUNT }, |ctx| ctx.thread_count);
    let op = match bytes.len() {
        1 => WRITE_OP_U8,
        2 => WRITE_OP_U16,
        4 => WRITE_OP_U32,
        8 => WRITE_OP_U64,
        _ => WRITE_OP_BYTES,
    };
    if crate::tracepoints::guest_write_overlap_enabled() {
        let (sample, sample_len) = sample_u64(bytes);
        crate::tracepoints::record_guest_write_overlap(
            addr,
            bytes.len().min(u32::MAX as usize) as u32,
            op,
            sample,
            sample_len,
        );
    }
    let is_multi = unsafe { is_multi_threaded_with(thread_count) };
    let mask = if is_multi {
        stripe_mask(addr, bytes.len())
    } else {
        0
    };
    if is_multi {
        if use_lock {
            unsafe { lock_mask_with(reservation_lock, mask) };
        }
        if use_gen {
            unsafe { seqlock_begin_mask_with(reservation_gen, mask) };
        }
        if bytewise {
            for (index, byte) in bytes.iter().copied().enumerate() {
                unsafe { dst.add(index).write(byte) };
            }
        } else {
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
        }
        if use_gen {
            unsafe { seqlock_end_mask_with(reservation_gen, mask) };
        }
        if use_lock {
            unsafe { unlock_mask_with(reservation_lock, mask) };
        }
    } else if bytewise {
        for (index, byte) in bytes.iter().copied().enumerate() {
            unsafe { dst.add(index).write(byte) };
        }
    } else {
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    }
}

/// Write one byte into guest memory.
///
/// # Safety
/// `base + addr` must point to a writable guest byte in the current WASM
/// linear memory.
#[inline(always)]
pub unsafe fn write_u8(base: u32, addr: u64, val: u8) {
    record_access(addr, 1, ACCESS_WRITE);
    check_range(base, addr, 1, "guest_mem::write_u8");
    if unsafe { is_multi_threaded() } {
        let slot = ((addr >> 3) & 63) as usize;
        unsafe { lock_slot(slot) };
        unsafe { bump_gen(slot) }; // odd  → write-in-progress
        unsafe { *((base + addr as u32) as *mut u8) = val };
        unsafe { bump_gen(slot) }; // even → write-complete
        unsafe { unlock_slot(slot) };
    } else {
        unsafe { *((base + addr as u32) as *mut u8) = val };
    }
}

/// Write an unaligned little-endian `u16` into guest memory.
///
/// # Safety
/// `base + addr..base + addr + 2` must be writable guest memory.
#[inline(always)]
pub unsafe fn write_u16(base: u32, addr: u64, val: u16) {
    record_access(addr, 2, ACCESS_WRITE);
    check_range(base, addr, 2, "guest_mem::write_u16");
    if unsafe { is_multi_threaded() } {
        let mask = stripe_mask(addr, 2);
        unsafe { lock_mask(mask) };
        unsafe { seqlock_begin_mask(mask) };
        unsafe { ((base + addr as u32) as *mut u16).write_unaligned(val) };
        unsafe { seqlock_end_mask(mask) };
        unsafe { unlock_mask(mask) };
    } else {
        unsafe { ((base + addr as u32) as *mut u16).write_unaligned(val) };
    }
}

/// Write a `u32` into guest memory.
///
/// # Safety
/// `base + addr..base + addr + 4` must be writable guest memory.
#[inline(always)]
pub unsafe fn write_u32(base: u32, addr: u64, val: u32) {
    record_access(addr, 4, ACCESS_WRITE);
    check_range(base, addr, 4, "guest_mem::write_u32");
    let bytes = val.to_le_bytes();
    unsafe { write_scalar_with_mode(base, addr, &bytes, true, true, false) };
}

/// Write a `u64` into guest memory.
///
/// # Safety
/// `base + addr..base + addr + 8` must be writable guest memory.
#[inline(always)]
pub unsafe fn write_u64(base: u32, addr: u64, val: u64) {
    record_access(addr, 8, ACCESS_WRITE);
    check_range(base, addr, 8, "guest_mem::write_u64");
    let bytes = val.to_le_bytes();
    unsafe { write_scalar_with_mode(base, addr, &bytes, true, true, false) };
}

#[inline(always)]
pub unsafe fn sync_context_from_process(
    base: u32,
    process_ptr: u32,
) -> Option<GuestMemorySyncContext> {
    if process_ptr == 0 {
        return None;
    }
    check_range(
        base,
        process_ptr as u64,
        core::mem::size_of::<crate::types::ProcessState>(),
        "guest_mem::sync_context_from_process",
    );
    let ps = unsafe { &*((base as u64 + process_ptr as u64) as *const crate::types::ProcessState) };
    Some(GuestMemorySyncContext::new(
        core::ptr::addr_of!(ps.reservation_gen) as *const AtomicU32,
        core::ptr::addr_of!(ps.reservation_lock) as *const AtomicU32,
        core::ptr::addr_of!(ps.thread_count),
    ))
}

#[inline(always)]
pub unsafe fn write_u8_with_sync(base: u32, addr: u64, val: u8, sync: GuestMemorySyncContext) {
    record_access(addr, 1, ACCESS_WRITE);
    let bytes = [val];
    unsafe { write_scalar_with_mode_and_sync(base, addr, &bytes, true, true, false, Some(sync)) };
}

#[inline(always)]
pub unsafe fn write_u16_with_sync(base: u32, addr: u64, val: u16, sync: GuestMemorySyncContext) {
    record_access(addr, 2, ACCESS_WRITE);
    let bytes = val.to_le_bytes();
    unsafe { write_scalar_with_mode_and_sync(base, addr, &bytes, true, true, false, Some(sync)) };
}

#[inline(always)]
pub unsafe fn write_u32_with_sync(base: u32, addr: u64, val: u32, sync: GuestMemorySyncContext) {
    record_access(addr, 4, ACCESS_WRITE);
    let bytes = val.to_le_bytes();
    unsafe { write_scalar_with_mode_and_sync(base, addr, &bytes, true, true, false, Some(sync)) };
}

#[inline(always)]
pub unsafe fn write_u64_with_sync(base: u32, addr: u64, val: u64, sync: GuestMemorySyncContext) {
    record_access(addr, 8, ACCESS_WRITE);
    let bytes = val.to_le_bytes();
    unsafe { write_scalar_with_mode_and_sync(base, addr, &bytes, true, true, false, Some(sync)) };
}

/// Copy bytes from `data` into guest memory.
///
/// # Safety
/// `base + addr..base + addr + data.len()` must be writable guest memory.
pub unsafe fn write_bytes(base: u32, addr: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    record_access(addr, data.len() as u32, ACCESS_WRITE);
    check_range(base, addr, data.len(), "guest_mem::write_bytes");
    if crate::tracepoints::guest_write_overlap_enabled() {
        let (sample, sample_len) = sample_u64(data);
        crate::tracepoints::record_guest_write_overlap(
            addr,
            data.len().min(u32::MAX as usize) as u32,
            WRITE_OP_BYTES,
            sample,
            sample_len,
        );
    }
    let dst = (base + addr as u32) as *mut u8;
    debug_assert!(
        !dst.is_null(),
        "guest_mem::write_bytes null dst: base=0x{base:x} addr=0x{addr:x} len={}",
        data.len()
    );
    if unsafe { is_multi_threaded() } && !data.is_empty() {
        let mask = stripe_mask(addr, data.len());
        unsafe { lock_mask(mask) };
        unsafe { seqlock_begin_mask(mask) };
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
        unsafe { seqlock_end_mask(mask) };
        unsafe { unlock_mask(mask) };
    } else {
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
    }
}

/// Expose a writable guest-memory slice to a caller-owned copy routine.
///
/// # Safety
/// `base + addr..base + addr + len` must be writable guest memory, and the
/// closure must not retain the slice after returning.
pub unsafe fn with_write_slice<R>(
    base: u32,
    addr: u64,
    len: usize,
    f: impl FnOnce(&mut [u8]) -> R,
) -> R {
    record_access(addr, len.min(u32::MAX as usize) as u32, ACCESS_WRITE);
    check_range(base, addr, len, "guest_mem::with_write_slice");
    let dst = (base + addr as u32) as *mut u8;
    debug_assert!(
        !dst.is_null(),
        "guest_mem::with_write_slice null dst: base=0x{base:x} addr=0x{addr:x} len={len}"
    );
    let dst_slice = unsafe { core::slice::from_raw_parts_mut(dst, len) };
    let result = if unsafe { is_multi_threaded() } && len > 0 {
        let mask = stripe_mask(addr, len);
        unsafe { lock_mask(mask) };
        unsafe { seqlock_begin_mask(mask) };
        let result = f(dst_slice);
        unsafe { seqlock_end_mask(mask) };
        unsafe { unlock_mask(mask) };
        result
    } else {
        f(dst_slice)
    };
    if crate::tracepoints::guest_write_overlap_enabled() {
        let (sample, sample_len) = sample_u64(dst_slice);
        crate::tracepoints::record_guest_write_overlap(
            addr,
            len.min(u32::MAX as usize) as u32,
            WRITE_OP_BYTES,
            sample,
            sample_len,
        );
    }
    result
}

/// Zero a guest memory range.
///
/// # Safety
/// `base + addr..base + addr + len` must be writable guest memory.
pub unsafe fn zero_mem(base: u32, addr: u64, len: usize) {
    if len == 0 {
        return;
    }
    record_access(addr, len.min(u32::MAX as usize) as u32, ACCESS_ZERO);
    check_range(base, addr, len, "guest_mem::zero_mem");
    crate::tracepoints::record_execve_stage(360, addr, len as u64);
    if crate::tracepoints::guest_write_overlap_enabled() {
        crate::tracepoints::record_guest_write_overlap(
            addr,
            len.min(u32::MAX as usize) as u32,
            WRITE_OP_ZERO,
            0,
            0,
        );
    }
    if unsafe { is_multi_threaded() } && len > 0 {
        let mask = stripe_mask(addr, len);
        crate::tracepoints::record_execve_stage(361, unsafe { debug_thread_count() }, mask as u64);
        unsafe { lock_mask(mask) };
        crate::tracepoints::record_execve_stage(362, addr, len as u64);
        unsafe { seqlock_begin_mask(mask) };
        let dst = (base + addr as u32) as *mut u8;
        unsafe { core::ptr::write_bytes(dst, 0, len) };
        crate::tracepoints::record_execve_stage(363, addr, len as u64);
        unsafe { seqlock_end_mask(mask) };
        unsafe { unlock_mask(mask) };
        crate::tracepoints::record_execve_stage(364, addr, len as u64);
    } else {
        crate::tracepoints::record_execve_stage(365, unsafe { debug_thread_count() }, len as u64);
        let dst = (base + addr as u32) as *mut u8;
        unsafe { core::ptr::write_bytes(dst, 0, len) };
        crate::tracepoints::record_execve_stage(366, addr, len as u64);
    }
}

/// Read null-terminated string from guest memory. Returns length (excluding null).
///
/// # Safety
/// `base + addr` must point to a readable NUL-terminated guest string, and
/// the string including its terminator must fit in `buf`.
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
            let lock_table: [AtomicU32; 64] = core::array::from_fn(|_| AtomicU32::new(0));
            super::init(
                gen_table.as_ptr(),
                lock_table.as_ptr(),
                &thread_count as *const AtomicU32,
            );

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
            let half = super::read_u16_seqlock(base, addr);
            assert_eq!(half, 0xBEEF, "u16 seqlock read should see the low halfword");

            // Reset to single-threaded so subsequent tests are not affected.
            super::init(core::ptr::null(), core::ptr::null(), core::ptr::null());
        }
    }

    #[test]
    fn seqlock_slots_cover_cross_granule_reads() {
        assert_eq!(super::seqlock_slots(0x1000, 2), (0, 0));
        assert_eq!(super::seqlock_slots(0x1007, 2), (0, 1));
        assert_eq!(super::seqlock_slots(0x1005, 4), (0, 1));
        assert_eq!(super::seqlock_slots(0x1004, 8), (0, 1));
    }

    #[test]
    fn cross_granule_writes_bump_both_slots_and_reads_roundtrip() {
        unsafe {
            let gen_table: [AtomicU32; 64] = core::array::from_fn(|_| AtomicU32::new(0));
            let lock_table: [AtomicU32; 64] = core::array::from_fn(|_| AtomicU32::new(0));
            let thread_count = AtomicU32::new(2);
            super::init(
                gen_table.as_ptr(),
                lock_table.as_ptr(),
                &thread_count as *const AtomicU32,
            );

            let base: u32 = 0;
            let addr: u64 = 0x1004;
            let (first_slot, last_slot) = super::seqlock_slots(addr, 8);
            assert_ne!(
                first_slot, last_slot,
                "test address should cross a granule boundary"
            );

            super::write_u64(base, addr, 0x1122_3344_5566_7788);

            assert_eq!(gen_table[first_slot].load(Ordering::SeqCst), 2);
            assert_eq!(gen_table[last_slot].load(Ordering::SeqCst), 2);
            assert_eq!(super::read_u64_seqlock(base, addr), 0x1122_3344_5566_7788);

            super::init(core::ptr::null(), core::ptr::null(), core::ptr::null());
        }
    }

    #[test]
    fn watched_guest_write_overlap_records_sample_and_stage() {
        unsafe {
            super::init(core::ptr::null(), core::ptr::null(), core::ptr::null());
        }
        crate::harness::debug::clear_guest_write_watch_trace();
        crate::harness::debug::record_execve_stage(716, 0, 0);
        crate::harness::debug::configure_guest_write_watch(0, 0x2000, 0x2010);
        unsafe {
            super::write_u32(0, 0x2004, 0x1122_3344);
        }
        assert_eq!(crate::harness::debug::guest_write_overlap_trace_len(), 1);
        let entry = crate::harness::debug::guest_write_overlap_trace_entry(0);
        assert_eq!(entry.slot, 0);
        assert_eq!(entry.op, super::WRITE_OP_U32);
        assert_eq!(entry.addr, 0x2004);
        assert_eq!(entry.len, 4);
        assert_eq!(entry.sample_len, 4);
        assert_eq!(entry.sample, 0x1122_3344);
        assert_eq!(entry.execve_stage, 716);
        crate::harness::debug::clear_guest_write_watch_trace();
    }
}
