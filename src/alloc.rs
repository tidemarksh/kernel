//! Bump allocator for kernel Worker's WASM linear memory.
//!
//! Used to allocate ProcessState, ThreadState, OFD table, etc.
//! Free is a no-op (kernel objects are long-lived).

static mut HEAP_BASE: u32 = 0;
static mut HEAP_PTR: u32 = 0;

/// Initialize the allocator. `base` is the first usable byte after WASM data segments.
///
/// Monotonic: heap pointer never rewinds. If it has already advanced past `base`,
/// the heap continues from the current position. This prevents overlapping
/// allocations when subsystems are re-initialized (test environment).
///
/// # Safety
/// Must be called before any allocation.
pub unsafe fn init(base: u32) {
    unsafe {
        let effective = if HEAP_PTR > base { HEAP_PTR } else { base };
        HEAP_BASE = effective;
        HEAP_PTR = effective;
    }
}



/// Allocate `size` bytes aligned to `align`. Returns 0 on failure.
///
/// # Safety
/// Caller must ensure the WASM linear memory is large enough.
pub unsafe fn alloc(size: u32, align: u32) -> u32 {
    let aligned = (unsafe { HEAP_PTR } + align - 1) & !(align - 1);
    let end = aligned + size;
    // Check against WASM memory size
    let mem_size = unsafe { core::arch::wasm32::memory_size(0) } as u32 * 65536;
    if end > mem_size {
        // Try to grow
        let pages_needed = ((end - mem_size) + 65535) / 65536;
        let result = unsafe { core::arch::wasm32::memory_grow(0, pages_needed as usize) };
        if result == usize::MAX {
            return 0; // OOM
        }
    }
    unsafe { HEAP_PTR = end };
    aligned
}

/// Convenience: allocate a zeroed region.
///
/// # Safety
/// Same as `alloc`.
pub unsafe fn alloc_zeroed(size: u32, align: u32) -> u32 {
    let ptr = unsafe { alloc(size, align) };
    if ptr != 0 {
        unsafe { core::ptr::write_bytes(ptr as *mut u8, 0, size as usize) };
    }
    ptr
}

/// Convenience: allocate space for a type T, zeroed.
///
/// # Safety
/// Same as `alloc`.
pub unsafe fn alloc_type<T>() -> u32 {
    unsafe { alloc_zeroed(core::mem::size_of::<T>() as u32, core::mem::align_of::<T>() as u32) }
}

/// Return current heap usage in bytes.
pub fn heap_used() -> u32 {
    unsafe { HEAP_PTR - HEAP_BASE }
}

/// Return current heap pointer (first unallocated byte).
pub fn heap_ptr() -> u32 {
    unsafe { HEAP_PTR }
}
