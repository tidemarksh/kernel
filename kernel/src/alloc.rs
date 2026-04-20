//! Bump allocator for kernel Worker's WASM linear memory.
//!
//! Used to allocate ProcessState, ThreadState, OFD table, Vec<Vma>, etc.
//! Free is a no-op (kernel objects are long-lived).
//! Implements GlobalAlloc to enable `extern crate alloc` (Vec, etc.).

use core::alloc::{GlobalAlloc, Layout};

static mut HEAP_BASE: u32 = 0;
static mut HEAP_PTR: u32 = 0;

#[cold]
fn invalid_heap_range(op: &str, ptr: u32, size: u32, mem_size: u64) -> u32 {
    #[cfg(any(test, feature = "harness"))]
    panic!(
        "{op} out of wasm range ptr=0x{ptr:x} size=0x{size:x} mem_size=0x{mem_size:x} heap_base=0x{:x} heap_ptr=0x{:x}",
        heap_base(),
        heap_ptr(),
    );
    #[cfg(not(any(test, feature = "harness")))]
    {
        let _ = (op, ptr, size, mem_size);
        0
    }
}

/// Global allocator backed by the bump allocator.
#[allow(dead_code)]
struct BumpAlloc;

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { alloc(layout.size() as u32, layout.align() as u32) };
        if ptr == 0 {
            core::ptr::null_mut()
        } else {
            ptr as *mut u8
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // No-op: bump allocator does not free.
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[global_allocator]
static ALLOCATOR: BumpAlloc = BumpAlloc;

/// Initialize the allocator. `base` is the first usable byte after WASM data segments.
///
/// Monotonic: heap pointer never rewinds. If it has already advanced past `base`,
/// the heap continues from the current position. This prevents overlapping
/// allocations when subsystems are re-initialized in a shared WASM instance.
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

/// Reset the allocator to a known floor for a fresh test harness instance.
///
/// Test binaries run many isolated kernel setups in one WASM process. Those
/// setups intentionally discard all kernel-owned allocations between cases, so
/// rewinding the kernel bump allocator is correct there and keeps the guest
/// address-space ceiling stable across the suite.
#[cfg(any(test, feature = "harness"))]
///
/// # Safety
/// The caller must ensure no live allocations from the previous harness state
/// will be accessed after rewinding the bump allocator.
pub unsafe fn reset(base: u32) {
    unsafe {
        HEAP_BASE = base;
        HEAP_PTR = base;
    }
}

/// Allocate `size` bytes aligned to `align`. Returns 0 on failure.
///
/// # Safety
/// Caller must ensure the WASM linear memory is large enough.
pub unsafe fn alloc(size: u32, align: u32) -> u32 {
    if let Some(ptr) = crate::syscall::process::shared_heap_alloc(size, align) {
        if ptr != 0 {
            let mem_size = (core::arch::wasm32::memory_size(0) as u64) * 65536;
            let Some(end) = (ptr as u64).checked_add(size as u64) else {
                return invalid_heap_range("alloc(shared overflow)", ptr, size, mem_size);
            };
            if end > mem_size {
                return invalid_heap_range("alloc(shared)", ptr, size, mem_size);
            }
        }
        return ptr;
    }
    let Some(align_mask) = align.checked_sub(1) else {
        return 0;
    };
    let current = unsafe { HEAP_PTR };
    let Some(aligned) = current.checked_add(align_mask).map(|value| value & !align_mask) else {
        return 0;
    };
    let Some(end) = aligned.checked_add(size) else {
        return 0;
    };
    // Check against WASM memory size
    let mem_size = (core::arch::wasm32::memory_size(0) as u64) * 65536;
    if end as u64 > mem_size {
        // Try to grow
        let pages_needed = (end as u64 - mem_size).div_ceil(65536) as usize;
        let result = core::arch::wasm32::memory_grow(0, pages_needed);
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
        let mem_size = (core::arch::wasm32::memory_size(0) as u64) * 65536;
        let Some(end) = (ptr as u64).checked_add(size as u64) else {
            return invalid_heap_range("alloc_zeroed overflow", ptr, size, mem_size);
        };
        if end > mem_size {
            return invalid_heap_range("alloc_zeroed", ptr, size, mem_size);
        }
        unsafe { core::ptr::write_bytes(ptr as *mut u8, 0, size as usize) };
    }
    ptr
}

/// Convenience: allocate space for a type T, zeroed.
///
/// # Safety
/// Same as `alloc`.
pub unsafe fn alloc_type<T>() -> u32 {
    unsafe {
        alloc_zeroed(
            core::mem::size_of::<T>() as u32,
            core::mem::align_of::<T>() as u32,
        )
    }
}

/// Return current heap usage in bytes.
pub fn heap_used() -> u32 {
    heap_ptr().saturating_sub(heap_base())
}

/// Return the heap base address.
pub fn heap_base() -> u32 {
    if let Some(base) = crate::syscall::process::shared_heap_base() {
        return base;
    }
    unsafe { HEAP_BASE }
}

/// Return current heap pointer (first unallocated byte).
pub fn heap_ptr() -> u32 {
    if let Some(ptr) = crate::syscall::process::shared_heap_ptr() {
        return ptr;
    }
    unsafe { HEAP_PTR }
}

pub fn attach_heap_state(base: u32, ptr: u32) {
    unsafe {
        HEAP_BASE = base;
        HEAP_PTR = ptr;
    }
}

#[cfg(test)]
mod tests {
    /// Test that alloc returns a non-zero pointer.
    #[test]
    fn alloc_returns_nonzero() {
        unsafe {
            // Ensure sufficient WASM pages are available.
            let current_pages = core::arch::wasm32::memory_size(0);
            if current_pages < 256 {
                core::arch::wasm32::memory_grow(0, 256 - current_pages);
            }
            super::init(0x20_0000);

            let ptr = super::alloc(64, 8);
            assert!(ptr != 0, "alloc should return a non-zero pointer");
        }
    }

    /// Test that sequential allocations return non-overlapping regions.
    #[test]
    fn sequential_allocs_non_overlapping() {
        unsafe {
            let current_pages = core::arch::wasm32::memory_size(0);
            if current_pages < 256 {
                core::arch::wasm32::memory_grow(0, 256 - current_pages);
            }
            super::init(0x20_0000);

            let p1 = super::alloc(128, 8);
            let p2 = super::alloc(128, 8);
            assert!(p1 != 0, "first alloc should succeed");
            assert!(p2 != 0, "second alloc should succeed");
            // The second allocation must start at or after p1 + 128 (no overlap).
            assert!(
                p2 >= p1 + 128,
                "allocations should not overlap: p1={:#x}, p2={:#x}",
                p1,
                p2
            );
        }
    }

    /// Test that alloc_zeroed returns memory filled with zeroes.
    #[test]
    fn alloc_zeroed_is_zeroed() {
        unsafe {
            let current_pages = core::arch::wasm32::memory_size(0);
            if current_pages < 256 {
                core::arch::wasm32::memory_grow(0, 256 - current_pages);
            }
            super::init(0x20_0000);

            let ptr = super::alloc_zeroed(256, 8);
            assert!(ptr != 0, "alloc_zeroed should return a non-zero pointer");

            let slice = core::slice::from_raw_parts(ptr as *const u8, 256);
            for (i, &byte) in slice.iter().enumerate() {
                assert_eq!(byte, 0, "byte at offset {} should be zero, got {}", i, byte);
            }
        }
    }
}
