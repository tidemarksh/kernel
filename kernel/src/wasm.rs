#[cfg(target_arch = "wasm32")]
pub fn memory_size_pages() -> u64 {
    core::arch::wasm32::memory_size(0) as u64
}

#[cfg(target_arch = "wasm64")]
pub fn memory_size_pages() -> u64 {
    core::arch::wasm64::memory_size(0) as u64
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
pub fn memory_size_pages() -> u64 {
    0
}

pub fn memory_size_bytes() -> u64 {
    memory_size_pages().saturating_mul(65536)
}

#[cfg(target_arch = "wasm32")]
pub fn memory_grow_pages(pages: usize) -> bool {
    core::arch::wasm32::memory_grow(0, pages) != usize::MAX
}

#[cfg(target_arch = "wasm64")]
pub fn memory_grow_pages(pages: usize) -> bool {
    core::arch::wasm64::memory_grow(0, pages) != usize::MAX
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
pub fn memory_grow_pages(_pages: usize) -> bool {
    false
}

#[cfg(target_arch = "wasm32")]
pub fn unreachable() -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(target_arch = "wasm64")]
pub fn unreachable() -> ! {
    core::arch::wasm64::unreachable()
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
pub fn unreachable() -> ! {
    panic!("wasm unreachable called on non-wasm target")
}
