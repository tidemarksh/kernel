#![cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), no_std)]

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

pub mod abi;
pub mod alloc;
pub mod cpu;
pub mod elf;
pub mod fs;
pub mod guest_mem;
pub mod jit;
pub mod net;
pub mod syscall;
pub mod types;

#[cfg(test)]
pub mod test_helpers;
