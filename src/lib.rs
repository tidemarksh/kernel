#![cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), no_std)]

extern crate alloc as alloc_crate;

static mut LAST_PANIC_FILE_PTR: u32 = 0;
static mut LAST_PANIC_FILE_LEN: u32 = 0;
static mut LAST_PANIC_LINE: u32 = 0;
static mut LAST_PANIC_COLUMN: u32 = 0;

pub fn last_panic_location() -> (u32, u32, u32, u32) {
    unsafe {
        (
            LAST_PANIC_FILE_PTR,
            LAST_PANIC_FILE_LEN,
            LAST_PANIC_LINE,
            LAST_PANIC_COLUMN,
        )
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        if let Some(location) = info.location() {
            LAST_PANIC_FILE_PTR = location.file().as_ptr() as u32;
            LAST_PANIC_FILE_LEN = location.file().len() as u32;
            LAST_PANIC_LINE = location.line();
            LAST_PANIC_COLUMN = location.column();
        } else {
            LAST_PANIC_FILE_PTR = 0;
            LAST_PANIC_FILE_LEN = 0;
            LAST_PANIC_LINE = 0;
            LAST_PANIC_COLUMN = 0;
        }
    }
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
#[cfg(target_arch = "wasm32")]
pub mod runtime_test_support;
pub mod syscall;
pub mod types;

#[cfg(test)]
pub mod test_helpers;
