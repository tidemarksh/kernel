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
#[cfg(any(test, all(target_arch = "wasm32", feature = "harness")))]
pub mod harness;
#[path = "harness/debug.rs"]
mod harness_debug;
#[path = "harness/exports.rs"]
mod harness_exports;
#[path = "harness/support.rs"]
mod harness_support;
pub mod jit;
pub mod net;
pub mod syscall;
pub mod types;
