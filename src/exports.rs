//! WASM exports called by runtime (TS).
//!
//! These are the public API of the kernel WASM module. The runtime
//! instantiates the WASM, calls these exports to manage processes
//! and threads, and handles STATUS codes returned by thread_step.

use crate::abi::*;
use crate::types::*;
use crate::{alloc, cpu, elf, guest_mem, syscall, fs};

/// Initialize kernel state. Must be called once after WASM instantiation.
/// `heap_base`: first usable byte for bump allocator.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_init(heap_base: u32) {
    unsafe {
        alloc::init(heap_base);
        guest_mem::init(core::ptr::null(), core::ptr::null());
    }
    syscall::memory::init(0);
    syscall::signal::init();
    fs::fd_table::init();
    fs::memfs::init();
}

/// Create a new process. Loads an ELF from `elf_ptr` (in WASM memory) of
/// `elf_len` bytes. Returns a pointer to the ThreadState of the main thread,
/// or 0 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn process_create(
    elf_ptr: u32,
    elf_len: u32,
    ram_size: u32,
    stack_size: u32,
) -> u32 {
    unsafe {
        let base: u32 = 0;

        let elf_result = match elf::load_elf(base, ram_size as u64, elf_ptr, elf_len) {
            Ok(r) => r,
            Err(_) => return 0,
        };

        // Re-init brk after ELF load
        syscall::memory::init(elf_result.brk_start);

        // Allocate ProcessState
        let ps_ptr = alloc::alloc_zeroed(
            core::mem::size_of::<ProcessState>() as u32,
            core::mem::align_of::<ProcessState>() as u32,
        );
        if ps_ptr == 0 { return 0; }
        let ps = &mut *(ps_ptr as *mut ProcessState);
        ps.pid = 1;
        ps.ppid = 0;

        // Set up FD 0/1/2
        guest_mem::write_u32(base, ps_ptr as u64, 1);       // fd 0 ofd_id=1
        guest_mem::write_u32(base, ps_ptr as u64 + 8, 2);   // fd 1 ofd_id=2
        guest_mem::write_u32(base, ps_ptr as u64 + 16, 3);  // fd 2 ofd_id=3

        // Allocate ThreadState
        let ts_ptr = alloc::alloc_zeroed(
            core::mem::size_of::<ThreadState>() as u32,
            core::mem::align_of::<ThreadState>() as u32,
        );
        if ts_ptr == 0 { return 0; }
        let ts = &mut *(ts_ptr as *mut ThreadState);

        // Set up stack
        let stack_top = (ram_size - 4096) as u64;
        let random_addr = stack_top - 16;
        guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);

        let argv0_addr = stack_top - 64;
        guest_mem::write_bytes(base, argv0_addr, b"init\0");

        let sp = elf::setup_stack(
            base, stack_top - 128, &[argv0_addr], &[], &elf_result, random_addr,
        );

        ts.pc = elf_result.entry;
        ts.x[2] = sp;
        ts.status = STATUS_OK;
        ts.tid = 1;
        ts.process_ptr = ps_ptr;

        ts_ptr
    }
}

/// Execute `budget` guest instructions on the thread at `vm_ptr`.
/// Returns the remaining budget. Check `thread_status(vm_ptr)` for
/// the exit reason (STATUS_OK, STATUS_FAULT, STATUS_FS, etc.).
#[unsafe(no_mangle)]
pub extern "C" fn thread_step(vm_ptr: u32, budget: i32) -> i32 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        vm.status = STATUS_OK;
        cpu::exec(vm, budget, None, None, None, None)
    }
}

/// Get the current status of a thread.
#[unsafe(no_mangle)]
pub extern "C" fn thread_status(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const ThreadState)).status }
}

/// Get the exit code of a thread (valid when status == STATUS_FAULT).
#[unsafe(no_mangle)]
pub extern "C" fn thread_exit_code(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const ThreadState)).exit_code }
}

/// Get the PC of a thread.
#[unsafe(no_mangle)]
pub extern "C" fn thread_pc(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).pc }
}

/// Get the value of register a0 (x10) — syscall return value.
#[unsafe(no_mangle)]
pub extern "C" fn thread_a0(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[10] }
}
