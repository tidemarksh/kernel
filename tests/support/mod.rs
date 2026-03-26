//! ELF test helpers for integration tests.
//! Runs in a separate wasm instance from unit tests, so base=0 is safe.
//!
//! Uses Result<(), String> to avoid panics (wasm32-wasip1 uses panic=abort,
//! so any panic causes a WASM trap that terminates the entire test binary).

use tidemark_kernel::abi::*;
use tidemark_kernel::types::*;

/// Load an ELF, run the interpreter with block cache, return (exit_code, last_pc).
pub fn run_elf(elf_bytes: &[u8]) -> Result<(i32, u64), String> {
    run_elf_inner(elf_bytes, true)
}

/// Load an ELF, run the interpreter without block cache (baseline).
pub fn run_elf_no_cache(elf_bytes: &[u8]) -> Result<(i32, u64), String> {
    run_elf_inner(elf_bytes, false)
}

fn run_elf_inner(elf_bytes: &[u8], use_cache: bool) -> Result<(i32, u64), String> {
    unsafe {
        let base: u32 = 0;

        tidemark_kernel::guest_mem::init(core::ptr::null(), core::ptr::null());

        let current_pages = core::arch::wasm32::memory_size(0);
        let target_pages = 256; // 16MB
        if current_pages < target_pages {
            let grown = core::arch::wasm32::memory_grow(0, target_pages - current_pages);
            if grown == usize::MAX {
                return Err("memory_grow failed".into());
            }
        }

        // Copy ELF to a staging area above the host binary's data.
        let elf_load_addr: u64 = 0xC0_0000;
        tidemark_kernel::guest_mem::write_bytes(base, elf_load_addr, elf_bytes);

        let elf_result = tidemark_kernel::elf::load_elf(
            base, 0x100_0000,
            (base as u64 + elf_load_addr) as u32,
            elf_bytes.len() as u32,
        ).map_err(|e| format!("ELF load failed: {}", e))?;

        // Heap at 0x200000 (2MB) — above WASM host's stack (~0x100000)
        // and static data (~0x11D000), matching test_helpers.rs layout.
        tidemark_kernel::alloc::init(0x20_0000);
        tidemark_kernel::syscall::memory::init(elf_result.brk_start);
        tidemark_kernel::syscall::signal::init();
        tidemark_kernel::syscall::epoll::init();
        tidemark_kernel::syscall::pipe::init();
        tidemark_kernel::fs::fd_table::init();
        tidemark_kernel::fs::memfs::init();

        let random_addr = 0xBF_FF00u64;
        tidemark_kernel::guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);

        let argv0_addr = 0xBF_FE00u64;
        tidemark_kernel::guest_mem::write_bytes(base, argv0_addr, b"test\0");

        let sp = tidemark_kernel::elf::setup_stack(
            base, 0xBF_FD00, &[argv0_addr], &[], &elf_result, random_addr,
        );

        let mut vm: ThreadState = core::mem::zeroed();
        vm.pc = elf_result.entry;
        vm.x[2] = sp;
        vm.status = STATUS_OK;
        vm.tid = 1;

        // Allocate ProcessState in guest Memory via brk (not alloc.rs).
        let ps_size = core::mem::size_of::<ProcessState>() as u64;
        let ps_align = core::mem::align_of::<ProcessState>() as u64;
        let brk = tidemark_kernel::syscall::memory::current_brk();
        let ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
        let brk_ret = tidemark_kernel::syscall::memory::grow_brk(base, ps_addr + ps_size);
        if brk_ret < (ps_addr + ps_size) as i64 {
            return Err("ProcessState brk allocation failed".into());
        }
        tidemark_kernel::guest_mem::zero_mem(base, ps_addr, ps_size as usize);
        vm.process_ptr = ps_addr as u32;

        let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + pid_off, 1);

        let fd_off = 0u64;
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + fd_off + 0, 1);
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + fd_off + 8, 2);
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + fd_off + 16, 3);

        let cache_size = tidemark_kernel::cpu::block_cache::BlockCache::allocation_size() as u32;
        let cache_ptr = if use_cache {
            tidemark_kernel::alloc::alloc_zeroed(cache_size, 8)
        } else { 0 };
        let mut cache = if use_cache {
            Some(tidemark_kernel::cpu::block_cache::BlockCache::from_ptr(
                cache_ptr as *mut tidemark_kernel::cpu::block_cache::BlockEntry
            ))
        } else { None };

        let mut total = 0i64;
        loop {
            let budget = 500_000i32;
            vm.status = STATUS_OK;
            let rem = tidemark_kernel::cpu::exec(&mut vm, budget, cache.as_mut(), None, None, None);
            total += (budget - rem) as i64;

            match vm.status {
                STATUS_OK => {
                    if total > 50_000_000 { return Ok((-999, vm.pc)); }
                }
                STATUS_FAULT => return Ok((vm.exit_code, vm.pc)),
                STATUS_SLEEP => {}
                _ => return Ok((-vm.status, vm.pc)),
            }
        }
    }
}

pub fn assert_elf_pass(name: &str, elf_bytes: &[u8]) -> Result<(), String> {
    let (code, pc) = run_elf(elf_bytes)?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{} failed: exit_code={}, last_pc=0x{:x}", name, code, pc))
    }
}

pub fn assert_elf_pass_no_cache(name: &str, elf_bytes: &[u8]) -> Result<(), String> {
    let (code, pc) = run_elf_no_cache(elf_bytes)?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{} (no cache) failed: exit_code={}, last_pc=0x{:x}", name, code, pc))
    }
}
