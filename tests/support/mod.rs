//! ELF test helpers for integration tests.
//! Each filtered wasm32-wasip1 test run executes in a fresh wasmtime process,
//! so the guest layout can stay fixed.
//!
//! Uses Result<(), String> to avoid panics (wasm32-wasip1 uses panic=abort,
//! so any panic causes a WASM trap that terminates the entire test binary).

use tidemark_kernel::abi::*;
use tidemark_kernel::types::*;

const GUEST_RAM_BASE: u32 = 0x20_0000;
const GUEST_RAM_SIZE: u32 = 0x100_0000;
const HOST_HEAP_BASE: u32 = GUEST_RAM_BASE + GUEST_RAM_SIZE + 0x20_0000;
const TEST_MEMORY_PAGES: usize = 512; // 32 MiB
const INITIAL_PID: i32 = 2;
const INITIAL_PPID: i32 = 1;

fn ensure_dir(parent_ino: u32, name: &[u8], mode: u32) -> Result<u32, String> {
    let ino = tidemark_kernel::fs::memfs::lookup(parent_ino, name);
    if ino != 0 {
        return Ok(ino);
    }

    let ino = tidemark_kernel::fs::memfs::create_dir(parent_ino, name, mode);
    if ino == 0 {
        return Err(format!("failed to create directory {:?}", name));
    }
    Ok(ino)
}

fn ensure_file(parent_ino: u32, name: &[u8], data: &[u8], mode: u32) -> Result<u32, String> {
    let ino = match tidemark_kernel::fs::memfs::lookup(parent_ino, name) {
        0 => {
            let ino = tidemark_kernel::fs::memfs::create_file(parent_ino, name, mode);
            if ino == 0 {
                return Err(format!("failed to create file {:?}", name));
            }
            ino
        }
        ino => ino,
    };

    let truncate_ret = tidemark_kernel::fs::memfs::truncate(ino, 0);
    if truncate_ret != 0 {
        return Err(format!("failed to truncate file {:?}: {}", name, truncate_ret));
    }

    let written = tidemark_kernel::fs::memfs::write_file(ino, 0, data);
    if written != data.len() as i64 {
        return Err(format!(
            "failed to populate file {:?}: wrote {} of {} bytes",
            name,
            written,
            data.len()
        ));
    }

    Ok(ino)
}

fn proc_meminfo() -> String {
    let total_kib = tidemark_kernel::syscall::identity::SYSINFO_TOTALRAM_BYTES / 1024;
    let free_kib = tidemark_kernel::syscall::identity::SYSINFO_FREERAM_BYTES / 1024;
    format!(
        "MemTotal: {total_kib} kB\nMemFree: {free_kib} kB\nMemAvailable: {free_kib} kB\nCached: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
    )
}

fn proc_pid_max() -> String {
    format!("{}\n", tidemark_kernel::abi::MAX_PROCESSES)
}

fn allocate_cache(
    use_cache: bool,
) -> Option<tidemark_kernel::cpu::block_cache::BlockCache> {
    if !use_cache {
        return None;
    }

    let cache_size = tidemark_kernel::cpu::block_cache::BlockCache::allocation_size() as u32;
    let cache_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(cache_size, 8) };
    Some(unsafe {
        tidemark_kernel::cpu::block_cache::BlockCache::from_ptr(
            cache_ptr as *mut tidemark_kernel::cpu::block_cache::BlockEntry,
        )
    })
}

fn process_pid(base: u32, process_ptr: u32) -> i32 {
    let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
    unsafe { tidemark_kernel::guest_mem::read_i32(base, process_ptr as u64 + pid_off) }
}

fn set_process_identity(base: u32, process_ptr: u32, pid: i32, ppid: i32) {
    let ps_addr = process_ptr as u64;
    let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
    let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
    let thread_count_off = core::mem::offset_of!(ProcessState, thread_count) as u64;

    unsafe {
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + pid_off, pid as u32);
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + ppid_off, ppid as u32);
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + thread_count_off, 1);
    }
}

fn guest_window_size(base: u32) -> usize {
    let mem_size = (core::arch::wasm32::memory_size(0) as usize) * 65536;
    let guest_window_end = HOST_HEAP_BASE as usize;
    guest_window_end
        .saturating_sub(base as usize)
        .min(mem_size.saturating_sub(base as usize))
}

fn snapshot_guest_memory(base: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; guest_window_size(base)];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(base, 0, &mut bytes);
    }
    bytes
}

fn run_vm(vm: &mut ThreadState, base: u32, use_cache: bool) -> Result<(i32, u64), String> {
    let mut cache = allocate_cache(use_cache);
    let mut total = 0i64;

    loop {
        let budget = 500_000i32;
        vm.status = STATUS_OK;
        let rem = unsafe {
            tidemark_kernel::cpu::exec_at_base(vm, budget, base, cache.as_mut(), None, None, None)
        };
        total += (budget - rem) as i64;

        match vm.status {
            STATUS_OK => {
                if total > 50_000_000 {
                    return Ok((-999, vm.pc));
                }
            }
            STATUS_FAULT => return Ok((vm.exit_code, vm.pc)),
            STATUS_SLEEP => {}
            STATUS_EXECVE_SPAWN if vm.x[17] == SYS_CLONE => {
                handle_plain_fork(vm, base, use_cache)?;
            }
            _ => return Ok((-vm.status, vm.pc)),
        }
    }
}

fn handle_plain_fork(parent_vm: &mut ThreadState, base: u32, use_cache: bool) -> Result<(), String> {
    let child_pid = parent_vm.x[10] as i32;
    if child_pid <= 0 {
        return Err(format!("fork returned invalid child pid {}", child_pid));
    }

    let process_ptr = parent_vm.process_ptr;
    if process_ptr == 0 {
        return Err("fork without ProcessState".into());
    }

    let parent_pid = process_pid(base, process_ptr);
    let parent_memory = snapshot_guest_memory(base);
    let parent_mm_state = tidemark_kernel::runtime_test_support::snapshot_plain_fork();

    tidemark_kernel::fs::fd_table::retain_fds_for_fork(base, parent_vm);
    tidemark_kernel::syscall::signal::fork_from_parent(parent_pid, child_pid);

    let mut child_vm = unsafe { core::ptr::read(parent_vm as *const ThreadState) };
    child_vm.x[10] = 0;
    child_vm.tid = child_pid;
    child_vm.status = STATUS_OK;
    child_vm.exit_code = 0;
    child_vm.sig_pending = 0;
    child_vm.clear_child_tid = 0;

    set_process_identity(base, process_ptr, child_pid, parent_pid);

    let (child_exit, _child_pc) = run_vm(&mut child_vm, base, use_cache)?;
    tidemark_kernel::syscall::process::record_child_exit(child_pid, child_exit);

    tidemark_kernel::runtime_test_support::restore_plain_fork_parent(
        base,
        guest_window_size(base) as u64,
        &parent_memory,
        &parent_mm_state,
    );
    parent_vm.status = STATUS_OK;
    parent_vm.x[10] = child_pid as u64;

    Ok(())
}

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
        let base = GUEST_RAM_BASE;

        tidemark_kernel::guest_mem::init(core::ptr::null(), core::ptr::null());

        let current_pages = core::arch::wasm32::memory_size(0);
        let target_pages = TEST_MEMORY_PAGES;
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
            base,
            GUEST_RAM_SIZE as u64,
            (base as u64 + elf_load_addr) as u32,
            elf_bytes.len() as u32,
        )
        .map_err(|e| format!("ELF load failed: {}", e))?;

        // Keep kernel-private allocations outside the guest RAM window.
        tidemark_kernel::alloc::init(HOST_HEAP_BASE);
        let guest_brk_start = elf_result.brk_start;
        tidemark_kernel::syscall::memory::init(guest_brk_start);
        tidemark_kernel::syscall::signal::init();
        tidemark_kernel::syscall::epoll::init();
        tidemark_kernel::syscall::pipe::init();
        tidemark_kernel::syscall::socket::init();
        tidemark_kernel::fs::fd_table::init();
        tidemark_kernel::fs::memfs::init();
        let tmp_ino = ensure_dir(1, b"tmp", 0o1777)?;
        let dev_ino = ensure_dir(1, b"dev", 0o755)?;
        let proc_ino = ensure_dir(1, b"proc", 0o555)?;
        let proc_sys_ino = ensure_dir(proc_ino, b"sys", 0o555)?;
        let proc_kernel_ino = ensure_dir(proc_sys_ino, b"kernel", 0o555)?;
        let _ = ensure_dir(dev_ino, b"shm", 0o1777)?;
        let _ = ensure_file(proc_ino, b"meminfo", proc_meminfo().as_bytes(), 0o444)?;
        let _ = ensure_file(
            proc_kernel_ino,
            b"pid_max",
            proc_pid_max().as_bytes(),
            0o444,
        )?;
        let _ = tmp_ino;

        let random_addr = 0xBF_FF00u64;
        tidemark_kernel::guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);

        let argv0_addr = 0xBF_FE00u64;
        tidemark_kernel::guest_mem::write_bytes(base, argv0_addr, b"test\0");

        let sp = tidemark_kernel::elf::setup_stack(
            base,
            0xBF_FD00,
            &[argv0_addr],
            &[],
            &elf_result,
            random_addr,
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
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + pid_off, INITIAL_PID as u32);
        let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + ppid_off, INITIAL_PPID as u32);
        let cwd_off = core::mem::offset_of!(ProcessState, cwd_ino) as u64;
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + cwd_off, 1);
        tidemark_kernel::syscall::signal::init_for_process(INITIAL_PID);

        let fd_off = 0u64;
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + fd_off + 0, 1);
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + fd_off + 8, 2);
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + fd_off + 16, 3);

        let cache_size = tidemark_kernel::cpu::block_cache::BlockCache::allocation_size() as u32;
        let cache_ptr = if use_cache {
            tidemark_kernel::alloc::alloc_zeroed(cache_size, 8)
        } else {
            0
        };

        run_vm(&mut vm, base, use_cache)
    }
}

pub fn assert_elf_pass(name: &str, elf_bytes: &[u8]) -> Result<(), String> {
    let (code, pc) = run_elf(elf_bytes)?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{} failed: exit_code={}, last_pc=0x{:x}",
            name, code, pc
        ))
    }
}

pub fn assert_elf_pass_no_cache(name: &str, elf_bytes: &[u8]) -> Result<(), String> {
    let (code, pc) = run_elf_no_cache(elf_bytes)?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{} (no cache) failed: exit_code={}, last_pc=0x{:x}",
            name, code, pc
        ))
    }
}
