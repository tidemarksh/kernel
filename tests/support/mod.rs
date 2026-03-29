//! ELF test helpers for integration tests.
//! Each filtered wasm32-wasip1 test run executes in a fresh wasmtime process,
//! so the guest layout can stay fixed.
//!
//! Uses Result<(), String> to avoid panics (wasm32-wasip1 uses panic=abort,
//! so any panic causes a WASM trap that terminates the entire test binary).

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tidemark_kernel::abi::*;
use tidemark_kernel::types::*;

const GUEST_RAM_SIZE: u32 = 0x100_0000;
const GUEST_RAM_ALIGN: u32 = 0x20_0000;
const GUEST_BASE_PADDING: u32 = 0x080_00000;
// The LTP harness still uses std-backed Vec/String allocations after kernel
// init (for example guest-memory snapshots during plain-fork handling). Keep
// the kernel bump heap far enough above the WASI heap to avoid aliasing.
const HOST_HEAP_PADDING: u32 = 0x400_0000;
const GUEST_SNAPSHOT_CHUNK: usize = 64 * 1024;
const TEST_MEMORY_PAGES: usize = 512; // 32 MiB
const INITIAL_PID: i32 = 2;
const INITIAL_PPID: i32 = 1;
const MAX_VM_INSTRUCTIONS: i64 = 500_000_000;

static NEXT_GUEST_SNAPSHOT_ID: AtomicU64 = AtomicU64::new(1);

struct DeferredPlainFork {
    pid: i32,
    vm: ThreadState,
    guest_memory: GuestMemorySnapshot,
    mm_state: tidemark_kernel::runtime_test_support::PlainForkSnapshot,
}

enum VmRunOutcome {
    Exited(i32, u64),
    Deferred(u64),
}

struct HostHelperBinary {
    name: String,
    bytes: Vec<u8>,
}

struct GuestMemorySnapshot {
    path: PathBuf,
    len: usize,
}

impl GuestMemorySnapshot {
    fn capture(base: u32) -> Result<Self, String> {
        let len = guest_window_size(base);
        let mut path = PathBuf::from("/tmp");
        let id = NEXT_GUEST_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "tidemark-guest-snapshot-{}.bin",
            id
        ));

        let mut file =
            File::create(&path).map_err(|e| format!("failed to create {}: {}", path.display(), e))?;
        let mut buf = vec![0u8; GUEST_SNAPSHOT_CHUNK];
        let mut off = 0usize;
        while off < len {
            let chunk = (len - off).min(buf.len());
            unsafe {
                tidemark_kernel::guest_mem::read_bytes(base, off as u64, &mut buf[..chunk]);
            }
            file.write_all(&buf[..chunk])
                .map_err(|e| format!("failed to write {}: {}", path.display(), e))?;
            off += chunk;
        }
        file.flush()
            .map_err(|e| format!("failed to flush {}: {}", path.display(), e))?;

        Ok(Self { path, len })
    }

    fn restore(&self, base: u32) -> Result<(), String> {
        let mut file =
            File::open(&self.path).map_err(|e| format!("failed to open {}: {}", self.path.display(), e))?;
        let mut buf = vec![0u8; GUEST_SNAPSHOT_CHUNK];
        let mut off = 0usize;
        while off < self.len {
            let chunk = (self.len - off).min(buf.len());
            file.read_exact(&mut buf[..chunk])
                .map_err(|e| format!("failed to read {}: {}", self.path.display(), e))?;
            unsafe {
                tidemark_kernel::guest_mem::write_bytes(base, off as u64, &buf[..chunk]);
            }
            off += chunk;
        }
        Ok(())
    }

    fn read_i32(&self, guest_addr: usize) -> Result<i32, String> {
        let end = guest_addr
            .checked_add(core::mem::size_of::<i32>())
            .ok_or_else(|| "snapshot offset overflow".to_string())?;
        if end > self.len {
            return Err(format!(
                "snapshot read out of range: off={} len={}",
                guest_addr, self.len
            ));
        }

        let mut file =
            File::open(&self.path).map_err(|e| format!("failed to open {}: {}", self.path.display(), e))?;
        file.seek(SeekFrom::Start(guest_addr as u64))
            .map_err(|e| format!("failed to seek {}: {}", self.path.display(), e))?;
        let mut bytes = [0u8; 4];
        file.read_exact(&mut bytes)
            .map_err(|e| format!("failed to read {}: {}", self.path.display(), e))?;
        Ok(i32::from_le_bytes(bytes))
    }
}

impl Drop for GuestMemorySnapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

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
        return Err(format!(
            "failed to truncate file {:?}: {}",
            name, truncate_ret
        ));
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
const PROC_MEMINFO_BYTES: &[u8] =
    b"MemTotal: 262144 kB\nMemFree: 131072 kB\nMemAvailable: 131072 kB\nCached: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n";
const PROC_PID1_STAT_BYTES: &[u8] = b"1 (init) S 0 1\n";
const ETC_PASSWD_BYTES: &[u8] = b"root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/bin/sh\ndaemon:x:2:2:daemon:/usr/sbin:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/sh\n";
const ETC_GROUP_BYTES: &[u8] = b"root:x:0:\nbin:x:1:\ndaemon:x:2:\nnobody:x:65534:\n";

fn proc_kernel_tainted() -> &'static str {
    "0\n"
}

fn write_i32_decimal(value: i32, buf: &mut [u8]) -> usize {
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut n = value.unsigned_abs();
    let mut rev = [0u8; 10];
    let mut rev_len = 0usize;
    while n != 0 {
        rev[rev_len] = b'0' + (n % 10) as u8;
        rev_len += 1;
        n /= 10;
    }

    let mut pos = 0usize;
    if value < 0 {
        buf[pos] = b'-';
        pos += 1;
    }
    for idx in (0..rev_len).rev() {
        buf[pos] = rev[idx];
        pos += 1;
    }
    pos
}

fn proc_pid_max_bytes(buf: &mut [u8; 24]) -> &[u8] {
    let mut len = write_i32_decimal(tidemark_kernel::abi::MAX_PROCESSES as i32, buf);
    buf[len] = b'\n';
    len += 1;
    &buf[..len]
}

fn proc_pid_stat_bytes<'a>(
    pid: i32,
    ppid: i32,
    state: u8,
    pgrp: i32,
    buf: &'a mut [u8; 64],
) -> &'a [u8] {
    let mut pos = 0usize;
    pos += write_i32_decimal(pid, &mut buf[pos..]);
    buf[pos..pos + 6].copy_from_slice(b" (proc");
    pos += 6;
    pos += write_i32_decimal(pid, &mut buf[pos..]);
    buf[pos..pos + 2].copy_from_slice(b") ");
    pos += 2;
    buf[pos] = state;
    pos += 1;
    buf[pos] = b' ';
    pos += 1;
    pos += write_i32_decimal(ppid, &mut buf[pos..]);
    buf[pos] = b' ';
    pos += 1;
    pos += write_i32_decimal(pgrp, &mut buf[pos..]);
    buf[pos] = b'\n';
    pos += 1;
    &buf[..pos]
}

fn ensure_proc_pid_stat(pid: i32, ppid: i32, state: u8, pgrp: i32) -> Result<(), String> {
    let proc_ino = ensure_dir(1, b"proc", 0o555)?;
    let mut pid_dir_name = [0u8; 16];
    let pid_dir_name_len = write_i32_decimal(pid, &mut pid_dir_name);
    let pid_ino = ensure_dir(proc_ino, &pid_dir_name[..pid_dir_name_len], 0o555)?;
    let mut stat = [0u8; 64];
    let stat_bytes = proc_pid_stat_bytes(pid, ppid, state, pgrp, &mut stat);
    let _ = ensure_file(pid_ino, b"stat", stat_bytes, 0o444)?;
    Ok(())
}

fn load_ltp_helper_binaries() -> Result<Vec<HostHelperBinary>, String> {
    let ltp_dir = std::path::Path::new(env!("OUT_DIR")).join("ltp");
    let entries = match std::fs::read_dir(&ltp_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("failed to list {}: {}", ltp_dir.display(), err)),
    };

    let mut helpers = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read {}: {}", ltp_dir.display(), e))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("failed to stat {}: {}", entry.path().display(), e))?;
        if !file_type.is_file() {
            continue;
        }

        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| format!("non-utf8 LTP binary name: {:?}", name))?;
        if !name.ends_with("_child") {
            continue;
        }

        let bytes = std::fs::read(entry.path())
            .map_err(|e| format!("failed to read {}: {}", entry.path().display(), e))?;
        helpers.push(HostHelperBinary {
            name: name.to_string(),
            bytes,
        });
    }

    helpers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(helpers)
}

fn stage_ltp_helper_binaries(bin_ino: u32, helpers: &[HostHelperBinary]) -> Result<(), String> {
    for helper in helpers {
        let _ = ensure_file(1, helper.name.as_bytes(), &helper.bytes, 0o755)?;
        let _ = ensure_file(bin_ino, helper.name.as_bytes(), &helper.bytes, 0o755)?;
    }

    Ok(())
}

fn allocate_cache(use_cache: bool) -> Option<tidemark_kernel::cpu::block_cache::BlockCache> {
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

fn process_ppid(base: u32, process_ptr: u32) -> i32 {
    let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
    unsafe { tidemark_kernel::guest_mem::read_i32(base, process_ptr as u64 + ppid_off) }
}

fn process_pgid(vm: &ThreadState, base: u32) -> i32 {
    let pgid = tidemark_kernel::syscall::process::sys_getpgid(vm, base, 0);
    if pgid > 0 {
        pgid as i32
    } else if vm.process_ptr != 0 {
        process_pid(base, vm.process_ptr)
    } else {
        0
    }
}

fn refresh_proc_pid_stat(vm: &ThreadState, base: u32, state: u8) -> Result<(), String> {
    if vm.process_ptr == 0 {
        return Ok(());
    }
    let pid = process_pid(base, vm.process_ptr);
    let ppid = process_ppid(base, vm.process_ptr);
    let pgrp = process_pgid(vm, base);
    ensure_proc_pid_stat(pid, ppid, state, pgrp)
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
    (GUEST_RAM_SIZE as usize).min(mem_size.saturating_sub(base as usize))
}

fn snapshot_guest_memory(base: u32) -> Result<GuestMemorySnapshot, String> {
    GuestMemorySnapshot::capture(base)
}

fn child_wait_status(vm: &ThreadState, exit_code: i32) -> i32 {
    if vm.term_signal != 0 {
        vm.term_signal
    } else {
        ((exit_code as u32) << 8) as i32
    }
}

fn snapshot_pid(snapshot: &GuestMemorySnapshot, process_ptr: u32) -> Result<i32, String> {
    let off = process_ptr as usize + core::mem::offset_of!(ProcessState, pid);
    snapshot.read_i32(off)
}

fn run_vm(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
) -> Result<(i32, u64), String> {
    match run_vm_inner(vm, base, use_cache, deferred_plain_forks, false)? {
        VmRunOutcome::Exited(code, pc) => Ok((code, pc)),
        VmRunOutcome::Deferred(pc) => {
            Err(format!("top-level VM deferred unexpectedly at 0x{pc:x}"))
        }
    }
}

fn run_vm_inner(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
    allow_plain_fork_defer: bool,
) -> Result<VmRunOutcome, String> {
    let mut cache = allocate_cache(use_cache);
    let mut total = 0i64;
    let vm_ptr = vm as *mut ThreadState as u32;
    let mut vfork_child_active = false;

    loop {
        let budget = 500_000i32;
        vm.status = STATUS_OK;
        let rem = unsafe {
            tidemark_kernel::cpu::exec_at_base(vm, budget, base, cache.as_mut(), None, None, None)
        };
        total += (budget - rem) as i64;

        match vm.status {
            STATUS_OK => {
                if allow_plain_fork_defer && rem == 0 {
                    return Ok(VmRunOutcome::Deferred(vm.pc));
                }
                if total > MAX_VM_INSTRUCTIONS {
                    if allow_plain_fork_defer {
                        return Ok(VmRunOutcome::Deferred(vm.pc));
                    }
                    let pid = if vm.process_ptr != 0 {
                        process_pid(base, vm.process_ptr)
                    } else {
                        -1
                    };
                    return Err(format!(
                        "instruction budget exhausted pid={} pc=0x{:x} ra=0x{:x} sp=0x{:x} s0=0x{:x} a0=0x{:x}",
                        pid, vm.pc, vm.x[1], vm.x[2], vm.x[8], vm.x[10]
                    ));
                }
            }
            STATUS_FS => {
                tidemark_kernel::syscall::fs::process_pending_requests(vm_ptr, base);
                tidemark_kernel::syscall::fs::resume_from_fs(vm_ptr, base);
            }
            STATUS_VFORK_WAIT => {
                vfork_child_active = true;
            }
            STATUS_EXECVE_SPAWN => {
                handle_process_spawn(
                    vm,
                    base,
                    use_cache,
                    vfork_child_active,
                    deferred_plain_forks,
                )?;
                vfork_child_active = false;
            }
            STATUS_CLONE_SPAWN => {
                let child_ptr = tidemark_kernel::syscall::thread::spawn_from_clone(vm_ptr, base);
                if child_ptr == 0 {
                    return Err("spawn_from_clone failed".into());
                }
                let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
                match run_vm_inner(child_vm, base, use_cache, deferred_plain_forks, true)? {
                    VmRunOutcome::Exited(_, _) => {}
                    VmRunOutcome::Deferred(_) => {}
                }
                vm.status = STATUS_OK;
            }
            STATUS_WAIT4 if allow_plain_fork_defer => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_WAIT4 => {
                service_blocked_wait4(vm, base, use_cache, deferred_plain_forks)?;
            }
            STATUS_FUTEX_WAIT if allow_plain_fork_defer => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                if vm.process_ptr != 0 {
                    tidemark_kernel::runtime_test_support::register_plain_fork_futex_wait(
                        process_pid(base, vm.process_ptr),
                        vm.x[10] as u32,
                    );
                }
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_FUTEX_WAIT => {
                service_blocked_futex_wait(vm, base, use_cache, deferred_plain_forks)?;
            }
            STATUS_FAULT if vfork_child_active => {
                let child_pid = tidemark_kernel::syscall::process::vfork_child_pid();
                if child_pid <= 0 {
                    return Err("vfork child exited without an allocated child pid".into());
                }
                tidemark_kernel::syscall::process::record_child_exit(
                    child_pid,
                    child_wait_status(vm, vm.exit_code),
                );
                tidemark_kernel::syscall::process::vfork_parent_resume(vm, child_pid);
                vfork_child_active = false;
            }
            STATUS_FAULT => return Ok(VmRunOutcome::Exited(vm.exit_code, vm.pc)),
            STATUS_SLEEP if allow_plain_fork_defer => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_SLEEP => {}
            _ => return Ok(VmRunOutcome::Exited(-vm.status, vm.pc)),
        }
    }
}

fn handle_process_spawn(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    vfork_child_active: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
) -> Result<(), String> {
    match vm.spawn_kind {
        SPAWN_KIND_FORK => handle_plain_fork(vm, base, use_cache, deferred_plain_forks),
        SPAWN_KIND_EXECVE if vfork_child_active => {
            handle_vfork_execve_spawn(vm, base, use_cache, deferred_plain_forks)
        }
        SPAWN_KIND_EXECVE => Err("unexpected execve spawn outside vfork path".into()),
        kind => Err(format!(
            "unsupported spawn_kind {} for STATUS_EXECVE_SPAWN",
            kind
        )),
    }
}

fn handle_plain_fork(
    parent_vm: &mut ThreadState,
    base: u32,
    _use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
) -> Result<(), String> {
    let child_pid = parent_vm.x[10] as i32;
    if child_pid <= 0 {
        return Err(format!("fork returned invalid child pid {}", child_pid));
    }

    let process_ptr = parent_vm.process_ptr;
    if process_ptr == 0 {
        return Err("fork without ProcessState".into());
    }

    tidemark_kernel::syscall::memory::flush_shared_mappings(base);

    let parent_pid = process_pid(base, process_ptr);
    let parent_memory = snapshot_guest_memory(base)?;
    let snapshot_parent_pid = snapshot_pid(&parent_memory, process_ptr)?;
    if snapshot_parent_pid != parent_pid {
        return Err(format!(
            "plain fork snapshot corrupted parent pid: expected {}, got {}",
            parent_pid, snapshot_parent_pid
        ));
    }
    let parent_mm_state = tidemark_kernel::runtime_test_support::snapshot_plain_fork();
    refresh_proc_pid_stat(parent_vm, base, b'S')?;

    tidemark_kernel::fs::fd_table::retain_fds_for_fork(base, parent_vm);
    tidemark_kernel::syscall::signal::fork_from_parent(parent_pid, child_pid);

    let fork_clone_flags = parent_vm.clone_flags;
    let fork_child_stack = parent_vm.clone_child_stack;
    let fork_tls = parent_vm.clone_tls;
    let fork_child_tidptr = parent_vm.clone_child_tidptr;
    let mut child_vm = unsafe { core::ptr::read(parent_vm as *const ThreadState) };
    child_vm.x[10] = 0;
    child_vm.tid = child_pid;
    child_vm.status = STATUS_OK;
    child_vm.exit_code = 0;
    child_vm.term_signal = 0;
    child_vm.sig_pending = 0;
    child_vm.clone_flags = 0;
    child_vm.clone_child_stack = 0;
    child_vm.clone_tls = 0;
    child_vm.clone_child_tidptr = 0;
    child_vm.clone_child_tid = 0;
    child_vm.clone_pending = 0;
    child_vm.clear_child_tid = if fork_clone_flags & CLONE_CHILD_CLEARTID != 0 {
        fork_child_tidptr
    } else {
        0
    };
    if fork_child_stack != 0 {
        child_vm.x[2] = fork_child_stack;
    }
    if fork_clone_flags & CLONE_SETTLS != 0 {
        child_vm.x[4] = fork_tls;
        child_vm.tls_base = fork_tls;
    }
    if fork_clone_flags & CLONE_CHILD_SETTID != 0 && fork_child_tidptr != 0 {
        unsafe {
            tidemark_kernel::guest_mem::write_u32(base, fork_child_tidptr, child_pid as u32);
        }
    }

    let child_ppid = if fork_clone_flags & CLONE_PARENT != 0 {
        process_ppid(base, process_ptr)
    } else {
        parent_pid
    };
    set_process_identity(base, process_ptr, child_pid, child_ppid);
    tidemark_kernel::syscall::thread::init_main_thread(
        &mut child_vm as *mut ThreadState as u32,
        base,
    );
    refresh_proc_pid_stat(&child_vm, base, b'R')?;

    if parent_pid == INITIAL_PID {
        match run_vm_inner(&mut child_vm, base, _use_cache, deferred_plain_forks, true)? {
            VmRunOutcome::Exited(child_exit, _child_pc) => {
                tidemark_kernel::runtime_test_support::clear_plain_fork_futex_wait(child_pid);
                tidemark_kernel::syscall::process::record_child_exit(
                    child_pid,
                    child_wait_status(&child_vm, child_exit),
                );
            }
            VmRunOutcome::Deferred(_child_pc) => {
                deferred_plain_forks.push_back(DeferredPlainFork {
                    pid: child_pid,
                    vm: child_vm,
                    guest_memory: snapshot_guest_memory(base)?,
                    mm_state: tidemark_kernel::runtime_test_support::snapshot_plain_fork(),
                });
            }
        }
    } else {
        // Nested plain-fork children must give their parent the first turn so
        // process-group and wait4 orchestration can follow Linux-style ordering.
        deferred_plain_forks.push_back(DeferredPlainFork {
            pid: child_pid,
            vm: child_vm,
            guest_memory: snapshot_guest_memory(base)?,
            mm_state: tidemark_kernel::runtime_test_support::snapshot_plain_fork(),
        });
    }

    tidemark_kernel::runtime_test_support::restore_plain_fork_parent(
        base,
        guest_window_size(base) as u64,
        &parent_mm_state,
        || parent_memory.restore(base),
    )?;
    let restored_pid = process_pid(base, process_ptr);
    if restored_pid != parent_pid {
        return Err(format!(
            "plain fork restore corrupted parent pid: expected {}, got {}",
            parent_pid, restored_pid
        ));
    }
    refresh_proc_pid_stat(parent_vm, base, b'R')?;
    parent_vm.clone_flags = 0;
    parent_vm.clone_child_stack = 0;
    parent_vm.clone_tls = 0;
    parent_vm.clone_child_tidptr = 0;
    parent_vm.clone_child_tid = 0;
    parent_vm.clone_pending = 0;
    parent_vm.status = STATUS_OK;
    parent_vm.x[10] = child_pid as u64;

    Ok(())
}

fn handle_vfork_execve_spawn(
    parent_vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
) -> Result<(), String> {
    let child_pid = parent_vm.spawn_child_pid;
    if child_pid <= 0 {
        return Err(format!(
            "execve spawn returned invalid child pid {}",
            child_pid
        ));
    }

    let process_ptr = parent_vm.process_ptr;
    if process_ptr == 0 {
        return Err("execve spawn without ProcessState".into());
    }

    let parent_pid = process_pid(base, process_ptr);
    let parent_memory = snapshot_guest_memory(base)?;
    let parent_mm_state = tidemark_kernel::runtime_test_support::snapshot_plain_fork();

    let mut child_vm = unsafe { core::ptr::read(parent_vm as *const ThreadState) };
    set_process_identity(base, process_ptr, child_pid, parent_pid);

    let ret = tidemark_kernel::syscall::process::complete_execve_in_place(
        &mut child_vm,
        base,
        GUEST_RAM_SIZE as u64,
    );
    if ret < 0 {
        tidemark_kernel::runtime_test_support::restore_plain_fork_parent(
            base,
            guest_window_size(base) as u64,
            &parent_mm_state,
            || parent_memory.restore(base),
        )?;
        return Err(format!("complete_execve_in_place failed with {}", ret));
    }

    child_vm.tid = child_pid;
    tidemark_kernel::syscall::thread::init_main_thread(
        &mut child_vm as *mut ThreadState as u32,
        base,
    );

    let (child_exit, _child_pc) = run_vm(&mut child_vm, base, use_cache, deferred_plain_forks)?;
    tidemark_kernel::syscall::process::record_child_exit(
        child_pid,
        child_wait_status(&child_vm, child_exit),
    );

    tidemark_kernel::runtime_test_support::restore_plain_fork_parent(
        base,
        guest_window_size(base) as u64,
        &parent_mm_state,
        || parent_memory.restore(base),
    )?;
    tidemark_kernel::syscall::process::vfork_parent_resume(parent_vm, child_pid);

    Ok(())
}

fn run_next_deferred_plain_fork(
    current_vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
) -> Result<bool, String> {
    let Some(mut deferred) = deferred_plain_forks.pop_front() else {
        return Ok(false);
    };

    let current_memory = snapshot_guest_memory(base)?;
    let current_mm_state = tidemark_kernel::runtime_test_support::snapshot_plain_fork();

    tidemark_kernel::runtime_test_support::restore_plain_fork_parent(
        base,
        guest_window_size(base) as u64,
        &deferred.mm_state,
        || deferred.guest_memory.restore(base),
    )?;
    refresh_proc_pid_stat(&deferred.vm, base, b'R')?;

    match deferred.vm.status {
        STATUS_SLEEP => deferred.vm.status = STATUS_OK,
        STATUS_WAIT4 => {
            let vm_ptr = &mut deferred.vm as *mut ThreadState as u32;
            tidemark_kernel::syscall::process::resume_wait4(vm_ptr, base);
        }
        STATUS_FUTEX_WAIT => {
            let futex_addr = deferred.vm.x[10] as u32;
            if tidemark_kernel::runtime_test_support::take_plain_fork_futex_wake(
                deferred.pid,
                futex_addr,
            ) {
                tidemark_kernel::syscall::thread::resume_futex_wait(&mut deferred.vm, base);
            } else if current_vm.status == STATUS_WAIT4 && deferred.vm.futex_wait_timeout != 0 {
                tidemark_kernel::syscall::thread::resume_futex_wait_result(
                    &mut deferred.vm,
                    base,
                    tidemark_kernel::abi::ETIMEDOUT,
                );
            } else {
                refresh_proc_pid_stat(&deferred.vm, base, b'S')?;
                deferred.guest_memory = snapshot_guest_memory(base)?;
                deferred.mm_state = tidemark_kernel::runtime_test_support::snapshot_plain_fork();
                deferred_plain_forks.push_back(deferred);
                tidemark_kernel::runtime_test_support::restore_plain_fork_parent(
                    base,
                    guest_window_size(base) as u64,
                    &current_mm_state,
                    || current_memory.restore(base),
                )?;
                current_vm.status = STATUS_OK;
                return Ok(false);
            }
        }
        _ => {}
    }

    let exited = match deferred.vm.status {
        STATUS_WAIT4 => {
            refresh_proc_pid_stat(&deferred.vm, base, b'S')?;
            deferred.guest_memory = snapshot_guest_memory(base)?;
            deferred.mm_state = tidemark_kernel::runtime_test_support::snapshot_plain_fork();
            deferred_plain_forks.push_back(deferred);
            false
        }
        _ => match run_vm_inner(
            &mut deferred.vm,
            base,
            use_cache,
            deferred_plain_forks,
            true,
        )? {
            VmRunOutcome::Exited(child_exit, _child_pc) => {
                tidemark_kernel::runtime_test_support::clear_plain_fork_futex_wait(deferred.pid);
                tidemark_kernel::syscall::process::record_child_exit(
                    deferred.pid,
                    child_wait_status(&deferred.vm, child_exit),
                );
                true
            }
            VmRunOutcome::Deferred(_child_pc) => {
                refresh_proc_pid_stat(&deferred.vm, base, b'S')?;
                deferred.guest_memory = snapshot_guest_memory(base)?;
                deferred.mm_state = tidemark_kernel::runtime_test_support::snapshot_plain_fork();
                deferred_plain_forks.push_back(deferred);
                false
            }
        },
    };

    tidemark_kernel::runtime_test_support::restore_plain_fork_parent(
        base,
        guest_window_size(base) as u64,
        &current_mm_state,
        || current_memory.restore(base),
    )?;
    current_vm.status = STATUS_OK;
    Ok(exited)
}

fn service_blocked_wait4(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
) -> Result<(), String> {
    refresh_proc_pid_stat(vm, base, b'S')?;
    let vm_ptr = vm as *mut ThreadState as u32;
    let result = (|| -> Result<(), String> {
        for _ in 0..1024 {
            if vm.status != STATUS_WAIT4 {
                return Ok(());
            }
            if deferred_plain_forks.is_empty() {
                return Err("wait4 blocked with no deferred plain-fork child".into());
            }
            let _ = run_next_deferred_plain_fork(vm, base, use_cache, deferred_plain_forks)?;
            tidemark_kernel::syscall::process::resume_wait4(vm_ptr, base);
            if vm.status != STATUS_WAIT4 {
                return Ok(());
            }
        }
        Err("wait4 remained blocked after servicing deferred plain-fork children".into())
    })();
    refresh_proc_pid_stat(vm, base, b'R')?;
    result
}

fn service_blocked_futex_wait(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
) -> Result<(), String> {
    refresh_proc_pid_stat(vm, base, b'S')?;
    let pid = if vm.process_ptr != 0 {
        process_pid(base, vm.process_ptr)
    } else {
        0
    };
    let futex_addr = vm.futex_wait_addr as u32;
    let timed_wait = vm.futex_wait_timeout != 0;
    if pid > 0 {
        tidemark_kernel::runtime_test_support::register_plain_fork_futex_wait(pid, futex_addr);
    }

    let result = (|| -> Result<(), String> {
        for _ in 0..1024 {
            if pid > 0
                && tidemark_kernel::runtime_test_support::take_plain_fork_futex_wake(pid, futex_addr)
            {
                tidemark_kernel::syscall::thread::resume_futex_wait(vm, base);
                return Ok(());
            }
            if deferred_plain_forks.is_empty() {
                if timed_wait {
                    tidemark_kernel::syscall::thread::resume_futex_wait_result(
                        vm,
                        base,
                        tidemark_kernel::abi::ETIMEDOUT,
                    );
                    return Ok(());
                }
                return Err("futex wait blocked with no deferred plain-fork child".into());
            }
            let _ = run_next_deferred_plain_fork(vm, base, use_cache, deferred_plain_forks)?;
        }
        if timed_wait {
            tidemark_kernel::syscall::thread::resume_futex_wait_result(
                vm,
                base,
                tidemark_kernel::abi::ETIMEDOUT,
            );
            return Ok(());
        }
        Err("futex wait remained blocked after servicing deferred plain-fork children".into())
    })();

    if pid > 0 {
        tidemark_kernel::runtime_test_support::clear_plain_fork_futex_wait(pid);
    }
    refresh_proc_pid_stat(vm, base, b'R')?;
    result
}

/// Load an ELF, run the interpreter with block cache, return (exit_code, last_pc).
pub fn run_elf(elf_bytes: &[u8]) -> Result<(i32, u64), String> {
    let (code, pc, _) = run_elf_inner(elf_bytes, true)?;
    Ok((code, pc))
}

pub fn run_elf_with_output(elf_bytes: &[u8]) -> Result<(i32, u64, Vec<u8>), String> {
    run_elf_inner(elf_bytes, true)
}

/// Load an ELF, run the interpreter without block cache (baseline).
pub fn run_elf_no_cache(elf_bytes: &[u8]) -> Result<(i32, u64), String> {
    let (code, pc, _) = run_elf_inner(elf_bytes, false)?;
    Ok((code, pc))
}

pub fn run_elf_no_cache_with_output(elf_bytes: &[u8]) -> Result<(i32, u64, Vec<u8>), String> {
    run_elf_inner(elf_bytes, false)
}

fn run_elf_inner(elf_bytes: &[u8], use_cache: bool) -> Result<(i32, u64, Vec<u8>), String> {
    let helper_binaries = load_ltp_helper_binaries()?;
    tidemark_kernel::runtime_test_support::clear_guest_output();
    tidemark_kernel::runtime_test_support::clear_plain_fork_futex_waits();
    let mut deferred_plain_forks = VecDeque::new();
    let result = (|| -> Result<(i32, u64), String> {
        unsafe {
            tidemark_kernel::guest_mem::init(core::ptr::null(), core::ptr::null());

            let current_pages = core::arch::wasm32::memory_size(0);
            let current_bytes = (current_pages as u32).saturating_mul(65536);
            let guest_base_hint = current_bytes.saturating_add(GUEST_BASE_PADDING);
            let base = guest_base_hint.saturating_add(GUEST_RAM_ALIGN - 1) & !(GUEST_RAM_ALIGN - 1);
            let target_pages = (((base.saturating_add(GUEST_RAM_SIZE)) + 65535) / 65536) as usize;
            let target_pages = target_pages.max(TEST_MEMORY_PAGES);
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
            // After this point, avoid std heap allocations on the success path:
            // WASI-side heap growth can alias with the kernel bump heap.
            let host_heap_base = (core::arch::wasm32::memory_size(0) as u32)
                .saturating_mul(65536)
                .saturating_add(HOST_HEAP_PADDING);
            tidemark_kernel::alloc::init(host_heap_base);
            let guest_brk_start = elf_result.brk_start;
            tidemark_kernel::syscall::time::init();
            tidemark_kernel::syscall::memory::init(guest_brk_start);
            tidemark_kernel::syscall::process::init();
            tidemark_kernel::syscall::thread::init();
            tidemark_kernel::syscall::signal::init();
            tidemark_kernel::syscall::epoll::init();
            tidemark_kernel::syscall::pipe::init();
            tidemark_kernel::syscall::socket::init();
            tidemark_kernel::net::ring_buffer::init();
            tidemark_kernel::fs::fd_table::init();
            tidemark_kernel::fs::memfs::init();
            let tmp_ino = ensure_dir(1, b"tmp", 0o1777)?;
            let bin_ino = ensure_dir(1, b"bin", 0o755)?;
            let dev_ino = ensure_dir(1, b"dev", 0o755)?;
            let etc_ino = ensure_dir(1, b"etc", 0o755)?;
            let proc_ino = ensure_dir(1, b"proc", 0o555)?;
            let proc_sys_ino = ensure_dir(proc_ino, b"sys", 0o555)?;
            let proc_kernel_ino = ensure_dir(proc_sys_ino, b"kernel", 0o555)?;
            let _ = ensure_dir(dev_ino, b"shm", 0o1777)?;
            let _ = ensure_file(etc_ino, b"passwd", ETC_PASSWD_BYTES, 0o644)?;
            let _ = ensure_file(etc_ino, b"group", ETC_GROUP_BYTES, 0o644)?;
            let meminfo_ino = match tidemark_kernel::fs::memfs::lookup(proc_ino, b"meminfo") {
                0 => {
                    let ino = tidemark_kernel::fs::memfs::create_file(proc_ino, b"meminfo", 0o444);
                    if ino == 0 {
                        return Err("failed to create meminfo".into());
                    }
                    ino
                }
                ino => ino,
            };
            let meminfo_truncate = tidemark_kernel::fs::memfs::truncate(meminfo_ino, 0);
            if meminfo_truncate != 0 {
                return Err(format!("failed to truncate meminfo: {meminfo_truncate}"));
            }
            let meminfo_written =
                tidemark_kernel::fs::memfs::write_file(meminfo_ino, 0, PROC_MEMINFO_BYTES);
            if meminfo_written != PROC_MEMINFO_BYTES.len() as i64 {
                return Err(format!(
                    "failed to write meminfo: wrote {} of {}",
                    meminfo_written,
                    PROC_MEMINFO_BYTES.len()
                ));
            }
            let mut pid_max = [0u8; 24];
            let _ = ensure_file(
                proc_kernel_ino,
                b"pid_max",
                proc_pid_max_bytes(&mut pid_max),
                0o444,
            )?;
            let _ = ensure_file(
                proc_kernel_ino,
                b"tainted",
                proc_kernel_tainted().as_bytes(),
                0o444,
            )?;
            let proc1_ino = ensure_dir(proc_ino, b"1", 0o555)?;
            let _ = ensure_file(proc1_ino, b"stat", PROC_PID1_STAT_BYTES, 0o444)?;
            ensure_proc_pid_stat(INITIAL_PID, INITIAL_PPID, b'R', INITIAL_PID)?;
            let _ = tmp_ino;
            stage_ltp_helper_binaries(bin_ino, &helper_binaries)?;
            drop(helper_binaries);

            let random_addr = 0xBF_FF00u64;
            tidemark_kernel::guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);

            let argv0_addr = 0xBF_FE00u64;
            tidemark_kernel::guest_mem::write_bytes(base, argv0_addr, b"test\0");
            let env_path_addr = 0xBF_FDE0u64;
            tidemark_kernel::guest_mem::write_bytes(base, env_path_addr, b"PATH=/bin\0");

            let sp = tidemark_kernel::elf::setup_stack(
                base,
                0xBF_FD00,
                &[argv0_addr],
                &[env_path_addr],
                &elf_result,
                random_addr,
            );

            let mut vm: ThreadState = core::mem::zeroed();
            vm.pc = elf_result.entry;
            vm.x[2] = sp;
            vm.status = STATUS_OK;
            vm.tid = INITIAL_PID;

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
            let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;
            let fs_ring_base = tidemark_kernel::alloc::alloc_zeroed(
                tidemark_kernel::fs::ring_buffer::RING_BUFFER_SIZE as u32,
                16,
            );
            tidemark_kernel::guest_mem::write_u32(base, ps_addr + fs_ring_off, fs_ring_base);
            tidemark_kernel::syscall::signal::init_for_process(INITIAL_PID);

            tidemark_kernel::fs::fd_table::init_stdio(base, &vm);
            tidemark_kernel::syscall::thread::init_main_thread(
                &mut vm as *mut ThreadState as u32,
                base,
            );

            let cache_size =
                tidemark_kernel::cpu::block_cache::BlockCache::allocation_size() as u32;
            let _cache_ptr = if use_cache {
                tidemark_kernel::alloc::alloc_zeroed(cache_size, 8)
            } else {
                0
            };

            run_vm(&mut vm, base, use_cache, &mut deferred_plain_forks)
        }
    })();
    let output = tidemark_kernel::runtime_test_support::take_guest_output();

    match result {
        Ok((code, pc)) => Ok((code, pc, output)),
        Err(err) => {
            if output.is_empty() {
                Err(err)
            } else {
                Err(format!("{err}\n{}", String::from_utf8_lossy(&output)))
            }
        }
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
