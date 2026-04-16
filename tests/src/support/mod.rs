//! ELF test helpers for integration tests.
//! Uses Result<(), String> to avoid panics (wasm32-wasip1 uses panic=abort,
//! so any panic causes a WASM trap that terminates the entire test binary).

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tidemark_kernel::abi::*;
use tidemark_kernel::guest_mem;
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

static mut TEST_GUEST_BASE: u32 = 0;
static NEXT_GUEST_SNAPSHOT_ID: AtomicU64 = AtomicU64::new(1);

struct DeferredPlainFork {
    pid: i32,
    vm: ThreadState,
    guest_memory: GuestMemorySnapshot,
    mm_state: tidemark_kernel::harness::support::PlainForkSnapshot,
}

#[derive(Clone, Copy)]
struct DeferredCloneThread {
    owner_pid: i32,
    child_ptr: u32,
}

fn enqueue_deferred_clone_thread(
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
    owner_pid: i32,
    child_ptr: u32,
) {
    if child_ptr != 0
        && !deferred_clone_threads
            .iter()
            .any(|queued| queued.owner_pid == owner_pid && queued.child_ptr == child_ptr)
    {
        deferred_clone_threads.push_back(DeferredCloneThread {
            owner_pid,
            child_ptr,
        });
    }
}

fn status_label(status: i32) -> &'static str {
    match status {
        STATUS_OK => "STATUS_OK",
        STATUS_FS => "STATUS_FS",
        STATUS_VFORK_WAIT => "STATUS_VFORK_WAIT",
        STATUS_EXECVE_SPAWN => "STATUS_EXECVE_SPAWN",
        STATUS_CLONE_SPAWN => "STATUS_CLONE_SPAWN",
        STATUS_WAIT4 => "STATUS_WAIT4",
        STATUS_FUTEX_WAIT => "STATUS_FUTEX_WAIT",
        STATUS_PIPE_WAIT => "STATUS_PIPE_WAIT",
        STATUS_FAULT => "STATUS_FAULT",
        STATUS_SLEEP => "STATUS_SLEEP",
        STATUS_EPOLL_WAIT => "STATUS_EPOLL_WAIT",
        _ => "STATUS_OTHER",
    }
}

fn describe_deferred_plain_forks(deferred_plain_forks: &VecDeque<DeferredPlainFork>) -> String {
    let mut parts = Vec::with_capacity(deferred_plain_forks.len());
    for deferred in deferred_plain_forks.iter() {
        let blocked_ofd = tidemark_kernel::fs::fd_table::get_ofd_by_id(deferred.vm.blocked_ofd_id)
            .map(|ofd| {
                format!(
                    "type={} host_fd={} status_flags=0x{:x} offset={} ino={}",
                    ofd.fd_type, ofd.host_fd, ofd.status_flags, ofd.offset, ofd.ino
                )
            })
            .unwrap_or_else(|| "missing".to_string());
        parts.push(format!(
            "pid={} status={}({}) pc=0x{:x} blocked_fd={} blocked_ofd={} [{}] a0={} a1={} a2={}",
            deferred.pid,
            deferred.vm.status,
            status_label(deferred.vm.status),
            deferred.vm.pc,
            deferred.vm.blocked_fd,
            deferred.vm.blocked_ofd_id,
            blocked_ofd,
            deferred.vm.x[10] as i64,
            deferred.vm.x[11] as i64,
            deferred.vm.x[12] as i64,
        ));
    }
    parts.join("; ")
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
    file: RefCell<File>,
    len: usize,
}

impl GuestMemorySnapshot {
    fn capture(base: u32) -> Result<Self, String> {
        let len = guest_window_size(base);
        let mut path = snapshot_root_dir();
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("failed to create {}: {}", path.display(), e))?;
        let id = NEXT_GUEST_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!("tidemark-guest-snapshot-{stamp}-{id}.bin"));

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| format!("failed to create {}: {}", path.display(), e))?;
        let mut buf = vec![0u8; GUEST_SNAPSHOT_CHUNK];
        let mut off = 0usize;
        while off < len {
            let chunk = (len - off).min(GUEST_SNAPSHOT_CHUNK);
            unsafe {
                tidemark_kernel::guest_mem::read_bytes(base, off as u64, &mut buf[..chunk]);
            }
            file.write_all(&buf[..chunk])
                .map_err(|e| format!("failed to write {}: {}", path.display(), e))?;
            off += chunk;
        }
        file.set_len(len as u64)
            .map_err(|e| format!("failed to size {}: {}", path.display(), e))?;
        file.sync_all()
            .map_err(|e| format!("failed to sync {}: {}", path.display(), e))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("failed to rewind {}: {}", path.display(), e))?;

        Ok(Self {
            path,
            file: RefCell::new(file),
            len,
        })
    }

    fn restore(&self, base: u32) -> Result<(), String> {
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("failed to rewind {}: {}", self.path.display(), e))?;
        let mut buf = vec![0u8; GUEST_SNAPSHOT_CHUNK];
        let mut off = 0usize;
        while off < self.len {
            let chunk = (self.len - off).min(buf.len());
            file.read_exact(&mut buf[..chunk]).map_err(|e| {
                format!(
                    "failed to read {}: {} (expected_len={} actual_len={})",
                    self.path.display(),
                    e,
                    self.len,
                    file.metadata().map(|m| m.len()).unwrap_or(0)
                )
            })?;
            unsafe {
                let dst = (base + off as u32) as *mut u8;
                core::ptr::copy_nonoverlapping(buf[..chunk].as_ptr(), dst, chunk);
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
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(guest_addr as u64))
            .map_err(|e| format!("failed to seek {}: {}", self.path.display(), e))?;
        let mut word = [0u8; 4];
        file.read_exact(&mut word)
            .map_err(|e| format!("failed to read {}: {}", self.path.display(), e))?;
        Ok(i32::from_le_bytes(word))
    }

    fn restore_range(&self, base: u32, guest_addr: usize, len: usize) -> Result<(), String> {
        let end = guest_addr
            .checked_add(len)
            .ok_or_else(|| "snapshot restore range overflow".to_string())?;
        if end > self.len {
            return Err(format!(
                "snapshot restore out of range: off={} len={} snapshot_len={}",
                guest_addr, len, self.len
            ));
        }
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(guest_addr as u64))
            .map_err(|e| format!("failed to seek {}: {}", self.path.display(), e))?;
        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)
            .map_err(|e| format!("failed to read {}: {}", self.path.display(), e))?;
        unsafe {
            let dst = (base + guest_addr as u32) as *mut u8;
            core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, len);
        }
        Ok(())
    }
}

fn snapshot_root_dir() -> PathBuf {
    if let Some(root) = std::env::var_os("TIDEMARK_KERNEL_ROOT") {
        let mut path = PathBuf::from(root);
        path.push("target");
        path.push("tidemark-snapshots");
        return path;
    }

    let mut path = PathBuf::from("target");
    path.push("tidemark-snapshots");
    path
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
const PROC_CPUINFO_BYTES: &[u8] =
    b"processor\t: 0\nhart\t\t: 0\nisa\t\t: rv64imafdc_zicsr_zifencei_zmmul_zaamo_zalrsc_zca_zcd\nmmu\t\t: sv39\n";
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

fn remove_proc_pid_task_entry(task_ino: u32, tid: i32) {
    let mut tid_name = [0u8; 16];
    let tid_name_len = write_i32_decimal(tid, &mut tid_name);
    let tid_name = &tid_name[..tid_name_len];
    let tid_ino = tidemark_kernel::fs::memfs::lookup(task_ino, tid_name);
    if tid_ino == 0 {
        return;
    }
    let _ = tidemark_kernel::fs::memfs::unlink(tid_ino, b"stat");
    let _ = tidemark_kernel::fs::memfs::rmdir(task_ino, tid_name);
}

fn proc_thread_state_char(
    vm: &ThreadState,
    base: u32,
    record: &ThreadRecord,
    current_state: u8,
) -> Option<u8> {
    if record.tid <= 0 || matches!(record.state, THREAD_NONE | THREAD_DEAD) {
        return None;
    }
    if record.tid == vm.tid {
        return Some(current_state);
    }

    let state = match record.state {
        THREAD_BLOCKED_FUTEX | THREAD_BLOCKED_POLL | THREAD_EXITING => b'S',
        THREAD_STARTING => b'R',
        THREAD_RUNNING => {
            if record.thread_ptr != 0 {
                let thread_vm = unsafe { &*(record.thread_ptr as *const ThreadState) };
                match thread_vm.status {
                    STATUS_SLEEP | STATUS_WAIT4 | STATUS_FUTEX_WAIT | STATUS_PIPE_WAIT
                    | STATUS_EPOLL_WAIT => b'S',
                    _ => b'R',
                }
            } else {
                b'R'
            }
        }
        _ => b'R',
    };
    let _ = base;
    Some(state)
}

fn proc_state_for_tid(vm: &ThreadState, base: u32, tid: i32, current_state: u8) -> Option<u8> {
    if vm.process_ptr == 0 || tid <= 0 || tid as usize > MAX_THREADS {
        return None;
    }

    let ps = unsafe { &*((base as u64 + vm.process_ptr as u64) as *const ProcessState) };
    let record = &ps.threads[(tid - 1) as usize];
    proc_thread_state_char(vm, base, record, current_state)
}

fn ensure_proc_pid_task_entries(
    vm: &ThreadState,
    base: u32,
    current_state: u8,
) -> Result<(), String> {
    if vm.process_ptr == 0 {
        return Ok(());
    }

    let pid = process_pid(base, vm.process_ptr);
    let ppid = process_ppid(base, vm.process_ptr);
    let pgrp = process_pgid(vm, base);

    let proc_ino = ensure_dir(1, b"proc", 0o555)?;
    let mut pid_dir_name = [0u8; 16];
    let pid_dir_name_len = write_i32_decimal(pid, &mut pid_dir_name);
    let pid_ino = ensure_dir(proc_ino, &pid_dir_name[..pid_dir_name_len], 0o555)?;
    let task_ino = ensure_dir(pid_ino, b"task", 0o555)?;

    let ps = unsafe { &*((base as u64 + vm.process_ptr as u64) as *const ProcessState) };
    let mut present = [false; MAX_THREADS + 1];

    for record in ps.threads.iter() {
        let Some(state) = proc_thread_state_char(vm, base, record, current_state) else {
            continue;
        };
        let tid = record.tid;
        if tid <= 0 || tid as usize > MAX_THREADS {
            continue;
        }
        present[tid as usize] = true;

        let mut tid_name = [0u8; 16];
        let tid_name_len = write_i32_decimal(tid, &mut tid_name);
        let tid_ino = ensure_dir(task_ino, &tid_name[..tid_name_len], 0o555)?;
        let mut stat = [0u8; 64];
        let stat_bytes = proc_pid_stat_bytes(tid, ppid, state, pgrp, &mut stat);
        let _ = ensure_file(tid_ino, b"stat", stat_bytes, 0o444)?;
    }

    for tid in 1..=MAX_THREADS as i32 {
        if !present[tid as usize] {
            remove_proc_pid_task_entry(task_ino, tid);
        }
    }

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

fn vm_pid(vm: &ThreadState, base: u32) -> i32 {
    if vm.process_ptr != 0 {
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
    let leader_state = proc_state_for_tid(vm, base, pid, state).unwrap_or(state);
    ensure_proc_pid_stat(pid, ppid, leader_state, pgrp)?;
    ensure_proc_pid_task_entries(vm, base, state)
}

fn describe_process_threads(vm: &ThreadState, base: u32) -> String {
    if vm.process_ptr == 0 {
        return "process_ptr=0".to_string();
    }
    let ps = unsafe { &*((base as u64 + vm.process_ptr as u64) as *const ProcessState) };
    let thread_count = ps.thread_count.load(std::sync::atomic::Ordering::Acquire);
    let mut parts = Vec::new();
    for record in ps.threads.iter() {
        if matches!(record.state, THREAD_NONE | THREAD_DEAD) {
            continue;
        }
        parts.push(format!(
            "tid={} state={} thread_ptr=0x{:x} blocked=0x{:x} clear_child_tid=0x{:x}",
            record.tid,
            record.state,
            record.thread_ptr,
            record.blocked_addr,
            record.clear_child_tid
        ));
    }
    format!("thread_count={} [{}]", thread_count, parts.join(" | "))
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

fn restore_process_state_snapshot(
    snapshot: &GuestMemorySnapshot,
    base: u32,
    process_ptr: u32,
) -> Result<(), String> {
    snapshot.restore_range(
        base,
        process_ptr as usize,
        core::mem::size_of::<ProcessState>(),
    )?;

    let pid_off = process_ptr as usize + core::mem::offset_of!(ProcessState, pid);
    let ppid_off = process_ptr as usize + core::mem::offset_of!(ProcessState, ppid);
    let thread_count_off = process_ptr as usize + core::mem::offset_of!(ProcessState, thread_count);
    let pid = snapshot.read_i32(pid_off)? as u32;
    let ppid = snapshot.read_i32(ppid_off)? as u32;
    let thread_count = snapshot.read_i32(thread_count_off)? as u32;

    unsafe {
        guest_mem::write_u32(
            base,
            process_ptr as u64 + core::mem::offset_of!(ProcessState, pid) as u64,
            pid,
        );
        guest_mem::write_u32(
            base,
            process_ptr as u64 + core::mem::offset_of!(ProcessState, ppid) as u64,
            ppid,
        );
        guest_mem::write_u32(
            base,
            process_ptr as u64 + core::mem::offset_of!(ProcessState, thread_count) as u64,
            thread_count,
        );
    }
    Ok(())
}

fn repair_current_main_thread_record(vm: &ThreadState, base: u32) {
    if vm.process_ptr == 0 || vm.tid <= 0 || vm.tid as usize > MAX_THREADS {
        return;
    }
    let vm_ptr = vm as *const ThreadState as u32;
    unsafe {
        let ps = &mut *((base as u64 + vm.process_ptr as u64) as *mut ProcessState);
        let idx = (vm.tid - 1) as usize;
        let record = &mut ps.threads[idx];
        let valid = record.tid == vm.tid
            && !matches!(record.state, THREAD_NONE | THREAD_DEAD)
            && record.thread_ptr == vm_ptr;
        if valid && ps.thread_count.load(std::sync::atomic::Ordering::Acquire) > 0 {
            return;
        }
        *record = ThreadRecord::new(vm.tid, THREAD_RUNNING, vm_ptr, vm.clear_child_tid as u32, 0);
        ps.thread_count
            .store(1, std::sync::atomic::Ordering::Release);
    }
}

fn run_vm(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
) -> Result<(i32, u64), String> {
    match run_vm_inner(
        vm,
        base,
        use_cache,
        deferred_plain_forks,
        deferred_clone_threads,
        false,
        true,
    )? {
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
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
    allow_plain_fork_defer: bool,
    service_deferred_clones: bool,
) -> Result<VmRunOutcome, String> {
    let mut cache = allocate_cache(use_cache);
    let mut total = 0i64;
    let vm_ptr = vm as *mut ThreadState as u32;
    let mut vfork_child_active = false;
    let mut skip_deferred_clone_service_once = false;

    loop {
        if service_deferred_clones && !skip_deferred_clone_service_once {
            let _ = service_ready_deferred_clone_threads(
                base,
                use_cache,
                deferred_plain_forks,
                deferred_clone_threads,
                vm_pid(vm, base),
            )?;
        }
        skip_deferred_clone_service_once = false;
        refresh_proc_pid_stat(vm, base, b'R')?;
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
                    deferred_clone_threads,
                )?;
                vfork_child_active = false;
            }
            STATUS_CLONE_SPAWN => {
                let child_ptr = tidemark_kernel::syscall::thread::spawn_from_clone(vm_ptr, base);
                if child_ptr == 0 {
                    return Err("spawn_from_clone failed".into());
                }
                let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
                enqueue_deferred_clone_thread(
                    deferred_clone_threads,
                    process_pid(base, child_vm.process_ptr),
                    child_ptr,
                );
                refresh_proc_pid_stat(child_vm, base, b'R')?;
                refresh_proc_pid_stat(vm, base, b'R')?;
                vm.status = STATUS_OK;
                skip_deferred_clone_service_once = true;
            }
            STATUS_WAIT4 if allow_plain_fork_defer => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_WAIT4 => {
                service_blocked_wait4(
                    vm,
                    base,
                    use_cache,
                    deferred_plain_forks,
                    deferred_clone_threads,
                )?;
            }
            STATUS_FUTEX_WAIT if allow_plain_fork_defer => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                if vm.process_ptr != 0 && process_pid(base, vm.process_ptr) == vm.tid {
                    tidemark_kernel::harness::support::register_plain_fork_futex_wait(
                        process_pid(base, vm.process_ptr),
                        vm.x[10] as u32,
                    );
                }
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_FUTEX_WAIT => {
                service_blocked_futex_wait(
                    vm,
                    base,
                    use_cache,
                    deferred_plain_forks,
                    deferred_clone_threads,
                )?;
            }
            STATUS_PIPE_WAIT if allow_plain_fork_defer => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_PIPE_WAIT => {
                service_blocked_pipe_wait(
                    vm,
                    base,
                    use_cache,
                    deferred_plain_forks,
                    deferred_clone_threads,
                )?;
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
            STATUS_SLEEP => {
                consume_sleep_duration(vm)?;
                vm.status = STATUS_OK;
            }
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
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
) -> Result<(), String> {
    match vm.spawn_kind {
        SPAWN_KIND_FORK => handle_plain_fork(
            vm,
            base,
            use_cache,
            deferred_plain_forks,
            deferred_clone_threads,
        ),
        SPAWN_KIND_EXECVE if vfork_child_active => handle_vfork_execve_spawn(
            vm,
            base,
            use_cache,
            deferred_plain_forks,
            deferred_clone_threads,
        ),
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
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
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
    let parent_mm_state = tidemark_kernel::harness::support::snapshot_plain_fork();
    refresh_proc_pid_stat(parent_vm, base, b'S')?;

    tidemark_kernel::fs::fd_table::retain_fds_for_fork(base, parent_vm);
    tidemark_kernel::syscall::signal::fork_from_parent(parent_pid, child_pid);

    let fork_clone_flags = parent_vm.clone_flags;
    let fork_child_stack = parent_vm.clone_child_stack;
    let fork_tls = parent_vm.clone_tls;
    let fork_child_tidptr = parent_vm.clone_child_tidptr;
    let mut child_vm = unsafe { core::ptr::read(parent_vm as *const ThreadState) };
    child_vm.x[10] = 0;
    child_vm.tid = 1;
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
        match run_vm_inner(
            &mut child_vm,
            base,
            _use_cache,
            deferred_plain_forks,
            deferred_clone_threads,
            true,
            true,
        )? {
            VmRunOutcome::Exited(child_exit, _child_pc) => {
                drain_deferred_clone_threads_for_process(
                    base,
                    _use_cache,
                    deferred_plain_forks,
                    deferred_clone_threads,
                    child_pid,
                )?;
                tidemark_kernel::harness::support::clear_plain_fork_futex_wait(child_pid);
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
                    mm_state: tidemark_kernel::harness::support::snapshot_plain_fork(),
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
            mm_state: tidemark_kernel::harness::support::snapshot_plain_fork(),
        });
    }

    tidemark_kernel::harness::support::restore_plain_fork_parent(
        base,
        guest_window_size(base) as u64,
        &parent_mm_state,
        || parent_memory.restore(base),
    )?;
    let snapshot_parent_pid_after_child = snapshot_pid(&parent_memory, process_ptr)?;
    let pid_after_parent_restore = process_pid(base, process_ptr);
    restore_process_state_snapshot(&parent_memory, base, process_ptr)?;
    repair_current_main_thread_record(parent_vm, base);
    let restored_pid = process_pid(base, process_ptr);
    if restored_pid != parent_pid {
        return Err(format!(
            "plain fork restore corrupted parent pid: expected {}, got {}; snapshot_pid={} snapshot_pid_after_child={} pid_after_parent_restore={} process_ptr=0x{:x}",
            parent_pid,
            restored_pid,
            snapshot_parent_pid,
            snapshot_parent_pid_after_child,
            pid_after_parent_restore,
            process_ptr
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
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
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
    let parent_mm_state = tidemark_kernel::harness::support::snapshot_plain_fork();

    let mut child_vm = unsafe { core::ptr::read(parent_vm as *const ThreadState) };
    set_process_identity(base, process_ptr, child_pid, parent_pid);

    let ret = tidemark_kernel::syscall::process::complete_execve_in_place(
        &mut child_vm,
        base,
        GUEST_RAM_SIZE as u64,
    );
    if ret < 0 {
        tidemark_kernel::harness::support::restore_plain_fork_parent(
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

    let (child_exit, _child_pc) = run_vm(
        &mut child_vm,
        base,
        use_cache,
        deferred_plain_forks,
        deferred_clone_threads,
    )?;
    tidemark_kernel::syscall::process::record_child_exit(
        child_pid,
        child_wait_status(&child_vm, child_exit),
    );

    tidemark_kernel::harness::support::restore_plain_fork_parent(
        base,
        guest_window_size(base) as u64,
        &parent_mm_state,
        || parent_memory.restore(base),
    )?;
    restore_process_state_snapshot(&parent_memory, base, process_ptr)?;
    repair_current_main_thread_record(parent_vm, base);
    tidemark_kernel::syscall::process::vfork_parent_resume(parent_vm, child_pid);

    Ok(())
}

fn run_next_deferred_plain_fork(
    current_vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
) -> Result<bool, String> {
    let Some(mut deferred) = deferred_plain_forks.pop_front() else {
        return Ok(false);
    };

    let current_memory = snapshot_guest_memory(base)?;
    let current_mm_state = tidemark_kernel::harness::support::snapshot_plain_fork();
    let deferred_pid = deferred.pid;

    tidemark_kernel::harness::support::restore_plain_fork_parent(
        base,
        guest_window_size(base) as u64,
        &deferred.mm_state,
        || {
            deferred.guest_memory.restore(base).map_err(|e| {
                format!(
                    "restore deferred child pid {} guest memory: {}",
                    deferred.pid, e
                )
            })
        },
    )?;
    restore_process_state_snapshot(&deferred.guest_memory, base, deferred.vm.process_ptr)?;
    refresh_proc_pid_stat(&deferred.vm, base, b'R')?;

    let exited = loop {
        match deferred.vm.status {
            STATUS_SLEEP => {
                consume_sleep_duration(&deferred.vm)?;
                deferred.vm.status = STATUS_OK
            }
            STATUS_WAIT4 => {
                let vm_ptr = &mut deferred.vm as *mut ThreadState as u32;
                tidemark_kernel::syscall::process::resume_wait4(vm_ptr, base);
            }
            STATUS_FUTEX_WAIT => {
                let futex_addr = deferred.vm.x[10] as u32;
                if tidemark_kernel::harness::support::take_plain_fork_futex_wake(
                    deferred.pid,
                    futex_addr,
                ) {
                    tidemark_kernel::syscall::thread::resume_futex_wait(&mut deferred.vm, base);
                } else if count_deferred_clone_threads_for_process(
                    deferred_clone_threads,
                    deferred.pid,
                ) > 0
                {
                    tidemark_kernel::harness::support::clear_plain_fork_futex_wait(deferred.pid);
                    let _ = service_ready_deferred_clone_threads(
                        base,
                        use_cache,
                        deferred_plain_forks,
                        deferred_clone_threads,
                        deferred.pid,
                    )?;
                    if tidemark_kernel::syscall::thread::thread_record_blocked_addr(
                        &deferred.vm,
                        base,
                    ) == 0
                    {
                        tidemark_kernel::syscall::thread::resume_futex_wait(&mut deferred.vm, base);
                    } else {
                        tidemark_kernel::harness::support::register_plain_fork_futex_wait(
                            deferred.pid,
                            futex_addr,
                        );
                        refresh_proc_pid_stat(&deferred.vm, base, b'S')?;
                        deferred.guest_memory = snapshot_guest_memory(base)?;
                        deferred.mm_state =
                            tidemark_kernel::harness::support::snapshot_plain_fork();
                        deferred_plain_forks.push_back(deferred);
                        break false;
                    }
                } else if current_vm.status == STATUS_WAIT4 && deferred.vm.futex_wait_timeout != 0 {
                    consume_relative_futex_timeout(&deferred.vm, base, Instant::now())?;
                    tidemark_kernel::syscall::thread::resume_futex_wait_result(
                        &mut deferred.vm,
                        base,
                        tidemark_kernel::abi::ETIMEDOUT,
                    );
                } else {
                    tidemark_kernel::harness::support::register_plain_fork_futex_wait(
                        deferred.pid,
                        futex_addr,
                    );
                    refresh_proc_pid_stat(&deferred.vm, base, b'S')?;
                    deferred.guest_memory = snapshot_guest_memory(base)?;
                    deferred.mm_state = tidemark_kernel::harness::support::snapshot_plain_fork();
                    deferred_plain_forks.push_back(deferred);
                    break false;
                }
            }
            STATUS_PIPE_WAIT => {
                let vm_ptr = &mut deferred.vm as *mut ThreadState as u32;
                tidemark_kernel::abi::thread_resume_blocked_syscall(vm_ptr);
                if deferred.vm.status == STATUS_PIPE_WAIT {
                    refresh_proc_pid_stat(&deferred.vm, base, b'S')?;
                    deferred.guest_memory = snapshot_guest_memory(base)?;
                    deferred.mm_state = tidemark_kernel::harness::support::snapshot_plain_fork();
                    deferred_plain_forks.push_back(deferred);
                    break false;
                }
            }
            _ => {}
        }

        if deferred.vm.status == STATUS_WAIT4 {
            refresh_proc_pid_stat(&deferred.vm, base, b'S')?;
            deferred.guest_memory = snapshot_guest_memory(base)?;
            deferred.mm_state = tidemark_kernel::harness::support::snapshot_plain_fork();
            deferred_plain_forks.push_back(deferred);
            break false;
        }

        match run_vm_inner(
            &mut deferred.vm,
            base,
            use_cache,
            deferred_plain_forks,
            deferred_clone_threads,
            true,
            true,
        )? {
            VmRunOutcome::Exited(child_exit, _child_pc) => {
                tidemark_kernel::harness::support::clear_plain_fork_futex_wait(deferred.pid);
                tidemark_kernel::syscall::process::record_child_exit(
                    deferred.pid,
                    child_wait_status(&deferred.vm, child_exit),
                );
                break true;
            }
            VmRunOutcome::Deferred(_child_pc) => {
                if count_deferred_clone_threads_for_process(deferred_clone_threads, deferred.pid)
                    > 0
                {
                    continue;
                }
                if current_vm.status == STATUS_WAIT4
                    && deferred.vm.status == STATUS_FUTEX_WAIT
                    && deferred.vm.futex_wait_timeout != 0
                {
                    continue;
                }
                if deferred.vm.status == STATUS_FUTEX_WAIT {
                    tidemark_kernel::harness::support::register_plain_fork_futex_wait(
                        deferred.pid,
                        deferred.vm.x[10] as u32,
                    );
                }
                refresh_proc_pid_stat(&deferred.vm, base, b'S')?;
                deferred.guest_memory = snapshot_guest_memory(base)?;
                deferred.mm_state = tidemark_kernel::harness::support::snapshot_plain_fork();
                deferred_plain_forks.push_back(deferred);
                break false;
            }
        }
    };

    tidemark_kernel::harness::support::restore_plain_fork_parent(
        base,
        guest_window_size(base) as u64,
        &current_mm_state,
        || {
            current_memory.restore(base).map_err(|e| {
                format!(
                    "restore current parent guest memory after running deferred child {}: {}",
                    deferred_pid, e
                )
            })
        },
    )?;
    restore_process_state_snapshot(&current_memory, base, current_vm.process_ptr)?;
    repair_current_main_thread_record(current_vm, base);
    current_vm.status = STATUS_OK;
    Ok(exited)
}

fn service_ready_deferred_clone_threads(
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
    current_pid: i32,
) -> Result<u32, String> {
    let mut progressed = 0u32;
    let initial_len = deferred_clone_threads.len();

    for _ in 0..initial_len {
        let Some(deferred_thread) = deferred_clone_threads.pop_front() else {
            break;
        };
        if deferred_thread.owner_pid != current_pid {
            deferred_clone_threads.push_back(deferred_thread);
            continue;
        }
        let child_ptr = deferred_thread.child_ptr;
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };

        let runnable = match child_vm.status {
            STATUS_OK => true,
            STATUS_SLEEP => {
                consume_sleep_duration(child_vm)?;
                child_vm.status = STATUS_OK;
                true
            }
            STATUS_WAIT4 => {
                tidemark_kernel::syscall::process::resume_wait4(child_ptr, base);
                child_vm.status != STATUS_WAIT4
            }
            STATUS_FUTEX_WAIT => {
                if tidemark_kernel::syscall::thread::thread_record_blocked_addr(child_vm, base) == 0
                {
                    tidemark_kernel::syscall::thread::resume_futex_wait(child_vm, base);
                    true
                } else {
                    false
                }
            }
            STATUS_PIPE_WAIT | STATUS_EPOLL_WAIT => {
                tidemark_kernel::abi::thread_resume_blocked_syscall(child_ptr);
                child_vm.status != STATUS_PIPE_WAIT && child_vm.status != STATUS_EPOLL_WAIT
            }
            _ => false,
        };

        if !runnable {
            deferred_clone_threads.push_back(deferred_thread);
            continue;
        }

        progressed += 1;
        match run_vm_inner(
            child_vm,
            base,
            use_cache,
            deferred_plain_forks,
            deferred_clone_threads,
            true,
            false,
        )? {
            VmRunOutcome::Exited(_, _) => {
                refresh_proc_pid_stat(child_vm, base, b'R')?;
            }
            VmRunOutcome::Deferred(_) => {
                enqueue_deferred_clone_thread(deferred_clone_threads, current_pid, child_ptr);
                refresh_proc_pid_stat(child_vm, base, b'S')?;
            }
        }
    }

    Ok(progressed)
}

fn count_deferred_clone_threads_for_process(
    deferred_clone_threads: &VecDeque<DeferredCloneThread>,
    pid: i32,
) -> usize {
    deferred_clone_threads
        .iter()
        .filter(|queued| queued.owner_pid == pid && queued.child_ptr != 0)
        .count()
}

fn drain_deferred_clone_threads_for_process(
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
    pid: i32,
) -> Result<(), String> {
    for _ in 0..1024 {
        let pending = count_deferred_clone_threads_for_process(deferred_clone_threads, pid);
        if pending == 0 {
            return Ok(());
        }
        let progressed = service_ready_deferred_clone_threads(
            base,
            use_cache,
            deferred_plain_forks,
            deferred_clone_threads,
            pid,
        )?;
        let remaining = count_deferred_clone_threads_for_process(deferred_clone_threads, pid);
        if remaining == 0 {
            return Ok(());
        }
        if progressed == 0 || remaining >= pending {
            return Err(format!(
                "deferred clone threads for pid {pid} remained blocked: pending={remaining}"
            ));
        }
    }
    Err(format!(
        "draining deferred clone threads for pid {pid} exceeded iteration budget"
    ))
}

fn service_blocked_wait4(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
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
            let _ = run_next_deferred_plain_fork(
                vm,
                base,
                use_cache,
                deferred_plain_forks,
                deferred_clone_threads,
            )?;
            tidemark_kernel::syscall::process::resume_wait4(vm_ptr, base);
            if vm.status != STATUS_WAIT4 {
                return Ok(());
            }
        }
        Err(format!(
            "wait4 remained blocked after servicing deferred plain-fork children: {}",
            describe_deferred_plain_forks(deferred_plain_forks)
        ))
    })();
    refresh_proc_pid_stat(vm, base, b'R')?;
    result
}

fn service_blocked_futex_wait(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
) -> Result<(), String> {
    refresh_proc_pid_stat(vm, base, b'S')?;
    let pid = if vm.process_ptr != 0 {
        process_pid(base, vm.process_ptr)
    } else {
        0
    };
    let is_process_leader = pid > 0 && vm.tid == pid;
    let futex_addr = vm.futex_wait_addr as u32;
    let timed_wait = vm.futex_wait_timeout != 0;
    let timeout_started = Instant::now();
    let mut plain_fork_wait_registered = false;

    let result = (|| -> Result<(), String> {
        for _ in 0..1024 {
            if tidemark_kernel::syscall::thread::thread_record_blocked_addr(vm, base) == 0 {
                tidemark_kernel::syscall::thread::resume_futex_wait(vm, base);
                return Ok(());
            }
            if is_process_leader
                && plain_fork_wait_registered
                && tidemark_kernel::harness::support::take_plain_fork_futex_wake(pid, futex_addr)
            {
                tidemark_kernel::syscall::thread::resume_futex_wait(vm, base);
                return Ok(());
            }
            if !deferred_clone_threads.is_empty() {
                let _ = service_ready_deferred_clone_threads(
                    base,
                    use_cache,
                    deferred_plain_forks,
                    deferred_clone_threads,
                    pid,
                )?;
                if tidemark_kernel::syscall::thread::thread_record_blocked_addr(vm, base) == 0 {
                    tidemark_kernel::syscall::thread::resume_futex_wait(vm, base);
                    return Ok(());
                }
            }
            if deferred_plain_forks.is_empty() {
                if timed_wait {
                    consume_relative_futex_timeout(vm, base, timeout_started)?;
                    tidemark_kernel::syscall::thread::resume_futex_wait_result(
                        vm,
                        base,
                        tidemark_kernel::abi::ETIMEDOUT,
                    );
                    return Ok(());
                }
                return Err(format!(
                    "futex wait blocked with no deferred plain-fork child; deferred_clone_threads={} {}",
                    deferred_clone_threads.len(),
                    describe_process_threads(vm, base)
                ));
            }
            if is_process_leader && !plain_fork_wait_registered {
                tidemark_kernel::harness::support::register_plain_fork_futex_wait(pid, futex_addr);
                plain_fork_wait_registered = true;
            }
            let _ = run_next_deferred_plain_fork(
                vm,
                base,
                use_cache,
                deferred_plain_forks,
                deferred_clone_threads,
            )?;
        }
        if timed_wait {
            consume_relative_futex_timeout(vm, base, timeout_started)?;
            tidemark_kernel::syscall::thread::resume_futex_wait_result(
                vm,
                base,
                tidemark_kernel::abi::ETIMEDOUT,
            );
            return Ok(());
        }
        Err(format!(
            "futex wait remained blocked after servicing deferred plain-fork children; deferred_clone_threads={} {}",
            deferred_clone_threads.len(),
            describe_process_threads(vm, base)
        ))
    })();

    if pid > 0 {
        tidemark_kernel::harness::support::clear_plain_fork_futex_wait(pid);
    }
    refresh_proc_pid_stat(vm, base, b'R')?;
    result
}

fn consume_relative_futex_timeout(
    vm: &ThreadState,
    base: u32,
    _started_at: Instant,
) -> Result<(), String> {
    let Some(timeout) = read_guest_timespec_duration(base, vm.futex_wait_timeout)? else {
        return Ok(());
    };
    if vm.futex_wait_absolute != 0 {
        let clock_id = if (vm.futex_wait_flags & FUTEX_CLOCK_REALTIME) != 0 {
            0
        } else {
            1
        };
        let Some((now_sec, now_nsec)) = tidemark_kernel::syscall::time::current_timespec(clock_id)
        else {
            return Err(format!("unsupported futex wait clock id {}", clock_id));
        };
        let target_sec =
            unsafe { tidemark_kernel::guest_mem::read_u64(base, vm.futex_wait_timeout) };
        let target_nsec =
            unsafe { tidemark_kernel::guest_mem::read_u64(base, vm.futex_wait_timeout + 8) };
        if target_nsec >= 1_000_000_000 {
            return Err(format!(
                "invalid absolute futex timeout timespec: sec={} nsec={}",
                target_sec, target_nsec
            ));
        }
        let remaining = if (target_sec, target_nsec) <= (now_sec, now_nsec) {
            Duration::ZERO
        } else {
            let sec_delta = target_sec - now_sec;
            let (sec_delta, nsec_delta) = if target_nsec >= now_nsec {
                (sec_delta, target_nsec - now_nsec)
            } else {
                (
                    sec_delta.saturating_sub(1),
                    1_000_000_000 + target_nsec - now_nsec,
                )
            };
            Duration::new(sec_delta, nsec_delta as u32)
        };
        tidemark_kernel::syscall::time::advance_monotonic_duration(remaining);
        return Ok(());
    }
    tidemark_kernel::syscall::time::advance_monotonic_duration(timeout);
    Ok(())
}

fn consume_sleep_duration(vm: &ThreadState) -> Result<(), String> {
    if vm.fault_pc >= 1_000_000_000 {
        return Err(format!(
            "invalid sleep duration timespec: sec={} nsec={}",
            vm.fault_addr, vm.fault_pc
        ));
    }
    tidemark_kernel::syscall::time::advance_monotonic_duration(Duration::new(
        vm.fault_addr,
        vm.fault_pc as u32,
    ));
    Ok(())
}

fn read_guest_timespec_duration(base: u32, guest_addr: u64) -> Result<Option<Duration>, String> {
    if guest_addr == 0 {
        return Ok(None);
    }
    let sec = unsafe { tidemark_kernel::guest_mem::read_u64(base, guest_addr) };
    let nsec = unsafe { tidemark_kernel::guest_mem::read_u64(base, guest_addr + 8) };
    if nsec >= 1_000_000_000 {
        return Err(format!(
            "invalid futex timeout timespec: sec={} nsec={}",
            sec, nsec
        ));
    }
    Ok(Some(Duration::new(sec, nsec as u32)))
}

fn service_blocked_pipe_wait(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_plain_forks: &mut VecDeque<DeferredPlainFork>,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
) -> Result<(), String> {
    refresh_proc_pid_stat(vm, base, b'S')?;
    let vm_ptr = vm as *mut ThreadState as u32;
    let result = (|| -> Result<(), String> {
        for _ in 0..1024 {
            tidemark_kernel::abi::thread_resume_blocked_syscall(vm_ptr);
            if vm.status != STATUS_PIPE_WAIT {
                return Ok(());
            }
            if deferred_plain_forks.is_empty() {
                return Err("pipe/eventfd wait blocked with no deferred plain-fork child".into());
            }
            let _ = run_next_deferred_plain_fork(
                vm,
                base,
                use_cache,
                deferred_plain_forks,
                deferred_clone_threads,
            )?;
        }
        Err(
            "pipe/eventfd wait remained blocked after servicing deferred plain-fork children"
                .into(),
        )
    })();
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
    tidemark_kernel::harness::support::clear_guest_output();
    tidemark_kernel::harness::support::clear_plain_fork_futex_waits();
    let mut deferred_plain_forks = VecDeque::new();
    let mut deferred_clone_threads = VecDeque::new();
    let result = (|| -> Result<(i32, u64), String> {
        unsafe {
            tidemark_kernel::guest_mem::init(
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
            );

            let current_pages = core::arch::wasm32::memory_size(0);
            let base = if TEST_GUEST_BASE != 0 {
                TEST_GUEST_BASE
            } else {
                let current_bytes = (current_pages as u64).saturating_mul(65536);
                let guest_base_hint = current_bytes.saturating_add(GUEST_BASE_PADDING as u64);
                let aligned = guest_base_hint.saturating_add((GUEST_RAM_ALIGN - 1) as u64)
                    & !((GUEST_RAM_ALIGN - 1) as u64);
                let base = aligned.min(u32::MAX as u64) as u32;
                TEST_GUEST_BASE = base;
                base
            };
            let target_bytes = (base as u64).saturating_add(GUEST_RAM_SIZE as u64);
            let target_pages = ((target_bytes + 65535) / 65536) as usize;
            let target_pages = target_pages.max(TEST_MEMORY_PAGES);
            if current_pages < target_pages {
                let grown = core::arch::wasm32::memory_grow(0, target_pages - current_pages);
                if grown == usize::MAX {
                    return Err("memory_grow failed".into());
                }
            }

            tidemark_kernel::guest_mem::zero_mem(base, 0, GUEST_RAM_SIZE as usize);

            // Copy ELF to a staging area above the host binary's data.
            let elf_load_addr: u64 = 0xC0_0000;
            tidemark_kernel::guest_mem::write_bytes(base, elf_load_addr, elf_bytes);

            let load_segments = tidemark_kernel::elf::collect_load_segments(
                (base as u64 + elf_load_addr) as u32,
                elf_bytes.len() as u32,
                0,
            )
            .map_err(|e| format!("ELF segment inspection failed: {}", e))?;

            let elf_result = tidemark_kernel::elf::load_elf(
                base,
                GUEST_RAM_SIZE as u64,
                (base as u64 + elf_load_addr) as u32,
                elf_bytes.len() as u32,
            )
            .map_err(|e| format!("ELF load failed: {}", e))?;
            tidemark_kernel::elf::zero_fill_load_padding(
                base,
                elf_result.load_end,
                elf_result.brk_start,
            );

            // Keep kernel-private allocations outside the guest RAM window.
            // After this point, avoid std heap allocations on the success path:
            // WASI-side heap growth can alias with the kernel bump heap.
            let host_heap_base = base
                .saturating_add(GUEST_RAM_SIZE)
                .saturating_add(HOST_HEAP_PADDING);
            tidemark_kernel::alloc::reset(host_heap_base);
            let guest_brk_start = elf_result.brk_start;
            tidemark_kernel::syscall::time::init();
            tidemark_kernel::syscall::memory::init(guest_brk_start);
            for segment in load_segments {
                // riscv-tests run in a bare-metal style harness, not under Linux
                // ELF permission enforcement. Tests such as rv64ui/fence_i
                // self-modify and execute bytes placed in the data LOAD
                // segment, so treat all loaded guest segments as executable
                // within this riscv-tests-only runner.
                tidemark_kernel::syscall::memory::register_elf_load_segment(
                    segment.start,
                    segment.end,
                    segment.prot | tidemark_kernel::abi::PROT_EXEC,
                );
            }
            tidemark_kernel::syscall::process::init();
            tidemark_kernel::syscall::thread::init();
            tidemark_kernel::syscall::signal::init();
            tidemark_kernel::syscall::epoll::init();
            tidemark_kernel::syscall::pipe::init();
            tidemark_kernel::syscall::pty::init();
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
            let _ = ensure_file(proc_ino, b"cpuinfo", PROC_CPUINFO_BYTES, 0o444)?;
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
            let env_virt_override_addr = 0xBF_FDC0u64;
            tidemark_kernel::guest_mem::write_bytes(
                base,
                env_virt_override_addr,
                b"LTP_VIRT_OVERRIDE=\0",
            );

            let sp = tidemark_kernel::elf::setup_stack(
                base,
                0xBF_FD00,
                &[argv0_addr],
                &[env_path_addr, env_virt_override_addr],
                &elf_result,
                random_addr,
                argv0_addr,
            );

            let mut vm: ThreadState = core::mem::zeroed();
            vm.pc = elf_result.entry;
            vm.x[2] = sp;
            vm.status = STATUS_OK;
            vm.tid = INITIAL_PID;
            vm.guest_base = base;

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

            tidemark_kernel::fs::fd_table::init_stdio(base, &mut vm);
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

            run_vm(
                &mut vm,
                base,
                use_cache,
                &mut deferred_plain_forks,
                &mut deferred_clone_threads,
            )
        }
    })();
    let output = tidemark_kernel::harness::support::take_guest_output();

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

#[cfg(test)]
mod tests {
    use super::*;
    use tidemark_kernel::abi::{
        CLONE_FS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VM, FUTEX_WAIT, FUTEX_WAKE, STATUS_FUTEX_WAIT,
    };
    use tidemark_kernel::fs::memfs;
    use tidemark_kernel::guest_mem;
    use tidemark_kernel::harness::TestVm;
    use tidemark_kernel::syscall::thread as thread_impl;
    use tidemark_kernel::types::{ProcessState, THREAD_NONE};

    fn read_memfs_file(ino: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 128];
        let n = memfs::read_file(ino, 0, &mut buf);
        assert!(n >= 0);
        buf.truncate(n as usize);
        buf
    }

    fn proc_task_stat_ino(pid: i32, tid: i32) -> u32 {
        let proc_ino = memfs::lookup(1, b"proc");
        assert_ne!(proc_ino, 0);
        let pid_name = pid.to_string();
        let pid_ino = memfs::lookup(proc_ino, pid_name.as_bytes());
        assert_ne!(pid_ino, 0);
        let task_ino = memfs::lookup(pid_ino, b"task");
        assert_ne!(task_ino, 0);
        let tid_name = tid.to_string();
        let tid_ino = memfs::lookup(task_ino, tid_name.as_bytes());
        if tid_ino == 0 {
            return 0;
        }
        memfs::lookup(tid_ino, b"stat")
    }

    fn proc_pid_stat_bytes(pid: i32) -> Vec<u8> {
        let proc_ino = memfs::lookup(1, b"proc");
        assert_ne!(proc_ino, 0);
        let pid_name = pid.to_string();
        let pid_ino = memfs::lookup(proc_ino, pid_name.as_bytes());
        assert_ne!(pid_ino, 0);
        let stat_ino = memfs::lookup(pid_ino, b"stat");
        assert_ne!(stat_ino, 0);
        read_memfs_file(stat_ino)
    }

    fn write_exit_program(base: u32, pc: u64, exit_code: u8) {
        let code = [
            0x13,
            0x05,
            exit_code << 4,
            0x00, // addi a0, zero, exit_code
            0x93,
            0x08,
            0xd0,
            0x05, // addi a7, zero, 93 (SYS_exit)
            0x73,
            0x00,
            0x00,
            0x00, // ecall
        ];
        unsafe {
            guest_mem::write_bytes(base, pc, &code);
        }
    }

    fn write_futex_wake_then_exit_program(base: u32, pc: u64, exit_code: u8) {
        let code = [
            0x73,
            0x00,
            0x00,
            0x00, // ecall (futex)
            0x13,
            0x05,
            exit_code << 4,
            0x00, // addi a0, zero, exit_code
            0x93,
            0x08,
            0xd0,
            0x05, // addi a7, zero, 93 (SYS_exit)
            0x73,
            0x00,
            0x00,
            0x00, // ecall
        ];
        unsafe {
            guest_mem::write_bytes(base, pc, &code);
        }
    }

    fn write_futex_wake_return_then_exit_program(base: u32, pc: u64) {
        let code = [
            0x73, 0x00, 0x00, 0x00, // ecall (futex)
            0x93, 0x08, 0xd0, 0x05, // addi a7, zero, 93 (SYS_exit)
            0x73, 0x00, 0x00, 0x00, // ecall
        ];
        unsafe {
            guest_mem::write_bytes(base, pc, &code);
        }
    }

    #[test]
    fn deferred_clone_thread_resumes_after_futex_wake() {
        let mut t = TestVm::new();
        let pid = process_pid(t.base, t.vm.process_ptr);
        let futex_addr = t.scratch + 0x400;
        let code_addr = t.scratch + 0x800;
        write_exit_program(t.base, code_addr, 9);
        unsafe {
            guest_mem::write_u32(t.base, futex_addr, 0);
        }

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);

        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        child_vm.pc = code_addr;

        let wait_ret =
            thread_impl::sys_futex(child_vm, t.base, futex_addr, FUTEX_WAIT as u64, 0, 0, 0, 0);
        assert_eq!(wait_ret, 0);
        assert_eq!(child_vm.status, STATUS_FUTEX_WAIT);

        let mut deferred_plain_forks = VecDeque::new();
        let mut deferred_clone_threads = VecDeque::new();
        enqueue_deferred_clone_thread(&mut deferred_clone_threads, pid, child_ptr);

        let wake_ret =
            thread_impl::sys_futex(&mut t.vm, t.base, futex_addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
        assert_eq!(wake_ret, 1);

        let progressed = service_ready_deferred_clone_threads(
            t.base,
            false,
            &mut deferred_plain_forks,
            &mut deferred_clone_threads,
            pid,
        )
        .expect("deferred clone wake service should succeed");
        assert_eq!(progressed, 1);
        assert!(deferred_clone_threads.is_empty());

        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        assert_eq!(
            ps.thread_count.load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert_eq!(ps.threads[(child_tid - 1) as usize].state, THREAD_DEAD);
    }

    #[test]
    fn blocked_leader_futex_wait_services_deferred_clone_waker_thread() {
        let mut t = TestVm::new();
        let pid = 2;
        set_process_identity(t.base, t.vm.process_ptr, pid, 1);
        t.vm.tid = pid;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        let futex_addr = t.scratch + 0x440;
        let code_addr = t.scratch + 0x840;
        write_futex_wake_then_exit_program(t.base, code_addr, 0);
        unsafe {
            guest_mem::write_u32(t.base, futex_addr, 0);
        }

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);

        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        child_vm.pc = code_addr;
        child_vm.x[10] = futex_addr;
        child_vm.x[11] = FUTEX_WAKE as u64;
        child_vm.x[12] = 1;
        child_vm.x[13] = 0;
        child_vm.x[14] = 0;
        child_vm.x[15] = 0;
        child_vm.x[17] = tidemark_kernel::abi::SYS_FUTEX;

        let wait_ret =
            thread_impl::sys_futex(&mut t.vm, t.base, futex_addr, FUTEX_WAIT as u64, 0, 0, 0, 0);
        assert_eq!(wait_ret, 0);
        assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

        refresh_proc_pid_stat(child_vm, t.base, b'R').expect("proc refresh should succeed");
        let stat = proc_pid_stat_bytes(pid);
        let text = String::from_utf8(stat).expect("pid stat should be utf8");
        assert!(
            text.contains(" S "),
            "expected sleeping leader state, got {text:?}"
        );

        let mut deferred_plain_forks = VecDeque::new();
        let mut deferred_clone_threads = VecDeque::new();
        enqueue_deferred_clone_thread(&mut deferred_clone_threads, pid, child_ptr);

        service_blocked_futex_wait(
            &mut t.vm,
            t.base,
            false,
            &mut deferred_plain_forks,
            &mut deferred_clone_threads,
        )
        .expect("leader futex wait should be serviced by deferred clone thread");

        assert_eq!(t.vm.status, STATUS_OK);
        assert_eq!(t.vm.x[10], 0);
        assert!(deferred_clone_threads.is_empty());

        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        assert_eq!(
            ps.thread_count.load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert_eq!(ps.threads[(child_tid - 1) as usize].state, THREAD_DEAD);
    }

    #[test]
    fn blocked_leader_futex_wait_clone_waker_returns_single_wake_count() {
        let mut t = TestVm::new();
        let pid = 2;
        set_process_identity(t.base, t.vm.process_ptr, pid, 1);
        t.vm.tid = pid;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        let futex_addr = t.scratch + 0x4c0;
        let code_addr = t.scratch + 0x8c0;
        write_futex_wake_return_then_exit_program(t.base, code_addr);
        unsafe {
            guest_mem::write_u32(t.base, futex_addr, 0);
        }

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);

        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        child_vm.pc = code_addr;
        child_vm.x[10] = futex_addr;
        child_vm.x[11] = FUTEX_WAKE as u64;
        child_vm.x[12] = 1;
        child_vm.x[13] = 0;
        child_vm.x[14] = 0;
        child_vm.x[15] = 0;
        child_vm.x[17] = tidemark_kernel::abi::SYS_FUTEX;

        let wait_ret =
            thread_impl::sys_futex(&mut t.vm, t.base, futex_addr, FUTEX_WAIT as u64, 0, 0, 0, 0);
        assert_eq!(wait_ret, 0);
        assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

        let mut deferred_plain_forks = VecDeque::new();
        let mut deferred_clone_threads = VecDeque::new();
        enqueue_deferred_clone_thread(&mut deferred_clone_threads, pid, child_ptr);

        service_blocked_futex_wait(
            &mut t.vm,
            t.base,
            false,
            &mut deferred_plain_forks,
            &mut deferred_clone_threads,
        )
        .expect("leader futex wait should be serviced by deferred clone thread");

        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        assert_eq!(ps.threads[(child_tid - 1) as usize].state, THREAD_DEAD);
        assert_eq!(child_vm.exit_code, 1);
    }

    #[test]
    fn deferred_plain_fork_futex_wait_clone_waker_does_not_double_count_external_wait() {
        let mut t = TestVm::new();
        let pid = 2;
        set_process_identity(t.base, t.vm.process_ptr, pid, 1);
        t.vm.tid = pid;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        let futex_addr = t.scratch + 0x500;
        let code_addr = t.scratch + 0x900;
        write_futex_wake_return_then_exit_program(t.base, code_addr);
        unsafe {
            guest_mem::write_u32(t.base, futex_addr, 0);
        }

        let wait_ret =
            thread_impl::sys_futex(&mut t.vm, t.base, futex_addr, FUTEX_WAIT as u64, 0, 0, 0, 0);
        assert_eq!(wait_ret, 0);
        assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);
        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        child_vm.pc = code_addr;
        child_vm.x[10] = futex_addr;
        child_vm.x[11] = FUTEX_WAKE as u64;
        child_vm.x[12] = 1;
        child_vm.x[13] = 0;
        child_vm.x[14] = 0;
        child_vm.x[15] = 0;
        child_vm.x[17] = tidemark_kernel::abi::SYS_FUTEX;

        tidemark_kernel::harness::support::register_plain_fork_futex_wait(pid, futex_addr as u32);
        let mut deferred_plain_forks = VecDeque::new();
        let mut deferred_clone_threads = VecDeque::new();
        enqueue_deferred_clone_thread(&mut deferred_clone_threads, pid, child_ptr);

        tidemark_kernel::harness::support::clear_plain_fork_futex_wait(pid);
        let progressed = service_ready_deferred_clone_threads(
            t.base,
            false,
            &mut deferred_plain_forks,
            &mut deferred_clone_threads,
            pid,
        )
        .expect("deferred clone thread should run");

        assert_eq!(progressed, 1);
        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        assert_eq!(ps.threads[(child_tid - 1) as usize].state, THREAD_DEAD);
        assert_eq!(child_vm.exit_code, 1);
    }

    #[test]
    fn deferred_clone_thread_is_not_serviced_under_foreign_pid_image() {
        let mut t = TestVm::new();
        let pid = 2;
        set_process_identity(t.base, t.vm.process_ptr, pid, 1);
        t.vm.tid = pid;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);
        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        child_vm.status = STATUS_OK;

        let mut deferred_plain_forks = VecDeque::new();
        let mut deferred_clone_threads = VecDeque::new();
        enqueue_deferred_clone_thread(&mut deferred_clone_threads, pid + 1, child_ptr);

        let progressed = service_ready_deferred_clone_threads(
            t.base,
            false,
            &mut deferred_plain_forks,
            &mut deferred_clone_threads,
            pid,
        )
        .expect("foreign-owned clone thread should be skipped cleanly");

        assert_eq!(progressed, 0);
        assert_eq!(deferred_clone_threads.len(), 1);
        assert_eq!(
            deferred_clone_threads
                .front()
                .map(|queued| queued.owner_pid),
            Some(pid + 1)
        );
        assert_eq!(
            deferred_clone_threads
                .front()
                .map(|queued| queued.child_ptr),
            Some(child_ptr)
        );
    }

    #[test]
    fn proc_pid_stat_uses_leader_state_not_current_running_thread() {
        let mut t = TestVm::new();
        let pid = 2;
        set_process_identity(t.base, t.vm.process_ptr, pid, 1);
        t.vm.tid = pid;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        let futex_addr = t.scratch + 0x480;
        unsafe {
            guest_mem::write_u32(t.base, futex_addr, 0);
        }
        let wait_ret =
            thread_impl::sys_futex(&mut t.vm, t.base, futex_addr, FUTEX_WAIT as u64, 0, 0, 0, 0);
        assert_eq!(wait_ret, 0);
        assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);
        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        refresh_proc_pid_stat(child_vm, t.base, b'R').expect("proc refresh should succeed");

        let stat = proc_pid_stat_bytes(pid);
        let text = String::from_utf8(stat).expect("pid stat should be utf8");
        assert!(
            text.contains(" S "),
            "expected sleeping leader state, got {text:?}"
        );
    }

    #[test]
    fn proc_task_entry_disappears_after_clone_thread_exit() {
        let mut t = TestVm::new();
        let pid = 2;
        set_process_identity(t.base, t.vm.process_ptr, pid, 1);
        t.vm.tid = pid;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);
        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };

        refresh_proc_pid_stat(child_vm, t.base, b'R').expect("proc refresh should succeed");
        assert_ne!(proc_task_stat_ino(pid, child_tid), 0);

        assert_eq!(
            thread_impl::sys_exit(child_vm, t.base, 0),
            tidemark_kernel::abi::STATUS_FAULT
        );
        refresh_proc_pid_stat(child_vm, t.base, b'R')
            .expect("proc refresh after exit should succeed");
        assert_eq!(proc_task_stat_ino(pid, child_tid), 0);
    }

    #[test]
    fn plain_fork_parent_restore_preserves_process_identity() {
        let t = TestVm::new();
        let process_ptr = t.vm.process_ptr;
        let initial_pid = process_pid(t.base, process_ptr);
        let initial_ppid = process_ppid(t.base, process_ptr);
        let snapshot = snapshot_guest_memory(t.base).expect("snapshot should succeed");
        let mm_snapshot = tidemark_kernel::harness::support::snapshot_plain_fork();

        set_process_identity(t.base, process_ptr, 99, 2);
        assert_eq!(process_pid(t.base, process_ptr), 99);

        tidemark_kernel::harness::support::restore_plain_fork_parent(
            t.base,
            guest_window_size(t.base) as u64,
            &mm_snapshot,
            || snapshot.restore(t.base),
        )
        .expect("plain-fork restore should succeed");
        restore_process_state_snapshot(&snapshot, t.base, process_ptr)
            .expect("process state restore should succeed");

        assert_eq!(process_pid(t.base, process_ptr), initial_pid);
        assert_eq!(process_ppid(t.base, process_ptr), initial_ppid);
    }

    #[test]
    fn repair_current_main_thread_record_restores_parent_slot() {
        let t = TestVm::new();
        let tid = t.vm.tid;
        let vm_ptr = &t.vm as *const ThreadState as u32;
        let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
        ps.thread_count
            .store(0, std::sync::atomic::Ordering::Release);
        ps.threads[(tid - 1) as usize] = ThreadRecord::new(0, THREAD_NONE, 0, 0, 0);

        repair_current_main_thread_record(&t.vm, t.base);

        assert_eq!(
            ps.thread_count.load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert_eq!(ps.threads[(tid - 1) as usize].tid, tid);
        assert_eq!(ps.threads[(tid - 1) as usize].thread_ptr, vm_ptr);
    }

    #[test]
    fn handle_plain_fork_restores_parent_after_exited_child() {
        let mut t = TestVm::new();
        set_process_identity(t.base, t.vm.process_ptr, INITIAL_PID, INITIAL_PPID);
        t.vm.tid = INITIAL_PID;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        write_exit_program(t.base, t.vm.pc, 0);
        t.vm.x[10] = 3;

        let mut deferred_plain_forks = VecDeque::new();
        let mut deferred_clone_threads = VecDeque::new();
        handle_plain_fork(
            &mut t.vm,
            t.base,
            false,
            &mut deferred_plain_forks,
            &mut deferred_clone_threads,
        )
        .expect("plain fork should restore parent after child exit");

        assert_eq!(process_pid(t.base, t.vm.process_ptr), INITIAL_PID);
        assert_eq!(process_ppid(t.base, t.vm.process_ptr), INITIAL_PPID);
        assert!(deferred_plain_forks.is_empty());
    }
}
