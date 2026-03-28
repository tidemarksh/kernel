//! Process lifecycle syscalls: execve, wait4, vfork, fork.
//!
//! vfork: parent suspends (STATUS_VFORK_WAIT), child runs in parent's memory.
//! execve: normal path replaces the current process in place; vfork+execve exports
//! handoff data so TS can create the post-exec child Worker in runtime harness.
//! fork: guest Memory full copy → STATUS_EXECVE_SPAWN.
//! wait4: retrieve child exit status.
//!
//! Semantics:
//! https://man7.org/linux/man-pages/man2/vfork.2.html
//! https://man7.org/linux/man-pages/man2/execve.2.html
//! https://man7.org/linux/man-pages/man2/fork.2.html
//! https://man7.org/linux/man-pages/man2/wait4.2.html

use crate::abi::*;
use crate::alloc;
use crate::fs::{fd_table, memfs};
use crate::guest_mem;
use crate::types::{FdEntry, ProcessState, ThreadState};
use alloc_crate::{vec, vec::Vec};

// =========================================================================
// Process table — tracks child processes for wait4
// =========================================================================

const MAX_CHILDREN: usize = 64;
const EXECVE_RAM_LIMIT: u64 = 0x8000_0000;

#[derive(Clone, Copy)]
struct ChildEntry {
    pid: i32,
    exited: bool,
    exit_code: i32,
}

#[derive(Clone, Copy)]
struct ProcessEntry {
    pid: i32,
    ppid: i32,
    pgid: i32,
    sid: i32,
    did_exec: bool,
}

#[derive(Clone, Copy)]
struct VforkSnapshot {
    x: [u64; 32],
    pc: u64,
    f: [u64; 32],
    fcsr: u32,
    sig_mask: u64,
}

struct ExecveImage {
    path_bytes: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    elf_bytes: Vec<u8>,
    elf: crate::elf::ElfLoadResult,
}

#[repr(C)]
struct ProcessRuntimeState {
    children: [ChildEntry; MAX_CHILDREN],
    next_pid: i32,
    vfork_active: u32,
    process_table: [ProcessEntry; MAX_PROCESSES],
    vfork_snapshot: VforkSnapshot,
}

static mut PROCESS_RUNTIME_STATE: *mut ProcessRuntimeState = core::ptr::null_mut();

fn prs() -> &'static mut ProcessRuntimeState {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(PROCESS_RUNTIME_STATE));
        &mut *p
    }
}

fn children() -> &'static mut [ChildEntry; MAX_CHILDREN] {
    &mut prs().children
}

fn processes() -> &'static mut [ProcessEntry; MAX_PROCESSES] {
    &mut prs().process_table
}

pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_RUNTIME_STATE),
            core::ptr::null_mut(),
        );
        let ptr = alloc::alloc_zeroed(
            core::mem::size_of::<ProcessRuntimeState>() as u32,
            core::mem::align_of::<ProcessRuntimeState>() as u32,
        );
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        let state = ptr as *mut ProcessRuntimeState;
        core::ptr::write(
            state,
            ProcessRuntimeState {
                children: [ChildEntry {
                    pid: 0,
                    exited: false,
                    exit_code: 0,
                }; MAX_CHILDREN],
                next_pid: 3,
                vfork_active: 0,
                process_table: [ProcessEntry {
                    pid: 0,
                    ppid: 0,
                    pgid: 0,
                    sid: 0,
                    did_exec: false,
                }; MAX_PROCESSES],
                vfork_snapshot: VforkSnapshot {
                    x: [0; 32],
                    pc: 0,
                    f: [0; 32],
                    fcsr: 0,
                    sig_mask: 0,
                },
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(PROCESS_RUNTIME_STATE), state);
    }
}

pub fn process_runtime_state_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(PROCESS_RUNTIME_STATE)) as u32 }
}

pub fn attach_process_runtime_state_ptr(ptr: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PROCESS_RUNTIME_STATE),
            ptr as *mut ProcessRuntimeState,
        );
    }
}

/// Reset process lifecycle state for unit tests.
#[cfg(test)]
pub(crate) fn reset_for_tests() {
    init();
}

#[cfg(test)]
fn vfork_snapshot_active() -> bool {
    prs().vfork_active != 0
}

fn process_idx(pid: i32) -> Option<usize> {
    if (1..=MAX_PROCESSES as i32).contains(&pid) {
        Some((pid - 1) as usize)
    } else {
        None
    }
}

fn process_entry(pid: i32) -> Option<&'static mut ProcessEntry> {
    let idx = process_idx(pid)?;
    let slot = &mut processes()[idx];
    if slot.pid == pid { Some(slot) } else { None }
}

fn inherit_group_from_parent(ppid: i32) -> (i32, i32) {
    match process_entry(ppid) {
        Some(parent) => (parent.pgid, parent.sid),
        None => (0, 0),
    }
}

fn ensure_process(pid: i32, ppid: i32) -> Option<&'static mut ProcessEntry> {
    let idx = process_idx(pid)?;
    reserve_pid(pid);
    if processes()[idx].pid == 0 {
        let (parent_pgid, parent_sid) = inherit_group_from_parent(ppid);
        processes()[idx] = ProcessEntry {
            pid,
            ppid,
            pgid: if parent_pgid != 0 { parent_pgid } else { pid },
            sid: if parent_sid != 0 { parent_sid } else { pid },
            did_exec: false,
        };
    } else {
        processes()[idx].ppid = ppid;
    }
    Some(&mut processes()[idx])
}

fn ensure_current_process(vm: &ThreadState, base: u32) -> Option<&'static mut ProcessEntry> {
    let pid = crate::syscall::signal::pid_from_vm(vm, base);
    if pid <= 0 {
        return None;
    }
    let ppid_offset = core::mem::offset_of!(ProcessState, ppid) as u64;
    let ppid = unsafe { guest_mem::read_i32(base, vm.process_ptr as u64 + ppid_offset) };
    ensure_process(pid, ppid)
}

fn inherit_process(parent_pid: i32, child_pid: i32, did_exec: bool) {
    let (parent_pgid, parent_sid) = inherit_group_from_parent(parent_pid);
    if let Some(slot) = process_idx(child_pid).map(|idx| &mut processes()[idx]) {
        *slot = ProcessEntry {
            pid: child_pid,
            ppid: parent_pid,
            pgid: if parent_pgid != 0 {
                parent_pgid
            } else {
                child_pid
            },
            sid: if parent_sid != 0 {
                parent_sid
            } else {
                child_pid
            },
            did_exec,
        };
    }
}

fn group_exists_in_session(pgid: i32, sid: i32) -> bool {
    processes()
        .iter()
        .any(|slot| slot.pid != 0 && slot.pgid == pgid && slot.sid == sid)
}

fn reserve_pid(pid: i32) {
    let next = prs().next_pid;
    if pid >= next {
        prs().next_pid = pid + 1;
    }
}

fn alloc_pid() -> i32 {
    let pid = prs().next_pid;
    prs().next_pid = pid + 1;
    pid
}

fn set_spawn_handoff(
    vm: &mut ThreadState,
    kind: u32,
    child_pid: i32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
) {
    vm.spawn_kind = kind;
    vm.spawn_flags = 0;
    vm.spawn_child_pid = child_pid;
    vm.spawn_path = path_addr;
    vm.spawn_argv = argv_addr;
    vm.spawn_envp = envp_addr;
}

fn clear_spawn_handoff(vm: &mut ThreadState) {
    vm.spawn_kind = SPAWN_KIND_NONE;
    vm.spawn_flags = 0;
    vm.spawn_child_pid = 0;
    vm.spawn_path = 0;
    vm.spawn_argv = 0;
    vm.spawn_envp = 0;
}

fn current_cwd_ino(vm: &ThreadState, base: u32) -> u32 {
    let cwd_off = core::mem::offset_of!(ProcessState, cwd_ino) as u64;
    let cwd = unsafe { guest_mem::read_u32(base, vm.process_ptr as u64 + cwd_off) };
    if cwd == 0 { 1 } else { cwd }
}

fn read_guest_cstr_bytes(base: u32, addr: u64) -> Result<Vec<u8>, i64> {
    if addr == 0 {
        return Err(EFAULT);
    }
    let mut buf = [0u8; 512];
    let len = unsafe { guest_mem::read_cstr(base, addr, &mut buf) };
    if len == 0 {
        return Err(ENOENT);
    }
    Ok(buf[..len].to_vec())
}

fn resolve_execve_inode(vm: &ThreadState, base: u32, path_addr: u64) -> Result<(u32, Vec<u8>), i64> {
    let path = read_guest_cstr_bytes(base, path_addr)?;
    let ino = if path.first() == Some(&b'/') {
        memfs::resolve_path(&path)
    } else {
        memfs::resolve_path_from(current_cwd_ino(vm, base), &path)
    };
    if ino == 0 {
        return Err(ENOENT);
    }
    Ok((ino, path))
}

fn read_guest_strvec(base: u32, vec_addr: u64) -> Result<Vec<Vec<u8>>, i64> {
    let mut out = Vec::new();
    if vec_addr == 0 {
        return Ok(out);
    }

    let mut idx = 0u64;
    loop {
        let ptr = unsafe { guest_mem::read_u64(base, vec_addr + idx * 8) };
        if ptr == 0 {
            break;
        }
        let mut bytes = read_guest_cstr_bytes(base, ptr)?;
        bytes.push(0);
        out.push(bytes);
        idx += 1;
    }
    Ok(out)
}

fn load_execve_image(
    vm: &ThreadState,
    base: u32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
    ram_size: u64,
) -> Result<ExecveImage, i64> {
    let (ino, path_bytes) = resolve_execve_inode(vm, base, path_addr)?;
    let argv = read_guest_strvec(base, argv_addr)?;
    let envp = read_guest_strvec(base, envp_addr)?;

    let st = match memfs::stat(ino) {
        Some(st) => st,
        None => return Err(ENOENT),
    };
    let mut elf_bytes = vec![0u8; st.size as usize];
    let nread = memfs::read_file(ino, 0, &mut elf_bytes);
    if nread != elf_bytes.len() as i64 {
        return Err(EIO);
    }

    let elf = match unsafe {
        crate::elf::inspect_elf(elf_bytes.as_ptr() as u32, elf_bytes.len() as u32, ram_size)
    } {
        Ok(result) => result,
        Err(_) => return Err(EINVAL),
    };

    Ok(ExecveImage {
        path_bytes,
        argv,
        envp,
        elf_bytes,
        elf,
    })
}

fn install_proc_self_exe(target: &[u8]) {
    let proc_ino = memfs::resolve_path(b"/proc");
    let proc_ino = if proc_ino == 0 {
        memfs::create_dir(1, b"proc", 0o555)
    } else {
        proc_ino
    };
    if proc_ino == 0 {
        return;
    }

    let self_ino = memfs::resolve_path(b"/proc/self");
    let self_ino = if self_ino == 0 {
        memfs::create_dir(proc_ino, b"self", 0o555)
    } else {
        self_ino
    };
    if self_ino == 0 {
        return;
    }

    if memfs::lookup(self_ino, b"exe") != 0 {
        let _ = memfs::unlink(self_ino, b"exe");
    }
    let _ = memfs::create_symlink(self_ino, b"exe", target);
}

fn write_stack_strings(base: u32, start: u64, strings: &[Vec<u8>]) -> Vec<u64> {
    let mut addrs = Vec::with_capacity(strings.len());
    let mut cursor = start;
    for bytes in strings {
        unsafe {
            guest_mem::write_bytes(base, cursor, bytes);
        }
        addrs.push(cursor);
        cursor += bytes.len() as u64;
    }
    addrs
}

fn ensure_guest_memory_capacity(base: u32, guest_end: u64) -> bool {
    let needed = base as u64 + guest_end;
    let mem_size = (core::arch::wasm32::memory_size(0) as u64) * 65536;
    if needed <= mem_size {
        return true;
    }

    let pages = ((needed - mem_size) + 65535) / 65536;
    core::arch::wasm32::memory_grow(0, pages as usize) != usize::MAX
}

fn current_guest_memory_limit(base: u32) -> u64 {
    ((core::arch::wasm32::memory_size(0) as u64) * 65536).saturating_sub(base as u64)
}

pub fn complete_execve_in_place(vm: &mut ThreadState, base: u32, ram_size: u64) -> i64 {
    if vm.spawn_kind != SPAWN_KIND_EXECVE {
        return EINVAL;
    }

    let ExecveImage {
        path_bytes,
        argv,
        envp,
        elf_bytes,
        elf,
    } = match load_execve_image(vm, base, vm.spawn_path, vm.spawn_argv, vm.spawn_envp, ram_size) {
        Ok(image) => image,
        Err(errno) => return errno,
    };

    let ps_addr = vm.process_ptr as u64;
    let old_pid =
        unsafe { guest_mem::read_i32(base, ps_addr + core::mem::offset_of!(ProcessState, pid) as u64) };
    let old_ppid = unsafe {
        guest_mem::read_i32(base, ps_addr + core::mem::offset_of!(ProcessState, ppid) as u64)
    };
    let old_cwd = unsafe {
        guest_mem::read_u32(base, ps_addr + core::mem::offset_of!(ProcessState, cwd_ino) as u64)
    };
    let old_fs_ring_base = unsafe {
        guest_mem::read_u32(base, ps_addr + core::mem::offset_of!(ProcessState, fs_ring_base) as u64)
    };
    let mut old_fd_table = [FdEntry {
        ofd_id: 0,
        fd_flags: 0,
    }; MAX_FDS];
    for (idx, entry) in old_fd_table.iter_mut().enumerate() {
        let entry_off = ps_addr + (idx * core::mem::size_of::<FdEntry>()) as u64;
        entry.ofd_id = unsafe { guest_mem::read_u32(base, entry_off) };
        entry.fd_flags = unsafe { guest_mem::read_u32(base, entry_off + 4) };
    }
    let target_pid = vm.spawn_child_pid;
    let is_vfork_exec = target_pid != old_pid;
    if is_vfork_exec {
        return EINVAL;
    }

    let mut inherited_fds = [FdEntry {
        ofd_id: 0,
        fd_flags: 0,
    }; MAX_FDS];
    for (idx, entry) in old_fd_table.iter().copied().enumerate() {
        if entry.ofd_id == 0 {
            continue;
        }
        if entry.fd_flags & fd_table::FD_CLOEXEC != 0 {
            continue;
        }
        inherited_fds[idx] = entry;
    }

    let ps_size = core::mem::size_of::<ProcessState>() as u64;
    let ps_align = core::mem::align_of::<ProcessState>() as u64;
    let new_ps_addr = (elf.brk_start + ps_align - 1) & !(ps_align - 1);
    if !ensure_guest_memory_capacity(base, new_ps_addr + ps_size) {
        return ENOMEM;
    }

    crate::syscall::thread::discard_other_threads_for_exec(vm, base);
    let elf_result = match unsafe {
        crate::elf::load_elf(base, ram_size, elf_bytes.as_ptr() as u32, elf_bytes.len() as u32)
    } {
        Ok(result) => result,
        Err(_) => return EINVAL,
    };
    crate::syscall::memory::reset_for_execve(elf_result.brk_start);

    let brk = crate::syscall::memory::current_brk();
    let ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
    if crate::syscall::memory::grow_brk(base, ps_addr + ps_size) < (ps_addr + ps_size) as i64 {
        return ENOMEM;
    }
    unsafe {
        guest_mem::zero_mem(base, ps_addr, ps_size as usize);
    }

    let mut released_cloexec_ofds = [false; MAX_FDS];
    for entry in old_fd_table.iter().copied() {
        if entry.ofd_id == 0 || entry.fd_flags & fd_table::FD_CLOEXEC == 0 {
            continue;
        }
        if inherited_fds.iter().any(|fd| fd.ofd_id == entry.ofd_id) {
            continue;
        }
        if released_cloexec_ofds[entry.ofd_id as usize] {
            continue;
        }
        released_cloexec_ofds[entry.ofd_id as usize] = true;
        fd_table::release_ofd_id(entry.ofd_id);
    }

    vm.process_ptr = ps_addr as u32;
    for (idx, entry) in inherited_fds.iter().enumerate() {
        let entry_off = ps_addr + (idx * core::mem::size_of::<FdEntry>()) as u64;
        unsafe {
            guest_mem::write_u32(base, entry_off, entry.ofd_id);
            guest_mem::write_u32(base, entry_off + 4, entry.fd_flags);
        }
    }
    let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
    let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
    let cwd_off = core::mem::offset_of!(ProcessState, cwd_ino) as u64;
    let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;
    unsafe {
        guest_mem::write_u32(base, ps_addr + pid_off, target_pid as u32);
        guest_mem::write_u32(base, ps_addr + ppid_off, old_ppid as u32);
        guest_mem::write_u32(base, ps_addr + cwd_off, old_cwd);
        guest_mem::write_u32(base, ps_addr + fs_ring_off, old_fs_ring_base);
    }

    let stack_top = current_guest_memory_limit(base).saturating_sub(PAGE_SIZE);
    let random_addr = stack_top.saturating_sub(16);
    unsafe {
        guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);
    }
    let argv_ptrs = write_stack_strings(base, stack_top.saturating_sub(0x4000), &argv);
    let envp_ptrs = write_stack_strings(base, stack_top.saturating_sub(0x2000), &envp);
    let sp = unsafe {
        crate::elf::setup_stack(
            base,
            stack_top.saturating_sub(128),
            &argv_ptrs,
            &envp_ptrs,
            &elf_result,
            random_addr,
        )
    };

    vm.x = [0; 32];
    vm.pc = elf_result.entry;
    vm.x[2] = sp;
    vm.f = [0; 32];
    vm.fcsr = 0;
    vm.status = STATUS_OK;
    vm.exit_code = 0;
    vm.tid = 1;
    vm.tls_base = 0;
    vm.sigaltstack_sp = 0;
    vm.sigaltstack_size = 0;
    vm.sigaltstack_flags = 0;
    vm.clear_child_tid = 0;
    vm.robust_list_head = 0;
    vm.robust_list_len = 0;
    vm.clone_flags = 0;
    vm.clone_child_stack = 0;
    vm.clone_tls = 0;
    vm.clone_child_tidptr = 0;
    vm.clone_child_tid = 0;
    vm.clone_pending = 0;
    clear_spawn_handoff(vm);

    crate::syscall::thread::init_main_thread(vm as *mut ThreadState as u32, base);
    crate::syscall::signal::reset_on_execve(target_pid);
    install_proc_self_exe(&path_bytes);
    if let Some(slot) = ensure_process(target_pid, old_ppid) {
        slot.did_exec = true;
    }

    0
}

fn record_child(pid: i32) {
    for c in children().iter_mut() {
        if c.pid == 0 {
            *c = ChildEntry {
                pid,
                exited: false,
                exit_code: 0,
            };
            return;
        }
    }
}

/// Record child exit (called by TS runtime when child Worker finishes).
pub fn record_child_exit(pid: i32, exit_code: i32) {
    for c in children().iter_mut() {
        if c.pid == pid && !c.exited {
            c.exited = true;
            c.exit_code = exit_code;
            return;
        }
    }
}

/// getpgid: return the process group ID for `pid`, or the caller when `pid == 0`.
/// A child inherits its parent's PGID across fork and PGID is preserved across execve.
/// https://man7.org/linux/man-pages/man2/setpgid.2.html
pub fn sys_getpgid(vm: &ThreadState, base: u32, pid: i64) -> i64 {
    let caller = match ensure_current_process(vm, base) {
        Some(slot) => *slot,
        None => return ESRCH,
    };
    let target_pid = if pid == 0 { caller.pid } else { pid as i32 };
    match process_entry(target_pid) {
        Some(slot) => slot.pgid as i64,
        None => ESRCH,
    }
}

/// setpgid: update the caller's or a direct child's process group membership.
/// This keeps the Linux/POSIX rules we rely on for LTP:
/// - pid == 0 targets the caller
/// - pgid == 0 makes PGID equal to the target PID
/// - only the caller or its direct child may be targeted
/// - session leaders cannot change PGID
/// - joining a different group requires an existing group in the same session
/// https://man7.org/linux/man-pages/man2/setpgid.2.html
pub fn sys_setpgid(vm: &ThreadState, base: u32, pid: i64, pgid: i64) -> i64 {
    if pgid < 0 {
        return EINVAL;
    }

    let caller = match ensure_current_process(vm, base) {
        Some(slot) => *slot,
        None => return ESRCH,
    };
    let target_pid = if pid == 0 { caller.pid } else { pid as i32 };
    let target_pgid = if pgid == 0 { target_pid } else { pgid as i32 };

    let target = match process_entry(target_pid) {
        Some(slot) => slot,
        None if target_pid == caller.pid => match ensure_current_process(vm, base) {
            Some(slot) => slot,
            None => return ESRCH,
        },
        None => return ESRCH,
    };

    if target_pid != caller.pid {
        if target.ppid != caller.pid {
            return ESRCH;
        }
        if target.did_exec {
            return EACCES;
        }
    }

    if target.sid == 0 {
        target.sid = caller.sid.max(caller.pid);
    }
    if target.sid != caller.sid {
        return EPERM;
    }
    if target.pid == target.sid {
        return EPERM;
    }

    if target_pgid != target.pid {
        if !group_exists_in_session(target_pgid, target.sid) {
            return EPERM;
        }
    }

    target.pgid = target_pgid;
    0
}

/// setsid: create a new session if the caller is not already a process group leader.
/// https://man7.org/linux/man-pages/man2/setsid.2.html
pub fn sys_setsid(vm: &ThreadState, base: u32) -> i64 {
    let caller = match ensure_current_process(vm, base) {
        Some(slot) => slot,
        None => return ESRCH,
    };
    let caller_pid = caller.pid;

    if processes()
        .iter()
        .any(|slot| slot.pid != 0 && slot.pgid == caller_pid)
    {
        return EPERM;
    }

    caller.sid = caller_pid;
    caller.pgid = caller_pid;
    caller_pid as i64
}

// =========================================================================
// vfork — parent suspend, child runs in parent's address space
// =========================================================================

/// sys_clone with CLONE_VFORK: snapshot parent, child continues with a0=0.
/// Returns STATUS_VFORK_WAIT to suspend parent.
pub fn sys_vfork(vm: &mut ThreadState, _base: u32) -> i32 {
    clear_spawn_handoff(vm);
    // Snapshot parent registers
    prs().vfork_snapshot = VforkSnapshot {
        x: vm.x,
        pc: vm.pc,
        f: vm.f,
        fcsr: vm.fcsr,
        sig_mask: vm.sig_mask,
    };
    prs().vfork_active = 1;

    // Child returns 0 from clone
    vm.x[10] = 0;
    // Parent will be resumed by TS when child calls execve or _exit.
    // For single-instance: child continues executing in the same thread-worker.
    // STATUS_VFORK_WAIT tells TS to suspend the parent side.
    vm.status = STATUS_VFORK_WAIT;
    STATUS_VFORK_WAIT
}

/// Restore parent from vfork snapshot. Called when child does execve or _exit.
pub fn vfork_parent_resume(vm: &mut ThreadState, child_pid: i32) {
    if prs().vfork_active == 0 {
        return;
    }
    let snap = prs().vfork_snapshot;
    prs().vfork_active = 0;
    vm.x = snap.x;
    vm.pc = snap.pc;
    vm.f = snap.f;
    vm.fcsr = snap.fcsr;
    vm.sig_mask = snap.sig_mask;
    vm.x[10] = child_pid as u64; // parent's clone returns child PID
    clear_spawn_handoff(vm);
    vm.status = STATUS_OK;
}

// =========================================================================
// execve
// =========================================================================

/// execve: replace process image.
/// Normal execve completes in place inside the current ThreadState.
/// vfork+execve exports `STATUS_EXECVE_SPAWN` so TS can create the post-exec child Worker.
/// https://man7.org/linux/man-pages/man2/execve.2.html
pub fn sys_execve(
    vm: &mut ThreadState,
    base: u32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
) -> i64 {
    let current_pid = match ensure_current_process(vm, base) {
        Some(slot) => slot.pid,
        None => return ESRCH,
    };
    let is_vfork_exec = prs().vfork_active != 0;

    if is_vfork_exec {
        if let Err(errno) =
            load_execve_image(vm, base, path_addr, argv_addr, envp_addr, EXECVE_RAM_LIMIT)
        {
            return errno;
        }
        let child_pid = alloc_pid();
        record_child(child_pid);
        inherit_process(current_pid, child_pid, true);
        crate::syscall::signal::fork_from_parent(current_pid, child_pid);
        crate::syscall::signal::reset_on_execve(child_pid);
        set_spawn_handoff(
            vm,
            SPAWN_KIND_EXECVE,
            child_pid,
            path_addr,
            argv_addr,
            envp_addr,
        );

        // Legacy fallback for existing tests/runtime stubs.
        vm.x[10] = path_addr;
        vm.x[11] = argv_addr;
        vm.x[12] = envp_addr;
        vm.x[13] = child_pid as u64;
        vm.status = STATUS_EXECVE_SPAWN;
        return child_pid as i64;
    }

    set_spawn_handoff(
        vm,
        SPAWN_KIND_EXECVE,
        current_pid,
        path_addr,
        argv_addr,
        envp_addr,
    );
    let ret = complete_execve_in_place(vm, base, EXECVE_RAM_LIMIT);
    if ret < 0 {
        clear_spawn_handoff(vm);
    }
    ret
}

// =========================================================================
// wait4
// =========================================================================

/// wait4: wait for child process state change.
/// https://man7.org/linux/man-pages/man2/wait4.2.html
pub fn sys_wait4(
    vm: &mut ThreadState,
    base: u32,
    pid: i64,
    wstatus_addr: u64,
    options: u64,
    _rusage_addr: u64,
) -> i64 {
    let wnohang = (options & WNOHANG) != 0;

    for c in children().iter_mut() {
        if c.pid == 0 {
            continue;
        }

        let matches = pid == -1 || pid == c.pid as i64;
        if !matches {
            continue;
        }

        if c.exited {
            let child_pid = c.pid;
            let code = c.exit_code;
            *c = ChildEntry {
                pid: 0,
                exited: false,
                exit_code: 0,
            };

            if wstatus_addr != 0 {
                let wstatus = (code as u32) << 8;
                unsafe { guest_mem::write_u32(base, wstatus_addr, wstatus) };
            }

            return child_pid as i64;
        }
    }

    if wnohang {
        return 0;
    }

    let has_children = children()
        .iter()
        .any(|c| c.pid != 0 && (pid == -1 || pid == c.pid as i64));
    if !has_children {
        return ECHILD;
    }

    // TODO: STATUS_WAIT for blocking wait4
    ECHILD
}

// =========================================================================
// fork (plain)
// =========================================================================

/// Plain fork: guest Memory full copy → STATUS_EXECVE_SPAWN.
/// TS creates new Worker with copied Memory.
pub fn sys_fork(vm: &mut ThreadState, base: u32) -> i64 {
    let parent_pid = match ensure_current_process(vm, base) {
        Some(slot) => slot.pid,
        None => return ESRCH,
    };
    let child_pid = alloc_pid();
    record_child(child_pid);
    inherit_process(parent_pid, child_pid, false);

    set_spawn_handoff(vm, SPAWN_KIND_FORK, child_pid, 0, 0, 0);
    // Legacy fallback for existing tests/runtime stubs.
    vm.x[10] = child_pid as u64;
    vm.status = STATUS_EXECVE_SPAWN;
    child_pid as i64
}

// ECHILD error code
const ECHILD: i64 = -10;
// WNOHANG flag
const WNOHANG: u64 = 1;

#[cfg(test)]
mod tests {
    use alloc_crate::vec;
    use alloc_crate::vec::Vec;
    use crate::abi::*;
    use crate::fs::memfs;
    use crate::test_helpers::TestVm;
    use crate::types::{FdEntry, ProcessState, ThreadRecord, THREAD_NONE, THREAD_RUNNING};
    use core::sync::atomic::Ordering;

    fn write_process_ids(t: &TestVm, pid: i32, ppid: i32) {
        let ps_ptr = t.vm.process_ptr as u64;
        let pid_off = core::mem::offset_of!(crate::types::ProcessState, pid) as u64;
        let ppid_off = core::mem::offset_of!(crate::types::ProcessState, ppid) as u64;
        unsafe {
            crate::guest_mem::write_u32(t.base, ps_ptr + pid_off, pid as u32);
            crate::guest_mem::write_u32(t.base, ps_ptr + ppid_off, ppid as u32);
        }
    }

    fn ensure_dir(parent: u32, name: &[u8]) -> u32 {
        let ino = memfs::lookup(parent, name);
        if ino != 0 {
            ino
        } else {
            memfs::create_dir(parent, name, 0o755)
        }
    }

    fn build_test_elf(code: &[u8]) -> Vec<u8> {
        fn put_u16(buf: &mut [u8], off: usize, value: u16) {
            buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn put_u32(buf: &mut [u8], off: usize, value: u32) {
            buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn put_u64(buf: &mut [u8], off: usize, value: u64) {
            buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }

        let mut elf = vec![0u8; 0x100 + code.len()];
        elf[0] = 0x7f;
        elf[1] = b'E';
        elf[2] = b'L';
        elf[3] = b'F';
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        put_u16(&mut elf, 16, 2);
        put_u16(&mut elf, 18, 243);
        put_u32(&mut elf, 20, 1);
        put_u64(&mut elf, 24, 0x1000);
        put_u64(&mut elf, 32, 64);
        put_u16(&mut elf, 52, 64);
        put_u16(&mut elf, 54, 56);
        put_u16(&mut elf, 56, 1);

        put_u32(&mut elf, 64, 1);
        put_u32(&mut elf, 68, 5);
        put_u64(&mut elf, 72, 0x100);
        put_u64(&mut elf, 80, 0x1000);
        put_u64(&mut elf, 96, code.len() as u64);
        put_u64(&mut elf, 104, code.len() as u64);
        put_u64(&mut elf, 112, 0x1000);
        elf[0x100..0x100 + code.len()].copy_from_slice(code);
        elf
    }

    fn install_exec_file(t: &TestVm, name: &[u8], elf_bytes: &[u8]) -> u64 {
        let bin = ensure_dir(1, b"bin");
        let ino = match memfs::lookup(bin, name) {
            0 => memfs::create_file(bin, name, 0o755),
            ino => ino,
        };
        assert!(ino != 0);
        assert_eq!(memfs::truncate(ino, 0), 0);
        assert_eq!(memfs::write_file(ino, 0, elf_bytes), elf_bytes.len() as i64);

        let mut path = Vec::from(&b"/bin/"[..]);
        path.extend_from_slice(name);
        path.push(0);
        let path_addr = t.scratch;
        t.write_mem(path_addr, &path);
        path_addr
    }

    fn write_strvec(t: &TestVm, offset: u64, values: &[&[u8]]) -> u64 {
        if values.is_empty() {
            return 0;
        }
        let vec_addr = t.scratch + offset;
        let mut data_cursor = vec_addr + ((values.len() + 1) as u64) * 8;
        for (idx, value) in values.iter().enumerate() {
            unsafe {
                crate::guest_mem::write_u64(t.base, vec_addr + (idx as u64) * 8, data_cursor);
                crate::guest_mem::write_bytes(t.base, data_cursor, value);
                crate::guest_mem::write_u8(t.base, data_cursor + value.len() as u64, 0);
            }
            data_cursor += value.len() as u64 + 1;
        }
        unsafe {
            crate::guest_mem::write_u64(t.base, vec_addr + (values.len() as u64) * 8, 0);
        }
        vec_addr
    }

    #[test]
    fn vfork_snapshots_and_suspends_parent() {
        let mut t = TestVm::new();
        t.vm.x[1] = 0xDEAD;
        t.vm.pc = 0x1000;

        let status = super::sys_vfork(&mut t.vm, t.base);
        assert_eq!(status, STATUS_VFORK_WAIT);
        assert_eq!(t.vm.x[10], 0, "child should see a0=0");
        assert_eq!(t.vm.status, STATUS_VFORK_WAIT);

        // Snapshot should be stored
        assert!(super::vfork_snapshot_active());
    }

    #[test]
    fn vfork_parent_resume_restores_state() {
        let mut t = TestVm::new();
        t.vm.x[1] = 0xBEEF;
        t.vm.pc = 0x2000;

        super::sys_vfork(&mut t.vm, t.base);

        // Child modifies state
        t.vm.x[1] = 0xFFFF;
        t.vm.pc = 0x9999;

        // Resume parent with child_pid=42
        super::vfork_parent_resume(&mut t.vm, 42);
        assert_eq!(t.vm.x[1], 0xBEEF, "parent x1 should be restored");
        assert_eq!(t.vm.pc, 0x2000, "parent pc should be restored");
        assert_eq!(t.vm.x[10], 42, "parent a0 should be child PID");
        assert_eq!(t.vm.status, STATUS_OK);
    }

    #[test]
    fn execve_completes_in_place_without_spawn() {
        let mut t = TestVm::new();
        let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
        let path_addr = install_exec_file(&t, b"test", &elf);

        let ret = super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
        assert_eq!(ret, 0, "successful execve should not return a child pid");
        assert_eq!(t.vm.status, STATUS_OK);
        assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
        assert_eq!(t.vm.spawn_child_pid, 0);
        assert_eq!(t.vm.pc, 0x1000);
    }

    #[test]
    fn execve_discards_other_threads_on_success() {
        let mut t = TestVm::new();
        let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
        ps.thread_count.store(2, Ordering::Release);
        ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
        let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
        let path_addr = install_exec_file(&t, b"test", &elf);
        let ret = super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
        assert_eq!(ret, 0);
        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        assert_eq!(ps.thread_count.load(Ordering::Acquire), 1);
        assert_eq!(ps.threads[0].state, THREAD_RUNNING);
        assert_eq!(ps.threads[1].state, THREAD_NONE);
    }

    #[test]
    fn execve_clears_alt_stack() {
        let mut t = TestVm::new();
        t.vm.sigaltstack_sp = 0x5000;
        t.vm.sigaltstack_size = 8192;

        let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
        let path_addr = install_exec_file(&t, b"test", &elf);
        super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

        assert_eq!(
            t.vm.sigaltstack_sp, 0,
            "alt stack should be cleared by execve"
        );
        assert_eq!(t.vm.sigaltstack_size, 0);
    }

    #[test]
    fn execve_preserves_signal_mask_and_pending() {
        let mut t = TestVm::new();
        t.vm.sig_mask = (1u64 << (crate::abi::SIGALRM - 1)) | (1u64 << (crate::abi::SIGTERM - 1));
        t.vm.sig_pending = 1u64 << (crate::abi::SIGCHLD - 1);

        let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
        let path_addr = install_exec_file(&t, b"test", &elf);
        super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

        assert_eq!(
            t.vm.sig_mask,
            (1u64 << (crate::abi::SIGALRM - 1)) | (1u64 << (crate::abi::SIGTERM - 1))
        );
        assert_eq!(t.vm.sig_pending, 1u64 << (crate::abi::SIGCHLD - 1));
    }

    #[test]
    fn execve_in_place_reload_rebuilds_process_state() {
        let mut t = TestVm::new();
        let mapped = crate::syscall::memory::sys_mmap(
            &mut t.vm,
            t.base,
            0,
            PAGE_SIZE,
            PROT_NONE as u64,
            (MAP_PRIVATE | MAP_ANONYMOUS) as u64,
            -1,
            0,
        );
        assert!(mapped >= 0);
        assert!(crate::syscall::memory::has_prot_none());

        t.memfs.create_file(b"keep.txt", b"payload");
        let kept_fd = t.sys_openat(b"/keep.txt", O_RDONLY);
        assert_eq!(kept_fd, 3);
        let cloexec_fd = t.sys_dup(kept_fd as u64);
        assert_eq!(cloexec_fd, 4);
        assert_eq!(t.sys_fcntl(cloexec_fd as u64, 2, 1), 0);

        let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
        let path_addr = install_exec_file(&t, b"test", &elf);
        let argv_addr = write_strvec(&t, 0x400, &[b"/bin/test", b"arg1"]);
        let envp_addr = write_strvec(&t, 0x800, &[b"KEY=VALUE"]);

        let ret = super::sys_execve(&mut t.vm, t.base, path_addr, argv_addr, envp_addr);
        assert_eq!(ret, 0);
        assert_eq!(t.vm.status, STATUS_OK);
        assert_eq!(t.vm.pc, 0x1000);
        assert_eq!(t.vm.tid, 1);
        assert!(!crate::syscall::memory::has_prot_none());

        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        assert_eq!(ps.pid, 42);
        let kept_entry = unsafe {
            crate::guest_mem::read_u32(t.base, t.vm.process_ptr as u64 + 3 * core::mem::size_of::<FdEntry>() as u64)
        };
        let cloexec_entry = unsafe {
            crate::guest_mem::read_u32(t.base, t.vm.process_ptr as u64 + 4 * core::mem::size_of::<FdEntry>() as u64)
        };
        assert_ne!(kept_entry, 0, "non-CLOEXEC fd should survive execve");
        assert_eq!(cloexec_entry, 0, "CLOEXEC fd should be dropped on execve");

        let argc = unsafe { crate::guest_mem::read_u64(t.base, t.vm.x[2]) };
        assert_eq!(argc, 2);
        let argv0 = unsafe { crate::guest_mem::read_u64(t.base, t.vm.x[2] + 8) };
        let argv1 = unsafe { crate::guest_mem::read_u64(t.base, t.vm.x[2] + 16) };
        let mut buf = [0u8; 32];
        let len0 = unsafe { crate::guest_mem::read_cstr(t.base, argv0, &mut buf) };
        assert_eq!(&buf[..len0], b"/bin/test");
        let len1 = unsafe { crate::guest_mem::read_cstr(t.base, argv1, &mut buf) };
        assert_eq!(&buf[..len1], b"arg1");
    }

    #[test]
    fn execve_failure_preserves_thread_group_and_altstack() {
        let mut t = TestVm::new();
        let ps_before = t.vm.process_ptr;
        let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
        ps.thread_count.store(2, Ordering::Release);
        ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
        t.vm.sigaltstack_sp = 0x7000;
        t.vm.sigaltstack_size = 4096;

        let path_addr = install_exec_file(&t, b"bad", b"not-an-elf");
        let ret = super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
        assert_eq!(ret, EINVAL);
        assert_eq!(t.vm.status, STATUS_OK);
        assert_eq!(t.vm.process_ptr, ps_before);
        assert_eq!(t.vm.sigaltstack_sp, 0x7000);
        assert_eq!(t.vm.sigaltstack_size, 4096);

        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        assert_eq!(ps.thread_count.load(Ordering::Acquire), 2);
        assert_eq!(ps.threads[1].state, THREAD_RUNNING);
    }

    #[test]
    fn wait4_returns_exited_child() {
        let mut t = TestVm::new();
        let child_pid = super::alloc_pid();
        super::record_child(child_pid);
        super::record_child_exit(child_pid, 42);

        let wstatus_addr = t.scratch + 0x100;
        let ret = super::sys_wait4(&mut t.vm, t.base, -1, wstatus_addr, 0, 0);
        assert_eq!(ret, child_pid as i64);

        let wstatus = unsafe { crate::guest_mem::read_u32(t.base, wstatus_addr) };
        assert_eq!(wstatus >> 8, 42, "wstatus should encode exit_code=42");
    }

    #[test]
    fn wait4_wnohang_returns_zero_if_no_exit() {
        let mut t = TestVm::new();
        let child_pid = super::alloc_pid();
        super::record_child(child_pid);
        // Child not yet exited

        let ret = super::sys_wait4(&mut t.vm, t.base, -1, 0, super::WNOHANG, 0);
        assert_eq!(ret, 0, "WNOHANG should return 0 when no child exited");
    }

    #[test]
    fn fork_returns_status_execve_spawn() {
        let mut t = TestVm::new();
        let ret = super::sys_fork(&mut t.vm, t.base);
        assert!(ret > 0, "fork should return positive child PID");
        assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
        assert_eq!(t.vm.spawn_kind, SPAWN_KIND_FORK);
        assert_eq!(t.vm.spawn_child_pid, ret as i32);
        assert_eq!(t.vm.spawn_path, 0);
    }

    #[test]
    fn vfork_parent_resume_clears_spawn_handoff() {
        let mut t = TestVm::new();
        let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
        let path_addr = install_exec_file(&t, b"test", &elf);

        super::sys_vfork(&mut t.vm, t.base);
        let child_pid = super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
        assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
        assert_eq!(t.vm.spawn_kind, SPAWN_KIND_EXECVE);
        assert_ne!(child_pid, 42, "vfork child execve should allocate a new child PID");

        super::vfork_parent_resume(&mut t.vm, child_pid as i32);
        assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
        assert_eq!(t.vm.spawn_child_pid, 0);
        assert_eq!(t.vm.x[10], child_pid as u64);
    }

    #[test]
    fn vfork_execve_failure_does_not_publish_spawn_handoff() {
        let mut t = TestVm::new();
        let path_addr = install_exec_file(&t, b"bad", b"not-an-elf");

        super::sys_vfork(&mut t.vm, t.base);
        let ret = super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
        assert_eq!(ret, EINVAL);
        assert_eq!(t.vm.status, STATUS_VFORK_WAIT);
        assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
        assert_eq!(t.vm.spawn_child_pid, 0);
    }

    #[test]
    fn getpgid_and_setpgid_track_child_groups() {
        let mut t = TestVm::new();

        assert_eq!(super::sys_getpgid(&t.vm, t.base, 0), 42);

        let child_pid = super::sys_fork(&mut t.vm, t.base);
        assert!(child_pid > 0);
        assert_eq!(super::sys_getpgid(&t.vm, t.base, child_pid), 42);

        assert_eq!(super::sys_setpgid(&t.vm, t.base, child_pid, child_pid), 0);
        assert_eq!(super::sys_getpgid(&t.vm, t.base, child_pid), child_pid);
    }

    #[test]
    fn setsid_creates_new_session_for_non_group_leader() {
        let t = TestVm::new();

        write_process_ids(&t, 1, 0);
        assert_eq!(super::sys_getpgid(&t.vm, t.base, 0), 1);

        write_process_ids(&t, 42, 1);
        assert_eq!(super::sys_getpgid(&t.vm, t.base, 0), 1);

        assert_eq!(super::sys_setsid(&t.vm, t.base), 42);
        assert_eq!(super::sys_getpgid(&t.vm, t.base, 0), 42);
    }
}
