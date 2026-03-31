//! Process lifecycle syscalls: execve, wait4, vfork, fork.
//!
//! vfork: parent suspends (STATUS_VFORK_WAIT), child runs in parent's memory.
//! execve: normal path replaces the current process in place; vfork+execve exports
//! handoff data so TS can create the post-exec child Worker in the runtime harness.
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
pub const EXECVE_RAM_LIMIT: u64 = 0x8000_0000;
const EXECVE_PATH_MAX: usize = 4096;
const EXECVE_NAME_MAX: usize = 255;

#[derive(Clone, Copy)]
struct ChildEntry {
    pid: i32,
    parent_pid: i32,
    exited: bool,
    wait_status: i32,
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
    status: i32,
    exit_code: i32,
    term_signal: i32,
    tid: i32,
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    tls_base: u64,
    clear_child_tid: u64,
    robust_list_head: u64,
    robust_list_len: u64,
    sig_mask: u64,
    sig_pending: u64,
    sigaltstack_sp: u64,
    sigaltstack_size: u64,
    sigaltstack_flags: i32,
    lr_addr: u64,
    lr_val: u64,
    insn_budget: i32,
    fault_pc: u64,
    fault_addr: u64,
    guest_base: u32,
    process_ptr: u32,
    clone_flags: u64,
    clone_child_stack: u64,
    clone_tls: u64,
    clone_child_tidptr: u64,
    clone_child_tid: i32,
    clone_pending: i32,
    spawn_kind: u32,
    spawn_flags: u32,
    spawn_child_pid: i32,
    spawn_path: u64,
    spawn_argv: u64,
    spawn_envp: u64,
    wait_pid: i64,
    wait_kind: u32,
    wait_idtype: u32,
    wait_wstatus_addr: u64,
    wait_options: u64,
    wait_rusage_addr: u64,
    futex_wait_addr: u64,
    futex_wait_timeout: u64,
    epoll_timeout_ms: i64,
    blocked_fd: u32,
    blocked_ofd_id: u32,
    child_pid: i32,
}

struct ExecveImage {
    path_bytes: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    elf_ptr: u32,
    elf_len: u32,
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

fn empty_vfork_snapshot() -> VforkSnapshot {
    VforkSnapshot {
        x: [0; 32],
        pc: 0,
        f: [0; 32],
        fcsr: 0,
        status: 0,
        exit_code: 0,
        term_signal: 0,
        tid: 0,
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        tls_base: 0,
        clear_child_tid: 0,
        robust_list_head: 0,
        robust_list_len: 0,
        sig_mask: 0,
        sig_pending: 0,
        sigaltstack_sp: 0,
        sigaltstack_size: 0,
        sigaltstack_flags: 0,
        lr_addr: 0,
        lr_val: 0,
        insn_budget: 0,
        fault_pc: 0,
        fault_addr: 0,
        guest_base: 0,
        process_ptr: 0,
        clone_flags: 0,
        clone_child_stack: 0,
        clone_tls: 0,
        clone_child_tidptr: 0,
        clone_child_tid: 0,
        clone_pending: 0,
        spawn_kind: 0,
        spawn_flags: 0,
        spawn_child_pid: 0,
        spawn_path: 0,
        spawn_argv: 0,
        spawn_envp: 0,
        wait_pid: 0,
        wait_kind: 0,
        wait_idtype: 0,
        wait_wstatus_addr: 0,
        wait_options: 0,
        wait_rusage_addr: 0,
        futex_wait_addr: 0,
        futex_wait_timeout: 0,
        epoll_timeout_ms: 0,
        blocked_fd: 0,
        blocked_ofd_id: 0,
        child_pid: 0,
    }
}

fn seeded_process_table() -> [ProcessEntry; MAX_PROCESSES] {
    let mut table = [ProcessEntry {
        pid: 0,
        ppid: 0,
        pgid: 0,
        sid: 0,
        did_exec: false,
    }; MAX_PROCESSES];
    // Seed PID 1 so process-group queries against init work in both
    // runtime code and LTP process-group tests.
    table[0] = ProcessEntry {
        pid: 1,
        ppid: 0,
        pgid: 1,
        sid: 1,
        did_exec: false,
    };
    table
}

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
                    parent_pid: 0,
                    exited: false,
                    wait_status: 0,
                }; MAX_CHILDREN],
                next_pid: 3,
                vfork_active: 0,
                process_table: seeded_process_table(),
                vfork_snapshot: empty_vfork_snapshot(),
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(PROCESS_RUNTIME_STATE), state);
    }
}

pub fn process_runtime_state_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(PROCESS_RUNTIME_STATE)) as u32 }
}

pub fn process_runtime_state_bytes() -> u32 {
    core::mem::size_of::<ProcessRuntimeState>() as u32
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

pub fn vfork_active() -> bool {
    prs().vfork_active != 0
}

pub fn vfork_child_pid() -> i32 {
    if prs().vfork_active == 0 {
        0
    } else {
        prs().vfork_snapshot.child_pid
    }
}

fn set_next_pid_floor(next_pid: i32) {
    prs().next_pid = prs().next_pid.max(next_pid.max(3));
}

fn current_process_state_mut(vm: &ThreadState, base: u32) -> Option<&'static mut ProcessState> {
    if vm.process_ptr == 0 {
        return None;
    }
    unsafe { Some(&mut *((base as u64 + vm.process_ptr as u64) as *mut ProcessState)) }
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

fn inherit_process(identity_parent_pid: i32, child_ppid: i32, child_pid: i32, did_exec: bool) {
    let (parent_pgid, parent_sid) = inherit_group_from_parent(identity_parent_pid);
    if let Some(slot) = process_idx(child_pid).map(|idx| &mut processes()[idx]) {
        *slot = ProcessEntry {
            pid: child_pid,
            ppid: child_ppid,
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

pub fn current_process_pid(vm: &ThreadState, base: u32) -> i32 {
    crate::syscall::signal::pid_from_vm(vm, base)
}

pub fn current_process_ppid(vm: &ThreadState, base: u32) -> i32 {
    current_process_state_mut(vm, base).map(|ps| ps.ppid).unwrap_or(0)
}

pub fn current_process_pgid(vm: &ThreadState, base: u32) -> i32 {
    ensure_current_process(vm, base)
        .map(|slot| slot.pgid)
        .unwrap_or_else(|| current_process_pid(vm, base))
}

pub fn current_process_sid(vm: &ThreadState, base: u32) -> i32 {
    ensure_current_process(vm, base)
        .map(|slot| slot.sid)
        .unwrap_or_else(|| current_process_pid(vm, base))
}

pub fn current_process_did_exec(vm: &ThreadState, base: u32) -> bool {
    let pid = current_process_pid(vm, base);
    process_entry(pid).map(|slot| slot.did_exec).unwrap_or(false)
}

pub fn upsert_process_entry(pid: i32, ppid: i32, pgid: i32, sid: i32, did_exec: bool) {
    let Some(idx) = process_idx(pid) else {
        return;
    };
    reserve_pid(pid);
    processes()[idx] = ProcessEntry {
        pid,
        ppid,
        pgid,
        sid,
        did_exec,
    };
}

pub fn remove_process_entry(pid: i32) {
    let Some(idx) = process_idx(pid) else {
        return;
    };
    processes()[idx] = ProcessEntry {
        pid: 0,
        ppid: 0,
        pgid: 0,
        sid: 0,
        did_exec: false,
    };
}

pub fn rewrite_child_pid(
    vm: &mut ThreadState,
    base: u32,
    old_pid: i32,
    new_pid: i32,
    next_pid: i32,
) {
    if old_pid <= 0 || new_pid <= 0 {
        set_next_pid_floor(next_pid);
        return;
    }

    if old_pid != new_pid {
        for child in children().iter_mut() {
            if child.pid == old_pid {
                child.pid = new_pid;
            }
            if child.parent_pid == old_pid {
                child.parent_pid = new_pid;
            }
        }

        let old_idx = process_idx(old_pid);
        let new_idx = process_idx(new_pid);
        if let (Some(old_idx), Some(new_idx)) = (old_idx, new_idx) {
            let old_entry = processes()[old_idx];
            if old_entry.pid == old_pid {
                processes()[new_idx] = ProcessEntry {
                    pid: new_pid,
                    ..old_entry
                };
                processes()[old_idx] = ProcessEntry {
                    pid: 0,
                    ppid: 0,
                    pgid: 0,
                    sid: 0,
                    did_exec: false,
                };
            }
        }

        if prs().vfork_snapshot.child_pid == old_pid {
            prs().vfork_snapshot.child_pid = new_pid;
        }

        if let Some(ps) = current_process_state_mut(vm, base) {
            if ps.pid == old_pid {
                ps.pid = new_pid;
            }
            if ps.ppid == old_pid {
                ps.ppid = new_pid;
            }
        }

        if vm.spawn_child_pid == old_pid {
            vm.spawn_child_pid = new_pid;
        }
        if vm.clone_child_tid == old_pid {
            vm.clone_child_tid = new_pid;
        }
        if vm.x[10] == old_pid as u64 {
            vm.x[10] = new_pid as u64;
        }

        crate::syscall::signal::reassign_process_pid(old_pid, new_pid);
    }

    set_next_pid_floor(next_pid);
}

pub fn reset_process_lifecycle(
    vm: &mut ThreadState,
    base: u32,
    pid: i32,
    ppid: i32,
    next_pid: i32,
    pgid: i32,
    sid: i32,
    did_exec: bool,
) {
    let old_pid = current_process_pid(vm, base);

    prs().children = [empty_child_entry(); MAX_CHILDREN];
    prs().next_pid = next_pid.max(pid + 1).max(3);
    prs().vfork_active = 0;
    prs().vfork_snapshot = empty_vfork_snapshot();
    prs().process_table = seeded_process_table();

    if let Some(slot) = process_idx(pid).map(|idx| &mut processes()[idx]) {
        *slot = ProcessEntry {
            pid,
            ppid,
            pgid,
            sid,
            did_exec,
        };
    }

    if let Some(ps) = current_process_state_mut(vm, base) {
        ps.pid = pid;
        ps.ppid = ppid;
    }
    crate::syscall::thread::init_main_thread(vm as *mut ThreadState as u32, base);

    crate::syscall::signal::reassign_process_pid(old_pid, pid);
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

fn current_effective_uid(_vm: &ThreadState) -> u32 {
    _vm.euid
}

fn current_effective_gid(_vm: &ThreadState) -> u32 {
    _vm.egid
}

fn reattach_guest_thread_count(vm: &mut ThreadState, base: u32) {
    if let Some(ps) = current_process_state_mut(vm, base) {
        let tc_ptr = core::ptr::addr_of!(ps.thread_count);
        unsafe {
            guest_mem::init(core::ptr::null(), tc_ptr);
        }
    }
}

fn read_guest_cstr_bytes(base: u32, addr: u64) -> Result<Vec<u8>, i64> {
    if addr == 0 {
        return Err(EFAULT);
    }

    let guest_limit = ((core::arch::wasm32::memory_size(0) as u64) * 65536)
        .saturating_sub(base as u64);
    if addr >= guest_limit || addr > u32::MAX as u64 {
        return Err(EFAULT);
    }

    let mut out = Vec::new();
    let mut offset = 0u64;
    loop {
        let Some(cur) = addr.checked_add(offset) else {
            return Err(EFAULT);
        };
        if cur >= guest_limit || cur > u32::MAX as u64 {
            return Err(EFAULT);
        }
        if crate::syscall::memory::range_has_prot_none(cur, 1) {
            return Err(EFAULT);
        }

        let byte = unsafe { guest_mem::read_u8(base, cur) };
        if byte == 0 {
            break;
        }
        out.push(byte);
        if out.len() > EXECVE_PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        offset += 1;
    }

    if out.is_empty() {
        return Err(ENOENT);
    }
    Ok(out)
}

fn resolve_execve_inode(
    vm: &ThreadState,
    base: u32,
    path_addr: u64,
) -> Result<(u32, Vec<u8>), i64> {
    let path = read_guest_cstr_bytes(base, path_addr)?;
    let mut ino = if path.first() == Some(&b'/') {
        1
    } else {
        current_cwd_ino(vm, base)
    };

    let components = if path.first() == Some(&b'/') {
        &path[1..]
    } else {
        &path[..]
    };
    for component in components.split(|&b| b == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component.len() > EXECVE_NAME_MAX {
            return Err(ENAMETOOLONG);
        }
        let parent = match memfs::stat(ino) {
            Some(parent) => parent,
            None => return Err(ENOENT),
        };
        if parent.mode & memfs::S_IFMT != memfs::S_IFDIR {
            return Err(ENOTDIR);
        }
        ino = memfs::lookup(ino, component);
        if ino == 0 {
            return Err(ENOENT);
        }
    }

    let mut absolute = [0u8; 1024];
    let absolute_len = memfs::write_path(ino, &mut absolute);
    if absolute_len != 0 {
        Ok((ino, absolute[..absolute_len].to_vec()))
    } else {
        Ok((ino, path))
    }
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
    let st = match memfs::stat(ino) {
        Some(st) => st,
        None => return Err(ENOENT),
    };
    if st.mode & memfs::S_IFMT != memfs::S_IFREG {
        return Err(EACCES);
    }
    let exec_mask = if current_effective_uid(vm) == 0 {
        st.mode & 0o111
    } else if current_effective_uid(vm) == st.uid {
        st.mode & 0o100
    } else if current_effective_gid(vm) == st.gid {
        st.mode & 0o010
    } else {
        st.mode & 0o001
    };
    if exec_mask == 0 {
        return Err(EACCES);
    }
    if fd_table::inode_has_write_open(ino) {
        return Err(ETXTBSY);
    }
    let elf_len = match u32::try_from(st.size) {
        Ok(len) if len > 0 => len,
        _ => return Err(ENOEXEC),
    };
    let elf_ptr = match memfs::file_data_ptr(ino) {
        Some(ptr) => ptr,
        None => return Err(EIO),
    };

    let elf = match unsafe { crate::elf::inspect_elf(elf_ptr, elf_len, ram_size) } {
        Ok(result) => result,
        Err(_) => return Err(ENOEXEC),
    };
    let mut argv = read_guest_strvec(base, argv_addr)?;
    let envp = read_guest_strvec(base, envp_addr)?;
    if argv.is_empty() {
        // Linux fills in a dummy argv[0] when execve() is called with an
        // empty argument vector, so post-exec user space never sees argc == 0.
        argv.push(vec![0]);
    }

    Ok(ExecveImage {
        path_bytes,
        argv,
        envp,
        elf_ptr,
        elf_len,
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

fn write_stack_strings(base: u32, start: u64, strings: &[Vec<u8>], addrs: &mut [u64]) {
    let mut cursor = start;
    for (idx, bytes) in strings.iter().enumerate() {
        unsafe {
            guest_mem::write_bytes(base, cursor, bytes);
        }
        addrs[idx] = cursor;
        cursor += bytes.len() as u64;
    }
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
    let heap_base = crate::alloc::heap_base() as u64;
    let limit = if heap_base > base as u64 {
        heap_base - base as u64
    } else {
        ((core::arch::wasm32::memory_size(0) as u64) * 65536).saturating_sub(base as u64)
    };
    limit.min(EXECVE_RAM_LIMIT)
}

fn retain_process_ofds(base: u32, process_ptr: u32) {
    let ps = unsafe { &*((base as u64 + process_ptr as u64) as *const ProcessState) };
    let mut seen = [false; MAX_FDS];
    for entry in ps.fd_table.iter() {
        if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS || seen[entry.ofd_id as usize] {
            continue;
        }
        seen[entry.ofd_id as usize] = true;
        fd_table::retain_ofd_id(entry.ofd_id);
    }
}

fn clone_process_state_for_vfork(
    vm: &ThreadState,
    base: u32,
    parent_pid: i32,
    child_pid: i32,
) -> Option<u32> {
    let parent_ps_addr = vm.process_ptr as u64;
    if parent_ps_addr == 0 {
        return None;
    }

    let ps_size = core::mem::size_of::<ProcessState>() as u64;
    let ps_align = core::mem::align_of::<ProcessState>() as u64;
    let brk = crate::syscall::memory::current_brk();
    let child_ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
    if crate::syscall::memory::grow_brk(base, child_ps_addr + ps_size) < (child_ps_addr + ps_size) as i64
    {
        return None;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            (base as u64 + parent_ps_addr) as *const u8,
            (base as u64 + child_ps_addr) as *mut u8,
            ps_size as usize,
        );
    }

    let child_ps = unsafe { &mut *((base as u64 + child_ps_addr) as *mut ProcessState) };
    child_ps.pid = child_pid;
    child_ps.ppid = parent_pid;
    child_ps.thread_count
        .store(1, core::sync::atomic::Ordering::Release);
    for record in child_ps.threads.iter_mut() {
        *record = crate::types::ThreadRecord::empty();
    }
    if vm.tid > 0 && vm.tid as usize <= MAX_THREADS {
        child_ps.threads[(vm.tid - 1) as usize] = crate::types::ThreadRecord::new(
            vm.tid,
            crate::types::THREAD_RUNNING,
            vm as *const ThreadState as u32,
            vm.clear_child_tid as u32,
            0,
        );
    }

    retain_process_ofds(base, child_ps_addr as u32);
    Some(child_ps_addr as u32)
}

pub fn complete_execve_in_place(vm: &mut ThreadState, base: u32, ram_size: u64) -> i64 {
    if vm.spawn_kind != SPAWN_KIND_EXECVE {
        return EINVAL;
    }
    crate::runtime_test_support::record_execve_stage(1, base as u64, ram_size);

    let ExecveImage {
        path_bytes,
        argv,
        envp,
        elf_ptr,
        elf_len,
        elf,
    } = match load_execve_image(
        vm,
        base,
        vm.spawn_path,
        vm.spawn_argv,
        vm.spawn_envp,
        ram_size,
    ) {
        Ok(image) => image,
        Err(errno) => return errno,
    };
    crate::runtime_test_support::record_execve_stage(2, elf.brk_start, elf.entry);

    let ps_addr = vm.process_ptr as u64;
    let old_pid = unsafe {
        guest_mem::read_i32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, pid) as u64,
        )
    };
    let old_ppid = unsafe {
        guest_mem::read_i32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, ppid) as u64,
        )
    };
    let old_cwd = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, cwd_ino) as u64,
        )
    };
    let old_stdin_pipe_slot = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, stdin_pipe_slot) as u64,
        )
    };
    let old_stdout_pipe_slot = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, stdout_pipe_slot) as u64,
        )
    };
    let old_stderr_pipe_slot = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, stderr_pipe_slot) as u64,
        )
    };
    let old_fs_ring_base = unsafe {
        guest_mem::read_u32(
            base,
            ps_addr + core::mem::offset_of!(ProcessState, fs_ring_base) as u64,
        )
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
    // A vfork child inherits the parent's ThreadState scratch. Clear any
    // retained blocked-syscall OFD pin before rebuilding the process image so
    // post-exec blocked resumes cannot patch the new fd table with stale OFD
    // ids from the pre-exec image.
    fd_table::clear_blocked_ofd_pin(vm);
    let target_pid = if vm.spawn_child_pid != 0 {
        vm.spawn_child_pid
    } else {
        old_pid
    };
    if target_pid <= 0 {
        return EINVAL;
    }
    let target_ppid = if target_pid != old_pid { old_pid } else { old_ppid };

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

    // Allocate the pointer vectors before rebuilding the guest image. This
    // keeps execve off the system allocator after load_elf()/memory reset.
    let mut argv_ptrs = vec![0u64; argv.len()];
    let mut envp_ptrs = vec![0u64; envp.len()];
    let guest_limit = current_guest_memory_limit(base);

    let ps_size = core::mem::size_of::<ProcessState>() as u64;
    let ps_align = core::mem::align_of::<ProcessState>() as u64;
    let new_ps_addr = (elf.brk_start + ps_align - 1) & !(ps_align - 1);
    crate::runtime_test_support::record_execve_stage(3, guest_limit, new_ps_addr + ps_size);
    if !ensure_guest_memory_capacity(base, new_ps_addr + ps_size) {
        crate::runtime_test_support::record_execve_stage(11, guest_limit, new_ps_addr + ps_size);
        return ENOMEM;
    }

    crate::syscall::thread::discard_other_threads_for_exec(vm, base);
    let elf_result = match unsafe {
        crate::elf::load_elf(base, ram_size, elf_ptr, elf_len)
    } {
        Ok(result) => result,
        Err(_) => return ENOEXEC,
    };
    crate::runtime_test_support::record_execve_stage(4, elf_result.brk_start, elf_result.entry);
    crate::syscall::memory::reset_for_execve(base, elf_result.brk_start);
    let stack_top = crate::syscall::memory::map_initial_stack(
        base,
        guest_limit,
        crate::syscall::memory::DEFAULT_STACK_SIZE,
    );
    if stack_top < 0 {
        crate::runtime_test_support::record_execve_stage(12, guest_limit, stack_top as u64);
        return ENOMEM;
    }
    let stack_top = stack_top as u64;
    crate::runtime_test_support::record_execve_stage(5, guest_limit, stack_top);

    let brk = crate::syscall::memory::current_brk();
    let ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
    if crate::syscall::memory::grow_brk(base, ps_addr + ps_size) < (ps_addr + ps_size) as i64 {
        crate::runtime_test_support::record_execve_stage(13, brk, ps_addr + ps_size);
        return ENOMEM;
    }
    crate::runtime_test_support::record_execve_stage(6, brk, ps_addr + ps_size);
    unsafe {
        guest_mem::zero_mem(base, ps_addr, ps_size as usize);
    }

    let mut released_cloexec_ofds = [false; MAX_FDS];
    for entry in old_fd_table.iter().copied() {
        if entry.ofd_id == 0
            || entry.ofd_id as usize >= MAX_FDS
            || entry.fd_flags & fd_table::FD_CLOEXEC == 0
        {
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
    let stdin_pipe_off = core::mem::offset_of!(ProcessState, stdin_pipe_slot) as u64;
    let stdout_pipe_off = core::mem::offset_of!(ProcessState, stdout_pipe_slot) as u64;
    let stderr_pipe_off = core::mem::offset_of!(ProcessState, stderr_pipe_slot) as u64;
    let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;
    unsafe {
        guest_mem::write_u32(base, ps_addr + pid_off, target_pid as u32);
        guest_mem::write_u32(base, ps_addr + ppid_off, target_ppid as u32);
        guest_mem::write_u32(base, ps_addr + cwd_off, old_cwd);
        guest_mem::write_u32(base, ps_addr + stdin_pipe_off, old_stdin_pipe_slot);
        guest_mem::write_u32(base, ps_addr + stdout_pipe_off, old_stdout_pipe_slot);
        guest_mem::write_u32(base, ps_addr + stderr_pipe_off, old_stderr_pipe_slot);
        guest_mem::write_u32(base, ps_addr + fs_ring_off, old_fs_ring_base);
    }

    let random_addr = stack_top.saturating_sub(16);
    unsafe {
        guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);
    }
    write_stack_strings(
        base,
        stack_top.saturating_sub(0x4000),
        &argv,
        &mut argv_ptrs,
    );
    write_stack_strings(
        base,
        stack_top.saturating_sub(0x2000),
        &envp,
        &mut envp_ptrs,
    );
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
    vm.term_signal = 0;
    vm.clone_flags = 0;
    vm.clone_child_stack = 0;
    vm.clone_tls = 0;
    vm.clone_child_tidptr = 0;
    vm.clone_child_tid = 0;
    vm.clone_pending = 0;
    vm.futex_wait_addr = 0;
    vm.futex_wait_timeout = 0;
    vm.epoll_timeout_ms = 0;
    vm.blocked_fd = 0;
    vm.blocked_ofd_id = 0;
    clear_wait4_state(vm);
    clear_spawn_handoff(vm);

    crate::syscall::thread::init_main_thread(vm as *mut ThreadState as u32, base);
    crate::syscall::signal::reset_on_execve(target_pid);
    install_proc_self_exe(&path_bytes);
    if let Some(slot) = ensure_process(target_pid, target_ppid) {
        slot.did_exec = true;
    }

    crate::runtime_test_support::record_execve_stage(7, vm.pc, vm.x[2]);
    0
}

fn empty_child_entry() -> ChildEntry {
    ChildEntry {
        pid: 0,
        parent_pid: 0,
        exited: false,
        wait_status: 0,
    }
}

fn record_child(parent_pid: i32, pid: i32) {
    for c in children().iter_mut() {
        if c.pid == 0 {
            *c = ChildEntry {
                pid,
                parent_pid,
                exited: false,
                wait_status: 0,
            };
            return;
        }
    }
}

/// Record child exit (called by TS runtime when child Worker finishes).
pub fn record_child_exit(pid: i32, wait_status: i32) {
    for c in children().iter_mut() {
        if c.pid == pid && !c.exited {
            c.exited = true;
            c.wait_status = wait_status;
            return;
        }
    }
}

fn clear_wait4_state(vm: &mut ThreadState) {
    vm.wait_pid = 0;
    vm.wait_kind = 0;
    vm.wait_idtype = 0;
    vm.wait_wstatus_addr = 0;
    vm.wait_options = 0;
    vm.wait_rusage_addr = 0;
}

fn child_matches_wait_target(caller_pid: i32, child: &ChildEntry, pid: i64) -> bool {
    if child.pid == 0 || child.parent_pid != caller_pid {
        return false;
    }

    match pid {
        -1 => true,
        0 => {
            let caller_pgid = process_entry(caller_pid)
                .map(|slot| slot.pgid)
                .unwrap_or(caller_pid);
            process_entry(child.pid)
                .map(|slot| slot.pgid == caller_pgid)
                .unwrap_or(false)
        }
        target if target > 0 => child.pid as i64 == target,
        target => {
            let wanted_pgid = (-target) as i32;
            process_entry(child.pid)
                .map(|slot| slot.pgid == wanted_pgid)
                .unwrap_or(false)
        }
    }
}

fn child_matches_waitid_target(caller_pid: i32, child: &ChildEntry, idtype: u32, id: i64) -> bool {
    match idtype {
        P_ALL => child_matches_wait_target(caller_pid, child, -1),
        P_PID => child_matches_wait_target(caller_pid, child, id),
        P_PGID => {
            let pgid = if id == 0 {
                process_entry(caller_pid)
                    .map(|slot| slot.pgid as i64)
                    .unwrap_or(caller_pid as i64)
            } else {
                -id
            };
            child_matches_wait_target(caller_pid, child, pgid)
        }
        _ => false,
    }
}

fn decode_wait_status(wait_status: i32) -> (i32, i32) {
    let status = wait_status as u32;
    let signal = (status & 0x7f) as i32;
    if signal == 0 {
        (((status >> 8) & 0xff) as i32, CLD_EXITED)
    } else {
        (signal, CLD_KILLED)
    }
}

fn clear_waitid_siginfo(base: u32, infop_addr: u64) {
    if infop_addr == 0 {
        return;
    }

    unsafe {
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_SIGNO, 0);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_ERRNO, 0);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_CODE, 0);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_PID, 0);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_UID, 0);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_STATUS, 0);
    }
}

fn write_waitid_siginfo(base: u32, infop_addr: u64, child_pid: i32, wait_status: i32) {
    if infop_addr == 0 {
        return;
    }

    let (si_status, si_code) = decode_wait_status(wait_status);
    unsafe {
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_SIGNO, SIGCHLD as u32);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_ERRNO, 0);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_CODE, si_code as u32);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_PID, child_pid as u32);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_UID, 0);
        guest_mem::write_u32(base, infop_addr + SIGINFO_OFF_SI_STATUS, si_status as u32);
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
pub fn sys_vfork(vm: &mut ThreadState, base: u32) -> i32 {
    clear_spawn_handoff(vm);
    let parent_pid = ensure_current_process(vm, base).map(|slot| slot.pid).unwrap_or(0);
    let child_pid = if parent_pid > 0 {
        let pid = alloc_pid();
        record_child(parent_pid, pid);
        inherit_process(parent_pid, parent_pid, pid, false);
        crate::syscall::signal::fork_from_parent(parent_pid, pid);
        pid
    } else {
        0
    };
    let child_process_ptr = if child_pid > 0 {
        match clone_process_state_for_vfork(vm, base, parent_pid, child_pid) {
            Some(ptr) => ptr,
            None => return STATUS_FAULT,
        }
    } else {
        vm.process_ptr
    };
    // Snapshot parent registers
    prs().vfork_snapshot = VforkSnapshot {
        x: vm.x,
        pc: vm.pc,
        f: vm.f,
        fcsr: vm.fcsr,
        status: vm.status,
        exit_code: vm.exit_code,
        term_signal: vm.term_signal,
        tid: vm.tid,
        uid: vm.uid,
        euid: vm.euid,
        gid: vm.gid,
        egid: vm.egid,
        tls_base: vm.tls_base,
        clear_child_tid: vm.clear_child_tid,
        robust_list_head: vm.robust_list_head,
        robust_list_len: vm.robust_list_len,
        sig_mask: vm.sig_mask,
        sig_pending: vm.sig_pending,
        sigaltstack_sp: vm.sigaltstack_sp,
        sigaltstack_size: vm.sigaltstack_size,
        sigaltstack_flags: vm.sigaltstack_flags,
        lr_addr: vm.lr_addr,
        lr_val: vm.lr_val,
        insn_budget: vm.insn_budget,
        fault_pc: vm.fault_pc,
        fault_addr: vm.fault_addr,
        guest_base: vm.guest_base,
        process_ptr: vm.process_ptr,
        clone_flags: vm.clone_flags,
        clone_child_stack: vm.clone_child_stack,
        clone_tls: vm.clone_tls,
        clone_child_tidptr: vm.clone_child_tidptr,
        clone_child_tid: vm.clone_child_tid,
        clone_pending: vm.clone_pending,
        spawn_kind: vm.spawn_kind,
        spawn_flags: vm.spawn_flags,
        spawn_child_pid: vm.spawn_child_pid,
        spawn_path: vm.spawn_path,
        spawn_argv: vm.spawn_argv,
        spawn_envp: vm.spawn_envp,
        wait_pid: vm.wait_pid,
        wait_kind: vm.wait_kind,
        wait_idtype: vm.wait_idtype,
        wait_wstatus_addr: vm.wait_wstatus_addr,
        wait_options: vm.wait_options,
        wait_rusage_addr: vm.wait_rusage_addr,
        futex_wait_addr: vm.futex_wait_addr,
        futex_wait_timeout: vm.futex_wait_timeout,
        epoll_timeout_ms: vm.epoll_timeout_ms,
        blocked_fd: vm.blocked_fd,
        blocked_ofd_id: vm.blocked_ofd_id,
        child_pid,
    };
    prs().vfork_active = 1;
    vm.sig_pending = 0;
    vm.process_ptr = child_process_ptr;
    reattach_guest_thread_count(vm, base);

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
    if vm.process_ptr != 0 && vm.process_ptr != snap.process_ptr {
        crate::fs::fd_table::close_all_for_process(vm.guest_base, vm);
    }
    vm.x = snap.x;
    vm.pc = snap.pc;
    vm.f = snap.f;
    vm.fcsr = snap.fcsr;
    vm.status = snap.status;
    vm.exit_code = snap.exit_code;
    vm.term_signal = snap.term_signal;
    vm.tid = snap.tid;
    vm.uid = snap.uid;
    vm.euid = snap.euid;
    vm.gid = snap.gid;
    vm.egid = snap.egid;
    vm.tls_base = snap.tls_base;
    vm.clear_child_tid = snap.clear_child_tid;
    vm.robust_list_head = snap.robust_list_head;
    vm.robust_list_len = snap.robust_list_len;
    vm.sig_mask = snap.sig_mask;
    vm.sig_pending = snap.sig_pending;
    vm.sigaltstack_sp = snap.sigaltstack_sp;
    vm.sigaltstack_size = snap.sigaltstack_size;
    vm.sigaltstack_flags = snap.sigaltstack_flags;
    vm.lr_addr = snap.lr_addr;
    vm.lr_val = snap.lr_val;
    vm.insn_budget = snap.insn_budget;
    vm.fault_pc = snap.fault_pc;
    vm.fault_addr = snap.fault_addr;
    vm.guest_base = snap.guest_base;
    vm.process_ptr = snap.process_ptr;
    vm.clone_flags = snap.clone_flags;
    vm.clone_child_stack = snap.clone_child_stack;
    vm.clone_tls = snap.clone_tls;
    vm.clone_child_tidptr = snap.clone_child_tidptr;
    vm.clone_child_tid = snap.clone_child_tid;
    vm.clone_pending = snap.clone_pending;
    vm.spawn_kind = snap.spawn_kind;
    vm.spawn_flags = snap.spawn_flags;
    vm.spawn_child_pid = snap.spawn_child_pid;
    vm.spawn_path = snap.spawn_path;
    vm.spawn_argv = snap.spawn_argv;
    vm.spawn_envp = snap.spawn_envp;
    vm.wait_pid = snap.wait_pid;
    vm.wait_kind = snap.wait_kind;
    vm.wait_idtype = snap.wait_idtype;
    vm.wait_wstatus_addr = snap.wait_wstatus_addr;
    vm.wait_options = snap.wait_options;
    vm.wait_rusage_addr = snap.wait_rusage_addr;
    vm.futex_wait_addr = snap.futex_wait_addr;
    vm.futex_wait_timeout = snap.futex_wait_timeout;
    vm.epoll_timeout_ms = snap.epoll_timeout_ms;
    vm.blocked_fd = snap.blocked_fd;
    vm.blocked_ofd_id = snap.blocked_ofd_id;
    reattach_guest_thread_count(vm, vm.guest_base);
    vm.x[10] = child_pid as u64; // parent's clone returns child PID
    clear_spawn_handoff(vm);
    vm.status = STATUS_OK;
}

pub fn clear_vfork_runtime_state() {
    prs().vfork_active = 0;
    prs().vfork_snapshot = empty_vfork_snapshot();
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
    crate::runtime_test_support::record_execve_stage(0, 0, 0);
    if let Ok(path) = read_guest_cstr_bytes(base, path_addr) {
        crate::runtime_test_support::record_execve_path(&path);
    }
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
        let child_pid = prs().vfork_snapshot.child_pid;
        if child_pid <= 0 {
            return ECHILD;
        }
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
    rusage_addr: u64,
) -> i64 {
    if pid == i32::MIN as i64 {
        return ESRCH;
    }
    if options & !WNOHANG != 0 {
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return EINVAL;
    }
    let caller_pid = crate::syscall::signal::pid_from_vm(vm, base);
    if caller_pid <= 0 {
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return ESRCH;
    }
    let wnohang = (options & WNOHANG) != 0;
    let mut has_matching_child = false;

    for c in children().iter_mut() {
        if !child_matches_wait_target(caller_pid, c, pid) {
            continue;
        }
        has_matching_child = true;

        if c.exited {
            let child_pid = c.pid;
            let wait_status = c.wait_status as u32;
            *c = empty_child_entry();

            if wstatus_addr != 0 {
                unsafe { guest_mem::write_u32(base, wstatus_addr, wait_status) };
            }

            clear_wait4_state(vm);
            vm.status = STATUS_OK;
            return child_pid as i64;
        }
    }

    if !has_matching_child {
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return ECHILD;
    }

    if wnohang {
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return 0;
    }

    vm.wait_pid = pid;
    vm.wait_kind = WAIT_KIND_WAIT4;
    vm.wait_idtype = 0;
    vm.wait_wstatus_addr = wstatus_addr;
    vm.wait_options = options;
    vm.wait_rusage_addr = rusage_addr;
    vm.status = STATUS_WAIT4;
    0
}

/// waitid: wait for child state change and write siginfo_t.
/// Minimal runtime-harness surface: P_ALL/P_PID/P_PGID with WEXITED/WNOHANG/WNOWAIT.
pub fn sys_waitid(
    vm: &mut ThreadState,
    base: u32,
    idtype: u32,
    id: i64,
    infop_addr: u64,
    options: u64,
    rusage_addr: u64,
) -> i64 {
    if infop_addr == 0 {
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return EFAULT;
    }
    if options & WEXITED == 0 || options & !(WEXITED | WNOHANG | WNOWAIT) != 0 {
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return EINVAL;
    }
    if idtype != P_ALL && id < 0 {
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return EINVAL;
    }

    let caller_pid = crate::syscall::signal::pid_from_vm(vm, base);
    if caller_pid <= 0 {
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return ESRCH;
    }

    let wnohang = (options & WNOHANG) != 0;
    let wnowait = (options & WNOWAIT) != 0;
    let mut has_matching_child = false;

    for child in children().iter_mut() {
        if !child_matches_waitid_target(caller_pid, child, idtype, id) {
            continue;
        }
        has_matching_child = true;

        if child.exited {
            let child_pid = child.pid;
            let wait_status = child.wait_status;
            if !wnowait {
                *child = empty_child_entry();
            }
            write_waitid_siginfo(base, infop_addr, child_pid, wait_status);
            clear_wait4_state(vm);
            vm.status = STATUS_OK;
            return 0;
        }
    }

    if !has_matching_child {
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return ECHILD;
    }

    if wnohang {
        clear_waitid_siginfo(base, infop_addr);
        clear_wait4_state(vm);
        vm.status = STATUS_OK;
        return 0;
    }

    vm.wait_pid = id;
    vm.wait_kind = WAIT_KIND_WAITID;
    vm.wait_idtype = idtype;
    vm.wait_wstatus_addr = infop_addr;
    vm.wait_options = options;
    vm.wait_rusage_addr = rusage_addr;
    vm.status = STATUS_WAIT4;
    0
}

pub fn resume_wait4(vm_ptr: u32, base: u32) -> i64 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        let result = if vm.wait_kind == WAIT_KIND_WAITID {
            sys_waitid(
                vm,
                base,
                vm.wait_idtype,
                vm.wait_pid,
                vm.wait_wstatus_addr,
                vm.wait_options,
                vm.wait_rusage_addr,
            )
        } else {
            sys_wait4(
                vm,
                base,
                vm.wait_pid,
                vm.wait_wstatus_addr,
                vm.wait_options,
                vm.wait_rusage_addr,
            )
        };
        if vm.status == STATUS_WAIT4 {
            return 0;
        }

        vm.x[10] = result as u64;
        vm.status = STATUS_OK;
        crate::syscall::signal::check_pending(vm, base);
        result
    }
}

// =========================================================================
// fork (plain)
// =========================================================================

/// Plain fork: guest Memory full copy → STATUS_EXECVE_SPAWN.
/// TS creates new Worker with copied Memory, then reattaches kernel-owned
/// objects (OFD/MemFS/control state) from the canonical owner separately.
pub fn sys_fork(
    vm: &mut ThreadState,
    base: u32,
    flags: u64,
    child_stack: u64,
    parent_tidptr: u64,
    tls: u64,
    child_tidptr: u64,
) -> i64 {
    let parent_pid = match ensure_current_process(vm, base) {
        Some(slot) => slot.pid,
        None => return ESRCH,
    };
    let child_ppid = if flags & CLONE_PARENT != 0 {
        ensure_current_process(vm, base)
            .map(|slot| slot.ppid)
            .unwrap_or(parent_pid)
    } else {
        parent_pid
    };
    let child_pid = alloc_pid();
    record_child(child_ppid, child_pid);
    inherit_process(parent_pid, child_ppid, child_pid, false);

    if flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
        unsafe { guest_mem::write_u32(base, parent_tidptr, child_pid as u32) };
    }

    vm.clone_flags = flags;
    vm.clone_child_tidptr = child_tidptr;
    vm.clone_child_tid = child_pid;
    vm.clone_pending = 0;
    vm.clone_child_stack = child_stack;
    vm.clone_tls = tls;
    set_spawn_handoff(vm, SPAWN_KIND_FORK, child_pid, 0, 0, 0);
    // Legacy fallback for existing tests/runtime stubs.
    vm.x[10] = child_pid as u64;
    vm.status = STATUS_EXECVE_SPAWN;
    child_pid as i64
}

// ECHILD error code
const ECHILD: i64 = -10;
const ESRCH: i64 = -3;
// WNOHANG flag
const WNOHANG: u64 = 1;
const WNOWAIT: u64 = 0x01000000;
const WEXITED: u64 = 4;
const P_ALL: u32 = 0;
const P_PID: u32 = 1;
const P_PGID: u32 = 2;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const WAIT_KIND_WAIT4: u32 = 1;
const WAIT_KIND_WAITID: u32 = 2;
const SIGINFO_OFF_SI_SIGNO: u64 = 0;
const SIGINFO_OFF_SI_ERRNO: u64 = 4;
const SIGINFO_OFF_SI_CODE: u64 = 8;
const SIGINFO_OFF_SI_PID: u64 = 16;
const SIGINFO_OFF_SI_UID: u64 = 20;
const SIGINFO_OFF_SI_STATUS: u64 = 24;

#[cfg(test)]
mod tests {
    use crate::abi::*;
    use crate::fs::memfs;
    use crate::test_helpers::TestVm;
    use crate::types::{FdEntry, ProcessState, THREAD_NONE, THREAD_RUNNING, ThreadRecord};
    use alloc_crate::vec;
    use alloc_crate::vec::Vec;
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

    mod contract_tests {
        use super::*;
        use crate::syscall::process as process_impl;
        use crate::syscall::thread as thread_impl;

        // Permanent Tidemark contract tests. These cover snapshot/resume and
        // spawn-handoff behavior that LTP cannot observe directly.
        #[test]
        fn contract_load_execve_image_accepts_minimal_test_elf() {
            let t = TestVm::new();
            let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
            let path_addr = install_exec_file(&t, b"image-ok", &elf);
            let image = super::super::load_execve_image(
                &t.vm,
                t.base,
                path_addr,
                0,
                0,
                super::super::EXECVE_RAM_LIMIT,
            );
            assert!(image.is_ok(), "minimal test ELF should pass image load");
        }

        #[test]
        fn contract_vfork_snapshots_and_suspends_parent() {
            let mut t = TestVm::new();
            t.vm.x[1] = 0xDEAD;
            t.vm.pc = 0x1000;

            let status = process_impl::sys_vfork(&mut t.vm, t.base);
            assert_eq!(status, STATUS_VFORK_WAIT);
            assert_eq!(t.vm.x[10], 0, "child should see a0=0");
            assert_eq!(t.vm.status, STATUS_VFORK_WAIT);

            // Snapshot should be stored
            assert!(process_impl::vfork_snapshot_active());
        }

        #[test]
        fn contract_vfork_parent_resume_restores_state() {
            let mut t = TestVm::new();
            t.vm.x[1] = 0xBEEF;
            t.vm.pc = 0x2000;
            t.vm.sig_pending = 1 << (SIGTERM - 1);
            t.vm.fault_pc = 0x4444;
            t.vm.fault_addr = 0x5555;
            t.vm.blocked_fd = 17;
            t.vm.blocked_ofd_id = 23;
            t.vm.epoll_timeout_ms = 99;
            t.vm.clone_pending = 1;
            t.vm.clone_child_tid = 77;

            process_impl::sys_vfork(&mut t.vm, t.base);
            assert_eq!(t.vm.sig_pending, 0, "vfork child should not inherit pending signals");

            // Child modifies state
            t.vm.x[1] = 0xFFFF;
            t.vm.pc = 0x9999;
            t.vm.fault_pc = 0xAAAA;
            t.vm.fault_addr = 0xBBBB;
            t.vm.blocked_fd = 0;
            t.vm.blocked_ofd_id = 0;
            t.vm.epoll_timeout_ms = -1;
            t.vm.clone_pending = 0;
            t.vm.clone_child_tid = 0;

            // Resume parent with child_pid=42
            process_impl::vfork_parent_resume(&mut t.vm, 42);
            assert_eq!(t.vm.x[1], 0xBEEF, "parent x1 should be restored");
            assert_eq!(t.vm.pc, 0x2000, "parent pc should be restored");
            assert_eq!(t.vm.x[10], 42, "parent a0 should be child PID");
            assert_eq!(t.vm.sig_pending, 1 << (SIGTERM - 1));
            assert_eq!(t.vm.fault_pc, 0x4444);
            assert_eq!(t.vm.fault_addr, 0x5555);
            assert_eq!(t.vm.blocked_fd, 17);
            assert_eq!(t.vm.blocked_ofd_id, 23);
            assert_eq!(t.vm.epoll_timeout_ms, 99);
            assert_eq!(t.vm.clone_pending, 1);
            assert_eq!(t.vm.clone_child_tid, 77);
            assert_eq!(t.vm.status, STATUS_OK);
        }

        #[test]
        fn contract_vfork_exit_preserves_parent_thread_state() {
            let mut t = TestVm::new();
            let thread_count_off = core::mem::offset_of!(ProcessState, thread_count) as u64;

            process_impl::sys_vfork(&mut t.vm, t.base);
            let child_pid = process_impl::vfork_child_pid();
            assert!(child_pid > 0, "vfork should allocate a child pid");

            let status = thread_impl::sys_exit(&mut t.vm, t.base, 7);
            assert_eq!(status, STATUS_FAULT);

            let thread_count = unsafe {
                crate::guest_mem::read_u32(t.base, t.vm.process_ptr as u64 + thread_count_off)
            };
            assert_eq!(thread_count, 1, "vfork child exit must not tear down parent process");

            process_impl::record_child_exit(child_pid, ((t.vm.exit_code as u32) << 8) as i32);
            process_impl::vfork_parent_resume(&mut t.vm, child_pid);
            assert_eq!(t.vm.x[10], child_pid as u64);
            assert_eq!(t.vm.status, STATUS_OK);
        }

        #[test]
        fn contract_execve_completes_in_place_without_spawn() {
            let mut t = TestVm::new();
            let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
            let path_addr = install_exec_file(&t, b"test", &elf);

            let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
            assert_eq!(ret, 0, "successful execve should not return a child pid");
            assert_eq!(t.vm.status, STATUS_OK);
            assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
            assert_eq!(t.vm.spawn_child_pid, 0);
            assert_eq!(t.vm.pc, 0x1000);
        }

        #[test]
        fn contract_execve_preserves_host_stdio_slots() {
            let mut t = TestVm::new();
            let ps_addr = t.vm.process_ptr as u64;
            let stdin_pipe_off = core::mem::offset_of!(ProcessState, stdin_pipe_slot) as u64;
            let stdout_pipe_off = core::mem::offset_of!(ProcessState, stdout_pipe_slot) as u64;
            let stderr_pipe_off = core::mem::offset_of!(ProcessState, stderr_pipe_slot) as u64;
            let old_stdin = unsafe { guest_mem::read_u32(t.base, ps_addr + stdin_pipe_off) };
            let old_stdout = unsafe { guest_mem::read_u32(t.base, ps_addr + stdout_pipe_off) };
            let old_stderr = unsafe { guest_mem::read_u32(t.base, ps_addr + stderr_pipe_off) };
            assert!(old_stdin != 0 && old_stdout != 0 && old_stderr != 0);

            let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
            let path_addr = install_exec_file(&t, b"test", &elf);
            let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
            assert_eq!(ret, 0);

            let new_ps_addr = t.vm.process_ptr as u64;
            let new_stdin = unsafe { guest_mem::read_u32(t.base, new_ps_addr + stdin_pipe_off) };
            let new_stdout = unsafe { guest_mem::read_u32(t.base, new_ps_addr + stdout_pipe_off) };
            let new_stderr = unsafe { guest_mem::read_u32(t.base, new_ps_addr + stderr_pipe_off) };
            assert_eq!(new_stdin, old_stdin);
            assert_eq!(new_stdout, old_stdout);
            assert_eq!(new_stderr, old_stderr);
        }

        #[test]
        fn contract_fork_returns_status_execve_spawn() {
            let mut t = TestVm::new();
            let ret = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0);
            assert!(ret > 0, "fork should return positive child PID");
            assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
            assert_eq!(t.vm.spawn_kind, SPAWN_KIND_FORK);
            assert_eq!(t.vm.spawn_child_pid, ret as i32);
            assert_eq!(t.vm.spawn_path, 0);
        }

        #[test]
        fn contract_vfork_parent_resume_clears_spawn_handoff() {
            let mut t = TestVm::new();
            let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
            let path_addr = install_exec_file(&t, b"test", &elf);

            process_impl::sys_vfork(&mut t.vm, t.base);
            let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
            assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
            assert_eq!(t.vm.spawn_kind, SPAWN_KIND_EXECVE);
            assert_ne!(
                child_pid, 42,
                "vfork child execve should allocate a new child PID"
            );

            process_impl::vfork_parent_resume(&mut t.vm, child_pid as i32);
            assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
            assert_eq!(t.vm.spawn_child_pid, 0);
            assert_eq!(t.vm.x[10], child_pid as u64);
        }

        #[test]
        fn contract_vfork_execve_failure_does_not_publish_spawn_handoff() {
            let mut t = TestVm::new();
            let path_addr = install_exec_file(&t, b"bad", b"not-an-elf");

            process_impl::sys_vfork(&mut t.vm, t.base);
            let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
            assert_eq!(ret, ENOEXEC);
            assert_eq!(t.vm.status, STATUS_VFORK_WAIT);
            assert_eq!(t.vm.spawn_kind, SPAWN_KIND_NONE);
            assert_eq!(t.vm.spawn_child_pid, 0);
        }
    }

    mod semantics_tests {
        use super::*;
        use crate::syscall::process as process_impl;

        // Linux-visible semantics tests that are not covered by the permanent
        // contract suite.
        //
        // Temporary until the runtime-backed LTP harness:
        // - execve(2) post-reload process-state semantics
        //
        // Explicit kernel-only harness exception:
        // - nested process-group / setsid success-paths
        //   (upstream LTP has only setsid01 error-path coverage)
        #[test]
        fn semantics_execve_discards_other_threads_on_success() {
            let mut t = TestVm::new();
            let ps =
                unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
            ps.thread_count.store(2, Ordering::Release);
            ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
            let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
            let path_addr = install_exec_file(&t, b"test", &elf);
            let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
            assert_eq!(ret, 0);
            let ps =
                unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
            assert_eq!(ps.thread_count.load(Ordering::Acquire), 1);
            assert_eq!(ps.threads[0].state, THREAD_RUNNING);
            assert_eq!(ps.threads[1].state, THREAD_NONE);
        }

        #[test]
        fn semantics_execve_clears_alt_stack() {
            let mut t = TestVm::new();
            t.vm.sigaltstack_sp = 0x5000;
            t.vm.sigaltstack_size = 8192;

            let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
            let path_addr = install_exec_file(&t, b"test", &elf);
            process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

            assert_eq!(
                t.vm.sigaltstack_sp, 0,
                "alt stack should be cleared by execve"
            );
            assert_eq!(t.vm.sigaltstack_size, 0);
        }

        #[test]
        fn semantics_execve_preserves_signal_mask_and_pending() {
            let mut t = TestVm::new();
            t.vm.sig_mask =
                (1u64 << (crate::abi::SIGALRM - 1)) | (1u64 << (crate::abi::SIGTERM - 1));
            t.vm.sig_pending = 1u64 << (crate::abi::SIGCHLD - 1);

            let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
            let path_addr = install_exec_file(&t, b"test", &elf);
            process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

            assert_eq!(
                t.vm.sig_mask,
                (1u64 << (crate::abi::SIGALRM - 1)) | (1u64 << (crate::abi::SIGTERM - 1))
            );
            assert_eq!(t.vm.sig_pending, 1u64 << (crate::abi::SIGCHLD - 1));
        }

        #[test]
        fn semantics_execve_in_place_reload_rebuilds_process_state() {
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

            let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, argv_addr, envp_addr);
            assert_eq!(ret, 0);
            assert_eq!(t.vm.status, STATUS_OK);
            assert_eq!(t.vm.pc, 0x1000);
            assert_eq!(t.vm.tid, 1);
            assert!(!crate::syscall::memory::has_prot_none());

            let ps =
                unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
            assert_eq!(ps.pid, 42);
            let kept_entry = unsafe {
                crate::guest_mem::read_u32(
                    t.base,
                    t.vm.process_ptr as u64 + 3 * core::mem::size_of::<FdEntry>() as u64,
                )
            };
            let cloexec_entry = unsafe {
                crate::guest_mem::read_u32(
                    t.base,
                    t.vm.process_ptr as u64 + 4 * core::mem::size_of::<FdEntry>() as u64,
                )
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
        fn semantics_execve_clears_blocked_resume_scratch() {
            let mut t = TestVm::new();
            let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
            let stdout_ofd = ps.fd_table[1].ofd_id;
            assert!(stdout_ofd > 0, "stdout must be initialized");

            crate::fs::fd_table::retain_ofd_id(stdout_ofd);
            t.vm.blocked_fd = 1;
            t.vm.blocked_ofd_id = stdout_ofd;
            t.vm.futex_wait_addr = 0x1234;
            t.vm.futex_wait_timeout = 0x5678;
            t.vm.epoll_timeout_ms = 99;

            let before = crate::fs::fd_table::get_ofd_by_id(stdout_ofd)
                .expect("stdout OFD should exist before execve");
            assert_eq!(before.refcount, 2);

            let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
            let path_addr = install_exec_file(&t, b"test", &elf);

            let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
            assert_eq!(ret, 0);
            assert_eq!(t.vm.blocked_fd, 0);
            assert_eq!(t.vm.blocked_ofd_id, 0);
            assert_eq!(t.vm.futex_wait_addr, 0);
            assert_eq!(t.vm.futex_wait_timeout, 0);
            assert_eq!(t.vm.epoll_timeout_ms, 0);

            let after = crate::fs::fd_table::get_ofd_by_id(stdout_ofd)
                .expect("stdout OFD should survive execve");
            assert_eq!(after.refcount, 1);
        }

        #[test]
        fn semantics_vfork_execve_preserves_stdio_fds() {
            let mut t = TestVm::new();
            let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
            let old_fd0 = ps.fd_table[0].ofd_id;
            let old_fd1 = ps.fd_table[1].ofd_id;
            let old_fd2 = ps.fd_table[2].ofd_id;
            assert!(old_fd0 != 0 && old_fd1 != 0 && old_fd2 != 0);

            let status = process_impl::sys_vfork(&mut t.vm, t.base);
            assert_eq!(status, STATUS_VFORK_WAIT);

            let elf = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
            let path_addr = install_exec_file(&t, b"test", &elf);
            let child_pid = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
            assert!(child_pid > 0);
            assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);

            process_impl::clear_vfork_runtime_state();
            let ret = process_impl::complete_execve_in_place(
                &mut t.vm,
                t.base,
                process_impl::EXECVE_RAM_LIMIT,
            );
            assert_eq!(ret, 0);

            let new_ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
            assert_eq!(new_ps.fd_table[0].ofd_id, old_fd0);
            assert_eq!(new_ps.fd_table[1].ofd_id, old_fd1);
            assert_eq!(new_ps.fd_table[2].ofd_id, old_fd2);
        }

        #[test]
        fn semantics_execve_failure_preserves_thread_group_and_altstack() {
            let mut t = TestVm::new();
            let ps_before = t.vm.process_ptr;
            let ps =
                unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
            ps.thread_count.store(2, Ordering::Release);
            ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
            t.vm.sigaltstack_sp = 0x7000;
            t.vm.sigaltstack_size = 4096;

            let path_addr = install_exec_file(&t, b"bad", b"not-an-elf");
            let ret = process_impl::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
            assert_eq!(ret, ENOEXEC);
            assert_eq!(t.vm.status, STATUS_OK);
            assert_eq!(t.vm.process_ptr, ps_before);
            assert_eq!(t.vm.sigaltstack_sp, 0x7000);
            assert_eq!(t.vm.sigaltstack_size, 4096);

            let ps =
                unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
            assert_eq!(ps.thread_count.load(Ordering::Acquire), 2);
            assert_eq!(ps.threads[1].state, THREAD_RUNNING);
        }

        #[test]
        fn contract_reset_process_lifecycle_reinitializes_thread_registry() {
            let mut t = TestVm::new();
            let ps =
                unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
            ps.thread_count.store(3, Ordering::Release);
            ps.threads[1] = ThreadRecord::new(2, THREAD_RUNNING, 0xFEED_BEEFu32, 0, 0);
            ps.threads[2] = ThreadRecord::new(3, THREAD_RUNNING, 0xCAFE_BABEu32, 0, 0);

            process_impl::reset_process_lifecycle(&mut t.vm, t.base, 7, 1, 8, 7, 7, true);

            let ps =
                unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
            assert_eq!(ps.pid, 7);
            assert_eq!(ps.ppid, 1);
            assert_eq!(ps.thread_count.load(Ordering::Acquire), 1);
            assert_eq!(ps.threads[0].tid, t.vm.tid);
            assert_eq!(ps.threads[0].state, THREAD_RUNNING);
            assert_eq!(ps.threads[0].thread_ptr, &t.vm as *const _ as u32);
            assert_eq!(ps.threads[1].state, THREAD_NONE);
            assert_eq!(ps.threads[2].state, THREAD_NONE);
        }

        #[test]
        fn semantics_nested_child_can_join_existing_parent_group() {
            let t = TestVm::new();

            write_process_ids(&t, 2, 1);
            assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 1);

            write_process_ids(&t, 3, 2);
            assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
            assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 3);

            write_process_ids(&t, 4, 3);
            assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
            assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 4);

            assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 3), 0);
            assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 3);
        }

        #[test]
        fn semantics_fork_inherited_session_allows_nested_group_join() {
            let mut t = TestVm::new();

            let child1 = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
            assert!(child1 > 0);
            t.vm.status = STATUS_OK;

            write_process_ids(&t, child1, 42);
            let child2 = process_impl::sys_fork(&mut t.vm, t.base, 0, 0, 0, 0, 0) as i32;
            assert!(child2 > 0);
            t.vm.status = STATUS_OK;

            assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
            assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), child1 as i64);

            write_process_ids(&t, child2, child1);
            assert_eq!(process_impl::sys_setpgid(&t.vm, t.base, 0, 0), 0);
            assert_eq!(
                process_impl::sys_setpgid(&t.vm, t.base, 0, child1 as i64),
                0
            );
            assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), child1 as i64);
        }

        #[test]
        fn semantics_setsid_creates_new_session_for_non_group_leader() {
            let t = TestVm::new();

            write_process_ids(&t, 1, 0);
            assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 1);

            write_process_ids(&t, 42, 1);
            assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 1);

            assert_eq!(process_impl::sys_setsid(&t.vm, t.base), 42);
            assert_eq!(process_impl::sys_getpgid(&t.vm, t.base, 0), 42);
        }

        #[test]
        fn semantics_waitid_wnowait_reports_without_reaping() {
            let mut t = TestVm::new();
            let info_addr = t.scratch + 0x1000;

            process_impl::record_child(42, 77);
            process_impl::record_child_exit(77, 9 << 8);

            let ret = process_impl::sys_waitid(
                &mut t.vm,
                t.base,
                P_PID,
                77,
                info_addr,
                WEXITED | WNOWAIT,
                0,
            );
            assert_eq!(ret, 0);
            assert_eq!(unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_PID) }, 77);
            assert_eq!(
                unsafe { guest_mem::read_u32(t.base, info_addr + SIGINFO_OFF_SI_STATUS) },
                9
            );

            let ret = process_impl::sys_waitid(
                &mut t.vm,
                t.base,
                P_PID,
                77,
                info_addr,
                WEXITED,
                0,
            );
            assert_eq!(ret, 0);

            let ret = process_impl::sys_waitid(
                &mut t.vm,
                t.base,
                P_PID,
                77,
                info_addr,
                WEXITED | WNOHANG,
                0,
            );
            assert_eq!(ret, ECHILD);
        }

    }
}
