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
use core::sync::atomic::{AtomicU32, Ordering};

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
    sig_info_code: i32,
    sigaltstack_sp: u64,
    sigaltstack_size: u64,
    sigaltstack_flags: i32,
    lr_addr: u64,
    lr_val: u64,
    lr_gen: u32,
    lr_gen_end: u32,
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
    futex_wait_expected: u32,
    futex_wait_bitset: u32,
    epoll_timeout_ms: i64,
    epoll_maxevents: u32,
    blocked_fd: u32,
    blocked_ofd_id: u32,
    child_pid: i32,
}

struct ExecveImage {
    path_bytes: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    main_bytes: Vec<u8>,
    main_bias: u64,
    main_elf: crate::elf::ElfLoadResult,
    interp_bytes: Option<Vec<u8>>,
    interp_bias: u64,
    interp_elf: Option<crate::elf::ElfLoadResult>,
}

#[repr(C)]
struct ProcessRuntimeState {
    heap_base: u32,
    heap_ptr: AtomicU32,
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
        sig_info_code: 0,
        sigaltstack_sp: 0,
        sigaltstack_size: 0,
        sigaltstack_flags: 0,
        lr_addr: u64::MAX,
        lr_val: 0,
        lr_gen: 0,
        lr_gen_end: 0,
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
        futex_wait_expected: 0,
        futex_wait_bitset: 0,
        epoll_timeout_ms: 0,
        epoll_maxevents: 0,
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
                heap_base: alloc::heap_base(),
                heap_ptr: AtomicU32::new(alloc::heap_ptr()),
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

pub fn shared_heap_base() -> Option<u32> {
    let ptr = unsafe { core::ptr::read(core::ptr::addr_of!(PROCESS_RUNTIME_STATE)) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).heap_base })
    }
}

pub fn shared_heap_ptr() -> Option<u32> {
    let ptr = unsafe { core::ptr::read(core::ptr::addr_of!(PROCESS_RUNTIME_STATE)) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).heap_ptr.load(Ordering::Acquire) })
    }
}

pub fn shared_heap_alloc(size: u32, align: u32) -> Option<u32> {
    let ptr = unsafe { core::ptr::read(core::ptr::addr_of!(PROCESS_RUNTIME_STATE)) };
    if ptr.is_null() {
        return None;
    }
    let state = unsafe { &*ptr };
    loop {
        let current = state.heap_ptr.load(Ordering::Acquire);
        let aligned = (current + align - 1) & !(align - 1);
        let end = aligned + size;
        let mem_size = (core::arch::wasm32::memory_size(0) as u64) * 65536;
        if end as u64 > mem_size {
            let pages_needed = (end as u64 - mem_size).div_ceil(65536) as usize;
            let result = core::arch::wasm32::memory_grow(0, pages_needed);
            if result == usize::MAX {
                return Some(0);
            }
        }
        if state
            .heap_ptr
            .compare_exchange(current, end, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(aligned);
        }
    }
}

/// Reset process lifecycle state for unit tests.
#[cfg(any(test, feature = "harness"))]
pub(crate) fn reset_for_tests() {
    init();
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
    current_process_state_mut(vm, base)
        .map(|ps| ps.ppid)
        .unwrap_or(0)
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
    process_entry(pid)
        .map(|slot| slot.did_exec)
        .unwrap_or(false)
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
        crate::syscall::resource::reassign_process_pid(old_pid, new_pid);
    }

    set_next_pid_floor(next_pid);
}

#[allow(clippy::too_many_arguments)]
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
    crate::syscall::resource::reassign_process_pid(old_pid, pid);
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
        let gen_ptr =
            core::ptr::addr_of!(ps.reservation_gen) as *const core::sync::atomic::AtomicU32;
        let lock_ptr =
            core::ptr::addr_of!(ps.reservation_lock) as *const core::sync::atomic::AtomicU32;
        let tc_ptr = core::ptr::addr_of!(ps.thread_count);
        unsafe {
            guest_mem::init(gen_ptr, lock_ptr, tc_ptr);
        }
    }
}

fn read_guest_cstr_bytes(base: u32, addr: u64) -> Result<Vec<u8>, i64> {
    if addr == 0 {
        return Err(EFAULT);
    }

    let guest_limit =
        ((core::arch::wasm32::memory_size(0) as u64) * 65536).saturating_sub(base as u64);
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

fn read_execve_elf_bytes(ino: u32, elf_len: u32) -> Result<Vec<u8>, i64> {
    let mut elf_bytes = vec![0u8; elf_len as usize];
    if memfs::read_file(ino, 0, &mut elf_bytes) != elf_len as i64 {
        return Err(EIO);
    }
    Ok(elf_bytes)
}

fn inspect_execve_elf_bytes(
    elf_bytes: &[u8],
    ram_size: u64,
) -> Result<crate::elf::ElfLoadResult, i64> {
    unsafe {
        crate::elf::inspect_elf(elf_bytes.as_ptr() as u32, elf_bytes.len() as u32, ram_size)
            .map_err(|_| ENOEXEC)
    }
}

fn load_execve_elf_bytes_at(
    base: u32,
    ram_size: u64,
    elf_bytes: &[u8],
    load_bias: u64,
) -> Result<crate::elf::ElfLoadResult, i64> {
    unsafe {
        crate::elf::load_elf_at(
            base,
            ram_size,
            elf_bytes.as_ptr() as u32,
            elf_bytes.len() as u32,
            load_bias,
        )
        .map_err(|_| ENOEXEC)
    }
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
    let main_bytes = read_execve_elf_bytes(ino, elf_len)?;
    let mut elf = inspect_execve_elf_bytes(&main_bytes, ram_size)?;
    let interp_path = crate::elf::read_interp_path_bytes(&main_bytes).map_err(|_| ENOEXEC)?;
    let main_bias = crate::elf::main_executable_load_bias(&elf, interp_path.is_some());
    if main_bias != 0 {
        elf = crate::elf::bias_load_result(elf, main_bias);
    }
    let (interp_bytes, interp_bias, interp_elf) = match interp_path {
        Some(interp_path) => {
            let interp_ino = memfs::resolve_path(&interp_path);
            if interp_ino == 0 {
                return Err(ENOENT);
            }
            let interp_st = memfs::stat(interp_ino).ok_or(ENOENT)?;
            if interp_st.mode & memfs::S_IFMT != memfs::S_IFREG {
                return Err(EACCES);
            }
            let interp_len = u32::try_from(interp_st.size).map_err(|_| ENOEXEC)?;
            if interp_len == 0 {
                return Err(ENOEXEC);
            }
            let interp_bytes = read_execve_elf_bytes(interp_ino, interp_len)?;
            let mut interp_elf = inspect_execve_elf_bytes(&interp_bytes, ram_size)?;
            let interp_bias = crate::elf::interpreter_load_bias(elf.brk_start);
            interp_elf = crate::elf::bias_load_result(interp_elf, interp_bias);
            crate::elf::preserve_main_executable_process_image(&mut interp_elf, &elf);
            (Some(interp_bytes), interp_bias, Some(interp_elf))
        }
        None => (None, 0, None),
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
        main_bytes,
        main_bias,
        main_elf: elf,
        interp_bytes,
        interp_bias,
        interp_elf,
    })
}

fn install_proc_self_exe(target: &[u8]) {
    crate::harness_debug::record_execve_stage(711, target.len() as u64, 0);
    let proc_ino = memfs::resolve_path(b"/proc");
    let proc_ino = if proc_ino == 0 {
        memfs::create_dir(1, b"proc", 0o555)
    } else {
        proc_ino
    };
    crate::harness_debug::record_execve_stage(712, proc_ino as u64, 0);
    if proc_ino == 0 {
        return;
    }

    let self_ino = memfs::resolve_path(b"/proc/self");
    let self_ino = if self_ino == 0 {
        memfs::create_dir(proc_ino, b"self", 0o555)
    } else {
        self_ino
    };
    crate::harness_debug::record_execve_stage(713, self_ino as u64, 0);
    if self_ino == 0 {
        return;
    }

    let existing_exe = memfs::lookup(self_ino, b"exe");
    crate::harness_debug::record_execve_stage(714, existing_exe as u64, self_ino as u64);
    if existing_exe != 0 {
        let _ = memfs::unlink(self_ino, b"exe");
    }
    crate::harness_debug::record_execve_stage(715, self_ino as u64, target.len() as u64);
    let exe_ino = memfs::create_symlink(self_ino, b"exe", target);
    crate::harness_debug::record_execve_stage(716, exe_ino as u64, 0);
}

const PROC_STAT_BYTES: &[u8] = b"cpu  1 1 1 1 0 0 0 0 0 0\ncpu0 1 1 1 1 0 0 0 0 0 0\n";
const PROC_CPUINFO_BYTES: &[u8] = b"processor\t: 0\nmodel name\t: tidemark-riscv64\n\n";

fn replace_proc_file(proc_ino: u32, name: &[u8], data: &[u8]) {
    let existing = memfs::lookup(proc_ino, name);
    if existing != 0 {
        let _ = memfs::unlink(proc_ino, name);
    }
    let _ = memfs::create_file_with_data(proc_ino, name, data);
}

pub fn install_procfs_snapshot(exe_target: &[u8]) {
    install_proc_self_exe(exe_target);

    let proc_ino = memfs::resolve_path(b"/proc");
    if proc_ino == 0 {
        return;
    }
    let self_ino = memfs::resolve_path(b"/proc/self");
    if self_ino == 0 {
        return;
    }

    replace_proc_file(proc_ino, b"stat", PROC_STAT_BYTES);
    replace_proc_file(proc_ino, b"cpuinfo", PROC_CPUINFO_BYTES);
    replace_proc_file(
        self_ino,
        b"maps",
        &crate::syscall::memory::proc_self_maps_snapshot(),
    );
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

fn stack_string_bytes_total(strings: &[Vec<u8>]) -> u64 {
    strings.iter().map(|bytes| bytes.len() as u64).sum()
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn ensure_guest_memory_capacity(base: u32, guest_end: u64) -> bool {
    let needed = base as u64 + guest_end;
    let mem_size = (core::arch::wasm32::memory_size(0) as u64) * 65536;
    if needed <= mem_size {
        return true;
    }

    let pages = (needed - mem_size).div_ceil(65536);
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

fn execve_guest_limit(base: u32, brk_start: u64, stack_size: u64) -> u64 {
    const EXECVE_STACK_HEADROOM: u64 = 64 * 1024 * 1024;
    let current_limit = current_guest_memory_limit(base);
    let usable_stack = ((stack_size.max(64 * 1024) + 4095) & !4095).saturating_add(4096);
    let required_limit = brk_start
        .saturating_add(usable_stack)
        .saturating_add(EXECVE_STACK_HEADROOM);
    let rounded_limit = (required_limit + 0xF_FFFF) & !0xF_FFFF;
    current_limit.max(rounded_limit).min(EXECVE_RAM_LIMIT)
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
    if crate::syscall::memory::grow_brk(base, child_ps_addr + ps_size)
        < (child_ps_addr + ps_size) as i64
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
    child_ps
        .thread_count
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

fn complete_execve_in_place_inner(
    vm: &mut ThreadState,
    base: u32,
    ram_size: u64,
    flush_shared_mappings: bool,
) -> i64 {
    let vm_ptr = vm as *mut ThreadState as u32;
    if vm.spawn_kind != SPAWN_KIND_EXECVE {
        return EINVAL;
    }
    crate::harness_debug::record_execve_stage(1, base as u64, ram_size);

    let ExecveImage {
        path_bytes,
        argv,
        envp,
        main_bytes,
        main_bias,
        main_elf,
        interp_bytes,
        interp_bias,
        interp_elf,
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
    let load_brk_start = main_elf
        .brk_start
        .max(interp_elf.as_ref().map(|elf| elf.brk_start).unwrap_or(0));
    let active_elf = interp_elf.as_ref().copied().unwrap_or(main_elf);
    crate::harness_debug::record_execve_stage(2, load_brk_start, active_elf.entry);

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
    let target_ppid = if target_pid != old_pid {
        old_pid
    } else {
        old_ppid
    };
    let defer_backend_cleanup = target_pid != old_pid;

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

    // Allocate the pointer vectors before rebuilding the guest image so the
    // guest image rewrite itself does not depend on post-reset allocations.
    let mut argv_ptrs = vec![0u64; argv.len()];
    let mut envp_ptrs = vec![0u64; envp.len()];
    let guest_limit = execve_guest_limit(
        base,
        load_brk_start,
        crate::syscall::memory::DEFAULT_STACK_SIZE,
    );

    let ps_size = core::mem::size_of::<ProcessState>() as u64;
    let ps_align = core::mem::align_of::<ProcessState>() as u64;
    let new_ps_addr = (load_brk_start + ps_align - 1) & !(ps_align - 1);
    crate::harness_debug::record_execve_stage(3, guest_limit, new_ps_addr + ps_size);
    // vfork+execve handoff starts from a bootstrap-sized child memory. Grow the
    // guest view to the full execve limit before resetting and loading ELF
    // segments, matching process_create()'s dynamic-growth contract.
    if !ensure_guest_memory_capacity(base, guest_limit) {
        crate::harness_debug::record_execve_stage(11, guest_limit, new_ps_addr + ps_size);
        return ENOMEM;
    }

    crate::syscall::thread::discard_other_threads_for_exec(vm, base);
    crate::syscall::memory::reset_for_execve_with_flush(
        base,
        load_brk_start,
        flush_shared_mappings,
    );
    let main_result = match load_execve_elf_bytes_at(base, ram_size, &main_bytes, main_bias) {
        Ok(result) => result,
        Err(errno) => return errno,
    };
    let mut elf_result = match interp_bytes.as_deref() {
        Some(interp_bytes) => {
            match load_execve_elf_bytes_at(base, ram_size, interp_bytes, interp_bias) {
                Ok(result) => result,
                Err(errno) => return errno,
            }
        }
        None => main_result,
    };
    if interp_bytes.is_some() {
        crate::elf::preserve_main_executable_process_image(&mut elf_result, &main_result);
    }
    let loaded_end = main_result
        .load_end
        .max(interp_elf.map(|elf| elf.load_end).unwrap_or(0));
    crate::elf::zero_fill_load_padding(base, loaded_end, load_brk_start);
    elf_result.brk_start = load_brk_start;
    let main_segments = unsafe {
        crate::elf::collect_load_segments(main_bytes.as_ptr() as u32, main_bytes.len() as u32, main_bias)
    };
    let Ok(main_segments) = main_segments else {
        return ENOEXEC;
    };
    for segment in main_segments {
        crate::syscall::memory::register_elf_load_segment(segment.start, segment.end, segment.prot);
    }
    if let Some(interp_bytes) = interp_bytes.as_deref() {
        let interp_segments = unsafe {
            crate::elf::collect_load_segments(
                interp_bytes.as_ptr() as u32,
                interp_bytes.len() as u32,
                interp_bias,
            )
        };
        let Ok(interp_segments) = interp_segments else {
            return ENOEXEC;
        };
        for segment in interp_segments {
            crate::syscall::memory::register_elf_load_segment(
                segment.start,
                segment.end,
                segment.prot,
            );
        }
    }
    crate::harness_debug::record_execve_stage(4, elf_result.brk_start, elf_result.entry);
    let stack_top = crate::syscall::memory::map_initial_stack(
        base,
        guest_limit,
        crate::syscall::memory::DEFAULT_STACK_SIZE,
    );
    if stack_top < 0 {
        crate::harness_debug::record_execve_stage(12, guest_limit, stack_top as u64);
        return ENOMEM;
    }
    let stack_top = stack_top as u64;
    crate::harness_debug::record_execve_stage(5, guest_limit, stack_top);

    let brk = crate::syscall::memory::current_brk();
    let ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
    if crate::syscall::memory::grow_brk(base, ps_addr + ps_size) < (ps_addr + ps_size) as i64 {
        crate::harness_debug::record_execve_stage(13, brk, ps_addr + ps_size);
        return ENOMEM;
    }
    crate::harness_debug::record_execve_stage(6, brk, ps_addr + ps_size);
    crate::harness_debug::record_execve_stage(61, ps_addr, ps_size);
    unsafe {
        guest_mem::zero_mem(base, ps_addr, ps_size as usize);
    }
    crate::harness_debug::record_execve_stage(62, ps_addr, ps_size);

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
        if defer_backend_cleanup {
            let _ = fd_table::release_ofd_id_deferred(entry.ofd_id);
        } else {
            fd_table::release_ofd_id(entry.ofd_id);
        }
    }

    let vm = unsafe { &mut *(vm_ptr as *mut ThreadState) };
    vm.process_ptr = ps_addr as u32;
    for (idx, entry) in inherited_fds.iter().enumerate() {
        let entry_off = ps_addr + (idx * core::mem::size_of::<FdEntry>()) as u64;
        unsafe {
            guest_mem::write_u32(base, entry_off, entry.ofd_id);
            guest_mem::write_u32(base, entry_off + 4, entry.fd_flags);
        }
    }
    crate::harness_debug::record_execve_stage(63, ps_addr, inherited_fds.len() as u64);
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
    crate::harness_debug::record_execve_stage(64, ps_addr + pid_off, ps_addr + fs_ring_off);

    let random_addr = stack_top.saturating_sub(16);
    crate::harness_debug::record_execve_stage(65, stack_top, random_addr);
    unsafe {
        guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);
    }
    let string_bytes = stack_string_bytes_total(&argv) + stack_string_bytes_total(&envp);
    let strings_end = stack_top.saturating_sub(128);
    let strings_start = align_down(strings_end.saturating_sub(string_bytes), 16);
    let stack_setup_top = strings_start.saturating_sub(128);
    let cursor = {
        write_stack_strings(base, strings_start, &argv, &mut argv_ptrs);
        crate::harness_debug::record_execve_stage(66, strings_start, argv.len() as u64);
        let argv_bytes_end = strings_start.saturating_add(stack_string_bytes_total(&argv));
        write_stack_strings(base, argv_bytes_end, &envp, &mut envp_ptrs);
        argv_bytes_end
    };
    crate::harness_debug::record_execve_stage(67, cursor, envp.len() as u64);
    let mut stack_elf = active_elf;
    stack_elf.entry = elf_result.entry;
    stack_elf.brk_start = elf_result.brk_start;
    stack_elf.tls_base = elf_result.tls_base;
    stack_elf.phdr_addr = elf_result.phdr_addr;
    stack_elf.phent = elf_result.phent;
    stack_elf.phnum = elf_result.phnum;
    stack_elf.aux_entry = elf_result.aux_entry;
    stack_elf.aux_phdr_addr = elf_result.aux_phdr_addr;
    stack_elf.aux_phent = elf_result.aux_phent;
    stack_elf.aux_phnum = elf_result.aux_phnum;
    stack_elf.aux_base = elf_result.aux_base;
    let sp = unsafe {
        crate::elf::setup_stack(
            base,
            stack_setup_top,
            &argv_ptrs,
            &envp_ptrs,
            &stack_elf,
            random_addr,
            argv_ptrs[0],
        )
    };
    crate::harness_debug::record_execve_stage(68, sp, stack_setup_top);

    vm.x = [0; 32];
    vm.pc = elf_result.entry;
    vm.x[2] = sp;
    vm.x[4] = elf_result.tls_base;
    vm.f = [0; 32];
    vm.fcsr = 0;
    vm.status = STATUS_OK;
    vm.exit_code = 0;
    vm.tid = 1;
    vm.tls_base = elf_result.tls_base;
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
    vm.futex_wait_expected = 0;
    vm.futex_wait_bitset = 0;
    vm.epoll_timeout_ms = 0;
    vm.epoll_maxevents = 0;
    vm.blocked_fd = 0;
    vm.blocked_ofd_id = 0;
    clear_wait4_state(vm);
    clear_spawn_handoff(vm);
    crate::harness_debug::record_execve_stage(69, vm.pc, vm.x[2]);

    crate::syscall::thread::init_main_thread(vm as *mut ThreadState as u32, base);
    crate::harness_debug::record_execve_stage(70, vm.pc, vm.x[2]);
    crate::syscall::signal::reset_on_execve(target_pid);
    crate::harness_debug::record_execve_stage(71, target_pid as u64, 0);
    if flush_shared_mappings {
        install_proc_self_exe(&path_bytes);
        crate::harness_debug::record_execve_stage(72, path_bytes.len() as u64, 0);
    }
    if let Some(slot) = ensure_process(target_pid, target_ppid) {
        slot.did_exec = true;
    }
    crate::harness_debug::record_execve_stage(73, target_pid as u64, target_ppid as u64);

    crate::harness_debug::record_execve_stage(7, vm.pc, vm.x[2]);
    0
}

pub fn complete_execve_in_place(vm: &mut ThreadState, base: u32, ram_size: u64) -> i64 {
    complete_execve_in_place_inner(vm, base, ram_size, true)
}

pub fn complete_execve_in_place_from_handoff(
    vm: &mut ThreadState,
    base: u32,
    ram_size: u64,
) -> i64 {
    complete_execve_in_place_inner(vm, base, ram_size, false)
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
///
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

    if target_pgid != target.pid && !group_exists_in_session(target_pgid, target.sid) {
        return EPERM;
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
    let parent_pid = ensure_current_process(vm, base)
        .map(|slot| slot.pid)
        .unwrap_or(0);
    let child_pid = if parent_pid > 0 {
        let pid = alloc_pid();
        record_child(parent_pid, pid);
        inherit_process(parent_pid, parent_pid, pid, false);
        crate::syscall::signal::fork_from_parent(parent_pid, pid);
        crate::syscall::resource::fork_from_parent(parent_pid, pid);
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
        sig_info_code: vm.sig_info_code,
        sigaltstack_sp: vm.sigaltstack_sp,
        sigaltstack_size: vm.sigaltstack_size,
        sigaltstack_flags: vm.sigaltstack_flags,
        lr_addr: vm.lr_addr,
        lr_val: vm.lr_val,
        lr_gen: vm.lr_gen,
        lr_gen_end: vm.lr_gen_end,
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
        futex_wait_expected: vm.futex_wait_expected,
        futex_wait_bitset: vm.futex_wait_bitset,
        epoll_timeout_ms: vm.epoll_timeout_ms,
        epoll_maxevents: vm.epoll_maxevents,
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
fn vfork_parent_resume_inner(vm: &mut ThreadState, child_pid: i32, cleanup_child_fds: bool) {
    if prs().vfork_active == 0 {
        return;
    }
    let snap = prs().vfork_snapshot;
    prs().vfork_active = 0;
    if cleanup_child_fds && vm.process_ptr != 0 && vm.process_ptr != snap.process_ptr {
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
    vm.sig_info_code = snap.sig_info_code;
    vm.sigaltstack_sp = snap.sigaltstack_sp;
    vm.sigaltstack_size = snap.sigaltstack_size;
    vm.sigaltstack_flags = snap.sigaltstack_flags;
    vm.lr_addr = snap.lr_addr;
    vm.lr_val = snap.lr_val;
    vm.lr_gen = snap.lr_gen;
    vm.lr_gen_end = snap.lr_gen_end;
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
    vm.futex_wait_expected = snap.futex_wait_expected;
    vm.futex_wait_bitset = snap.futex_wait_bitset;
    vm.epoll_timeout_ms = snap.epoll_timeout_ms;
    vm.epoll_maxevents = snap.epoll_maxevents;
    vm.blocked_fd = snap.blocked_fd;
    vm.blocked_ofd_id = snap.blocked_ofd_id;
    reattach_guest_thread_count(vm, vm.guest_base);
    vm.x[10] = child_pid as u64; // parent's clone returns child PID
    clear_spawn_handoff(vm);
    vm.status = STATUS_OK;
}

pub fn vfork_parent_resume(vm: &mut ThreadState, child_pid: i32) {
    vfork_parent_resume_inner(vm, child_pid, true);
}

pub fn vfork_parent_restore_without_cleanup(vm: &mut ThreadState, child_pid: i32) {
    if prs().vfork_active == 0 {
        return;
    }
    let snap = prs().vfork_snapshot;
    if vm.process_ptr != 0 && vm.process_ptr != snap.process_ptr {
        crate::fs::fd_table::close_all_for_process_without_backend_cleanup(vm.guest_base, vm);
    }
    vfork_parent_resume_inner(vm, child_pid, false);
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
    crate::harness_debug::record_execve_stage(0, 0, 0);
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
