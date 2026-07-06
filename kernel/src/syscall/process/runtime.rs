use crate::abi::*;
use crate::alloc;
use crate::types::ThreadState;
#[cfg(any(test, feature = "harness"))]
use alloc_crate::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

const MAX_CHILDREN: usize = MAX_PROCESSES;
const VFORK_PROC_SELF_EXE_MAX: usize = super::execve::PROC_SELF_EXE_SNAPSHOT_MAX;

#[derive(Clone, Copy)]
pub(crate) struct ChildEntry {
    pub(crate) pid: i32,
    pub(crate) parent_pid: i32,
    pub(crate) pgid: i32,
    pub(crate) exited: bool,
    pub(crate) wait_status: i32,
}

#[derive(Clone, Copy)]
pub(crate) struct ProcessEntry {
    pub(crate) pid: i32,
    pub(crate) ppid: i32,
    pub(crate) pgid: i32,
    pub(crate) sid: i32,
    pub(crate) did_exec: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct VforkSnapshot {
    pub(crate) x: [u64; 32],
    pub(crate) pc: u64,
    pub(crate) f: [u64; 32],
    pub(crate) fcsr: u32,
    pub(crate) status: i32,
    pub(crate) exit_code: i32,
    pub(crate) term_signal: i32,
    pub(crate) tid: i32,
    pub(crate) uid: u32,
    pub(crate) euid: u32,
    pub(crate) gid: u32,
    pub(crate) egid: u32,
    pub(crate) tls_base: u64,
    pub(crate) clear_child_tid: u64,
    pub(crate) robust_list_head: u64,
    pub(crate) robust_list_len: u64,
    pub(crate) sig_mask: u64,
    pub(crate) sig_pending: u64,
    pub(crate) sig_info_code: i32,
    pub(crate) sigaltstack_sp: u64,
    pub(crate) sigaltstack_size: u64,
    pub(crate) sigaltstack_flags: i32,
    pub(crate) lr_addr: u64,
    pub(crate) lr_val: u64,
    pub(crate) lr_gen: u32,
    pub(crate) lr_gen_end: u32,
    pub(crate) insn_budget: i32,
    pub(crate) fault_pc: u64,
    pub(crate) fault_addr: u64,
    pub(crate) fault_kind: u32,
    pub(crate) fault_signal: i32,
    pub(crate) fault_code: i32,
    pub(crate) _pad_fault: u32,
    pub(crate) guest_base: u32,
    pub(crate) guest_address_profile: u32,
    pub(crate) guest_address_limit: u64,
    pub(crate) guest_memory_policy_limit: u64,
    pub(crate) process_max_memory_pages: u32,
    pub(crate) process_ptr: u32,
    pub(crate) clone_flags: u64,
    pub(crate) clone_child_stack: u64,
    pub(crate) clone_tls: u64,
    pub(crate) clone_child_tidptr: u64,
    pub(crate) clone_child_tid: i32,
    pub(crate) clone_pending: i32,
    pub(crate) spawn_kind: u32,
    pub(crate) spawn_address_profile: u32,
    pub(crate) spawn_guest_memory_policy_limit: u64,
    pub(crate) spawn_process_max_memory_pages: u32,
    pub(crate) spawn_child_pid: i32,
    pub(crate) spawn_path: u64,
    pub(crate) spawn_argv: u64,
    pub(crate) spawn_envp: u64,
    pub(crate) wait_pid: i64,
    pub(crate) wait_kind: u32,
    pub(crate) wait_idtype: u32,
    pub(crate) wait_wstatus_addr: u64,
    pub(crate) wait_options: u64,
    pub(crate) wait_rusage_addr: u64,
    pub(crate) futex_wait_addr: u64,
    pub(crate) futex_wait_timeout: u64,
    pub(crate) futex_wait_expected: u32,
    pub(crate) futex_wait_bitset: u32,
    pub(crate) futex_wait_absolute: u32,
    pub(crate) futex_wait_flags: u32,
    pub(crate) epoll_timeout_ms: i64,
    pub(crate) socket_timeout_ms: i64,
    pub(crate) epoll_maxevents: u32,
    pub(crate) blocked_fd: u32,
    pub(crate) blocked_ofd_id: u32,
    pub(crate) blocked_syscall_nr: u64,
    pub(crate) blocked_syscall_args: [u64; 6],
    pub(crate) child_pid: i32,
}

#[repr(C)]
pub(crate) struct ProcessRuntimeState {
    pub(crate) heap_base: u32,
    pub(crate) heap_ptr: AtomicU32,
    pub(crate) children: [ChildEntry; MAX_CHILDREN],
    pub(crate) next_pid: i32,
    pub(crate) fork_active: u32,
    pub(crate) vfork_active: u32,
    pub(crate) process_table: [ProcessEntry; MAX_PROCESSES],
    pub(crate) fork_snapshot: VforkSnapshot,
    pub(crate) vfork_snapshot: VforkSnapshot,
}

#[cfg(any(test, feature = "harness"))]
#[derive(Clone, Copy)]
pub(crate) struct ProcessRuntimeStateImage {
    heap_ptr: u32,
    children: [ChildEntry; MAX_CHILDREN],
    next_pid: i32,
    fork_active: u32,
    vfork_active: u32,
    process_table: [ProcessEntry; MAX_PROCESSES],
    fork_snapshot: VforkSnapshot,
    vfork_snapshot: VforkSnapshot,
    vfork_proc_self_exe_len: u32,
    vfork_proc_self_exe_target: [u8; VFORK_PROC_SELF_EXE_MAX],
}

#[cfg(any(test, feature = "harness"))]
impl ProcessRuntimeStateImage {
    pub(crate) fn empty() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

static mut PROCESS_RUNTIME_STATE: *mut ProcessRuntimeState = core::ptr::null_mut();
static mut VFORK_PROC_SELF_EXE_LEN: u32 = 0;
static mut VFORK_PROC_SELF_EXE_TARGET: [u8; VFORK_PROC_SELF_EXE_MAX] = [0; VFORK_PROC_SELF_EXE_MAX];

macro_rules! for_each_vfork_snapshot_field {
    ($callback:ident, $target:ident, $source:ident) => {
        $callback!($target, $source, x);
        $callback!($target, $source, pc);
        $callback!($target, $source, f);
        $callback!($target, $source, fcsr);
        $callback!($target, $source, status);
        $callback!($target, $source, exit_code);
        $callback!($target, $source, term_signal);
        $callback!($target, $source, tid);
        $callback!($target, $source, uid);
        $callback!($target, $source, euid);
        $callback!($target, $source, gid);
        $callback!($target, $source, egid);
        $callback!($target, $source, tls_base);
        $callback!($target, $source, clear_child_tid);
        $callback!($target, $source, robust_list_head);
        $callback!($target, $source, robust_list_len);
        $callback!($target, $source, sig_mask);
        $callback!($target, $source, sig_pending);
        $callback!($target, $source, sig_info_code);
        $callback!($target, $source, sigaltstack_sp);
        $callback!($target, $source, sigaltstack_size);
        $callback!($target, $source, sigaltstack_flags);
        $callback!($target, $source, lr_addr);
        $callback!($target, $source, lr_val);
        $callback!($target, $source, lr_gen);
        $callback!($target, $source, lr_gen_end);
        $callback!($target, $source, insn_budget);
        $callback!($target, $source, fault_pc);
        $callback!($target, $source, fault_addr);
        $callback!($target, $source, fault_kind);
        $callback!($target, $source, fault_signal);
        $callback!($target, $source, fault_code);
        $callback!($target, $source, _pad_fault);
        $callback!($target, $source, guest_base);
        $callback!($target, $source, guest_address_profile);
        $callback!($target, $source, guest_address_limit);
        $callback!($target, $source, guest_memory_policy_limit);
        $callback!($target, $source, process_max_memory_pages);
        $callback!($target, $source, process_ptr);
        $callback!($target, $source, clone_flags);
        $callback!($target, $source, clone_child_stack);
        $callback!($target, $source, clone_tls);
        $callback!($target, $source, clone_child_tidptr);
        $callback!($target, $source, clone_child_tid);
        $callback!($target, $source, clone_pending);
        $callback!($target, $source, spawn_kind);
        $callback!($target, $source, spawn_address_profile);
        $callback!($target, $source, spawn_guest_memory_policy_limit);
        $callback!($target, $source, spawn_process_max_memory_pages);
        $callback!($target, $source, spawn_child_pid);
        $callback!($target, $source, spawn_path);
        $callback!($target, $source, spawn_argv);
        $callback!($target, $source, spawn_envp);
        $callback!($target, $source, wait_pid);
        $callback!($target, $source, wait_kind);
        $callback!($target, $source, wait_idtype);
        $callback!($target, $source, wait_wstatus_addr);
        $callback!($target, $source, wait_options);
        $callback!($target, $source, wait_rusage_addr);
        $callback!($target, $source, futex_wait_addr);
        $callback!($target, $source, futex_wait_timeout);
        $callback!($target, $source, futex_wait_expected);
        $callback!($target, $source, futex_wait_bitset);
        $callback!($target, $source, futex_wait_absolute);
        $callback!($target, $source, futex_wait_flags);
        $callback!($target, $source, epoll_timeout_ms);
        $callback!($target, $source, socket_timeout_ms);
        $callback!($target, $source, epoll_maxevents);
        $callback!($target, $source, blocked_fd);
        $callback!($target, $source, blocked_ofd_id);
        $callback!($target, $source, blocked_syscall_nr);
        $callback!($target, $source, blocked_syscall_args);
    };
}

#[cfg(any(test, feature = "harness"))]
macro_rules! for_each_runtime_state_image_field {
    ($callback:ident, $target:ident, $source:ident) => {
        $callback!($target, $source, children);
        $callback!($target, $source, next_pid);
        $callback!($target, $source, fork_active);
        $callback!($target, $source, vfork_active);
        $callback!($target, $source, process_table);
        $callback!($target, $source, fork_snapshot);
        $callback!($target, $source, vfork_snapshot);
    };
}

fn checked_process_runtime_state_ptr() -> *mut ProcessRuntimeState {
    let ptr = unsafe { core::ptr::read(core::ptr::addr_of!(PROCESS_RUNTIME_STATE)) };
    if ptr.is_null() {
        return ptr;
    }
    let mem_size = crate::wasm::memory_size_bytes();
    let ptr_usize = ptr as usize as u64;
    let size = core::mem::size_of::<ProcessRuntimeState>() as u64;
    let end = ptr_usize.saturating_add(size);
    if end > mem_size {
        #[cfg(any(test, feature = "harness"))]
        panic!(
            "PROCESS_RUNTIME_STATE out of wasm range ptr=0x{:x} end=0x{:x} mem_size=0x{:x}",
            ptr_usize, end, mem_size,
        );
        #[cfg(not(any(test, feature = "harness")))]
        return core::ptr::null_mut();
    }
    ptr
}

pub(crate) fn empty_vfork_snapshot() -> VforkSnapshot {
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
        fault_kind: 0,
        fault_signal: 0,
        fault_code: 0,
        _pad_fault: 0,
        guest_base: 0,
        guest_address_profile: 0,
        guest_address_limit: 0,
        guest_memory_policy_limit: 0,
        process_max_memory_pages: 0,
        process_ptr: 0,
        clone_flags: 0,
        clone_child_stack: 0,
        clone_tls: 0,
        clone_child_tidptr: 0,
        clone_child_tid: 0,
        clone_pending: 0,
        spawn_kind: 0,
        spawn_address_profile: 0,
        spawn_guest_memory_policy_limit: 0,
        spawn_process_max_memory_pages: 0,
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
        futex_wait_absolute: 0,
        futex_wait_flags: 0,
        epoll_timeout_ms: 0,
        socket_timeout_ms: -1,
        epoll_maxevents: 0,
        blocked_fd: 0,
        blocked_ofd_id: 0,
        blocked_syscall_nr: 0,
        blocked_syscall_args: [0; 6],
        child_pid: 0,
    }
}

pub(crate) fn capture_thread_snapshot(vm: &ThreadState, child_pid: i32) -> VforkSnapshot {
    macro_rules! capture_snapshot_field {
        ($target:ident, $source:ident, $field:ident) => {
            $target.$field = $source.$field;
        };
    }

    let mut snapshot = empty_vfork_snapshot();
    for_each_vfork_snapshot_field!(capture_snapshot_field, snapshot, vm);
    snapshot.child_pid = child_pid;
    snapshot
}

pub(crate) fn restore_thread_snapshot(vm: &mut ThreadState, snap: VforkSnapshot) {
    macro_rules! restore_snapshot_field {
        ($target:ident, $source:ident, $field:ident) => {
            $target.$field = $source.$field;
        };
    }

    for_each_vfork_snapshot_field!(restore_snapshot_field, vm, snap);
}

pub(crate) fn rewrite_snapshot_child_pid(snapshot: &mut VforkSnapshot, old_pid: i32, new_pid: i32) {
    if snapshot.child_pid == old_pid {
        snapshot.child_pid = new_pid;
    }
}

pub(crate) fn clear_vfork_runtime_snapshot() {
    prs().vfork_active = 0;
    prs().vfork_snapshot = empty_vfork_snapshot();
}

pub(crate) fn take_fork_snapshot() -> Option<VforkSnapshot> {
    if prs().fork_active == 0 {
        return None;
    }
    let snapshot = prs().fork_snapshot;
    prs().fork_active = 0;
    prs().fork_snapshot = empty_vfork_snapshot();
    Some(snapshot)
}

pub(crate) fn seeded_process_table() -> [ProcessEntry; MAX_PROCESSES] {
    let mut table = [ProcessEntry {
        pid: 0,
        ppid: 0,
        pgid: 0,
        sid: 0,
        did_exec: false,
    }; MAX_PROCESSES];
    table[0] = ProcessEntry {
        pid: 1,
        ppid: 0,
        pgid: 1,
        sid: 1,
        did_exec: false,
    };
    table
}

pub(crate) fn prs() -> &'static mut ProcessRuntimeState {
    unsafe {
        let p = checked_process_runtime_state_ptr();
        &mut *p
    }
}

pub(crate) fn store_vfork_proc_self_exe_snapshot(target: &[u8]) {
    let len = target.len().min(VFORK_PROC_SELF_EXE_MAX);
    unsafe {
        VFORK_PROC_SELF_EXE_TARGET[..len].copy_from_slice(&target[..len]);
        if len < VFORK_PROC_SELF_EXE_MAX {
            VFORK_PROC_SELF_EXE_TARGET[len..].fill(0);
        }
        VFORK_PROC_SELF_EXE_LEN = len as u32;
    }
}

pub(crate) fn clear_vfork_proc_self_exe_snapshot() {
    unsafe {
        VFORK_PROC_SELF_EXE_LEN = 0;
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!(VFORK_PROC_SELF_EXE_TARGET) as *mut u8,
            0,
            VFORK_PROC_SELF_EXE_MAX,
        );
    }
}

pub(crate) fn vfork_proc_self_exe_snapshot() -> &'static [u8] {
    unsafe { &VFORK_PROC_SELF_EXE_TARGET[..VFORK_PROC_SELF_EXE_LEN as usize] }
}

pub(crate) fn children() -> &'static mut [ChildEntry; MAX_CHILDREN] {
    &mut prs().children
}

pub(crate) fn processes() -> &'static mut [ProcessEntry; MAX_PROCESSES] {
    &mut prs().process_table
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn child_entry_state(pid: i32) -> Option<(i32, bool, i32)> {
    for child in children().iter() {
        if child.pid == pid {
            return Some((child.parent_pid, child.exited, child.wait_status));
        }
    }
    None
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn exited_children_for_parent(parent_pid: i32) -> Vec<(i32, i32)> {
    let mut exited = Vec::new();
    for child in children().iter() {
        if child.parent_pid == parent_pid && child.exited {
            exited.push((child.pid, child.wait_status));
        }
    }
    exited
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn child_entries_for_parent(parent_pid: i32) -> Vec<(i32, bool, i32)> {
    let mut entries = Vec::new();
    for child in children().iter() {
        if child.parent_pid == parent_pid && child.pid > 0 {
            entries.push((child.pid, child.exited, child.wait_status));
        }
    }
    entries
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn sync_child_entry(parent_pid: i32, pid: i32, exited: bool, wait_status: i32) {
    if parent_pid <= 0 || pid <= 0 {
        return;
    }
    let pgid = processes()
        .iter()
        .find(|process| process.pid == pid)
        .map(|process| process.pgid)
        .or_else(|| {
            processes()
                .iter()
                .find(|process| process.pid == parent_pid)
                .map(|process| process.pgid)
        })
        .unwrap_or(parent_pid);
    for child in children().iter_mut() {
        if child.pid == pid {
            child.parent_pid = parent_pid;
            child.pgid = if pgid > 0 { pgid } else { child.pgid };
            child.exited = exited;
            child.wait_status = wait_status;
            return;
        }
    }
    for child in children().iter_mut() {
        if child.pid == 0 {
            *child = ChildEntry {
                pid,
                parent_pid,
                pgid,
                exited,
                wait_status,
            };
            return;
        }
    }
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
            crate::wasm::unreachable();
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
                    pgid: 0,
                    exited: false,
                    wait_status: 0,
                }; MAX_CHILDREN],
                next_pid: 3,
                fork_active: 0,
                vfork_active: 0,
                process_table: seeded_process_table(),
                fork_snapshot: empty_vfork_snapshot(),
                vfork_snapshot: empty_vfork_snapshot(),
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(PROCESS_RUNTIME_STATE), state);
        VFORK_PROC_SELF_EXE_LEN = 0;
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!(VFORK_PROC_SELF_EXE_TARGET) as *mut u8,
            0,
            VFORK_PROC_SELF_EXE_MAX,
        );
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

pub fn advance_shared_heap_ptr(heap_ptr: u32) {
    let ptr = checked_process_runtime_state_ptr();
    if ptr.is_null() {
        return;
    }
    let state = unsafe { &*ptr };
    let mut current = state.heap_ptr.load(Ordering::Acquire);
    while heap_ptr > current {
        match state.heap_ptr.compare_exchange(
            current,
            heap_ptr,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

pub fn shared_heap_base() -> Option<u32> {
    let ptr = checked_process_runtime_state_ptr();
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).heap_base })
    }
}

pub fn shared_heap_ptr() -> Option<u32> {
    let ptr = checked_process_runtime_state_ptr();
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).heap_ptr.load(Ordering::Acquire) })
    }
}

pub fn shared_heap_alloc(size: u32, align: u32) -> Option<u32> {
    let ptr = checked_process_runtime_state_ptr();
    if ptr.is_null() {
        return None;
    }
    let state = unsafe { &*ptr };
    loop {
        let current = state.heap_ptr.load(Ordering::Acquire);
        let mem_size = crate::wasm::memory_size_bytes();
        #[cfg(any(test, feature = "harness"))]
        {
            if current < state.heap_base {
                panic!(
                    "shared_heap_alloc: current 0x{:x} below heap_base 0x{:x} size={} align={}",
                    current, state.heap_base, size, align
                );
            }
            if current as u64 > mem_size {
                panic!(
                    "shared_heap_alloc: current 0x{:x} beyond mem_size 0x{:x} heap_base=0x{:x} size={} align={}",
                    current, mem_size, state.heap_base, size, align
                );
            }
        }
        let align_mask = align.checked_sub(1)?;
        let aligned = current
            .checked_add(align_mask)
            .map(|value| value & !align_mask)?;
        let Some(end) = aligned.checked_add(size) else {
            return Some(0);
        };
        #[cfg(any(test, feature = "harness"))]
        {
            if aligned < state.heap_base {
                panic!(
                    "shared_heap_alloc: aligned 0x{:x} below heap_base 0x{:x} size={} align={}",
                    aligned, state.heap_base, size, align
                );
            }
        }
        if end as u64 > mem_size {
            let pages_needed = (end as u64 - mem_size).div_ceil(65536) as usize;
            if !crate::wasm::memory_grow_pages(pages_needed) {
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

#[cfg(any(test, feature = "harness"))]
pub(crate) fn snapshot_runtime_state_into(snapshot: &mut ProcessRuntimeStateImage) {
    macro_rules! copy_runtime_state_field_to_image {
        ($target:ident, $source:ident, $field:ident) => {
            $target.$field = $source.$field;
        };
    }

    let state = prs();
    snapshot.heap_ptr = state.heap_ptr.load(Ordering::Acquire);
    for_each_runtime_state_image_field!(copy_runtime_state_field_to_image, snapshot, state);
    unsafe {
        snapshot.vfork_proc_self_exe_len = VFORK_PROC_SELF_EXE_LEN;
        snapshot.vfork_proc_self_exe_target = VFORK_PROC_SELF_EXE_TARGET;
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn restore_runtime_state_from(snapshot: &ProcessRuntimeStateImage) {
    macro_rules! restore_runtime_state_field_from_image {
        ($target:ident, $source:ident, $field:ident) => {
            $target.$field = $source.$field;
        };
    }

    let state = prs();
    state.heap_ptr.store(snapshot.heap_ptr, Ordering::Release);
    for_each_runtime_state_image_field!(restore_runtime_state_field_from_image, state, snapshot);
    unsafe {
        VFORK_PROC_SELF_EXE_LEN = snapshot.vfork_proc_self_exe_len;
        VFORK_PROC_SELF_EXE_TARGET = snapshot.vfork_proc_self_exe_target;
    }
}

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
