use crate::abi::*;
use crate::alloc;
use crate::types::ThreadState;
#[cfg(any(test, feature = "harness"))]
use alloc_crate::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

const MAX_CHILDREN: usize = MAX_PROCESSES;
const VFORK_PROC_SELF_EXE_MAX: usize = super::execve::PROC_SELF_EXE_SNAPSHOT_MAX;

#[derive(Clone, Copy)]
pub(super) struct ChildEntry {
    pub(super) pid: i32,
    pub(super) parent_pid: i32,
    pub(super) exited: bool,
    pub(super) wait_status: i32,
}

#[derive(Clone, Copy)]
pub(super) struct ProcessEntry {
    pub(super) pid: i32,
    pub(super) ppid: i32,
    pub(super) pgid: i32,
    pub(super) sid: i32,
    pub(super) did_exec: bool,
}

#[derive(Clone, Copy)]
pub(super) struct VforkSnapshot {
    pub(super) x: [u64; 32],
    pub(super) pc: u64,
    pub(super) f: [u64; 32],
    pub(super) fcsr: u32,
    pub(super) status: i32,
    pub(super) exit_code: i32,
    pub(super) term_signal: i32,
    pub(super) tid: i32,
    pub(super) uid: u32,
    pub(super) euid: u32,
    pub(super) gid: u32,
    pub(super) egid: u32,
    pub(super) tls_base: u64,
    pub(super) clear_child_tid: u64,
    pub(super) robust_list_head: u64,
    pub(super) robust_list_len: u64,
    pub(super) sig_mask: u64,
    pub(super) sig_pending: u64,
    pub(super) sig_info_code: i32,
    pub(super) sigaltstack_sp: u64,
    pub(super) sigaltstack_size: u64,
    pub(super) sigaltstack_flags: i32,
    pub(super) lr_addr: u64,
    pub(super) lr_val: u64,
    pub(super) lr_gen: u32,
    pub(super) lr_gen_end: u32,
    pub(super) insn_budget: i32,
    pub(super) fault_pc: u64,
    pub(super) fault_addr: u64,
    pub(super) guest_base: u32,
    pub(super) guest_ram_limit: u32,
    pub(super) process_ptr: u32,
    pub(super) clone_flags: u64,
    pub(super) clone_child_stack: u64,
    pub(super) clone_tls: u64,
    pub(super) clone_child_tidptr: u64,
    pub(super) clone_child_tid: i32,
    pub(super) clone_pending: i32,
    pub(super) spawn_kind: u32,
    pub(super) spawn_ram_size: u32,
    pub(super) spawn_child_pid: i32,
    pub(super) spawn_path: u64,
    pub(super) spawn_argv: u64,
    pub(super) spawn_envp: u64,
    pub(super) wait_pid: i64,
    pub(super) wait_kind: u32,
    pub(super) wait_idtype: u32,
    pub(super) wait_wstatus_addr: u64,
    pub(super) wait_options: u64,
    pub(super) wait_rusage_addr: u64,
    pub(super) futex_wait_addr: u64,
    pub(super) futex_wait_timeout: u64,
    pub(super) futex_wait_expected: u32,
    pub(super) futex_wait_bitset: u32,
    pub(super) futex_wait_absolute: u32,
    pub(super) futex_wait_flags: u32,
    pub(super) epoll_timeout_ms: i64,
    pub(super) socket_timeout_ms: i64,
    pub(super) epoll_maxevents: u32,
    pub(super) blocked_fd: u32,
    pub(super) blocked_ofd_id: u32,
    pub(super) child_pid: i32,
}

#[repr(C)]
pub(super) struct ProcessRuntimeState {
    pub(super) heap_base: u32,
    pub(super) heap_ptr: AtomicU32,
    pub(super) children: [ChildEntry; MAX_CHILDREN],
    pub(super) next_pid: i32,
    pub(super) fork_active: u32,
    pub(super) vfork_active: u32,
    pub(super) process_table: [ProcessEntry; MAX_PROCESSES],
    pub(super) fork_snapshot: VforkSnapshot,
    pub(super) vfork_snapshot: VforkSnapshot,
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
        $callback!($target, $source, guest_base);
        $callback!($target, $source, guest_ram_limit);
        $callback!($target, $source, process_ptr);
        $callback!($target, $source, clone_flags);
        $callback!($target, $source, clone_child_stack);
        $callback!($target, $source, clone_tls);
        $callback!($target, $source, clone_child_tidptr);
        $callback!($target, $source, clone_child_tid);
        $callback!($target, $source, clone_pending);
        $callback!($target, $source, spawn_kind);
        $callback!($target, $source, spawn_ram_size);
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
    let mem_size = (core::arch::wasm32::memory_size(0) as usize) * 65536;
    let ptr_usize = ptr as usize;
    let size = core::mem::size_of::<ProcessRuntimeState>();
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

pub(super) fn empty_vfork_snapshot() -> VforkSnapshot {
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
        guest_ram_limit: 0,
        process_ptr: 0,
        clone_flags: 0,
        clone_child_stack: 0,
        clone_tls: 0,
        clone_child_tidptr: 0,
        clone_child_tid: 0,
        clone_pending: 0,
        spawn_kind: 0,
        spawn_ram_size: 0,
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
        child_pid: 0,
    }
}

pub(super) fn capture_thread_snapshot(vm: &ThreadState, child_pid: i32) -> VforkSnapshot {
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

pub(super) fn restore_thread_snapshot(vm: &mut ThreadState, snap: VforkSnapshot) {
    macro_rules! restore_snapshot_field {
        ($target:ident, $source:ident, $field:ident) => {
            $target.$field = $source.$field;
        };
    }

    for_each_vfork_snapshot_field!(restore_snapshot_field, vm, snap);
}

pub(super) fn rewrite_snapshot_child_pid(snapshot: &mut VforkSnapshot, old_pid: i32, new_pid: i32) {
    if snapshot.child_pid == old_pid {
        snapshot.child_pid = new_pid;
    }
}

pub(super) fn clear_vfork_runtime_snapshot() {
    prs().vfork_active = 0;
    prs().vfork_snapshot = empty_vfork_snapshot();
}

pub(super) fn take_fork_snapshot() -> Option<VforkSnapshot> {
    if prs().fork_active == 0 {
        return None;
    }
    let snapshot = prs().fork_snapshot;
    prs().fork_active = 0;
    prs().fork_snapshot = empty_vfork_snapshot();
    Some(snapshot)
}

pub(super) fn seeded_process_table() -> [ProcessEntry; MAX_PROCESSES] {
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

pub(super) fn prs() -> &'static mut ProcessRuntimeState {
    unsafe {
        let p = checked_process_runtime_state_ptr();
        &mut *p
    }
}

pub(super) fn store_vfork_proc_self_exe_snapshot(target: &[u8]) {
    let len = target.len().min(VFORK_PROC_SELF_EXE_MAX);
    unsafe {
        VFORK_PROC_SELF_EXE_TARGET[..len].copy_from_slice(&target[..len]);
        if len < VFORK_PROC_SELF_EXE_MAX {
            VFORK_PROC_SELF_EXE_TARGET[len..].fill(0);
        }
        VFORK_PROC_SELF_EXE_LEN = len as u32;
    }
}

pub(super) fn clear_vfork_proc_self_exe_snapshot() {
    unsafe {
        VFORK_PROC_SELF_EXE_LEN = 0;
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!(VFORK_PROC_SELF_EXE_TARGET) as *mut u8,
            0,
            VFORK_PROC_SELF_EXE_MAX,
        );
    }
}

pub(super) fn vfork_proc_self_exe_snapshot() -> &'static [u8] {
    unsafe { &VFORK_PROC_SELF_EXE_TARGET[..VFORK_PROC_SELF_EXE_LEN as usize] }
}

pub(super) fn children() -> &'static mut [ChildEntry; MAX_CHILDREN] {
    &mut prs().children
}

pub(super) fn processes() -> &'static mut [ProcessEntry; MAX_PROCESSES] {
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
    for child in children().iter_mut() {
        if child.pid == pid {
            child.parent_pid = parent_pid;
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
        let mem_size = (core::arch::wasm32::memory_size(0) as u64) * 65536;
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
