use crate::abi::*;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::supervisor::process_vfork::reattach_guest_thread_count;
use crate::syscall::process::common::{
    CLD_EXITED, CLD_KILLED, ESRCH, P_ALL, P_PGID, P_PID, SIGINFO_OFF_SI_CODE, SIGINFO_OFF_SI_ERRNO,
    SIGINFO_OFF_SI_PID, SIGINFO_OFF_SI_SIGNO, SIGINFO_OFF_SI_STATUS, SIGINFO_OFF_SI_UID,
};
use crate::syscall::process::handoff::clear_spawn_handoff;
use crate::syscall::process::runtime::{
    children, clear_vfork_runtime_snapshot, processes, prs, restore_thread_snapshot,
    rewrite_snapshot_child_pid, seeded_process_table, take_fork_snapshot,
};
use crate::types::{ProcessState, ThreadState};
use core::sync::atomic::Ordering;

fn set_next_pid_floor(next_pid: i32) {
    prs().next_pid = prs().next_pid.max(next_pid.max(3));
}

pub(crate) fn current_process_state_mut(
    vm: &ThreadState,
    base: u32,
) -> Option<&'static mut ProcessState> {
    if vm.process_ptr == 0 {
        return None;
    }
    let absolute = (base as u64).checked_add(vm.process_ptr as u64)?;
    let end = absolute.checked_add(core::mem::size_of::<ProcessState>() as u64)?;
    let mem_size = crate::wasm::memory_size_bytes();
    if end > mem_size {
        None
    } else {
        unsafe { Some(&mut *(absolute as *mut ProcessState)) }
    }
}

fn reset_process_runtime_sync_state(ps: &mut ProcessState) {
    // fork(2) creates a single-thread child. Reservation locks are Tidemark
    // runtime bookkeeping, not guest-visible state, so the copied child must
    // not inherit a held inter-worker lock. See:
    // https://man7.org/linux/man-pages/man2/fork.2.html
    for lock in ps.reservation_lock.iter() {
        lock.store(0, Ordering::Release);
    }
    for generation in ps.reservation_gen.iter() {
        generation.store(0, Ordering::Release);
    }
}

fn process_idx(pid: i32) -> Option<usize> {
    if (1..=MAX_PROCESSES as i32).contains(&pid) {
        Some((pid - 1) as usize)
    } else {
        None
    }
}

pub(crate) fn process_entry(
    pid: i32,
) -> Option<&'static mut crate::syscall::process::runtime::ProcessEntry> {
    let idx = process_idx(pid)?;
    let slot = &mut processes()[idx];
    if slot.pid == pid { Some(slot) } else { None }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn has_process_entry(pid: i32) -> bool {
    process_entry(pid).is_some()
}

pub fn process_pgid(pid: i32) -> i32 {
    process_entry(pid).map(|entry| entry.pgid).unwrap_or(0)
}

fn child_record_pgid(parent_pid: i32, child_pid: i32) -> i32 {
    process_entry(child_pid)
        .map(|entry| entry.pgid)
        .or_else(|| process_entry(parent_pid).map(|entry| entry.pgid))
        .unwrap_or(parent_pid)
}

fn inherit_group_from_parent(ppid: i32) -> (i32, i32) {
    match process_entry(ppid) {
        Some(parent) => (parent.pgid, parent.sid),
        None => (0, 0),
    }
}

pub(crate) fn ensure_process(
    pid: i32,
    ppid: i32,
) -> Option<&'static mut crate::syscall::process::runtime::ProcessEntry> {
    let idx = process_idx(pid)?;
    reserve_pid(pid);
    if processes()[idx].pid == 0 {
        let (parent_pgid, parent_sid) = inherit_group_from_parent(ppid);
        processes()[idx] = crate::syscall::process::runtime::ProcessEntry {
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

pub(crate) fn ensure_current_process(
    vm: &ThreadState,
    base: u32,
) -> Option<&'static mut crate::syscall::process::runtime::ProcessEntry> {
    let pid = crate::syscall::signal::pid_from_vm(vm, base);
    if pid <= 0 {
        return None;
    }
    let ppid_offset = core::mem::offset_of!(ProcessState, ppid) as u64;
    let ppid = unsafe { guest_mem::read_i32(base, vm.process_ptr as u64 + ppid_offset) };
    ensure_process(pid, ppid)
}

pub(crate) fn inherit_process(
    identity_parent_pid: i32,
    child_ppid: i32,
    child_pid: i32,
    did_exec: bool,
) {
    let (parent_pgid, parent_sid) = inherit_group_from_parent(identity_parent_pid);
    if let Some(slot) = process_idx(child_pid).map(|idx| &mut processes()[idx]) {
        *slot = crate::syscall::process::runtime::ProcessEntry {
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

fn find_available_pid(skip: impl Fn(i32) -> bool) -> Option<i32> {
    let next_pid = prs().next_pid.max(3);
    for pid in next_pid..=(MAX_PROCESSES as i32) {
        if !skip(pid) {
            reserve_pid(pid);
            return Some(pid);
        }
    }
    for pid in 3..next_pid {
        if !skip(pid) {
            reserve_pid(pid);
            return Some(pid);
        }
    }
    None
}

fn pid_in_use(pid: i32) -> bool {
    process_entry(pid).is_some() || children().iter().any(|child| child.pid == pid)
}

pub fn has_active_child(parent_pid: i32) -> bool {
    active_child_pid(parent_pid) > 0
}

pub fn active_child_pid(parent_pid: i32) -> i32 {
    if parent_pid <= 0 {
        return 0;
    }
    children()
        .iter()
        .find(|child| {
            child.pid > 0
                && child.parent_pid == parent_pid
                && !child.exited
                && process_entry(child.pid).is_some()
        })
        .map(|child| child.pid)
        .unwrap_or(0)
}

pub fn child_ppid(pid: i32) -> i32 {
    process_entry(pid)
        .map(|entry| entry.ppid)
        .or_else(|| {
            children()
                .iter()
                .find(|child| child.pid == pid)
                .map(|child| child.parent_pid)
        })
        .unwrap_or(0)
}

pub fn child_pgid(pid: i32) -> i32 {
    process_entry(pid)
        .map(|entry| entry.pgid)
        .or_else(|| {
            children()
                .iter()
                .find(|child| child.pid == pid)
                .map(|child| child.pgid)
        })
        .unwrap_or(0)
}

pub fn child_sid(pid: i32) -> i32 {
    process_entry(pid).map(|entry| entry.sid).unwrap_or(0)
}

pub fn next_pid() -> i32 {
    prs().next_pid.max(3)
}

fn pid_conflicts_with_live_thread(vm: &ThreadState, base: u32, pid: i32) -> bool {
    let Some(ps) = current_process_state_mut(vm, base) else {
        return false;
    };
    ps.threads.iter().any(|record| {
        record.tid == pid
            && record.thread_ptr != 0
            && !matches!(
                record.state,
                crate::types::THREAD_NONE | crate::types::THREAD_DEAD
            )
    })
}

pub(crate) fn alloc_pid_avoiding_live_threads(vm: &ThreadState, base: u32) -> i32 {
    if let Some(pid) =
        find_available_pid(|pid| pid_in_use(pid) || pid_conflicts_with_live_thread(vm, base, pid))
    {
        return pid;
    }
    let mut pid = prs().next_pid.max(3);
    while pid_conflicts_with_live_thread(vm, base, pid) {
        pid += 1;
    }
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

pub fn restore_current_process_identity(
    vm: &mut ThreadState,
    base: u32,
    pid: i32,
    ppid: i32,
    next_pid: i32,
) {
    if pid > 0 && ppid >= 0 {
        if let Some(ps) = current_process_state_mut(vm, base) {
            ps.pid = pid;
            ps.ppid = ppid;
        }
    }
    set_next_pid_floor(next_pid);
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
    processes()[idx] = crate::syscall::process::runtime::ProcessEntry {
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
    processes()[idx] = crate::syscall::process::runtime::ProcessEntry {
        pid: 0,
        ppid: 0,
        pgid: 0,
        sid: 0,
        did_exec: false,
    };
}

fn update_child_record_pgid(pid: i32, pgid: i32) {
    if pid <= 0 || pgid <= 0 {
        return;
    }
    for child in children().iter_mut() {
        if child.pid == pid {
            child.pgid = pgid;
        }
    }
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
                processes()[new_idx] = crate::syscall::process::runtime::ProcessEntry {
                    pid: new_pid,
                    ..old_entry
                };
                processes()[old_idx] = crate::syscall::process::runtime::ProcessEntry {
                    pid: 0,
                    ppid: 0,
                    pgid: 0,
                    sid: 0,
                    did_exec: false,
                };
            }
        }

        rewrite_snapshot_child_pid(&mut prs().vfork_snapshot, old_pid, new_pid);
        rewrite_snapshot_child_pid(&mut prs().fork_snapshot, old_pid, new_pid);

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

pub fn canonicalize_child_pid(
    vm: &mut ThreadState,
    base: u32,
    provisional_child_pid: i32,
    next_pid_floor: i32,
) -> (i32, i32) {
    let child_pid = provisional_child_pid.max(next_pid_floor).max(3);
    let next_pid = child_pid.saturating_add(1).max(3);
    rewrite_child_pid(vm, base, provisional_child_pid, child_pid, next_pid);
    (child_pid, next_pid)
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

    prs().children = [empty_child_entry(); MAX_PROCESSES];
    prs().next_pid = next_pid.max(pid + 1).max(3);
    clear_vfork_runtime_snapshot();
    prs().process_table = seeded_process_table();

    if let Some(slot) = process_idx(pid).map(|idx| &mut processes()[idx]) {
        *slot = crate::syscall::process::runtime::ProcessEntry {
            pid,
            ppid,
            pgid,
            sid,
            did_exec,
        };
    }

    // ThreadState::tid is the process-local thread slot used to index
    // ProcessState::threads. The process ID itself lives in ProcessState.
    vm.tid = 1;
    if let Some(ps) = current_process_state_mut(vm, base) {
        ps.pid = pid;
        ps.ppid = ppid;
    }
    crate::syscall::thread::init_main_thread(vm as *mut ThreadState as u32, base);

    crate::syscall::signal::reassign_process_pid(old_pid, pid);
    crate::syscall::resource::reassign_process_pid(old_pid, pid);
}

pub fn prepare_fork_child_after_handoff(vm: &mut ThreadState, base: u32, pid: i32) {
    if let Some(snap) = take_fork_snapshot() {
        restore_thread_snapshot(vm, snap);
    }

    let clone_flags = vm.clone_flags;
    let clone_child_stack = vm.clone_child_stack;
    let clone_tls = vm.clone_tls;
    let clone_child_tidptr = vm.clone_child_tidptr;

    // ThreadState::tid is the process-local thread slot used to index
    // ProcessState::threads. The process ID itself lives in ProcessState.
    vm.tid = 1;
    vm.x[0] = 0;
    vm.x[10] = 0;
    if clone_child_stack != 0 {
        vm.x[2] = clone_child_stack;
    }
    if clone_flags & CLONE_SETTLS != 0 {
        vm.x[4] = clone_tls;
        vm.tls_base = clone_tls;
    }
    if clone_flags & CLONE_CHILD_CLEARTID != 0 {
        vm.clear_child_tid = clone_child_tidptr;
    } else {
        vm.clear_child_tid = 0;
    }
    if let Some(ps) = current_process_state_mut(vm, base) {
        ps.pid = pid;
        reset_process_runtime_sync_state(ps);
    }
    vm.lr_addr = u64::MAX;
    vm.lr_val = 0;
    vm.lr_gen = 0;
    vm.lr_gen_end = 0;
    crate::syscall::thread::init_main_thread(vm as *mut ThreadState as u32, base);
    if clone_flags & CLONE_CHILD_SETTID != 0 && clone_child_tidptr != 0 {
        unsafe {
            guest_mem::write_u32(base, clone_child_tidptr, pid as u32);
        }
    }

    vm.clone_flags = 0;
    vm.clone_child_stack = 0;
    vm.clone_tls = 0;
    vm.clone_child_tidptr = 0;
    vm.clone_child_tid = 0;
    vm.clone_pending = 0;

    clear_wait4_state(vm);
    vm.futex_wait_addr = 0;
    vm.futex_wait_timeout = 0;
    vm.futex_wait_expected = 0;
    vm.futex_wait_bitset = 0;
    vm.futex_wait_absolute = 0;
    vm.futex_wait_flags = 0;
    vm.epoll_timeout_ms = 0;
    vm.socket_timeout_ms = -1;
    vm.epoll_maxevents = 0;
    vm.blocked_fd = 0;
    vm.blocked_ofd_id = 0;
    vm.blocked_syscall_nr = 0;
    vm.blocked_syscall_args = [0; 6];
    vm.completed_sync_effects = 0;
    vm.completed_pipe_sync_slots = 0;
    vm.completed_pipe_sync_read_slots = 0;
    vm.completed_pipe_sync_write_slots = 0;
    vm.completed_pipe_sync_control_slots = 0;
    vm.completed_pipe_fresh_slots = 0;
    vm.completed_pipe_read_guest_ptr = 0;
    vm.completed_pipe_read_len = 0;
    vm.block_cache_ptr = 0;
    vm.jit_state_ptr = 0;
    vm.execve_backing_miss_ino = 0;
    vm.execve_backing_miss_len = 0;
    vm.execve_backing_miss_offset = 0;
    vm.execve_backing_miss_expected_size = 0;
    vm.sig_pending = 0;
    vm.sig_info_code = 0;
    vm.status = STATUS_OK;
    vm.exit_code = 0;
    vm.term_signal = 0;
    vm.fault_pc = 0;
    vm.fault_addr = 0;
    fd_table::clear_blocked_ofd_pin(vm);
}

pub fn restore_fork_parent_after_handoff(
    vm: &mut ThreadState,
    base: u32,
    process_ptr: u32,
    pid: i32,
    ppid: i32,
) {
    if process_ptr == 0 || pid <= 0 {
        return;
    }

    if let Some(snap) = take_fork_snapshot() {
        restore_thread_snapshot(vm, snap);
        vm.x[10] = snap.child_pid as u64;
        clear_spawn_handoff(vm);
        vm.status = STATUS_OK;
    }

    vm.process_ptr = process_ptr;

    if let Some(ps) = current_process_state_mut(vm, base) {
        ps.pid = pid;
        ps.ppid = ppid;
    }

    vm.clone_flags = 0;
    vm.clone_child_stack = 0;
    vm.clone_tls = 0;
    vm.clone_child_tidptr = 0;
    vm.clone_child_tid = 0;
    vm.clone_pending = 0;
    clear_wait4_state(vm);
    vm.futex_wait_addr = 0;
    vm.futex_wait_timeout = 0;
    vm.futex_wait_expected = 0;
    vm.futex_wait_bitset = 0;
    vm.futex_wait_absolute = 0;
    vm.futex_wait_flags = 0;
    vm.epoll_timeout_ms = 0;
    vm.socket_timeout_ms = -1;
    vm.epoll_maxevents = 0;
    vm.blocked_fd = 0;
    vm.blocked_ofd_id = 0;
    vm.blocked_syscall_nr = 0;
    vm.blocked_syscall_args = [0; 6];
    vm.completed_sync_effects = 0;
    vm.completed_pipe_sync_slots = 0;
    vm.completed_pipe_sync_read_slots = 0;
    vm.completed_pipe_sync_write_slots = 0;
    vm.completed_pipe_sync_control_slots = 0;
    vm.completed_pipe_fresh_slots = 0;
    vm.completed_pipe_read_guest_ptr = 0;
    vm.completed_pipe_read_len = 0;
    vm.block_cache_ptr = 0;
    vm.jit_state_ptr = 0;
    vm.execve_backing_miss_ino = 0;
    vm.execve_backing_miss_len = 0;
    vm.execve_backing_miss_offset = 0;
    vm.execve_backing_miss_expected_size = 0;
    vm.sig_pending = 0;
    vm.sig_info_code = 0;
    vm.status = STATUS_OK;
    vm.exit_code = 0;
    vm.term_signal = 0;
    vm.fault_pc = 0;
    vm.fault_addr = 0;
    fd_table::clear_blocked_ofd_pin(vm);
    reattach_guest_thread_count(vm, base);
}

pub(crate) fn empty_child_entry() -> crate::syscall::process::runtime::ChildEntry {
    crate::syscall::process::runtime::ChildEntry {
        pid: 0,
        parent_pid: 0,
        pgid: 0,
        exited: false,
        wait_status: 0,
    }
}

pub(crate) fn record_child(parent_pid: i32, pid: i32) {
    let pgid = child_record_pgid(parent_pid, pid);
    for c in children().iter_mut() {
        if c.pid == 0 {
            *c = crate::syscall::process::runtime::ChildEntry {
                pid,
                parent_pid,
                pgid,
                exited: false,
                wait_status: 0,
            };
            return;
        }
    }
}

fn record_child_exit_publication(parent_pid: i32, pid: i32, wait_status: i32) {
    crate::supervisor::record_process_lifecycle(
        crate::supervisor::SUPERVISOR_PROCESS_LIFECYCLE_KIND_CHILD_EXIT_PUBLISHED,
        0,
        parent_pid,
        pid,
        wait_status,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );
}

pub fn record_child_exit(pid: i32, wait_status: i32) {
    for c in children().iter_mut() {
        if c.pid == pid && !c.exited {
            let pgid = child_record_pgid(c.parent_pid, pid);
            if c.pgid <= 0 && pgid > 0 {
                c.pgid = pgid;
            }
            c.exited = true;
            c.wait_status = wait_status;
            record_child_exit_publication(c.parent_pid, pid, wait_status);
            crate::syscall::signal::queue_process_signal(c.parent_pid, SIGCHLD);
            return;
        }
    }
}

pub fn record_child_exit_for_parent(parent_pid: i32, pid: i32, wait_status: i32) {
    if parent_pid <= 0 || pid <= 0 {
        return;
    }
    let pgid = child_record_pgid(parent_pid, pid);
    for c in children().iter_mut() {
        if c.pid == pid {
            c.parent_pid = parent_pid;
            if c.pgid <= 0 && pgid > 0 {
                c.pgid = pgid;
            }
            c.exited = true;
            c.wait_status = wait_status;
            record_child_exit_publication(parent_pid, pid, wait_status);
            crate::syscall::signal::queue_process_signal(parent_pid, SIGCHLD);
            return;
        }
    }
    for c in children().iter_mut() {
        if c.pid == 0 {
            *c = crate::syscall::process::runtime::ChildEntry {
                pid,
                parent_pid,
                pgid,
                exited: true,
                wait_status,
            };
            record_child_exit_publication(parent_pid, pid, wait_status);
            crate::syscall::signal::queue_process_signal(parent_pid, SIGCHLD);
            return;
        }
    }
}

pub(crate) fn clear_wait4_state(vm: &mut ThreadState) {
    vm.wait_pid = 0;
    vm.wait_kind = 0;
    vm.wait_idtype = 0;
    vm.wait_wstatus_addr = 0;
    vm.wait_options = 0;
    vm.wait_rusage_addr = 0;
}

pub(crate) fn child_matches_wait_target(
    caller_pid: i32,
    child: &crate::syscall::process::runtime::ChildEntry,
    pid: i64,
) -> bool {
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
                .unwrap_or(child.pgid == caller_pgid)
        }
        target if target > 0 => child.pid as i64 == target,
        target => {
            let wanted_pgid = (-target) as i32;
            process_entry(child.pid)
                .map(|slot| slot.pgid == wanted_pgid)
                .unwrap_or(child.pgid == wanted_pgid)
        }
    }
}

pub(crate) fn child_matches_waitid_target(
    caller_pid: i32,
    child: &crate::syscall::process::runtime::ChildEntry,
    idtype: u32,
    id: i64,
) -> bool {
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

pub(crate) fn clear_waitid_siginfo(base: u32, infop_addr: u64) {
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

pub(crate) fn write_waitid_siginfo(base: u32, infop_addr: u64, child_pid: i32, wait_status: i32) {
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

    {
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
    }

    update_child_record_pgid(target_pid, target_pgid);
    0
}

pub fn sys_setsid(vm: &ThreadState, base: u32) -> i64 {
    let caller_pid = match ensure_current_process(vm, base) {
        Some(slot) => slot.pid,
        None => return ESRCH,
    };

    if processes()
        .iter()
        .any(|slot| slot.pid != 0 && slot.pgid == caller_pid)
    {
        return EPERM;
    }

    match ensure_current_process(vm, base) {
        Some(slot) => {
            slot.sid = caller_pid;
            slot.pgid = caller_pid;
        }
        None => return ESRCH,
    }
    update_child_record_pgid(caller_pid, caller_pid);
    caller_pid as i64
}
