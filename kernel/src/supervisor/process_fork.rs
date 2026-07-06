use crate::abi::*;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::supervisor::process_lifecycle::{
    alloc_pid_avoiding_live_threads, ensure_current_process, inherit_process, record_child,
};
use crate::syscall::process::common::ESRCH;
use crate::syscall::process::handoff::set_spawn_handoff;
use crate::syscall::process::runtime::{capture_thread_snapshot, prs};
use crate::types::ThreadState;

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
    let child_pid = alloc_pid_avoiding_live_threads(vm, base);
    record_child(child_ppid, child_pid);
    inherit_process(parent_pid, child_ppid, child_pid, false);
    crate::syscall::signal::fork_from_parent(parent_pid, child_pid);
    crate::syscall::resource::fork_from_parent(parent_pid, child_pid);
    fd_table::retain_fds_for_fork(base, vm);

    if flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
        unsafe { guest_mem::write_u32(base, parent_tidptr, child_pid as u32) };
    }

    vm.clone_flags = flags;
    vm.clone_child_tidptr = child_tidptr;
    vm.clone_child_tid = child_pid;
    vm.clone_pending = 0;
    vm.clone_child_stack = child_stack;
    vm.clone_tls = tls;
    prs().fork_snapshot = capture_thread_snapshot(vm, child_pid);
    prs().fork_active = 1;
    set_spawn_handoff(vm, SPAWN_KIND_FORK, child_pid, 0, 0, 0);
    vm.x[10] = child_pid as u64;
    vm.status = STATUS_EXECVE_SPAWN;
    child_pid as i64
}
