use crate::abi::*;
use crate::guest_mem;
use crate::supervisor::process_lifecycle::{
    child_matches_wait_target, child_matches_waitid_target, clear_wait4_state,
    clear_waitid_siginfo, empty_child_entry, write_waitid_siginfo,
};
use crate::syscall::process::common::{ECHILD, ESRCH, P_ALL};
use crate::syscall::process::remove_process_entry;
use crate::syscall::process::runtime::children;
use crate::types::ThreadState;

const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
const WCONTINUED: u64 = 8;
const __WNOTHREAD: u64 = 0x20000000;
const __WALL: u64 = 0x40000000;
const __WCLONE: u64 = 0x80000000;
const WAIT4_SUPPORTED_OPTIONS: u64 =
    WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WALL | __WCLONE;
const WNOWAIT: u64 = 0x01000000;
const WEXITED: u64 = 4;

const WAIT_KIND_WAIT4: u32 = 1;
const WAIT_KIND_WAITID: u32 = 2;

pub(super) const CHILD_EXIT_BLOCKED_PARENT_ACTION_NONE: u32 = 0;
pub(super) const CHILD_EXIT_BLOCKED_PARENT_ACTION_INVALIDATE_RPC: u32 = 1;
pub(super) const CHILD_EXIT_BLOCKED_PARENT_ACTION_CLEAR_PIPE_SYNC_BEFORE_RETRY: u32 = 1 << 1;

pub(super) const WAIT4_RPC_LOCAL_STATUS_ACTION_SKIP: u32 = 0;
pub(super) const WAIT4_RPC_LOCAL_STATUS_ACTION_START: u32 = 1;

pub(super) fn child_exit_blocked_parent_action_none() -> u32 {
    CHILD_EXIT_BLOCKED_PARENT_ACTION_NONE
}

pub(super) fn child_exit_blocked_parent_action_invalidate_rpc() -> u32 {
    CHILD_EXIT_BLOCKED_PARENT_ACTION_INVALIDATE_RPC
}

pub(super) fn child_exit_blocked_parent_action_clear_pipe_sync_before_retry() -> u32 {
    CHILD_EXIT_BLOCKED_PARENT_ACTION_CLEAR_PIPE_SYNC_BEFORE_RETRY
}

pub(super) fn wait4_rpc_local_status_action_skip() -> u32 {
    WAIT4_RPC_LOCAL_STATUS_ACTION_SKIP
}

pub(super) fn wait4_rpc_local_status_action_start() -> u32 {
    WAIT4_RPC_LOCAL_STATUS_ACTION_START
}

pub(super) fn child_exit_blocked_parent_action(status: i32) -> i32 {
    match status {
        STATUS_WAIT4 | STATUS_EPOLL_WAIT => CHILD_EXIT_BLOCKED_PARENT_ACTION_INVALIDATE_RPC as i32,
        STATUS_PIPE_WAIT => {
            (CHILD_EXIT_BLOCKED_PARENT_ACTION_INVALIDATE_RPC
                | CHILD_EXIT_BLOCKED_PARENT_ACTION_CLEAR_PIPE_SYNC_BEFORE_RETRY) as i32
        }
        _ => CHILD_EXIT_BLOCKED_PARENT_ACTION_NONE as i32,
    }
}

pub(super) fn wait4_rpc_local_status_action(status: i32) -> i32 {
    match status {
        STATUS_WAIT4 => WAIT4_RPC_LOCAL_STATUS_ACTION_START as i32,
        _ => WAIT4_RPC_LOCAL_STATUS_ACTION_SKIP as i32,
    }
}

fn parent_has_exited_child(parent_pid: i32) -> bool {
    children()
        .iter()
        .any(|child| child.pid > 0 && child.parent_pid == parent_pid && child.exited)
}

fn discard_sigchld_if_no_other_exited_child(parent_pid: i32) {
    if !parent_has_exited_child(parent_pid) {
        crate::syscall::signal::clear_process_signal(parent_pid, SIGCHLD);
    }
}

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
    if options & !WAIT4_SUPPORTED_OPTIONS != 0 {
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
            remove_process_entry(child_pid);
            discard_sigchld_if_no_other_exited_child(caller_pid);

            if wstatus_addr != 0 {
                unsafe { guest_mem::write_u32(base, wstatus_addr, wait_status) };
            }

            let published_seq = crate::supervisor::process_lifecycle_count();
            crate::supervisor::record_process_lifecycle(
                crate::supervisor::SUPERVISOR_PROCESS_LIFECYCLE_KIND_WAIT4_COMPLETED,
                vm as *const ThreadState as u32,
                caller_pid,
                child_pid,
                wait_status as i32,
                WAIT_KIND_WAIT4,
                STATUS_OK as u32,
                child_pid as i64,
                pid,
                options,
                wstatus_addr,
                rusage_addr,
                published_seq,
            );
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
                remove_process_entry(child_pid);
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
