//! Process lifecycle syscalls: execve, wait4, vfork, fork.
//!
//! vfork: parent suspends (STATUS_VFORK_WAIT), child runs in parent's memory.
//! execve: STATUS_EXECVE_SPAWN → TS spawns child Worker with new Memory.
//! fork: guest Memory full copy → STATUS_EXECVE_SPAWN.
//! wait4: retrieve child exit status.
//!
//! Semantics:
//! https://man7.org/linux/man-pages/man2/vfork.2.html
//! https://man7.org/linux/man-pages/man2/execve.2.html
//! https://man7.org/linux/man-pages/man2/fork.2.html
//! https://man7.org/linux/man-pages/man2/wait4.2.html

use crate::abi::*;
use crate::guest_mem;
use crate::types::{FdEntry, ProcessState, ThreadState};

// =========================================================================
// Process table — tracks child processes for wait4
// =========================================================================

const MAX_CHILDREN: usize = 64;

#[derive(Clone, Copy)]
struct ChildEntry {
    pid: i32,
    exited: bool,
    exit_code: i32,
}

static mut CHILDREN: [ChildEntry; MAX_CHILDREN] = [ChildEntry {
    pid: 0,
    exited: false,
    exit_code: 0,
}; MAX_CHILDREN];
static mut NEXT_PID: i32 = 3; // PID 1 is init, PID 2 is the first user process

fn children() -> &'static mut [ChildEntry; MAX_CHILDREN] {
    unsafe { &mut *core::ptr::addr_of_mut!(CHILDREN) }
}

#[derive(Clone, Copy)]
struct ProcessEntry {
    pid: i32,
    ppid: i32,
    pgid: i32,
    sid: i32,
    did_exec: bool,
}

static mut PROCESS_TABLE: [ProcessEntry; MAX_PROCESSES] = [ProcessEntry {
    pid: 0,
    ppid: 0,
    pgid: 0,
    sid: 0,
    did_exec: false,
}; MAX_PROCESSES];

fn processes() -> &'static mut [ProcessEntry; MAX_PROCESSES] {
    unsafe { &mut *core::ptr::addr_of_mut!(PROCESS_TABLE) }
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
    if slot.pid == pid {
        Some(slot)
    } else {
        None
    }
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
            sid: if parent_sid != 0 { parent_sid } else { child_pid },
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
    unsafe {
        let p = core::ptr::addr_of_mut!(NEXT_PID);
        let next = core::ptr::read(p);
        if pid >= next {
            core::ptr::write(p, pid + 1);
        }
    }
}

fn alloc_pid() -> i32 {
    unsafe {
        let p = core::ptr::addr_of_mut!(NEXT_PID);
        let pid = core::ptr::read(p);
        core::ptr::write(p, pid + 1);
        pid
    }
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

/// Saved parent state during vfork.
static mut VFORK_SNAPSHOT: Option<VforkSnapshot> = None;

fn vfork_snapshot() -> &'static mut Option<VforkSnapshot> {
    unsafe { &mut *core::ptr::addr_of_mut!(VFORK_SNAPSHOT) }
}

struct VforkSnapshot {
    x: [u64; 32],
    pc: u64,
    f: [u64; 32],
    fcsr: u32,
    sig_mask: u64,
}

/// sys_clone with CLONE_VFORK: snapshot parent, child continues with a0=0.
/// Returns STATUS_VFORK_WAIT to suspend parent.
pub fn sys_vfork(vm: &mut ThreadState, _base: u32) -> i32 {
    // Snapshot parent registers
    *vfork_snapshot() = Some(VforkSnapshot {
        x: vm.x,
        pc: vm.pc,
        f: vm.f,
        fcsr: vm.fcsr,
        sig_mask: vm.sig_mask,
    });

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
    if let Some(snap) = vfork_snapshot().take() {
        vm.x = snap.x;
        vm.pc = snap.pc;
        vm.f = snap.f;
        vm.fcsr = snap.fcsr;
        vm.sig_mask = snap.sig_mask;
        vm.x[10] = child_pid as u64; // parent's clone returns child PID
        vm.status = STATUS_OK;
    }
}

// =========================================================================
// execve
// =========================================================================

/// execve: replace process image. Kernel side prepares handoff data,
/// returns STATUS_EXECVE_SPAWN for TS to create child Worker.
/// https://man7.org/linux/man-pages/man2/execve.2.html
pub fn sys_execve(
    vm: &mut ThreadState,
    base: u32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
) -> i64 {
    let parent_pid = match ensure_current_process(vm, base) {
        Some(slot) => slot.pid,
        None => return ESRCH,
    };
    let child_pid = alloc_pid();
    record_child(child_pid);
    inherit_process(parent_pid, child_pid, true);

    // Build FD list: close CLOEXEC, keep the rest
    // The TS runtime reads the surviving FD entries from ProcessState.
    let ps_ptr = vm.process_ptr as u64;
    let max_fds = MAX_FDS;
    for i in 0..max_fds {
        let entry_off = ps_ptr + (i * core::mem::size_of::<FdEntry>()) as u64;
        let ofd_id = unsafe { guest_mem::read_u32(base, entry_off) };
        let fd_flags = unsafe { guest_mem::read_u32(base, entry_off + 4) };
        if ofd_id != 0 && (fd_flags & O_CLOEXEC as u32) != 0 {
            // Mark as closed for the child
            unsafe { guest_mem::write_u32(base, entry_off, 0) };
            unsafe { guest_mem::write_u32(base, entry_off + 4, 0) };
        }
    }

    // Signal dispositions: caught → SIG_DFL (POSIX execve semantics)
    let pid = crate::syscall::signal::pid_from_vm(vm, base);
    crate::syscall::signal::reset_on_execve(pid);
    // Signal mask: preserved (already in ThreadState)
    // Alt stack: not preserved
    vm.sigaltstack_sp = 0;
    vm.sigaltstack_size = 0;
    vm.sigaltstack_flags = 0;

    // Store handoff info in registers for TS to read:
    // a0 = path_addr, a1 = argv_addr, a2 = envp_addr, a3 = child_pid
    vm.x[10] = path_addr;
    vm.x[11] = argv_addr;
    vm.x[12] = envp_addr;
    vm.x[13] = child_pid as u64;

    // If we're in a vfork child, TS will resume parent after child Worker is created.

    vm.status = STATUS_EXECVE_SPAWN;
    child_pid as i64
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

    // TS reads: a0 = child_pid, status = STATUS_EXECVE_SPAWN
    // TS copies guest Memory, creates new Worker
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
    use crate::abi::*;
    use crate::test_helpers::TestVm;

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
        assert!(super::vfork_snapshot().is_some());
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
    fn execve_returns_status_execve_spawn() {
        let mut t = TestVm::new();
        let path_addr = t.scratch;
        t.write_mem(path_addr, b"/bin/test\0");

        let ret = super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);
        assert!(ret > 0, "execve should return positive child PID");
        assert_eq!(t.vm.status, STATUS_EXECVE_SPAWN);
    }

    #[test]
    fn execve_clears_cloexec_fds() {
        let mut t = TestVm::new();
        // Set FD 3 with O_CLOEXEC
        let ps_ptr = t.vm.process_ptr as u64;
        let fd3_off = ps_ptr + 3 * core::mem::size_of::<crate::types::FdEntry>() as u64;
        unsafe {
            crate::guest_mem::write_u32(t.base, fd3_off, 5); // ofd_id = 5
            crate::guest_mem::write_u32(t.base, fd3_off + 4, O_CLOEXEC as u32); // fd_flags
        }

        let path_addr = t.scratch;
        t.write_mem(path_addr, b"/bin/test\0");
        super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

        // FD 3 should be cleared
        let ofd = unsafe { crate::guest_mem::read_u32(t.base, fd3_off) };
        assert_eq!(ofd, 0, "CLOEXEC fd should be cleared by execve");
    }

    #[test]
    fn execve_clears_alt_stack() {
        let mut t = TestVm::new();
        t.vm.sigaltstack_sp = 0x5000;
        t.vm.sigaltstack_size = 8192;

        let path_addr = t.scratch;
        t.write_mem(path_addr, b"/bin/test\0");
        super::sys_execve(&mut t.vm, t.base, path_addr, 0, 0);

        assert_eq!(
            t.vm.sigaltstack_sp, 0,
            "alt stack should be cleared by execve"
        );
        assert_eq!(t.vm.sigaltstack_size, 0);
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
    }
}
