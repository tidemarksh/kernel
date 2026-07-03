use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::abi::{
    FD_TYPE_FILE, FD_TYPE_PIPE, FD_TYPE_SOCKET, MAX_FDS, SYS_ACCEPT4, SYS_CLOSE, SYS_CLOSE_RANGE,
    SYS_DUP, SYS_DUP3, SYS_EPOLL_CREATE1, SYS_EVENTFD2, SYS_EXECVE, SYS_FCNTL, SYS_IOCTL,
    SYS_LSEEK, SYS_OPENAT, SYS_PIPE2, SYS_PWRITE64, SYS_READ, SYS_READV, SYS_RECVFROM, SYS_RECVMSG,
    SYS_SENDMSG, SYS_SENDTO, SYS_SOCKET, SYS_SOCKETPAIR, SYS_WRITE, SYS_WRITEV,
};
use crate::fs::fd_table;
use crate::types::{OpenFileDesc, ProcessState, ThreadState};

static FD_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static FD_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_FD_CONTROL: super::SupervisorFdControlRecord =
    super::SupervisorFdControlRecord::empty();

const F_SETFL: u64 = 4;
const FIONBIO: u64 = 0x5421;

pub(super) const FD_SYSCALL_NR_CURRENT: u64 = u64::MAX;
pub(super) const FD_TRACE_ARG_UNKNOWN: u64 = u64::MAX;
pub(super) const FD_TRACE_TOPOLOGY_ACTION_UNRESOLVED: u32 = 0;
pub(super) const FD_TRACE_TOPOLOGY_ACTION_RULES_OUT: u32 = 1;
pub(super) const FD_TRACE_TOPOLOGY_ACTION_NEEDS_PEER_CHECK: u32 = 2;

pub(super) fn init() {
    FD_CONTROL_COUNT.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&FD_CONTROL_LOCK, || unsafe {
        LAST_FD_CONTROL = super::SupervisorFdControlRecord::empty();
    });
}

pub fn fd_control_count() -> u64 {
    FD_CONTROL_COUNT.load(Ordering::Relaxed)
}

pub(super) fn process_state_from_vm_ptr(vm_ptr: u32) -> Option<&'static ProcessState> {
    let vm = super::thread::state_from_ptr(vm_ptr)?;
    if vm.process_ptr == 0 {
        return None;
    }
    let absolute = (vm.guest_base as u64).checked_add(vm.process_ptr as u64)?;
    let align = core::mem::align_of::<ProcessState>() as u64;
    if (absolute & (align - 1)) != 0 {
        return None;
    }
    let end = absolute.checked_add(core::mem::size_of::<ProcessState>() as u64)?;
    let memory_size = crate::wasm::memory_size_bytes();
    if memory_size == 0 || end > memory_size {
        return None;
    }
    Some(unsafe { &*(absolute as *const ProcessState) })
}

pub(super) fn for_each_process_held_ofd<F>(vm_ptr: u32, mut f: F)
where
    F: FnMut(u32, OpenFileDesc),
{
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return;
    };
    let Some(ps) = process_state_from_vm_ptr(vm_ptr) else {
        return;
    };

    for fd in 0..MAX_FDS {
        let entry = fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, fd);
        let ofd_id = entry.ofd_id;
        if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
            continue;
        }
        if let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) {
            f(ofd_id, ofd);
        }
    }

    for thread in ps.threads.iter() {
        let Some(thread_vm) = super::thread::state_from_ptr(thread.thread_ptr) else {
            continue;
        };
        if thread_vm.guest_base != vm.guest_base
            || thread_vm.process_ptr != vm.process_ptr
            || thread_vm.tid != thread.tid
        {
            continue;
        }
        let ofd_id = thread_vm.blocked_ofd_id;
        if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
            continue;
        }
        if let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) {
            f(ofd_id, ofd);
        }
    }
}

pub fn process_held_ofd_refcount(vm_ptr: u32, ofd_id: u32) -> i32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let mut refcount = 0i32;
    for_each_process_held_ofd(vm_ptr, |held_ofd_id, _| {
        if held_ofd_id == ofd_id {
            refcount = refcount.saturating_add(1);
        }
    });
    refcount
}

pub(super) fn fd_syscall_nr_current() -> u64 {
    FD_SYSCALL_NR_CURRENT
}

pub(super) fn fd_trace_arg_unknown() -> u64 {
    FD_TRACE_ARG_UNKNOWN
}

pub(super) fn fd_trace_topology_action_unresolved() -> u32 {
    FD_TRACE_TOPOLOGY_ACTION_UNRESOLVED
}

pub(super) fn fd_trace_topology_action_rules_out() -> u32 {
    FD_TRACE_TOPOLOGY_ACTION_RULES_OUT
}

pub(super) fn fd_trace_topology_action_needs_peer_check() -> u32 {
    FD_TRACE_TOPOLOGY_ACTION_NEEDS_PEER_CHECK
}

fn thread_state(vm_ptr: u32) -> Option<&'static ThreadState> {
    super::thread::state_from_ptr(vm_ptr)
}

fn current_or_given_syscall_nr(vm_ptr: u32, syscall_nr: u64) -> Option<u64> {
    if syscall_nr == FD_SYSCALL_NR_CURRENT {
        thread_state(vm_ptr).map(|vm| vm.x[17])
    } else {
        Some(syscall_nr)
    }
}

fn optional_trace_arg(value: u64) -> Option<u64> {
    (value != FD_TRACE_ARG_UNKNOWN).then_some(value)
}

fn u64_as_i64(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

fn thread_syscall_returned_error(vm_ptr: u32) -> bool {
    thread_state(vm_ptr).is_some_and(|vm| u64_as_i64(vm.x[10]) < 0)
}

fn thread_arg1(vm_ptr: u32) -> Option<u64> {
    thread_state(vm_ptr).map(|vm| vm.x[11])
}

fn fcntl_command_may_change_fork_shared_ofd_topology(cmd: Option<u64>) -> bool {
    match cmd {
        None => true,
        Some(F_SETFL) => true,
        Some(_) => false,
    }
}

fn ioctl_request_may_change_fork_shared_ofd_topology(request: Option<u64>) -> bool {
    match request {
        None => true,
        Some(FIONBIO) => true,
        Some(_) => false,
    }
}

fn syscall_may_change_fork_shared_ofd_topology_for(
    nr: Option<u64>,
    returned_error: bool,
    arg1: Option<u64>,
) -> bool {
    if returned_error {
        return false;
    }
    match nr {
        Some(SYS_FCNTL) => fcntl_command_may_change_fork_shared_ofd_topology(arg1),
        Some(SYS_IOCTL) => ioctl_request_may_change_fork_shared_ofd_topology(arg1),
        Some(
            SYS_OPENAT | SYS_CLOSE | SYS_CLOSE_RANGE | SYS_PIPE2 | SYS_SOCKET | SYS_SOCKETPAIR
            | SYS_ACCEPT4 | SYS_EVENTFD2 | SYS_EPOLL_CREATE1 | SYS_DUP | SYS_DUP3 | SYS_EXECVE,
        ) => true,
        _ => false,
    }
}

pub fn syscall_may_change_fork_shared_ofd_topology(vm_ptr: u32, syscall_nr: u64) -> i32 {
    let nr = current_or_given_syscall_nr(vm_ptr, syscall_nr);
    let arg1 = if matches!(nr, Some(SYS_FCNTL | SYS_IOCTL)) {
        thread_arg1(vm_ptr)
    } else {
        None
    };
    syscall_may_change_fork_shared_ofd_topology_for(nr, thread_syscall_returned_error(vm_ptr), arg1)
        as i32
}

fn explicit_fork_shared_effect_may_require_sync_for(
    nr: Option<u64>,
    returned_error: bool,
    arg1: Option<u64>,
) -> bool {
    if returned_error {
        return false;
    }
    match nr {
        Some(SYS_FCNTL) => fcntl_command_may_change_fork_shared_ofd_topology(arg1),
        Some(SYS_IOCTL) => ioctl_request_may_change_fork_shared_ofd_topology(arg1),
        _ => true,
    }
}

pub fn explicit_fork_shared_effect_may_require_sync(vm_ptr: u32, syscall_nr: u64) -> i32 {
    let nr = current_or_given_syscall_nr(vm_ptr, syscall_nr);
    let arg1 = if matches!(nr, Some(SYS_FCNTL | SYS_IOCTL)) {
        thread_arg1(vm_ptr)
    } else {
        None
    };
    explicit_fork_shared_effect_may_require_sync_for(
        nr,
        thread_syscall_returned_error(vm_ptr),
        arg1,
    ) as i32
}

fn regular_file_offset_sync_candidate_syscall(nr: Option<u64>) -> bool {
    matches!(
        nr,
        Some(SYS_READ | SYS_READV | SYS_WRITE | SYS_WRITEV | SYS_PWRITE64 | SYS_LSEEK)
    )
}

pub fn syscall_only_regular_file_offset_sync_when_peer_shared(vm_ptr: u32, syscall_nr: u64) -> i32 {
    let nr = current_or_given_syscall_nr(vm_ptr, syscall_nr);
    if !regular_file_offset_sync_candidate_syscall(nr) {
        return 0;
    }
    let Some(vm) = thread_state(vm_ptr) else {
        return 0;
    };
    let fd = vm.x[10];
    if fd >= MAX_FDS as u64 {
        return 0;
    }
    fd_table::get_ofd(vm.guest_base, vm, fd).is_some_and(|ofd| ofd.fd_type == FD_TYPE_FILE) as i32
}

fn dup3_replaces_regular_file_fd(vm_ptr: u32, new_fd: Option<u64>) -> bool {
    let Some(new_fd) = new_fd else {
        return false;
    };
    if new_fd >= MAX_FDS as u64 {
        return false;
    }
    let Some(vm) = thread_state(vm_ptr) else {
        return false;
    };
    fd_table::get_ofd(vm.guest_base, vm, new_fd).is_some_and(|ofd| ofd.fd_type == FD_TYPE_FILE)
}

fn fd_trace_fork_shared_topology_action_for(
    nr: u64,
    arg1: Option<u64>,
    result: i64,
    result_known: bool,
    dup3_new_fd_is_regular_file: bool,
) -> u32 {
    if result_known && result < 0 {
        return FD_TRACE_TOPOLOGY_ACTION_RULES_OUT;
    }
    if nr == SYS_DUP3 && dup3_new_fd_is_regular_file {
        return FD_TRACE_TOPOLOGY_ACTION_UNRESOLVED;
    }
    match nr {
        SYS_CLOSE | SYS_DUP | SYS_PIPE2 | SYS_SOCKET | SYS_SOCKETPAIR | SYS_ACCEPT4
        | SYS_EVENTFD2 | SYS_EPOLL_CREATE1 => FD_TRACE_TOPOLOGY_ACTION_NEEDS_PEER_CHECK,
        SYS_FCNTL => {
            if fcntl_command_may_change_fork_shared_ofd_topology(arg1) {
                FD_TRACE_TOPOLOGY_ACTION_NEEDS_PEER_CHECK
            } else {
                FD_TRACE_TOPOLOGY_ACTION_RULES_OUT
            }
        }
        SYS_IOCTL => {
            if ioctl_request_may_change_fork_shared_ofd_topology(arg1) {
                FD_TRACE_TOPOLOGY_ACTION_NEEDS_PEER_CHECK
            } else {
                FD_TRACE_TOPOLOGY_ACTION_RULES_OUT
            }
        }
        _ => FD_TRACE_TOPOLOGY_ACTION_UNRESOLVED,
    }
}

pub fn fd_trace_fork_shared_topology_action(
    vm_ptr: u32,
    nr: u64,
    arg1: u64,
    result: i64,
    result_known: u32,
) -> u32 {
    let arg1 = optional_trace_arg(arg1);
    let dup3_new_fd_is_regular_file = nr == SYS_DUP3 && dup3_replaces_regular_file_fd(vm_ptr, arg1);
    fd_trace_fork_shared_topology_action_for(
        nr,
        arg1,
        result,
        result_known != 0,
        dup3_new_fd_is_regular_file,
    )
}

fn fd_data_plane_io_syscall(nr: u64) -> bool {
    matches!(
        nr,
        SYS_READ
            | SYS_READV
            | SYS_WRITE
            | SYS_WRITEV
            | SYS_RECVFROM
            | SYS_RECVMSG
            | SYS_SENDTO
            | SYS_SENDMSG
    )
}

fn ofd_type_from_trace_or_table(arg0_ofd_id: u32, arg0_ofd_type: i32) -> i32 {
    if arg0_ofd_type > 0 {
        return arg0_ofd_type;
    }
    if arg0_ofd_id == 0 || arg0_ofd_id as usize >= MAX_FDS {
        return 0;
    }
    fd_table::get_ofd_by_id(arg0_ofd_id)
        .map(|ofd| ofd.fd_type)
        .unwrap_or(0)
}

fn fd_trace_data_plane_io_uses_socket_or_pipe_for(
    nr: u64,
    arg0_ofd_type: i32,
    result: i64,
    result_known: bool,
) -> bool {
    result_known
        && result > 0
        && fd_data_plane_io_syscall(nr)
        && (arg0_ofd_type == FD_TYPE_SOCKET || arg0_ofd_type == FD_TYPE_PIPE)
}

pub fn fd_trace_data_plane_io_uses_socket_or_pipe(
    nr: u64,
    arg0_ofd_id: u32,
    arg0_ofd_type: i32,
    result: i64,
    result_known: u32,
) -> i32 {
    fd_trace_data_plane_io_uses_socket_or_pipe_for(
        nr,
        ofd_type_from_trace_or_table(arg0_ofd_id, arg0_ofd_type),
        result,
        result_known != 0,
    ) as i32
}

fn fd_trace_regular_file_write_mutated_memfs_for(
    nr: u64,
    arg0_ofd_type: i32,
    result: i64,
    result_known: bool,
) -> bool {
    result_known && nr == SYS_WRITE && result > 0 && arg0_ofd_type == FD_TYPE_FILE
}

pub fn fd_trace_regular_file_write_mutated_memfs(
    nr: u64,
    arg0_ofd_type: i32,
    result: i64,
    result_known: u32,
) -> i32 {
    fd_trace_regular_file_write_mutated_memfs_for(nr, arg0_ofd_type, result, result_known != 0)
        as i32
}

#[allow(clippy::too_many_arguments)]
pub fn record_fd_control(
    kind: u32,
    vm_ptr: u32,
    process_ptr: u32,
    pid: i32,
    fd: u32,
    fd2: u32,
    ofd_id: u32,
    ofd2_id: u32,
    fd_type: u32,
    resource_slot: u32,
    resource_generation: u32,
    result: i64,
    flags: u64,
    detail0: u64,
    detail1: u64,
) {
    let seq = FD_CONTROL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = super::SupervisorFdControlRecord {
        kind,
        seq,
        vm_ptr,
        process_ptr,
        pid: pid as u32,
        fd,
        fd2,
        ofd_id,
        ofd2_id,
        fd_type,
        resource_slot,
        resource_generation,
        result,
        flags,
        detail0,
        detail1,
    };
    super::lock::with_spin_lock(&FD_CONTROL_LOCK, || unsafe {
        LAST_FD_CONTROL = record;
    });
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_FD_CONTROL_RECORD_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_FD_CONTROL_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = super::lock::with_spin_lock(&FD_CONTROL_LOCK, || unsafe { LAST_FD_CONTROL });
    let mut encoded = [0u8; super::SUPERVISOR_FD_CONTROL_RECORD_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_FD_CONTROL_RECORD_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_FD_CONTROL_RECORD_BYTES);
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.vm_ptr);
    super::write_u32(&mut encoded, 28, record.process_ptr);
    super::write_u32(&mut encoded, 32, record.pid);
    super::write_u32(&mut encoded, 36, record.fd);
    super::write_u32(&mut encoded, 40, record.fd2);
    super::write_u32(&mut encoded, 44, record.ofd_id);
    super::write_u32(&mut encoded, 48, record.ofd2_id);
    super::write_u32(&mut encoded, 52, record.fd_type);
    super::write_u32(&mut encoded, 56, record.resource_slot);
    super::write_u32(&mut encoded, 60, record.resource_generation);
    super::write_u64(&mut encoded, 64, record.result as u64);
    super::write_u64(&mut encoded, 72, record.flags);
    super::write_u64(&mut encoded, 80, record.detail0);
    super::write_u64(&mut encoded, 88, record.detail1);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_FD_CONTROL_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_FD_CONTROL_RECORD_BYTES as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_fd_policy_classifies_topology_syscalls() {
        assert!(syscall_may_change_fork_shared_ofd_topology_for(
            Some(SYS_OPENAT),
            false,
            None,
        ));
        assert!(syscall_may_change_fork_shared_ofd_topology_for(
            Some(SYS_FCNTL),
            false,
            Some(F_SETFL),
        ));
        assert!(syscall_may_change_fork_shared_ofd_topology_for(
            Some(SYS_IOCTL),
            false,
            Some(FIONBIO),
        ));
        assert!(!syscall_may_change_fork_shared_ofd_topology_for(
            Some(SYS_FCNTL),
            false,
            Some(0),
        ));
        assert!(!syscall_may_change_fork_shared_ofd_topology_for(
            Some(SYS_IOCTL),
            false,
            Some(0),
        ));
        assert!(!syscall_may_change_fork_shared_ofd_topology_for(
            Some(SYS_DUP),
            true,
            None,
        ));
    }

    #[test]
    fn supervisor_fd_policy_classifies_trace_topology_actions() {
        assert_eq!(
            fd_trace_fork_shared_topology_action_for(SYS_DUP, None, -1, true, false),
            FD_TRACE_TOPOLOGY_ACTION_RULES_OUT
        );
        assert_eq!(
            fd_trace_fork_shared_topology_action_for(SYS_DUP3, Some(4), 0, true, true),
            FD_TRACE_TOPOLOGY_ACTION_UNRESOLVED
        );
        assert_eq!(
            fd_trace_fork_shared_topology_action_for(SYS_DUP3, Some(4), 0, true, false),
            FD_TRACE_TOPOLOGY_ACTION_UNRESOLVED
        );
        assert_eq!(
            fd_trace_fork_shared_topology_action_for(SYS_FCNTL, Some(F_SETFL), 0, true, false),
            FD_TRACE_TOPOLOGY_ACTION_NEEDS_PEER_CHECK
        );
        assert_eq!(
            fd_trace_fork_shared_topology_action_for(SYS_FCNTL, Some(0), 0, true, false),
            FD_TRACE_TOPOLOGY_ACTION_RULES_OUT
        );
        assert_eq!(
            fd_trace_fork_shared_topology_action_for(SYS_WRITE, None, 8, true, false),
            FD_TRACE_TOPOLOGY_ACTION_UNRESOLVED
        );
    }

    #[test]
    fn supervisor_fd_policy_classifies_data_plane_and_memfs_traces() {
        assert!(regular_file_offset_sync_candidate_syscall(Some(SYS_READ)));
        assert!(regular_file_offset_sync_candidate_syscall(Some(SYS_LSEEK)));
        assert!(!regular_file_offset_sync_candidate_syscall(Some(
            SYS_RECVFROM
        )));
        assert!(fd_trace_data_plane_io_uses_socket_or_pipe_for(
            SYS_RECVFROM,
            FD_TYPE_SOCKET,
            1,
            true,
        ));
        assert!(fd_trace_data_plane_io_uses_socket_or_pipe_for(
            SYS_WRITE,
            FD_TYPE_PIPE,
            1,
            true,
        ));
        assert!(!fd_trace_data_plane_io_uses_socket_or_pipe_for(
            SYS_WRITE,
            FD_TYPE_FILE,
            1,
            true,
        ));
        assert!(fd_trace_regular_file_write_mutated_memfs_for(
            SYS_WRITE,
            FD_TYPE_FILE,
            1,
            true,
        ));
        assert!(!fd_trace_regular_file_write_mutated_memfs_for(
            SYS_WRITE,
            FD_TYPE_FILE,
            0,
            true,
        ));
    }
}
