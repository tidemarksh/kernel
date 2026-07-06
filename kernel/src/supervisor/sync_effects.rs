use crate::abi::{
    FD_TYPE_EVENTFD, FD_TYPE_FILE, FD_TYPE_PIPE, FD_TYPE_SOCKET, STATUS_OK, SYS_ACCEPT4, SYS_BIND,
    SYS_CLOSE, SYS_CLOSE_RANGE, SYS_CONNECT, SYS_DUP, SYS_DUP3, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL,
    SYS_EVENTFD2, SYS_EXECVE, SYS_EXECVEAT, SYS_FCNTL, SYS_IOCTL, SYS_KILL, SYS_LISTEN, SYS_LSEEK,
    SYS_OPENAT, SYS_PIPE2, SYS_PWRITE64, SYS_READ, SYS_READV, SYS_RECVFROM, SYS_RECVMSG,
    SYS_SENDMSG, SYS_SENDTO, SYS_SETPGID, SYS_SETSID, SYS_SETSOCKOPT, SYS_SHUTDOWN, SYS_SOCKET,
    SYS_SOCKETPAIR, SYS_TGKILL, SYS_TKILL, SYS_WRITE, SYS_WRITEV,
};
use crate::types::ThreadState;

pub(super) const SYNC_EFFECT_PIPE_STATE: u32 = 1 << 0;
pub(super) const SYNC_EFFECT_SOCKET_STATE: u32 = 1 << 1;
pub(super) const SYNC_EFFECT_EPOLL_STATE: u32 = 1 << 2;
pub(super) const SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE: u32 = 1 << 3;
pub(super) const SYNC_EFFECT_PROCESS_LIFECYCLE: u32 = 1 << 4;
pub(super) const SYNC_EFFECT_SIGNAL_WAITERS: u32 = 1 << 5;
pub(super) const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;
pub(super) const SYNC_EFFECT_PROCESS_MEMFS: u32 = 1 << 7;

const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const FIONBIO: u64 = 0x5421;

const PIPE_SOCKET_EPOLL_EFFECTS: u32 = SYNC_EFFECT_PIPE_STATE
    | SYNC_EFFECT_SOCKET_STATE
    | SYNC_EFFECT_EPOLL_STATE
    | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE;

const EPOLL_READY_EFFECTS: u32 = SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE;

#[derive(Clone, Copy)]
struct FdTrace {
    nr: u64,
    arg0_ofd_type: i32,
    arg1: u64,
    result: i64,
    result_known: bool,
}

pub(super) fn take_completed_sync_effects(vm_ptr: u32, status: i32) -> u32 {
    if vm_ptr == 0 {
        return 0;
    }
    let vm = unsafe { &mut *(vm_ptr as *mut ThreadState) };
    let completed = vm.completed_sync_effects;
    vm.completed_sync_effects = 0;
    let nr = vm.x[17];
    let result = u64_as_i64(vm.x[10]);
    let trace = latest_fd_trace(vm_ptr, nr);
    classify_completed_sync_effects_for(status, Some(nr), completed, Some(vm.x[11]), result, trace)
}

fn u64_as_i64(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

fn matches_fd_data_syscall(nr: u64) -> bool {
    matches!(
        nr,
        SYS_READ | SYS_WRITE | SYS_PWRITE64 | SYS_LSEEK | SYS_READV | SYS_WRITEV
    )
}

fn regular_file_writing_syscall(nr: u64) -> bool {
    matches!(nr, SYS_WRITE | SYS_WRITEV | SYS_PWRITE64)
}

fn fcntl_command_needs_fd_state_sync(command: Option<u64>) -> bool {
    match command {
        None => true,
        Some(F_GETFD | F_SETFD | F_GETFL) => false,
        Some(_) => true,
    }
}

fn ioctl_request_needs_fd_state_sync(request: Option<u64>) -> bool {
    match request {
        None => true,
        Some(FIONBIO) => true,
        Some(_) => false,
    }
}

fn fcntl_command_may_mutate_fork_shared_ofd(command: Option<u64>) -> bool {
    match command {
        None => true,
        Some(F_SETFL) => true,
        Some(_) => false,
    }
}

fn ioctl_request_may_mutate_fork_shared_ofd(request: Option<u64>) -> bool {
    match request {
        None => true,
        Some(FIONBIO) => true,
        Some(_) => false,
    }
}

fn syscall_mutates_fork_shared_ofd_state(nr: Option<u64>) -> bool {
    matches!(
        nr,
        Some(
            SYS_OPENAT
                | SYS_CLOSE
                | SYS_DUP
                | SYS_DUP3
                | SYS_PIPE2
                | SYS_SOCKET
                | SYS_ACCEPT4
                | SYS_EVENTFD2
                | SYS_EPOLL_CREATE1
        )
    )
}

fn normalize_fork_shared_sync_effects(effects: u32, nr: Option<u64>) -> u32 {
    if nr.is_none() || syscall_mutates_fork_shared_ofd_state(nr) {
        effects
    } else {
        effects & !SYNC_EFFECT_FORK_SHARED_OFD_STATE
    }
}

fn latest_trace_or_current(
    trace: Option<FdTrace>,
    nr: u64,
    arg1: Option<u64>,
    result: i64,
) -> FdTrace {
    trace.unwrap_or(FdTrace {
        nr,
        arg0_ofd_type: 0,
        arg1: arg1.unwrap_or(0),
        result,
        result_known: true,
    })
}

fn trace_failed(trace: FdTrace) -> bool {
    trace.result_known && trace.result < 0
}

fn classify_completed_sync_effects_for(
    status: i32,
    nr: Option<u64>,
    completed_effects: u32,
    arg1: Option<u64>,
    result: i64,
    fd_trace: Option<FdTrace>,
) -> u32 {
    if status != STATUS_OK {
        return if completed_effects == 0 {
            0
        } else {
            normalize_fork_shared_sync_effects(completed_effects, nr)
        };
    }

    let Some(nr) = nr else {
        return if completed_effects == 0 {
            0
        } else {
            normalize_fork_shared_sync_effects(completed_effects, None)
        };
    };

    if matches_fd_data_syscall(nr) {
        let trace = fd_trace.filter(|trace| trace.nr == nr);
        if let Some(trace) = trace {
            if trace.arg0_ofd_type == FD_TYPE_FILE {
                let regular_file_effects = completed_effects & !PIPE_SOCKET_EPOLL_EFFECTS;
                if regular_file_writing_syscall(nr) {
                    return regular_file_effects
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                        | SYNC_EFFECT_PROCESS_MEMFS;
                }
                return regular_file_effects | SYNC_EFFECT_FORK_SHARED_OFD_STATE;
            }
            if trace.arg0_ofd_type == FD_TYPE_EVENTFD {
                return completed_effects | EPOLL_READY_EFFECTS;
            }
        }
        return completed_effects;
    }

    if matches!(nr, SYS_FCNTL | SYS_IOCTL) {
        let trace = latest_trace_or_current(fd_trace, nr, arg1, result);
        if trace_failed(trace) {
            return completed_effects & !SYNC_EFFECT_FORK_SHARED_OFD_STATE;
        }
        let command = Some(trace.arg1);
        let needs_fd_state_sync = if nr == SYS_FCNTL {
            fcntl_command_needs_fd_state_sync(command)
        } else {
            ioctl_request_needs_fd_state_sync(command)
        };
        if !needs_fd_state_sync {
            return 0;
        }
        let may_mutate_fork_shared_ofd = if nr == SYS_FCNTL {
            fcntl_command_may_mutate_fork_shared_ofd(command)
        } else {
            ioctl_request_may_mutate_fork_shared_ofd(command)
        };
        return PIPE_SOCKET_EPOLL_EFFECTS
            | if may_mutate_fork_shared_ofd {
                SYNC_EFFECT_FORK_SHARED_OFD_STATE
            } else {
                0
            };
    }

    if nr == SYS_OPENAT {
        return SYNC_EFFECT_FORK_SHARED_OFD_STATE;
    }

    if matches!(nr, SYS_CLOSE | SYS_DUP | SYS_DUP3) {
        let trace = latest_trace_or_current(fd_trace, nr, arg1, result);
        if trace_failed(trace) {
            return completed_effects & !SYNC_EFFECT_FORK_SHARED_OFD_STATE;
        }
        return match trace.arg0_ofd_type {
            FD_TYPE_FILE => SYNC_EFFECT_FORK_SHARED_OFD_STATE,
            FD_TYPE_SOCKET => {
                SYNC_EFFECT_SOCKET_STATE
                    | SYNC_EFFECT_EPOLL_STATE
                    | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                    | SYNC_EFFECT_FORK_SHARED_OFD_STATE
            }
            FD_TYPE_PIPE => {
                SYNC_EFFECT_PIPE_STATE
                    | SYNC_EFFECT_EPOLL_STATE
                    | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                    | SYNC_EFFECT_FORK_SHARED_OFD_STATE
            }
            _ => PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE,
        };
    }

    if nr == SYS_CLOSE_RANGE {
        return PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE;
    }

    if nr == SYS_PIPE2 {
        return SYNC_EFFECT_PIPE_STATE
            | SYNC_EFFECT_EPOLL_STATE
            | SYNC_EFFECT_FORK_SHARED_OFD_STATE;
    }

    if matches!(nr, SYS_SOCKET | SYS_SOCKETPAIR | SYS_ACCEPT4) {
        return SYNC_EFFECT_SOCKET_STATE
            | SYNC_EFFECT_EPOLL_STATE
            | SYNC_EFFECT_FORK_SHARED_OFD_STATE;
    }

    if matches!(
        nr,
        SYS_BIND
            | SYS_LISTEN
            | SYS_CONNECT
            | SYS_SENDTO
            | SYS_RECVFROM
            | SYS_SENDMSG
            | SYS_RECVMSG
            | SYS_SETSOCKOPT
            | SYS_SHUTDOWN
    ) {
        return SYNC_EFFECT_SOCKET_STATE | SYNC_EFFECT_EPOLL_STATE;
    }

    if nr == SYS_EVENTFD2 {
        return SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
            | SYNC_EFFECT_EPOLL_STATE
            | SYNC_EFFECT_FORK_SHARED_OFD_STATE;
    }

    if nr == SYS_EPOLL_CREATE1 {
        return SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_FORK_SHARED_OFD_STATE;
    }

    if nr == SYS_EPOLL_CTL {
        return SYNC_EFFECT_EPOLL_STATE;
    }

    if matches!(nr, SYS_EXECVE | SYS_EXECVEAT) {
        return PIPE_SOCKET_EPOLL_EFFECTS
            | SYNC_EFFECT_FORK_SHARED_OFD_STATE
            | SYNC_EFFECT_PROCESS_LIFECYCLE;
    }

    if matches!(nr, SYS_SETPGID | SYS_SETSID) {
        return SYNC_EFFECT_PROCESS_LIFECYCLE;
    }

    if matches!(nr, SYS_KILL | SYS_TKILL | SYS_TGKILL) {
        return SYNC_EFFECT_SIGNAL_WAITERS;
    }

    if completed_effects == 0 {
        0
    } else {
        normalize_fork_shared_sync_effects(completed_effects, Some(nr))
    }
}

#[cfg(not(any(test, feature = "harness")))]
fn latest_fd_trace(vm_ptr: u32, nr: u64) -> Option<FdTrace> {
    let len = crate::syscall::trace::fd::len();
    for index in (0..len).rev() {
        let trace = crate::syscall::trace::fd::entry(index);
        if trace.vm_ptr != 0 && trace.vm_ptr != vm_ptr {
            continue;
        }
        if trace.nr != nr {
            continue;
        }
        return Some(FdTrace {
            nr: trace.nr,
            arg0_ofd_type: trace.arg0_ofd_type,
            arg1: trace.arg1,
            result: trace.result,
            result_known: true,
        });
    }
    None
}

#[cfg(any(test, feature = "harness"))]
fn latest_fd_trace(vm_ptr: u32, nr: u64) -> Option<FdTrace> {
    let len = crate::harness::debug::fd_syscall_trace_len();
    for index in (0..len).rev() {
        let trace = crate::harness::debug::fd_syscall_trace_entry(index);
        if trace.vm_ptr != 0 && trace.vm_ptr != vm_ptr {
            continue;
        }
        if trace.nr != nr {
            continue;
        }
        return Some(FdTrace {
            nr: trace.nr,
            arg0_ofd_type: trace.arg0_ofd_type,
            arg1: trace.arg1,
            result: trace.result,
            result_known: true,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(nr: u64, fd_type: i32, arg1: u64, result: i64) -> FdTrace {
        FdTrace {
            nr,
            arg0_ofd_type: fd_type,
            arg1,
            result,
            result_known: true,
        }
    }

    #[test]
    fn supervisor_sync_effects_classifies_fd_control_commands() {
        assert_eq!(
            classify_completed_sync_effects_for(
                STATUS_OK,
                Some(SYS_FCNTL),
                PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE,
                Some(F_GETFL),
                0,
                Some(trace(SYS_FCNTL, FD_TYPE_PIPE, F_GETFL, 0)),
            ),
            0
        );
        assert_eq!(
            classify_completed_sync_effects_for(
                STATUS_OK,
                Some(SYS_FCNTL),
                PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE,
                Some(F_SETFL),
                0,
                Some(trace(SYS_FCNTL, FD_TYPE_PIPE, F_SETFL, 0)),
            ),
            PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE
        );
        assert_eq!(
            classify_completed_sync_effects_for(
                STATUS_OK,
                Some(SYS_IOCTL),
                PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE,
                Some(0),
                0,
                Some(trace(SYS_IOCTL, FD_TYPE_SOCKET, 0, 0)),
            ),
            0
        );
        assert_eq!(
            classify_completed_sync_effects_for(
                STATUS_OK,
                Some(SYS_IOCTL),
                PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE,
                Some(FIONBIO),
                0,
                Some(trace(SYS_IOCTL, FD_TYPE_SOCKET, FIONBIO, 0)),
            ),
            PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE
        );
    }

    #[test]
    fn supervisor_sync_effects_classifies_stream_io_from_fd_trace() {
        assert_eq!(
            classify_completed_sync_effects_for(
                STATUS_OK,
                Some(SYS_READ),
                SYNC_EFFECT_PIPE_STATE | SYNC_EFFECT_EPOLL_STATE,
                None,
                16,
                Some(trace(SYS_READ, FD_TYPE_FILE, 0, 16)),
            ),
            SYNC_EFFECT_FORK_SHARED_OFD_STATE
        );
        assert_eq!(
            classify_completed_sync_effects_for(
                STATUS_OK,
                Some(SYS_WRITE),
                SYNC_EFFECT_PIPE_STATE,
                None,
                16,
                Some(trace(SYS_WRITE, FD_TYPE_FILE, 0, 16)),
            ),
            SYNC_EFFECT_FORK_SHARED_OFD_STATE | SYNC_EFFECT_PROCESS_MEMFS
        );
        assert_eq!(
            classify_completed_sync_effects_for(
                STATUS_OK,
                Some(SYS_WRITE),
                0,
                None,
                8,
                Some(trace(SYS_WRITE, FD_TYPE_EVENTFD, 0, 8)),
            ),
            SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
        );
    }

    #[test]
    fn supervisor_sync_effects_classifies_fd_lifecycle_and_process_effects() {
        assert_eq!(
            classify_completed_sync_effects_for(
                STATUS_OK,
                Some(SYS_CLOSE),
                PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE,
                None,
                0,
                Some(trace(SYS_CLOSE, FD_TYPE_FILE, 0, 0)),
            ),
            SYNC_EFFECT_FORK_SHARED_OFD_STATE
        );
        assert_eq!(
            classify_completed_sync_effects_for(
                STATUS_OK,
                Some(SYS_CLOSE),
                PIPE_SOCKET_EPOLL_EFFECTS | SYNC_EFFECT_FORK_SHARED_OFD_STATE,
                None,
                0,
                Some(trace(SYS_CLOSE, FD_TYPE_SOCKET, 0, 0)),
            ),
            SYNC_EFFECT_SOCKET_STATE
                | SYNC_EFFECT_EPOLL_STATE
                | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                | SYNC_EFFECT_FORK_SHARED_OFD_STATE
        );
        assert_eq!(
            classify_completed_sync_effects_for(STATUS_OK, Some(SYS_PIPE2), 0, None, 0, None,),
            SYNC_EFFECT_PIPE_STATE | SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_FORK_SHARED_OFD_STATE
        );
        assert_eq!(
            classify_completed_sync_effects_for(STATUS_OK, Some(SYS_EXECVE), 0, None, 0, None,),
            PIPE_SOCKET_EPOLL_EFFECTS
                | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                | SYNC_EFFECT_PROCESS_LIFECYCLE
        );
        assert_eq!(
            classify_completed_sync_effects_for(STATUS_OK, Some(SYS_KILL), 0, None, 0, None,),
            SYNC_EFFECT_SIGNAL_WAITERS
        );
    }
}
