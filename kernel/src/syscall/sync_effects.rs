use crate::abi;
use crate::abi::*;
use crate::fs::fd_table;
use crate::types::ThreadState;

const SYNC_EFFECT_PIPE_STATE: u32 = 1 << 0;
const SYNC_EFFECT_SOCKET_STATE: u32 = 1 << 1;
const SYNC_EFFECT_EPOLL_STATE: u32 = 1 << 2;
const SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE: u32 = 1 << 3;
const SYNC_EFFECT_PROCESS_LIFECYCLE: u32 = 1 << 4;
const SYNC_EFFECT_SIGNAL_WAITERS: u32 = 1 << 5;
const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;
const SYNC_EFFECT_PROCESS_MEMFS: u32 = 1 << 7;

pub(in crate::syscall) fn mark_process_memfs_sync_effect(vm: &mut ThreadState) {
    vm.completed_sync_effects |= SYNC_EFFECT_PROCESS_MEMFS;
}

pub(in crate::syscall) fn mark_fork_shared_ofd_sync_effect(vm: &mut ThreadState) {
    vm.completed_sync_effects |= SYNC_EFFECT_FORK_SHARED_OFD_STATE;
}

pub(in crate::syscall) fn mark_socket_sync_effect(vm: &mut ThreadState) {
    vm.completed_sync_effects |=
        SYNC_EFFECT_SOCKET_STATE | SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE;
}

pub(in crate::syscall) fn mark_epoll_ready_sync_effect(vm: &mut ThreadState) {
    vm.completed_sync_effects |= SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE;
}

pub(in crate::syscall) fn mark_pipe_sync_effect(
    vm: &mut ThreadState,
    pipe_slot: u32,
    write_effect: bool,
) {
    vm.completed_sync_effects |= SYNC_EFFECT_PIPE_STATE;
    if pipe_slot > 0 && pipe_slot < 64 {
        vm.completed_pipe_sync_slots |= 1u64 << pipe_slot;
        if write_effect {
            vm.completed_pipe_sync_write_slots |= 1u64 << pipe_slot;
        } else {
            vm.completed_pipe_sync_read_slots |= 1u64 << pipe_slot;
        }
    }
}

pub(super) fn mark_completed_syscall_sync_effects(
    vm: &mut ThreadState,
    base: u32,
    nr: u64,
    a0: u64,
    result: i64,
    status: i32,
) {
    if status != abi::STATUS_OK || result < 0 {
        return;
    }
    let effects = match nr {
        SYS_OPENAT => SYNC_EFFECT_FORK_SHARED_OFD_STATE,
        SYS_PIPE2 => {
            SYNC_EFFECT_PIPE_STATE | SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_FORK_SHARED_OFD_STATE
        }
        SYS_CLOSE | SYS_CLOSE_RANGE | SYS_DUP | SYS_DUP3 | SYS_FCNTL | SYS_IOCTL => {
            SYNC_EFFECT_PIPE_STATE
                | SYNC_EFFECT_SOCKET_STATE
                | SYNC_EFFECT_EPOLL_STATE
                | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                | SYNC_EFFECT_FORK_SHARED_OFD_STATE
        }
        SYS_SOCKET | SYS_SOCKETPAIR | SYS_ACCEPT4 => {
            SYNC_EFFECT_SOCKET_STATE | SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_FORK_SHARED_OFD_STATE
        }
        SYS_EVENTFD2 => {
            SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                | SYNC_EFFECT_EPOLL_STATE
                | SYNC_EFFECT_FORK_SHARED_OFD_STATE
        }
        SYS_EPOLL_CREATE1 => SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_FORK_SHARED_OFD_STATE,
        SYS_EPOLL_CTL => SYNC_EFFECT_EPOLL_STATE,
        SYS_EXECVE | SYS_EXECVEAT => {
            SYNC_EFFECT_PIPE_STATE
                | SYNC_EFFECT_SOCKET_STATE
                | SYNC_EFFECT_EPOLL_STATE
                | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                | SYNC_EFFECT_PROCESS_LIFECYCLE
        }
        SYS_SETPGID | SYS_SETSID => SYNC_EFFECT_PROCESS_LIFECYCLE,
        SYS_KILL | SYS_TKILL | SYS_TGKILL => SYNC_EFFECT_SIGNAL_WAITERS,
        _ => 0,
    };
    if nr == SYS_PIPE2 {
        unsafe {
            let read_fd = crate::guest_mem::read_u32(base, a0) as u64;
            if let Some(ofd) = fd_table::get_ofd(base, vm, read_fd) {
                if ofd.fd_type == abi::FD_TYPE_PIPE && ofd.ino < 64 {
                    let bit = 1u64 << ofd.ino;
                    vm.completed_pipe_sync_slots |= bit;
                    vm.completed_pipe_sync_read_slots |= bit;
                    vm.completed_pipe_sync_write_slots |= bit;
                    vm.completed_pipe_fresh_slots |= bit;
                }
            }
        }
    }
    vm.completed_sync_effects |= effects;
}
