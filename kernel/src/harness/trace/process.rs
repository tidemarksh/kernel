use super::RUNTIME_DEBUG_ENABLED;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallTraceSummary {
    pub vm_ptr: u32,
    pub nr: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub result: i64,
    pub status: i32,
    pub pid_sample0: u64,
    pub pid_sample1: u64,
}

static mut SYSCALL_TRACE: SyscallTraceSummary = SyscallTraceSummary {
    vm_ptr: 0,
    nr: 0,
    arg0: 0,
    arg1: 0,
    arg2: 0,
    arg3: 0,
    arg4: 0,
    arg5: 0,
    result: 0,
    status: 0,
    pid_sample0: 0,
    pid_sample1: 0,
};
const SYSCALL_TRACE_CAP: usize = 256;
static mut SYSCALL_TRACE_RING: [SyscallTraceSummary; SYSCALL_TRACE_CAP] = [SyscallTraceSummary {
    vm_ptr: 0,
    nr: 0,
    arg0: 0,
    arg1: 0,
    arg2: 0,
    arg3: 0,
    arg4: 0,
    arg5: 0,
    result: 0,
    status: 0,
    pid_sample0: 0,
    pid_sample1: 0,
}; SYSCALL_TRACE_CAP];
static mut SYSCALL_TRACE_RING_LEN: u32 = 0;
static mut SYSCALL_TRACE_RING_NEXT: u32 = 0;
const SYSCALL_PROFILE_SLOTS: usize = 512;
static mut SYSCALL_PROFILE_COUNTS: [u64; SYSCALL_PROFILE_SLOTS] = [0; SYSCALL_PROFILE_SLOTS];
static mut SYSCALL_PROFILE_NON_OK_STATUS_COUNTS: [u64; SYSCALL_PROFILE_SLOTS] =
    [0; SYSCALL_PROFILE_SLOTS];
static mut SYSCALL_PROFILE_ERROR_COUNTS: [u64; SYSCALL_PROFILE_SLOTS] = [0; SYSCALL_PROFILE_SLOTS];

const RISCV_SYSCALL_TRACE_CAP: usize = 64;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RiscvSyscallTraceEntry {
    pub vm_ptr: u32,
    pub nr: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub result: i64,
    pub status: i32,
}

static mut RISCV_SYSCALL_TRACE: [RiscvSyscallTraceEntry; RISCV_SYSCALL_TRACE_CAP] =
    [RiscvSyscallTraceEntry {
        vm_ptr: 0,
        nr: 0,
        arg0: 0,
        arg1: 0,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
        result: 0,
        status: 0,
    }; RISCV_SYSCALL_TRACE_CAP];
static mut RISCV_SYSCALL_TRACE_LEN: u32 = 0;
static mut RISCV_SYSCALL_TRACE_NEXT: u32 = 0;

const FUTEX_TRACE_CAP: usize = 128;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FutexTraceEntry {
    pub vm_ptr: u32,
    pub tid: i32,
    pub op: u32,
    pub addr: u64,
    pub addr2: u64,
    pub val: u64,
    pub val3: u64,
    pub current: u32,
    pub local: u32,
    pub external: u32,
    pub requeued: u32,
    pub result: i64,
    pub status: i32,
}

static mut FUTEX_TRACE: [FutexTraceEntry; FUTEX_TRACE_CAP] = [FutexTraceEntry {
    vm_ptr: 0,
    tid: 0,
    op: 0,
    addr: 0,
    addr2: 0,
    val: 0,
    val3: 0,
    current: 0,
    local: 0,
    external: 0,
    requeued: 0,
    result: 0,
    status: 0,
}; FUTEX_TRACE_CAP];
static mut FUTEX_TRACE_LEN: u32 = 0;
static mut FUTEX_TRACE_NEXT: u32 = 0;

const SYNC_EFFECT_PIPE_STATE: u32 = 1 << 0;
const SYNC_EFFECT_SOCKET_STATE: u32 = 1 << 1;
const SYNC_EFFECT_EPOLL_STATE: u32 = 1 << 2;
const SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE: u32 = 1 << 3;
const SYNC_EFFECT_PROCESS_LIFECYCLE: u32 = 1 << 4;
const SYNC_EFFECT_SIGNAL_WAITERS: u32 = 1 << 5;
const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;

static mut COMPLETED_SYNC_EFFECTS: u32 = 0;

#[cfg(any(test, feature = "harness"))]
pub(crate) fn clear_syscall_trace() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SYSCALL_TRACE),
            SyscallTraceSummary {
                vm_ptr: 0,
                nr: 0,
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
                result: 0,
                status: 0,
                pid_sample0: 0,
                pid_sample1: 0,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(SYSCALL_TRACE_RING),
            [SyscallTraceSummary {
                vm_ptr: 0,
                nr: 0,
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
                result: 0,
                status: 0,
                pid_sample0: 0,
                pid_sample1: 0,
            }; SYSCALL_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(SYSCALL_TRACE_RING_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(SYSCALL_TRACE_RING_NEXT), 0);
        core::ptr::write(core::ptr::addr_of_mut!(COMPLETED_SYNC_EFFECTS), 0);
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn clear_futex_trace() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(FUTEX_TRACE),
            [FutexTraceEntry {
                vm_ptr: 0,
                tid: 0,
                op: 0,
                addr: 0,
                addr2: 0,
                val: 0,
                val3: 0,
                current: 0,
                local: 0,
                external: 0,
                requeued: 0,
                result: 0,
                status: 0,
            }; FUTEX_TRACE_CAP],
        );
        core::ptr::write(core::ptr::addr_of_mut!(FUTEX_TRACE_LEN), 0);
        core::ptr::write(core::ptr::addr_of_mut!(FUTEX_TRACE_NEXT), 0);
    }
}

#[cfg(any(test, feature = "harness"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_futex_trace(
    vm_ptr: u32,
    tid: i32,
    op: u32,
    addr: u64,
    addr2: u64,
    val: u64,
    val3: u64,
    current: u32,
    local: u32,
    external: u32,
    requeued: u32,
    result: i64,
    status: i32,
) {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        let next = core::ptr::read(core::ptr::addr_of!(FUTEX_TRACE_NEXT)) as usize;
        core::ptr::write(
            core::ptr::addr_of_mut!(FUTEX_TRACE[next]),
            FutexTraceEntry {
                vm_ptr,
                tid,
                op,
                addr,
                addr2,
                val,
                val3,
                current,
                local,
                external,
                requeued,
                result,
                status,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(FUTEX_TRACE_NEXT),
            ((next + 1) % FUTEX_TRACE_CAP) as u32,
        );
        let len = core::ptr::read(core::ptr::addr_of!(FUTEX_TRACE_LEN));
        if len < FUTEX_TRACE_CAP as u32 {
            core::ptr::write(core::ptr::addr_of_mut!(FUTEX_TRACE_LEN), len + 1);
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn futex_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(FUTEX_TRACE_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn futex_trace_entry(index: u32) -> FutexTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return FutexTraceEntry {
            vm_ptr: 0,
            tid: 0,
            op: 0,
            addr: 0,
            addr2: 0,
            val: 0,
            val3: 0,
            current: 0,
            local: 0,
            external: 0,
            requeued: 0,
            result: 0,
            status: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(FUTEX_TRACE_LEN));
        if index >= len {
            return FutexTraceEntry {
                vm_ptr: 0,
                tid: 0,
                op: 0,
                addr: 0,
                addr2: 0,
                val: 0,
                val3: 0,
                current: 0,
                local: 0,
                external: 0,
                requeued: 0,
                result: 0,
                status: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(FUTEX_TRACE_NEXT)) as usize;
        let len_usize = len as usize;
        let slot = if len_usize < FUTEX_TRACE_CAP {
            index as usize
        } else {
            (next + index as usize) % FUTEX_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(FUTEX_TRACE[slot]))
    }
}

pub(crate) fn record_syscall(
    vm_ptr: u32,
    nr: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    result: i64,
    status: i32,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (
            vm_ptr, nr, arg0, arg1, arg2, arg3, arg4, arg5, result, status,
        );
        return;
    }
    let (pid_sample0, pid_sample1) = sample_process_pid_bytes(vm_ptr);
    unsafe {
        if (nr as usize) < SYSCALL_PROFILE_SLOTS {
            let slot = nr as usize;
            let count_ptr = core::ptr::addr_of_mut!(SYSCALL_PROFILE_COUNTS[slot]);
            core::ptr::write(count_ptr, core::ptr::read(count_ptr).wrapping_add(1));
            if status != crate::abi::STATUS_OK {
                let status_ptr =
                    core::ptr::addr_of_mut!(SYSCALL_PROFILE_NON_OK_STATUS_COUNTS[slot]);
                core::ptr::write(status_ptr, core::ptr::read(status_ptr).wrapping_add(1));
            }
            if result < 0 {
                let error_ptr = core::ptr::addr_of_mut!(SYSCALL_PROFILE_ERROR_COUNTS[slot]);
                core::ptr::write(error_ptr, core::ptr::read(error_ptr).wrapping_add(1));
            }
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(SYSCALL_TRACE),
            SyscallTraceSummary {
                vm_ptr,
                nr,
                arg0,
                arg1,
                arg2,
                arg3,
                arg4,
                arg5,
                result,
                status,
                pid_sample0,
                pid_sample1,
            },
        );
        let next = core::ptr::read(core::ptr::addr_of!(SYSCALL_TRACE_RING_NEXT)) as usize;
        core::ptr::write(
            core::ptr::addr_of_mut!(SYSCALL_TRACE_RING[next]),
            SyscallTraceSummary {
                vm_ptr,
                nr,
                arg0,
                arg1,
                arg2,
                arg3,
                arg4,
                arg5,
                result,
                status,
                pid_sample0,
                pid_sample1,
            },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(SYSCALL_TRACE_RING_NEXT),
            ((next + 1) % SYSCALL_TRACE_CAP) as u32,
        );
        let len = core::ptr::read(core::ptr::addr_of!(SYSCALL_TRACE_RING_LEN));
        if len < SYSCALL_TRACE_CAP as u32 {
            core::ptr::write(core::ptr::addr_of_mut!(SYSCALL_TRACE_RING_LEN), len + 1);
        }
        if nr == crate::abi::SYS_RISCV_HWPROBE || nr == crate::abi::SYS_RISCV_FLUSH_ICACHE {
            let riscv_next =
                core::ptr::read(core::ptr::addr_of!(RISCV_SYSCALL_TRACE_NEXT)) as usize;
            core::ptr::write(
                core::ptr::addr_of_mut!(RISCV_SYSCALL_TRACE[riscv_next]),
                RiscvSyscallTraceEntry {
                    vm_ptr,
                    nr,
                    arg0,
                    arg1,
                    arg2,
                    arg3,
                    arg4,
                    arg5,
                    result,
                    status,
                },
            );
            core::ptr::write(
                core::ptr::addr_of_mut!(RISCV_SYSCALL_TRACE_NEXT),
                ((riscv_next + 1) % RISCV_SYSCALL_TRACE_CAP) as u32,
            );
            let riscv_len = core::ptr::read(core::ptr::addr_of!(RISCV_SYSCALL_TRACE_LEN));
            if riscv_len < RISCV_SYSCALL_TRACE_CAP as u32 {
                core::ptr::write(
                    core::ptr::addr_of_mut!(RISCV_SYSCALL_TRACE_LEN),
                    riscv_len + 1,
                );
            }
        }
        if status == crate::abi::STATUS_OK {
            let effects = match nr {
                crate::abi::SYS_READ
                | crate::abi::SYS_WRITE
                | crate::abi::SYS_LSEEK
                | crate::abi::SYS_READV
                | crate::abi::SYS_WRITEV
                | crate::abi::SYS_CLOSE
                | crate::abi::SYS_CLOSE_RANGE
                | crate::abi::SYS_DUP
                | crate::abi::SYS_DUP3
                | crate::abi::SYS_FCNTL
                | crate::abi::SYS_IOCTL => {
                    SYNC_EFFECT_PIPE_STATE
                        | SYNC_EFFECT_SOCKET_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_PIPE2 => {
                    SYNC_EFFECT_PIPE_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_SOCKET
                | crate::abi::SYS_SOCKETPAIR
                | crate::abi::SYS_BIND
                | crate::abi::SYS_LISTEN
                | crate::abi::SYS_CONNECT
                | crate::abi::SYS_ACCEPT4
                | crate::abi::SYS_SENDTO
                | crate::abi::SYS_RECVFROM
                | crate::abi::SYS_SETSOCKOPT
                | crate::abi::SYS_SHUTDOWN => {
                    SYNC_EFFECT_SOCKET_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_EVENTFD2 => {
                    SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_EPOLL_CREATE1 => {
                    SYNC_EFFECT_EPOLL_STATE | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_EPOLL_CTL => SYNC_EFFECT_EPOLL_STATE,
                crate::abi::SYS_EXECVE | crate::abi::SYS_EXECVEAT => {
                    SYNC_EFFECT_PIPE_STATE
                        | SYNC_EFFECT_SOCKET_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                        | SYNC_EFFECT_PROCESS_LIFECYCLE
                }
                crate::abi::SYS_SETPGID | crate::abi::SYS_SETSID => SYNC_EFFECT_PROCESS_LIFECYCLE,
                crate::abi::SYS_KILL | crate::abi::SYS_TKILL | crate::abi::SYS_TGKILL => {
                    SYNC_EFFECT_SIGNAL_WAITERS
                }
                _ => 0,
            };
            let current = core::ptr::read(core::ptr::addr_of!(COMPLETED_SYNC_EFFECTS));
            core::ptr::write(
                core::ptr::addr_of_mut!(COMPLETED_SYNC_EFFECTS),
                current | effects,
            );
        }
    }
}

pub(super) fn sample_process_pid_bytes(vm_ptr: u32) -> (u64, u64) {
    if vm_ptr == 0 {
        return (0, 0);
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if vm.process_ptr == 0 {
        return (0, 0);
    }
    let pid_addr = vm.guest_base as usize
        + vm.process_ptr as usize
        + core::mem::offset_of!(crate::types::ProcessState, pid);
    let sample0 = unsafe { core::ptr::read_unaligned(pid_addr as *const u64) };
    let sample1 = unsafe { core::ptr::read_unaligned((pid_addr + 8) as *const u64) };
    (sample0, sample1)
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn completed_sync_effects() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(COMPLETED_SYNC_EFFECTS)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn syscall_trace_summary() -> SyscallTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return SyscallTraceSummary {
            vm_ptr: 0,
            nr: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            result: 0,
            status: 0,
            pid_sample0: 0,
            pid_sample1: 0,
        };
    }
    unsafe { *core::ptr::addr_of!(SYSCALL_TRACE) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn syscall_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(SYSCALL_TRACE_RING_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn syscall_trace_entry(index: u32) -> SyscallTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return SyscallTraceSummary {
            vm_ptr: 0,
            nr: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            result: 0,
            status: 0,
            pid_sample0: 0,
            pid_sample1: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(SYSCALL_TRACE_RING_LEN));
        if index >= len {
            return SyscallTraceSummary {
                vm_ptr: 0,
                nr: 0,
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
                result: 0,
                status: 0,
                pid_sample0: 0,
                pid_sample1: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(SYSCALL_TRACE_RING_NEXT)) as usize;
        let len_usize = len as usize;
        let slot = if len_usize < SYSCALL_TRACE_CAP {
            index as usize
        } else {
            (next + index as usize) % SYSCALL_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(SYSCALL_TRACE_RING[slot]))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn syscall_profile_slot_count(nr: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED || nr as usize >= SYSCALL_PROFILE_SLOTS {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(SYSCALL_PROFILE_COUNTS[nr as usize])) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn syscall_profile_slot_non_ok_status_count(nr: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED || nr as usize >= SYSCALL_PROFILE_SLOTS {
        return 0;
    }
    unsafe {
        core::ptr::read(core::ptr::addr_of!(
            SYSCALL_PROFILE_NON_OK_STATUS_COUNTS[nr as usize]
        ))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn syscall_profile_slot_error_count(nr: u32) -> u64 {
    if !RUNTIME_DEBUG_ENABLED || nr as usize >= SYSCALL_PROFILE_SLOTS {
        return 0;
    }
    unsafe {
        core::ptr::read(core::ptr::addr_of!(
            SYSCALL_PROFILE_ERROR_COUNTS[nr as usize]
        ))
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn riscv_syscall_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(RISCV_SYSCALL_TRACE_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn riscv_syscall_trace_entry(index: u32) -> RiscvSyscallTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return RiscvSyscallTraceEntry {
            vm_ptr: 0,
            nr: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            result: 0,
            status: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(RISCV_SYSCALL_TRACE_LEN));
        if index >= len {
            return RiscvSyscallTraceEntry {
                vm_ptr: 0,
                nr: 0,
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
                result: 0,
                status: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(RISCV_SYSCALL_TRACE_NEXT)) as usize;
        let len_usize = len as usize;
        let slot = if len_usize < RISCV_SYSCALL_TRACE_CAP {
            index as usize
        } else {
            (next + index as usize) % RISCV_SYSCALL_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(RISCV_SYSCALL_TRACE[slot]))
    }
}

static mut LAST_EXECVE_STAGE: u32 = 0;
static mut LAST_EXECVE_VALUE0: u64 = 0;
static mut LAST_EXECVE_VALUE1: u64 = 0;
static mut LAST_EXECVE_ERROR_ERRNO: i64 = 0;
static mut LAST_EXECVE_ERROR_STAGE: u32 = 0;
static mut LAST_EXECVE_ERROR_VALUE0: u64 = 0;
static mut LAST_EXECVE_ERROR_VALUE1: u64 = 0;
const EXECVE_STAGE_TRACE_CAP: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveStageTraceEntry {
    pub stage: u32,
    pub value0: u64,
    pub value1: u64,
}

static mut EXECVE_STAGE_TRACE: [ExecveStageTraceEntry; EXECVE_STAGE_TRACE_CAP] =
    [ExecveStageTraceEntry {
        stage: 0,
        value0: 0,
        value1: 0,
    }; EXECVE_STAGE_TRACE_CAP];
static mut EXECVE_STAGE_TRACE_LEN: u32 = 0;
static mut EXECVE_STAGE_TRACE_NEXT: u32 = 0;

pub(crate) fn record_execve_stage(stage: u32, value0: u64, value1: u64) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (stage, value0, value1);
        return;
    }
    unsafe {
        if stage == 0 {
            core::ptr::write(core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE_LEN), 0);
            core::ptr::write(core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE_NEXT), 0);
        }
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_STAGE), stage);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_VALUE0), value0);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_VALUE1), value1);
        let len = core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_LEN)) as usize;
        let next = core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_NEXT)) as usize;
        let slot = if len < EXECVE_STAGE_TRACE_CAP {
            len
        } else {
            next
        };
        core::ptr::write(
            core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE[slot]),
            ExecveStageTraceEntry {
                stage,
                value0,
                value1,
            },
        );
        if len < EXECVE_STAGE_TRACE_CAP {
            core::ptr::write(
                core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE_LEN),
                (len + 1) as u32,
            );
        } else {
            core::ptr::write(
                core::ptr::addr_of_mut!(EXECVE_STAGE_TRACE_NEXT),
                ((next + 1) % EXECVE_STAGE_TRACE_CAP) as u32,
            );
        }
    }
}

pub(super) fn current_execve_stage() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_STAGE)) }
}

pub(crate) fn record_execve_error(errno: i64) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = errno;
        return;
    }
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_ERROR_ERRNO), errno);
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_EXECVE_ERROR_STAGE),
            core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_STAGE)),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_EXECVE_ERROR_VALUE0),
            core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE0)),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(LAST_EXECVE_ERROR_VALUE1),
            core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE1)),
        );
    }
}

pub(crate) fn record_execve_approach(vm_ptr: u32, pc: u64, raw: u32) {
    let _ = (vm_ptr, pc, raw);
}

pub(crate) fn record_execve_dispatch(vm_ptr: u32, stage: u32) {
    let _ = (vm_ptr, stage);
}

pub(crate) fn record_execve_ecall(value0: u64, value1: u64) {
    let _ = (value0, value1);
}

pub(crate) fn record_execve_pre_dispatch(pc: u64, raw: u32, value0: u64, value1: u64) {
    let _ = (pc, raw, value0, value1);
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_stage() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_STAGE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_value0() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE0)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_value1() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE1)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_error_errno() -> i64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_ERROR_ERRNO)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_error_stage() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_ERROR_STAGE)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_error_value0() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_ERROR_VALUE0)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_error_value1() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_ERROR_VALUE1)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_stage_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn execve_stage_trace_entry(index: u32) -> ExecveStageTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        return ExecveStageTraceEntry {
            stage: 0,
            value0: 0,
            value1: 0,
        };
    }
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_LEN));
        if index >= len {
            return ExecveStageTraceEntry {
                stage: 0,
                value0: 0,
                value1: 0,
            };
        }
        let next = core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE_NEXT)) as usize;
        let len_usize = len as usize;
        let slot = if len_usize < EXECVE_STAGE_TRACE_CAP {
            index as usize
        } else {
            (next + index as usize) % EXECVE_STAGE_TRACE_CAP
        };
        core::ptr::read(core::ptr::addr_of!(EXECVE_STAGE_TRACE[slot]))
    }
}
