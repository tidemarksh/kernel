#[repr(C)]
#[derive(Clone, Copy)]
pub struct WriteTraceSummary {
    pub write_calls: u32,
    pub writev_calls: u32,
    pub last_fd: u64,
    pub last_nr: u64,
    pub last_buf_addr: u64,
    pub last_count: u64,
    pub last_result: i64,
    pub last_ofd_id: u32,
    pub last_ofd_type: i32,
    pub last_ofd_ino: u32,
    pub last_status_flags: i32,
    pub last_pipe_read_open: i32,
    pub last_pipe_write_open: i32,
}

const RUNTIME_DEBUG_ENABLED: bool = cfg!(any(test, feature = "harness"));

static mut WRITE_TRACE: WriteTraceSummary = WriteTraceSummary {
    write_calls: 0,
    writev_calls: 0,
    last_fd: 0,
    last_nr: 0,
    last_buf_addr: 0,
    last_count: 0,
    last_result: 0,
    last_ofd_id: 0,
    last_ofd_type: 0,
    last_ofd_ino: 0,
    last_status_flags: 0,
    last_pipe_read_open: 0,
    last_pipe_write_open: 0,
};
static mut LAST_WRITE_BYTES: [u8; 64] = [0; 64];
static mut LAST_WRITE_BYTES_LEN: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallTraceSummary {
    pub vm_ptr: u32,
    pub nr: u64,
    pub result: i64,
    pub status: i32,
}

static mut SYSCALL_TRACE: SyscallTraceSummary = SyscallTraceSummary {
    vm_ptr: 0,
    nr: 0,
    result: 0,
    status: 0,
};

const FD_SYSCALL_TRACE_CAP: usize = 1024;
const PATH_SYSCALL_TRACE_CAP: usize = 128;
const PATH_SYSCALL_TRACE_BYTES: usize = 192;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdSyscallTraceEntry {
    pub vm_ptr: u32,
    pub nr: u64,
    pub arg0: u64,
    pub arg0_ofd_id: u32,
    pub arg0_ofd_type: i32,
    pub arg1: u64,
    pub arg2: u64,
    pub arg2_ofd_id: u32,
    pub arg2_ofd_type: i32,
    pub arg3: u64,
    pub result: i64,
    pub status: i32,
}

static mut FD_SYSCALL_TRACE: [FdSyscallTraceEntry; FD_SYSCALL_TRACE_CAP] = [FdSyscallTraceEntry {
    vm_ptr: 0,
    nr: 0,
    arg0: 0,
    arg0_ofd_id: 0,
    arg0_ofd_type: 0,
    arg1: 0,
    arg2: 0,
    arg2_ofd_id: 0,
    arg2_ofd_type: 0,
    arg3: 0,
    result: 0,
    status: 0,
}; FD_SYSCALL_TRACE_CAP];
static mut FD_SYSCALL_TRACE_LEN: u32 = 0;
static mut FD_SYSCALL_TRACE_NEXT: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathSyscallTraceEntry {
    pub vm_ptr: u32,
    pub nr: u64,
    pub dirfd: i64,
    pub result: i64,
    pub status: i32,
    pub path_len: u32,
    pub path: [u8; PATH_SYSCALL_TRACE_BYTES],
}

static mut PATH_SYSCALL_TRACE: [PathSyscallTraceEntry; PATH_SYSCALL_TRACE_CAP] =
    [PathSyscallTraceEntry {
        vm_ptr: 0,
        nr: 0,
        dirfd: 0,
        result: 0,
        status: 0,
        path_len: 0,
        path: [0; PATH_SYSCALL_TRACE_BYTES],
    }; PATH_SYSCALL_TRACE_CAP];
static mut PATH_SYSCALL_TRACE_LEN: u32 = 0;
static mut PATH_SYSCALL_TRACE_NEXT: u32 = 0;

const SYNC_EFFECT_PIPE_STATE: u32 = 1 << 0;
const SYNC_EFFECT_SOCKET_STATE: u32 = 1 << 1;
const SYNC_EFFECT_EPOLL_STATE: u32 = 1 << 2;
const SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE: u32 = 1 << 3;
const SYNC_EFFECT_PROCESS_LIFECYCLE: u32 = 1 << 4;
const SYNC_EFFECT_SIGNAL_WAITERS: u32 = 1 << 5;
const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;

static mut COMPLETED_SYNC_EFFECTS: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryTraceSummary {
    pub nr: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub result: i64,
}

static mut MEMORY_TRACE: MemoryTraceSummary = MemoryTraceSummary {
    nr: 0,
    arg0: 0,
    arg1: 0,
    arg2: 0,
    arg3: 0,
    result: 0,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpollWaitTraceSummary {
    pub vm_ptr: u32,
    pub epfd: u64,
    pub ofd_id: u32,
    pub ofd_type: i32,
    pub epoll_idx: u32,
    pub epoll_ptr: u32,
    pub epoll_count: u32,
    pub result: i64,
    pub reason: u32,
}

static mut EPOLL_WAIT_TRACE: EpollWaitTraceSummary = EpollWaitTraceSummary {
    vm_ptr: 0,
    epfd: 0,
    ofd_id: 0,
    ofd_type: 0,
    epoll_idx: 0,
    epoll_ptr: 0,
    epoll_count: 0,
    result: 0,
    reason: 0,
};

static mut LAST_EXECVE_STAGE: u32 = 0;
static mut LAST_EXECVE_VALUE0: u64 = 0;
static mut LAST_EXECVE_VALUE1: u64 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PipeCloseTraceSummary {
    pub pipe_idx: u32,
    pub is_read_end: u32,
    pub ofd_id: u32,
    pub read_open: i32,
    pub write_open: i32,
}

static mut PIPE_CLOSE_TRACE: PipeCloseTraceSummary = PipeCloseTraceSummary {
    pipe_idx: 0,
    is_read_end: 0,
    ofd_id: 0,
    read_open: 0,
    write_open: 0,
};

const THREAD_COUNT_TRACE_CAP: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadCountTraceEntry {
    pub kind: u32,
    pub vm_ptr: u32,
    pub tid: i32,
    pub process_ptr: u32,
    pub before: u32,
    pub after: u32,
}

static mut THREAD_COUNT_TRACE: [ThreadCountTraceEntry; THREAD_COUNT_TRACE_CAP] =
    [ThreadCountTraceEntry {
        kind: 0,
        vm_ptr: 0,
        tid: 0,
        process_ptr: 0,
        before: 0,
        after: 0,
    }; THREAD_COUNT_TRACE_CAP];
static mut THREAD_COUNT_TRACE_LEN: u32 = 0;
static mut THREAD_COUNT_TRACE_NEXT: u32 = 0;

#[cfg(any(test, feature = "harness"))]
pub fn clear_write_trace() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(WRITE_TRACE),
            WriteTraceSummary {
                write_calls: 0,
                writev_calls: 0,
                last_fd: 0,
                last_nr: 0,
                last_buf_addr: 0,
                last_count: 0,
                last_result: 0,
                last_ofd_id: 0,
                last_ofd_type: 0,
                last_ofd_ino: 0,
                last_status_flags: 0,
                last_pipe_read_open: 0,
                last_pipe_write_open: 0,
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(LAST_WRITE_BYTES), [0; 64]);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_WRITE_BYTES_LEN), 0);
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn clear_syscall_trace() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SYSCALL_TRACE),
            SyscallTraceSummary {
                vm_ptr: 0,
                nr: 0,
                result: 0,
                status: 0,
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(COMPLETED_SYNC_EFFECTS), 0);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn record_epoll_wait(
    vm_ptr: u32,
    epfd: u64,
    ofd_id: u32,
    ofd_type: i32,
    epoll_idx: u32,
    epoll_ptr: u32,
    epoll_count: u32,
    result: i64,
    reason: u32,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (
            vm_ptr,
            epfd,
            ofd_id,
            ofd_type,
            epoll_idx,
            epoll_ptr,
            epoll_count,
            result,
            reason,
        );
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(EPOLL_WAIT_TRACE),
            EpollWaitTraceSummary {
                vm_ptr,
                epfd,
                ofd_id,
                ofd_type,
                epoll_idx,
                epoll_ptr,
                epoll_count,
                result,
                reason,
            },
        );
    }
}

pub fn record_thread_count(
    kind: u32,
    vm_ptr: u32,
    tid: i32,
    process_ptr: u32,
    before: u32,
    after: u32,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (kind, vm_ptr, tid, process_ptr, before, after);
        return;
    }
    unsafe {
        let idx = (THREAD_COUNT_TRACE_NEXT as usize) % THREAD_COUNT_TRACE_CAP;
        THREAD_COUNT_TRACE[idx] = ThreadCountTraceEntry {
            kind,
            vm_ptr,
            tid,
            process_ptr,
            before,
            after,
        };
        THREAD_COUNT_TRACE_NEXT = ((idx + 1) % THREAD_COUNT_TRACE_CAP) as u32;
        if THREAD_COUNT_TRACE_LEN < THREAD_COUNT_TRACE_CAP as u32 {
            THREAD_COUNT_TRACE_LEN += 1;
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn thread_count_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { THREAD_COUNT_TRACE_LEN }
}

#[cfg(any(test, feature = "harness"))]
pub fn thread_count_trace_entry(index: u32) -> ThreadCountTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = index;
        return ThreadCountTraceEntry {
            kind: 0,
            vm_ptr: 0,
            tid: 0,
            process_ptr: 0,
            before: 0,
            after: 0,
        };
    }
    unsafe {
        let len = THREAD_COUNT_TRACE_LEN.min(THREAD_COUNT_TRACE_CAP as u32);
        if index >= len {
            return ThreadCountTraceEntry {
                kind: 0,
                vm_ptr: 0,
                tid: 0,
                process_ptr: 0,
                before: 0,
                after: 0,
            };
        }
        let start = if THREAD_COUNT_TRACE_LEN >= THREAD_COUNT_TRACE_CAP as u32 {
            THREAD_COUNT_TRACE_NEXT as usize
        } else {
            0
        };
        THREAD_COUNT_TRACE[(start + index as usize) % THREAD_COUNT_TRACE_CAP]
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn epoll_wait_trace() -> EpollWaitTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return EpollWaitTraceSummary {
            vm_ptr: 0,
            epfd: 0,
            ofd_id: 0,
            ofd_type: 0,
            epoll_idx: 0,
            epoll_ptr: 0,
            epoll_count: 0,
            result: 0,
            reason: 0,
        };
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(EPOLL_WAIT_TRACE)) }
}

#[cfg(any(test, feature = "harness"))]
pub fn clear_memory_trace() {
    if !RUNTIME_DEBUG_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(MEMORY_TRACE),
            MemoryTraceSummary {
                nr: 0,
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                result: 0,
            },
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub fn record_write_attempt(
    fd: u64,
    nr: u64,
    buf_addr: u64,
    count: u64,
    result: i64,
    ofd_id: u32,
    ofd_type: i32,
    ofd_ino: u32,
    status_flags: i32,
    pipe_read_open: i32,
    pipe_write_open: i32,
    bytes: Option<&[u8]>,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (
            fd,
            nr,
            buf_addr,
            count,
            result,
            ofd_id,
            ofd_type,
            ofd_ino,
            status_flags,
            pipe_read_open,
            pipe_write_open,
            bytes,
        );
        return;
    }
    unsafe {
        let trace = &mut *core::ptr::addr_of_mut!(WRITE_TRACE);
        if nr == crate::abi::SYS_WRITEV {
            trace.writev_calls = trace.writev_calls.saturating_add(1);
        } else {
            trace.write_calls = trace.write_calls.saturating_add(1);
        }
        trace.last_fd = fd;
        trace.last_nr = nr;
        trace.last_buf_addr = buf_addr;
        trace.last_count = count;
        trace.last_result = result;
        trace.last_ofd_id = ofd_id;
        trace.last_ofd_type = ofd_type;
        trace.last_ofd_ino = ofd_ino;
        trace.last_status_flags = status_flags;
        trace.last_pipe_read_open = pipe_read_open;
        trace.last_pipe_write_open = pipe_write_open;

        let mut snapshot = [0u8; 64];
        let snapshot_len = bytes.map_or(0, |bytes| {
            let len = bytes.len().min(snapshot.len());
            snapshot[..len].copy_from_slice(&bytes[..len]);
            len as u32
        });
        core::ptr::write(core::ptr::addr_of_mut!(LAST_WRITE_BYTES), snapshot);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_WRITE_BYTES_LEN), snapshot_len);
    }
}

pub fn record_pipe_close_event(
    pipe_idx: u32,
    is_read_end: bool,
    ofd_id: u32,
    read_open: i32,
    write_open: i32,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (pipe_idx, is_read_end, ofd_id, read_open, write_open);
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PIPE_CLOSE_TRACE),
            PipeCloseTraceSummary {
                pipe_idx,
                is_read_end: if is_read_end { 1 } else { 0 },
                ofd_id,
                read_open,
                write_open,
            },
        );
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn pipe_close_trace_summary() -> PipeCloseTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return PipeCloseTraceSummary {
            pipe_idx: 0,
            is_read_end: 0,
            ofd_id: 0,
            read_open: 0,
            write_open: 0,
        };
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(PIPE_CLOSE_TRACE)) }
}

pub fn record_syscall(vm_ptr: u32, nr: u64, result: i64, status: i32) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm_ptr, nr, result, status);
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(SYSCALL_TRACE),
            SyscallTraceSummary {
                vm_ptr,
                nr,
                result,
                status,
            },
        );
        if status == crate::abi::STATUS_OK {
            let effects = match nr {
                crate::abi::SYS_READ
                | crate::abi::SYS_WRITE
                | crate::abi::SYS_LSEEK
                | crate::abi::SYS_READV
                | crate::abi::SYS_WRITEV
                | crate::abi::SYS_CLOSE
                | crate::abi::SYS_DUP
                | crate::abi::SYS_DUP3
                | crate::abi::SYS_FCNTL => {
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
                | crate::abi::SYS_BIND
                | crate::abi::SYS_LISTEN
                | crate::abi::SYS_ACCEPT4 => {
                    SYNC_EFFECT_SOCKET_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_EVENTFD2 => {
                    SYNC_EFFECT_EPOLL_DEPENDENT_OFD_STATE
                        | SYNC_EFFECT_EPOLL_STATE
                        | SYNC_EFFECT_FORK_SHARED_OFD_STATE
                }
                crate::abi::SYS_EPOLL_CTL => SYNC_EFFECT_EPOLL_STATE,
                crate::abi::SYS_EXECVE | crate::abi::SYS_SETPGID | crate::abi::SYS_SETSID => {
                    SYNC_EFFECT_PROCESS_LIFECYCLE
                }
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

#[allow(clippy::too_many_arguments)]
pub fn record_fd_syscall(
    vm_ptr: u32,
    nr: u64,
    arg0: u64,
    arg0_ofd_id: u32,
    arg0_ofd_type: i32,
    arg1: u64,
    arg2: u64,
    arg2_ofd_id: u32,
    arg2_ofd_type: i32,
    arg3: u64,
    result: i64,
    status: i32,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (
            vm_ptr,
            nr,
            arg0,
            arg0_ofd_id,
            arg0_ofd_type,
            arg1,
            arg2,
            arg2_ofd_id,
            arg2_ofd_type,
            arg3,
            result,
            status,
        );
        return;
    }
    let should_record = matches!(
        nr,
        crate::abi::SYS_EPOLL_CREATE1
            | crate::abi::SYS_EPOLL_CTL
            | crate::abi::SYS_EPOLL_PWAIT
            | crate::abi::SYS_CLOSE
            | crate::abi::SYS_DUP
            | crate::abi::SYS_DUP3
            | crate::abi::SYS_PIPE2
            | crate::abi::SYS_FCNTL
    );
    if !should_record {
        return;
    }

    unsafe {
        let idx = (FD_SYSCALL_TRACE_NEXT as usize) % FD_SYSCALL_TRACE_CAP;
        FD_SYSCALL_TRACE[idx] = FdSyscallTraceEntry {
            vm_ptr,
            nr,
            arg0,
            arg0_ofd_id,
            arg0_ofd_type,
            arg1,
            arg2,
            arg2_ofd_id,
            arg2_ofd_type,
            arg3,
            result,
            status,
        };
        FD_SYSCALL_TRACE_NEXT = ((idx + 1) % FD_SYSCALL_TRACE_CAP) as u32;
        if FD_SYSCALL_TRACE_LEN < FD_SYSCALL_TRACE_CAP as u32 {
            FD_SYSCALL_TRACE_LEN += 1;
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn fd_syscall_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { FD_SYSCALL_TRACE_LEN }
}

#[cfg(any(test, feature = "harness"))]
pub fn fd_syscall_trace_entry(index: u32) -> FdSyscallTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = index;
        return FdSyscallTraceEntry {
            vm_ptr: 0,
            nr: 0,
            arg0: 0,
            arg0_ofd_id: 0,
            arg0_ofd_type: 0,
            arg1: 0,
            arg2: 0,
            arg2_ofd_id: 0,
            arg2_ofd_type: 0,
            arg3: 0,
            result: 0,
            status: 0,
        };
    }
    unsafe {
        let len = FD_SYSCALL_TRACE_LEN.min(FD_SYSCALL_TRACE_CAP as u32);
        if index >= len {
            return FdSyscallTraceEntry {
                vm_ptr: 0,
                nr: 0,
                arg0: 0,
                arg0_ofd_id: 0,
                arg0_ofd_type: 0,
                arg1: 0,
                arg2: 0,
                arg2_ofd_id: 0,
                arg2_ofd_type: 0,
                arg3: 0,
                result: 0,
                status: 0,
            };
        }
        let start = if len < FD_SYSCALL_TRACE_CAP as u32 {
            0
        } else {
            FD_SYSCALL_TRACE_NEXT % FD_SYSCALL_TRACE_CAP as u32
        };
        let idx = ((start + index) as usize) % FD_SYSCALL_TRACE_CAP;
        FD_SYSCALL_TRACE[idx]
    }
}

pub fn record_path_syscall(
    vm_ptr: u32,
    nr: u64,
    dirfd: i64,
    path: &[u8],
    result: i64,
    status: i32,
) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (vm_ptr, nr, dirfd, path, result, status);
        return;
    }
    let should_record = matches!(
        nr,
        crate::abi::SYS_OPENAT
            | crate::abi::SYS_NEWFSTATAT
            | crate::abi::SYS_FACCESSAT
            | crate::abi::SYS_READLINKAT
    );
    if !should_record {
        return;
    }

    unsafe {
        let idx = (PATH_SYSCALL_TRACE_NEXT as usize) % PATH_SYSCALL_TRACE_CAP;
        let mut path_copy = [0u8; PATH_SYSCALL_TRACE_BYTES];
        let path_len = path.len().min(PATH_SYSCALL_TRACE_BYTES);
        path_copy[..path_len].copy_from_slice(&path[..path_len]);
        PATH_SYSCALL_TRACE[idx] = PathSyscallTraceEntry {
            vm_ptr,
            nr,
            dirfd,
            result,
            status,
            path_len: path_len as u32,
            path: path_copy,
        };
        PATH_SYSCALL_TRACE_NEXT = ((idx + 1) % PATH_SYSCALL_TRACE_CAP) as u32;
        if PATH_SYSCALL_TRACE_LEN < PATH_SYSCALL_TRACE_CAP as u32 {
            PATH_SYSCALL_TRACE_LEN += 1;
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn path_syscall_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { PATH_SYSCALL_TRACE_LEN }
}

#[cfg(any(test, feature = "harness"))]
pub fn path_syscall_trace_entry(index: u32) -> PathSyscallTraceEntry {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = index;
        return PathSyscallTraceEntry {
            vm_ptr: 0,
            nr: 0,
            dirfd: 0,
            result: 0,
            status: 0,
            path_len: 0,
            path: [0; PATH_SYSCALL_TRACE_BYTES],
        };
    }
    unsafe {
        let len = PATH_SYSCALL_TRACE_LEN.min(PATH_SYSCALL_TRACE_CAP as u32);
        if index >= len {
            return PathSyscallTraceEntry {
                vm_ptr: 0,
                nr: 0,
                dirfd: 0,
                result: 0,
                status: 0,
                path_len: 0,
                path: [0; PATH_SYSCALL_TRACE_BYTES],
            };
        }
        let start = if len < PATH_SYSCALL_TRACE_CAP as u32 {
            0
        } else {
            PATH_SYSCALL_TRACE_NEXT % PATH_SYSCALL_TRACE_CAP as u32
        };
        let idx = ((start + index) as usize) % PATH_SYSCALL_TRACE_CAP;
        PATH_SYSCALL_TRACE[idx]
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn path_syscall_trace_path_ptr(index: u32) -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = index;
        return 0;
    }
    unsafe {
        let len = PATH_SYSCALL_TRACE_LEN.min(PATH_SYSCALL_TRACE_CAP as u32);
        if index >= len {
            return 0;
        }
        let start = if len < PATH_SYSCALL_TRACE_CAP as u32 {
            0
        } else {
            PATH_SYSCALL_TRACE_NEXT % PATH_SYSCALL_TRACE_CAP as u32
        };
        let idx = ((start + index) as usize) % PATH_SYSCALL_TRACE_CAP;
        core::ptr::addr_of!(PATH_SYSCALL_TRACE[idx].path) as u32
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn completed_sync_effects() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(COMPLETED_SYNC_EFFECTS)) }
}

pub fn record_memory_syscall(nr: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, result: i64) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (nr, arg0, arg1, arg2, arg3, result);
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(MEMORY_TRACE),
            MemoryTraceSummary {
                nr,
                arg0,
                arg1,
                arg2,
                arg3,
                result,
            },
        );
    }
}

pub fn record_execve_stage(stage: u32, value0: u64, value1: u64) {
    if !RUNTIME_DEBUG_ENABLED {
        let _ = (stage, value0, value1);
        return;
    }
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_STAGE), stage);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_VALUE0), value0);
        core::ptr::write(core::ptr::addr_of_mut!(LAST_EXECVE_VALUE1), value1);
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn write_trace_summary() -> WriteTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return WriteTraceSummary {
            write_calls: 0,
            writev_calls: 0,
            last_fd: 0,
            last_nr: 0,
            last_buf_addr: 0,
            last_count: 0,
            last_result: 0,
            last_ofd_id: 0,
            last_ofd_type: 0,
            last_ofd_ino: 0,
            last_status_flags: 0,
            last_pipe_read_open: 0,
            last_pipe_write_open: 0,
        };
    }
    unsafe { *core::ptr::addr_of!(WRITE_TRACE) }
}

#[cfg(any(test, feature = "harness"))]
pub fn write_trace_ptr() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    core::ptr::addr_of!(LAST_WRITE_BYTES) as u32
}

#[cfg(any(test, feature = "harness"))]
pub fn write_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_WRITE_BYTES_LEN)) }
}

#[cfg(any(test, feature = "harness"))]
pub fn syscall_trace_summary() -> SyscallTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return SyscallTraceSummary {
            vm_ptr: 0,
            nr: 0,
            result: 0,
            status: 0,
        };
    }
    unsafe { *core::ptr::addr_of!(SYSCALL_TRACE) }
}

#[cfg(any(test, feature = "harness"))]
pub fn memory_trace_summary() -> MemoryTraceSummary {
    if !RUNTIME_DEBUG_ENABLED {
        return MemoryTraceSummary {
            nr: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            result: 0,
        };
    }
    unsafe { *core::ptr::addr_of!(MEMORY_TRACE) }
}

#[cfg(any(test, feature = "harness"))]
pub fn execve_stage() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_STAGE)) }
}

#[cfg(any(test, feature = "harness"))]
pub fn execve_value0() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE0)) }
}

#[cfg(any(test, feature = "harness"))]
pub fn execve_value1() -> u64 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(LAST_EXECVE_VALUE1)) }
}
