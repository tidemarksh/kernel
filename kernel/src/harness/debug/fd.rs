use super::{RUNTIME_DEBUG_ENABLED, sample_process_pid_bytes};

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
    pub pid_sample0: u64,
    pub pid_sample1: u64,
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
    pid_sample0: 0,
    pid_sample1: 0,
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_fd_syscall(
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
        crate::abi::SYS_READ
            | crate::abi::SYS_PREAD64
            | crate::abi::SYS_READV
            | crate::abi::SYS_WRITE
            | crate::abi::SYS_PWRITE64
            | crate::abi::SYS_WRITEV
            | crate::abi::SYS_PWRITEV
            | crate::abi::SYS_LSEEK
            | crate::abi::SYS_EPOLL_CREATE1
            | crate::abi::SYS_EPOLL_CTL
            | crate::abi::SYS_EPOLL_PWAIT
            | crate::abi::SYS_CLOSE
            | crate::abi::SYS_CLOSE_RANGE
            | crate::abi::SYS_DUP
            | crate::abi::SYS_DUP3
            | crate::abi::SYS_PIPE2
            | crate::abi::SYS_FCNTL
            | crate::abi::SYS_IOCTL
            | crate::abi::SYS_SOCKET
            | crate::abi::SYS_SOCKETPAIR
            | crate::abi::SYS_BIND
            | crate::abi::SYS_LISTEN
            | crate::abi::SYS_CONNECT
            | crate::abi::SYS_ACCEPT4
            | crate::abi::SYS_SENDTO
            | crate::abi::SYS_RECVFROM
            | crate::abi::SYS_SENDMSG
            | crate::abi::SYS_RECVMSG
            | crate::abi::SYS_SHUTDOWN
            | crate::abi::SYS_SETSOCKOPT
            | crate::abi::SYS_GETSOCKOPT
            | crate::abi::SYS_GETSOCKNAME
            | crate::abi::SYS_GETPEERNAME
            | crate::abi::SYS_PPOLL
            | crate::abi::SYS_PSELECT6
    );
    if !should_record {
        return;
    }

    let (pid_sample0, pid_sample1) = sample_process_pid_bytes(vm_ptr);
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
            pid_sample0,
            pid_sample1,
        };
        FD_SYSCALL_TRACE_NEXT = ((idx + 1) % FD_SYSCALL_TRACE_CAP) as u32;
        if FD_SYSCALL_TRACE_LEN < FD_SYSCALL_TRACE_CAP as u32 {
            FD_SYSCALL_TRACE_LEN += 1;
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn fd_syscall_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { FD_SYSCALL_TRACE_LEN }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn fd_syscall_trace_entry(index: u32) -> FdSyscallTraceEntry {
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
            pid_sample0: 0,
            pid_sample1: 0,
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
                pid_sample0: 0,
                pid_sample1: 0,
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

pub(crate) fn record_path_syscall(
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
            | crate::abi::SYS_EXECVE
            | crate::abi::SYS_EXECVEAT
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_write_attempt(
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
}

pub(crate) fn record_pipe_close_event(
    pipe_idx: u32,
    is_read_end: bool,
    ofd_id: u32,
    read_open: i32,
    write_open: i32,
) {
    let _ = (pipe_idx, is_read_end, ofd_id, read_open, write_open);
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn path_syscall_trace_len() -> u32 {
    if !RUNTIME_DEBUG_ENABLED {
        return 0;
    }
    unsafe { PATH_SYSCALL_TRACE_LEN }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn path_syscall_trace_entry(index: u32) -> PathSyscallTraceEntry {
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
pub(crate) fn path_syscall_trace_path_ptr(index: u32) -> u32 {
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
