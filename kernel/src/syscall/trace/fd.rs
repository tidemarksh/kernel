#[cfg(not(any(test, feature = "harness")))]
use crate::abi::*;
use crate::fs::fd_table;
use crate::types::ThreadState;

#[inline(always)]
pub(in crate::syscall) fn snapshot(base: u32, vm: &ThreadState, fd: u64) -> (u32, i32) {
    let Some(ofd_id) = fd_table::get_ofd_id(base, vm, fd) else {
        return (0, 0);
    };
    let ofd_type = fd_table::get_ofd(base, vm, fd)
        .map(|ofd| ofd.fd_type)
        .unwrap_or(0);
    (ofd_id, ofd_type)
}

#[cfg(not(any(test, feature = "harness")))]
#[derive(Clone, Copy)]
pub(crate) struct FdSyscallTraceEntry {
    pub vm_ptr: u32,
    pub nr: u64,
    pub arg0: u64,
    pub arg0_ofd_id: u32,
    pub arg0_ofd_type: i32,
    pub arg0_ofd_offset: i64,
    pub arg0_ofd_host_fd: i32,
    pub arg0_ofd_status_flags: i32,
    pub arg0_ofd_ino: u32,
    pub arg0_inode_mode: u32,
    pub arg0_pipe_generation: u32,
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

#[cfg(not(any(test, feature = "harness")))]
#[derive(Clone, Copy)]
pub(crate) struct PathSyscallTraceEntry {
    pub vm_ptr: u32,
    pub nr: u64,
    pub dirfd: i64,
    pub result: i64,
    pub status: i32,
    pub path_len: u32,
    pub path: [u8; PATH_SYSCALL_TRACE_BYTES],
}

#[cfg(not(any(test, feature = "harness")))]
const FD_SYSCALL_TRACE_CAP: usize = 1024;

#[cfg(not(any(test, feature = "harness")))]
const PATH_SYSCALL_TRACE_CAP: usize = 256;

#[cfg(not(any(test, feature = "harness")))]
const PATH_SYSCALL_TRACE_BYTES: usize = 224;

#[cfg(not(any(test, feature = "harness")))]
static mut FD_SYSCALL_TRACE: [FdSyscallTraceEntry; FD_SYSCALL_TRACE_CAP] = [FdSyscallTraceEntry {
    vm_ptr: 0,
    nr: 0,
    arg0: 0,
    arg0_ofd_id: 0,
    arg0_ofd_type: 0,
    arg0_ofd_offset: 0,
    arg0_ofd_host_fd: 0,
    arg0_ofd_status_flags: 0,
    arg0_ofd_ino: 0,
    arg0_inode_mode: 0,
    arg0_pipe_generation: 0,
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

#[cfg(not(any(test, feature = "harness")))]
static mut FD_SYSCALL_TRACE_LEN: u32 = 0;

#[cfg(not(any(test, feature = "harness")))]
static mut FD_SYSCALL_TRACE_NEXT: u32 = 0;

#[cfg(not(any(test, feature = "harness")))]
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

#[cfg(not(any(test, feature = "harness")))]
static mut PATH_SYSCALL_TRACE_LEN: u32 = 0;

#[cfg(not(any(test, feature = "harness")))]
static mut PATH_SYSCALL_TRACE_NEXT: u32 = 0;

#[cfg(not(any(test, feature = "harness")))]
fn sample_process_pid_bytes(vm_ptr: u32) -> (u64, u64) {
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

#[cfg(not(any(test, feature = "harness")))]
#[allow(clippy::too_many_arguments)]
pub(in crate::syscall) fn record(
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
    let should_record = matches!(
        nr,
        SYS_READ
            | SYS_PREAD64
            | SYS_READV
            | SYS_WRITE
            | SYS_PWRITE64
            | SYS_WRITEV
            | SYS_PWRITEV
            | SYS_LSEEK
            | SYS_EVENTFD2
            | SYS_EPOLL_CREATE1
            | SYS_EPOLL_CTL
            | SYS_EPOLL_PWAIT
            | SYS_CLOSE
            | SYS_CLOSE_RANGE
            | SYS_DUP
            | SYS_DUP3
            | SYS_PIPE2
            | SYS_FCNTL
            | SYS_IOCTL
            | SYS_SOCKET
            | SYS_SOCKETPAIR
            | SYS_BIND
            | SYS_LISTEN
            | SYS_CONNECT
            | SYS_ACCEPT4
            | SYS_SENDTO
            | SYS_RECVFROM
            | SYS_SENDMSG
            | SYS_RECVMSG
            | SYS_SHUTDOWN
            | SYS_SETSOCKOPT
            | SYS_GETSOCKOPT
            | SYS_GETSOCKNAME
            | SYS_GETPEERNAME
            | SYS_FACCESSAT
            | SYS_NEWFSTATAT
            | SYS_READLINKAT
            | SYS_EXECVE
            | SYS_EXECVEAT
    );
    if !should_record {
        return;
    }
    let (pid_sample0, pid_sample1) = sample_process_pid_bytes(vm_ptr);
    let (
        arg0_ofd_offset,
        arg0_ofd_host_fd,
        arg0_ofd_status_flags,
        arg0_ofd_ino,
        arg0_inode_mode,
        arg0_pipe_generation,
    ) = fd_table::get_ofd_by_id(arg0_ofd_id)
        .map(|ofd| {
            let pipe_generation = if ofd.fd_type == FD_TYPE_PIPE {
                crate::syscall::pipe::pipe_generation(ofd.ino)
            } else {
                0
            };
            let inode_mode = if ofd.fd_type == FD_TYPE_FILE {
                crate::fs::memfs::stat(ofd.ino).map_or(0, |stat| stat.mode)
            } else {
                0
            };
            (
                ofd.offset,
                ofd.host_fd,
                ofd.status_flags,
                ofd.ino,
                inode_mode,
                pipe_generation,
            )
        })
        .unwrap_or((0, 0, 0, 0, 0, 0));
    unsafe {
        let idx = (FD_SYSCALL_TRACE_NEXT as usize) % FD_SYSCALL_TRACE_CAP;
        FD_SYSCALL_TRACE[idx] = FdSyscallTraceEntry {
            vm_ptr,
            nr,
            arg0,
            arg0_ofd_id,
            arg0_ofd_type,
            arg0_ofd_offset,
            arg0_ofd_host_fd,
            arg0_ofd_status_flags,
            arg0_ofd_ino,
            arg0_inode_mode,
            arg0_pipe_generation,
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

#[cfg(not(any(test, feature = "harness")))]
fn empty_entry() -> FdSyscallTraceEntry {
    FdSyscallTraceEntry {
        vm_ptr: 0,
        nr: 0,
        arg0: 0,
        arg0_ofd_id: 0,
        arg0_ofd_type: 0,
        arg0_ofd_offset: 0,
        arg0_ofd_host_fd: 0,
        arg0_ofd_status_flags: 0,
        arg0_ofd_ino: 0,
        arg0_inode_mode: 0,
        arg0_pipe_generation: 0,
        arg1: 0,
        arg2: 0,
        arg2_ofd_id: 0,
        arg2_ofd_type: 0,
        arg3: 0,
        result: 0,
        status: 0,
        pid_sample0: 0,
        pid_sample1: 0,
    }
}

#[cfg(not(any(test, feature = "harness")))]
pub(crate) fn len() -> u32 {
    unsafe { FD_SYSCALL_TRACE_LEN }
}

#[cfg(not(any(test, feature = "harness")))]
pub(crate) fn entry(index: u32) -> FdSyscallTraceEntry {
    unsafe {
        let len = FD_SYSCALL_TRACE_LEN.min(FD_SYSCALL_TRACE_CAP as u32);
        if index >= len {
            return empty_entry();
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

#[cfg(not(any(test, feature = "harness")))]
fn empty_path_entry() -> PathSyscallTraceEntry {
    PathSyscallTraceEntry {
        vm_ptr: 0,
        nr: 0,
        dirfd: 0,
        result: 0,
        status: 0,
        path_len: 0,
        path: [0; PATH_SYSCALL_TRACE_BYTES],
    }
}

#[cfg(not(any(test, feature = "harness")))]
#[allow(dead_code)]
pub(crate) fn record_path_syscall(
    vm_ptr: u32,
    nr: u64,
    dirfd: i64,
    path: &[u8],
    result: i64,
    status: i32,
) {
    let should_record = matches!(
        nr,
        SYS_OPENAT | SYS_NEWFSTATAT | SYS_FACCESSAT | SYS_READLINKAT | SYS_EXECVE | SYS_EXECVEAT
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

#[cfg(not(any(test, feature = "harness")))]
pub(crate) fn path_len() -> u32 {
    unsafe { PATH_SYSCALL_TRACE_LEN }
}

#[cfg(not(any(test, feature = "harness")))]
pub(crate) fn path_entry(index: u32) -> PathSyscallTraceEntry {
    unsafe {
        let len = PATH_SYSCALL_TRACE_LEN.min(PATH_SYSCALL_TRACE_CAP as u32);
        if index >= len {
            return empty_path_entry();
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

#[cfg(not(any(test, feature = "harness")))]
pub(crate) fn path_ptr(index: u32) -> u32 {
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
