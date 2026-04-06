//! Syscall dispatch and shared helpers.
//!
//! RISC-V Linux syscall ABI: a7 (x17) = syscall number,
//! a0-a5 (x10-x15) = arguments, a0 (x10) = return value.

pub mod epoll;
pub mod fs;
pub mod identity;
pub mod memory;
pub mod pipe;
pub mod process;
pub mod resource;
pub mod signal;
pub mod socket;
pub mod thread;
pub mod time;

use crate::abi;
use crate::abi::*;
use crate::fs::fd_table;
use crate::types::ThreadState;

#[inline(always)]
fn debug_return(vm: &ThreadState, nr: u64, result: i64, status: i32) -> i32 {
    crate::harness_hooks::record_syscall(vm as *const ThreadState as u32, nr, result, status);
    status
}

#[inline(always)]
fn record_memory_trace(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, result: i64) {
    match nr {
        SYS_BRK | SYS_MMAP | SYS_MUNMAP | SYS_MSYNC | SYS_MREMAP | SYS_MPROTECT => {
            crate::harness_hooks::record_memory_syscall(nr, a0, a1, a2, a3, result);
        }
        _ => {}
    }
}

#[inline(always)]
fn trace_fd_snapshot(base: u32, vm: &ThreadState, fd: u64) -> (u32, i32) {
    let Some(ofd_id) = fd_table::get_ofd_id(base, vm, fd) else {
        return (0, 0);
    };
    let ofd_type = fd_table::get_ofd(base, vm, fd)
        .map(|ofd| ofd.fd_type)
        .unwrap_or(0);
    (ofd_id, ofd_type)
}

/// Dispatch a syscall. Called from ECALL handler in cpu::exec.
/// Returns STATUS_OK if the syscall completed synchronously,
/// or a blocking STATUS (STATUS_FS, STATUS_SLEEP, etc.) if JS must wait.
pub fn dispatch(vm: &mut ThreadState, base: u32) -> i32 {
    let nr = vm.x[17]; // a7 = syscall number
    let a0 = vm.x[10];
    let a1 = vm.x[11];
    let a2 = vm.x[12];
    let a3 = vm.x[13];
    let a4 = vm.x[14];
    let a5 = vm.x[15];
    let (arg0_ofd_id, arg0_ofd_type) = trace_fd_snapshot(base, vm, a0);
    let (arg2_ofd_id, arg2_ofd_type) = trace_fd_snapshot(base, vm, a2);
    let result: i64 = match nr {
        // identity
        SYS_GETPID => identity::sys_getpid(vm, base),
        SYS_GETPPID => identity::sys_getppid(vm, base),
        SYS_GETTID => identity::sys_gettid(vm),
        SYS_GETUID => identity::sys_getuid(vm),
        SYS_GETEUID => identity::sys_geteuid(vm),
        SYS_GETGID => identity::sys_getgid(vm),
        SYS_GETEGID => identity::sys_getegid(vm),
        SYS_GETRESUID => identity::sys_getresuid(vm, base, a0, a1, a2),
        SYS_GETRESGID => identity::sys_getresgid(vm, base, a0, a1, a2),
        SYS_SETUID => identity::sys_setuid(vm, a0 as i64),
        SYS_SETGID => identity::sys_setgid(vm, a0 as i64),
        SYS_SETREUID => identity::sys_setreuid(vm, a0 as i64, a1 as i64),
        SYS_SETREGID => identity::sys_setregid(vm, a0 as i64, a1 as i64),
        SYS_SETRESUID => identity::sys_setresuid(vm, a0 as i64, a1 as i64, a2 as i64),
        SYS_SETRESGID => identity::sys_setresgid(vm, a0 as i64, a1 as i64, a2 as i64),
        SYS_UNAME => identity::sys_uname(vm, base, a0),
        SYS_SYSINFO => identity::sys_sysinfo(vm, base, a0),
        SYS_GETRANDOM => identity::sys_getrandom(vm, base, a0, a1, a2),

        // time
        SYS_CLOCK_GETTIME => time::sys_clock_gettime(vm, base, a0, a1),
        SYS_GETITIMER => time::sys_getitimer(vm, base, a0, a1),
        SYS_SETITIMER => time::sys_setitimer(vm, base, a0, a1, a2),
        114 => time::sys_clock_getres(vm, base, a0, a1), // clock_getres
        SYS_NANOSLEEP => {
            let status = time::sys_nanosleep(vm, base, a0, a1);
            return debug_return(vm, nr, vm.x[10] as i64, status);
        }
        SYS_SCHED_GETAFFINITY => time::sys_sched_getaffinity(vm, base, a0 as i64, a1, a2),
        SYS_SCHED_YIELD => {
            let ret = time::sys_sched_yield(vm);
            if vm.status == abi::STATUS_SLEEP {
                return debug_return(vm, nr, ret as i64, abi::STATUS_SLEEP);
            }
            ret as i64
        }
        SYS_TIMES => 0, // stub: return 0 clock ticks

        // memory
        SYS_BRK => memory::sys_brk(vm, base, a0),
        SYS_MMAP => memory::sys_mmap(vm, base, a0, a1, a2, a3, a4 as i64, vm.x[15]),
        SYS_MUNMAP => memory::sys_munmap(vm, base, a0, a1),
        SYS_MSYNC => memory::sys_msync(vm, base, a0, a1, a2),
        SYS_MREMAP => memory::sys_mremap(vm, base, a0, a1, a2, a3, a4),
        SYS_MPROTECT => memory::sys_mprotect(vm, base, a0, a1, a2),
        SYS_MADVISE => 0, // no-op, return success

        // signal
        SYS_RT_SIGACTION => signal::sys_rt_sigaction(vm, base, a0, a1, a2, a3),
        SYS_RT_SIGPROCMASK => signal::sys_rt_sigprocmask(vm, base, a0, a1, a2, a3),
        SYS_RT_SIGPENDING => signal::sys_rt_sigpending(vm, base, a0, a1),
        SYS_SIGALTSTACK => signal::sys_sigaltstack(vm, base, a0, a1),
        SYS_RT_SIGRETURN => {
            signal::sys_rt_sigreturn(vm, base);
            0
        }

        // filesystem
        SYS_OPENAT => {
            let r = fs::dispatch_openat(vm, base, a0, a1, a2, a3);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            r
        }
        SYS_READ => {
            let r = fs::sys_read(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_PIPE_WAIT {
                return debug_return(vm, nr, r, abi::STATUS_PIPE_WAIT);
            }
            if vm.status == abi::STATUS_SOCKET_RECV {
                return debug_return(vm, nr, r, abi::STATUS_SOCKET_RECV);
            }
            r
        }
        SYS_PREAD64 => fs::sys_pread64(vm, base, a0, a1, a2, a3),
        SYS_WRITE | SYS_WRITEV => {
            let r = fs::dispatch_write(vm, base, a0, a1, a2, nr);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            if vm.status == abi::STATUS_PIPE_WAIT {
                return debug_return(vm, nr, r, abi::STATUS_PIPE_WAIT);
            }
            if vm.status == abi::STATUS_SOCKET_SEND {
                return debug_return(vm, nr, r, abi::STATUS_SOCKET_SEND);
            }
            r
        }
        SYS_PWRITE64 => {
            let r = fs::dispatch_pwrite64(vm, base, a0, a1, a2, a3);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            r
        }
        SYS_READV => 0, // TODO
        SYS_NEWFSTATAT => fs::sys_newfstatat(vm, base, a0, a1, a2, a3),
        SYS_FSTAT => {
            let r = fs::dispatch_fstat(vm, base, a0, a1);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            r
        }
        SYS_LSEEK => {
            let r = fs::dispatch_lseek(vm, base, a0, a1 as i64, a2);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            r
        }
        SYS_GETDENTS64 => {
            let r = fs::dispatch_getdents64(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            r
        }
        SYS_MKDIRAT => {
            let r = fs::dispatch_mkdirat(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            r
        }
        SYS_UNLINKAT => {
            let r = fs::dispatch_unlinkat(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            r
        }
        SYS_STATFS => fs::sys_statfs(vm, base, a0, a1),
        SYS_FACCESSAT => fs::sys_faccessat(vm, base, a0, a1, a2),
        SYS_CHDIR => fs::sys_chdir(vm, base, a0),
        SYS_FCHMODAT => fs::sys_fchmodat(vm, base, a0, a1, a2, a3),
        SYS_FCHOWNAT => fs::sys_fchownat(vm, base, a0, a1, a2, a3, a4),
        SYS_READLINKAT => fs::sys_readlinkat(vm, base, a0, a1, a2, a3),
        SYS_TRUNCATE => {
            let r = fs::dispatch_truncate(vm, base, a0, a1);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            r
        }
        SYS_FTRUNCATE => {
            let r = fs::dispatch_ftruncate(vm, base, a0, a1);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, r, abi::STATUS_FS);
            }
            r
        }
        SYS_IOCTL => 0,
        SYS_GETCWD => fs::sys_getcwd(vm, base, a0, a1),

        // fd table
        SYS_DUP => fd_table::sys_dup(vm, base, a0),
        SYS_DUP3 => fd_table::sys_dup3(vm, base, a0, a1, a2),
        SYS_FCNTL => fd_table::sys_fcntl(vm, base, a0, a1, a2),
        SYS_FLOCK => {
            let r = fd_table::sys_flock(vm, base, a0, a1);
            if vm.status == abi::STATUS_FLOCK_WAIT {
                return debug_return(vm, nr, r, abi::STATUS_FLOCK_WAIT);
            }
            r
        }
        SYS_CLOSE => fd_table::sys_close(vm, base, a0),

        // pipe
        SYS_PIPE2 => pipe::sys_pipe2(vm, base, a0, a1),

        // socket
        SYS_SOCKET => socket::sys_socket(vm, base, a0, a1, a2),
        SYS_BIND => socket::sys_bind(vm, base, a0, a1, a2),
        SYS_LISTEN => socket::sys_listen(vm, base, a0, a1),
        SYS_CONNECT => {
            let r = socket::sys_connect(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_CONNECT {
                return debug_return(vm, nr, r, abi::STATUS_CONNECT);
            }
            r
        }
        SYS_ACCEPT4 => {
            let r = socket::sys_accept4(vm, base, a0, a1, a2, a3);
            if vm.status == abi::STATUS_SOCKET_RECV {
                return debug_return(vm, nr, r, abi::STATUS_SOCKET_RECV);
            }
            r
        }
        SYS_SENDTO => {
            let r = socket::sys_sendto(vm, base, a0, a1, a2, a3, a4, a5);
            if vm.status == abi::STATUS_SOCKET_SEND {
                return debug_return(vm, nr, r, abi::STATUS_SOCKET_SEND);
            }
            r
        }
        SYS_RECVFROM => {
            let r = socket::sys_recvfrom(vm, base, a0, a1, a2, a3, a4, a5);
            if vm.status == abi::STATUS_SOCKET_RECV {
                return debug_return(vm, nr, r, abi::STATUS_SOCKET_RECV);
            }
            r
        }
        SYS_SETSOCKOPT => socket::sys_setsockopt(vm, base, a0, a1, a2, a3, a4),
        SYS_GETSOCKOPT => socket::sys_getsockopt(vm, base, a0, a1, a2, a3, a4),
        SYS_GETSOCKNAME => socket::sys_getsockname(vm, base, a0, a1, a2),
        SYS_GETPEERNAME => socket::sys_getpeername(vm, base, a0, a1, a2),

        // epoll
        SYS_EPOLL_CREATE1 => epoll::sys_epoll_create1(vm, base, a0),
        SYS_EPOLL_CTL => epoll::sys_epoll_ctl(vm, base, a0, a1, a2, a3),
        SYS_EPOLL_PWAIT => {
            let r = epoll::sys_epoll_pwait(vm, base, a0, a1, a2, a3 as i64, a4);
            if vm.status == abi::STATUS_EPOLL_WAIT {
                return debug_return(vm, nr, r, abi::STATUS_EPOLL_WAIT);
            }
            r
        }
        SYS_EVENTFD2 => pipe::sys_eventfd2(vm, base, a0, a1),

        // signal delivery
        SYS_KILL => signal::send_signal_to_pid(vm, base, a0 as i32, a1 as i32),
        SYS_TKILL | SYS_TGKILL => {
            let self_pid = signal::pid_from_vm(vm, base);
            let target_pid = if nr == SYS_TGKILL {
                a0 as i32
            } else {
                self_pid
            };
            let target_tid = if nr == SYS_TGKILL {
                a1 as i32
            } else {
                a0 as i32
            };
            let sig = if nr == SYS_TGKILL {
                a2 as i32
            } else {
                a1 as i32
            };
            if target_pid != self_pid {
                ESRCH
            } else {
                signal::send_signal_to_tid(vm, base, target_tid, sig)
            }
        }

        // thread lifecycle
        SYS_SET_TID_ADDRESS => thread::sys_set_tid_address(vm, a0),
        SYS_SET_ROBUST_LIST => thread::sys_set_robust_list(vm, a0, a1),
        SYS_SETPGID => process::sys_setpgid(vm, base, a0 as i64, a1 as i64),
        SYS_GETPGID => process::sys_getpgid(vm, base, a0 as i64),
        SYS_SETSID => process::sys_setsid(vm, base),
        SYS_CLONE => {
            // Dispatch based on clone flags:
            // CLONE_VFORK → vfork (process.rs)
            // CLONE_VM | CLONE_THREAD → new thread (thread.rs)
            // neither → plain fork (process.rs)
            if a0 & CLONE_VFORK != 0 {
                let status = process::sys_vfork(vm, base);
                return debug_return(vm, nr, vm.x[10] as i64, status);
            } else if a0 & CLONE_VM != 0 && a0 & CLONE_THREAD != 0 {
                let ret = thread::sys_clone(vm, base, a0, a1, a2, a3, a4);
                if vm.status == abi::STATUS_CLONE_SPAWN {
                    return debug_return(vm, nr, ret, abi::STATUS_CLONE_SPAWN);
                }
                ret
            } else {
                let ret = process::sys_fork(vm, base, a0, a1, a2, a3, a4);
                if vm.status == abi::STATUS_EXECVE_SPAWN {
                    return debug_return(vm, nr, ret, abi::STATUS_EXECVE_SPAWN);
                }
                ret
            }
        }
        SYS_EXECVE => {
            let ret = process::sys_execve(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_EXECVE_SPAWN {
                return debug_return(vm, nr, ret, abi::STATUS_EXECVE_SPAWN);
            }
            ret
        }
        SYS_WAIT4 => {
            let ret = process::sys_wait4(vm, base, a0 as i64, a1, a2, a3);
            if vm.status == abi::STATUS_WAIT4 {
                return debug_return(vm, nr, ret, abi::STATUS_WAIT4);
            }
            ret
        }
        SYS_WAITID => {
            let ret = process::sys_waitid(vm, base, a0 as u32, a1 as i64, a2, a3, a4);
            if vm.status == abi::STATUS_WAIT4 {
                return debug_return(vm, nr, ret, abi::STATUS_WAIT4);
            }
            ret
        }
        SYS_FUTEX | SYS_FUTEX_TIME64 => {
            let ret = thread::sys_futex(vm, base, a0, a1, a2, a3, a4, vm.x[15]);
            if vm.status == abi::STATUS_FUTEX_WAIT {
                return debug_return(vm, nr, ret, abi::STATUS_FUTEX_WAIT);
            }
            ret
        }
        SYS_EXIT => {
            let status = thread::sys_exit(vm, base, a0);
            return debug_return(vm, nr, vm.exit_code as i64, status);
        }
        SYS_EXIT_GROUP => {
            let status = thread::sys_exit_group(vm, base, a0);
            return debug_return(vm, nr, vm.exit_code as i64, status);
        }
        SYS_GETRLIMIT => resource::sys_getrlimit(vm, base, a0, a1),
        SYS_SETRLIMIT => resource::sys_setrlimit(vm, base, a0, a1),
        SYS_PRCTL => 0,
        SYS_UMASK => 0o022, // return previous umask
        SYS_RISCV_HWPROBE => identity::sys_riscv_hwprobe(vm, base, a0, a1, a2, a3, a4),
        SYS_RSEQ => EINVAL,
        SYS_PRLIMIT64 => resource::sys_prlimit64(vm, base, a0 as i32, a1, a2, a3),

        // not yet implemented
        _ => ENOSYS,
    };

    record_memory_trace(nr, a0, a1, a2, a3, result);
    if nr != SYS_RT_SIGRETURN {
        vm.x[10] = result as u64;
    }

    // Check and deliver pending signals at syscall return boundary
    signal::check_pending(vm, base);
    let status = vm.status;
    crate::harness_hooks::record_fd_syscall(
        vm as *const ThreadState as u32,
        nr,
        a0,
        arg0_ofd_id,
        arg0_ofd_type,
        a1,
        a2,
        arg2_ofd_id,
        arg2_ofd_type,
        a3,
        result,
        status,
    );
    crate::harness_hooks::record_syscall(vm as *const ThreadState as u32, nr, result, status);
    if status != abi::STATUS_OK {
        return status;
    }
    abi::STATUS_OK
}
