//! Syscall dispatch and shared helpers.
//!
//! RISC-V Linux syscall ABI: a7 (x17) = syscall number,
//! a0-a5 (x10-x15) = arguments, a0 (x10) = return value.

pub mod epoll;
pub mod fs;
pub mod identity;
pub mod memory;
pub mod pipe;
pub mod poll;
pub mod process;
pub mod pty;
pub mod resource;
pub mod signal;
pub mod socket;
mod sync_effects;
pub mod thread;
pub mod time;
pub(crate) mod trace;

use crate::abi;
use crate::abi::*;
use crate::fs::fd_table;
use crate::types::ThreadState;
use trace::debug_return::{debug_return, debug_return_fd_arg0, save_blocked_syscall_args};

/// Dispatch a syscall. Called from ECALL handler in cpu::exec.
/// Returns STATUS_OK if the syscall completed synchronously,
/// or a blocking STATUS (STATUS_FS, STATUS_SLEEP, etc.) if JS must wait.
pub fn dispatch(vm: &mut ThreadState, base: u32) -> i32 {
    let nr = vm.x[17]; // a7 = syscall number
    if nr == SYS_EXECVE || nr == SYS_EXECVEAT {
        crate::tracepoints::record_execve_dispatch(vm as *const ThreadState as u32, 1);
    }
    let a0 = vm.x[10];
    let a1 = vm.x[11];
    let a2 = vm.x[12];
    let a3 = vm.x[13];
    let a4 = vm.x[14];
    let a5 = vm.x[15];
    let (mut arg0_ofd_id, mut arg0_ofd_type) = trace::fd::snapshot(base, vm, a0);
    let (mut arg2_ofd_id, mut arg2_ofd_type) = trace::fd::snapshot(base, vm, a2);
    vm.status = abi::STATUS_OK;
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
        SYS_GETGROUPS => identity::sys_getgroups(base, a0 as i64, a1),
        SYS_SETGROUPS => identity::sys_setgroups(vm, a0 as i64, a1),
        SYS_UNAME => identity::sys_uname(vm, base, a0),
        SYS_SYSINFO => identity::sys_sysinfo(vm, base, a0),
        SYS_GETRANDOM => identity::sys_getrandom(vm, base, a0, a1, a2),

        // async I/O
        SYS_IO_SETUP | SYS_IO_SUBMIT | SYS_IO_CANCEL | SYS_IO_GETEVENTS => ENOSYS,
        SYS_IO_DESTROY => EINVAL,

        // time
        SYS_CLOCK_GETTIME => time::sys_clock_gettime(vm, base, a0, a1),
        SYS_GETCPU => time::sys_getcpu(vm, base, a0, a1, a2),
        SYS_GETITIMER => time::sys_getitimer(vm, base, a0, a1),
        SYS_SETITIMER => time::sys_setitimer(vm, base, a0, a1, a2),
        SYS_TIMERFD_CREATE => time::sys_timerfd_create(vm, base, a0, a1),
        SYS_TIMERFD_SETTIME => time::sys_timerfd_settime(vm, base, a0, a1, a2, a3),
        SYS_TIMERFD_GETTIME => time::sys_timerfd_gettime(vm, base, a0, a1),
        114 => time::sys_clock_getres(vm, base, a0, a1), // clock_getres
        SYS_CLOCK_NANOSLEEP => {
            let status = time::sys_clock_nanosleep(vm, base, a0, a1, a2, a3);
            return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, vm.x[10] as i64, status);
        }
        SYS_NANOSLEEP => {
            let status = time::sys_nanosleep(vm, base, a0, a1);
            return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, vm.x[10] as i64, status);
        }
        SYS_SCHED_GETAFFINITY => time::sys_sched_getaffinity(vm, base, a0 as i64, a1, a2),
        SYS_SCHED_YIELD => {
            let ret = time::sys_sched_yield(vm);
            if vm.status == abi::STATUS_SLEEP {
                return debug_return(
                    vm,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    ret as i64,
                    abi::STATUS_SLEEP,
                );
            }
            ret as i64
        }
        SYS_TIMES => ENOSYS,

        // memory
        SYS_BRK => memory::sys_brk(vm, base, a0),
        SYS_MMAP => {
            let r = fs::dispatch_mmap(vm, base, a0, a1, a2, a3, a4 as i64, vm.x[15]);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_MUNMAP => memory::sys_munmap(vm, base, a0, a1),
        SYS_MSYNC => memory::sys_msync(vm, base, a0, a1, a2),
        SYS_MREMAP => memory::sys_mremap(vm, base, a0, a1, a2, a3, a4),
        SYS_MPROTECT => memory::sys_mprotect(vm, base, a0, a1, a2),
        SYS_MADVISE => memory::sys_madvise(vm, base, a0, a1, a2),

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
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_READ => {
            let r = fs::dispatch_read(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            if vm.status == abi::STATUS_PIPE_WAIT {
                save_blocked_syscall_args(vm, nr, a0, a1, a2, a3, a4, a5);
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_PIPE_WAIT,
                );
            }
            if vm.status == abi::STATUS_SOCKET_RECV {
                save_blocked_syscall_args(vm, nr, a0, a1, a2, a3, a4, a5);
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_SOCKET_RECV,
                );
            }
            r
        }
        SYS_PREAD64 => {
            let r = fs::dispatch_pread64(vm, base, a0, a1, a2, a3);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_WRITE | SYS_WRITEV => {
            let r = fs::dispatch_write(vm, base, a0, a1, a2, nr);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            if vm.status == abi::STATUS_PIPE_WAIT {
                save_blocked_syscall_args(vm, nr, a0, a1, a2, a3, a4, a5);
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_PIPE_WAIT,
                );
            }
            if vm.status == abi::STATUS_SOCKET_SEND {
                save_blocked_syscall_args(vm, nr, a0, a1, a2, a3, a4, a5);
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_SOCKET_SEND,
                );
            }
            r
        }
        SYS_PWRITE64 => {
            let r = fs::dispatch_pwrite64(vm, base, a0, a1, a2, a3);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_READV => {
            let r = fs::sys_readv(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_PIPE_WAIT {
                save_blocked_syscall_args(vm, nr, a0, a1, a2, a3, a4, a5);
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_PIPE_WAIT,
                );
            }
            if vm.status == abi::STATUS_SOCKET_RECV {
                save_blocked_syscall_args(vm, nr, a0, a1, a2, a3, a4, a5);
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_SOCKET_RECV,
                );
            }
            r
        }
        SYS_NEWFSTATAT => fs::sys_newfstatat(vm, base, a0, a1, a2, a3),
        SYS_UTIMENSAT => fs::sys_utimensat(vm, base, a0, a1, a2, a3),
        SYS_FSTAT => {
            let r = fs::dispatch_fstat(vm, base, a0, a1);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_LSEEK => {
            let r = fs::dispatch_lseek(vm, base, a0, a1 as i64, a2);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_GETDENTS64 => {
            let r = fs::dispatch_getdents64(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_MKDIRAT => {
            let r = fs::dispatch_mkdirat(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_UNLINKAT => {
            let r = fs::dispatch_unlinkat(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_RENAMEAT | SYS_RENAMEAT2 => {
            let flags = if nr == SYS_RENAMEAT { 0 } else { a4 };
            let r = fs::dispatch_renameat2(vm, base, a0, a1, a2, a3, flags);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_SETXATTR | SYS_LSETXATTR => fs::sys_setxattr(vm, base, a0),
        SYS_FSETXATTR => fs::sys_fsetxattr(vm, base, a0),
        SYS_GETXATTR | SYS_LGETXATTR => fs::sys_getxattr(vm, base, a0),
        SYS_FGETXATTR => fs::sys_fgetxattr(vm, base, a0),
        SYS_LISTXATTR | SYS_LLISTXATTR => fs::sys_listxattr(vm, base, a0),
        SYS_FLISTXATTR => fs::sys_flistxattr(vm, base, a0),
        SYS_REMOVEXATTR | SYS_LREMOVEXATTR => fs::sys_removexattr(vm, base, a0),
        SYS_FREMOVEXATTR => fs::sys_fremovexattr(vm, base, a0),
        SYS_UMOUNT2 => fs::sys_umount2(vm, base, a0, a1),
        SYS_MOUNT => fs::sys_mount(vm, base, a0, a1, a2, a3, a4),
        SYS_STATFS => fs::sys_statfs(vm, base, a0, a1),
        SYS_FACCESSAT => fs::sys_faccessat(vm, base, a0, a1, a2),
        SYS_CHDIR => fs::sys_chdir(vm, base, a0),
        SYS_CHROOT => fs::sys_chroot(vm, base, a0),
        SYS_FCHMOD => fs::sys_fchmod(vm, base, a0, a1),
        SYS_FCHMODAT => fs::sys_fchmodat(vm, base, a0, a1, a2, a3),
        SYS_FCHOWNAT => fs::sys_fchownat(vm, base, a0, a1, a2, a3, a4),
        SYS_FCHOWN => fs::sys_fchown(vm, base, a0, a1, a2),
        SYS_READLINKAT => fs::sys_readlinkat(vm, base, a0, a1, a2, a3),
        SYS_TRUNCATE => {
            let r = fs::dispatch_truncate(vm, base, a0, a1);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_FTRUNCATE => {
            let r = fs::dispatch_ftruncate(vm, base, a0, a1);
            if vm.status == abi::STATUS_FS {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_FS);
            }
            r
        }
        SYS_IOCTL => pty::sys_ioctl(vm, base, a0, a1, a2),
        SYS_SIGNALFD4 => signal::sys_signalfd4(vm, base, a0 as i64, a1, a2, a3),
        SYS_GETCWD => fs::sys_getcwd(vm, base, a0, a1),

        // fd table
        SYS_DUP => fd_table::sys_dup(vm, base, a0),
        SYS_DUP3 => fd_table::sys_dup3(vm, base, a0, a1, a2),
        SYS_FCNTL => fd_table::sys_fcntl(vm, base, a0, a1, a2),
        SYS_FLOCK => {
            let r = fd_table::sys_flock(vm, base, a0, a1);
            if vm.status == abi::STATUS_FLOCK_WAIT {
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_FLOCK_WAIT,
                );
            }
            r
        }
        SYS_CLOSE => {
            let r = fd_table::sys_close(vm, base, a0);
            if vm.status == abi::STATUS_SOCKET_SEND {
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_SOCKET_SEND,
                );
            }
            r
        }
        SYS_CLOSE_RANGE => fd_table::sys_close_range(vm, base, a0, a1, a2),

        // pipe
        SYS_PIPE2 => pipe::sys_pipe2(vm, base, a0, a1),

        // socket
        SYS_SOCKET => socket::sys_socket(vm, base, a0, a1, a2),
        SYS_SOCKETPAIR => socket::sys_socketpair(vm, base, a0, a1, a2, a3),
        SYS_BIND => socket::sys_bind(vm, base, a0, a1, a2),
        SYS_LISTEN => socket::sys_listen(vm, base, a0, a1),
        SYS_CONNECT => {
            let r = socket::sys_connect(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_CONNECT {
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_CONNECT,
                );
            }
            r
        }
        SYS_ACCEPT4 => {
            let r = socket::sys_accept4(vm, base, a0, a1, a2, a3);
            if vm.status == abi::STATUS_SOCKET_RECV {
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_SOCKET_RECV,
                );
            }
            r
        }
        SYS_SENDTO => {
            let r = socket::sys_sendto(vm, base, a0, a1, a2, a3, a4, a5);
            if vm.status == abi::STATUS_SOCKET_SEND {
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_SOCKET_SEND,
                );
            }
            r
        }
        SYS_RECVFROM => {
            let r = socket::sys_recvfrom(vm, base, a0, a1, a2, a3, a4, a5);
            if vm.status == abi::STATUS_SOCKET_RECV {
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_SOCKET_RECV,
                );
            }
            r
        }
        SYS_SENDMSG => {
            let r = socket::sys_sendmsg(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_SOCKET_SEND {
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_SOCKET_SEND,
                );
            }
            r
        }
        SYS_RECVMSG => {
            let r = socket::sys_recvmsg(vm, base, a0, a1, a2);
            if vm.status == abi::STATUS_SOCKET_RECV {
                return debug_return_fd_arg0(
                    vm,
                    base,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    r,
                    abi::STATUS_SOCKET_RECV,
                );
            }
            r
        }
        SYS_SHUTDOWN => socket::sys_shutdown(vm, base, a0, a1),
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
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_EPOLL_WAIT);
            }
            r
        }
        SYS_PPOLL => {
            let r = poll::sys_ppoll(vm, base, a0, a1, a2, a3, a4);
            if vm.status == abi::STATUS_PIPE_WAIT {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_PIPE_WAIT);
            }
            r
        }
        SYS_PSELECT6 => {
            let r = poll::sys_pselect6(vm, base, a0, a1, a2, a3, a4, a5);
            if vm.status == abi::STATUS_PIPE_WAIT {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, r, abi::STATUS_PIPE_WAIT);
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
            if nr == SYS_TGKILL && target_pid <= 0 {
                EINVAL
            } else if target_pid != self_pid {
                ESRCH
            } else {
                signal::send_signal_to_tid(vm, base, target_tid, sig)
            }
        }

        // thread lifecycle
        SYS_SET_TID_ADDRESS => thread::sys_set_tid_address(vm, a0),
        SYS_GET_ROBUST_LIST => thread::sys_get_robust_list(vm, base, a0 as i64, a1, a2),
        SYS_SET_ROBUST_LIST => thread::sys_set_robust_list(vm, a0, a1),
        SYS_SETPGID => process::sys_setpgid(vm, base, a0 as i64, a1 as i64),
        SYS_GETPGID => process::sys_getpgid(vm, base, a0 as i64),
        SYS_SETSID => process::sys_setsid(vm, base),
        SYS_CLONE => {
            // Dispatch based on clone flags:
            // CLONE_VFORK → vfork (process.rs)
            // CLONE_VM | CLONE_THREAD → new thread (thread.rs)
            // neither → process context (process.rs)
            if a0 & CLONE_VFORK != 0 {
                let status = process::sys_clone_vfork(vm, base, a0, a1, a2, a3, a4);
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, vm.x[10] as i64, status);
            } else if a0 & CLONE_VM != 0 && a0 & CLONE_THREAD != 0 {
                let ret = thread::sys_clone(vm, base, a0, a1, a2, a3, a4);
                if vm.status == abi::STATUS_CLONE_SPAWN {
                    return debug_return(
                        vm,
                        nr,
                        a0,
                        a1,
                        a2,
                        a3,
                        a4,
                        a5,
                        ret,
                        abi::STATUS_CLONE_SPAWN,
                    );
                }
                ret
            } else {
                let ret = process::sys_fork(vm, base, a0, a1, a2, a3, a4);
                if vm.status == abi::STATUS_EXECVE_SPAWN {
                    return debug_return(
                        vm,
                        nr,
                        a0,
                        a1,
                        a2,
                        a3,
                        a4,
                        a5,
                        ret,
                        abi::STATUS_EXECVE_SPAWN,
                    );
                }
                ret
            }
        }
        SYS_CLONE3 => {
            let ret = thread::sys_clone3(vm, base, a0, a1);
            if vm.status == abi::STATUS_CLONE_SPAWN {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, ret, abi::STATUS_CLONE_SPAWN);
            }
            ret
        }
        SYS_EXECVE => {
            let ret = process::sys_execve(vm, base, a0, a1, a2);
            crate::tracepoints::record_execve_dispatch(vm as *const ThreadState as u32, 2);
            if vm.status == abi::STATUS_EXECVE_SPAWN {
                return debug_return(
                    vm,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    ret,
                    abi::STATUS_EXECVE_SPAWN,
                );
            }
            ret
        }
        SYS_EXECVEAT => {
            let ret = process::sys_execveat(vm, base, a0, a1, a2, a3, a4);
            crate::tracepoints::record_execve_dispatch(vm as *const ThreadState as u32, 2);
            if vm.status == abi::STATUS_EXECVE_SPAWN {
                return debug_return(
                    vm,
                    nr,
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    ret,
                    abi::STATUS_EXECVE_SPAWN,
                );
            }
            ret
        }
        SYS_WAIT4 => {
            let ret = process::sys_wait4(vm, base, a0 as i64, a1, a2, a3);
            if vm.status == abi::STATUS_WAIT4 {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, ret, abi::STATUS_WAIT4);
            }
            ret
        }
        SYS_WAITID => {
            let ret = process::sys_waitid(vm, base, a0 as u32, a1 as i64, a2, a3, a4);
            if vm.status == abi::STATUS_WAIT4 {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, ret, abi::STATUS_WAIT4);
            }
            ret
        }
        SYS_FUTEX | SYS_FUTEX_TIME64 => {
            let ret = thread::sys_futex(vm, base, a0, a1, a2, a3, a4, vm.x[15]);
            if vm.status == abi::STATUS_FUTEX_WAIT {
                return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, ret, abi::STATUS_FUTEX_WAIT);
            }
            ret
        }
        SYS_EXIT => {
            let status = thread::sys_exit(vm, base, a0);
            return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, vm.exit_code as i64, status);
        }
        SYS_EXIT_GROUP => {
            let status = thread::sys_exit_group(vm, base, a0);
            return debug_return(vm, nr, a0, a1, a2, a3, a4, a5, vm.exit_code as i64, status);
        }
        SYS_GETRLIMIT => resource::sys_getrlimit(vm, base, a0, a1),
        SYS_SETRLIMIT => resource::sys_setrlimit(vm, base, a0, a1),
        SYS_PRCTL => ENOSYS,
        SYS_UMASK => fs::sys_umask(vm, base, a0),
        SYS_RISCV_HWPROBE => identity::sys_riscv_hwprobe(vm, base, a0, a1, a2, a3, a4),
        SYS_RISCV_FLUSH_ICACHE => identity::sys_riscv_flush_icache(vm, base, a0, a1, a2),
        SYS_RSEQ => ENOSYS,
        SYS_PRLIMIT64 => resource::sys_prlimit64(vm, base, a0 as i32, a1, a2, a3),

        // not yet implemented
        _ => ENOSYS,
    };

    trace::memory::record_trace(nr, a0, a1, a2, a3, result);
    trace::memory::record_debug(vm, nr, a0, a1, a2, a3, a4, a5, result);
    if nr != SYS_RT_SIGRETURN {
        vm.x[10] = result as u64;
    }

    // Check and deliver pending signals at syscall return boundary
    signal::check_pending(vm, base);
    if nr == SYS_EXECVE || nr == SYS_EXECVEAT {
        crate::tracepoints::record_execve_dispatch(vm as *const ThreadState as u32, 3);
    }
    let status = vm.status;
    sync_effects::mark_completed_syscall_sync_effects(vm, base, nr, a0, result, status);
    if nr == SYS_PIPE2 && result == 0 {
        unsafe {
            let read_fd = crate::guest_mem::read_u32(base, a0);
            let write_fd = crate::guest_mem::read_u32(base, a0 + 4);
            (arg0_ofd_id, arg0_ofd_type) = trace::fd::snapshot(base, vm, read_fd as u64);
            (arg2_ofd_id, arg2_ofd_type) = trace::fd::snapshot(base, vm, write_fd as u64);
        }
    } else if (nr == SYS_SOCKET || nr == SYS_ACCEPT4) && result >= 0 {
        (arg0_ofd_id, arg0_ofd_type) = trace::fd::snapshot(base, vm, result as u64);
        arg2_ofd_id = 0;
        arg2_ofd_type = 0;
    } else if nr == SYS_SOCKETPAIR && result == 0 {
        unsafe {
            let left_fd = crate::guest_mem::read_u32(base, a3);
            let right_fd = crate::guest_mem::read_u32(base, a3 + 4);
            (arg0_ofd_id, arg0_ofd_type) = trace::fd::snapshot(base, vm, left_fd as u64);
            (arg2_ofd_id, arg2_ofd_type) = trace::fd::snapshot(base, vm, right_fd as u64);
        }
    }
    crate::tracepoints::record_fd_syscall(
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
    #[cfg(not(any(test, feature = "harness")))]
    trace::fd::record(
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
    crate::tracepoints::record_syscall(
        vm as *const ThreadState as u32,
        nr,
        a0,
        a1,
        a2,
        a3,
        a4,
        a5,
        result,
        status,
    );
    if status != abi::STATUS_OK {
        if fd_table::blocked_status_uses_ofd_pin(status) {
            save_blocked_syscall_args(vm, nr, a0, a1, a2, a3, a4, a5);
        } else {
            fd_table::clear_blocked_ofd_pin(vm);
        }
        return status;
    }
    fd_table::clear_blocked_ofd_pin(vm);
    abi::STATUS_OK
}
