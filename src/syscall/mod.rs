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
pub mod signal;
pub mod socket;
pub mod thread;
pub mod time;

use crate::abi;
use crate::abi::*;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::ThreadState;

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
    let _a5 = vm.x[15];

    let result: i64 = match nr {
        // identity
        SYS_GETPID => identity::sys_getpid(vm),
        SYS_GETPPID => identity::sys_getppid(vm),
        SYS_GETTID => identity::sys_gettid(vm),
        SYS_GETUID | SYS_GETEUID | SYS_GETGID | SYS_GETEGID => identity::sys_getuid(),
        SYS_UNAME => identity::sys_uname(vm, base, a0),
        SYS_SYSINFO => identity::sys_sysinfo(vm, base, a0),
        SYS_GETRANDOM => identity::sys_getrandom(vm, base, a0, a1, a2),

        // time
        SYS_CLOCK_GETTIME => time::sys_clock_gettime(vm, base, a0, a1),
        114 => time::sys_clock_getres(vm, base, a0, a1), // clock_getres
        SYS_NANOSLEEP => return time::sys_nanosleep(vm, base, a0, a1),
        SYS_SCHED_YIELD => time::sys_sched_yield(),
        SYS_TIMES => 0,      // stub: return 0 clock ticks

        // memory
        SYS_BRK => memory::sys_brk(vm, base, a0),
        SYS_MMAP => memory::sys_mmap(vm, base, a0, a1, a2, a3, a4 as i64, vm.x[15]),
        SYS_MUNMAP => memory::sys_munmap(vm, base, a0, a1),
        SYS_MREMAP => memory::sys_mremap(vm, base, a0, a1, a2, a3, a4),
        SYS_MPROTECT => memory::sys_mprotect(vm, base, a0, a1, a2),
        SYS_MADVISE => 0, // no-op, return success

        // signal
        SYS_RT_SIGACTION => signal::sys_rt_sigaction(vm, base, a0, a1, a2, a3),
        SYS_RT_SIGPROCMASK => signal::sys_rt_sigprocmask(vm, base, a0, a1, a2, a3),
        SYS_SIGALTSTACK => signal::sys_sigaltstack(vm, base, a0, a1),
        SYS_RT_SIGRETURN => { signal::sys_rt_sigreturn(vm, base); 0 }

        // filesystem
        SYS_OPENAT => fs::sys_openat(vm, base, a0, a1, a2, a3),
        SYS_READ => fs::sys_read(vm, base, a0, a1, a2),
        SYS_PREAD64 => fs::sys_pread64(vm, base, a0, a1, a2, a3),
        SYS_WRITE | SYS_WRITEV => fs::sys_write(vm, base, a0, a1, a2, nr),
        SYS_PWRITE64 => fs::sys_pwrite64(vm, base, a0, a1, a2, a3),
        SYS_READV => 0, // TODO
        SYS_NEWFSTATAT => fs::sys_newfstatat(vm, base, a0, a1, a2, a3),
        SYS_FSTAT => fs::sys_fstat(vm, base, a0, a1),
        SYS_LSEEK => fs::sys_lseek(vm, base, a0, a1 as i64, a2),
        SYS_GETDENTS64 => fs::sys_getdents64(vm, base, a0, a1, a2),
        SYS_MKDIRAT => fs::sys_mkdirat(vm, base, a0, a1, a2),
        SYS_UNLINKAT => fs::sys_unlinkat(vm, base, a0, a1, a2),
        SYS_FACCESSAT => fs::sys_faccessat(vm, base, a0, a1, a2),
        SYS_READLINKAT => fs::sys_readlinkat(vm, base, a0, a1, a2, a3),
        SYS_TRUNCATE => fs::sys_truncate(vm, base, a0, a1),
        SYS_FTRUNCATE => fs::sys_ftruncate(vm, base, a0, a1),
        SYS_IOCTL => 0,
        SYS_GETCWD => {
            // Write "/" to buf
            if a1 >= 2 {
                unsafe { guest_mem::write_bytes(base, a0, b"/\0"); }
                a0 as i64
            } else { EINVAL }
        }

        // fd table
        SYS_DUP => fd_table::sys_dup(vm, base, a0),
        SYS_DUP3 => fd_table::sys_dup3(vm, base, a0, a1, a2),
        SYS_FCNTL => fd_table::sys_fcntl(vm, base, a0, a1, a2),
        SYS_CLOSE => fd_table::sys_close(vm, base, a0),

        // pipe
        SYS_PIPE2 => pipe::sys_pipe2(vm, base, a0, a1),

        // epoll
        SYS_EPOLL_CREATE1 => epoll::sys_epoll_create1(vm, base, a0),
        SYS_EPOLL_CTL => epoll::sys_epoll_ctl(vm, base, a0, a1, a2, a3),
        SYS_EPOLL_PWAIT => {
            let r = epoll::sys_epoll_pwait(vm, base, a0, a1, a2, a3 as i64, a4);
            if vm.status == abi::STATUS_EPOLL_WAIT { return abi::STATUS_EPOLL_WAIT; }
            r
        }
        SYS_EVENTFD2 => pipe::sys_eventfd2(vm, base, a0, a1),

        // signal delivery
        SYS_KILL | SYS_TKILL | SYS_TGKILL => {
            let sig = if nr == SYS_KILL { a1 } else { a2 };
            signal::send_signal(vm, sig as i32);
            0
        }

        // process (stubs — real impl with kernel Worker)
        SYS_SET_TID_ADDRESS => {
            vm.clear_child_tid = a0;
            vm.tid as i64
        }
        SYS_SET_ROBUST_LIST => 0,
        SYS_PRCTL => 0,
        SYS_UMASK => 0o022, // return previous umask
        SYS_RSEQ => EINVAL,
        261 => 0,            // prlimit64: stub success

        // exit
        SYS_EXIT | SYS_EXIT_GROUP => {
            vm.exit_code = a0 as i32;
            vm.status = abi::STATUS_FAULT;
            return abi::STATUS_FAULT;
        }

        // not yet implemented
        _ => ENOSYS,
    };

    vm.x[10] = result as u64;

    // Check and deliver pending signals at syscall return boundary
    signal::check_pending(vm, base);

    abi::STATUS_OK
}
