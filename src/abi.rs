//! ABI constants and WASM exports.
//! Single source of truth for all constants shared between kernel and runtime.
//! Runtime (TS) reads these via WASM exports — no hand-written constants in TS.

// =============================================================================
// Status codes (WASM exec → JS control flow)
// =============================================================================
pub const STATUS_OK: i32 = 0;
pub const STATUS_FAULT: i32 = 3;
pub const STATUS_FS: i32 = 6;
pub const STATUS_FUTEX_WAIT: i32 = 20;
pub const STATUS_PIPE_WAIT: i32 = 21;
pub const STATUS_EPOLL_WAIT: i32 = 22;
pub const STATUS_VFORK_WAIT: i32 = 23;
pub const STATUS_EXECVE_SPAWN: i32 = 24;
pub const STATUS_CLONE_SPAWN: i32 = 25;
pub const STATUS_SLEEP: i32 = 26;
pub const STATUS_JIT_READY: i32 = 27;
pub const STATUS_CONNECT: i32 = 28;
pub const STATUS_SOCKET_SEND: i32 = 29;
pub const STATUS_SOCKET_RECV: i32 = 30;
pub const STATUS_WAIT4: i32 = 31;

// =============================================================================
// Process spawn handoff kinds
// =============================================================================
pub const SPAWN_KIND_NONE: u32 = 0;
pub const SPAWN_KIND_EXECVE: u32 = 1;
pub const SPAWN_KIND_FORK: u32 = 2;

// =============================================================================
// FD types (internal, not Linux ABI)
// =============================================================================
pub const FD_TYPE_NONE: i32 = 0;
pub const FD_TYPE_STDOUT: i32 = 1;
pub const FD_TYPE_STDERR: i32 = 2;
pub const FD_TYPE_FILE: i32 = 3;
pub const FD_TYPE_DIR: i32 = 4;
pub const FD_TYPE_DEVNULL: i32 = 5;
pub const FD_TYPE_PIPE: i32 = 6;
pub const FD_TYPE_EPOLL: i32 = 7;
pub const FD_TYPE_SOCKET: i32 = 8;
pub const FD_TYPE_EVENTFD: i32 = 9;
pub const FD_TYPE_TIMERFD: i32 = 10;
pub const FD_TYPE_PTY_MASTER: i32 = 11;
pub const FD_TYPE_PTY_SLAVE: i32 = 12;
pub const FD_TYPE_INOTIFY: i32 = 13;

// =============================================================================
// Syscall numbers (asm-generic, used by RISC-V)
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/unistd.h
// =============================================================================
pub const SYS_GETCWD: u64 = 17;
pub const SYS_EVENTFD2: u64 = 19;
pub const SYS_EPOLL_CREATE1: u64 = 20;
pub const SYS_EPOLL_CTL: u64 = 21;
pub const SYS_EPOLL_PWAIT: u64 = 22;
pub const SYS_DUP: u64 = 23;
pub const SYS_DUP3: u64 = 24;
pub const SYS_INOTIFY_INIT1: u64 = 26;
pub const SYS_INOTIFY_ADD_WATCH: u64 = 27;
pub const SYS_INOTIFY_RM_WATCH: u64 = 28;
pub const SYS_IOCTL: u64 = 29;
pub const SYS_FCNTL: u64 = 25;
pub const SYS_MKDIRAT: u64 = 34;
pub const SYS_UNLINKAT: u64 = 35;
pub const SYS_STATFS: u64 = 43;
pub const SYS_RENAMEAT2: u64 = 276;
pub const SYS_STATX: u64 = 291;
pub const SYS_FACCESSAT: u64 = 48;
pub const SYS_CHDIR: u64 = 49;
pub const SYS_FCHMODAT: u64 = 53;
pub const SYS_FCHOWNAT: u64 = 54;
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_PIPE2: u64 = 59;
pub const SYS_GETDENTS64: u64 = 61;
pub const SYS_LSEEK: u64 = 62;
pub const SYS_READ: u64 = 63;
pub const SYS_WRITE: u64 = 64;
pub const SYS_READV: u64 = 65;
pub const SYS_WRITEV: u64 = 66;
pub const SYS_PREAD64: u64 = 67;
pub const SYS_PWRITE64: u64 = 68;
pub const SYS_PREADV: u64 = 69;
pub const SYS_PWRITEV: u64 = 70;
pub const SYS_MSYNC: u64 = 227;
pub const SYS_READLINKAT: u64 = 78;
pub const SYS_NEWFSTATAT: u64 = 79;
pub const SYS_FSTAT: u64 = 80;
pub const SYS_TRUNCATE: u64 = 45;
pub const SYS_FTRUNCATE: u64 = 46;
pub const SYS_UTIMENSAT: u64 = 88;
pub const SYS_EXIT: u64 = 93;
pub const SYS_EXIT_GROUP: u64 = 94;
pub const SYS_WAITID: u64 = 95;
pub const SYS_SET_TID_ADDRESS: u64 = 96;
pub const SYS_SET_ROBUST_LIST: u64 = 99;
pub const SYS_FUTEX: u64 = 98;
pub const SYS_NANOSLEEP: u64 = 101;
pub const SYS_GETITIMER: u64 = 102;
pub const SYS_SETITIMER: u64 = 103;
pub const SYS_CLOCK_GETTIME: u64 = 113;
pub const SYS_SCHED_GETAFFINITY: u64 = 123;
pub const SYS_SCHED_YIELD: u64 = 124;
pub const SYS_KILL: u64 = 129;
pub const SYS_TKILL: u64 = 130;
pub const SYS_TGKILL: u64 = 131;
pub const SYS_RT_SIGACTION: u64 = 134;
pub const SYS_RT_SIGPROCMASK: u64 = 135;
pub const SYS_RT_SIGPENDING: u64 = 136;
pub const SYS_RT_SIGRETURN: u64 = 139;
pub const SYS_SIGALTSTACK: u64 = 132;
pub const SYS_SETREGID: u64 = 143;
pub const SYS_SETGID: u64 = 144;
pub const SYS_SETREUID: u64 = 145;
pub const SYS_SETUID: u64 = 146;
pub const SYS_SETRESUID: u64 = 147;
pub const SYS_GETRESUID: u64 = 148;
pub const SYS_SETRESGID: u64 = 149;
pub const SYS_GETRESGID: u64 = 150;
pub const SYS_TIMES: u64 = 153;
pub const SYS_SETPGID: u64 = 154;
pub const SYS_GETPGID: u64 = 155;
pub const SYS_GETPID: u64 = 172;
pub const SYS_GETPPID: u64 = 173;
pub const SYS_GETUID: u64 = 174;
pub const SYS_GETEUID: u64 = 175;
pub const SYS_GETGID: u64 = 176;
pub const SYS_GETEGID: u64 = 177;
pub const SYS_GETTID: u64 = 178;
pub const SYS_SYSINFO: u64 = 179;
pub const SYS_BRK: u64 = 214;
pub const SYS_MUNMAP: u64 = 215;
pub const SYS_MREMAP: u64 = 216;
pub const SYS_CLONE: u64 = 220;
pub const SYS_EXECVE: u64 = 221;
pub const SYS_MMAP: u64 = 222;
pub const SYS_MPROTECT: u64 = 226;
pub const SYS_WAIT4: u64 = 260;
pub const SYS_PRCTL: u64 = 167;
pub const SYS_SETSID: u64 = 157;
pub const SYS_GETRANDOM: u64 = 278;
pub const SYS_RSEQ: u64 = 293;
pub const SYS_CLONE3: u64 = 435;
pub const SYS_SOCKET: u64 = 198;
pub const SYS_BIND: u64 = 200;
pub const SYS_LISTEN: u64 = 201;
pub const SYS_ACCEPT4: u64 = 242;
pub const SYS_CONNECT: u64 = 203;
pub const SYS_SENDTO: u64 = 206;
pub const SYS_RECVFROM: u64 = 207;
pub const SYS_SETSOCKOPT: u64 = 208;
pub const SYS_GETSOCKOPT: u64 = 209;
pub const SYS_GETSOCKNAME: u64 = 204;
pub const SYS_GETPEERNAME: u64 = 205;
pub const SYS_PPOLL: u64 = 73;
pub const SYS_TIMERFD_CREATE: u64 = 85;
pub const SYS_TIMERFD_SETTIME: u64 = 86;
pub const SYS_UNAME: u64 = 160;
pub const SYS_MADVISE: u64 = 233;
pub const SYS_FLOCK: u64 = 32;
pub const SYS_UMASK: u64 = 166;

// =============================================================================
// clone flags
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/sched.h
// =============================================================================
pub const CLONE_VM: u64 = 0x00000100;
pub const CLONE_FS: u64 = 0x00000200;
pub const CLONE_FILES: u64 = 0x00000400;
pub const CLONE_SIGHAND: u64 = 0x00000800;
pub const CLONE_PARENT: u64 = 0x00008000;
pub const CLONE_THREAD: u64 = 0x00010000;
pub const CLONE_SETTLS: u64 = 0x00080000;
pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
pub const CLONE_CHILD_SETTID: u64 = 0x01000000;
pub const CLONE_VFORK: u64 = 0x00004000;

// =============================================================================
// mmap / mprotect flags
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/mman-common.h
// =============================================================================
pub const PROT_NONE: i32 = 0x0;
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;

pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_SHARED: u64 = 0x01;

// =============================================================================
// open flags
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/fcntl.h
// =============================================================================
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0x40;
pub const O_TRUNC: i32 = 0x200;
pub const O_APPEND: i32 = 0x400;
pub const O_NONBLOCK: i32 = 0x800;
pub const O_CLOEXEC: i32 = 0x80000;
pub const O_DIRECTORY: i32 = 0x10000;

// =============================================================================
// Signal numbers
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/signal.h
// =============================================================================
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGSEGV: i32 = 11;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGURG: i32 = 23;
pub const SIGWINCH: i32 = 28;

// =============================================================================
// Limits
// =============================================================================
pub const MAX_FDS: usize = 256;
pub const MAX_THREADS: usize = 32;
pub const MAX_MMAP_REGIONS: usize = 256;
pub const MAX_SOCKETS: usize = 32;
pub const MAX_EPOLL_ENTRIES: usize = 64;
pub const MAX_EVENTFDS: usize = 16;
pub const MAX_TIMERFDS: usize = 8;
pub const MAX_PIPES: usize = 64;
pub const MAX_PROCESSES: usize = 64;

// Futex operations (https://man7.org/linux/man-pages/man2/futex.2.html)
pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_CMP_REQUEUE: u32 = 4;
pub const PAGE_SIZE: u64 = 4096;

// =============================================================================
// Error codes (negated, as returned by syscalls)
// =============================================================================
pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const EIO: i64 = -5;
pub const ENXIO: i64 = -6;
pub const ENOEXEC: i64 = -8;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EEXIST: i64 = -17;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const ETXTBSY: i64 = -26;
pub const ERANGE: i64 = -34;
pub const ENAMETOOLONG: i64 = -36;
pub const EMFILE: i64 = -24;
pub const ESPIPE: i64 = -29;
pub const ENOSPC: i64 = -28;
pub const EPIPE: i64 = -32;
pub const ENOSYS: i64 = -38;
pub const ENOTEMPTY: i64 = -39;
pub const ENOTSOCK: i64 = -88;
pub const EDESTADDRREQ: i64 = -89;
pub const EPROTOTYPE: i64 = -91;
pub const ENOPROTOOPT: i64 = -92;
pub const EPROTONOSUPPORT: i64 = -93;
pub const EAFNOSUPPORT: i64 = -97;
pub const EADDRINUSE: i64 = -98;
pub const EADDRNOTAVAIL: i64 = -99;
pub const ENOTCONN: i64 = -107;
pub const EISCONN: i64 = -106;
pub const ECONNREFUSED: i64 = -111;
pub const ETIMEDOUT: i64 = -110;

// =============================================================================
// Socket address families
// https://github.com/torvalds/linux/blob/v6.12/include/linux/socket.h
// =============================================================================
pub const AF_UNIX: u32 = 1;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;

// =============================================================================
// Socket types
// https://github.com/torvalds/linux/blob/v6.12/include/linux/net.h
// =============================================================================
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_NONBLOCK: u32 = 0x800;
pub const SOCK_CLOEXEC: u32 = 0x80000;

// =============================================================================
// WASM exports — runtime reads these, no hand-written constants in TS
// =============================================================================
macro_rules! export_const {
    ($name:ident, $val:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $name() -> i32 {
            $val
        }
    };
}

export_const!(abi_status_ok, STATUS_OK);
export_const!(abi_status_fault, STATUS_FAULT);
export_const!(abi_status_fs, STATUS_FS);
export_const!(abi_status_futex_wait, STATUS_FUTEX_WAIT);
export_const!(abi_status_pipe_wait, STATUS_PIPE_WAIT);
export_const!(abi_status_epoll_wait, STATUS_EPOLL_WAIT);
export_const!(abi_status_vfork_wait, STATUS_VFORK_WAIT);
export_const!(abi_status_execve_spawn, STATUS_EXECVE_SPAWN);
export_const!(abi_status_clone_spawn, STATUS_CLONE_SPAWN);
export_const!(abi_status_sleep, STATUS_SLEEP);
export_const!(abi_status_jit_ready, STATUS_JIT_READY);
export_const!(abi_spawn_kind_none, SPAWN_KIND_NONE as i32);
export_const!(abi_spawn_kind_execve, SPAWN_KIND_EXECVE as i32);
export_const!(abi_spawn_kind_fork, SPAWN_KIND_FORK as i32);
export_const!(abi_status_connect, STATUS_CONNECT);
export_const!(abi_status_socket_send, STATUS_SOCKET_SEND);
export_const!(abi_status_socket_recv, STATUS_SOCKET_RECV);
export_const!(abi_status_wait4, STATUS_WAIT4);
export_const!(abi_page_size, PAGE_SIZE as i32);
export_const!(abi_max_fds, MAX_FDS as i32);
export_const!(abi_max_threads, MAX_THREADS as i32);
export_const!(abi_max_pipes, MAX_PIPES as i32);

// FD types
export_const!(abi_fd_type_none, FD_TYPE_NONE);
export_const!(abi_fd_type_stdout, FD_TYPE_STDOUT);
export_const!(abi_fd_type_stderr, FD_TYPE_STDERR);
export_const!(abi_fd_type_file, FD_TYPE_FILE);
export_const!(abi_fd_type_dir, FD_TYPE_DIR);
export_const!(abi_fd_type_devnull, FD_TYPE_DEVNULL);
export_const!(abi_fd_type_pipe, FD_TYPE_PIPE);
export_const!(abi_fd_type_epoll, FD_TYPE_EPOLL);
export_const!(abi_fd_type_socket, FD_TYPE_SOCKET);
export_const!(abi_fd_type_eventfd, FD_TYPE_EVENTFD);
export_const!(abi_fd_type_timerfd, FD_TYPE_TIMERFD);
export_const!(abi_fd_type_pty_master, FD_TYPE_PTY_MASTER);
export_const!(abi_fd_type_pty_slave, FD_TYPE_PTY_SLAVE);
export_const!(abi_fd_type_inotify, FD_TYPE_INOTIFY);

// Syscall numbers
macro_rules! export_const_u64 {
    ($name:ident, $val:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $name() -> u64 {
            $val
        }
    };
}

export_const_u64!(abi_sys_openat, SYS_OPENAT);
export_const_u64!(abi_sys_close, SYS_CLOSE);
export_const_u64!(abi_sys_read, SYS_READ);
export_const_u64!(abi_sys_write, SYS_WRITE);
export_const_u64!(abi_sys_mmap, SYS_MMAP);
export_const_u64!(abi_sys_munmap, SYS_MUNMAP);
export_const_u64!(abi_sys_msync, SYS_MSYNC);
export_const_u64!(abi_sys_brk, SYS_BRK);
export_const_u64!(abi_sys_clone, SYS_CLONE);
export_const_u64!(abi_sys_execve, SYS_EXECVE);
export_const_u64!(abi_sys_exit, SYS_EXIT);
export_const_u64!(abi_sys_exit_group, SYS_EXIT_GROUP);
export_const_u64!(abi_sys_waitid, SYS_WAITID);
export_const_u64!(abi_sys_futex, SYS_FUTEX);
export_const_u64!(abi_sys_pipe2, SYS_PIPE2);
export_const_u64!(abi_sys_epoll_create1, SYS_EPOLL_CREATE1);
export_const_u64!(abi_sys_epoll_ctl, SYS_EPOLL_CTL);
export_const_u64!(abi_sys_epoll_pwait, SYS_EPOLL_PWAIT);
export_const_u64!(abi_sys_rt_sigaction, SYS_RT_SIGACTION);
export_const_u64!(abi_sys_rt_sigprocmask, SYS_RT_SIGPROCMASK);
export_const_u64!(abi_sys_rt_sigpending, SYS_RT_SIGPENDING);
export_const_u64!(abi_sys_wait4, SYS_WAIT4);
export_const_u64!(abi_sys_getpid, SYS_GETPID);
export_const_u64!(abi_sys_gettid, SYS_GETTID);
export_const_u64!(abi_sys_nanosleep, SYS_NANOSLEEP);
export_const_u64!(abi_sys_clock_gettime, SYS_CLOCK_GETTIME);
export_const_u64!(abi_sys_getcwd, SYS_GETCWD);
export_const_u64!(abi_sys_eventfd2, SYS_EVENTFD2);
export_const_u64!(abi_sys_dup, SYS_DUP);
export_const_u64!(abi_sys_dup3, SYS_DUP3);
export_const_u64!(abi_sys_inotify_init1, SYS_INOTIFY_INIT1);
export_const_u64!(abi_sys_inotify_add_watch, SYS_INOTIFY_ADD_WATCH);
export_const_u64!(abi_sys_inotify_rm_watch, SYS_INOTIFY_RM_WATCH);
export_const_u64!(abi_sys_ioctl, SYS_IOCTL);
export_const_u64!(abi_sys_fcntl, SYS_FCNTL);
export_const_u64!(abi_sys_mkdirat, SYS_MKDIRAT);
export_const_u64!(abi_sys_unlinkat, SYS_UNLINKAT);
export_const_u64!(abi_sys_statfs, SYS_STATFS);
export_const_u64!(abi_sys_renameat2, SYS_RENAMEAT2);
export_const_u64!(abi_sys_statx, SYS_STATX);
export_const_u64!(abi_sys_faccessat, SYS_FACCESSAT);
export_const_u64!(abi_sys_chdir, SYS_CHDIR);
export_const_u64!(abi_sys_fchmodat, SYS_FCHMODAT);
export_const_u64!(abi_sys_fchownat, SYS_FCHOWNAT);
export_const_u64!(abi_sys_getdents64, SYS_GETDENTS64);
export_const_u64!(abi_sys_lseek, SYS_LSEEK);
export_const_u64!(abi_sys_readv, SYS_READV);
export_const_u64!(abi_sys_writev, SYS_WRITEV);
export_const_u64!(abi_sys_pread64, SYS_PREAD64);
export_const_u64!(abi_sys_pwrite64, SYS_PWRITE64);
export_const_u64!(abi_sys_preadv, SYS_PREADV);
export_const_u64!(abi_sys_pwritev, SYS_PWRITEV);
export_const_u64!(abi_sys_readlinkat, SYS_READLINKAT);
export_const_u64!(abi_sys_newfstatat, SYS_NEWFSTATAT);
export_const_u64!(abi_sys_fstat, SYS_FSTAT);
export_const_u64!(abi_sys_truncate, SYS_TRUNCATE);
export_const_u64!(abi_sys_ftruncate, SYS_FTRUNCATE);
export_const_u64!(abi_sys_utimensat, SYS_UTIMENSAT);
export_const_u64!(abi_sys_set_tid_address, SYS_SET_TID_ADDRESS);
export_const_u64!(abi_sys_set_robust_list, SYS_SET_ROBUST_LIST);
export_const_u64!(abi_sys_sched_yield, SYS_SCHED_YIELD);
export_const_u64!(abi_sys_kill, SYS_KILL);
export_const_u64!(abi_sys_tkill, SYS_TKILL);
export_const_u64!(abi_sys_tgkill, SYS_TGKILL);
export_const_u64!(abi_sys_rt_sigreturn, SYS_RT_SIGRETURN);
export_const_u64!(abi_sys_sigaltstack, SYS_SIGALTSTACK);
export_const_u64!(abi_sys_setregid, SYS_SETREGID);
export_const_u64!(abi_sys_setgid, SYS_SETGID);
export_const_u64!(abi_sys_setreuid, SYS_SETREUID);
export_const_u64!(abi_sys_setuid, SYS_SETUID);
export_const_u64!(abi_sys_setresuid, SYS_SETRESUID);
export_const_u64!(abi_sys_getresuid, SYS_GETRESUID);
export_const_u64!(abi_sys_setresgid, SYS_SETRESGID);
export_const_u64!(abi_sys_getresgid, SYS_GETRESGID);
export_const_u64!(abi_sys_times, SYS_TIMES);
export_const_u64!(abi_sys_getppid, SYS_GETPPID);
export_const_u64!(abi_sys_getuid, SYS_GETUID);
export_const_u64!(abi_sys_geteuid, SYS_GETEUID);
export_const_u64!(abi_sys_getgid, SYS_GETGID);
export_const_u64!(abi_sys_getegid, SYS_GETEGID);
export_const_u64!(abi_sys_sysinfo, SYS_SYSINFO);
export_const_u64!(abi_sys_mremap, SYS_MREMAP);
export_const_u64!(abi_sys_mprotect, SYS_MPROTECT);
export_const_u64!(abi_sys_prctl, SYS_PRCTL);
export_const_u64!(abi_sys_getrandom, SYS_GETRANDOM);
export_const_u64!(abi_sys_rseq, SYS_RSEQ);
export_const_u64!(abi_sys_clone3, SYS_CLONE3);
export_const_u64!(abi_sys_socket, SYS_SOCKET);
export_const_u64!(abi_sys_bind, SYS_BIND);
export_const_u64!(abi_sys_listen, SYS_LISTEN);
export_const_u64!(abi_sys_accept4, SYS_ACCEPT4);
export_const_u64!(abi_sys_connect, SYS_CONNECT);
export_const_u64!(abi_sys_sendto, SYS_SENDTO);
export_const_u64!(abi_sys_recvfrom, SYS_RECVFROM);
export_const_u64!(abi_sys_setsockopt, SYS_SETSOCKOPT);
export_const_u64!(abi_sys_getsockopt, SYS_GETSOCKOPT);
export_const_u64!(abi_sys_getsockname, SYS_GETSOCKNAME);
export_const_u64!(abi_sys_getpeername, SYS_GETPEERNAME);
export_const_u64!(abi_sys_ppoll, SYS_PPOLL);
export_const_u64!(abi_sys_timerfd_create, SYS_TIMERFD_CREATE);
export_const_u64!(abi_sys_timerfd_settime, SYS_TIMERFD_SETTIME);
export_const_u64!(abi_sys_uname, SYS_UNAME);
export_const_u64!(abi_sys_madvise, SYS_MADVISE);
export_const_u64!(abi_sys_flock, SYS_FLOCK);
export_const_u64!(abi_sys_umask, SYS_UMASK);

// Clone flags
export_const_u64!(abi_clone_vm, CLONE_VM);
export_const_u64!(abi_clone_thread, CLONE_THREAD);
export_const_u64!(abi_clone_vfork, CLONE_VFORK);
export_const_u64!(abi_clone_parent, CLONE_PARENT);
export_const_u64!(abi_clone_files, CLONE_FILES);
export_const_u64!(abi_clone_sighand, CLONE_SIGHAND);
export_const_u64!(abi_clone_settls, CLONE_SETTLS);
export_const_u64!(abi_clone_child_cleartid, CLONE_CHILD_CLEARTID);
export_const_u64!(abi_clone_fs, CLONE_FS);
export_const_u64!(abi_clone_parent_settid, CLONE_PARENT_SETTID);
export_const_u64!(abi_clone_child_settid, CLONE_CHILD_SETTID);

// Signal numbers
export_const!(abi_sigkill, SIGKILL);
export_const!(abi_sigterm, SIGTERM);
export_const!(abi_sigchld, SIGCHLD);
export_const!(abi_sigpipe, SIGPIPE);
export_const!(abi_sigsegv, SIGSEGV);
export_const!(abi_sigill, SIGILL);
export_const!(abi_sigbus, SIGBUS);
export_const!(abi_sigstop, SIGSTOP);
export_const!(abi_sighup, SIGHUP);
export_const!(abi_sigint, SIGINT);
export_const!(abi_sigquit, SIGQUIT);
export_const!(abi_sigtrap, SIGTRAP);
export_const!(abi_sigabrt, SIGABRT);
export_const!(abi_sigfpe, SIGFPE);
export_const!(abi_sigalrm, SIGALRM);
export_const!(abi_sigcont, SIGCONT);
export_const!(abi_sigurg, SIGURG);
export_const!(abi_sigwinch, SIGWINCH);

// mmap/mprotect flags
export_const!(abi_prot_none, PROT_NONE);
export_const!(abi_prot_read, PROT_READ);
export_const!(abi_prot_write, PROT_WRITE);
export_const!(abi_prot_exec, PROT_EXEC);
export_const_u64!(abi_map_private, MAP_PRIVATE);
export_const_u64!(abi_map_anonymous, MAP_ANONYMOUS);
export_const_u64!(abi_map_fixed, MAP_FIXED);
export_const_u64!(abi_map_shared, MAP_SHARED);

// Open flags
export_const!(abi_o_rdonly, O_RDONLY);
export_const!(abi_o_wronly, O_WRONLY);
export_const!(abi_o_rdwr, O_RDWR);
export_const!(abi_o_creat, O_CREAT);
export_const!(abi_o_trunc, O_TRUNC);
export_const!(abi_o_append, O_APPEND);
export_const!(abi_o_cloexec, O_CLOEXEC);
export_const!(abi_o_nonblock, O_NONBLOCK);
export_const!(abi_o_directory, O_DIRECTORY);

// Error codes
export_const!(abi_enoent, ENOENT as i32);
export_const!(abi_ebadf, EBADF as i32);
export_const!(abi_einval, EINVAL as i32);
export_const!(abi_enomem, ENOMEM as i32);
export_const!(abi_enosys, ENOSYS as i32);
export_const!(abi_eagain, EAGAIN as i32);
export_const!(abi_epipe, EPIPE as i32);
export_const!(abi_eperm, EPERM as i32);
export_const!(abi_eexist, EEXIST as i32);
export_const!(abi_eacces, EACCES as i32);
export_const!(abi_esrch, ESRCH as i32);
export_const!(abi_eintr, EINTR as i32);
export_const!(abi_eio, EIO as i32);
export_const!(abi_enxio, ENXIO as i32);
export_const!(abi_enoexec, ENOEXEC as i32);
export_const!(abi_efault, EFAULT as i32);
export_const!(abi_enotdir, ENOTDIR as i32);
export_const!(abi_eisdir, EISDIR as i32);
export_const!(abi_emfile, EMFILE as i32);
export_const!(abi_enospc, ENOSPC as i32);
export_const!(abi_enotempty, ENOTEMPTY as i32);
export_const!(abi_enametoolong, ENAMETOOLONG as i32);
export_const!(abi_enotsock, ENOTSOCK as i32);
export_const!(abi_edestaddrreq, EDESTADDRREQ as i32);
export_const!(abi_eprototype, EPROTOTYPE as i32);
export_const!(abi_enoprotoopt, ENOPROTOOPT as i32);
export_const!(abi_eprotonosupport, EPROTONOSUPPORT as i32);
export_const!(abi_eafnosupport, EAFNOSUPPORT as i32);
export_const!(abi_eaddrinuse, EADDRINUSE as i32);
export_const!(abi_eaddrnotavail, EADDRNOTAVAIL as i32);
export_const!(abi_enotconn, ENOTCONN as i32);
export_const!(abi_eisconn, EISCONN as i32);
export_const!(abi_econnrefused, ECONNREFUSED as i32);

// Limits (remaining)
export_const!(abi_max_mmap_regions, MAX_MMAP_REGIONS as i32);
export_const!(abi_max_sockets, MAX_SOCKETS as i32);
export_const!(abi_max_epoll_entries, MAX_EPOLL_ENTRIES as i32);
export_const!(abi_max_eventfds, MAX_EVENTFDS as i32);
export_const!(abi_max_timerfds, MAX_TIMERFDS as i32);

// =============================================================================
// WASM exports — runtime calls these to manage processes and threads
// =============================================================================

/// Set the base wall-clock time for clock_gettime(CLOCK_REALTIME).
/// Called by runtime before process_create. sec/nsec are Unix epoch time.
#[unsafe(no_mangle)]
pub extern "C" fn set_base_time(sec: u64, nsec: u64) {
    crate::syscall::time::set_base_time(sec, nsec);
}

/// Initialize kernel state. Must be called once after WASM instantiation.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_init(heap_base: u32) {
    unsafe {
        crate::alloc::init(heap_base);
        crate::guest_mem::init(core::ptr::null(), core::ptr::null());
    }
    crate::syscall::memory::init(0);
    crate::syscall::process::init();
    crate::syscall::time::init();
    crate::syscall::thread::init();
    crate::syscall::signal::init();
    crate::syscall::epoll::init();
    crate::syscall::pipe::init();
    crate::syscall::socket::init();
    crate::fs::fd_table::init();
    crate::fs::memfs::init();
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_heap_base() -> u32 {
    crate::alloc::heap_base()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_heap_ptr() -> u32 {
    crate::alloc::heap_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_table_ptr() -> u32 {
    crate::fs::fd_table::ofd_table_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_ptr() -> u32 {
    crate::fs::memfs::memfs_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_mem_state_ptr() -> u32 {
    crate::syscall::memory::mem_state_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_epoll_table_ptr() -> u32 {
    crate::syscall::epoll::epoll_table_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_socket_table_ptr() -> u32 {
    crate::syscall::socket::socket_table_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_socket_used() -> u32 {
    crate::syscall::socket::socket_used()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_pipe_base() -> u32 {
    crate::syscall::pipe::pipe_state().0
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_pipe_used() -> u64 {
    crate::syscall::pipe::pipe_state().1
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_net_buf_base() -> u32 {
    crate::net::ring_buffer::net_buffer_state().0
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_net_buf_used() -> u64 {
    crate::net::ring_buffer::net_buffer_state().1
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_sig_slots_ptr() -> u32 {
    crate::syscall::signal::sig_slots_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_pending_ptr() -> u32 {
    crate::syscall::signal::process_pending_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_runtime_state_ptr() -> u32 {
    crate::syscall::process::process_runtime_state_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_time_state_ptr() -> u32 {
    crate::syscall::time::time_state_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_attach_runtime_state(
    heap_base: u32,
    heap_ptr: u32,
    ofd_table_ptr: u32,
    memfs_ptr: u32,
    mem_state_ptr: u32,
    epoll_table_ptr: u32,
    socket_table_ptr: u32,
    socket_used: u32,
    pipe_base: u32,
    pipe_used: u64,
    net_buf_base: u32,
    net_buf_used: u64,
    sig_slots_ptr: u32,
    process_pending_ptr: u32,
    process_runtime_state_ptr: u32,
    time_state_ptr: u32,
) {
    crate::alloc::attach_heap_state(heap_base, heap_ptr);
    crate::fs::fd_table::attach_ofd_table_ptr(ofd_table_ptr);
    crate::fs::memfs::attach_memfs_ptr(memfs_ptr);
    crate::syscall::memory::attach_mem_state_ptr(mem_state_ptr);
    crate::syscall::epoll::attach_epoll_table_ptr(epoll_table_ptr);
    crate::syscall::socket::attach_socket_state(socket_table_ptr, socket_used);
    crate::syscall::pipe::attach_pipe_state(pipe_base, pipe_used);
    crate::net::ring_buffer::attach_net_buffer_state(net_buf_base, net_buf_used);
    crate::syscall::signal::attach_process_signal_state(sig_slots_ptr, process_pending_ptr);
    crate::syscall::process::attach_process_runtime_state_ptr(process_runtime_state_ptr);
    crate::syscall::time::attach_time_state_ptr(time_state_ptr);
}

// =========================================================================
// Staged argv/envp for process_create
// =========================================================================

const MAX_ARGS: usize = 64;

struct StagedArgs {
    argv: [u64; MAX_ARGS],
    envp: [u64; MAX_ARGS],
    argc: usize,
    envc: usize,
}

static mut STAGED: StagedArgs = StagedArgs {
    argv: [0; MAX_ARGS],
    envp: [0; MAX_ARGS],
    argc: 0,
    envc: 0,
};

fn staged_args() -> &'static mut StagedArgs {
    unsafe { &mut *core::ptr::addr_of_mut!(STAGED) }
}

/// Push an argv string address (guest memory pointer to null-terminated string).
/// Call before process_create. Strings must already be in guest memory.
#[unsafe(no_mangle)]
pub extern "C" fn process_push_arg(addr: u32) {
    let s = staged_args();
    if s.argc < MAX_ARGS {
        s.argv[s.argc] = addr as u64;
        s.argc += 1;
    }
}

/// Push an envp string address (guest memory pointer to null-terminated string).
#[unsafe(no_mangle)]
pub extern "C" fn process_push_env(addr: u32) {
    let s = staged_args();
    if s.envc < MAX_ARGS {
        s.envp[s.envc] = addr as u64;
        s.envc += 1;
    }
}

/// Clear staged argv/envp.
#[unsafe(no_mangle)]
pub extern "C" fn process_clear_args() {
    let s = staged_args();
    s.argc = 0;
    s.envc = 0;
}

/// Create a new process. Loads ELF from `elf_ptr` in WASM memory.
/// Returns pointer to ThreadState, or 0 on failure.
#[unsafe(no_mangle)]
/// Debug: test ELF loading without full process setup. Returns brk_start or error code.
#[unsafe(no_mangle)]
pub extern "C" fn debug_inspect_elf(elf_ptr: u32, elf_len: u32, ram_size: u32) -> u64 {
    unsafe {
        match crate::elf::inspect_elf(elf_ptr, elf_len, ram_size as u64) {
            Ok(r) => r.brk_start,
            Err(code) => code as u64,
        }
    }
}

/// Debug: test load_elf. Returns brk_start or 0 on error.
#[unsafe(no_mangle)]
pub extern "C" fn debug_load_elf(elf_ptr: u32, elf_len: u32, ram_size: u32) -> u64 {
    unsafe {
        match crate::elf::load_elf(0, ram_size as u64, elf_ptr, elf_len) {
            Ok(r) => r.brk_start,
            Err(_) => 0,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_create(
    elf_ptr: u32,
    elf_len: u32,
    ram_size: u32,
    _stack_size: u32,
) -> u32 {
    unsafe {
        // Guest RAM base must be above kernel's WASM data segments (__heap_base).
        // When kernel shares memory with guest (import-memory), kernel data
        // occupies low addresses. Guest segments start above that.
        let base: u32 = 0;
        let elf_result = match crate::elf::load_elf(base, ram_size as u64, elf_ptr, elf_len) {
            Ok(r) => r,
            Err(_) => return 0,
        };

        crate::syscall::memory::init(elf_result.brk_start);

        // ProcessState lives in guest Memory (shared WebAssembly.Memory),
        // not in kernel Worker private memory (alloc.rs).
        // Allocate via brk in the guest address space.
        let ps_size = core::mem::size_of::<crate::types::ProcessState>() as u64;
        let ps_align = core::mem::align_of::<crate::types::ProcessState>() as u64;
        let brk = crate::syscall::memory::current_brk();
        let ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
        let new_brk = ps_addr + ps_size;
        let brk_ret = crate::syscall::memory::grow_brk(base, new_brk);
        if brk_ret < new_brk as i64 {
            return 0;
        }
        crate::guest_mem::zero_mem(base, ps_addr, ps_size as usize);
        let ps_ptr = (base as u64 + ps_addr) as u32;
        let ps = &mut *(ps_ptr as *mut crate::types::ProcessState);
        ps.pid = 2;
        ps.ppid = 1;
        ps.cwd_ino = 1;
        ps.fs_ring_base =
            crate::alloc::alloc_zeroed(crate::fs::ring_buffer::RING_BUFFER_SIZE as u32, 16);
        if ps.fs_ring_base == 0 {
            return 0;
        }
        crate::syscall::signal::init_for_process(2);

        // Wire guest_mem to ProcessState's thread_count for seqlock
        let tc_ptr = core::ptr::addr_of!(ps.thread_count);
        crate::guest_mem::init(core::ptr::null(), tc_ptr);

        crate::guest_mem::write_u32(base, ps_ptr as u64, 1);
        crate::guest_mem::write_u32(base, ps_ptr as u64 + 8, 2);
        crate::guest_mem::write_u32(base, ps_ptr as u64 + 16, 3);

        let ts_ptr = crate::alloc::alloc_zeroed(
            core::mem::size_of::<crate::types::ThreadState>() as u32,
            core::mem::align_of::<crate::types::ThreadState>() as u32,
        );
        if ts_ptr == 0 {
            return 0;
        }
        let ts = &mut *(ts_ptr as *mut crate::types::ThreadState);

        let stack_top = (ram_size - 4096) as u64;
        let random_addr = stack_top - 16;
        crate::guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);

        // Read argv/envp from staged area in guest memory (set by TS via process_push_arg/env)
        let staged = staged_args();
        let argv_addrs: &[u64] = if staged.argc > 0 {
            &staged.argv[..staged.argc]
        } else {
            // Default: argv = ["init"]
            let argv0_addr = stack_top - 64;
            crate::guest_mem::write_bytes(base, argv0_addr, b"init\0");
            staged.argv[0] = argv0_addr;
            &staged.argv[..1]
        };
        let envp_addrs: &[u64] = &staged.envp[..staged.envc];

        let sp = crate::elf::setup_stack(
            base,
            stack_top - 128 - (staged.argc as u64 + staged.envc as u64) * 16,
            argv_addrs,
            envp_addrs,
            &elf_result,
            random_addr,
        );
        // Clear staged args for next process
        staged.argc = 0;
        staged.envc = 0;

        // Create /proc/self/exe symlink pointing to argv[0]
        let proc_ino = crate::fs::memfs::resolve_path(b"/proc");
        let proc_ino = if proc_ino == 0 {
            crate::fs::memfs::create_dir(1, b"proc", 0o555)
        } else {
            proc_ino
        };
        if proc_ino > 0 {
            let self_ino = crate::fs::memfs::resolve_path(b"/proc/self");
            let self_ino = if self_ino == 0 {
                crate::fs::memfs::create_dir(proc_ino, b"self", 0o555)
            } else {
                self_ino
            };
            if self_ino > 0 {
                // Use argv[0] as the exe path; fall back to "/init"
                let mut exe_target = [0u8; 256];
                let exe_len = if staged.argc > 0 {
                    // argv[0] was already written to guest memory; read it back
                    crate::guest_mem::read_cstr(base, argv_addrs[0], &mut exe_target)
                } else {
                    0
                };
                let target = if exe_len > 0 {
                    &exe_target[..exe_len]
                } else {
                    b"/init" as &[u8]
                };
                crate::fs::memfs::create_symlink(self_ino, b"exe", target);
            }
        }

        ts.pc = elf_result.entry;
        ts.x[2] = sp;
        ts.status = STATUS_OK;
        ts.tid = 1;
        ts.process_ptr = ps_ptr;
        crate::syscall::thread::init_main_thread(ts_ptr, base);
        ts_ptr
    }
}

/// Execute `budget` guest instructions. Returns remaining budget.
#[unsafe(no_mangle)]
pub extern "C" fn thread_step(vm_ptr: u32, budget: i32) -> i32 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        if vm.process_ptr != 0 {
            let ps = &*(vm.process_ptr as *const crate::types::ProcessState);
            let tc_ptr = core::ptr::addr_of!(ps.thread_count);
            crate::guest_mem::init(core::ptr::null(), tc_ptr);
        }
        vm.status = STATUS_OK;
        crate::cpu::exec(vm, budget, None, None, None, None)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_status(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).status }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_exit_code(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).exit_code }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pc(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).pc }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a0(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[10] }
}

/// Allocate and initialize the child ThreadState for a pending
/// clone(CLONE_VM | CLONE_THREAD) handoff.
#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_from_clone(parent_vm_ptr: u32) -> u32 {
    crate::syscall::thread::spawn_from_clone(parent_vm_ptr, 0)
}

/// Return the current shared ProcessState.thread_count for the given thread.
#[unsafe(no_mangle)]
pub extern "C" fn thread_process_thread_count(vm_ptr: u32) -> u32 {
    crate::syscall::thread::process_thread_count(vm_ptr, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_process_fs(vm_ptr: u32) {
    crate::syscall::fs::process_pending_requests(vm_ptr, 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_fs(vm_ptr: u32) -> i64 {
    crate::syscall::fs::resume_from_fs(vm_ptr, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_wait4(vm_ptr: u32) -> i64 {
    crate::syscall::process::resume_wait4(vm_ptr, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_kind(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).spawn_kind }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_child_pid(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).spawn_child_pid }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_path(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).spawn_path }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_argv(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).spawn_argv }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_envp(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).spawn_envp }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_clear_spawn_handoff(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        vm.spawn_kind = SPAWN_KIND_NONE;
        vm.spawn_flags = 0;
        vm.spawn_child_pid = 0;
        vm.spawn_path = 0;
        vm.spawn_argv = 0;
        vm.spawn_envp = 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_vfork_parent(vm_ptr: u32, child_pid: i32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::process::vfork_parent_resume(vm, child_pid);
    }
}

// =============================================================================
// Blocking state accessors (for runtime Atomics.wait integration)
// =============================================================================

/// Return the guest-memory address this thread is blocked on for FUTEX_WAIT.
/// The runtime uses this to call Atomics.wait32 on the shared Memory.
#[unsafe(no_mangle)]
pub extern "C" fn thread_futex_wait_addr(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).futex_wait_addr }
}

/// Return the guest pointer to the timeout timespec for FUTEX_WAIT (0 = infinite).
#[unsafe(no_mangle)]
pub extern "C" fn thread_futex_wait_timeout(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).futex_wait_timeout }
}

/// Resume a thread after FUTEX_WAIT (woken by another thread's FUTEX_WAKE).
#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_futex_wait(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::thread::resume_futex_wait(vm, 0);
    }
}

/// Resume a thread after FUTEX_WAIT with a specific result (e.g. -ETIMEDOUT).
#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_futex_wait_result(vm_ptr: u32, result: i64) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::thread::resume_futex_wait_result(vm, 0, result);
    }
}

/// Return the sleep duration seconds (stored in fault_addr by STATUS_SLEEP).
#[unsafe(no_mangle)]
pub extern "C" fn thread_sleep_seconds(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).fault_addr }
}

/// Return the sleep duration nanoseconds (stored in fault_pc by STATUS_SLEEP).
#[unsafe(no_mangle)]
pub extern "C" fn thread_sleep_nanoseconds(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).fault_pc }
}

/// Return the ThreadRecord.blocked_addr for the given thread.
/// Returns 0 if the thread has been woken (FUTEX_WAKE clears this).
/// Returns u32::MAX if the thread record was not found.
#[unsafe(no_mangle)]
pub extern "C" fn thread_record_blocked_addr(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::thread::thread_record_blocked_addr(vm, 0)
    }
}

/// Return the child PID allocated during an active vfork.
#[unsafe(no_mangle)]
pub extern "C" fn thread_vfork_child_pid() -> i32 {
    crate::syscall::process::vfork_child_pid()
}

// =============================================================================
// MemFS operations (for Runtime.writeFile/readFile via kernel Worker)
// =============================================================================

/// Resolve an absolute path to an inode number. Returns 0 if not found.
/// `path_ptr` and `path_len` point into kernel Worker WASM linear memory.
#[unsafe(no_mangle)]
pub extern "C" fn memfs_resolve_path(path_ptr: u32, path_len: u32) -> u32 {
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    crate::fs::memfs::resolve_path(path)
}

/// Create a file under `parent_ino`. Returns the new inode number, or 0 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn memfs_create_file(parent_ino: u32, name_ptr: u32, name_len: u32) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    crate::fs::memfs::create_file(parent_ino, name, 0o644)
}

/// Write data to a file at the given offset. Returns bytes written or negative error.
#[unsafe(no_mangle)]
pub extern "C" fn memfs_write_file_at(ino: u32, offset: u64, data_ptr: u32, data_len: u32) -> i64 {
    let data = unsafe { core::slice::from_raw_parts(data_ptr as *const u8, data_len as usize) };
    crate::fs::memfs::write_file(ino, offset, data)
}

/// Read file data into a buffer. Returns bytes read or negative error.
#[unsafe(no_mangle)]
pub extern "C" fn memfs_read_file_to(ino: u32, offset: u64, buf_ptr: u32, buf_len: u32) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize) };
    crate::fs::memfs::read_file(ino, offset, buf)
}

/// Return the size of a file in bytes, or 0 if the inode doesn't exist.
#[unsafe(no_mangle)]
pub extern "C" fn memfs_file_size(ino: u32) -> u64 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.size)
}

/// Ensure a directory exists under `parent_ino`. Returns existing or new inode.
#[unsafe(no_mangle)]
pub extern "C" fn memfs_ensure_dir(parent_ino: u32, name_ptr: u32, name_len: u32, mode: u32) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    let existing = crate::fs::memfs::lookup(parent_ino, name);
    if existing != 0 {
        return existing;
    }
    crate::fs::memfs::create_dir(parent_ino, name, mode)
}

/// Create a file with initial data content. Returns the new inode number.
#[unsafe(no_mangle)]
pub extern "C" fn memfs_create_file_with_data(
    parent_ino: u32,
    name_ptr: u32,
    name_len: u32,
    data_ptr: u32,
    data_len: u32,
) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    let data = unsafe { core::slice::from_raw_parts(data_ptr as *const u8, data_len as usize) };
    crate::fs::memfs::create_file_with_data(parent_ino, name, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::TestVm;
    use alloc_crate::vec;

    #[test]
    fn status_codes_are_distinct() {
        let codes = [
            STATUS_OK,
            STATUS_FAULT,
            STATUS_FS,
            STATUS_FUTEX_WAIT,
            STATUS_PIPE_WAIT,
            STATUS_EPOLL_WAIT,
            STATUS_VFORK_WAIT,
            STATUS_EXECVE_SPAWN,
            STATUS_CLONE_SPAWN,
            STATUS_SLEEP,
            STATUS_JIT_READY,
            STATUS_CONNECT,
            STATUS_SOCKET_SEND,
            STATUS_SOCKET_RECV,
            STATUS_WAIT4,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j]);
            }
        }
    }

    #[test]
    fn spawn_handoff_exports_round_trip() {
        let mut t = TestVm::new();
        let mut elf = vec![0u8; 0x104];
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&243u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5u32.to_le_bytes());
        elf[72..80].copy_from_slice(&0x100u64.to_le_bytes());
        elf[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[96..104].copy_from_slice(&4u64.to_le_bytes());
        elf[104..112].copy_from_slice(&4u64.to_le_bytes());
        elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[0x100..0x104].copy_from_slice(&[0x13, 0x05, 0x70, 0x00]);

        assert_ne!(t.memfs.create_file(b"test", &elf), 0);
        let path_addr = t.scratch;
        t.write_mem(path_addr, b"/test\0");

        crate::syscall::process::sys_vfork(&mut t.vm, t.base);
        let ret = crate::syscall::process::sys_execve(&mut t.vm, t.base, path_addr, 0x1111, 0x2222);
        assert!(ret > 0);

        let vm_ptr = &mut t.vm as *mut crate::types::ThreadState as u32;
        assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_EXECVE);
        assert_eq!(thread_spawn_child_pid(vm_ptr), ret as i32);
        assert_eq!(thread_spawn_path(vm_ptr), path_addr);
        assert_eq!(thread_spawn_argv(vm_ptr), 0x1111);
        assert_eq!(thread_spawn_envp(vm_ptr), 0x2222);

        thread_clear_spawn_handoff(vm_ptr);
        assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_NONE);
        assert_eq!(thread_spawn_child_pid(vm_ptr), 0);
        assert_eq!(thread_spawn_path(vm_ptr), 0);
    }

    #[test]
    fn resume_vfork_parent_export_restores_parent_view() {
        let mut t = TestVm::new();
        t.vm.x[1] = 0x1234;
        t.vm.pc = 0x4000;
        crate::syscall::process::sys_vfork(&mut t.vm, t.base);
        t.vm.x[1] = 0xFFFF;
        t.vm.pc = 0x9000;

        let vm_ptr = &mut t.vm as *mut crate::types::ThreadState as u32;
        thread_resume_vfork_parent(vm_ptr, 55);
        assert_eq!(t.vm.x[1], 0x1234);
        assert_eq!(t.vm.pc, 0x4000);
        assert_eq!(t.vm.x[10], 55);
        assert_eq!(t.vm.status, STATUS_OK);
    }

    #[test]
    fn fd_types_are_distinct() {
        let types = [
            FD_TYPE_NONE,
            FD_TYPE_STDOUT,
            FD_TYPE_STDERR,
            FD_TYPE_FILE,
            FD_TYPE_DIR,
            FD_TYPE_DEVNULL,
            FD_TYPE_PIPE,
            FD_TYPE_EPOLL,
            FD_TYPE_SOCKET,
            FD_TYPE_EVENTFD,
            FD_TYPE_TIMERFD,
            FD_TYPE_PTY_MASTER,
            FD_TYPE_PTY_SLAVE,
            FD_TYPE_INOTIFY,
        ];
        for i in 0..types.len() {
            for j in (i + 1)..types.len() {
                assert_ne!(types[i], types[j]);
            }
        }
    }

    #[test]
    fn error_codes_are_negative() {
        assert!(ENOENT < 0);
        assert!(EBADF < 0);
        assert!(EINVAL < 0);
        assert!(ENOMEM < 0);
        assert!(ENOSYS < 0);
    }

    #[test]
    fn clone_flags_no_overlap() {
        assert_eq!(CLONE_VM & CLONE_THREAD, 0);
        assert_eq!(CLONE_VM & CLONE_VFORK, 0);
        assert_eq!(CLONE_THREAD & CLONE_VFORK, 0);
    }
}
