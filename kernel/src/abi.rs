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
pub const STATUS_FLOCK_WAIT: i32 = 32;

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

const ELF_EI_CLASS: usize = 4;
const ELF_EI_DATA: usize = 5;
const ELF_E_PHOFF: usize = 32;
const ELF_E_PHENTSIZE: usize = 54;
const ELF_E_PHNUM: usize = 56;
const ELF_PH_TYPE: usize = 0;
const ELF_PH_OFFSET: usize = 8;
const ELF_PH_FILESZ: usize = 32;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const PT_INTERP: u32 = 3;

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
export_const!(abi_status_flock_wait, STATUS_FLOCK_WAIT);
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
export_const_u64!(abi_sys_setpgid, SYS_SETPGID);
export_const_u64!(abi_sys_setsid, SYS_SETSID);
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

/// Raise CLOCK_MONOTONIC to at least `ticks`.
#[unsafe(no_mangle)]
pub extern "C" fn sync_monotonic_ticks_floor(ticks: u64) {
    crate::syscall::time::sync_monotonic_ticks_floor(ticks);
}

/// Initialize kernel state. Must be called once after WASM instantiation.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_init(heap_base: u32) {
    unsafe {
        crate::alloc::init(heap_base);
        crate::guest_mem::init(core::ptr::null(), core::ptr::null(), core::ptr::null());
    }
    crate::syscall::memory::init(0);
    crate::syscall::process::init();
    crate::syscall::time::init();
    crate::syscall::thread::init();
    crate::syscall::signal::init();
    crate::syscall::epoll::init();
    crate::syscall::pipe::init();
    crate::syscall::socket::init();
    crate::net::ring_buffer::init();
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
pub extern "C" fn kernel_ofd_table_bytes() -> u32 {
    crate::fs::fd_table::ofd_table_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_ptr() -> u32 {
    crate::fs::memfs::memfs_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_header_bytes() -> u32 {
    crate::fs::memfs::memfs_header_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_inodes_ptr() -> u32 {
    crate::fs::memfs::memfs_inodes_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_inodes_bytes() -> u32 {
    crate::fs::memfs::memfs_inodes_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_first_child_ptr() -> u32 {
    crate::fs::memfs::memfs_first_child_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_first_child_bytes() -> u32 {
    crate::fs::memfs::memfs_first_child_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_dir_entries_ptr() -> u32 {
    crate::fs::memfs::memfs_dir_entries_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_dir_entries_bytes() -> u32 {
    crate::fs::memfs::memfs_dir_entries_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_data_ptr() -> u32 {
    crate::fs::memfs::memfs_data_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_memfs_data_bytes() -> u32 {
    crate::fs::memfs::memfs_data_bytes()
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
pub extern "C" fn kernel_epoll_table_bytes() -> u32 {
    crate::syscall::epoll::epoll_table_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_epoll_instance_bytes() -> u32 {
    crate::syscall::epoll::epoll_instance_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_socket_table_ptr() -> u32 {
    crate::syscall::socket::socket_table_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_socket_table_bytes() -> u32 {
    crate::syscall::socket::socket_table_bytes()
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
pub extern "C" fn kernel_pipe_region_bytes() -> u32 {
    crate::syscall::pipe::pipe_region_bytes()
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
pub extern "C" fn kernel_net_buf_pool_bytes() -> u32 {
    crate::net::ring_buffer::net_buffer_pool_bytes()
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
pub extern "C" fn kernel_sig_slots_bytes() -> u32 {
    crate::syscall::signal::signal_slots_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_signal_action_table_bytes() -> u32 {
    crate::syscall::signal::signal_action_table_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_pending_ptr() -> u32 {
    crate::syscall::signal::process_pending_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_pending_bytes() -> u32 {
    crate::syscall::signal::process_pending_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_runtime_state_ptr() -> u32 {
    crate::syscall::process::process_runtime_state_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_process_runtime_state_bytes() -> u32 {
    crate::syscall::process::process_runtime_state_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_time_state_ptr() -> u32 {
    crate::syscall::time::time_state_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_time_state_bytes() -> u32 {
    crate::syscall::time::time_state_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_reset_memfs() {
    crate::fs::memfs::reset();
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
// Staged argv/envp sources for process_create
// =========================================================================

const MAX_ARGS: usize = 64;
const GUEST_GUARD_BYTES: u64 = 4 * 1024 * 1024;
const GUEST_ADDR_LIMIT: u64 = 0x8000_0000;
const LINEAR_MEMORY_LIMIT: u64 = 0x1_0000_0000;

struct StagedArgs {
    argv: [u32; MAX_ARGS],
    envp: [u32; MAX_ARGS],
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

fn process_guest_base_for_ram(ram_size: u32) -> u32 {
    let _ = ram_size;
    let aligned =
        ((crate::alloc::heap_ptr() as u64 + GUEST_GUARD_BYTES + 0xF_FFFF) & !0xF_FFFF) as u32;
    if aligned as u64 + GUEST_ADDR_LIMIT > LINEAR_MEMORY_LIMIT {
        0
    } else {
        aligned
    }
}

fn process_guest_ram_size(ram_size: u32, guest_base: u32) -> u64 {
    let _ = guest_base;
    ram_size as u64
}

fn page_align_up(len: u64) -> u64 {
    (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn process_stack_capacity(stack_size: u32) -> u64 {
    let usable = page_align_up((stack_size as u64).max(64 * 1024));
    usable.saturating_sub(PAGE_SIZE)
}

fn process_stack_setup_bytes(argc: usize, envc: usize) -> u64 {
    let auxv_size = 7u64 * 16; // 6 entries + AT_NULL
    let total_entries = (1 + argc + 1 + envc + 1) as u64; // argc + argv + NULL + envp + NULL
    total_entries * 8 + auxv_size
}

unsafe fn staged_cstr_len(ptr: u32) -> usize {
    let src = ptr as *const u8;
    let mut len = 0usize;
    while unsafe { *src.add(len) } != 0 {
        len += 1;
    }
    len + 1
}

unsafe fn staged_cstr_bytes_total(ptrs: &[u32]) -> usize {
    ptrs.iter()
        .copied()
        .map(|ptr| unsafe { staged_cstr_len(ptr) })
        .sum()
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .map(u16::from_le_bytes)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_le_bytes)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .map(u64::from_le_bytes)
}

unsafe fn read_process_create_interp_path(elf_ptr: u32, elf_len: u32) -> Option<Vec<u8>> {
    if elf_len < 64 {
        return None;
    }
    let elf = unsafe { core::slice::from_raw_parts(elf_ptr as *const u8, elf_len as usize) };
    if elf[0] != 0x7f || elf[1] != b'E' || elf[2] != b'L' || elf[3] != b'F' {
        return None;
    }
    if elf[ELF_EI_CLASS] != ELFCLASS64 || elf[ELF_EI_DATA] != ELFDATA2LSB {
        return None;
    }
    let ph_off = read_u64_le(elf, ELF_E_PHOFF)? as usize;
    let ph_entsize = read_u16_le(elf, ELF_E_PHENTSIZE)? as usize;
    let ph_num = read_u16_le(elf, ELF_E_PHNUM)? as usize;
    if ph_entsize < 56 {
        return None;
    }
    let ph_size = ph_num.checked_mul(ph_entsize)?;
    let ph_end = ph_off.checked_add(ph_size)?;
    if ph_end > elf_len as usize {
        return None;
    }
    for index in 0..ph_num {
        let start = ph_off + index * ph_entsize;
        let ph = &elf[start..start + ph_entsize];
        if read_u32_le(ph, ELF_PH_TYPE) != Some(PT_INTERP) {
            continue;
        }
        let p_offset = read_u64_le(ph, ELF_PH_OFFSET)? as usize;
        let p_filesz = read_u64_le(ph, ELF_PH_FILESZ)? as usize;
        let p_end = p_offset.checked_add(p_filesz)?;
        if p_filesz == 0 || p_end > elf_len as usize {
            return None;
        }
        let mut interp = elf[p_offset..p_end].to_vec();
        if let Some(nul) = interp.iter().position(|b| *b == 0) {
            interp.truncate(nul);
        }
        if interp.is_empty() {
            return None;
        }
        return Some(interp);
    }
    None
}

unsafe fn write_staged_cstrings(base: u32, start: u64, ptrs: &[u32], out: &mut [u64]) -> u64 {
    let mut cursor = start;
    for (idx, ptr) in ptrs.iter().copied().enumerate() {
        let len = unsafe { staged_cstr_len(ptr) };
        let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
        unsafe {
            crate::guest_mem::write_bytes(base, cursor, bytes);
        }
        out[idx] = cursor;
        cursor += len as u64;
    }
    cursor
}

/// Push an argv string source pointer (kernel scratch pointer to a null-terminated string).
/// Call before process_create. The source bytes may live anywhere in linear memory.
#[unsafe(no_mangle)]
pub extern "C" fn process_push_arg(addr: u32) {
    let s = staged_args();
    if s.argc < MAX_ARGS {
        s.argv[s.argc] = addr;
        s.argc += 1;
    }
}

/// Push an envp string source pointer (kernel scratch pointer to a null-terminated string).
#[unsafe(no_mangle)]
pub extern "C" fn process_push_env(addr: u32) {
    let s = staged_args();
    if s.envc < MAX_ARGS {
        s.envp[s.envc] = addr;
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

#[unsafe(no_mangle)]
pub extern "C" fn process_guest_base(ram_size: u32) -> u32 {
    process_guest_base_for_ram(ram_size)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_inspect_elf_brk(elf_ptr: u32, elf_len: u32, ram_size: u32) -> u64 {
    unsafe {
        let guest_base = process_guest_base_for_ram(ram_size);
        if guest_base == 0 {
            return 0;
        }
        match crate::elf::inspect_elf(
            elf_ptr,
            elf_len,
            process_guest_ram_size(ram_size, guest_base),
        ) {
            Ok(r) => r.brk_start,
            Err(_) => 0,
        }
    }
}

/// Create a new process. Loads ELF from `elf_ptr` in WASM memory.
/// Returns pointer to ThreadState, or 0 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn process_create(
    elf_ptr: u32,
    elf_len: u32,
    ram_size: u32,
    stack_size: u32,
) -> u32 {
    unsafe {
        // Guest RAM lives above the kernel's reserved linear-memory region.
        let base = process_guest_base_for_ram(ram_size);
        if base == 0 {
            return 0;
        }
        let guest_ram_size = process_guest_ram_size(ram_size, base);
        let main_inspected = match crate::elf::inspect_elf(elf_ptr, elf_len, guest_ram_size) {
            Ok(r) => r,
            Err(_) => return 0,
        };
        let mut load_ptr = elf_ptr;
        let mut load_len = elf_len;
        let mut interpreter_handoff = false;
        let load_brk_start = match read_process_create_interp_path(elf_ptr, elf_len) {
            Some(interp_path) => {
                let interp_ino = crate::fs::memfs::resolve_path(&interp_path);
                if interp_ino == 0 {
                    return 0;
                }
                let interp_st = match crate::fs::memfs::stat(interp_ino) {
                    Some(st) if st.mode & crate::fs::memfs::S_IFMT == crate::fs::memfs::S_IFREG => st,
                    _ => return 0,
                };
                let interp_len = match u32::try_from(interp_st.size) {
                    Ok(len) if len > 0 => len,
                    _ => return 0,
                };
                let interp_ptr = crate::alloc::alloc_zeroed(interp_len, 16);
                if interp_ptr == 0 {
                    return 0;
                }
                let interp_buf =
                    core::slice::from_raw_parts_mut(interp_ptr as *mut u8, interp_len as usize);
                if crate::fs::memfs::read_file(interp_ino, 0, interp_buf) != interp_len as i64 {
                    return 0;
                }
                let interp_inspected =
                    match crate::elf::inspect_elf(interp_ptr, interp_len, guest_ram_size) {
                        Ok(r) => r,
                        Err(_) => return 0,
                    };
                load_ptr = interp_ptr;
                load_len = interp_len;
                interpreter_handoff = true;
                interp_inspected.brk_start
            }
            None => main_inspected.brk_start,
        };
        if !crate::syscall::memory::ensure_guest_memory_capacity(base, load_brk_start) {
            return 0;
        }
        let mut elf_result = match crate::elf::load_elf(base, guest_ram_size, load_ptr, load_len) {
            Ok(r) => r,
            Err(_) => return 0,
        };
        if interpreter_handoff {
            elf_result.aux_entry = main_inspected.entry;
            elf_result.aux_phdr_addr = main_inspected.phdr_addr;
            elf_result.aux_phent = main_inspected.phent;
            elf_result.aux_phnum = main_inspected.phnum;
        }

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

        // Wire guest_mem to ProcessState reservation metadata and thread_count.
        let gen_ptr =
            core::ptr::addr_of!(ps.reservation_gen) as *const core::sync::atomic::AtomicU32;
        let lock_ptr =
            core::ptr::addr_of!(ps.reservation_lock) as *const core::sync::atomic::AtomicU32;
        let tc_ptr = core::ptr::addr_of!(ps.thread_count);
        crate::guest_mem::init(gen_ptr, lock_ptr, tc_ptr);

        let ts_ptr = crate::alloc::alloc_zeroed(
            core::mem::size_of::<crate::types::ThreadState>() as u32,
            core::mem::align_of::<crate::types::ThreadState>() as u32,
        );
        if ts_ptr == 0 {
            return 0;
        }
        let ts = &mut *(ts_ptr as *mut crate::types::ThreadState);
        ts.lr_addr = u64::MAX;

        let stack_top =
            crate::syscall::memory::map_initial_stack(base, guest_ram_size, stack_size as u64);
        if stack_top < 0 {
            return 0;
        }
        let stack_top = stack_top as u64;
        let random_addr = stack_top - 16;
        crate::guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);

        let staged = staged_args();
        let staged_argc = staged.argc;
        let staged_envc = staged.envc;
        let argc = if staged_argc > 0 { staged_argc } else { 1 };
        let envc = staged_envc;
        let string_bytes = if staged_argc > 0 {
            staged_cstr_bytes_total(&staged.argv[..staged_argc])
        } else {
            b"init\0".len()
        } + staged_cstr_bytes_total(&staged.envp[..staged_envc]);
        let required_stack_bytes =
            process_stack_setup_bytes(argc, envc) + string_bytes as u64 + 256;
        if required_stack_bytes > process_stack_capacity(stack_size) {
            staged.argc = 0;
            staged.envc = 0;
            return 0;
        }

        let strings_end = stack_top.saturating_sub(128);
        let strings_start = align_down(strings_end.saturating_sub(string_bytes as u64), 16);
        let stack_setup_top = strings_start.saturating_sub(128);
        let mut argv_addrs = [0u64; MAX_ARGS];
        let mut envp_addrs = [0u64; MAX_ARGS];
        let cursor = if staged_argc > 0 {
            write_staged_cstrings(
                base,
                strings_start,
                &staged.argv[..staged_argc],
                &mut argv_addrs[..staged_argc],
            )
        } else {
            crate::guest_mem::write_bytes(base, strings_start, b"init\0");
            argv_addrs[0] = strings_start;
            strings_start + b"init\0".len() as u64
        };
        write_staged_cstrings(
            base,
            cursor,
            &staged.envp[..staged_envc],
            &mut envp_addrs[..staged_envc],
        );

        let sp = crate::elf::setup_stack(
            base,
            stack_setup_top,
            &argv_addrs[..argc],
            &envp_addrs[..envc],
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
                let exe_len = crate::guest_mem::read_cstr(base, argv_addrs[0], &mut exe_target);
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
        ts.x[4] = elf_result.tls_base;
        ts.status = STATUS_OK;
        ts.tid = 1;
        ts.tls_base = elf_result.tls_base;
        ts.guest_base = base;
        ts.process_ptr = ps_addr as u32;
        crate::fs::fd_table::init_stdio(base, ts);
        crate::syscall::thread::init_main_thread(ts_ptr, base);
        ts_ptr
    }
}

/// Execute `budget` guest instructions. Returns remaining budget.
#[unsafe(no_mangle)]
pub extern "C" fn thread_step(vm_ptr: u32, budget: i32) -> i32 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        let base = vm.guest_base;
        if vm.process_ptr != 0 {
            let ps = &*((base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState);
            let gen_ptr =
                core::ptr::addr_of!(ps.reservation_gen) as *const core::sync::atomic::AtomicU32;
            let lock_ptr =
                core::ptr::addr_of!(ps.reservation_lock) as *const core::sync::atomic::AtomicU32;
            let tc_ptr = core::ptr::addr_of!(ps.thread_count);
            crate::guest_mem::init(gen_ptr, lock_ptr, tc_ptr);
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
pub extern "C" fn thread_term_signal(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).term_signal }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pc(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).pc }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_sig_pending(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).sig_pending }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_sp(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[2] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a0(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[10] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a1(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[11] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a2(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[12] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a3(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[13] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a4(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[14] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a5(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[15] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a6(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[16] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a7(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).x[17] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_blocked_fd(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).blocked_fd }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_blocked_ofd_id(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).blocked_ofd_id }
}

/// Allocate and initialize the child ThreadState for a pending
/// clone(CLONE_VM | CLONE_THREAD) handoff.
#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_from_clone(parent_vm_ptr: u32) -> u32 {
    unsafe {
        let parent = &*(parent_vm_ptr as *const crate::types::ThreadState);
        crate::syscall::thread::spawn_from_clone(parent_vm_ptr, parent.guest_base)
    }
}

/// Return the current shared ProcessState.thread_count for the given thread.
#[unsafe(no_mangle)]
pub extern "C" fn thread_process_thread_count(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::thread::process_thread_count(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_process_ptr(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).process_ptr }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_state_bytes() -> u32 {
    core::mem::size_of::<crate::types::ProcessState>() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn process_thread_tid(vm_ptr: u32, slot: u32) -> i32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        if vm.process_ptr == 0 || slot as usize >= MAX_THREADS {
            return 0;
        }
        let ps =
            &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState);
        ps.threads[slot as usize].tid
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_thread_state(vm_ptr: u32, slot: u32) -> i32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        if vm.process_ptr == 0 || slot as usize >= MAX_THREADS {
            return crate::types::THREAD_NONE;
        }
        let ps =
            &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState);
        ps.threads[slot as usize].state
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_thread_vm_ptr(vm_ptr: u32, slot: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        if vm.process_ptr == 0 || slot as usize >= MAX_THREADS {
            return 0;
        }
        let ps =
            &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState);
        ps.threads[slot as usize].thread_ptr
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_effects(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::fs::pending_request_effects(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_target_ino(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::fs::pending_request_target_ino(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_opcode(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::fs::pending_request_opcode(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_path_ptr(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::fs::pending_request_path_ptr(vm_ptr, vm.guest_base) as u32
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_path_len(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::fs::pending_request_path_len(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_process_fs(vm_ptr: u32) {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::fs::process_pending_requests(vm_ptr, vm.guest_base);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_fs(vm_ptr: u32) -> i64 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::fs::resume_from_fs(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_wait4(vm_ptr: u32) -> i64 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::process::resume_wait4(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_epoll_wait_timeout(vm_ptr: u32) -> i64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).epoll_timeout_ms }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_epoll_wait_timeout(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::epoll::resume_timeout(vm);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_interrupt_epoll_wait(vm_ptr: u32, errno: i32) -> i32 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        vm.epoll_timeout_ms = 0;
        vm.epoll_maxevents = 0;
        vm.fault_pc = 0;
        vm.fault_addr = 0;
        crate::syscall::signal::patch_current_signal_frame_a0(vm, vm.guest_base, errno as i64)
            as i32
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_blocked_syscall(vm_ptr: u32) -> i64 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        let saved_fd_entry =
            crate::fs::fd_table::patch_blocked_fd_entry_for_resume(vm.guest_base, vm);
        let status = if vm.status == STATUS_EPOLL_WAIT {
            crate::syscall::epoll::resume_wait(vm, vm.guest_base);
            vm.status
        } else {
            vm.status = STATUS_OK;
            crate::syscall::dispatch(vm, vm.guest_base)
        };
        crate::fs::fd_table::restore_blocked_fd_entry(vm.guest_base, vm, saved_fd_entry);
        vm.status = status;
        if !crate::fs::fd_table::blocked_status_uses_ofd_pin(status) {
            crate::fs::fd_table::clear_blocked_ofd_pin(vm);
        }
        if status == STATUS_OK {
            vm.x[10] as i64
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_connect_result(vm_ptr: u32, result: i64) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::socket::resume_connect_result(vm, vm.guest_base, result);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_kind(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).spawn_kind }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_clone_flags(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).clone_flags }
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
pub extern "C" fn thread_set_execve_handoff(
    vm_ptr: u32,
    process_ptr: u32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        vm.process_ptr = process_ptr;
        vm.spawn_kind = SPAWN_KIND_EXECVE;
        vm.spawn_path = path_addr;
        vm.spawn_argv = argv_addr;
        vm.spawn_envp = envp_addr;
    }
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

#[unsafe(no_mangle)]
pub extern "C" fn thread_restore_vfork_parent_without_cleanup(vm_ptr: u32, child_pid: i32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::process::vfork_parent_restore_without_cleanup(vm, child_pid);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_complete_execve_handoff(vm_ptr: u32) -> i64 {
    unsafe {
        crate::syscall::process::clear_vfork_runtime_state();
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::process::complete_execve_in_place_from_handoff(
            vm,
            vm.guest_base,
            crate::syscall::process::EXECVE_RAM_LIMIT,
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_record_child_exit(pid: i32, wait_status: i32) {
    crate::syscall::process::record_child_exit(pid, wait_status);
}

#[unsafe(no_mangle)]
pub extern "C" fn process_current_pid(vm_ptr: u32) -> i32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::process::current_process_pid(vm, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_current_ppid(vm_ptr: u32) -> i32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::process::current_process_ppid(vm, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_current_pgid(vm_ptr: u32) -> i32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::process::current_process_pgid(vm, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_current_sid(vm_ptr: u32) -> i32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        crate::syscall::process::current_process_sid(vm, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_current_did_exec(vm_ptr: u32) -> i32 {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        i32::from(crate::syscall::process::current_process_did_exec(
            vm,
            vm.guest_base,
        ))
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_rewrite_child_pid(
    vm_ptr: u32,
    old_pid: i32,
    new_pid: i32,
    next_pid: i32,
) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::process::rewrite_child_pid(vm, vm.guest_base, old_pid, new_pid, next_pid);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_reset_lifecycle(
    vm_ptr: u32,
    pid: i32,
    ppid: i32,
    next_pid: i32,
    pgid: i32,
    sid: i32,
    did_exec: i32,
) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::process::reset_process_lifecycle(
            vm,
            vm.guest_base,
            pid,
            ppid,
            next_pid,
            pgid,
            sid,
            did_exec != 0,
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_upsert_process_entry(
    pid: i32,
    ppid: i32,
    pgid: i32,
    sid: i32,
    did_exec: i32,
) {
    crate::syscall::process::upsert_process_entry(pid, ppid, pgid, sid, did_exec != 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn process_remove_process_entry(pid: i32) {
    crate::syscall::process::remove_process_entry(pid);
}

fn process_state_from_vm(vm_ptr: u32) -> Option<&'static mut crate::types::ProcessState> {
    unsafe {
        let vm = &*(vm_ptr as *const crate::types::ThreadState);
        if vm.process_ptr == 0 {
            None
        } else {
            Some(
                &mut *((vm.guest_base as u64 + vm.process_ptr as u64)
                    as *mut crate::types::ProcessState),
            )
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_stdin_pipe(vm_ptr: u32) -> u32 {
    process_state_from_vm(vm_ptr).map_or(0, |ps| ps.stdin_pipe_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_stdout_pipe(vm_ptr: u32) -> u32 {
    process_state_from_vm(vm_ptr).map_or(0, |ps| ps.stdout_pipe_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_stderr_pipe(vm_ptr: u32) -> u32 {
    process_state_from_vm(vm_ptr).map_or(0, |ps| ps.stderr_pipe_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_set_host_stdio(
    vm_ptr: u32,
    stdin_pipe_slot: u32,
    stdout_pipe_slot: u32,
    stderr_pipe_slot: u32,
) {
    if let Some(ps) = process_state_from_vm(vm_ptr) {
        ps.stdin_pipe_slot = stdin_pipe_slot;
        ps.stdout_pipe_slot = stdout_pipe_slot;
        ps.stderr_pipe_slot = stderr_pipe_slot;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_cwd_ino(vm_ptr: u32) -> u32 {
    process_state_from_vm(vm_ptr).map_or(1, |ps| if ps.cwd_ino == 0 { 1 } else { ps.cwd_ino })
}

#[unsafe(no_mangle)]
pub extern "C" fn process_set_cwd_ino(vm_ptr: u32, ino: u32) {
    if let Some(ps) = process_state_from_vm(vm_ptr) {
        ps.cwd_ino = ino;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_fd_ofd_id(vm_ptr: u32, fd: u32) -> u32 {
    process_state_from_vm(vm_ptr)
        .and_then(|ps| ps.fd_table.get(fd as usize))
        .map_or(0, |entry| entry.ofd_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_fd_flags(vm_ptr: u32, fd: u32) -> u32 {
    process_state_from_vm(vm_ptr)
        .and_then(|ps| ps.fd_table.get(fd as usize))
        .map_or(0, |entry| entry.fd_flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_set_fd_entry(vm_ptr: u32, fd: u32, ofd_id: u32, fd_flags: u32) {
    if let Some(ps) = process_state_from_vm(vm_ptr) {
        if let Some(entry) = ps.fd_table.get_mut(fd as usize) {
            entry.ofd_id = ofd_id;
            entry.fd_flags = fd_flags;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_retain_ofd(ofd_id: u32) {
    crate::fs::fd_table::retain_ofd_id(ofd_id);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_release_ofd(ofd_id: u32) {
    crate::fs::fd_table::release_ofd_id(ofd_id);
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_fd_type(ofd_id: u32) -> i32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.fd_type)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_host_fd(ofd_id: u32) -> i32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(-1, |ofd| ofd.host_fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_status_flags(ofd_id: u32) -> i32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.status_flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_ino(ofd_id: u32) -> u32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.ino)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_refcount(ofd_id: u32) -> i32 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.refcount)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_ofd_offset(ofd_id: u32) -> i64 {
    crate::fs::fd_table::get_ofd_by_id(ofd_id).map_or(0, |ofd| ofd.offset)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_release_host_stdio(vm_ptr: u32) {
    if let Some(ps) = process_state_from_vm(vm_ptr) {
        // stdin/stdout/stderr_pipe_slot are the runtime-side handles for the
        // same pipe slots that fd 0/1/2 already close through close(2) /
        // exit(2). Clearing these slots here must not close the pipe a second
        // time, otherwise shared subprocess pipes underflow their open counts.
        ps.stdin_pipe_slot = 0;
        ps.stdout_pipe_slot = 0;
        ps.stderr_pipe_slot = 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_inject_http(vm_ptr: u32, port: u32, req_ptr: u32, req_len: u32) -> i32 {
    let request = unsafe { core::slice::from_raw_parts(req_ptr as *const u8, req_len as usize) };
    crate::syscall::socket::inject_http_connection(vm_ptr, port as u16, request)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_read_http_response(
    vm_ptr: u32,
    conn_id: i32,
    dst_ptr: u32,
    dst_len: u32,
) -> i32 {
    let dst = unsafe { core::slice::from_raw_parts_mut(dst_ptr as *mut u8, dst_len as usize) };
    crate::syscall::socket::read_http_response(vm_ptr, conn_id, dst)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_close_http_connection(vm_ptr: u32, conn_id: i32) {
    crate::syscall::socket::close_http_connection(vm_ptr, conn_id);
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

/// Return the futex word value captured at FUTEX_WAIT entry.
#[unsafe(no_mangle)]
pub extern "C" fn thread_futex_wait_expected(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const crate::types::ThreadState)).futex_wait_expected }
}

/// Resume a thread after FUTEX_WAIT (woken by another thread's FUTEX_WAKE).
#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_futex_wait(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::thread::resume_futex_wait(vm, vm.guest_base);
    }
}

/// Resume a thread after FUTEX_WAIT with a specific result (e.g. -ETIMEDOUT).
#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_futex_wait_result(vm_ptr: u32, result: i64) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut crate::types::ThreadState);
        crate::syscall::thread::resume_futex_wait_result(vm, vm.guest_base, result);
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
        crate::syscall::thread::thread_record_blocked_addr(vm, vm.guest_base)
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

#[unsafe(no_mangle)]
pub extern "C" fn memfs_reserve_inode_until(target_ino: u32) -> i64 {
    crate::fs::memfs::reserve_inode_until(target_ino)
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

#[unsafe(no_mangle)]
pub extern "C" fn memfs_truncate_file(ino: u32, size: u64) -> i64 {
    crate::fs::memfs::truncate(ino, size)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_set_file_size_shallow(ino: u32, size: u64) -> i64 {
    crate::fs::memfs::set_file_size_shallow(ino, size)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_inode_mode(ino: u32) -> u32 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_inode_nlink(ino: u32) -> u32 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.nlink)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_inode_uid(ino: u32) -> u32 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.uid)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_inode_gid(ino: u32) -> u32 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.gid)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_read_link(ino: u32, buf_ptr: u32, buf_len: u32) -> i64 {
    if buf_ptr == 0 {
        return EFAULT;
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize) };
    crate::fs::memfs::read_link(ino, buf) as i64
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_set_mode(ino: u32, mode: u32) -> i64 {
    crate::fs::memfs::set_mode(ino, mode)
}

/// Ensure a directory exists under `parent_ino`. Returns existing or new inode.
#[unsafe(no_mangle)]
pub extern "C" fn memfs_ensure_dir(
    parent_ino: u32,
    name_ptr: u32,
    name_len: u32,
    mode: u32,
) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    let existing = crate::fs::memfs::lookup(parent_ino, name);
    if existing != 0 {
        return existing;
    }
    crate::fs::memfs::create_dir(parent_ino, name, mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_create_symlink(
    parent_ino: u32,
    name_ptr: u32,
    name_len: u32,
    target_ptr: u32,
    target_len: u32,
) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    let target =
        unsafe { core::slice::from_raw_parts(target_ptr as *const u8, target_len as usize) };
    crate::fs::memfs::create_symlink(parent_ino, name, target)
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

/// Write NUL-separated directory entry names into `buf_ptr`.
/// Returns bytes written or negative errno.
#[unsafe(no_mangle)]
pub extern "C" fn memfs_readdir_names(dir_ino: u32, buf_ptr: u32, buf_len: u32) -> i64 {
    if buf_ptr == 0 {
        return EFAULT;
    }

    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize) };
    let mut written = 0usize;
    let mut overflow = false;

    let result = crate::fs::memfs::readdir(dir_ino, |name, _ino| {
        let needed = name.len().saturating_add(1);
        if overflow || written.saturating_add(needed) > buf.len() {
            overflow = true;
            return;
        }

        buf[written..written + name.len()].copy_from_slice(name);
        written += name.len();
        buf[written] = 0;
        written += 1;
    });

    if result < 0 {
        return result;
    }
    if overflow {
        return ENOSPC;
    }

    written as i64
}
