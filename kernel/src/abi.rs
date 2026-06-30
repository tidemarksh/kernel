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
// Fault classification
// =============================================================================
pub const FAULT_KIND_NONE: u32 = 0;
pub const FAULT_KIND_GUEST_MAPERR: u32 = 1;
pub const FAULT_KIND_GUEST_ACCERR: u32 = 2;
pub const FAULT_KIND_ILLEGAL_INSTRUCTION: u32 = 3;
pub const FAULT_KIND_GUEST_BUS: u32 = 4;

// =============================================================================
// Process spawn handoff kinds
// =============================================================================
pub const SPAWN_KIND_NONE: u32 = 0;
pub const SPAWN_KIND_EXECVE: u32 = 1;
pub const SPAWN_KIND_FORK: u32 = 2;

// =============================================================================
// Guest addressability profiles
// =============================================================================
pub const GUEST_ADDRESS_PROFILE_NONE: u32 = 0;
pub const GUEST_ADDRESS_PROFILE_MEMORY64: u32 = 2;

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
pub const FD_TYPE_SIGNALFD: i32 = 14;

// =============================================================================
// Syscall numbers (asm-generic, used by RISC-V)
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/unistd.h
// =============================================================================
pub const SYS_IO_SETUP: u64 = 0;
pub const SYS_IO_DESTROY: u64 = 1;
pub const SYS_IO_SUBMIT: u64 = 2;
pub const SYS_IO_CANCEL: u64 = 3;
pub const SYS_IO_GETEVENTS: u64 = 4;
pub const SYS_SETXATTR: u64 = 5;
pub const SYS_LSETXATTR: u64 = 6;
pub const SYS_FSETXATTR: u64 = 7;
pub const SYS_GETXATTR: u64 = 8;
pub const SYS_LGETXATTR: u64 = 9;
pub const SYS_FGETXATTR: u64 = 10;
pub const SYS_LISTXATTR: u64 = 11;
pub const SYS_LLISTXATTR: u64 = 12;
pub const SYS_FLISTXATTR: u64 = 13;
pub const SYS_REMOVEXATTR: u64 = 14;
pub const SYS_LREMOVEXATTR: u64 = 15;
pub const SYS_FREMOVEXATTR: u64 = 16;
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
pub const SYS_RENAMEAT: u64 = 38;
pub const SYS_UMOUNT2: u64 = 39;
pub const SYS_MOUNT: u64 = 40;
pub const SYS_STATFS: u64 = 43;
pub const SYS_RENAMEAT2: u64 = 276;
pub const SYS_STATX: u64 = 291;
pub const SYS_FACCESSAT: u64 = 48;
pub const SYS_CHDIR: u64 = 49;
pub const SYS_CHROOT: u64 = 51;
pub const SYS_FCHMOD: u64 = 52;
pub const SYS_FCHMODAT: u64 = 53;
pub const SYS_FCHOWNAT: u64 = 54;
pub const SYS_FCHOWN: u64 = 55;
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_CLOSE_RANGE: u64 = 436;
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
pub const SYS_FSYNC: u64 = 82;
pub const SYS_FDATASYNC: u64 = 83;
pub const SYS_TRUNCATE: u64 = 45;
pub const SYS_FTRUNCATE: u64 = 46;
pub const SYS_UTIMENSAT: u64 = 88;
pub const SYS_EXIT: u64 = 93;
pub const SYS_EXIT_GROUP: u64 = 94;
pub const SYS_WAITID: u64 = 95;
pub const SYS_SET_TID_ADDRESS: u64 = 96;
pub const SYS_GET_ROBUST_LIST: u64 = 100;
pub const SYS_SET_ROBUST_LIST: u64 = 99;
pub const SYS_FUTEX: u64 = 98;
pub const SYS_FUTEX_TIME64: u64 = 422;
pub const SYS_NANOSLEEP: u64 = 101;
pub const SYS_CLOCK_NANOSLEEP: u64 = 115;
pub const SYS_GETITIMER: u64 = 102;
pub const SYS_SETITIMER: u64 = 103;
pub const SYS_CLOCK_GETTIME: u64 = 113;
pub const SYS_GETCPU: u64 = 168;
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
pub const SYS_GETGROUPS: u64 = 158;
pub const SYS_SETGROUPS: u64 = 159;
pub const SYS_TIMES: u64 = 153;
pub const SYS_GETRLIMIT: u64 = 163;
pub const SYS_SETRLIMIT: u64 = 164;
pub const SYS_GETRUSAGE: u64 = 165;
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
pub const SYS_EXECVEAT: u64 = 281;
pub const SYS_RISCV_HWPROBE: u64 = 258;
pub const SYS_RISCV_FLUSH_ICACHE: u64 = 259;
pub const SYS_WAIT4: u64 = 260;
pub const SYS_PRLIMIT64: u64 = 261;
pub const SYS_PRCTL: u64 = 167;
pub const SYS_SETSID: u64 = 157;
pub const SYS_GETRANDOM: u64 = 278;
pub const SYS_RSEQ: u64 = 293;
pub const SYS_CLONE3: u64 = 435;
pub const SYS_SOCKET: u64 = 198;
pub const SYS_SOCKETPAIR: u64 = 199;
pub const SYS_BIND: u64 = 200;
pub const SYS_LISTEN: u64 = 201;
pub const SYS_ACCEPT4: u64 = 242;
pub const SYS_CONNECT: u64 = 203;
pub const SYS_SENDTO: u64 = 206;
pub const SYS_RECVFROM: u64 = 207;
pub const SYS_SETSOCKOPT: u64 = 208;
pub const SYS_GETSOCKOPT: u64 = 209;
pub const SYS_SHUTDOWN: u64 = 210;
pub const SYS_SENDMSG: u64 = 211;
pub const SYS_RECVMSG: u64 = 212;
pub const SYS_GETSOCKNAME: u64 = 204;
pub const SYS_GETPEERNAME: u64 = 205;
pub const SYS_PPOLL: u64 = 73;
pub const SYS_PSELECT6: u64 = 72;
pub const SYS_SIGNALFD4: u64 = 74;
pub const SYS_TIMERFD_CREATE: u64 = 85;
pub const SYS_TIMERFD_SETTIME: u64 = 86;
pub const SYS_TIMERFD_GETTIME: u64 = 87;
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
pub const CLONE_PIDFD: u64 = 0x00001000;
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
pub const MAP_NORESERVE: u64 = 0x4000;
pub const MAP_FIXED_NOREPLACE: u64 = 0x100000;

// https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/mman-common.h
pub const MADV_NORMAL: i32 = 0;
pub const MADV_RANDOM: i32 = 1;
pub const MADV_SEQUENTIAL: i32 = 2;
pub const MADV_WILLNEED: i32 = 3;
pub const MADV_DONTNEED: i32 = 4;
pub const MADV_FREE: i32 = 8;
pub const MADV_DONTFORK: i32 = 10;
pub const MADV_DOFORK: i32 = 11;

// =============================================================================
// open flags
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/fcntl.h
// =============================================================================
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0x40;
pub const O_EXCL: i32 = 0x80;
pub const O_TRUNC: i32 = 0x200;
pub const O_APPEND: i32 = 0x400;
pub const O_NONBLOCK: i32 = 0x800;
pub const O_CLOEXEC: i32 = 0x80000;
pub const TFD_TIMER_ABSTIME: u64 = 0x1;
pub const TFD_TIMER_CANCEL_ON_SET: u64 = 0x2;
pub const O_DIRECTORY: i32 = 0x10000;
pub const O_NOFOLLOW: i32 = 0x20000;
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

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
pub const MAX_THREADS: usize = 64;
pub const MAX_MMAP_REGIONS: usize = 256;
pub const MAX_SOCKETS: usize = 32;
pub const MAX_EPOLL_ENTRIES: usize = 64;
pub const MAX_EVENTFDS: usize = 16;
pub const MAX_TIMERFDS: usize = 8;
pub const MAX_SIGNALFDS: usize = 8;
pub const MAX_PIPES: usize = 64;
pub const MAX_PROCESSES: usize = 2048;

// Futex operations (https://man7.org/linux/man-pages/man2/futex.2.html)
pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_CMP_REQUEUE: u32 = 4;
pub const FUTEX_WAIT_BITSET: u32 = 9;
pub const FUTEX_WAKE_BITSET: u32 = 10;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;
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
pub const ENOTTY: i64 = -25;
pub const ETXTBSY: i64 = -26;
pub const ERANGE: i64 = -34;
pub const ENAMETOOLONG: i64 = -36;
pub const EMFILE: i64 = -24;
pub const ESPIPE: i64 = -29;
pub const ENOSPC: i64 = -28;
pub const EPIPE: i64 = -32;
pub const ENOSYS: i64 = -38;
pub const ENOTEMPTY: i64 = -39;
pub const ELOOP: i64 = -40;
pub const ENODATA: i64 = -61;
pub const ENOTSOCK: i64 = -88;
pub const EDESTADDRREQ: i64 = -89;
pub const EPROTOTYPE: i64 = -91;
pub const ENOPROTOOPT: i64 = -92;
pub const EPROTONOSUPPORT: i64 = -93;
pub const EOPNOTSUPP: i64 = -95;
pub const EAFNOSUPPORT: i64 = -97;
pub const EADDRINUSE: i64 = -98;
pub const EADDRNOTAVAIL: i64 = -99;
pub const ENOTCONN: i64 = -107;
pub const EISCONN: i64 = -106;
pub const ECONNREFUSED: i64 = -111;
pub const ETIMEDOUT: i64 = -110;
pub const EINPROGRESS: i64 = -115;

// =============================================================================
// Socket address families
// https://github.com/torvalds/linux/blob/v6.12/include/linux/socket.h
// =============================================================================
pub const AF_UNIX: u32 = 1;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
pub const AF_NETLINK: u32 = 16;

// =============================================================================
// Socket types
// https://github.com/torvalds/linux/blob/v6.12/include/linux/net.h
// =============================================================================
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
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
export_const!(abi_fault_kind_none, FAULT_KIND_NONE as i32);
export_const!(abi_fault_kind_guest_maperr, FAULT_KIND_GUEST_MAPERR as i32);
export_const!(abi_fault_kind_guest_accerr, FAULT_KIND_GUEST_ACCERR as i32);
export_const!(
    abi_fault_kind_illegal_instruction,
    FAULT_KIND_ILLEGAL_INSTRUCTION as i32
);
export_const!(abi_fault_kind_guest_bus, FAULT_KIND_GUEST_BUS as i32);
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
export_const!(abi_fd_type_signalfd, FD_TYPE_SIGNALFD);

// Syscall numbers
macro_rules! export_const_u64 {
    ($name:ident, $val:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $name() -> u64 {
            $val
        }
    };
}

export_const_u64!(abi_sys_io_setup, SYS_IO_SETUP);
export_const_u64!(abi_sys_io_destroy, SYS_IO_DESTROY);
export_const_u64!(abi_sys_io_submit, SYS_IO_SUBMIT);
export_const_u64!(abi_sys_io_cancel, SYS_IO_CANCEL);
export_const_u64!(abi_sys_io_getevents, SYS_IO_GETEVENTS);
export_const_u64!(abi_sys_setxattr, SYS_SETXATTR);
export_const_u64!(abi_sys_lsetxattr, SYS_LSETXATTR);
export_const_u64!(abi_sys_fsetxattr, SYS_FSETXATTR);
export_const_u64!(abi_sys_getxattr, SYS_GETXATTR);
export_const_u64!(abi_sys_lgetxattr, SYS_LGETXATTR);
export_const_u64!(abi_sys_fgetxattr, SYS_FGETXATTR);
export_const_u64!(abi_sys_listxattr, SYS_LISTXATTR);
export_const_u64!(abi_sys_llistxattr, SYS_LLISTXATTR);
export_const_u64!(abi_sys_flistxattr, SYS_FLISTXATTR);
export_const_u64!(abi_sys_removexattr, SYS_REMOVEXATTR);
export_const_u64!(abi_sys_lremovexattr, SYS_LREMOVEXATTR);
export_const_u64!(abi_sys_fremovexattr, SYS_FREMOVEXATTR);
export_const_u64!(abi_sys_openat, SYS_OPENAT);
export_const_u64!(abi_sys_close, SYS_CLOSE);
export_const_u64!(abi_sys_close_range, SYS_CLOSE_RANGE);
export_const_u64!(abi_sys_read, SYS_READ);
export_const_u64!(abi_sys_write, SYS_WRITE);
export_const_u64!(abi_sys_mmap, SYS_MMAP);
export_const_u64!(abi_sys_munmap, SYS_MUNMAP);
export_const_u64!(abi_sys_msync, SYS_MSYNC);
export_const_u64!(abi_sys_brk, SYS_BRK);
export_const_u64!(abi_sys_clone, SYS_CLONE);
export_const_u64!(abi_sys_execve, SYS_EXECVE);
export_const_u64!(abi_sys_execveat, SYS_EXECVEAT);
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
export_const_u64!(abi_sys_clock_nanosleep, SYS_CLOCK_NANOSLEEP);
export_const_u64!(abi_sys_clock_gettime, SYS_CLOCK_GETTIME);
export_const_u64!(abi_sys_getcpu, SYS_GETCPU);
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
export_const_u64!(abi_sys_umount2, SYS_UMOUNT2);
export_const_u64!(abi_sys_mount, SYS_MOUNT);
export_const_u64!(abi_sys_statfs, SYS_STATFS);
export_const_u64!(abi_sys_renameat, SYS_RENAMEAT);
export_const_u64!(abi_sys_renameat2, SYS_RENAMEAT2);
export_const_u64!(abi_sys_statx, SYS_STATX);
export_const_u64!(abi_sys_faccessat, SYS_FACCESSAT);
export_const_u64!(abi_sys_chdir, SYS_CHDIR);
export_const_u64!(abi_sys_fchmod, SYS_FCHMOD);
export_const_u64!(abi_sys_fchmodat, SYS_FCHMODAT);
export_const_u64!(abi_sys_fchownat, SYS_FCHOWNAT);
export_const_u64!(abi_sys_fchown, SYS_FCHOWN);
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
export_const_u64!(abi_sys_fsync, SYS_FSYNC);
export_const_u64!(abi_sys_fdatasync, SYS_FDATASYNC);
export_const_u64!(abi_sys_truncate, SYS_TRUNCATE);
export_const_u64!(abi_sys_ftruncate, SYS_FTRUNCATE);
export_const_u64!(abi_sys_utimensat, SYS_UTIMENSAT);
export_const_u64!(abi_sys_set_tid_address, SYS_SET_TID_ADDRESS);
export_const_u64!(abi_sys_get_robust_list, SYS_GET_ROBUST_LIST);
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
export_const_u64!(abi_sys_getgroups, SYS_GETGROUPS);
export_const_u64!(abi_sys_setgroups, SYS_SETGROUPS);
export_const_u64!(abi_sys_times, SYS_TIMES);
export_const_u64!(abi_sys_getrusage, SYS_GETRUSAGE);
export_const_u64!(abi_sys_getppid, SYS_GETPPID);
export_const_u64!(abi_sys_getuid, SYS_GETUID);
export_const_u64!(abi_sys_geteuid, SYS_GETEUID);
export_const_u64!(abi_sys_getgid, SYS_GETGID);
export_const_u64!(abi_sys_getegid, SYS_GETEGID);
export_const_u64!(abi_sys_sysinfo, SYS_SYSINFO);
export_const_u64!(abi_sys_mremap, SYS_MREMAP);
export_const_u64!(abi_sys_mprotect, SYS_MPROTECT);
export_const_u64!(abi_sys_riscv_hwprobe, SYS_RISCV_HWPROBE);
export_const_u64!(abi_sys_prctl, SYS_PRCTL);
export_const_u64!(abi_sys_getrandom, SYS_GETRANDOM);
export_const_u64!(abi_sys_rseq, SYS_RSEQ);
export_const_u64!(abi_sys_clone3, SYS_CLONE3);
export_const_u64!(abi_sys_socket, SYS_SOCKET);
export_const_u64!(abi_sys_socketpair, SYS_SOCKETPAIR);
export_const_u64!(abi_sys_bind, SYS_BIND);
export_const_u64!(abi_sys_listen, SYS_LISTEN);
export_const_u64!(abi_sys_accept4, SYS_ACCEPT4);
export_const_u64!(abi_sys_connect, SYS_CONNECT);
export_const_u64!(abi_sys_sendto, SYS_SENDTO);
export_const_u64!(abi_sys_recvfrom, SYS_RECVFROM);
export_const_u64!(abi_sys_sendmsg, SYS_SENDMSG);
export_const_u64!(abi_sys_recvmsg, SYS_RECVMSG);
export_const_u64!(abi_sys_setsockopt, SYS_SETSOCKOPT);
export_const_u64!(abi_sys_getsockopt, SYS_GETSOCKOPT);
export_const_u64!(abi_sys_getsockname, SYS_GETSOCKNAME);
export_const_u64!(abi_sys_getpeername, SYS_GETPEERNAME);
export_const_u64!(abi_sys_ppoll, SYS_PPOLL);
export_const_u64!(abi_sys_pselect6, SYS_PSELECT6);
export_const_u64!(abi_sys_signalfd4, SYS_SIGNALFD4);
export_const_u64!(abi_sys_timerfd_create, SYS_TIMERFD_CREATE);
export_const_u64!(abi_sys_timerfd_settime, SYS_TIMERFD_SETTIME);
export_const_u64!(abi_sys_timerfd_gettime, SYS_TIMERFD_GETTIME);
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
export_const!(abi_madv_normal, MADV_NORMAL);
export_const!(abi_madv_random, MADV_RANDOM);
export_const!(abi_madv_sequential, MADV_SEQUENTIAL);
export_const!(abi_madv_willneed, MADV_WILLNEED);
export_const!(abi_madv_dontneed, MADV_DONTNEED);
export_const!(abi_madv_free, MADV_FREE);
export_const!(abi_madv_dontfork, MADV_DONTFORK);
export_const!(abi_madv_dofork, MADV_DOFORK);

// Open flags
export_const!(abi_o_rdonly, O_RDONLY);
export_const!(abi_o_wronly, O_WRONLY);
export_const!(abi_o_rdwr, O_RDWR);
export_const!(abi_o_creat, O_CREAT);
export_const!(abi_o_excl, O_EXCL);
export_const!(abi_o_trunc, O_TRUNC);
export_const!(abi_o_append, O_APPEND);
export_const!(abi_o_cloexec, O_CLOEXEC);
export_const!(abi_o_nonblock, O_NONBLOCK);
export_const!(abi_o_directory, O_DIRECTORY);
export_const!(abi_o_nofollow, O_NOFOLLOW);
export_const_u64!(abi_tfd_timer_abstime, TFD_TIMER_ABSTIME);
export_const_u64!(abi_tfd_timer_cancel_on_set, TFD_TIMER_CANCEL_ON_SET);

// Error codes
export_const!(abi_enoent, ENOENT as i32);
export_const!(abi_ebadf, EBADF as i32);
export_const!(abi_einval, EINVAL as i32);
export_const!(abi_enotty, ENOTTY as i32);
export_const!(abi_enomem, ENOMEM as i32);
export_const!(abi_enosys, ENOSYS as i32);
export_const!(abi_eloop, ELOOP as i32);
export_const!(abi_eagain, EAGAIN as i32);
export_const!(abi_etimedout, ETIMEDOUT as i32);
export_const!(abi_einprogress, EINPROGRESS as i32);
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
export_const!(abi_enodata, ENODATA as i32);
export_const!(abi_enametoolong, ENAMETOOLONG as i32);
export_const!(abi_enotsock, ENOTSOCK as i32);
export_const!(abi_edestaddrreq, EDESTADDRREQ as i32);
export_const!(abi_eprototype, EPROTOTYPE as i32);
export_const!(abi_enoprotoopt, ENOPROTOOPT as i32);
export_const!(abi_eprotonosupport, EPROTONOSUPPORT as i32);
export_const!(abi_eopnotsupp, EOPNOTSUPP as i32);
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
export_const!(abi_max_signalfds, MAX_SIGNALFDS as i32);

pub use crate::exports::kernel::*;
pub use crate::exports::memfs::*;
pub use crate::exports::thread::*;
pub use crate::supervisor::{
    supervisor_abi_version, supervisor_complete_futex_wait, supervisor_complete_host_op,
    supervisor_debug_snapshot, supervisor_debug_snapshot_bytes,
    supervisor_futex_wait_completion_invalid_address, supervisor_futex_wait_completion_not_equal,
    supervisor_futex_wait_completion_signal_check, supervisor_futex_wait_completion_timed_out,
    supervisor_futex_wait_completion_woken, supervisor_next_host_op, supervisor_next_resume,
    supervisor_reset_shadow_log, supervisor_resume_kind_futex_wake, supervisor_resume_record_bytes,
    supervisor_shadow_host_completion_count, supervisor_shadow_host_completion_log_hash,
    supervisor_shadow_host_op_poll_count, supervisor_shadow_resume_enqueue_count,
    supervisor_shadow_resume_overflow_count, supervisor_shadow_resume_poll_count,
    supervisor_shadow_thread_event_count, supervisor_shadow_thread_event_log_hash,
    supervisor_submit_thread_event, supervisor_thread_state_snapshot,
    supervisor_thread_state_snapshot_bytes,
};

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

/// Read the current guest CLOCK_MONOTONIC tick counter.
#[unsafe(no_mangle)]
pub extern "C" fn monotonic_ticks_current() -> u64 {
    crate::syscall::time::monotonic_ticks_current()
}

// =========================================================================
// Staged argv/envp sources for process_create
// =========================================================================

const MAX_ARGS: usize = 64;
const GUEST_GUARD_BYTES: u64 = 4 * 1024 * 1024;
const GUEST_EXEC_SCRATCH_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;
const WASM32_LINEAR_MEMORY_LIMIT: u64 = 0x1_0000_0000;
const MEMORY64_GUEST_ADDRESS_LIMIT: u64 = i64::MAX as u64;

pub const fn max_guest_window_for_base(base: u32) -> u64 {
    MEMORY64_GUEST_ADDRESS_LIMIT.saturating_sub(base as u64)
}

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

static mut PROCESS_CREATE_LAST_ERROR: i32 = 0;

fn set_process_create_last_error(code: i32) {
    unsafe {
        PROCESS_CREATE_LAST_ERROR = code;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_create_last_error() -> i32 {
    unsafe { PROCESS_CREATE_LAST_ERROR }
}

fn staged_args() -> &'static mut StagedArgs {
    unsafe { &mut *core::ptr::addr_of_mut!(STAGED) }
}

fn process_guest_base_for_reserved_guest_window() -> u32 {
    // Keep a guard plus exec scratch headroom between kernel-owned linear
    // memory and the live guest window. execve() stages large ELF bytes in
    // kernel memory before rebuilding the guest image, so a single guard page
    // is not enough once workloads include browser-shell child exec.
    let aligned = (crate::alloc::heap_ptr() as u64
        + GUEST_GUARD_BYTES
        + GUEST_EXEC_SCRATCH_HEADROOM_BYTES
        + 0xF_FFFF)
        & !0xF_FFFF;
    if aligned >= WASM32_LINEAR_MEMORY_LIMIT {
        0
    } else {
        aligned as u32
    }
}

fn process_guest_base_for_profile(address_profile: u32) -> u64 {
    match address_profile {
        GUEST_ADDRESS_PROFILE_MEMORY64 => process_guest_base_for_reserved_guest_window() as u64,
        _ => 0,
    }
}

fn guest_address_limit_for_profile(address_profile: u32, guest_base: u64) -> u64 {
    match address_profile {
        GUEST_ADDRESS_PROFILE_MEMORY64 => MEMORY64_GUEST_ADDRESS_LIMIT.saturating_sub(guest_base),
        _ => 0,
    }
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
    let auxv_size = 11u64 * 16; // 10 entries + AT_NULL
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
pub extern "C" fn abi_guest_address_profile_memory64() -> u32 {
    GUEST_ADDRESS_PROFILE_MEMORY64
}

#[unsafe(no_mangle)]
pub extern "C" fn abi_guest_address_profile_target() -> u32 {
    GUEST_ADDRESS_PROFILE_MEMORY64
}

#[unsafe(no_mangle)]
pub extern "C" fn process_guest_base_for_address_profile(address_profile: u32) -> u64 {
    process_guest_base_for_profile(address_profile)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_guest_address_limit_for_profile(
    address_profile: u32,
    guest_base: u64,
) -> u64 {
    guest_address_limit_for_profile(address_profile, guest_base)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_inspect_elf_brk_with_memory_policy(
    elf_ptr: u32,
    elf_len: u32,
    address_profile: u32,
    guest_memory_policy_limit: u64,
) -> u64 {
    unsafe {
        let guest_base = process_guest_base_for_profile(address_profile);
        if guest_base == 0 {
            return 0;
        }
        let guest_address_limit = guest_address_limit_for_profile(address_profile, guest_base);
        if guest_address_limit == 0 {
            return 0;
        }
        let guest_limit = if guest_memory_policy_limit != 0 {
            guest_memory_policy_limit.min(guest_address_limit)
        } else {
            guest_address_limit
        };
        match crate::elf::inspect_elf(elf_ptr, elf_len, guest_limit) {
            Ok(r) => r.brk_start,
            Err(_) => 0,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_create_with_memory_policy(
    elf_ptr: u32,
    elf_len: u32,
    address_profile: u32,
    guest_memory_policy_limit: u64,
    process_max_memory_pages: u32,
    stack_size: u32,
) -> u32 {
    unsafe {
        set_process_create_last_error(0);
        // The guest address window lives above the kernel's reserved linear-memory region.
        let base_u64 = process_guest_base_for_profile(address_profile);
        if base_u64 == 0 || base_u64 > u32::MAX as u64 {
            set_process_create_last_error(1);
            return 0;
        }
        let base = base_u64 as u32;
        let guest_address_limit = guest_address_limit_for_profile(address_profile, base_u64);
        if guest_address_limit == 0 {
            set_process_create_last_error(1);
            return 0;
        }
        let guest_limit = if guest_memory_policy_limit != 0 {
            guest_memory_policy_limit.min(guest_address_limit)
        } else {
            guest_address_limit
        };
        let mut main_inspected = match crate::elf::inspect_elf(elf_ptr, elf_len, guest_limit) {
            Ok(r) => r,
            Err(_) => {
                set_process_create_last_error(2);
                return 0;
            }
        };
        let interp_path = match crate::elf::read_interp_path(elf_ptr, elf_len) {
            Ok(path) => path,
            Err(_) => {
                set_process_create_last_error(3);
                return 0;
            }
        };
        let main_load_bias =
            crate::elf::main_executable_load_bias(&main_inspected, interp_path.is_some());
        if main_load_bias != 0 {
            main_inspected = crate::elf::bias_load_result(main_inspected, main_load_bias);
        }
        let main_brk_start = main_inspected.brk_start;
        let mut interp_load: Option<(u32, u32, u64, crate::elf::ElfLoadResult)> = None;
        let load_brk_start = match interp_path {
            Some(interp_path) => {
                let interp_ino = crate::fs::memfs::resolve_path_following_symlinks(&interp_path);
                if interp_ino == 0 {
                    set_process_create_last_error(4);
                    return 0;
                }
                let interp_st = match crate::fs::memfs::stat(interp_ino) {
                    Some(st) if st.mode & crate::fs::memfs::S_IFMT == crate::fs::memfs::S_IFREG => {
                        st
                    }
                    _ => {
                        set_process_create_last_error(5);
                        return 0;
                    }
                };
                let interp_len = match u32::try_from(interp_st.size) {
                    Ok(len) if len > 0 => len,
                    _ => {
                        set_process_create_last_error(6);
                        return 0;
                    }
                };
                let interp_ptr = crate::alloc::alloc_zeroed(interp_len, 16);
                if interp_ptr == 0 {
                    set_process_create_last_error(7);
                    return 0;
                }
                let interp_buf =
                    core::slice::from_raw_parts_mut(interp_ptr as *mut u8, interp_len as usize);
                if crate::fs::memfs::read_file(interp_ino, 0, interp_buf) != interp_len as i64 {
                    set_process_create_last_error(8);
                    return 0;
                }
                let interp_inspected =
                    match crate::elf::inspect_elf(interp_ptr, interp_len, guest_limit) {
                        Ok(r) => r,
                        Err(_) => {
                            set_process_create_last_error(9);
                            return 0;
                        }
                    };
                let interp_bias = crate::elf::interpreter_load_bias(main_brk_start);
                let interp_brk_start = interp_inspected.brk_start.saturating_add(interp_bias);
                interp_load = Some((interp_ptr, interp_len, interp_bias, interp_inspected));
                main_brk_start.max(interp_brk_start)
            }
            None => main_brk_start,
        };
        let main_segments =
            match crate::elf::collect_load_segments(elf_ptr, elf_len, main_load_bias) {
                Ok(segments) => segments,
                Err(_) => {
                    set_process_create_last_error(13);
                    return 0;
                }
            };
        let interp_segments = match interp_load {
            Some((interp_ptr, interp_len, interp_bias, _)) => {
                match crate::elf::collect_load_segments(interp_ptr, interp_len, interp_bias) {
                    Ok(segments) => Some(segments),
                    Err(_) => {
                        set_process_create_last_error(14);
                        return 0;
                    }
                }
            }
            None => None,
        };
        if !crate::syscall::memory::ensure_guest_memory_capacity(base, load_brk_start) {
            set_process_create_last_error(10);
            return 0;
        }
        let main_loaded =
            match crate::elf::load_elf_at(base, guest_limit, elf_ptr, elf_len, main_load_bias) {
                Ok(r) => r,
                Err(_) => {
                    set_process_create_last_error(11);
                    return 0;
                }
            };
        let interp_loaded = match interp_load {
            Some((interp_ptr, interp_len, interp_bias, _interp_inspected)) => {
                match crate::elf::load_elf_at(
                    base,
                    guest_limit,
                    interp_ptr,
                    interp_len,
                    interp_bias,
                ) {
                    Ok(result) => Some(result),
                    Err(_) => {
                        set_process_create_last_error(12);
                        return 0;
                    }
                }
            }
            None => None,
        };
        let mut elf_result = interp_loaded.unwrap_or(main_loaded);
        if interp_load.is_some() {
            crate::elf::preserve_main_executable_process_image(&mut elf_result, &main_loaded);
        }
        let loaded_end = main_loaded
            .load_end
            .max(interp_loaded.map(|interp| interp.load_end).unwrap_or(0));
        crate::elf::zero_fill_load_padding(base, loaded_end, load_brk_start);
        elf_result.brk_start = load_brk_start;

        crate::syscall::memory::init(elf_result.brk_start);
        for segment in main_segments {
            crate::syscall::memory::register_elf_load_segment(
                segment.start,
                segment.end,
                segment.prot,
            );
        }
        if let Some(segments) = interp_segments {
            for segment in segments {
                crate::syscall::memory::register_elf_load_segment(
                    segment.start,
                    segment.end,
                    segment.prot,
                );
            }
        }

        // ProcessState lives in guest Memory (shared WebAssembly.Memory),
        // not in kernel Worker private memory (alloc.rs).
        // Allocate via brk in the guest address space.
        let ps_size = core::mem::size_of::<crate::types::ProcessState>() as u64;
        let ps_align = core::mem::align_of::<crate::types::ProcessState>() as u64;
        let brk = crate::syscall::memory::current_brk();
        let ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
        let new_brk = ps_addr + ps_size;
        let public_brk = crate::syscall::memory::user_brk_start_after_hidden_prefix(new_brk);
        let brk_ret = crate::syscall::memory::grow_brk(base, public_brk);
        if brk_ret < public_brk as i64 {
            set_process_create_last_error(15);
            return 0;
        }
        crate::guest_mem::zero_mem(base, ps_addr, ps_size as usize);
        crate::syscall::memory::rebase_brk_after_hidden_prefix(new_brk);
        let ps_ptr = (base as u64 + ps_addr) as u32;
        let ps = &mut *(ps_ptr as *mut crate::types::ProcessState);
        ps.pid = 2;
        ps.ppid = 1;
        ps.cwd_ino = 1;
        ps.fs_ring_base =
            crate::alloc::alloc_zeroed(crate::fs::ring_buffer::RING_BUFFER_SIZE as u32, 16);
        ps.umask = 0o022;
        if ps.fs_ring_base == 0 {
            set_process_create_last_error(16);
            return 0;
        }
        crate::syscall::signal::init_for_process(2);
        crate::syscall::resource::init_for_process(2);

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
            set_process_create_last_error(17);
            return 0;
        }
        let ts = &mut *(ts_ptr as *mut crate::types::ThreadState);
        ts.lr_addr = u64::MAX;

        let stack_top =
            crate::syscall::memory::map_initial_stack(base, guest_limit, stack_size as u64);
        if stack_top < 0 {
            set_process_create_last_error(18);
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
            set_process_create_last_error(19);
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
            argv_addrs[0],
        );
        // Clear staged args for next process
        staged.argc = 0;
        staged.envc = 0;

        // Seed the minimal procfs snapshot that early userspace expects.
        let mut exe_target = [0u8; 256];
        let exe_len = crate::guest_mem::read_cstr(base, argv_addrs[0], &mut exe_target);
        let target = if exe_len > 0 {
            &exe_target[..exe_len]
        } else {
            b"/init" as &[u8]
        };
        crate::syscall::process::install_procfs_snapshot(target, guest_memory_policy_limit);

        ts.pc = elf_result.entry;
        ts.x[2] = sp;
        ts.x[4] = elf_result.tls_base;
        ts.status = STATUS_OK;
        ts.tid = 1;
        ts.tls_base = elf_result.tls_base;
        ts.guest_base = base;
        ts.guest_address_profile = address_profile;
        ts.guest_address_limit = guest_address_limit;
        ts.guest_memory_policy_limit = guest_memory_policy_limit;
        ts.process_max_memory_pages = process_max_memory_pages;
        ts.process_ptr = ps_addr as u32;
        crate::fs::fd_table::init_stdio(base, ts);
        crate::syscall::thread::init_main_thread(ts_ptr, base);
        ts_ptr
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_state_bytes() -> u32 {
    core::mem::size_of::<crate::types::ProcessState>() as u32
}

fn process_state_from_vm(vm_ptr: u32) -> Option<&'static mut crate::types::ProcessState> {
    let vm = thread_state_from_ptr(vm_ptr)?;
    if vm.process_ptr == 0 {
        return None;
    }
    unsafe {
        Some(
            &mut *((vm.guest_base as u64 + vm.process_ptr as u64)
                as *mut crate::types::ProcessState),
        )
    }
}

fn thread_state_from_ptr(vm_ptr: u32) -> Option<&'static crate::types::ThreadState> {
    if vm_ptr == 0 {
        return None;
    }
    Some(unsafe { &*(vm_ptr as *const crate::types::ThreadState) })
}

#[unsafe(no_mangle)]
pub extern "C" fn process_thread_tid(vm_ptr: u32, slot: u32) -> i32 {
    let Some(ps) = process_state_from_vm(vm_ptr) else {
        return 0;
    };
    if slot as usize >= MAX_THREADS {
        return 0;
    }
    ps.threads[slot as usize].tid
}

#[unsafe(no_mangle)]
pub extern "C" fn process_thread_state(vm_ptr: u32, slot: u32) -> i32 {
    let Some(ps) = process_state_from_vm(vm_ptr) else {
        return crate::types::THREAD_NONE;
    };
    if slot as usize >= MAX_THREADS {
        return crate::types::THREAD_NONE;
    }
    ps.threads[slot as usize].state
}

#[unsafe(no_mangle)]
pub extern "C" fn process_thread_vm_ptr(vm_ptr: u32, slot: u32) -> u32 {
    let Some(ps) = process_state_from_vm(vm_ptr) else {
        return 0;
    };
    if slot as usize >= MAX_THREADS {
        return 0;
    }
    ps.threads[slot as usize].thread_ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn process_record_child_exit(pid: i32, wait_status: i32) {
    crate::syscall::process::record_child_exit(pid, wait_status);
}

#[unsafe(no_mangle)]
pub extern "C" fn process_record_child_exit_for_parent(
    parent_pid: i32,
    pid: i32,
    wait_status: i32,
) {
    crate::syscall::process::record_child_exit_for_parent(parent_pid, pid, wait_status);
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
        crate::syscall::pty::refresh_controlling_tty_foreground(vm, vm.guest_base);
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
pub extern "C" fn process_tty_pty_slot(vm_ptr: u32) -> u32 {
    process_state_from_vm(vm_ptr).map_or(0, |ps| ps.tty_pty_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_use_pipe_stdio(vm_ptr: u32) -> i32 {
    let vm = unsafe { &mut *(vm_ptr as *mut crate::types::ThreadState) };
    if unsafe { crate::fs::fd_table::use_pipe_stdio(vm.guest_base, vm) } {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_close_host_stdin(vm_ptr: u32) {
    if let Some(ps) = process_state_from_vm(vm_ptr) {
        let pipe_slot = ps.stdin_pipe_slot;
        if pipe_slot != 0 {
            crate::syscall::pipe::pipe_close(pipe_slot, false);
            ps.stdin_pipe_slot = 0;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_host_write_stdin(vm_ptr: u32, src_ptr: u32, src_len: u32) -> i32 {
    let vm = unsafe { &mut *(vm_ptr as *mut crate::types::ThreadState) };
    let data = unsafe { core::slice::from_raw_parts(src_ptr as *const u8, src_len as usize) };
    crate::syscall::pty::host_write_from_process(vm, vm.guest_base, data) as i32
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
pub extern "C" fn process_install_procfs_snapshot(
    target_ptr: u32,
    target_len: u32,
    guest_memory_policy_limit: u64,
) {
    let target =
        unsafe { core::slice::from_raw_parts(target_ptr as *const u8, target_len as usize) };
    crate::syscall::process::install_procfs_snapshot(target, guest_memory_policy_limit);
}

#[unsafe(no_mangle)]
pub extern "C" fn process_fd_ofd_id(vm_ptr: u32, fd: u32) -> u32 {
    let Some(vm) = thread_state_from_ptr(vm_ptr) else {
        return 0;
    };
    crate::fs::fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, fd as usize).ofd_id
}

#[unsafe(no_mangle)]
pub extern "C" fn process_fd_flags(vm_ptr: u32, fd: u32) -> u32 {
    let Some(vm) = thread_state_from_ptr(vm_ptr) else {
        return 0;
    };
    crate::fs::fd_table::load_process_fd_entry(vm.guest_base, vm.process_ptr, fd as usize).fd_flags
}

#[unsafe(no_mangle)]
pub extern "C" fn process_fd_generation(vm_ptr: u32, fd: u32) -> u32 {
    let Some(vm) = thread_state_from_ptr(vm_ptr) else {
        return 0;
    };
    crate::fs::fd_table::load_process_fd_generation(vm.guest_base, vm.process_ptr, fd as usize)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_set_fd_entry(vm_ptr: u32, fd: u32, ofd_id: u32, fd_flags: u32) {
    let Some(vm) = thread_state_from_ptr(vm_ptr) else {
        return;
    };
    crate::fs::fd_table::store_process_fd_entry(
        vm.guest_base,
        vm.process_ptr,
        fd as usize,
        crate::types::FdEntry { ofd_id, fd_flags },
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn process_release_host_stdio(vm_ptr: u32) {
    if let Some(ps) = process_state_from_vm(vm_ptr) {
        let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
        crate::syscall::pty::release_host_attachment(vm, vm.guest_base);
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
    // Legacy runtime ABI name. Kernel socket semantics stay generic here; the
    // wrapper delegates to the external-connection helper for compatibility.
    let _ = vm_ptr;
    let request = unsafe { core::slice::from_raw_parts(req_ptr as *const u8, req_len as usize) };
    crate::syscall::socket::inject_external_connection_by_port(port as u16, request)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_read_http_response(
    vm_ptr: u32,
    conn_id: i32,
    dst_ptr: u32,
    dst_len: u32,
) -> i32 {
    // Legacy runtime ABI name. The connection slot is generic socket state.
    let _ = vm_ptr;
    let dst = unsafe { core::slice::from_raw_parts_mut(dst_ptr as *mut u8, dst_len as usize) };
    crate::syscall::socket::read_external_connection_data(conn_id, dst)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_close_http_connection(vm_ptr: u32, conn_id: i32) {
    // Legacy runtime ABI name. The connection slot is generic socket state.
    let _ = vm_ptr;
    crate::syscall::socket::close_connection_slot(conn_id);
}

// =============================================================================
// Blocking state accessors (for runtime Atomics.wait integration)
// =============================================================================

// =============================================================================
// MemFS operations (for Runtime.writeFile/readFile via kernel Worker)
// =============================================================================
