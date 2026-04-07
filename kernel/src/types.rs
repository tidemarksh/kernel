//! Core type definitions for kernel state.
//!
//! Ownership model:
//!   thread-local:   ThreadState (registers, PC, TLS, per-thread signal)
//!   guest Memory:   FdTable, thread_count (shared between threads in a process)
//!   SAB page cache: file data, inode metadata, pipe buffers (cross-worker visible)
//!   kernel Worker:  OFD table, VMA table, epoll, socket, signal dispositions

use crate::abi::*;
use core::sync::atomic::AtomicU32;

// =============================================================================
// ThreadState — per-thread CPU state (thread-local)
// =============================================================================

#[repr(C)]
pub struct ThreadState {
    /// Integer registers x0..x31 (x0 is always 0, enforced by convention)
    pub x: [u64; 32],
    /// Program counter
    pub pc: u64,
    /// Floating-point registers f0..f31 (stored as u64 bit patterns)
    pub f: [u64; 32],
    /// Floating-point control/status register
    pub fcsr: u32,
    /// Execution status (STATUS_OK, STATUS_FAULT, STATUS_FS, etc.)
    pub status: i32,
    /// Exit code (set on STATUS_FAULT)
    pub exit_code: i32,
    /// Non-zero when STATUS_FAULT was caused by default signal termination.
    pub term_signal: i32,
    /// Thread ID
    pub tid: i32,
    /// Real user ID
    pub uid: u32,
    /// Effective user ID
    pub euid: u32,
    /// Real group ID
    pub gid: u32,
    /// Effective group ID
    pub egid: u32,
    /// TLS base address (set by set_tid_address / clone CLONE_SETTLS)
    pub tls_base: u64,
    /// Address to clear and futex-wake on thread exit (set_tid_address)
    pub clear_child_tid: u64,
    /// Head pointer registered by set_robust_list(2).
    pub robust_list_head: u64,
    /// Size of the registered robust_list_head.
    pub robust_list_len: u64,

    // --- Per-thread signal state ---
    /// Signal mask (blocked signals)
    pub sig_mask: u64,
    /// Pending signals (delivered at syscall return boundary)
    pub sig_pending: u64,
    /// `siginfo.si_code` for the next delivered pending signal.
    pub sig_info_code: i32,
    /// Alternate signal stack base
    pub sigaltstack_sp: u64,
    /// Alternate signal stack size
    pub sigaltstack_size: u64,
    /// Alternate signal stack flags
    pub sigaltstack_flags: i32,

    // --- LR/SC reservation (per-thread) ---
    pub lr_addr: u64,
    pub lr_val: u64,
    pub lr_gen: u32,
    pub lr_gen_end: u32,

    // --- Instruction budget ---
    pub insn_budget: i32,

    // --- Fault info ---
    pub fault_pc: u64,
    pub fault_addr: u64,

    // --- Guest/process pointers ---
    /// Base offset of the guest address space inside the shared WASM memory.
    pub guest_base: u32,
    /// Guest-relative pointer to ProcessState in guest Memory.
    pub process_ptr: u32,

    // --- Runtime handoff scratch ---
    /// Pending clone flags for `STATUS_CLONE_SPAWN` handoff. Zero = inactive.
    pub clone_flags: u64,
    /// Child stack pointer requested by clone.
    pub clone_child_stack: u64,
    /// TLS base requested via CLONE_SETTLS.
    pub clone_tls: u64,
    /// Child TID pointer for CLONE_CHILD_{SET,CLEAR}TID.
    pub clone_child_tidptr: u64,
    /// Allocated child TID for the pending clone handoff.
    pub clone_child_tid: i32,
    /// Non-zero while a clone handoff is pending.
    pub clone_pending: i32,
    /// Pending process-spawn handoff kind. Zero = inactive.
    pub spawn_kind: u32,
    /// Reserved for future process-spawn flags.
    pub spawn_flags: u32,
    /// Child PID allocated for execve/fork handoff.
    pub spawn_child_pid: i32,
    _pad1: u32,
    /// Guest pointer to execve path string.
    pub spawn_path: u64,
    /// Guest pointer to argv vector.
    pub spawn_argv: u64,
    /// Guest pointer to envp vector.
    pub spawn_envp: u64,
    /// Pending blocking wait4 target pid.
    pub wait_pid: i64,
    /// wait-family selector (wait4/waitid).
    pub wait_kind: u32,
    /// waitid idtype (P_ALL/P_PID/P_PGID).
    pub wait_idtype: u32,
    /// Guest pointer for wait status storage.
    pub wait_wstatus_addr: u64,
    /// wait4 options (WNOHANG, etc.).
    pub wait_options: u64,
    /// Guest pointer for wait rusage storage.
    pub wait_rusage_addr: u64,
    /// Blocked futex address for `STATUS_FUTEX_WAIT`.
    pub futex_wait_addr: u64,
    /// Guest pointer to FUTEX_WAIT timeout timespec (0 = infinite wait).
    pub futex_wait_timeout: u64,
    /// Expected futex word captured at FUTEX_WAIT entry.
    pub futex_wait_expected: u32,
    /// FUTEX_WAIT_BITSET mask captured at entry (`FUTEX_BITSET_MATCH_ANY` for FUTEX_WAIT).
    pub futex_wait_bitset: u32,
    /// Non-zero when the blocked wait uses absolute timeout semantics.
    pub futex_wait_absolute: u32,
    /// Saved FUTEX_* flags for timed wait handling (`FUTEX_CLOCK_REALTIME`, etc.).
    pub futex_wait_flags: u32,
    /// epoll_wait timeout in milliseconds (-1 = infinite wait).
    pub epoll_timeout_ms: i64,
    /// maxevents captured for STATUS_EPOLL_WAIT retry.
    pub epoll_maxevents: u32,
    /// FD number captured for a blocked OFD-backed syscall resume.
    pub blocked_fd: u32,
    /// Retained OFD id captured for a blocked syscall resume. 0 = inactive.
    pub blocked_ofd_id: u32,
}

// =============================================================================
// FdEntry — per-FD entry in guest Memory ProcessState
// =============================================================================

/// FD table entry. Lives in guest Memory (ProcessState).
/// dup/close(refcount>1)/fcntl operate on this without kernel Worker.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdEntry {
    /// OFD identifier (index into kernel Worker's OFD table). 0 = unused.
    pub ofd_id: u32,
    /// FD flags (FD_CLOEXEC etc.)
    pub fd_flags: u32,
}

// =============================================================================
// ProcessState — per-process shared state in guest Memory
// =============================================================================

/// Process state shared between threads via shared WebAssembly.Memory.
/// FD table lives here (guest Memory) for fast dup/close.
/// Other state (OFD, VMA, epoll, socket) lives in kernel Worker.
#[repr(C)]
pub struct ProcessState {
    /// FD table (fd → ofd_id + fd_flags)
    pub fd_table: [FdEntry; MAX_FDS],
    /// Number of active threads (clone increments, exit decrements).
    /// Used for seqlock optimization: thread_count == 1 → skip seqlock on stores.
    pub thread_count: AtomicU32,
    /// Reservation generations for LR/SC invalidation across shared-memory threads.
    pub reservation_gen: [AtomicU32; 64],
    /// Reservation locks used to make SC/AMO checks atomic across workers.
    pub reservation_lock: [AtomicU32; 64],
    /// Process ID
    pub pid: i32,
    /// Parent process ID
    pub ppid: i32,
    /// Current working directory inode in MemFS. 0 means "/".
    pub cwd_ino: u32,
    /// Hidden stdin pipe slot (runtime owns the write side).
    pub stdin_pipe_slot: u32,
    /// Hidden stdout pipe slot (runtime owns the read side).
    pub stdout_pipe_slot: u32,
    /// Hidden stderr pipe slot (runtime owns the read side).
    pub stderr_pipe_slot: u32,
    /// Per-process FS request/completion ring in shared WebAssembly.Memory.
    pub fs_ring_base: u32,
    /// Thread registry
    pub threads: [ThreadRecord; MAX_THREADS],
}

// =============================================================================
// ThreadRecord — per-thread entry in ProcessState thread table
// =============================================================================

pub const THREAD_NONE: i32 = 0;
pub const THREAD_STARTING: i32 = 1;
pub const THREAD_RUNNING: i32 = 2;
pub const THREAD_BLOCKED_FUTEX: i32 = 3;
pub const THREAD_BLOCKED_POLL: i32 = 4;
pub const THREAD_EXITING: i32 = 5;
pub const THREAD_DEAD: i32 = 7;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadRecord {
    pub tid: i32,
    pub state: i32,
    pub thread_ptr: u32, // absolute pointer to ThreadState in WASM linear memory
    pub clear_child_tid: u32,
    pub blocked_addr: u32,
    _pad: [u8; 12],
}

impl ThreadRecord {
    pub const fn empty() -> Self {
        Self {
            tid: 0,
            state: THREAD_NONE,
            thread_ptr: 0,
            clear_child_tid: 0,
            blocked_addr: 0,
            _pad: [0; 12],
        }
    }

    pub const fn new(
        tid: i32,
        state: i32,
        thread_ptr: u32,
        clear_child_tid: u32,
        blocked_addr: u32,
    ) -> Self {
        Self {
            tid,
            state,
            thread_ptr,
            clear_child_tid,
            blocked_addr,
            _pad: [0; 12],
        }
    }
}

// =============================================================================
// OFD — Open File Description (kernel Worker private)
// =============================================================================

/// Open file description. Lives in kernel Worker's linear memory.
/// Shared by FDs via refcount (dup/fork share the same OFD).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenFileDesc {
    pub fd_type: i32,
    pub host_fd: i32,
    pub status_flags: i32,
    pub refcount: i32,
    pub offset: i64,
    /// Cached inode number for direct SAB page cache read
    pub ino: u32,
    /// Advisory BSD flock state (LOCK_SH/LOCK_EX). 0 = unlocked.
    pub flock_state: u32,
}

// =============================================================================
// VMA — Virtual Memory Area (kernel Worker private)
// =============================================================================

/// VMA entry for mmap/munmap/mprotect management.
/// Stored as sorted Vec<Vma> in kernel Worker (not in guest Memory).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: i32,  // PROT_READ | PROT_WRITE | PROT_EXEC | PROT_NONE
    pub flags: i32, // MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    pub fd: i32,    // file-backed: backing MemFS inode. -1 = anonymous
    pub _pad: i32,
    pub offset: u64, // file offset for file-backed mmap
}

// =============================================================================
// SigAction — signal disposition (kernel Worker private)
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigAction {
    pub handler: u64, // SIG_DFL (0), SIG_IGN (1), or handler address
    pub flags: u64,   // SA_SIGINFO, SA_RESTART, SA_RESETHAND, etc.
    pub mask: u64,    // signals to block during handler execution
}

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;
pub const MAX_SIGNALS: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_state_layout() {
        let size = core::mem::size_of::<ThreadState>();
        assert!(size > 0);
        assert_eq!(size % 8, 0, "ThreadState should be 8-byte aligned");
    }

    #[test]
    fn process_state_has_fd_table() {
        let size = core::mem::size_of::<ProcessState>();
        assert!(size >= MAX_FDS * core::mem::size_of::<FdEntry>());
    }

    #[test]
    fn vma_is_copy() {
        let v = Vma {
            start: 0x1000,
            end: 0x2000,
            prot: PROT_READ | PROT_WRITE,
            flags: 0,
            fd: -1,
            _pad: 0,
            offset: 0,
        };
        let v2 = v;
        assert_eq!(v2.start, 0x1000);
    }
}
