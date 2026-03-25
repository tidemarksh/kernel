//! Core type definitions for kernel state.
//!
//! Ownership model (§6.1):
//!   thread-local:   ThreadState (registers, PC, TLS, per-thread signal)
//!   guest Memory:   FdTable, thread_count (shared between threads in a process)
//!   SAB page cache: file data, inode metadata, pipe buffers (cross-worker visible)
//!   kernel Worker:  OFD table, VMA table, epoll, socket, signal dispositions

use core::sync::atomic::AtomicU32;
use crate::abi::*;

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
    /// Thread ID
    pub tid: i32,
    /// TLS base address (set by set_tid_address / clone CLONE_SETTLS)
    pub tls_base: u64,
    /// Address to clear and futex-wake on thread exit (set_tid_address)
    pub clear_child_tid: u64,

    // --- Per-thread signal state ---
    /// Signal mask (blocked signals)
    pub sig_mask: u64,
    /// Pending signals (delivered at syscall return boundary)
    pub sig_pending: u64,
    /// Alternate signal stack base
    pub sigaltstack_sp: u64,
    /// Alternate signal stack size
    pub sigaltstack_size: u64,
    /// Alternate signal stack flags
    pub sigaltstack_flags: i32,

    // --- LR/SC reservation (per-thread) ---
    pub lr_addr: u64,
    pub lr_val: u64,

    // --- Instruction budget ---
    pub insn_budget: i32,

    // --- Fault info ---
    pub fault_pc: u64,
    pub fault_addr: u64,

    // --- Process pointer ---
    /// Points to ProcessState in guest Memory (shared with other threads)
    pub process_ptr: u32,

    _pad: [u8; 4],
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
    /// Process ID
    pub pid: i32,
    /// Parent process ID
    pub ppid: i32,
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
    pub thread_ptr: u32, // pointer to ThreadState in guest Memory
    pub clear_child_tid: u32,
    pub blocked_addr: u32,
    _pad: [u8; 12],
}

// =============================================================================
// OFD — Open File Description (kernel Worker private)
// =============================================================================

/// Open file description. Lives in kernel Worker's linear memory.
/// Shared by FDs via refcount (dup/fork share the same OFD).
#[repr(C)]
pub struct OpenFileDesc {
    pub fd_type: i32,
    pub host_fd: i32,
    pub status_flags: i32,
    pub refcount: i32,
    pub offset: i64,
    /// Cached inode number for direct SAB page cache read
    pub ino: u32,
    _pad: u32,
}

// =============================================================================
// VMA — Virtual Memory Area (kernel Worker private, §6.8.1)
// =============================================================================

/// VMA entry for mmap/munmap/mprotect management.
/// Stored as sorted Vec<Vma> in kernel Worker (not in guest Memory).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: i32,   // PROT_READ | PROT_WRITE | PROT_EXEC | PROT_NONE
    pub flags: i32,  // MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    pub fd: i32,     // file-backed: OFD id. -1 = anonymous
    pub _pad: i32,
    pub offset: u64, // file offset for file-backed mmap
}

// =============================================================================
// SigAction — signal disposition (kernel Worker private, §6.8.3)
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigAction {
    pub handler: u64,  // SIG_DFL (0), SIG_IGN (1), or handler address
    pub flags: u64,    // SA_SIGINFO, SA_RESTART, SA_RESETHAND, etc.
    pub mask: u64,     // signals to block during handler execution
}

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;
pub const MAX_SIGNALS: usize = 64;

// =============================================================================
// MmapEntry legacy compat — will be replaced by Vma
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MmapEntry {
    pub guest_addr: u64,
    pub length: u64,
    pub prot: i32,
    pub flags: i32,
    pub offset: u64,
}
