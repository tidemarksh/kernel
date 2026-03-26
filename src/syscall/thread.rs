//! Thread syscalls: clone, futex, exit, exit_group, set_tid_address, set_robust_list.
//!
//! clone(CLONE_VM | CLONE_THREAD) → STATUS_CLONE_SPAWN → TS spawns Worker.
//! futex(WAIT/WAKE) uses guest Memory Atomics directly.
//! futex(CMP_REQUEUE) requires kernel Worker.
//!
//! Stub — not yet implemented.
