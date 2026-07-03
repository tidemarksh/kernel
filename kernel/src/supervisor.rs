//! Additive supervisor shadow protocol.
//!
//! Phase A records deterministic shadows of runtime decisions without changing
//! guest-visible behavior. Later phases can replace these no-op decisions with
//! supervisor-owned policy.

mod abi;
mod blocked;
mod codec;
mod debug;
mod epoll;
mod event;
mod exports;
mod fault;
mod fd;
mod fs;
mod futex;
mod host_op;
mod lock;
mod log;
mod network;
mod pipe;
mod process;
pub mod process_fork;
pub mod process_lifecycle;
mod process_memory;
pub mod process_vfork;
pub mod process_wait;
mod records;
mod resume;
mod runnable;
mod signal;
mod socket;
mod state;
mod state_sync;
mod stdio;
mod thread;
mod thread_exit;
mod timer;

pub use abi::*;
pub(in crate::supervisor) use codec::{read_shadow_bytes, write_u32, write_u64};
pub use exports::*;
pub use fd::{fd_control_count, record_fd_control};
pub use fs::{fs_control_count, record_fs_control};
pub use process::{process_lifecycle_count, record_process_lifecycle};
pub(super) use records::*;
pub use signal::{record_signal_control, signal_control_count};
pub use thread::{
    discard_other_threads_for_exec, init_main_thread, last_clone_spawn, last_clone_spawn_details,
    process_thread_count, register_clone_thread, reset_thread_clone_registry,
    set_thread_clear_child_tid, spawn_from_clone, thread_record_blocked_addr,
};
pub use thread_exit::{
    cleanup_thread_robust_futexes, clear_tid_and_wake, complete_thread_exit,
    complete_thread_group_exit, record_thread_exit_cleanup, thread_exit_cleanup_count,
};

pub fn init() {
    log::init();
    thread_exit::init();
    process::init();
    fd::init();
    fs::init();
    signal::init();
    thread::init();
    event::init_state();
    fault::init();
    runnable::init();
    resume::init();
    host_op::init();
    network::init();
    pipe::init();
    state_sync::init();
}

pub fn thread_event_count() -> u64 {
    log::thread_event_count()
}

pub fn host_completion_count() -> u64 {
    log::host_completion_count()
}

pub fn host_op_poll_count() -> u64 {
    host_op::poll_count()
}

pub fn host_op_emit_count() -> u64 {
    host_op::emit_count()
}

pub fn host_op_overflow_count() -> u64 {
    host_op::overflow_count()
}

pub fn resume_poll_count() -> u64 {
    resume::poll_count()
}

pub fn resume_enqueue_count() -> u64 {
    resume::enqueue_count()
}

pub fn resume_overflow_count() -> u64 {
    resume::overflow_count()
}

pub fn thread_event_log_hash() -> u64 {
    log::thread_event_log_hash()
}

pub fn host_completion_log_hash() -> u64 {
    log::host_completion_log_hash()
}

pub fn host_op_log_hash() -> u64 {
    log::host_op_log_hash()
}

pub fn enqueue_clone_spawn(parent_vm_ptr: u32) -> bool {
    host_op::enqueue_clone_spawn(parent_vm_ptr)
}

pub fn discard_clone_spawn(parent_vm_ptr: u32) -> bool {
    host_op::discard_clone_spawn(parent_vm_ptr)
}

pub fn enqueue_futex_wait_timer(vm: &crate::types::ThreadState) -> bool {
    timer::enqueue_futex_wait_timer(vm)
}

pub fn enqueue_sleep_timer(vm: &crate::types::ThreadState) -> bool {
    timer::enqueue_sleep_timer(vm)
}

pub fn enqueue_runnable_thread(vm: &crate::types::ThreadState) -> bool {
    resume::enqueue_runnable_thread(vm)
}

pub fn enqueue_blocked_wait_timer(vm: &crate::types::ThreadState, status: i32) -> bool {
    timer::enqueue_blocked_wait_timer(vm, status)
}

pub fn enqueue_blocked_wait_timer_for_vm(vm_ptr: u32) -> i32 {
    timer::enqueue_blocked_wait_timer_for_vm(vm_ptr)
}

pub fn enqueue_futex_resume(process_ptr: u32, vm_ptr: u32, tid: i32, futex_addr: u64) -> bool {
    futex::enqueue_resume(process_ptr, vm_ptr, tid, futex_addr)
}
