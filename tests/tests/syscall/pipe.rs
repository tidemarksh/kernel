use tidemark_kernel::abi::*;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::supervisor::{
    supervisor_abi_version, supervisor_blocked_pipe_resume_action,
    supervisor_blocked_pipe_resume_action_defer, supervisor_blocked_pipe_resume_action_direct,
    supervisor_fd_control_kind_fd_closed, supervisor_fd_control_kind_pipe_created,
    supervisor_fd_control_record, supervisor_fd_control_record_bytes,
    supervisor_pipe_slot_mode_read, supervisor_pipe_slot_mode_write,
    supervisor_process_held_ofd_refcount, supervisor_process_held_pipe_slot_mask,
    supervisor_process_pipe_read_open_count, supervisor_process_pipe_slot_mode,
    supervisor_process_pipe_used_mask, supervisor_process_pipe_write_open_count,
    supervisor_process_private_pipe_slot_mask, supervisor_process_private_pipe_source_mode,
    supervisor_process_private_pipe_target_mode, supervisor_reset_shadow_log,
    supervisor_shadow_fd_control_count,
};
use tidemark_kernel::syscall::pipe::{self, PipeCloseOutcome};
use tidemark_kernel::syscall::{poll, pty};
use tidemark_kernel::types::FdEntry;

const OPEN_ACCESS_MODE_MASK: i64 = 0x3;
const EFD_SEMAPHORE: u64 = 0x1;
const FIONBIO: u64 = 0x5421;
const SYNC_EFFECT_PIPE_STATE: u32 = 1 << 0;
const SYNC_EFFECT_EPOLL_STATE: u32 = 1 << 2;
const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[test]
fn write_read_roundtrip() {
    let _t = TestVm::new();
    let idx = pipe::alloc_pipe_slot().unwrap();
    assert_eq!(pipe::pipe_write(idx, b"hello pipe"), 10);
    let mut buf = [0u8; 32];
    assert_eq!(pipe::pipe_read(idx, &mut buf), 10);
    assert_eq!(&buf[..10], b"hello pipe");
}

#[test]
fn dispatch_pipe2_marks_runtime_sync_effects_without_harness_trace() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x0800;

    t.vm.x[10] = pipefd_addr;
    t.vm.x[11] = 0;
    t.vm.x[17] = SYS_PIPE2;

    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, 0);
    assert_ne!(t.vm.completed_sync_effects & SYNC_EFFECT_PIPE_STATE, 0);
    assert_ne!(t.vm.completed_sync_effects & SYNC_EFFECT_EPOLL_STATE, 0);
    assert_ne!(
        t.vm.completed_sync_effects & SYNC_EFFECT_FORK_SHARED_OFD_STATE,
        0
    );
}

#[test]
fn eof_on_writer_close() {
    let _t = TestVm::new();
    let idx = pipe::alloc_pipe_slot().unwrap();
    pipe::pipe_close(idx, false);
    let mut buf = [0u8; 16];
    assert_eq!(pipe::pipe_read(idx, &mut buf), 0);
}

#[test]
fn blocked_read_resumes_eof_after_writer_close() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    let buf_addr = t.scratch + 0x1100;

    assert_eq!(t.sys_close(write_fd), 0);
    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 0);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn supervisor_blocked_pipe_resume_action_reports_defer_and_direct() {
    let mut blocked = TestVm::new();
    let pipefd_addr = blocked.scratch + 0x1000;
    assert_eq!(
        pipe::sys_pipe2(&mut blocked.vm, blocked.base, pipefd_addr, 0),
        0
    );
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(blocked.base, pipefd_addr) };
    let buf_addr = blocked.scratch + 0x1100;

    blocked.vm.x[17] = SYS_READ;
    blocked.vm.x[10] = read_fd as u64;
    blocked.vm.x[11] = buf_addr;
    blocked.vm.x[12] = 16;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut blocked.vm, blocked.base),
        STATUS_PIPE_WAIT
    );
    let blocked_vm_ptr = &mut blocked.vm as *mut _ as u32;
    assert_eq!(
        supervisor_blocked_pipe_resume_action(blocked_vm_ptr),
        supervisor_blocked_pipe_resume_action_defer() as i32
    );

    let mut eof = TestVm::new();
    let pipefd_addr = eof.scratch + 0x1200;
    assert_eq!(pipe::sys_pipe2(&mut eof.vm, eof.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(eof.base, pipefd_addr) };
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(eof.base, pipefd_addr + 4) };
    assert_eq!(eof.sys_close(write_fd as i64), 0);

    eof.vm.x[17] = SYS_READ;
    eof.vm.x[10] = read_fd as u64;
    eof.vm.x[11] = eof.scratch + 0x1300;
    eof.vm.x[12] = 16;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut eof.vm, eof.base),
        STATUS_PIPE_WAIT
    );
    let eof_vm_ptr = &mut eof.vm as *mut _ as u32;
    assert_eq!(
        supervisor_blocked_pipe_resume_action(eof_vm_ptr),
        supervisor_blocked_pipe_resume_action_direct() as i32
    );
}

#[test]
fn supervisor_pipe_open_counts_include_private_stdio_peers() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(process_use_pipe_stdio(vm_ptr), 0);

    let stdin_pipe = process_stdin_pipe(vm_ptr);
    let stdout_pipe = process_stdout_pipe(vm_ptr);
    let stderr_pipe = process_stderr_pipe(vm_ptr);
    assert!(stdin_pipe > 0);
    assert!(stdout_pipe > 0);
    assert!(stderr_pipe > 0);
    assert_ne!(stdin_pipe, stdout_pipe);
    assert_ne!(stdout_pipe, stderr_pipe);

    let private_mask = supervisor_process_private_pipe_slot_mask(vm_ptr);
    for pipe_slot in [stdin_pipe, stdout_pipe, stderr_pipe] {
        assert_ne!(private_mask & (1u64 << pipe_slot), 0);
        assert_ne!(
            supervisor_process_pipe_used_mask(vm_ptr) & (1u64 << pipe_slot),
            0
        );
        assert_eq!(
            supervisor_process_private_pipe_source_mode(vm_ptr, pipe_slot),
            supervisor_pipe_slot_mode_read() | supervisor_pipe_slot_mode_write()
        );
        assert_eq!(
            supervisor_process_private_pipe_target_mode(vm_ptr, pipe_slot),
            supervisor_pipe_slot_mode_read()
        );
    }

    assert_eq!(
        supervisor_process_pipe_read_open_count(vm_ptr, stdin_pipe),
        1
    );
    assert_eq!(
        supervisor_process_pipe_write_open_count(vm_ptr, stdin_pipe),
        1
    );
    assert_eq!(
        supervisor_process_pipe_read_open_count(vm_ptr, stdout_pipe),
        1
    );
    assert_eq!(
        supervisor_process_pipe_write_open_count(vm_ptr, stdout_pipe),
        1
    );
    assert_eq!(
        supervisor_process_pipe_read_open_count(vm_ptr, stderr_pipe),
        1
    );
    assert_eq!(
        supervisor_process_pipe_write_open_count(vm_ptr, stderr_pipe),
        1
    );
}

#[test]
fn repeated_pipe_eof_read_after_resume_does_not_wait_again() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    let buf_addr = t.scratch + 0x1100;

    assert_eq!(t.sys_close(write_fd), 0);
    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_PIPE_WAIT
    );
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 0);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_OK);

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.fault_addr, 0);
    assert_eq!(t.vm.fault_pc, 0);

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_OK
    );
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.fault_addr, 0);
    assert_eq!(t.vm.fault_pc, 0);
}

#[test]
fn blocked_read_resume_eof_uses_pinned_ofd_after_fd_close() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    let buf_addr = t.scratch + 0x1100;

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);
    assert_ne!(t.vm.blocked_ofd_id, 0);

    assert_eq!(t.sys_close(read_fd as i64), 0);
    assert_eq!(t.sys_close(write_fd), 0);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 0);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn blocked_read_resume_eof_uses_pinned_ofd_when_saved_syscall_is_missing() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    let buf_addr = t.scratch + 0x1100;

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);
    assert_ne!(t.vm.blocked_ofd_id, 0);

    t.vm.blocked_syscall_nr = 0;
    t.vm.blocked_syscall_args = [0; 6];
    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    assert_eq!(t.sys_close(read_fd as i64), 0);
    assert_eq!(t.sys_close(write_fd), 0);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 0);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn blocked_read_resume_eof_uses_blocked_fd_when_saved_syscall_and_pin_are_missing() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    let buf_addr = t.scratch + 0x1100;

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    assert_eq!(t.sys_close(write_fd), 0);
    t.vm.blocked_syscall_nr = 0;
    t.vm.blocked_syscall_args = [0; 6];
    t.vm.blocked_fd = read_fd as u32;
    t.vm.blocked_ofd_id = 0;
    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = EBADF as u64;

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 0);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn blocked_read_resume_eof_uses_pinned_ofd_after_write_open_reconcile() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as u64;
    let buf_addr = t.scratch + 0x1100;

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);
    assert_ne!(t.vm.blocked_ofd_id, 0);

    let blocked_ofd = tidemark_kernel::fs::fd_table::get_ofd_by_id(t.vm.blocked_ofd_id)
        .expect("blocked read OFD remains pinned");
    let pipe_slot = blocked_ofd.ino;
    assert_eq!(blocked_ofd.offset as u32, pipe::pipe_generation(pipe_slot));
    assert_eq!(pipe::debug_write_open(pipe_slot), 1);

    pipe::pipe_close(pipe_slot, false);
    assert_eq!(pipe::debug_write_open(pipe_slot), 0);
    assert!(tidemark_kernel::fs::fd_table::get_ofd(t.base, &t.vm, write_fd).is_some());

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 0);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn blocked_read_resume_eof_marker_uses_pinned_ofd_after_fd_close() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    let buf_addr = t.scratch + 0x1100;

    assert_eq!(t.sys_close(write_fd), 0);
    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = read_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 16;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_PIPE_WAIT
    );
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);
    assert_ne!(t.vm.blocked_ofd_id, 0);

    t.vm.blocked_syscall_nr = 0;
    t.vm.blocked_syscall_args = [0; 6];
    tidemark_kernel::fs::fd_table::store_process_fd_entry(
        t.base,
        t.vm.process_ptr,
        read_fd as usize,
        FdEntry {
            ofd_id: 0,
            fd_flags: 0,
        },
    );

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_pipe_read_eof_sync_pending(vm_ptr), 1);
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 0);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn pselect_reports_closed_pipe_read_end_as_ready() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as u64;
    assert_eq!(t.sys_close(write_fd as i64), 0);

    let readfds = t.scratch + 0x1100;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, readfds, 1u64 << read_fd);
    }

    t.vm.x[17] = SYS_PSELECT6;
    t.vm.x[10] = read_fd + 1;
    t.vm.x[11] = readfds;
    t.vm.x[12] = 0;
    t.vm.x[13] = 0;
    t.vm.x[14] = 0;
    t.vm.x[15] = 0;
    let result = poll::sys_pselect6(&mut t.vm, t.base, read_fd + 1, readfds, 0, 0, 0, 0);
    assert_eq!(result, 0);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_poll_hup_sync_pending(vm_ptr), 1);
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 1);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, readfds) } & (1u64 << read_fd),
        1u64 << read_fd
    );
}

#[test]
fn pselect_pipe_read_ready_ignores_unwatched_readable_pipe() {
    let mut t = TestVm::new();
    let unrelated_pipefd_addr = t.scratch + 0x1000;
    let watched_pipefd_addr = t.scratch + 0x1010;
    assert_eq!(
        pipe::sys_pipe2(&mut t.vm, t.base, unrelated_pipefd_addr, 0),
        0
    );
    assert_eq!(
        pipe::sys_pipe2(&mut t.vm, t.base, watched_pipefd_addr, 0),
        0
    );
    let unrelated_write_fd =
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, unrelated_pipefd_addr + 4) } as i64;
    let watched_read_fd =
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, watched_pipefd_addr) } as u64;

    assert_eq!(t.sys_close(unrelated_write_fd), 0);

    let readfds = t.scratch + 0x1100;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, readfds, 1u64 << watched_read_fd);
    }

    t.vm.x[17] = SYS_PSELECT6;
    t.vm.x[10] = watched_read_fd + 1;
    t.vm.x[11] = readfds;
    t.vm.x[12] = 0;
    t.vm.x[13] = 0;
    t.vm.x[14] = 0;
    t.vm.x[15] = 0;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_PIPE_WAIT
    );
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_poll_wait_ready_count(vm_ptr), 0);
    assert_eq!(thread_blocked_pipe_read_ready(vm_ptr), 0);
}

#[test]
fn epipe_on_reader_close() {
    let _t = TestVm::new();
    let idx = pipe::alloc_pipe_slot().unwrap();
    pipe::pipe_close(idx, true);
    assert_eq!(pipe::pipe_write(idx, b"data"), EPIPE);
}

#[test]
fn pipe_write_broken_reader_resume_completes_with_epipe() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1200;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as u64;
    assert_eq!(t.sys_close(read_fd as i64), 0);

    let buf_addr = t.scratch + 0x1300;
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(t.base, buf_addr, b"x");
    }
    t.vm.x[17] = SYS_WRITE;
    t.vm.x[10] = write_fd;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 1;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    let vm_ptr = &mut t.vm as *mut _ as u32;
    let resumed = thread_resume_blocked_syscall(vm_ptr);
    assert_eq!(resumed, 0);
    assert_eq!(t.vm.x[10] as i64, EPIPE);
    assert_eq!(t.vm.status, STATUS_FAULT);
    assert_eq!(t.vm.term_signal, SIGPIPE);
}

#[test]
fn pipe_close_outcome_reports_remaining_open_ends() {
    let _t = TestVm::new();
    let idx = pipe::alloc_pipe_slot().unwrap();

    let first = pipe::pipe_close_outcome(idx, true);
    assert_eq!(
        first,
        PipeCloseOutcome {
            read_open: 0,
            write_open: 1,
            slot_released: false,
        }
    );

    let second = pipe::pipe_close_outcome(idx, false);
    assert_eq!(
        second,
        PipeCloseOutcome {
            read_open: 0,
            write_open: 0,
            slot_released: true,
        }
    );
}

#[test]
fn supervisor_fd_control_records_pipe_create_and_close() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let pipefd_addr = t.scratch + 0x1380;
    let flags = (O_CLOEXEC | O_NONBLOCK) as u64;

    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, flags), 0);

    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) };
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) };
    let read_ofd = tidemark_kernel::fs::fd_table::get_ofd_id(t.base, &t.vm, read_fd as u64)
        .expect("pipe read fd should have OFD");
    let write_ofd = tidemark_kernel::fs::fd_table::get_ofd_id(t.base, &t.vm, write_fd as u64)
        .expect("pipe write fd should have OFD");
    let pipe_slot = tidemark_kernel::fs::fd_table::get_ofd_by_id(read_ofd)
        .expect("pipe read OFD should exist")
        .ino;
    let generation = pipe::pipe_generation(pipe_slot);

    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let mut record = vec![0u8; supervisor_fd_control_record_bytes() as usize];
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&record, 0), 0x4446_5354);
    assert_eq!(read_u32_le(&record, 4), supervisor_abi_version());
    assert_eq!(
        read_u32_le(&record, 8),
        supervisor_fd_control_record_bytes()
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_pipe_created()
    );
    assert_eq!(read_u64_le(&record, 16), 1);
    assert_eq!(read_u32_le(&record, 24), vm_ptr);
    assert_eq!(read_u32_le(&record, 28), t.vm.process_ptr);
    assert_eq!(read_u32_le(&record, 36), read_fd);
    assert_eq!(read_u32_le(&record, 40), write_fd);
    assert_eq!(read_u32_le(&record, 44), read_ofd);
    assert_eq!(read_u32_le(&record, 48), write_ofd);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_PIPE as u32);
    assert_eq!(read_u32_le(&record, 56), pipe_slot);
    assert_eq!(read_u32_le(&record, 60), generation);
    assert_eq!(read_u64_le(&record, 64), 0);
    assert_eq!(read_u64_le(&record, 72), flags);
    assert_eq!(read_u64_le(&record, 80), 1);
    assert_eq!(read_u64_le(&record, 88), 1);

    assert_eq!(t.sys_close(write_fd as i64), 0);
    assert_eq!(supervisor_shadow_fd_control_count(), 2);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_fd_closed()
    );
    assert_eq!(read_u64_le(&record, 16), 2);
    assert_eq!(read_u32_le(&record, 24), vm_ptr);
    assert_eq!(read_u32_le(&record, 28), t.vm.process_ptr);
    assert_eq!(read_u32_le(&record, 36), write_fd);
    assert_eq!(read_u32_le(&record, 44), write_ofd);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_PIPE as u32);
    assert_eq!(read_u32_le(&record, 56), pipe_slot);
    assert_eq!(read_u32_le(&record, 60), generation);
    assert_eq!(read_u64_le(&record, 64), 0);
    assert_eq!(read_u64_le(&record, 72), (O_WRONLY | O_NONBLOCK) as u64);
    assert_eq!(read_u64_le(&record, 80), 1);
    assert_eq!(read_u64_le(&record, 88), 0);
}

#[test]
fn supervisor_process_pipe_queries_dedupe_aliases_by_ofd() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let pipefd_addr = t.scratch + 0x1480;

    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) };
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) };
    let dup_read_fd = t.sys_dup(read_fd as u64);
    assert!(dup_read_fd >= 0);

    let read_ofd = tidemark_kernel::fs::fd_table::get_ofd_id(t.base, &t.vm, read_fd as u64)
        .expect("pipe read fd should have OFD");
    let write_ofd = tidemark_kernel::fs::fd_table::get_ofd_id(t.base, &t.vm, write_fd as u64)
        .expect("pipe write fd should have OFD");
    let pipe_slot = tidemark_kernel::fs::fd_table::get_ofd_by_id(read_ofd)
        .expect("pipe read OFD should exist")
        .ino;
    let pipe_bit = 1u64 << pipe_slot;

    assert_eq!(supervisor_process_held_ofd_refcount(vm_ptr, read_ofd), 2);
    assert_eq!(supervisor_process_held_ofd_refcount(vm_ptr, write_ofd), 1);
    assert_ne!(supervisor_process_held_pipe_slot_mask(vm_ptr) & pipe_bit, 0);
    assert_ne!(supervisor_process_pipe_used_mask(vm_ptr) & pipe_bit, 0);
    assert_eq!(
        supervisor_process_pipe_slot_mode(vm_ptr, pipe_slot),
        supervisor_pipe_slot_mode_read() | supervisor_pipe_slot_mode_write()
    );
    assert_eq!(
        supervisor_process_pipe_read_open_count(vm_ptr, pipe_slot),
        1
    );
    assert_eq!(
        supervisor_process_pipe_write_open_count(vm_ptr, pipe_slot),
        1
    );
}

#[test]
fn pipe_slot_zero_is_reserved() {
    let _t = TestVm::new();
    let idx = pipe::alloc_pipe_slot().unwrap();
    assert_ne!(idx, 0);
}

#[test]
fn circular_wrap() {
    let _t = TestVm::new();
    let idx = pipe::alloc_pipe_slot().unwrap();
    let big = [0xABu8; 4000];
    assert_eq!(pipe::pipe_write(idx, &big), 4000);
    let mut tmp = [0u8; 3000];
    assert_eq!(pipe::pipe_read(idx, &mut tmp), 3000);
    let w2 = pipe::pipe_write(idx, &big[..3000]);
    assert!(w2 > 0);
    let mut out = [0u8; 4095];
    let r2 = pipe::pipe_read(idx, &mut out);
    assert!(r2 > 0);
}

#[test]
fn circular_wrap_preserves_split_payload_order() {
    let _t = TestVm::new();
    let idx = pipe::alloc_pipe_slot().unwrap();

    let cap = pipe::PIPE_BUF_SIZE;
    let first_write_len = cap - 512;
    let first_read_len = cap - 1024;
    let wrap_write_len = 2048;
    let remaining_first = first_write_len - first_read_len;

    let first = vec![0xB1u8; first_write_len];
    assert_eq!(pipe::pipe_write(idx, &first), first_write_len as i64);

    let mut tmp = vec![0u8; first_read_len];
    assert_eq!(pipe::pipe_read(idx, &mut tmp), first_read_len as i64);

    let wrapped = vec![0xC2u8; wrap_write_len];
    assert_eq!(pipe::pipe_write(idx, &wrapped), wrap_write_len as i64);

    let mut out = vec![0u8; remaining_first + wrap_write_len];
    assert_eq!(pipe::pipe_read(idx, &mut out), out.len() as i64);
    assert!(out[..remaining_first].iter().all(|byte| *byte == 0xB1));
    assert!(out[remaining_first..].iter().all(|byte| *byte == 0xC2));
}

#[test]
fn sys_pipe2_sets_cloexec_and_nonblock_flags() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;

    assert_eq!(
        pipe::sys_pipe2(
            &mut t.vm,
            t.base,
            pipefd_addr,
            (O_CLOEXEC | O_NONBLOCK) as u64
        ),
        0
    );

    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as i64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    assert!(read_fd >= 3);
    assert!(write_fd >= 3);

    assert_eq!(t.sys_fcntl(read_fd as u64, 1, 0), 1);
    assert_eq!(t.sys_fcntl(write_fd as u64, 1, 0), 1);
    assert_ne!(t.sys_fcntl(read_fd as u64, 3, 0) & O_NONBLOCK as i64, 0);
    assert_ne!(t.sys_fcntl(write_fd as u64, 3, 0) & O_NONBLOCK as i64, 0);

    assert_eq!(t.sys_write_data(write_fd, b"ok"), 2);
    let mut buf = [0u8; 2];
    assert_eq!(t.sys_read(read_fd, &mut buf), 2);
    assert_eq!(&buf, b"ok");
}

#[test]
fn sys_pipe2_reports_read_write_access_modes() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1400;

    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);

    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as i64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;

    assert_eq!(
        t.sys_fcntl(read_fd as u64, 3, 0) & OPEN_ACCESS_MODE_MASK,
        O_RDONLY as i64
    );
    assert_eq!(
        t.sys_fcntl(write_fd as u64, 3, 0) & OPEN_ACCESS_MODE_MASK,
        O_WRONLY as i64
    );
}

#[test]
fn ioctl_fionbio_toggles_pipe_nonblock_status() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1500;

    assert_eq!(
        pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, O_NONBLOCK as u64),
        0
    );

    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let flag_addr = t.scratch + 0x1510;

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, flag_addr, 0);
    }
    assert_eq!(
        pty::sys_ioctl(&mut t.vm, t.base, read_fd, FIONBIO, flag_addr),
        0
    );
    assert_eq!(t.sys_fcntl(read_fd, 3, 0) & O_NONBLOCK as i64, 0);

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, flag_addr, 1);
    }
    assert_eq!(
        pty::sys_ioctl(&mut t.vm, t.base, read_fd, FIONBIO, flag_addr),
        0
    );
    assert_ne!(t.sys_fcntl(read_fd, 3, 0) & O_NONBLOCK as i64, 0);
}

#[test]
fn eventfd_roundtrip_and_nonblock_flags() {
    let mut t = TestVm::new();
    let fd = pipe::sys_eventfd2(&mut t.vm, t.base, 2, (O_CLOEXEC | O_NONBLOCK) as u64);
    assert!(fd >= 3);
    assert_eq!(t.sys_fcntl(fd as u64, 1, 0), 1);
    assert_ne!(t.sys_fcntl(fd as u64, 3, 0) & O_NONBLOCK as i64, 0);

    let buf_addr = t.scratch + 0x1800;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, buf_addr, 3);
    }
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_write(
            &mut t.vm, t.base, fd as u64, buf_addr, 8, SYS_WRITE
        ),
        8
    );
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf_addr) },
        5
    );
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
        EAGAIN
    );
}

#[test]
fn eventfd_read_reports_linux_shaped_error_cases() {
    let mut t = TestVm::new();
    let fd = pipe::sys_eventfd2(&mut t.vm, t.base, 10, O_NONBLOCK as u64);
    assert!(fd >= 3);

    let buf_addr = t.scratch + 0x1900;
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf_addr) },
        10
    );
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
        EAGAIN
    );

    let fd2 = pipe::sys_eventfd2(&mut t.vm, t.base, 1, 0);
    assert!(fd2 >= 3);
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd2 as u64, buf_addr, 4),
        EINVAL
    );
}

#[test]
fn eventfd_write_reports_linux_shaped_error_cases() {
    let mut t = TestVm::new();
    let fd = pipe::sys_eventfd2(&mut t.vm, t.base, 0, O_NONBLOCK as u64);
    assert!(fd >= 3);

    let buf_addr = t.scratch + 0x1a00;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, buf_addr, 12);
    }
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_write(
            &mut t.vm, t.base, fd as u64, buf_addr, 8, SYS_WRITE
        ),
        8
    );
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf_addr) },
        12
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, buf_addr, u64::MAX - 1);
    }
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_write(
            &mut t.vm, t.base, fd as u64, buf_addr, 8, SYS_WRITE
        ),
        8
    );
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_write(
            &mut t.vm, t.base, fd as u64, buf_addr, 8, SYS_WRITE
        ),
        EAGAIN
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, buf_addr, 7);
    }
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_write(
            &mut t.vm, t.base, fd as u64, buf_addr, 4, SYS_WRITE
        ),
        EINVAL
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, buf_addr, u64::MAX);
    }
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_write(
            &mut t.vm, t.base, fd as u64, buf_addr, 8, SYS_WRITE
        ),
        EINVAL
    );
}

#[test]
fn eventfd_semaphore_reads_one_per_token() {
    let mut t = TestVm::new();
    let fd = pipe::sys_eventfd2(&mut t.vm, t.base, 2, EFD_SEMAPHORE | O_NONBLOCK as u64);
    assert!(fd >= 3);

    let buf_addr = t.scratch + 0x1b00;
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf_addr) },
        1
    );
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf_addr) },
        1
    );
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
        EAGAIN
    );

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, buf_addr, 5);
    }
    assert_eq!(
        tidemark_kernel::syscall::fs::sys_write(
            &mut t.vm, t.base, fd as u64, buf_addr, 8, SYS_WRITE
        ),
        8
    );
    for _ in 0..5 {
        assert_eq!(
            tidemark_kernel::syscall::fs::sys_read(&mut t.vm, t.base, fd as u64, buf_addr, 8),
            8
        );
        assert_eq!(
            unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf_addr) },
            1
        );
    }
}

#[test]
fn eventfd_blocked_read_resume_writes_guest_buffer_before_returning() {
    let mut t = TestVm::new();
    let fd = pipe::sys_eventfd2(&mut t.vm, t.base, 0, EFD_SEMAPHORE);
    assert!(fd >= 3);

    let buf_addr = t.scratch + 0x1b00;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, buf_addr, 0);
    }

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = fd as u64;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 8;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    tidemark_kernel::fs::fd_table::set_offset(t.base, &t.vm, fd as u64, 1);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 8);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf_addr) },
        1
    );
}

#[test]
fn eventfd_blocked_read_resume_writes_stack_buffer_before_returning() {
    let mut t = TestVm::new();
    let fd = pipe::sys_eventfd2(&mut t.vm, t.base, 0, EFD_SEMAPHORE);
    assert!(fd >= 3);

    t.vm.x[2] = t.scratch + 0x2000;
    let buf_addr = (t.vm.x[2] - 16) as u64;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, buf_addr, 0);
    }

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = fd as u64;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 8;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    tidemark_kernel::fs::fd_table::set_offset(t.base, &t.vm, fd as u64, 1);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 8);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf_addr) },
        1
    );
}

#[test]
fn eventfd_blocked_read_resume_preserves_register_context() {
    let mut t = TestVm::new();
    let fd = pipe::sys_eventfd2(&mut t.vm, t.base, 0, EFD_SEMAPHORE);
    assert!(fd >= 3);

    let buf_addr = t.scratch + 0x1d00;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, buf_addr, 0);
    }

    t.vm.x[17] = SYS_READ;
    t.vm.x[10] = fd as u64;
    t.vm.x[11] = buf_addr;
    t.vm.x[12] = 8;
    let status = tidemark_kernel::syscall::dispatch(&mut t.vm, t.base);
    assert_eq!(status, STATUS_PIPE_WAIT);
    assert_eq!(t.vm.status, STATUS_PIPE_WAIT);

    t.vm.pc = 0x4455_6677;
    t.vm.x[1] = 0x5566_7788;
    t.vm.x[2] = t.scratch + 0x2800;
    t.vm.x[27] = 0x7788_9900;

    tidemark_kernel::fs::fd_table::set_offset(t.base, &t.vm, fd as u64, 1);
    let vm_ptr = &mut t.vm as *mut _ as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 8);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, 0x4455_6677);
    assert_eq!(t.vm.x[1], 0x5566_7788);
    assert_eq!(t.vm.x[2], t.scratch + 0x2800);
    assert_eq!(t.vm.x[27], 0x7788_9900);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, buf_addr) },
        1
    );
}
