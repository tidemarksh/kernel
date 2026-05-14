use tidemark_kernel::abi::*;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::pipe::{self, PipeCloseOutcome};
use tidemark_kernel::syscall::{poll, pty};

const OPEN_ACCESS_MODE_MASK: i64 = 0x3;
const EFD_SEMAPHORE: u64 = 0x1;
const FIONBIO: u64 = 0x5421;
const SYNC_EFFECT_PIPE_STATE: u32 = 1 << 0;
const SYNC_EFFECT_EPOLL_STATE: u32 = 1 << 2;
const SYNC_EFFECT_FORK_SHARED_OFD_STATE: u32 = 1 << 6;

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
