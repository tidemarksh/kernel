use tidemark_kernel::abi::*;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::pipe::{self, PipeCloseOutcome};

const OPEN_ACCESS_MODE_MASK: i64 = 0x3;

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
fn eof_on_writer_close() {
    let _t = TestVm::new();
    let idx = pipe::alloc_pipe_slot().unwrap();
    pipe::pipe_close(idx, false);
    let mut buf = [0u8; 16];
    assert_eq!(pipe::pipe_read(idx, &mut buf), 0);
}

#[test]
fn epipe_on_reader_close() {
    let _t = TestVm::new();
    let idx = pipe::alloc_pipe_slot().unwrap();
    pipe::pipe_close(idx, true);
    assert_eq!(pipe::pipe_write(idx, b"data"), EPIPE);
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
