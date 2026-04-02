use core::sync::atomic::Ordering;
use tidemark_kernel::abi::*;
use tidemark_kernel::fs::fd_table::{self, BackendCleanup};
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::{epoll, pipe};

const LOCK_SH: u64 = 0x1;
const LOCK_EX: u64 = 0x2;
const LOCK_NB: u64 = 0x4;
const LOCK_UN: u64 = 0x8;

#[test]
fn fd_table_syscalls() {
    let mut t = TestVm::new();

    let newfd = t.sys_dup(1);
    assert_eq!(newfd, 3);

    assert_eq!(t.sys_fcntl(3, 1, 0), 0);
    assert_eq!(t.sys_fcntl(3, 2, 1), 0);
    assert_eq!(t.sys_fcntl(3, 1, 0), 1);

    assert_eq!(t.sys_close(3), 0);
    assert_eq!(t.sys_close(3), EBADF);
    assert_eq!(t.sys_dup3(1, 10, O_CLOEXEC as u64), 10);
}

#[test]
fn close_shared_fd_only_drops_last_process_reference() {
    let mut t = TestVm::new();
    let fd = t.sys_dup(1);
    assert_eq!(fd, 3);

    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, 1).expect("stdout OFD should exist");
    assert_eq!(
        fd_table::get_ofd_by_id(ofd_id)
            .expect("stdout OFD should exist")
            .refcount,
        1
    );

    assert_eq!(t.sys_close(fd), 0);
    assert_eq!(
        fd_table::get_ofd_by_id(ofd_id)
            .expect("stdout OFD should still exist after closing duplicate")
            .refcount,
        1
    );

    assert_eq!(t.sys_close(1), 0);
    assert!(fd_table::get_ofd_by_id(ofd_id).is_none());
}

#[test]
fn retain_fds_for_fork_counts_distinct_ofds_once() {
    let mut t = TestVm::new();
    let fd = t.sys_dup(1);
    assert_eq!(fd, 3);

    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, 1).expect("stdout OFD should exist");
    assert_eq!(
        fd_table::get_ofd_by_id(ofd_id)
            .expect("stdout OFD should exist")
            .refcount,
        1
    );

    fd_table::retain_fds_for_fork(t.base, &t.vm);
    assert_eq!(
        fd_table::get_ofd_by_id(ofd_id)
            .expect("stdout OFD should still exist")
            .refcount,
        2
    );
}

#[test]
fn inode_has_write_open_tracks_open_and_close() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/etxtbusy.bin", O_CREAT | O_WRONLY);
    assert!(fd >= 3);

    let ino = tidemark_kernel::fs::memfs::resolve_path(b"/etxtbusy.bin");
    assert!(ino > 0);
    assert!(fd_table::inode_has_write_open(ino));

    assert_eq!(t.sys_close(fd), 0);
    assert!(!fd_table::inode_has_write_open(ino));
}

#[test]
fn deferred_pipe_cleanup_separates_last_close_from_backend_close() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1800;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);

    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, read_fd).expect("pipe OFD should exist");
    let pipe_idx = fd_table::get_ofd_by_id(ofd_id)
        .expect("pipe OFD should exist")
        .ino;
    let slot = pipe::slot_addr(pipe_idx);

    let cleanup = fd_table::release_ofd_id_deferred(ofd_id);
    assert_eq!(
        cleanup,
        Some(BackendCleanup::Pipe {
            pipe_idx,
            is_read_end: true,
            ofd_id,
        })
    );
    assert!(fd_table::get_ofd_by_id(ofd_id).is_none());
    assert_eq!(pipe::read_open_ptr(slot).load(Ordering::Acquire), 1);

    fd_table::run_backend_cleanup(cleanup.expect("cleanup action should exist"));
    assert_eq!(pipe::read_open_ptr(slot).load(Ordering::Acquire), 0);
}

#[test]
fn deferred_epoll_cleanup_separates_last_close_from_backend_close() {
    let mut t = TestVm::new();
    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, epfd as u64).expect("epoll OFD should exist");
    let epoll_idx = fd_table::get_ofd_by_id(ofd_id)
        .expect("epoll OFD should exist")
        .ino;

    let cleanup = fd_table::release_ofd_id_deferred(ofd_id);
    assert_eq!(cleanup, Some(BackendCleanup::Epoll { epoll_idx }));
    assert!(fd_table::get_ofd_by_id(ofd_id).is_none());
    assert!(epoll::epoll_slot_allocated(epoll_idx));

    fd_table::run_backend_cleanup(cleanup.expect("cleanup action should exist"));
    assert!(!epoll::epoll_slot_allocated(epoll_idx));
}

#[test]
fn flock_rejects_invalid_operations() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/flock-invalid.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);

    assert_eq!(t.sys_flock(fd as u64, LOCK_NB), EINVAL);
    assert_eq!(t.sys_flock(fd as u64, LOCK_SH | LOCK_EX), EINVAL);
}

#[test]
fn flock_is_shared_by_dup_and_conflicts_across_distinct_ofds() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/flock.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    let dup_fd = t.sys_dup(fd as u64);
    assert!(dup_fd >= 3);
    let other_fd = t.sys_openat(b"/flock.txt", O_RDWR);
    assert!(other_fd >= 3);

    assert_eq!(t.sys_flock(fd as u64, LOCK_EX), 0);
    assert_eq!(t.sys_flock(other_fd as u64, LOCK_EX | LOCK_NB), EAGAIN);

    assert_eq!(t.sys_flock(dup_fd as u64, LOCK_UN), 0);
    assert_eq!(t.sys_flock(other_fd as u64, LOCK_EX), 0);
}

#[test]
fn flock_blocks_without_lock_nb() {
    let mut t = TestVm::new();
    let fd = t.sys_openat(b"/flock-block.txt", O_CREAT | O_RDWR);
    assert!(fd >= 3);
    let other_fd = t.sys_openat(b"/flock-block.txt", O_RDWR);
    assert!(other_fd >= 3);

    assert_eq!(t.sys_flock(fd as u64, LOCK_EX), 0);
    assert_eq!(t.sys_flock(other_fd as u64, LOCK_SH), 0);
    assert_eq!(t.vm.status, STATUS_FLOCK_WAIT);

    assert_eq!(t.sys_flock(fd as u64, LOCK_UN), 0);
    t.vm.status = STATUS_OK;
    assert_eq!(t.sys_flock(other_fd as u64, LOCK_SH), 0);
    assert_ne!(t.vm.status, STATUS_FLOCK_WAIT);
}
