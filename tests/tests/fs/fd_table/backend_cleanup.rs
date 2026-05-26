use super::support::*;

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
    let generation = pipe::pipe_generation(pipe_idx);
    let slot = pipe::slot_addr(pipe_idx);

    let cleanup = fd_table::release_ofd_id_deferred(ofd_id);
    assert_eq!(
        cleanup,
        Some(BackendCleanup::Pipe {
            pipe_idx,
            generation,
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
