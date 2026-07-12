use super::support::*;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLLIN: u32 = 0x001;

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

#[test]
fn local_vfork_cleanup_preserves_epoll_interest_for_runtime_restore() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1800;
    let event_addr = t.scratch + 0x1820;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as u64;
    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x1234);
    }
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            read_fd,
            event_addr,
        ),
        0
    );

    let fds = [read_fd as usize, write_fd as usize, epfd as usize];
    let snapshots = fds.map(|fd| {
        let ofd_id = fd_table::get_ofd_id(t.base, &t.vm, fd as u64)
            .expect("fd should have an OFD before local cleanup");
        let ofd = fd_table::get_ofd_by_id(ofd_id).expect("OFD should exist before local cleanup");
        (fd, ofd_id, ofd)
    });

    fd_table::close_all_for_process_without_backend_cleanup(t.base, &t.vm);

    let table = fd_table::ofd_table_ptr() as *mut OpenFileDesc;
    for (fd, ofd_id, ofd) in snapshots {
        unsafe {
            table.add(ofd_id as usize).write(ofd);
        }
        fd_table::store_process_fd_entry(
            t.base,
            t.vm.process_ptr,
            fd,
            FdEntry {
                ofd_id,
                fd_flags: 0,
            },
        );
    }

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_DEL,
            read_fd,
            event_addr,
        ),
        0
    );
}
