use tidemark_kernel::abi::*;
use tidemark_kernel::fs::fd_table;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::{epoll, fs, pipe};
use tidemark_kernel::types::ProcessState;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLLIN: u32 = 0x001;

#[test]
fn close_epoll_clears_instance_slot() {
    let mut t = TestVm::new();
    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let epoll_idx = fd_table::get_ofd(t.base, &t.vm, epfd as u64)
        .expect("epoll OFD should exist")
        .ino;
    assert!(epoll::epoll_slot_allocated(epoll_idx));

    assert_eq!(t.sys_close(epfd), 0);
    assert!(!epoll::epoll_slot_allocated(epoll_idx));
}

#[test]
fn epoll_pwait_reports_ready_pipe() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let event_addr = t.scratch + 0x2000;
    let out_addr = t.scratch + 0x3000;
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
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );

    assert_eq!(t.sys_write_data(write_fd, b"x"), 1);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        EPOLLIN
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x1234
    );
}

#[test]
fn epoll_pwait_sets_wait_status_for_blocking_calls() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let event_addr = t.scratch + 0x2000;
    let out_addr = t.scratch + 0x3000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x55);
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

    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 10, 0),
        0
    );
    assert_eq!(t.vm.status, STATUS_EPOLL_WAIT);
    assert_eq!(t.vm.fault_addr, epfd as u64);
    assert_eq!(t.vm.fault_pc, out_addr);
}

#[test]
fn epoll_pwait_pins_blocked_epoll_fd_and_releases_on_timeout() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let event_addr = t.scratch + 0x2000;
    let out_addr = t.scratch + 0x3000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x55);
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

    let epoll_ofd = unsafe {
        let ps = &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState);
        ps.fd_table[epfd as usize].ofd_id
    };
    let before = fd_table::get_ofd_by_id(epoll_ofd).expect("epoll OFD should be tracked");
    assert_eq!(before.refcount, 1);

    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 10, 0),
        0
    );
    assert_eq!(t.vm.status, STATUS_EPOLL_WAIT);
    assert_eq!(t.vm.blocked_fd, epfd as u32);
    assert_eq!(t.vm.blocked_ofd_id, epoll_ofd);
    let pinned = fd_table::get_ofd_by_id(epoll_ofd).expect("blocked epoll OFD should stay pinned");
    assert_eq!(pinned.refcount, 2);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    thread_resume_epoll_wait_timeout(vm_ptr);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.blocked_fd, 0);
    assert_eq!(t.vm.blocked_ofd_id, 0);
    let released = fd_table::get_ofd_by_id(epoll_ofd).expect("epoll OFD should still exist");
    assert_eq!(released.refcount, 1);
}

#[test]
fn epoll_interest_follows_ofd_until_last_alias_and_not_reused_fd() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    let dup_fd = t.sys_dup(read_fd);
    assert!(dup_fd >= 3);

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let event_addr = t.scratch + 0x2000;
    let out_addr = t.scratch + 0x3000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x66);
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

    assert_eq!(t.sys_close(read_fd as i64), 0);
    assert_eq!(t.sys_write_data(write_fd, b"x"), 1);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x66
    );

    let mut buf = [0u8; 1];
    assert_eq!(t.sys_read(dup_fd, &mut buf), 1);
    assert_eq!(buf, [b'x']);
    assert_eq!(t.sys_close(dup_fd), 0);

    let new_pipefd_addr = t.scratch + 0x1100;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, new_pipefd_addr, 0), 0);
    let new_read_fd =
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, new_pipefd_addr) } as u64;
    let new_write_fd =
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, new_pipefd_addr + 4) } as i64;
    assert_eq!(new_read_fd, read_fd);

    assert_eq!(t.sys_write_data(new_write_fd, b"y"), 1);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );
}

#[test]
fn epoll_pwait_reports_ready_eventfd() {
    let mut t = TestVm::new();
    let efd = pipe::sys_eventfd2(&mut t.vm, t.base, 0, (O_NONBLOCK | O_CLOEXEC) as u64);
    assert!(efd >= 3);

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let event_addr = t.scratch + 0x2000;
    let out_addr = t.scratch + 0x3000;
    let buf_addr = t.scratch + 0x4000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x9876);
        tidemark_kernel::guest_mem::write_u64(t.base, buf_addr, 1);
    }

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            efd as u64,
            event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );

    assert_eq!(
        fs::sys_write(&mut t.vm, t.base, efd as u64, buf_addr, 8, SYS_WRITE),
        8
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        EPOLLIN
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x9876
    );
}

#[test]
fn epoll_pwait_writes_riscv_event_array() {
    let mut t = TestVm::new();
    let first_pipefd_addr = t.scratch + 0x1000;
    let second_pipefd_addr = t.scratch + 0x1100;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, first_pipefd_addr, 0), 0);
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, second_pipefd_addr, 0), 0);
    let first_read_fd =
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, first_pipefd_addr) } as u64;
    let first_write_fd =
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, first_pipefd_addr + 4) } as i64;
    let second_read_fd =
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, second_pipefd_addr) } as u64;
    let second_write_fd =
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, second_pipefd_addr + 4) } as i64;

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let first_event_addr = t.scratch + 0x2000;
    let second_event_addr = t.scratch + 0x2010;
    let out_addr = t.scratch + 0x3000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, first_event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, first_event_addr + 8, 0x1111);
        tidemark_kernel::guest_mem::write_u32(t.base, second_event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, second_event_addr + 8, 0x2222);
    }

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            first_read_fd,
            first_event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            second_read_fd,
            second_event_addr,
        ),
        0
    );

    assert_eq!(t.sys_write_data(first_write_fd, b"x"), 1);
    assert_eq!(t.sys_write_data(second_write_fd, b"y"), 1);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 2, 0, 0),
        2
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        EPOLLIN
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x1111
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr + 16) },
        EPOLLIN
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 24) },
        0x2222
    );
}

#[test]
fn epoll_ctl_rejects_regular_files_with_eperm() {
    let mut t = TestVm::new();
    t.memfs.create_file(b"regular.txt", b"hello");
    let file_fd = t.sys_openat(b"/regular.txt", O_RDONLY);
    assert!(file_fd >= 3);

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let event_addr = t.scratch + 0x2000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x44);
    }

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            file_fd as u64,
            event_addr,
        ),
        EPERM
    );
}
