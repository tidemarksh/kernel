use tidemark_kernel::abi::*;
use tidemark_kernel::fs::fd_table;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::socket;
use tidemark_kernel::syscall::{epoll, fs, pipe, time};
use tidemark_kernel::types::ProcessState;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;

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
fn epoll_ctl_mod_reports_pipe_write_end_level_trigger_writable() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let read_event_addr = t.scratch + 0x2000;
    let write_event_addr = t.scratch + 0x2010;
    let out_addr = t.scratch + 0x3000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, read_event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, read_event_addr + 8, read_fd);
        tidemark_kernel::guest_mem::write_u32(t.base, write_event_addr, EPOLLOUT);
        tidemark_kernel::guest_mem::write_u64(t.base, write_event_addr + 8, write_fd as u64);
    }

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            read_fd,
            read_event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            write_fd as u64,
            read_event_addr,
        ),
        0
    );

    assert_eq!(t.sys_write_data(write_fd, b"x"), 1);
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_MOD,
            write_fd as u64,
            write_event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 2, 0, 0),
        2
    );
    let first_events = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) };
    let first_data = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) };
    let second_events = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr + 16) };
    let second_data = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 24) };
    let mut saw_read = false;
    let mut saw_write = false;
    for (events, data) in [(first_events, first_data), (second_events, second_data)] {
        if events == EPOLLIN && data == read_fd {
            saw_read = true;
        }
        if events == EPOLLOUT && data == write_fd as u64 {
            saw_write = true;
        }
    }
    assert!(saw_read, "expected EPOLLIN for the pipe read end");
    assert!(saw_write, "expected EPOLLOUT for the pipe write end");
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
fn epoll_pwait_resume_reports_ready_events_with_ok_status() {
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
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x77);
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
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, -1, 0),
        0
    );
    assert_eq!(t.vm.status, STATUS_EPOLL_WAIT);

    let waiting_status = t.vm.status;
    let waiting_fault_addr = t.vm.fault_addr;
    let waiting_fault_pc = t.vm.fault_pc;
    t.vm.status = STATUS_OK;
    assert_eq!(t.sys_write_data(write_fd, b"x"), 1);
    t.vm.status = waiting_status;
    t.vm.fault_addr = waiting_fault_addr;
    t.vm.fault_pc = waiting_fault_pc;
    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 1);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], 1);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        EPOLLIN
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x77
    );
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
fn epoll_keys_duplicate_aliases_by_fd_and_ofd() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    let dup_fd = t.sys_dup(read_fd);
    assert!(dup_fd >= 3);

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let first_event_addr = t.scratch + 0x2000;
    let second_event_addr = t.scratch + 0x2010;
    let out_addr = t.scratch + 0x3000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, first_event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, first_event_addr + 8, 0x11);
        tidemark_kernel::guest_mem::write_u32(t.base, second_event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, second_event_addr + 8, 0x22);
    }

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            read_fd,
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
            dup_fd as u64,
            second_event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_ctl(&mut t.vm, t.base, epfd as u64, EPOLL_CTL_DEL, read_fd, 0,),
        0
    );

    assert_eq!(t.sys_write_data(write_fd, b"x"), 1);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 4, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x22
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
fn epoll_ctl_adds_cloexec_eventfd_after_cloexec_epoll_create() {
    let mut t = TestVm::new();
    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, O_CLOEXEC as u64);
    assert!(epfd >= 3);
    let efd = pipe::sys_eventfd2(&mut t.vm, t.base, 0, (O_NONBLOCK | O_CLOEXEC) as u64);
    assert!(efd >= 3);
    assert_ne!(epfd, efd);

    let event_addr = t.scratch + 0x2000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0xfeed);
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
}

#[test]
fn epoll_pwait_reports_ready_timerfd() {
    let mut t = TestVm::new();
    let tfd = time::sys_timerfd_create(&mut t.vm, t.base, 1, O_NONBLOCK as u64);
    assert!(tfd >= 3);

    let spec_addr = t.scratch + 0x3400;
    let event_addr = t.scratch + 0x3440;
    let out_addr = t.scratch + 0x3460;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, spec_addr, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, spec_addr + 8, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, spec_addr + 16, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, spec_addr + 24, 0);
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0xfeed);
    }
    assert_eq!(
        time::sys_timerfd_settime(&t.vm, t.base, tfd as u64, 0, spec_addr, 0),
        0
    );

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            tfd as u64,
            event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );

    time::advance_monotonic_duration(core::time::Duration::from_secs(1));
    let timerfd_idx = fd_table::get_ofd(t.base, &t.vm, tfd as u64)
        .expect("timerfd OFD should exist")
        .ino;
    assert!(time::timerfd_is_readable(timerfd_idx));
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
        0xfeed
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
fn epoll_pwait_oneshot_delivers_once_until_rearmed() {
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
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN | EPOLLONESHOT);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x5151);
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

    assert_eq!(t.sys_write_data(write_fd, b"a"), 1);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x5151
    );

    let mut buf = [0u8; 1];
    assert_eq!(t.sys_read(read_fd as i64, &mut buf), 1);
    assert_eq!(buf, [b'a']);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );

    assert_eq!(t.sys_write_data(write_fd, b"b"), 1);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_MOD,
            read_fd,
            event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x5151
    );
}

#[test]
fn epoll_pwait_edge_trigger_reports_only_new_edges() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(
        pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, O_NONBLOCK as u64),
        0
    );
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let read_event_addr = t.scratch + 0x2000;
    let write_event_addr = t.scratch + 0x2010;
    let out_addr = t.scratch + 0x3000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, read_event_addr, EPOLLIN | EPOLLET);
        tidemark_kernel::guest_mem::write_u64(t.base, read_event_addr + 8, 0x6060);
        tidemark_kernel::guest_mem::write_u32(t.base, write_event_addr, EPOLLOUT | EPOLLET);
        tidemark_kernel::guest_mem::write_u64(t.base, write_event_addr + 8, 0x7070);
    }

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            read_fd,
            read_event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            write_fd as u64,
            write_event_addr,
        ),
        0
    );

    let payload = vec![b'a'; 512];
    let mut written = 0usize;
    loop {
        let n = t.sys_write_data(write_fd, &payload);
        if n <= 0 {
            break;
        }
        written += n as usize;
    }
    assert!(
        written > 1,
        "pipe should accept enough bytes to test edge mode"
    );
    let half = written / 2;
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x6060
    );

    let mut first_half = vec![0u8; half];
    assert_eq!(t.sys_read(read_fd as i64, &mut first_half), half as i64);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );

    let mut second_half = vec![0u8; written - half];
    assert_eq!(
        t.sys_read(read_fd as i64, &mut second_half),
        (written - half) as i64
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x7070
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

#[test]
fn epoll_pwait_reports_rd_hup_after_shutdown_read() {
    let mut t = TestVm::new();
    let listener_fd = socket::sys_socket(&mut t.vm, t.base, AF_INET as u64, SOCK_STREAM as u64, 0);
    assert!(listener_fd >= 0);
    let sockaddr: [u8; 16] = [2, 0, 0x50, 0x00, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let bind_addr = t.scratch + 0x340;
    t.write_mem(bind_addr, &sockaddr);
    assert_eq!(
        socket::sys_bind(&mut t.vm, t.base, listener_fd as u64, bind_addr, 16),
        0
    );
    assert_eq!(
        socket::sys_listen(&mut t.vm, t.base, listener_fd as u64, 8),
        0
    );

    let client_idx = socket::inject_http_connection(0, 0x5000, b"GET / HTTP/1.0\r\n\r\n");
    assert!(client_idx >= 0);
    let client_fd = fd_table::open_socket(&mut t.vm, t.base, client_idx as u32, 0);
    assert!(client_fd >= 0);

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);

    let event_addr = t.scratch + 0x2200;
    let out_addr = t.scratch + 0x3200;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLRDHUP);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x8888);
    }
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            client_fd as u64,
            event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        0
    );
    assert_eq!(
        socket::sys_shutdown(&mut t.vm, t.base, client_fd as u64, SHUT_RD as u64),
        0
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        EPOLLRDHUP
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
        0x8888
    );
}
