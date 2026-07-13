use tidemark_kernel::abi::*;
use tidemark_kernel::fs::fd_table;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::syscall::socket;
use tidemark_kernel::syscall::{epoll, fs, pipe, signal, time};
use tidemark_kernel::types::ProcessState;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;

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

fn read_i64_le(bytes: &[u8], offset: usize) -> i64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    i64::from_le_bytes(value)
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

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
fn supervisor_fd_control_records_epoll_create_and_ctl() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1800;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let read_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, read_fd).expect("pipe read OFD should exist");

    supervisor_reset_shadow_log();
    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, O_CLOEXEC as u64);
    assert!(epfd >= 3);
    let epoll_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, epfd as u64).expect("epoll OFD should exist");
    let epoll_idx = fd_table::get_ofd(t.base, &t.vm, epfd as u64)
        .expect("epoll OFD should exist")
        .ino;

    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let mut record = vec![0u8; supervisor_fd_control_record_bytes() as usize];
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_epoll_created()
    );
    assert_eq!(read_u32_le(&record, 36), epfd as u32);
    assert_eq!(read_u32_le(&record, 44), epoll_ofd);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_EPOLL as u32);
    assert_eq!(read_u32_le(&record, 56), epoll_idx);
    assert_eq!(read_u64_le(&record, 64), epfd as u64);
    assert_eq!(read_u64_le(&record, 72), O_CLOEXEC as u64);

    let add_event_addr = t.scratch + 0x2000;
    let mod_event_addr = t.scratch + 0x2010;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, add_event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, add_event_addr + 8, 0x1234);
        tidemark_kernel::guest_mem::write_u32(t.base, mod_event_addr, EPOLLOUT);
        tidemark_kernel::guest_mem::write_u64(t.base, mod_event_addr + 8, 0x5678);
    }
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            read_fd,
            add_event_addr,
        ),
        0
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 2);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_epoll_ctl_add()
    );
    assert_eq!(read_u32_le(&record, 36), epfd as u32);
    assert_eq!(read_u32_le(&record, 40), read_fd as u32);
    assert_eq!(read_u32_le(&record, 44), epoll_ofd);
    assert_eq!(read_u32_le(&record, 48), read_ofd);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_PIPE as u32);
    assert_eq!(read_u32_le(&record, 56), epoll_idx);
    assert_eq!(read_u32_le(&record, 60), 1);
    assert_eq!(read_u64_le(&record, 72), EPOLLIN as u64);
    assert_eq!(read_u64_le(&record, 80), 0x1234);
    assert_eq!(read_u64_le(&record, 88), 1);

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_MOD,
            read_fd,
            mod_event_addr,
        ),
        0
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 3);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_epoll_ctl_mod()
    );
    assert_eq!(read_u64_le(&record, 72), EPOLLOUT as u64);
    assert_eq!(read_u64_le(&record, 80), 0x5678);
    assert_eq!(read_u64_le(&record, 88), 1);

    assert_eq!(
        epoll::sys_epoll_ctl(&mut t.vm, t.base, epfd as u64, EPOLL_CTL_DEL, read_fd, 0),
        0
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 4);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_epoll_ctl_del()
    );
    assert_eq!(read_u64_le(&record, 72), EPOLLOUT as u64);
    assert_eq!(read_u64_le(&record, 80), 0x5678);
    assert_eq!(read_u64_le(&record, 88), 0);
}

#[test]
fn supervisor_fd_control_records_epoll_ctl_failures() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1800;
    let event_addr = t.scratch + 0x2000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let read_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, read_fd).expect("pipe read OFD should exist");

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);
    let epoll_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, epfd as u64).expect("epoll OFD should exist");
    let epoll_idx = fd_table::get_ofd(t.base, &t.vm, epfd as u64)
        .expect("epoll OFD should exist")
        .ino;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x1234);
    }

    let mut record = vec![0u8; supervisor_fd_control_record_bytes() as usize];
    supervisor_reset_shadow_log();
    assert_eq!(
        epoll::sys_epoll_ctl(&mut t.vm, t.base, 999, EPOLL_CTL_ADD, read_fd, event_addr),
        EBADF
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_epoll_ctl_add()
    );
    assert_eq!(read_u32_le(&record, 36), 999);
    assert_eq!(read_u32_le(&record, 40), read_fd as u32);
    assert_eq!(read_u32_le(&record, 44), 0);
    assert_eq!(read_i64_le(&record, 64), EBADF);
    assert_eq!(read_u64_le(&record, 72), EPOLL_CTL_ADD);
    assert_eq!(read_u64_le(&record, 80), 1);

    supervisor_reset_shadow_log();
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            999,
            event_addr
        ),
        EBADF
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&record, 36), epfd as u32);
    assert_eq!(read_u32_le(&record, 40), 999);
    assert_eq!(read_u32_le(&record, 44), epoll_ofd);
    assert_eq!(read_u32_le(&record, 48), 0);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_NONE as u32);
    assert_eq!(read_u32_le(&record, 56), epoll_idx);
    assert_eq!(read_i64_le(&record, 64), EBADF);
    assert_eq!(read_u64_le(&record, 72), EPOLL_CTL_ADD);
    assert_eq!(read_u64_le(&record, 80), 4);
    assert_eq!(read_u64_le(&record, 88), epoll_idx as u64);

    supervisor_reset_shadow_log();
    epoll::close_epoll(epoll_idx);
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            read_fd,
            event_addr,
        ),
        EBADF
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&record, 36), epfd as u32);
    assert_eq!(read_u32_le(&record, 40), read_fd as u32);
    assert_eq!(read_u32_le(&record, 44), epoll_ofd);
    assert_eq!(read_u32_le(&record, 48), read_ofd);
    assert_eq!(read_u32_le(&record, 52), FD_TYPE_PIPE as u32);
    assert_eq!(read_u32_le(&record, 56), epoll_idx);
    assert_eq!(read_i64_le(&record, 64), EBADF);
    assert_eq!(read_u64_le(&record, 72), EPOLL_CTL_ADD);
    assert_eq!(read_u64_le(&record, 80), 7);
    assert_eq!(read_u64_le(&record, 88), epoll_idx as u64);
}

#[test]
fn supervisor_process_epoll_query_reports_unique_held_ofds() {
    let mut t = TestVm::new();
    let vm_ptr = &mut t.vm as *mut _ as u32;
    let pipefd_addr = t.scratch + 0x2200;
    let event_addr = t.scratch + 0x2240;
    let output_addr = t.scratch + 0x2280;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) };
    let read_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, read_fd as u64).expect("pipe read OFD should exist");
    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);
    let dup_epfd = t.sys_dup(epfd as u64);
    assert!(dup_epfd >= 0);
    let epoll_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, epfd as u64).expect("epoll OFD should exist");
    let event_fd = pipe::sys_eventfd2(&mut t.vm, t.base, 0, O_NONBLOCK as u64);
    assert!(event_fd >= 3);
    let event_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, event_fd as u64).expect("eventfd OFD should exist");
    let timer_fd = time::sys_timerfd_create(&mut t.vm, t.base, 1, O_NONBLOCK as u64);
    assert!(timer_fd >= 3);
    let timer_ofd =
        fd_table::get_ofd_id(t.base, &t.vm, timer_fd as u64).expect("timerfd OFD should exist");

    assert_eq!(supervisor_process_epoll_held_ofd(vm_ptr, 0), epoll_ofd);
    assert_eq!(supervisor_process_epoll_held_ofd(vm_ptr, 1), 0);
    assert_eq!(supervisor_process_sync_dependent_ofd(vm_ptr, 0), event_ofd);
    assert_eq!(supervisor_process_sync_dependent_ofd(vm_ptr, 1), timer_ofd);
    assert_eq!(supervisor_process_sync_dependent_ofd(vm_ptr, 2), 0);

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
            read_fd as u64,
            event_addr,
        ),
        0
    );
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0xbeef);
    }
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            event_fd as u64,
            event_addr,
        ),
        0
    );
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0xcafe);
    }
    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            timer_fd as u64,
            event_addr,
        ),
        0
    );

    assert_eq!(supervisor_process_epoll_dependent_ofd(vm_ptr, 0), read_ofd);
    assert_eq!(supervisor_process_epoll_dependent_ofd(vm_ptr, 1), event_ofd);
    assert_eq!(supervisor_process_epoll_dependent_ofd(vm_ptr, 2), timer_ofd);
    assert_eq!(supervisor_process_epoll_dependent_ofd(vm_ptr, 3), 0);
    assert_eq!(
        supervisor_process_epoll_dependent_sync_ofd(vm_ptr, 0),
        event_ofd
    );
    assert_eq!(
        supervisor_process_epoll_dependent_sync_ofd(vm_ptr, 1),
        timer_ofd
    );
    assert_eq!(supervisor_process_epoll_dependent_sync_ofd(vm_ptr, 2), 0);
    assert_eq!(supervisor_process_epoll_depends_on_ofd(vm_ptr, read_ofd), 1);
    assert_eq!(
        supervisor_process_epoll_depends_on_ofd(vm_ptr, event_ofd),
        1
    );
    assert_eq!(
        supervisor_process_epoll_depends_on_ofd(vm_ptr, timer_ofd),
        1
    );
    assert_eq!(supervisor_process_epoll_depends_on_ofd(vm_ptr, 31), 0);
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, output_addr, 1, -1, 0),
        0
    );
    assert_eq!(t.vm.status, STATUS_EPOLL_WAIT);
    assert_eq!(supervisor_blocked_epoll_watches_pipe(vm_ptr), 1);
    assert_eq!(supervisor_blocked_epoll_watched_ofd(vm_ptr, 0), read_ofd);
    assert_eq!(supervisor_blocked_epoll_watched_ofd(vm_ptr, 1), event_ofd);
    assert_eq!(supervisor_blocked_epoll_watched_ofd(vm_ptr, 2), timer_ofd);
    assert_eq!(supervisor_blocked_epoll_watched_ofd(vm_ptr, 3), 0);
    assert_eq!(
        supervisor_blocked_epoll_dependent_sync_ofd(vm_ptr, 0),
        event_ofd
    );
    assert_eq!(
        supervisor_blocked_epoll_dependent_sync_ofd(vm_ptr, 1),
        timer_ofd
    );
    assert_eq!(supervisor_blocked_epoll_dependent_sync_ofd(vm_ptr, 2), 0);
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
fn supervisor_epoll_timeout_host_op_resumes_and_publishes_runnable() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let monotonic_before = tidemark_kernel::syscall::time::monotonic_ticks_current();
    t.vm.tid = 1;
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

    t.vm.x[10] = epfd as u64;
    t.vm.x[11] = out_addr;
    t.vm.x[12] = 1;
    t.vm.x[13] = 10;
    t.vm.x[14] = 0;
    t.vm.x[17] = SYS_EPOLL_PWAIT;

    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        STATUS_EPOLL_WAIT
    );
    assert_eq!(t.vm.status, STATUS_EPOLL_WAIT);

    let mut host_op = vec![0u8; supervisor_host_op_record_bytes() as usize];
    assert_eq!(
        supervisor_next_host_op(host_op.as_mut_ptr() as u32, host_op.len() as u32),
        supervisor_host_op_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&host_op, 0), 0x4f48_5354);
    assert_eq!(read_u32_le(&host_op, 4), supervisor_abi_version());
    assert_eq!(read_u32_le(&host_op, 8), supervisor_host_op_record_bytes());
    assert_eq!(
        read_u32_le(&host_op, 12),
        supervisor_host_op_kind_arm_host_timer()
    );
    assert_eq!(
        read_u32_le(&host_op, 24),
        &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32
    );
    assert_eq!(read_u32_le(&host_op, 32), t.vm.tid as u32);
    assert_eq!(read_u32_le(&host_op, 36), t.vm.process_ptr);
    assert_eq!(read_u32_le(&host_op, 40), STATUS_EPOLL_WAIT as u32);
    assert_eq!(read_u64_le(&host_op, 48), 10);
    let deadline_ticks = read_u64_le(&host_op, 56);
    assert!(deadline_ticks > monotonic_before);
    assert_eq!(supervisor_next_host_op(0, 0), 0);

    let mut completion = [0u8; 64];
    write_u32_le(&mut completion, 0, 0x4348_5354);
    write_u32_le(&mut completion, 4, supervisor_abi_version());
    write_u32_le(&mut completion, 8, 64);
    write_u32_le(&mut completion, 12, read_u32_le(&host_op, 12));
    write_u64_le(&mut completion, 16, read_u64_le(&host_op, 16));
    write_u32_le(&mut completion, 24, read_u32_le(&host_op, 24));
    write_u32_le(&mut completion, 28, read_u32_le(&host_op, 28));
    write_u32_le(&mut completion, 32, read_u32_le(&host_op, 32));
    write_u32_le(&mut completion, 36, 1);
    write_u32_le(&mut completion, 40, 0);
    write_u64_le(&mut completion, 48, read_u64_le(&host_op, 48));
    write_u64_le(&mut completion, 56, read_u64_le(&host_op, 56));

    assert_eq!(
        supervisor_complete_host_op(completion.as_ptr() as u32, completion.len() as u32),
        STATUS_OK
    );
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.blocked_fd, 0);
    assert_eq!(t.vm.blocked_ofd_id, 0);
    assert!(tidemark_kernel::syscall::time::monotonic_ticks_current() >= deadline_ticks);

    let mut resume = vec![0u8; supervisor_resume_record_bytes() as usize];
    assert_eq!(
        supervisor_next_resume(resume.as_mut_ptr() as u32, resume.len() as u32),
        supervisor_resume_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&resume, 0), 0x5255_5354);
    assert_eq!(read_u32_le(&resume, 4), supervisor_abi_version());
    assert_eq!(read_u32_le(&resume, 8), supervisor_resume_record_bytes());
    assert_eq!(
        read_u32_le(&resume, 12),
        supervisor_resume_kind_runnable_thread()
    );
    assert_eq!(
        read_u32_le(&resume, 24),
        &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32
    );
    assert_eq!(read_u32_le(&resume, 28), t.vm.tid as u32);
    assert_eq!(read_u32_le(&resume, 32), t.vm.process_ptr);
    assert_eq!(read_u32_le(&resume, 36), STATUS_OK as u32);
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
fn epoll_pwait_resume_delivers_caught_signal_with_sa_restart_as_eintr() {
    const SA_RESTART: u64 = 0x10000000;
    const HANDLER: u64 = 0x88_000;

    let mut t = TestVm::new();
    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    let out_addr = t.scratch + 0x3000;
    let act_addr = t.scratch + 0x3800;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, act_addr, HANDLER);
        tidemark_kernel::guest_mem::write_u64(t.base, act_addr + 8, SA_RESTART);
        tidemark_kernel::guest_mem::write_u64(t.base, act_addr + 16, 0);
    }
    assert_eq!(
        signal::sys_rt_sigaction(&mut t.vm, t.base, SIGCHLD as u64, act_addr, 0, 8),
        0
    );
    t.vm.pc = 0x40_000;
    t.vm.x[2] = t.scratch + 0x8000;

    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, -1, 0),
        0
    );
    assert_eq!(t.vm.status, STATUS_EPOLL_WAIT);
    signal::queue_process_signal(42, SIGCHLD);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), EINTR);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.pc, HANDLER);
    assert_eq!(t.vm.x[10], SIGCHLD as u64);
    assert_eq!(t.vm.blocked_fd, 0);
    assert_eq!(t.vm.blocked_ofd_id, 0);
}

#[test]
fn epoll_pwait_resume_uses_pinned_ofd_after_epfd_close() {
    let mut t = TestVm::new();
    let pipefd_addr = t.scratch + 0x1000;
    assert_eq!(pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0), 0);
    let read_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
    let write_fd = unsafe { tidemark_kernel::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    let event_addr = t.scratch + 0x2000;
    let out_addr = t.scratch + 0x3000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x99);
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
    let pinned_ofd = t.vm.blocked_ofd_id;

    let waiting_status = t.vm.status;
    t.vm.status = STATUS_OK;
    assert_eq!(t.sys_close(epfd), 0);
    assert!(fd_table::get_ofd_by_id(pinned_ofd).is_some());
    assert_eq!(t.sys_write_data(write_fd, b"x"), 1);
    t.vm.status = waiting_status;

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 1);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], 1);
    assert_eq!(t.vm.blocked_ofd_id, 0);
    assert!(fd_table::get_ofd_id(t.base, &t.vm, epfd as u64).is_none());
}

#[test]
fn supervisor_resume_epoll_ready_wait_publishes_runnable() {
    supervisor_reset_shadow_log();

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
    assert_eq!(supervisor_resume_blocked_syscall(vm_ptr, 0), 1);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], 1);

    let mut resume = vec![0u8; supervisor_resume_record_bytes() as usize];
    assert_eq!(
        supervisor_next_resume(resume.as_mut_ptr() as u32, resume.len() as u32),
        supervisor_resume_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&resume, 0), 0x5255_5354);
    assert_eq!(read_u32_le(&resume, 4), supervisor_abi_version());
    assert_eq!(read_u32_le(&resume, 8), supervisor_resume_record_bytes());
    assert_eq!(
        read_u32_le(&resume, 12),
        supervisor_resume_kind_runnable_thread()
    );
    assert_eq!(read_u32_le(&resume, 24), vm_ptr);
    assert_eq!(read_u32_le(&resume, 28), t.vm.tid as u32);
    assert_eq!(read_u32_le(&resume, 32), t.vm.process_ptr);
    assert_eq!(read_u32_le(&resume, 36), STATUS_OK as u32);
}

#[test]
fn epoll_pwait_timerfd_exposes_guest_deadline_for_runtime_retry() {
    let mut t = TestVm::new();
    let timer_fd = time::sys_timerfd_create(&mut t.vm, t.base, 1, 0);
    assert!(timer_fd >= 3);

    let spec_addr = t.scratch + 0x1800;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, spec_addr, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, spec_addr + 8, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, spec_addr + 16, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, spec_addr + 24, 1_000_000);
    }
    let now = time::monotonic_ticks_current();
    assert_eq!(
        time::sys_timerfd_settime(&t.vm, t.base, timer_fd as u64, 0, spec_addr, 0),
        0
    );

    let epfd = epoll::sys_epoll_create1(&mut t.vm, t.base, 0);
    assert!(epfd >= 3);
    let event_addr = t.scratch + 0x2000;
    let out_addr = t.scratch + 0x3000;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x88);
    }

    assert_eq!(
        epoll::sys_epoll_ctl(
            &mut t.vm,
            t.base,
            epfd as u64,
            EPOLL_CTL_ADD,
            timer_fd as u64,
            event_addr,
        ),
        0
    );
    assert_eq!(
        epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, -1, 0),
        0
    );
    assert_eq!(t.vm.status, STATUS_EPOLL_WAIT);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    let deadline = thread_epoll_timerfd_deadline_ticks(vm_ptr);
    assert!(deadline > now);

    time::sync_monotonic_ticks_floor(deadline);
    assert_eq!(thread_resume_blocked_syscall(vm_ptr), 1);
    assert_eq!(t.vm.status, STATUS_OK);
    assert_eq!(t.vm.x[10], 1);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
        EPOLLIN
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
fn epoll_pwait_edge_trigger_always_reports_pipe_hup() {
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
        tidemark_kernel::guest_mem::write_u32(t.base, event_addr, EPOLLIN | EPOLLET);
        tidemark_kernel::guest_mem::write_u64(t.base, event_addr + 8, 0x8080);
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

    assert_eq!(t.sys_close(write_fd), 0);
    for _ in 0..2 {
        assert_eq!(
            epoll::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
            1
        );
        assert_eq!(
            unsafe { tidemark_kernel::guest_mem::read_u32(t.base, out_addr) },
            EPOLLHUP
        );
        assert_eq!(
            unsafe { tidemark_kernel::guest_mem::read_u64(t.base, out_addr + 8) },
            0x8080
        );
    }
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

    let client_idx = socket::inject_external_connection_by_port(0x5000, b"request");
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
