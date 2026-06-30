use super::support::*;

#[test]
fn close_range_closes_or_marks_fd_range() {
    let mut t = TestVm::new();

    let fd3 = t.sys_dup(1);
    let fd4 = t.sys_dup(1);
    let fd5 = t.sys_dup(1);
    assert_eq!((fd3, fd4, fd5), (3, 4, 5));

    assert_eq!(fd_table::sys_close_range(&mut t.vm, t.base, 4, 5, 0), 0);
    assert!(fd_table::get_ofd_id(t.base, &t.vm, 3).is_some());
    assert!(fd_table::get_ofd_id(t.base, &t.vm, 4).is_none());
    assert!(fd_table::get_ofd_id(t.base, &t.vm, 5).is_none());

    let fd4 = t.sys_dup(1);
    let fd5 = t.sys_dup(1);
    assert_eq!((fd4, fd5), (4, 5));
    assert_eq!(
        fd_table::sys_close_range(&mut t.vm, t.base, 4, 5, 1 << 2),
        0
    );
    assert_eq!(t.sys_fcntl(4, 1, 0), FD_CLOEXEC as i64);
    assert_eq!(t.sys_fcntl(5, 1, 0), FD_CLOEXEC as i64);
}

#[test]
fn supervisor_fd_control_records_close_range_close_and_cloexec() {
    let mut t = TestVm::new();

    let fd3 = t.sys_dup(1);
    let fd4 = t.sys_dup(1);
    assert_eq!((fd3, fd4), (3, 4));
    let fd4_ofd = fd_table::get_ofd_id(t.base, &t.vm, 4).expect("fd 4 OFD should exist");

    supervisor_reset_shadow_log();
    assert_eq!(fd_table::sys_close_range(&mut t.vm, t.base, 3, 4, 0), 0);
    assert_eq!(supervisor_shadow_fd_control_count(), 2);
    let mut record = vec![0u8; supervisor_fd_control_record_bytes() as usize];
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_fd_closed()
    );
    assert_eq!(read_u32_le(&record, 36), 4);
    assert_eq!(read_u32_le(&record, 44), fd4_ofd);

    let fd3 = t.sys_dup(1);
    let fd4 = t.sys_dup(1);
    assert_eq!((fd3, fd4), (3, 4));
    let fd4_ofd = fd_table::get_ofd_id(t.base, &t.vm, 4).expect("fd 4 OFD should exist");

    supervisor_reset_shadow_log();
    assert_eq!(
        fd_table::sys_close_range(&mut t.vm, t.base, 3, 4, 1 << 2),
        0
    );
    assert_eq!(supervisor_shadow_fd_control_count(), 2);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_fd_flags_updated()
    );
    assert_eq!(read_u32_le(&record, 36), 4);
    assert_eq!(read_u32_le(&record, 44), fd4_ofd);
    assert_eq!(read_u64_le(&record, 72), FD_CLOEXEC as u64);
    assert_eq!(read_u64_le(&record, 80), 0);
    assert_eq!(read_u64_le(&record, 88), 1 << 2);
}
