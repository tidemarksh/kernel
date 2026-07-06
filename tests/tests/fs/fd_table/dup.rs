use super::support::*;

#[test]
fn dup_and_dup3_allocate_fd_entries() {
    let mut t = TestVm::new();

    let newfd = t.sys_dup(1);
    assert_eq!(newfd, 3);

    assert_eq!(t.sys_dup3(1, 10, O_CLOEXEC as u64), 10);
}

#[test]
fn supervisor_fd_control_records_dup_and_dup3() {
    let mut t = TestVm::new();
    supervisor_reset_shadow_log();

    let stdout_ofd = fd_table::get_ofd_id(t.base, &t.vm, 1).expect("stdout OFD should exist");
    let dup_fd = t.sys_dup(1);
    assert_eq!(dup_fd, 3);

    assert_eq!(supervisor_shadow_fd_control_count(), 1);
    let mut record = vec![0u8; supervisor_fd_control_record_bytes() as usize];
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_fd_duplicated()
    );
    assert_eq!(read_u32_le(&record, 36), 1);
    assert_eq!(read_u32_le(&record, 40), dup_fd as u32);
    assert_eq!(read_u32_le(&record, 44), stdout_ofd);
    assert_eq!(read_u32_le(&record, 48), stdout_ofd);
    assert_eq!(read_u64_le(&record, 64), dup_fd as u64);
    assert_eq!(read_u64_le(&record, 72), 0);

    assert_eq!(t.sys_dup3(1, 10, O_CLOEXEC as u64), 10);
    assert_eq!(supervisor_shadow_fd_control_count(), 2);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_fd_duplicated()
    );
    assert_eq!(read_u32_le(&record, 36), 1);
    assert_eq!(read_u32_le(&record, 40), 10);
    assert_eq!(read_u32_le(&record, 44), stdout_ofd);
    assert_eq!(read_u32_le(&record, 48), stdout_ofd);
    assert_eq!(read_u64_le(&record, 64), 10);
    assert_eq!(read_u64_le(&record, 72), FD_CLOEXEC as u64);

    assert_eq!(t.sys_dup3(1, 10, 0), 10);
    assert_eq!(supervisor_shadow_fd_control_count(), 4);
    assert_eq!(
        supervisor_fd_control_record(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_fd_control_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_fd_control_kind_fd_duplicated()
    );
    assert_eq!(read_u32_le(&record, 36), 1);
    assert_eq!(read_u32_le(&record, 40), 10);
    assert_eq!(read_u64_le(&record, 72), 0);
}
