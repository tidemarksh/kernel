use tidemark_kernel::abi;
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::supervisor::{
    supervisor_abi_version, supervisor_complete_host_op, supervisor_host_op_kind_arm_host_timer,
    supervisor_host_op_record_bytes, supervisor_next_host_op, supervisor_next_resume,
    supervisor_process_resume, supervisor_reset_shadow_log, supervisor_resume_kind_runnable_thread,
    supervisor_resume_record_bytes,
};
use tidemark_kernel::syscall::time;
use tidemark_kernel::types::{ProcessState, THREAD_RUNNING, ThreadRecord, ThreadState};

const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const ITIMER_REAL: u64 = 0;
const TIMER_ABSTIME: u64 = 1;

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

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn install_current_thread_record(t: &mut TestVm) {
    let vm_ptr = (&mut t.vm as *mut ThreadState) as u32;
    let tid = t.vm.tid;
    unsafe {
        let ps = &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState);
        ps.threads[(tid - 1) as usize] = ThreadRecord::new(tid, THREAD_RUNNING, vm_ptr, 0, 0);
        ps.thread_count
            .store(1, std::sync::atomic::Ordering::Release);
    }
}

fn assert_next_runnable_resume(vm: &ThreadState) {
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
    assert_eq!(read_u32_le(&resume, 24), vm as *const ThreadState as u32);
    assert_eq!(read_u32_le(&resume, 28), vm.tid as u32);
    assert_eq!(read_u32_le(&resume, 32), vm.process_ptr);
    assert_eq!(read_u32_le(&resume, 36), abi::STATUS_OK as u32);
    assert_eq!(supervisor_next_resume(0, 0), 0);
}

fn write_itimerspec(
    base: u32,
    addr: u64,
    interval_sec: u64,
    interval_nsec: u64,
    value_sec: u64,
    value_nsec: u64,
) {
    unsafe {
        tidemark_kernel::guest_mem::write_u64(base, addr, interval_sec);
        tidemark_kernel::guest_mem::write_u64(base, addr + 8, interval_nsec);
        tidemark_kernel::guest_mem::write_u64(base, addr + 16, value_sec);
        tidemark_kernel::guest_mem::write_u64(base, addr + 24, value_nsec);
    }
}

#[test]
fn clock_gettime_realtime_uses_base_plus_monotonic() {
    let t = TestVm::new();
    tidemark_kernel::syscall::time::set_base_time(1735689600, 0);
    tidemark_kernel::syscall::time::advance_monotonic(100_000_000);

    let tp = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_REALTIME, tp),
        0
    );
    let sec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) };
    assert_eq!(sec, 1735689601);
}

#[test]
fn clock_gettime_monotonic_returns_ticks_based() {
    let t = TestVm::new();
    tidemark_kernel::syscall::time::advance_monotonic(200_000_000);

    let tp = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_MONOTONIC, tp),
        0
    );
    let sec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) };
    assert!(sec >= 2);
}

#[test]
fn sync_monotonic_ticks_floor_only_moves_forward() {
    let t = TestVm::new();
    let tp = t.scratch;

    tidemark_kernel::syscall::time::advance_monotonic(200_000_000);
    tidemark_kernel::syscall::time::sync_monotonic_ticks_floor(100_000_000);
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_MONOTONIC, tp),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) },
        2
    );

    tidemark_kernel::syscall::time::sync_monotonic_ticks_floor(300_000_000);
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_MONOTONIC, tp),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) },
        3
    );
}

#[test]
fn clock_gettime_monotonic_is_nonzero_at_millisecond_precision_at_startup() {
    let t = TestVm::new();
    let tp = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_MONOTONIC, tp),
        0
    );
    let sec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) };
    let nsec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp + 8) };
    assert!(sec.saturating_mul(1_000).saturating_add(nsec / 1_000_000) > 0);
}

#[test]
fn advance_monotonic_duration_updates_monotonic_clock() {
    let t = TestVm::new();
    let tp = t.scratch;

    tidemark_kernel::syscall::time::advance_monotonic_duration(core::time::Duration::from_millis(
        50,
    ));

    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_MONOTONIC, tp),
        0
    );
    let sec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp) };
    let nsec = unsafe { tidemark_kernel::guest_mem::read_u64(t.base, tp + 8) };
    assert!(sec > 0 || nsec >= 50_000_000);
}

#[test]
fn clock_gettime_invalid_clk_id_returns_einval() {
    let t = TestVm::new();
    let tp = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, 999, tp),
        abi::EINVAL,
    );
}

#[test]
fn clock_gettime_null_tp_returns_efault() {
    let t = TestVm::new();
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, 0, 0),
        abi::EFAULT,
    );
}

#[test]
fn clock_gettime_faults_bad_output_pointer() {
    let t = TestVm::new();
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_gettime(&t.vm, t.base, CLOCK_REALTIME, u64::MAX),
        abi::EFAULT,
    );
}

#[test]
fn clock_getres_validates_clk_id() {
    let t = TestVm::new();
    let res = t.scratch;
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_getres(&t.vm, t.base, 0, res),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_getres(&t.vm, t.base, 999, res),
        abi::EINVAL
    );
}

#[test]
fn clock_getres_allows_null_res_and_faults_bad_output_pointer() {
    let t = TestVm::new();
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_getres(&t.vm, t.base, CLOCK_REALTIME, 0),
        0,
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_getres(&t.vm, t.base, CLOCK_REALTIME, u64::MAX,),
        abi::EFAULT,
    );
}

#[test]
fn syscall_dispatch_reports_enosys_for_times() {
    let mut t = TestVm::new();
    t.vm.x[10] = t.scratch;
    t.vm.x[17] = abi::SYS_TIMES;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        abi::STATUS_OK
    );
    assert_eq!(t.vm.x[10] as i64, abi::ENOSYS);
}

#[test]
fn setitimer_and_getitimer_round_trip() {
    let t = TestVm::new();
    let new_value = t.scratch + 0x100;
    let curr_value = t.scratch + 0x200;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, new_value, 3);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 8, 250_000);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 16, 1);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 24, 125_000);
    }

    assert_eq!(
        tidemark_kernel::syscall::time::sys_setitimer(&t.vm, t.base, ITIMER_REAL, new_value, 0),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_getitimer(&t.vm, t.base, ITIMER_REAL, curr_value),
        0
    );

    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value) },
        3
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value + 8) },
        250_000
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value + 16) },
        1
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value + 24) },
        125_000
    );
}

#[test]
fn setitimer_rejects_invalid_usec_fields() {
    let t = TestVm::new();
    let new_value = t.scratch + 0x300;

    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, new_value, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 8, 1_000_000);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 16, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, new_value + 24, 0);
    }

    assert_eq!(
        tidemark_kernel::syscall::time::sys_setitimer(&t.vm, t.base, ITIMER_REAL, new_value, 0),
        abi::EINVAL
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_getitimer(&t.vm, t.base, ITIMER_REAL, 0),
        abi::EFAULT
    );
}

#[test]
fn sched_getaffinity_accepts_large_cpuset_buffers() {
    let t = TestVm::new();
    let mask_addr = t.scratch + 0x400;

    t.write_mem(mask_addr, &[0xaa; 128]);

    assert_eq!(
        tidemark_kernel::syscall::time::sys_sched_getaffinity(&t.vm, t.base, 0, 128, mask_addr),
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, mask_addr) },
        1
    );
}

#[test]
fn sched_getscheduler_reports_normal_policy_for_current_thread() {
    let t = TestVm::new();

    assert_eq!(
        tidemark_kernel::syscall::time::sys_sched_getscheduler(&t.vm, t.base, 0),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_sched_getscheduler(&t.vm, t.base, t.vm.tid as i64,),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_sched_getscheduler(&t.vm, t.base, i64::MAX),
        abi::ESRCH
    );
}

#[test]
fn sched_getparam_reports_zero_priority_for_current_thread() {
    let t = TestVm::new();
    let param_addr = t.scratch + 0x480;
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, param_addr, u32::MAX);
    }

    assert_eq!(
        tidemark_kernel::syscall::time::sys_sched_getparam(
            &t.vm,
            t.base,
            t.vm.tid as i64,
            param_addr,
        ),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, param_addr) },
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_sched_getparam(&t.vm, t.base, 0, 0),
        abi::EFAULT
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_sched_getparam(&t.vm, t.base, i64::MAX, param_addr,),
        abi::ESRCH
    );
}

#[test]
fn sched_query_dispatch_routes_scheduler_and_param() {
    let mut t = TestVm::new();
    let param_addr = t.scratch + 0x4c0;

    t.vm.x[10] = 0;
    t.vm.x[17] = abi::SYS_SCHED_GETSCHEDULER;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        abi::STATUS_OK
    );
    assert_eq!(t.vm.x[10], 0);

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, param_addr, u32::MAX);
    }
    t.vm.x[10] = t.vm.tid as u64;
    t.vm.x[11] = param_addr;
    t.vm.x[17] = abi::SYS_SCHED_GETPARAM;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        abi::STATUS_OK
    );
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, param_addr) },
        0
    );
}

#[test]
fn getcpu_reports_single_online_cpu_and_node() {
    let t = TestVm::new();
    let cpu_addr = t.scratch + 0x500;
    let node_addr = t.scratch + 0x504;

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, cpu_addr, u32::MAX);
        tidemark_kernel::guest_mem::write_u32(t.base, node_addr, u32::MAX);
    }

    assert_eq!(
        tidemark_kernel::syscall::time::sys_getcpu(&t.vm, t.base, cpu_addr, node_addr, 0),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, cpu_addr) },
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u32(t.base, node_addr) },
        0
    );
}

#[test]
fn getcpu_accepts_null_output_pointers_and_faults_bad_addresses() {
    let t = TestVm::new();
    assert_eq!(
        tidemark_kernel::syscall::time::sys_getcpu(&t.vm, t.base, 0, 0, 0),
        0
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_getcpu(&t.vm, t.base, u64::MAX, 0, 0),
        abi::EFAULT
    );
    assert_eq!(
        tidemark_kernel::syscall::time::sys_getcpu(&t.vm, t.base, 0, u64::MAX, 0),
        abi::EFAULT
    );
}

#[test]
fn timerfd_create_settime_gettime_and_read_expiration() {
    let mut t = TestVm::new();
    let fd = time::sys_timerfd_create(&mut t.vm, t.base, CLOCK_MONOTONIC, abi::O_NONBLOCK as u64);
    assert!(fd >= 3);

    let new_value = t.scratch + 0x600;
    let curr_value = t.scratch + 0x640;
    write_itimerspec(t.base, new_value, 0, 0, 1, 0);

    assert_eq!(
        time::sys_timerfd_settime(&t.vm, t.base, fd as u64, 0, new_value, 0),
        0
    );
    assert_eq!(
        time::sys_timerfd_gettime(&t.vm, t.base, fd as u64, curr_value),
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value) },
        0
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(t.base, curr_value + 16) },
        1
    );

    time::advance_monotonic_duration(core::time::Duration::from_secs(1));
    let mut buf = [0u8; 8];
    assert_eq!(t.sys_read(fd, &mut buf), 8);
    assert_eq!(u64::from_le_bytes(buf), 1);
}

#[test]
fn timerfd_periodic_timer_coalesces_expirations() {
    let mut t = TestVm::new();
    let fd = time::sys_timerfd_create(&mut t.vm, t.base, CLOCK_MONOTONIC, abi::O_NONBLOCK as u64);
    assert!(fd >= 3);

    let new_value = t.scratch + 0x700;
    write_itimerspec(t.base, new_value, 1, 0, 1, 0);
    assert_eq!(
        time::sys_timerfd_settime(&t.vm, t.base, fd as u64, 0, new_value, 0),
        0
    );

    time::advance_monotonic_duration(core::time::Duration::from_secs(3));
    let mut buf = [0u8; 8];
    assert_eq!(t.sys_read(fd, &mut buf), 8);
    assert_eq!(u64::from_le_bytes(buf), 3);
}

#[test]
fn timerfd_settime_supports_absolute_deadlines() {
    let mut t = TestVm::new();
    let fd = time::sys_timerfd_create(&mut t.vm, t.base, CLOCK_MONOTONIC, abi::O_NONBLOCK as u64);
    assert!(fd >= 3);

    let now = time::current_timespec(CLOCK_MONOTONIC).unwrap();
    let new_value = t.scratch + 0x780;
    write_itimerspec(t.base, new_value, 0, 0, now.0 + 2, now.1);
    assert_eq!(
        time::sys_timerfd_settime(
            &t.vm,
            t.base,
            fd as u64,
            abi::TFD_TIMER_ABSTIME,
            new_value,
            0,
        ),
        0
    );

    let mut buf = [0u8; 8];
    assert_eq!(t.sys_read(fd, &mut buf), abi::EAGAIN);
    time::advance_monotonic_duration(core::time::Duration::from_secs(2));
    assert_eq!(t.sys_read(fd, &mut buf), 8);
    assert_eq!(u64::from_le_bytes(buf), 1);
}

#[test]
fn timerfd_dispatch_routes_create_and_gettime() {
    let mut t = TestVm::new();
    t.vm.x[10] = CLOCK_MONOTONIC;
    t.vm.x[11] = abi::O_NONBLOCK as u64;
    t.vm.x[17] = abi::SYS_TIMERFD_CREATE;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        abi::STATUS_OK
    );
    let fd = t.vm.x[10] as i64;
    assert!(fd >= 3);

    let curr_value = t.scratch + 0x7c0;
    t.vm.x[10] = fd as u64;
    t.vm.x[11] = curr_value;
    t.vm.x[17] = abi::SYS_TIMERFD_GETTIME;
    assert_eq!(
        tidemark_kernel::syscall::dispatch(&mut t.vm, t.base),
        abi::STATUS_OK
    );
    assert_eq!(t.vm.x[10], 0);
}

#[test]
fn clock_nanosleep_relative_sets_sleep_status() {
    let mut t = TestVm::new();
    let req = t.scratch + 0x500;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, req, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, req + 8, 50_000_000);
    }

    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_nanosleep(
            &mut t.vm,
            t.base,
            CLOCK_MONOTONIC,
            0,
            req,
            0,
        ),
        abi::STATUS_SLEEP
    );
    assert_eq!(t.vm.fault_addr, 0);
    assert_eq!(t.vm.fault_pc, 50_000_000);
}

#[test]
fn nanosleep_zero_duration_publishes_runnable_resume_without_host_timer() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let req = t.scratch + 0x510;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, req, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, req + 8, 0);
    }
    t.vm.tid = 1;

    assert_eq!(
        tidemark_kernel::syscall::time::sys_nanosleep(&mut t.vm, t.base, req, 0),
        abi::STATUS_SLEEP
    );
    assert_eq!(t.vm.status, abi::STATUS_OK);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.fault_addr, 0);
    assert_eq!(t.vm.fault_pc, 0);
    assert_eq!(supervisor_next_host_op(0, 0), 0);
    assert_next_runnable_resume(&t.vm);
}

#[test]
fn sched_yield_publishes_runnable_resume_without_host_timer() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;

    assert_eq!(
        tidemark_kernel::syscall::time::sys_sched_yield(&mut t.vm),
        abi::STATUS_SLEEP
    );
    assert_eq!(t.vm.status, abi::STATUS_OK);
    assert_eq!(t.vm.x[10], 0);
    assert_eq!(t.vm.fault_addr, 0);
    assert_eq!(t.vm.fault_pc, 0);
    assert_eq!(supervisor_next_host_op(0, 0), 0);
    assert_next_runnable_resume(&t.vm);
}

#[test]
fn thread_step_sched_yield_keeps_vm_runnable_for_process_resume() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    t.vm.tid = 1;
    install_current_thread_record(&mut t);

    let code_addr = t.sys_mmap(
        0,
        4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
        abi::MAP_ANONYMOUS | abi::MAP_PRIVATE,
        -1,
        0,
    ) as u64;
    assert!(code_addr > 0);
    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr, 0x0000_0073); // ecall
    }

    t.vm.pc = code_addr;
    t.vm.x[17] = abi::SYS_SCHED_YIELD;
    t.vm.status = abi::STATUS_OK;

    let vm_ptr = &mut t.vm as *mut ThreadState as u32;
    let remaining = tidemark_kernel::abi::thread_step(vm_ptr, 1);

    assert!(remaining >= 0);
    assert_eq!(t.vm.status, abi::STATUS_OK);

    let mut resume = vec![0u8; supervisor_resume_record_bytes() as usize];
    assert_eq!(
        supervisor_process_resume(vm_ptr, resume.as_mut_ptr() as u32, resume.len() as u32),
        supervisor_resume_record_bytes() as i32
    );
    assert_eq!(
        read_u32_le(&resume, 12),
        supervisor_resume_kind_runnable_thread()
    );
    assert_eq!(read_u32_le(&resume, 24), vm_ptr);
    assert_eq!(read_u32_le(&resume, 28), t.vm.tid as u32);
    assert_eq!(read_u32_le(&resume, 36), abi::STATUS_OK as u32);
}

#[test]
fn supervisor_sleep_timeout_publishes_arm_host_timer_host_op() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let req = t.scratch + 0x520;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, req, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, req + 8, 2_000_000);
    }
    t.vm.tid = 1;

    assert_eq!(
        tidemark_kernel::syscall::time::sys_nanosleep(&mut t.vm, t.base, req, 0),
        abi::STATUS_SLEEP
    );

    let mut record = vec![0u8; supervisor_host_op_record_bytes() as usize];
    assert_eq!(
        supervisor_next_host_op(record.as_mut_ptr() as u32, record.len() as u32),
        supervisor_host_op_record_bytes() as i32
    );
    assert_eq!(read_u32_le(&record, 0), 0x4f48_5354);
    assert_eq!(read_u32_le(&record, 4), supervisor_abi_version());
    assert_eq!(read_u32_le(&record, 8), supervisor_host_op_record_bytes());
    assert_eq!(
        read_u32_le(&record, 12),
        supervisor_host_op_kind_arm_host_timer()
    );
    assert_eq!(
        read_u32_le(&record, 24),
        &mut t.vm as *mut ThreadState as u32
    );
    assert_eq!(read_u32_le(&record, 32), t.vm.tid as u32);
    assert_eq!(read_u32_le(&record, 36), t.vm.process_ptr);
    assert_eq!(read_u32_le(&record, 40), abi::STATUS_SLEEP as u32);
    assert_eq!(read_u64_le(&record, 48), 2);
    assert_eq!(
        read_u64_le(&record, 56),
        tidemark_kernel::syscall::time::sleep_deadline_ticks(t.vm.fault_addr, t.vm.fault_pc)
    );
    assert_eq!(supervisor_next_host_op(0, 0), 0);
}

#[test]
fn supervisor_sleep_timer_completion_resumes_and_publishes_runnable() {
    supervisor_reset_shadow_log();

    let mut t = TestVm::new();
    let req = t.scratch + 0x530;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(t.base, req, 0);
        tidemark_kernel::guest_mem::write_u64(t.base, req + 8, 2_000_000);
    }
    t.vm.tid = 1;

    assert_eq!(
        tidemark_kernel::syscall::time::sys_nanosleep(&mut t.vm, t.base, req, 0),
        abi::STATUS_SLEEP
    );

    let mut host_op = vec![0u8; supervisor_host_op_record_bytes() as usize];
    assert_eq!(
        supervisor_next_host_op(host_op.as_mut_ptr() as u32, host_op.len() as u32),
        supervisor_host_op_record_bytes() as i32
    );

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
        abi::STATUS_OK
    );
    assert_eq!(t.vm.status, abi::STATUS_OK);
    assert_eq!(t.vm.fault_addr, 0);
    assert_eq!(t.vm.fault_pc, 0);
    assert!(tidemark_kernel::syscall::time::monotonic_ticks_current() >= read_u64_le(&host_op, 56));

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
        &mut t.vm as *mut ThreadState as u32
    );
    assert_eq!(read_u32_le(&resume, 28), t.vm.tid as u32);
    assert_eq!(read_u32_le(&resume, 32), t.vm.process_ptr);
    assert_eq!(read_u32_le(&resume, 36), abi::STATUS_OK as u32);
}

#[test]
fn clock_nanosleep_abstime_uses_deadline_delta() {
    let mut t = TestVm::new();
    let req = t.scratch + 0x540;
    tidemark_kernel::syscall::time::advance_monotonic_duration(core::time::Duration::from_millis(
        20,
    ));
    let (now_sec, now_nsec) =
        tidemark_kernel::syscall::time::current_timespec(CLOCK_MONOTONIC).unwrap();
    let target_nsec_total = now_nsec + 30_000_000;
    unsafe {
        tidemark_kernel::guest_mem::write_u64(
            t.base,
            req,
            now_sec + target_nsec_total / 1_000_000_000,
        );
        tidemark_kernel::guest_mem::write_u64(t.base, req + 8, target_nsec_total % 1_000_000_000);
    }

    assert_eq!(
        tidemark_kernel::syscall::time::sys_clock_nanosleep(
            &mut t.vm,
            t.base,
            CLOCK_MONOTONIC,
            TIMER_ABSTIME,
            req,
            0,
        ),
        abi::STATUS_SLEEP
    );
    assert_eq!(t.vm.fault_addr, 0);
    assert_eq!(t.vm.fault_pc, 30_000_000);
}
