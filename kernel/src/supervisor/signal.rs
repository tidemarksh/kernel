use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static SIGNAL_CONTROL_COUNT: AtomicU64 = AtomicU64::new(0);
static SIGNAL_CONTROL_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_SIGNAL_CONTROL: super::SupervisorSignalControlRecord =
    super::SupervisorSignalControlRecord::empty();

pub(super) fn init() {
    SIGNAL_CONTROL_COUNT.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&SIGNAL_CONTROL_LOCK, || unsafe {
        LAST_SIGNAL_CONTROL = super::SupervisorSignalControlRecord::empty();
    });
}

pub fn signal_control_count() -> u64 {
    SIGNAL_CONTROL_COUNT.load(Ordering::Relaxed)
}

pub(super) fn boundary_check(vm_ptr: u32) -> i32 {
    if vm_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    let vm = unsafe { &mut *(vm_ptr as *mut crate::types::ThreadState) };
    let base = vm.guest_base;
    if !crate::syscall::thread::thread_may_step(vm, base) {
        return 0;
    }
    if vm.status != crate::abi::STATUS_OK && vm.status != crate::abi::STATUS_VFORK_WAIT {
        return 0;
    }
    i32::from(crate::syscall::signal::check_pending_at_boundary(
        vm,
        base,
        super::SUPERVISOR_SIGNAL_BOUNDARY_STEP,
    ))
}

pub(super) fn take_process_pending_for_transport(pid: i32) -> u64 {
    crate::syscall::signal::take_process_pending_for_transport(pid)
}

pub(super) fn merge_process_pending_from_transport(pid: i32, pending: u64) -> i32 {
    crate::syscall::signal::merge_process_pending_from_transport(pid, pending)
}

pub(super) fn first_signal_from_bits(bits: u64) -> u32 {
    if bits == 0 {
        0
    } else {
        bits.trailing_zeros() + 1
    }
}

#[allow(clippy::too_many_arguments)]
pub fn record_signal_control(
    kind: u32,
    vm: &crate::types::ThreadState,
    base: u32,
    sig: u32,
    boundary: u32,
    thread_pending: u64,
    process_pending: u64,
    record_pending: u64,
    deliverable: u64,
    detail0: u64,
    detail1: u64,
) {
    let seq = SIGNAL_CONTROL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = super::SupervisorSignalControlRecord {
        kind,
        seq,
        vm_ptr: vm as *const crate::types::ThreadState as u32,
        process_ptr: vm.process_ptr,
        pid: crate::syscall::signal::pid_from_vm(vm, base) as u32,
        tid: vm.tid as u32,
        sig,
        status: vm.status as u32,
        sig_info_code: vm.sig_info_code,
        boundary,
        thread_pending,
        process_pending,
        record_pending,
        deliverable,
        mask: vm.sig_mask,
        pc: vm.pc,
        detail0,
        detail1,
    };
    super::lock::with_spin_lock(&SIGNAL_CONTROL_LOCK, || unsafe {
        LAST_SIGNAL_CONTROL = record;
    });
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record =
        super::lock::with_spin_lock(&SIGNAL_CONTROL_LOCK, || unsafe { LAST_SIGNAL_CONTROL });
    let mut encoded = [0u8; super::SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES as usize];
    super::write_u32(
        &mut encoded,
        0,
        super::SUPERVISOR_SIGNAL_CONTROL_RECORD_MAGIC,
    );
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(
        &mut encoded,
        8,
        super::SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES,
    );
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.vm_ptr);
    super::write_u32(&mut encoded, 28, record.process_ptr);
    super::write_u32(&mut encoded, 32, record.pid);
    super::write_u32(&mut encoded, 36, record.tid);
    super::write_u32(&mut encoded, 40, record.sig);
    super::write_u32(&mut encoded, 44, record.status);
    super::write_u32(&mut encoded, 48, record.sig_info_code as u32);
    super::write_u32(&mut encoded, 52, record.boundary);
    super::write_u64(&mut encoded, 56, record.thread_pending);
    super::write_u64(&mut encoded, 64, record.process_pending);
    super::write_u64(&mut encoded, 72, record.record_pending);
    super::write_u64(&mut encoded, 80, record.deliverable);
    super::write_u64(&mut encoded, 88, record.mask);
    super::write_u64(&mut encoded, 96, record.pc);
    super::write_u64(&mut encoded, 104, record.detail0);
    super::write_u64(&mut encoded, 112, record.detail1);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_SIGNAL_CONTROL_RECORD_BYTES as i32
}
