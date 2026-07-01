use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static THREAD_EXIT_CLEANUP_COUNT: AtomicU64 = AtomicU64::new(0);
static THREAD_EXIT_CLEANUP_LOCK: AtomicU32 = AtomicU32::new(0);
static mut LAST_THREAD_EXIT_CLEANUP: super::SupervisorThreadExitCleanupRecord =
    super::SupervisorThreadExitCleanupRecord::empty();

pub(super) fn init() {
    THREAD_EXIT_CLEANUP_COUNT.store(0, Ordering::Relaxed);
    super::lock::with_spin_lock(&THREAD_EXIT_CLEANUP_LOCK, || unsafe {
        LAST_THREAD_EXIT_CLEANUP = super::SupervisorThreadExitCleanupRecord::empty();
    });
}

pub fn thread_exit_cleanup_count() -> u64 {
    THREAD_EXIT_CLEANUP_COUNT.load(Ordering::Relaxed)
}

#[allow(clippy::too_many_arguments)]
pub fn record_thread_exit_cleanup(
    kind: u32,
    vm_ptr: u32,
    tid: u32,
    process_ptr: u32,
    status: u32,
    robust_marked: u32,
    robust_woken: u32,
    clear_child_tid_woken: u32,
    robust_order: u32,
    clear_child_tid_order: u32,
    clear_child_tid: u64,
    robust_head: u64,
    robust_pending: u64,
    first_robust_futex_addr: u64,
) {
    let seq = THREAD_EXIT_CLEANUP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let record = super::SupervisorThreadExitCleanupRecord {
        kind,
        seq,
        vm_ptr,
        tid,
        process_ptr,
        status,
        robust_marked,
        robust_woken,
        clear_child_tid_woken,
        robust_order,
        clear_child_tid_order,
        clear_child_tid,
        robust_head,
        robust_pending,
        first_robust_futex_addr,
    };
    super::lock::with_spin_lock(&THREAD_EXIT_CLEANUP_LOCK, || unsafe {
        LAST_THREAD_EXIT_CLEANUP = record;
    });
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = super::lock::with_spin_lock(&THREAD_EXIT_CLEANUP_LOCK, || unsafe {
        LAST_THREAD_EXIT_CLEANUP
    });
    let mut encoded = [0u8; super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_THREAD_EXIT_CLEANUP_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES);
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.vm_ptr);
    super::write_u32(&mut encoded, 28, record.tid);
    super::write_u32(&mut encoded, 32, record.process_ptr);
    super::write_u32(&mut encoded, 36, record.status);
    super::write_u32(&mut encoded, 40, record.robust_marked);
    super::write_u32(&mut encoded, 44, record.robust_woken);
    super::write_u32(&mut encoded, 48, record.clear_child_tid_woken);
    super::write_u32(&mut encoded, 52, record.robust_order);
    super::write_u32(&mut encoded, 56, record.clear_child_tid_order);
    super::write_u32(&mut encoded, 60, 0);
    super::write_u64(&mut encoded, 64, record.clear_child_tid);
    super::write_u64(&mut encoded, 72, record.robust_head);
    super::write_u64(&mut encoded, 80, record.robust_pending);
    super::write_u64(&mut encoded, 88, record.first_robust_futex_addr);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_THREAD_EXIT_CLEANUP_BYTES as i32
}
