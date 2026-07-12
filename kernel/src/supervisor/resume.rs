use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const QUEUE_CAP: usize = 256;
const QUEUE_EMPTY: super::SupervisorResumeRecord = super::SupervisorResumeRecord {
    kind: 0,
    seq: 0,
    vm_ptr: 0,
    tid: 0,
    process_ptr: 0,
    status: 0,
    detail0: 0,
};

static POLL_COUNT: AtomicU64 = AtomicU64::new(0);
static ENQUEUE_COUNT: AtomicU64 = AtomicU64::new(0);
static OVERFLOW_COUNT: AtomicU64 = AtomicU64::new(0);
static QUEUE_LOCK: AtomicU32 = AtomicU32::new(0);
static QUEUE_HEAD: AtomicU32 = AtomicU32::new(0);
static QUEUE_TAIL: AtomicU32 = AtomicU32::new(0);
static mut QUEUE: [super::SupervisorResumeRecord; QUEUE_CAP] = [QUEUE_EMPTY; QUEUE_CAP];

#[derive(Clone, Copy, Eq, PartialEq)]
enum RecordDisposition {
    Ready,
    Pending,
    Drop,
}

fn with_queue_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if QUEUE_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    QUEUE_LOCK.store(0, Ordering::Release);
    result
}

pub(super) fn init() {
    POLL_COUNT.store(0, Ordering::Relaxed);
    ENQUEUE_COUNT.store(0, Ordering::Relaxed);
    OVERFLOW_COUNT.store(0, Ordering::Relaxed);
    with_queue_lock(|| unsafe {
        QUEUE_HEAD.store(0, Ordering::Relaxed);
        QUEUE_TAIL.store(0, Ordering::Relaxed);
        let queue_ptr = core::ptr::addr_of_mut!(QUEUE) as *mut super::SupervisorResumeRecord;
        for idx in 0..QUEUE_CAP {
            core::ptr::write(queue_ptr.add(idx), QUEUE_EMPTY);
        }
    });
}

pub(super) fn poll_count() -> u64 {
    POLL_COUNT.load(Ordering::Relaxed)
}

pub(super) fn enqueue_count() -> u64 {
    ENQUEUE_COUNT.load(Ordering::Relaxed)
}

pub(super) fn overflow_count() -> u64 {
    OVERFLOW_COUNT.load(Ordering::Relaxed)
}

pub(super) fn next_enqueue_seq() -> u64 {
    ENQUEUE_COUNT.fetch_add(1, Ordering::Relaxed) + 1
}

pub(super) fn push_record(record: super::SupervisorResumeRecord) -> bool {
    with_queue_lock(|| unsafe {
        let head = QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = QUEUE_TAIL.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % QUEUE_CAP as u32;
        if next_tail == head {
            OVERFLOW_COUNT.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let queue_ptr = core::ptr::addr_of_mut!(QUEUE) as *mut super::SupervisorResumeRecord;
        core::ptr::write(queue_ptr.add(tail as usize), record);
        QUEUE_TAIL.store(next_tail, Ordering::Relaxed);
        true
    })
}

pub(super) fn enqueue_runnable_thread(vm: &crate::types::ThreadState) -> bool {
    let vm_ptr = vm as *const crate::types::ThreadState as u32;
    if vm_ptr == 0 || vm.process_ptr == 0 || vm.tid <= 0 {
        return false;
    }
    let seq = next_enqueue_seq();
    push_record(super::SupervisorResumeRecord {
        kind: super::SUPERVISOR_RESUME_KIND_RUNNABLE_THREAD,
        seq,
        vm_ptr,
        tid: vm.tid as u32,
        process_ptr: vm.process_ptr,
        status: vm.status as u32,
        detail0: 0,
    })
}

fn has_ready_record() -> bool {
    with_queue_lock(|| unsafe {
        let head = QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = QUEUE_TAIL.load(Ordering::Relaxed);
        let queue_ptr = core::ptr::addr_of_mut!(QUEUE) as *mut super::SupervisorResumeRecord;
        let mut read = head;
        let mut write = head;
        let mut has_ready = false;
        let mut changed = false;

        while read != tail {
            let current = read;
            let record = core::ptr::read(queue_ptr.add(current as usize));
            read = (read + 1) % QUEUE_CAP as u32;
            match record_disposition(record) {
                RecordDisposition::Ready => {
                    has_ready = true;
                    core::ptr::write(queue_ptr.add(write as usize), record);
                    write = (write + 1) % QUEUE_CAP as u32;
                }
                RecordDisposition::Pending => {
                    core::ptr::write(queue_ptr.add(write as usize), record);
                    write = (write + 1) % QUEUE_CAP as u32;
                }
                RecordDisposition::Drop => {
                    changed = true;
                }
            }
        }

        if changed {
            let mut clear = write;
            while clear != tail {
                core::ptr::write(queue_ptr.add(clear as usize), QUEUE_EMPTY);
                clear = (clear + 1) % QUEUE_CAP as u32;
            }
            QUEUE_TAIL.store(write, Ordering::Relaxed);
        }

        has_ready
    })
}

fn pop_ready_record() -> Option<super::SupervisorResumeRecord> {
    with_queue_lock(|| unsafe {
        let head = QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = QUEUE_TAIL.load(Ordering::Relaxed);
        let queue_ptr = core::ptr::addr_of_mut!(QUEUE) as *mut super::SupervisorResumeRecord;
        let mut read = head;
        let mut write = head;
        let mut selected = None;
        let mut changed = false;

        while read != tail {
            let current = read;
            let record = core::ptr::read(queue_ptr.add(current as usize));
            read = (read + 1) % QUEUE_CAP as u32;
            match record_disposition(record) {
                RecordDisposition::Ready if selected.is_none() => {
                    selected = Some(record);
                    changed = true;
                    continue;
                }
                RecordDisposition::Drop => {
                    changed = true;
                    continue;
                }
                RecordDisposition::Ready | RecordDisposition::Pending => {}
            }
            core::ptr::write(queue_ptr.add(write as usize), record);
            write = (write + 1) % QUEUE_CAP as u32;
        }

        if changed {
            let mut clear = write;
            while clear != tail {
                core::ptr::write(queue_ptr.add(clear as usize), QUEUE_EMPTY);
                clear = (clear + 1) % QUEUE_CAP as u32;
            }
            QUEUE_TAIL.store(write, Ordering::Relaxed);
        }

        selected
    })
}

fn thread_from_resume_record(
    record: super::SupervisorResumeRecord,
) -> Option<&'static crate::types::ThreadState> {
    let thread = super::thread::state_from_ptr(record.vm_ptr)?;
    if thread.process_ptr != record.process_ptr
        || thread.tid <= 0
        || thread.tid as u32 != record.tid
    {
        return None;
    }
    Some(thread)
}

fn futex_resume_record_ready(record: super::SupervisorResumeRecord) -> bool {
    let Some(thread) = thread_from_resume_record(record) else {
        return true;
    };
    if thread.status != crate::abi::STATUS_FUTEX_WAIT {
        return true;
    }
    let blocked_addr = super::thread::thread_record_blocked_addr(thread, thread.guest_base);
    if blocked_addr == 0 || blocked_addr != record.detail0 {
        return true;
    }
    super::futex::wait_word_mismatched(thread, record.detail0)
}

fn runnable_resume_record_disposition(record: super::SupervisorResumeRecord) -> RecordDisposition {
    let Some(thread) = thread_from_resume_record(record) else {
        return RecordDisposition::Drop;
    };
    if super::blocked::vfork_process_gate_blocks(thread) {
        return RecordDisposition::Pending;
    }
    if super::runnable::process_has_process_wide_fs_gate_for_thread(thread) {
        return RecordDisposition::Pending;
    }
    match thread.status {
        crate::abi::STATUS_OK | crate::abi::STATUS_VFORK_WAIT => RecordDisposition::Ready,
        crate::abi::STATUS_FS => RecordDisposition::Pending,
        _ => RecordDisposition::Drop,
    }
}

fn record_disposition(record: super::SupervisorResumeRecord) -> RecordDisposition {
    match record.kind {
        super::SUPERVISOR_RESUME_KIND_FUTEX_WAKE => {
            if futex_resume_record_ready(record) {
                RecordDisposition::Ready
            } else {
                RecordDisposition::Pending
            }
        }
        super::SUPERVISOR_RESUME_KIND_RUNNABLE_THREAD => runnable_resume_record_disposition(record),
        _ => RecordDisposition::Ready,
    }
}

fn write_encoded_record(record: super::SupervisorResumeRecord, out_ptr: u32) -> i32 {
    let mut encoded = [0u8; super::SUPERVISOR_RESUME_RECORD_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_RESUME_RECORD_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_RESUME_RECORD_BYTES);
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.vm_ptr);
    super::write_u32(&mut encoded, 28, record.tid);
    super::write_u32(&mut encoded, 32, record.process_ptr);
    super::write_u32(&mut encoded, 36, record.status);
    super::write_u64(&mut encoded, 40, record.detail0);

    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_RESUME_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_RESUME_RECORD_BYTES as i32
}

fn validate_output(out_ptr: u32, out_len: u32) -> Result<(), i32> {
    if out_ptr == 0 {
        return Err(crate::abi::EFAULT as i32);
    }
    if out_len < super::SUPERVISOR_RESUME_RECORD_BYTES {
        return Err(crate::abi::ENOSPC as i32);
    }
    Ok(())
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    POLL_COUNT.fetch_add(1, Ordering::Relaxed);
    if out_len == 0 {
        return if has_ready_record() {
            super::SUPERVISOR_RESUME_RECORD_BYTES as i32
        } else {
            0
        };
    }
    if let Err(errno) = validate_output(out_ptr, out_len) {
        return errno;
    }
    let Some(record) = pop_ready_record() else {
        return 0;
    };
    if record.kind == super::SUPERVISOR_RESUME_KIND_FUTEX_WAKE {
        super::futex::authorize_wake_completion(record.vm_ptr);
    }
    write_encoded_record(record, out_ptr)
}

pub(super) fn write_process_record(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    POLL_COUNT.fetch_add(1, Ordering::Relaxed);
    if out_len == 0 {
        return match super::runnable::has_selection(vm_ptr) {
            Ok(true) => super::SUPERVISOR_RESUME_RECORD_BYTES as i32,
            Ok(false) => 0,
            Err(errno) => errno,
        };
    }
    if let Err(errno) = validate_output(out_ptr, out_len) {
        return errno;
    }
    let selected = match super::runnable::select_from_supervisor_state(vm_ptr) {
        Ok(Some(selected)) => selected,
        Ok(None) => return 0,
        Err(errno) => return errno,
    };
    let seq = next_enqueue_seq();
    write_encoded_record(
        super::SupervisorResumeRecord {
            kind: super::SUPERVISOR_RESUME_KIND_RUNNABLE_THREAD,
            seq,
            vm_ptr: selected.vm_ptr,
            tid: selected.tid,
            process_ptr: selected.process_ptr,
            status: selected.status,
            detail0: selected.slot as u64,
        },
        out_ptr,
    )
}
