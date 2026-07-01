use core::sync::atomic::Ordering;

fn with_queue_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if super::RESUME_QUEUE_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    super::RESUME_QUEUE_LOCK.store(0, Ordering::Release);
    result
}

pub(super) fn init_queue() {
    with_queue_lock(|| unsafe {
        super::RESUME_QUEUE_HEAD.store(0, Ordering::Relaxed);
        super::RESUME_QUEUE_TAIL.store(0, Ordering::Relaxed);
        let queue_ptr =
            core::ptr::addr_of_mut!(super::RESUME_QUEUE) as *mut super::SupervisorResumeRecord;
        for idx in 0..super::RESUME_QUEUE_CAP {
            core::ptr::write(queue_ptr.add(idx), super::RESUME_QUEUE_EMPTY);
        }
    });
}

pub(super) fn push_record(record: super::SupervisorResumeRecord) -> bool {
    with_queue_lock(|| unsafe {
        let head = super::RESUME_QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = super::RESUME_QUEUE_TAIL.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % super::RESUME_QUEUE_CAP as u32;
        if next_tail == head {
            super::RESUME_OVERFLOW_COUNT.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let queue_ptr =
            core::ptr::addr_of_mut!(super::RESUME_QUEUE) as *mut super::SupervisorResumeRecord;
        core::ptr::write(queue_ptr.add(tail as usize), record);
        super::RESUME_QUEUE_TAIL.store(next_tail, Ordering::Relaxed);
        true
    })
}

fn peek_record() -> Option<super::SupervisorResumeRecord> {
    with_queue_lock(|| unsafe {
        let head = super::RESUME_QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = super::RESUME_QUEUE_TAIL.load(Ordering::Relaxed);
        if head == tail {
            return None;
        }
        let queue_ptr =
            core::ptr::addr_of!(super::RESUME_QUEUE) as *const super::SupervisorResumeRecord;
        Some(core::ptr::read(queue_ptr.add(head as usize)))
    })
}

fn pop_record() -> Option<super::SupervisorResumeRecord> {
    with_queue_lock(|| unsafe {
        let head = super::RESUME_QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = super::RESUME_QUEUE_TAIL.load(Ordering::Relaxed);
        if head == tail {
            return None;
        }
        let queue_ptr =
            core::ptr::addr_of_mut!(super::RESUME_QUEUE) as *mut super::SupervisorResumeRecord;
        let record = core::ptr::read(queue_ptr.add(head as usize));
        core::ptr::write(queue_ptr.add(head as usize), super::RESUME_QUEUE_EMPTY);
        super::RESUME_QUEUE_HEAD.store(
            (head + 1) % super::RESUME_QUEUE_CAP as u32,
            Ordering::Relaxed,
        );
        Some(record)
    })
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
    super::RESUME_POLL_COUNT.fetch_add(1, Ordering::Relaxed);
    if out_len == 0 {
        return if peek_record().is_some() {
            super::SUPERVISOR_RESUME_RECORD_BYTES as i32
        } else {
            0
        };
    }
    if let Err(errno) = validate_output(out_ptr, out_len) {
        return errno;
    }
    let Some(record) = pop_record() else {
        return 0;
    };
    write_encoded_record(record, out_ptr)
}

pub(super) fn write_process_record(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    super::RESUME_POLL_COUNT.fetch_add(1, Ordering::Relaxed);
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
    let selected = match super::runnable::select_from_supervisor_state(vm_ptr, None) {
        Ok(Some(selected)) => selected,
        Ok(None) => return 0,
        Err(errno) => return errno,
    };
    let seq = super::RESUME_ENQUEUE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
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
