use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const QUEUE_CAP: usize = 256;
const QUEUE_EMPTY: super::SupervisorHostOpRequest = super::SupervisorHostOpRequest {
    kind: 0,
    parent_vm_ptr: 0,
    child_vm_ptr: 0,
    tid: 0,
    process_ptr: 0,
    status: 0,
    detail0: 0,
    detail1: 0,
};

static POLL_COUNT: AtomicU64 = AtomicU64::new(0);
static EMIT_COUNT: AtomicU64 = AtomicU64::new(0);
static OVERFLOW_COUNT: AtomicU64 = AtomicU64::new(0);
static QUEUE_LOCK: AtomicU32 = AtomicU32::new(0);
static QUEUE_HEAD: AtomicU32 = AtomicU32::new(0);
static QUEUE_TAIL: AtomicU32 = AtomicU32::new(0);
static mut QUEUE: [super::SupervisorHostOpRequest; QUEUE_CAP] = [QUEUE_EMPTY; QUEUE_CAP];

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
    EMIT_COUNT.store(0, Ordering::Relaxed);
    OVERFLOW_COUNT.store(0, Ordering::Relaxed);
    with_queue_lock(|| unsafe {
        QUEUE_HEAD.store(0, Ordering::Relaxed);
        QUEUE_TAIL.store(0, Ordering::Relaxed);
        let queue_ptr = core::ptr::addr_of_mut!(QUEUE) as *mut super::SupervisorHostOpRequest;
        for idx in 0..QUEUE_CAP {
            core::ptr::write(queue_ptr.add(idx), QUEUE_EMPTY);
        }
    });
}

pub(super) fn poll_count() -> u64 {
    POLL_COUNT.load(Ordering::Relaxed)
}

pub(super) fn emit_count() -> u64 {
    EMIT_COUNT.load(Ordering::Relaxed)
}

pub(super) fn overflow_count() -> u64 {
    OVERFLOW_COUNT.load(Ordering::Relaxed)
}

fn next_emit_seq() -> u64 {
    EMIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1
}

pub(super) fn push_request(record: super::SupervisorHostOpRequest) -> bool {
    with_queue_lock(|| unsafe {
        let head = QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = QUEUE_TAIL.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % QUEUE_CAP as u32;
        if next_tail == head {
            OVERFLOW_COUNT.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let queue_ptr = core::ptr::addr_of_mut!(QUEUE) as *mut super::SupervisorHostOpRequest;
        core::ptr::write(queue_ptr.add(tail as usize), record);
        QUEUE_TAIL.store(next_tail, Ordering::Relaxed);
        true
    })
}

fn peek_request() -> Option<super::SupervisorHostOpRequest> {
    with_queue_lock(|| unsafe {
        let head = QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = QUEUE_TAIL.load(Ordering::Relaxed);
        if head == tail {
            return None;
        }
        let queue_ptr = core::ptr::addr_of!(QUEUE) as *const super::SupervisorHostOpRequest;
        Some(core::ptr::read(queue_ptr.add(head as usize)))
    })
}

fn pop_request() -> Option<super::SupervisorHostOpRequest> {
    with_queue_lock(|| unsafe {
        let head = QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = QUEUE_TAIL.load(Ordering::Relaxed);
        if head == tail {
            return None;
        }
        let queue_ptr = core::ptr::addr_of_mut!(QUEUE) as *mut super::SupervisorHostOpRequest;
        let record = core::ptr::read(queue_ptr.add(head as usize));
        core::ptr::write(queue_ptr.add(head as usize), QUEUE_EMPTY);
        QUEUE_HEAD.store((head + 1) % QUEUE_CAP as u32, Ordering::Relaxed);
        Some(record)
    })
}

fn remove_request(kind: u32, parent_vm_ptr: u32) -> bool {
    with_queue_lock(|| unsafe {
        let head = QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = QUEUE_TAIL.load(Ordering::Relaxed);
        let queue_ptr = core::ptr::addr_of_mut!(QUEUE) as *mut super::SupervisorHostOpRequest;
        let mut read = head;
        let mut write = head;
        let mut removed = false;
        while read != tail {
            let current = read;
            let record = core::ptr::read(queue_ptr.add(current as usize));
            read = (read + 1) % QUEUE_CAP as u32;
            if !removed && record.kind == kind && record.parent_vm_ptr == parent_vm_ptr {
                removed = true;
                continue;
            }
            core::ptr::write(queue_ptr.add(write as usize), record);
            write = (write + 1) % QUEUE_CAP as u32;
        }
        if removed {
            let mut clear = write;
            while clear != tail {
                core::ptr::write(queue_ptr.add(clear as usize), QUEUE_EMPTY);
                clear = (clear + 1) % QUEUE_CAP as u32;
            }
            QUEUE_TAIL.store(write, Ordering::Relaxed);
        }
        removed
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = bytes.get(offset..end)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

pub(super) fn complete_host_op(bytes: &[u8]) -> i32 {
    if bytes.len() < super::SUPERVISOR_HOST_COMPLETION_RECORD_BYTES as usize {
        return 0;
    }
    let Some(magic) = read_u32(bytes, 0) else {
        return 0;
    };
    if magic != super::SUPERVISOR_HOST_COMPLETION_RECORD_MAGIC {
        return 0;
    }
    if read_u32(bytes, 4) != Some(super::SUPERVISOR_ABI_VERSION) {
        return 0;
    }
    let Some(record_len) = read_u32(bytes, 8) else {
        return 0;
    };
    if record_len < super::SUPERVISOR_HOST_COMPLETION_RECORD_BYTES
        || bytes.len() < record_len as usize
    {
        return 0;
    }
    if read_u32(bytes, 12) != Some(super::SUPERVISOR_HOST_OP_KIND_ARM_HOST_TIMER) {
        return 0;
    }
    if read_u32(bytes, 36) != Some(super::SUPERVISOR_HOST_COMPLETION_OUTCOME_SUCCESS) {
        return 0;
    }
    let parent_vm_ptr = read_u32(bytes, 24).unwrap_or(0);
    let deadline_ticks = read_u64(bytes, 56).unwrap_or(0);
    super::timer::complete_arm_host_timer(parent_vm_ptr, deadline_ticks)
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    POLL_COUNT.fetch_add(1, Ordering::Relaxed);
    if out_len == 0 {
        return if peek_request().is_some() {
            super::SUPERVISOR_HOST_OP_RECORD_BYTES as i32
        } else {
            0
        };
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_HOST_OP_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let Some(request) = pop_request() else {
        return 0;
    };
    let seq = next_emit_seq();
    let record = match request.kind {
        super::SUPERVISOR_HOST_OP_KIND_SPAWN_THREAD_WORKER => {
            let parent = unsafe { &*(request.parent_vm_ptr as *const crate::types::ThreadState) };
            let flags = parent.clone_flags;
            let child_tidptr = parent.clone_child_tidptr;
            let process_ptr = parent.process_ptr;
            let child_vm_ptr =
                crate::syscall::thread::spawn_from_clone(request.parent_vm_ptr, parent.guest_base);
            if child_vm_ptr == 0 {
                return crate::abi::EINVAL as i32;
            }
            let child = unsafe { &*(child_vm_ptr as *const crate::types::ThreadState) };
            super::SupervisorHostOpRecord {
                kind: request.kind,
                seq,
                parent_vm_ptr: request.parent_vm_ptr,
                child_vm_ptr,
                tid: child.tid as u32,
                process_ptr,
                status: crate::abi::STATUS_OK as u32,
                flags,
                child_tidptr,
            }
        }
        super::SUPERVISOR_HOST_OP_KIND_ARM_HOST_TIMER => super::SupervisorHostOpRecord {
            kind: request.kind,
            seq,
            parent_vm_ptr: request.parent_vm_ptr,
            child_vm_ptr: request.child_vm_ptr,
            tid: request.tid,
            process_ptr: request.process_ptr,
            status: request.status,
            flags: request.detail0,
            child_tidptr: request.detail1,
        },
        _ => return crate::abi::EINVAL as i32,
    };
    let mut encoded = [0u8; super::SUPERVISOR_HOST_OP_RECORD_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_HOST_OP_RECORD_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_HOST_OP_RECORD_BYTES);
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.parent_vm_ptr);
    super::write_u32(&mut encoded, 28, record.child_vm_ptr);
    super::write_u32(&mut encoded, 32, record.tid);
    super::write_u32(&mut encoded, 36, record.process_ptr);
    super::write_u32(&mut encoded, 40, record.status);
    super::write_u32(&mut encoded, 44, 0);
    super::write_u64(&mut encoded, 48, record.flags);
    super::write_u64(&mut encoded, 56, record.child_tidptr);
    super::log::record_host_op(&encoded, super::SUPERVISOR_HOST_OP_RECORD_BYTES);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_HOST_OP_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_HOST_OP_RECORD_BYTES as i32
}

fn process_op_pending(vm_ptr: u32) -> Result<bool, i32> {
    let vm = super::thread::state_from_ptr(vm_ptr).ok_or(crate::abi::EFAULT as i32)?;
    Ok(vm.spawn_kind != crate::abi::SPAWN_KIND_NONE && vm.spawn_child_pid > 0)
}

fn select_process_op(vm_ptr: u32) -> Result<Option<super::SupervisorProcessHostOpRecord>, i32> {
    let vm = super::thread::state_mut_from_ptr(vm_ptr).ok_or(crate::abi::EFAULT as i32)?;
    if vm.spawn_kind == crate::abi::SPAWN_KIND_NONE || vm.spawn_child_pid <= 0 {
        return Ok(None);
    }
    let log_emission = vm.spawn_supervisor_host_op_seq == 0;
    if log_emission {
        vm.spawn_supervisor_host_op_seq = next_emit_seq();
    }
    Ok(Some(super::SupervisorProcessHostOpRecord {
        kind: super::SUPERVISOR_PROCESS_HOST_OP_KIND_SPAWN_PROCESS_WORKER,
        seq: vm.spawn_supervisor_host_op_seq,
        log_emission,
        parent_vm_ptr: vm_ptr,
        spawn_kind: vm.spawn_kind,
        child_pid: vm.spawn_child_pid,
        process_ptr: vm.process_ptr,
        status: vm.status as u32,
        address_profile: vm.spawn_address_profile,
        guest_memory_policy_limit: vm.spawn_guest_memory_policy_limit,
        process_max_memory_pages: vm.spawn_process_max_memory_pages,
        path: vm.spawn_path,
        argv: vm.spawn_argv,
        envp: vm.spawn_envp,
    }))
}

pub(super) fn write_process_record(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    POLL_COUNT.fetch_add(1, Ordering::Relaxed);
    if out_len == 0 {
        return match process_op_pending(vm_ptr) {
            Ok(true) => super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES as i32,
            Ok(false) => 0,
            Err(errno) => errno,
        };
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let record = match select_process_op(vm_ptr) {
        Ok(Some(record)) => record,
        Ok(None) => return 0,
        Err(errno) => return errno,
    };
    let mut encoded = [0u8; super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES as usize];
    super::write_u32(
        &mut encoded,
        0,
        super::SUPERVISOR_PROCESS_HOST_OP_RECORD_MAGIC,
    );
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(
        &mut encoded,
        8,
        super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES,
    );
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.parent_vm_ptr);
    super::write_u32(&mut encoded, 28, record.spawn_kind);
    super::write_u32(&mut encoded, 32, record.child_pid as u32);
    super::write_u32(&mut encoded, 36, record.process_ptr);
    super::write_u32(&mut encoded, 40, record.status);
    super::write_u32(&mut encoded, 44, record.address_profile);
    super::write_u64(&mut encoded, 48, record.guest_memory_policy_limit);
    super::write_u32(&mut encoded, 56, record.process_max_memory_pages);
    super::write_u32(&mut encoded, 60, 0);
    super::write_u64(&mut encoded, 64, record.path);
    super::write_u64(&mut encoded, 72, record.argv);
    super::write_u64(&mut encoded, 80, record.envp);
    super::write_u64(&mut encoded, 88, 0);
    if record.log_emission {
        super::log::record_host_op(&encoded, super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES);
    }
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES as i32
}

pub(super) fn enqueue_clone_spawn(parent_vm_ptr: u32) -> bool {
    if parent_vm_ptr == 0 {
        return false;
    }
    push_request(super::SupervisorHostOpRequest {
        kind: super::SUPERVISOR_HOST_OP_KIND_SPAWN_THREAD_WORKER,
        parent_vm_ptr,
        child_vm_ptr: 0,
        tid: 0,
        process_ptr: 0,
        status: 0,
        detail0: 0,
        detail1: 0,
    })
}

pub(super) fn discard_clone_spawn(parent_vm_ptr: u32) -> bool {
    if parent_vm_ptr == 0 {
        return false;
    }
    remove_request(
        super::SUPERVISOR_HOST_OP_KIND_SPAWN_THREAD_WORKER,
        parent_vm_ptr,
    )
}
