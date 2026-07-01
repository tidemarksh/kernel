use core::sync::atomic::Ordering;

fn with_queue_lock<T>(f: impl FnOnce() -> T) -> T {
    loop {
        if super::HOST_OP_QUEUE_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let result = f();
    super::HOST_OP_QUEUE_LOCK.store(0, Ordering::Release);
    result
}

pub(super) fn init_queue() {
    with_queue_lock(|| unsafe {
        super::HOST_OP_QUEUE_HEAD.store(0, Ordering::Relaxed);
        super::HOST_OP_QUEUE_TAIL.store(0, Ordering::Relaxed);
        let queue_ptr =
            core::ptr::addr_of_mut!(super::HOST_OP_QUEUE) as *mut super::SupervisorHostOpRequest;
        for idx in 0..super::HOST_OP_QUEUE_CAP {
            core::ptr::write(queue_ptr.add(idx), super::HOST_OP_QUEUE_EMPTY);
        }
    });
}

fn push_request(record: super::SupervisorHostOpRequest) -> bool {
    with_queue_lock(|| unsafe {
        let head = super::HOST_OP_QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = super::HOST_OP_QUEUE_TAIL.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % super::HOST_OP_QUEUE_CAP as u32;
        if next_tail == head {
            super::HOST_OP_OVERFLOW_COUNT.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let queue_ptr =
            core::ptr::addr_of_mut!(super::HOST_OP_QUEUE) as *mut super::SupervisorHostOpRequest;
        core::ptr::write(queue_ptr.add(tail as usize), record);
        super::HOST_OP_QUEUE_TAIL.store(next_tail, Ordering::Relaxed);
        true
    })
}

fn peek_request() -> Option<super::SupervisorHostOpRequest> {
    with_queue_lock(|| unsafe {
        let head = super::HOST_OP_QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = super::HOST_OP_QUEUE_TAIL.load(Ordering::Relaxed);
        if head == tail {
            return None;
        }
        let queue_ptr =
            core::ptr::addr_of!(super::HOST_OP_QUEUE) as *const super::SupervisorHostOpRequest;
        Some(core::ptr::read(queue_ptr.add(head as usize)))
    })
}

fn pop_request() -> Option<super::SupervisorHostOpRequest> {
    with_queue_lock(|| unsafe {
        let head = super::HOST_OP_QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = super::HOST_OP_QUEUE_TAIL.load(Ordering::Relaxed);
        if head == tail {
            return None;
        }
        let queue_ptr =
            core::ptr::addr_of_mut!(super::HOST_OP_QUEUE) as *mut super::SupervisorHostOpRequest;
        let record = core::ptr::read(queue_ptr.add(head as usize));
        core::ptr::write(queue_ptr.add(head as usize), super::HOST_OP_QUEUE_EMPTY);
        super::HOST_OP_QUEUE_HEAD.store(
            (head + 1) % super::HOST_OP_QUEUE_CAP as u32,
            Ordering::Relaxed,
        );
        Some(record)
    })
}

fn remove_request(kind: u32, parent_vm_ptr: u32) -> bool {
    with_queue_lock(|| unsafe {
        let head = super::HOST_OP_QUEUE_HEAD.load(Ordering::Relaxed);
        let tail = super::HOST_OP_QUEUE_TAIL.load(Ordering::Relaxed);
        let queue_ptr =
            core::ptr::addr_of_mut!(super::HOST_OP_QUEUE) as *mut super::SupervisorHostOpRequest;
        let mut read = head;
        let mut write = head;
        let mut removed = false;
        while read != tail {
            let current = read;
            let record = core::ptr::read(queue_ptr.add(current as usize));
            read = (read + 1) % super::HOST_OP_QUEUE_CAP as u32;
            if !removed && record.kind == kind && record.parent_vm_ptr == parent_vm_ptr {
                removed = true;
                continue;
            }
            core::ptr::write(queue_ptr.add(write as usize), record);
            write = (write + 1) % super::HOST_OP_QUEUE_CAP as u32;
        }
        if removed {
            let mut clear = write;
            while clear != tail {
                core::ptr::write(queue_ptr.add(clear as usize), super::HOST_OP_QUEUE_EMPTY);
                clear = (clear + 1) % super::HOST_OP_QUEUE_CAP as u32;
            }
            super::HOST_OP_QUEUE_TAIL.store(write, Ordering::Relaxed);
        }
        removed
    })
}

pub(super) fn write_record(out_ptr: u32, out_len: u32) -> i32 {
    super::HOST_OP_POLL_COUNT.fetch_add(1, Ordering::Relaxed);
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
    let seq = super::HOST_OP_EMIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
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
    super::record_host_op_log_entry(&encoded, super::SUPERVISOR_HOST_OP_RECORD_BYTES);
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
        vm.spawn_supervisor_host_op_seq =
            super::HOST_OP_EMIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
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
    super::HOST_OP_POLL_COUNT.fetch_add(1, Ordering::Relaxed);
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
        super::record_host_op_log_entry(&encoded, super::SUPERVISOR_PROCESS_HOST_OP_RECORD_BYTES);
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

pub(super) fn enqueue_futex_wait_timer(vm: &crate::types::ThreadState) -> bool {
    if vm.futex_wait_timeout == 0 {
        return false;
    }
    let delay_ticks = crate::syscall::time::timeout_timespec_delta_ticks(
        vm.guest_base,
        vm.futex_wait_timeout,
        vm.futex_wait_absolute != 0,
        (vm.futex_wait_flags & crate::abi::FUTEX_CLOCK_REALTIME) != 0,
    )
    .unwrap_or(0);
    let delay_ms = crate::syscall::time::ticks_to_millis_ceil(delay_ticks);
    push_request(super::SupervisorHostOpRequest {
        kind: super::SUPERVISOR_HOST_OP_KIND_ARM_HOST_TIMER,
        parent_vm_ptr: vm as *const crate::types::ThreadState as u32,
        child_vm_ptr: 0,
        tid: vm.tid as u32,
        process_ptr: vm.process_ptr,
        status: vm.status as u32,
        detail0: delay_ms,
        detail1: delay_ticks,
    })
}
