use core::sync::atomic::Ordering;

pub(super) struct RunnableSelection {
    pub(super) seq: u64,
    pub(super) vm_ptr: u32,
    pub(super) tid: u32,
    pub(super) process_ptr: u32,
    pub(super) state: u32,
    pub(super) status: u32,
    pub(super) slot: u32,
}

fn find_from_supervisor_state(
    vm_ptr: u32,
    candidates: Option<&[u8]>,
    commit: bool,
) -> Result<Option<RunnableSelection>, i32> {
    if vm_ptr == 0 {
        return Err(crate::abi::EFAULT as i32);
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if vm.process_ptr == 0 {
        return Err(crate::abi::EINVAL as i32);
    }
    let ps = unsafe {
        &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState)
    };
    let cursor =
        super::RUNNABLE_SELECTION_CURSOR.load(Ordering::Relaxed) as usize % crate::abi::MAX_THREADS;
    for step in 0..crate::abi::MAX_THREADS {
        let slot = (cursor + step) % crate::abi::MAX_THREADS;
        let record = ps.threads[slot];
        if record.state != crate::types::THREAD_RUNNING {
            continue;
        }
        if let Some(candidates) = candidates {
            if !super::candidate_list_contains(candidates, record.thread_ptr) {
                continue;
            }
        }
        if super::event::suppresses_runnable(record.thread_ptr, record.tid as u32) {
            continue;
        }
        let Some(status) = super::state::validated_thread_status_from_record(
            &record,
            vm.guest_base,
            vm.process_ptr,
        ) else {
            continue;
        };
        if status != crate::abi::STATUS_OK as u32 {
            continue;
        }
        let seq = if commit {
            super::RUNNABLE_SELECTION_CURSOR.store(
                ((slot + 1) % crate::abi::MAX_THREADS) as u32,
                Ordering::Relaxed,
            );
            super::RUNNABLE_SELECTION_COUNT.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            0
        };
        return Ok(Some(RunnableSelection {
            seq,
            vm_ptr: record.thread_ptr,
            tid: record.tid as u32,
            process_ptr: vm.process_ptr,
            state: record.state as u32,
            status,
            slot: slot as u32,
        }));
    }
    Ok(None)
}

pub(super) fn has_selection(vm_ptr: u32) -> Result<bool, i32> {
    find_from_supervisor_state(vm_ptr, None, false).map(|selection| selection.is_some())
}

pub(super) fn select_from_supervisor_state(
    vm_ptr: u32,
    candidates: Option<&[u8]>,
) -> Result<Option<RunnableSelection>, i32> {
    find_from_supervisor_state(vm_ptr, candidates, true)
}

pub(super) fn write_selection(
    vm_ptr: u32,
    candidates_ptr: u32,
    candidate_count: u32,
    out_ptr: u32,
    out_len: u32,
) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_RUNNABLE_SELECTION_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_RUNNABLE_SELECTION_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    if candidate_count as usize > crate::abi::MAX_THREADS {
        return crate::abi::EINVAL as i32;
    }
    let candidates = if candidate_count == 0 {
        None
    } else {
        let Some(candidate_bytes_len) = candidate_count.checked_mul(4) else {
            return crate::abi::EINVAL as i32;
        };
        match super::read_shadow_bytes(candidates_ptr, candidate_bytes_len) {
            Ok(candidates) => Some(candidates),
            Err(errno) => return errno,
        }
    };
    let selected = match select_from_supervisor_state(vm_ptr, candidates) {
        Ok(Some(selected)) => selected,
        Ok(None) => return 0,
        Err(errno) => return errno,
    };
    let mut encoded = [0u8; super::SUPERVISOR_RUNNABLE_SELECTION_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_RUNNABLE_SELECTION_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_RUNNABLE_SELECTION_BYTES);
    super::write_u32(&mut encoded, 12, 0);
    super::write_u64(&mut encoded, 16, selected.seq);
    super::write_u32(&mut encoded, 24, selected.vm_ptr);
    super::write_u32(&mut encoded, 28, selected.tid);
    super::write_u32(&mut encoded, 32, selected.process_ptr);
    super::write_u32(&mut encoded, 36, selected.state);
    super::write_u32(&mut encoded, 40, selected.status);
    super::write_u32(&mut encoded, 44, selected.slot);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_RUNNABLE_SELECTION_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_RUNNABLE_SELECTION_BYTES as i32
}
