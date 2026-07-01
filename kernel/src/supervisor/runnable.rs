use core::sync::atomic::Ordering;

pub(super) struct RunnableSelection {
    pub(super) vm_ptr: u32,
    pub(super) tid: u32,
    pub(super) process_ptr: u32,
    pub(super) status: u32,
    pub(super) slot: u32,
}

fn find_from_supervisor_state(vm_ptr: u32, commit: bool) -> Result<Option<RunnableSelection>, i32> {
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
        if matches!(
            record.state,
            crate::types::THREAD_NONE | crate::types::THREAD_DEAD
        ) || record.thread_ptr == 0
        {
            continue;
        }
        match super::event::runnable_override(record.thread_ptr, record.tid as u32) {
            Some(false) => continue,
            Some(true) => {}
            None => {
                if record.state != crate::types::THREAD_RUNNING {
                    continue;
                }
            }
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
        if commit {
            super::RUNNABLE_SELECTION_CURSOR.store(
                ((slot + 1) % crate::abi::MAX_THREADS) as u32,
                Ordering::Relaxed,
            );
            super::RUNNABLE_SELECTION_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        return Ok(Some(RunnableSelection {
            vm_ptr: record.thread_ptr,
            tid: record.tid as u32,
            process_ptr: vm.process_ptr,
            status,
            slot: slot as u32,
        }));
    }
    Ok(None)
}

pub(super) fn has_selection(vm_ptr: u32) -> Result<bool, i32> {
    find_from_supervisor_state(vm_ptr, false).map(|selection| selection.is_some())
}

pub(super) fn select_from_supervisor_state(vm_ptr: u32) -> Result<Option<RunnableSelection>, i32> {
    find_from_supervisor_state(vm_ptr, true)
}
