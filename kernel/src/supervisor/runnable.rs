use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static SELECTION_COUNT: AtomicU64 = AtomicU64::new(0);
static SELECTION_CURSOR: AtomicU32 = AtomicU32::new(0);

pub(super) struct RunnableSelection {
    pub(super) vm_ptr: u32,
    pub(super) tid: u32,
    pub(super) process_ptr: u32,
    pub(super) status: u32,
    pub(super) slot: u32,
}

struct RunnableThreadSelection {
    status: u32,
    process_ptr: u32,
}

#[derive(Clone, Copy)]
struct GuestSleepSelection {
    deadline: u64,
    vm_ptr: u32,
    tid: u32,
    process_ptr: u32,
    slot: u32,
}

pub(super) fn init() {
    SELECTION_COUNT.store(0, Ordering::Relaxed);
    SELECTION_CURSOR.store(0, Ordering::Relaxed);
}

fn find_from_supervisor_state(
    vm_ptr: u32,
    commit: bool,
    excluded_vm_ptr: u32,
    excluded_tid: i32,
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
    let vfork_process_gate = super::blocked::vfork_process_gate_blocks(vm);
    if process_has_process_wide_fs_gate_for_thread(vm) {
        return Ok(None);
    }
    let cursor = SELECTION_CURSOR.load(Ordering::Relaxed) as usize % crate::abi::MAX_THREADS;
    let now = crate::syscall::time::monotonic_ticks_current();
    let mut earliest_guest_sleep: Option<GuestSleepSelection> = None;
    for step in 0..crate::abi::MAX_THREADS {
        let slot = (cursor + step) % crate::abi::MAX_THREADS;
        let mut record = ps.threads[slot];
        if matches!(
            record.state,
            crate::types::THREAD_NONE | crate::types::THREAD_DEAD
        ) || record.thread_ptr == 0
            || record.thread_ptr == excluded_vm_ptr
            || (excluded_tid > 0 && record.tid == excluded_tid)
        {
            continue;
        }
        let futex_word_mismatched = super::futex::blocked_wait_word_mismatched(record.thread_ptr);
        if futex_word_mismatched {
            if !commit {
                return Ok(Some(RunnableSelection {
                    vm_ptr: record.thread_ptr,
                    tid: record.tid as u32,
                    process_ptr: vm.process_ptr,
                    status: crate::abi::STATUS_OK as u32,
                    slot: slot as u32,
                }));
            }
            if !super::futex::complete_wait_if_word_mismatched(record.thread_ptr) {
                continue;
            }
            record = ps.threads[slot];
        }
        let event_override =
            super::event::thread_state_override(record.thread_ptr, record.tid as u32);
        let guest_sleep_deadline = super::thread::state_from_ptr(record.thread_ptr)
            .and_then(crate::syscall::time::thread_guest_sleep_deadline);
        let supervisor_manages_blocked_guest_sleep = guest_sleep_deadline.is_some()
            && event_override
                .as_ref()
                .is_none_or(|event| event.status == crate::abi::STATUS_SLEEP as u32);
        match super::event::runnable_override(record.thread_ptr, record.tid as u32) {
            Some(false) if !supervisor_manages_blocked_guest_sleep => continue,
            Some(false) => {}
            Some(true) => {}
            None => {
                if record.state != crate::types::THREAD_RUNNING {
                    continue;
                }
            }
        }
        let thread = if vfork_process_gate {
            active_vfork_child_selection_from_record(&record, vm.guest_base)
        } else {
            runnable_thread_selection_from_record(&record, vm.guest_base, vm.process_ptr)
        };
        let Some(mut thread) = thread else {
            continue;
        };
        if let Some(ref event) = event_override {
            thread.status = event.status;
        }
        if supervisor_manages_blocked_guest_sleep
            && thread.status == crate::abi::STATUS_SLEEP as u32
        {
            let Some(deadline) = guest_sleep_deadline else {
                continue;
            };
            if deadline <= now {
                if commit {
                    let sleeping_thread =
                        unsafe { &mut *(record.thread_ptr as *mut crate::types::ThreadState) };
                    crate::syscall::time::complete_thread_sleep(sleeping_thread);
                }
                thread.status = crate::abi::STATUS_OK as u32;
            } else {
                let candidate = GuestSleepSelection {
                    deadline,
                    vm_ptr: record.thread_ptr,
                    tid: record.tid as u32,
                    process_ptr: thread.process_ptr,
                    slot: slot as u32,
                };
                if earliest_guest_sleep.is_none_or(|current| candidate.deadline < current.deadline)
                {
                    earliest_guest_sleep = Some(candidate);
                }
                continue;
            }
        }
        if thread.status != crate::abi::STATUS_OK as u32
            && thread.status != crate::abi::STATUS_VFORK_WAIT as u32
        {
            continue;
        }
        if commit {
            SELECTION_CURSOR.store(
                ((slot + 1) % crate::abi::MAX_THREADS) as u32,
                Ordering::Relaxed,
            );
            SELECTION_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        return Ok(Some(RunnableSelection {
            vm_ptr: record.thread_ptr,
            tid: record.tid as u32,
            process_ptr: thread.process_ptr,
            status: thread.status,
            slot: slot as u32,
        }));
    }
    if let Some(sleep) = earliest_guest_sleep {
        if commit {
            crate::syscall::time::sync_monotonic_ticks_floor(sleep.deadline);
            let sleeping_thread = unsafe { &mut *(sleep.vm_ptr as *mut crate::types::ThreadState) };
            crate::syscall::time::complete_thread_sleep(sleeping_thread);
            SELECTION_CURSOR.store(
                ((sleep.slot as usize + 1) % crate::abi::MAX_THREADS) as u32,
                Ordering::Relaxed,
            );
            SELECTION_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        return Ok(Some(RunnableSelection {
            vm_ptr: sleep.vm_ptr,
            tid: sleep.tid,
            process_ptr: sleep.process_ptr,
            status: crate::abi::STATUS_OK as u32,
            slot: sleep.slot,
        }));
    }
    Ok(None)
}

fn live_thread_record(record: &crate::types::ThreadRecord) -> bool {
    !matches!(
        record.state,
        crate::types::THREAD_NONE | crate::types::THREAD_DEAD
    ) && record.thread_ptr != 0
}

fn thread_status_for_process_gate(
    record: &crate::types::ThreadRecord,
    base: u32,
    process_ptr: u32,
) -> Option<u32> {
    if let Some(override_state) =
        super::event::thread_state_override(record.thread_ptr, record.tid as u32)
    {
        if matches!(
            override_state.state,
            state if state == crate::types::THREAD_NONE as u32
                || state == crate::types::THREAD_DEAD as u32
        ) {
            return None;
        }
        return Some(override_state.status);
    }
    super::state::validated_thread_status_from_record(record, base, process_ptr)
}

fn process_has_process_wide_fs_gate(
    ps: &crate::types::ProcessState,
    base: u32,
    process_ptr: u32,
) -> bool {
    for record in ps.threads.iter() {
        if !live_thread_record(record) {
            continue;
        }
        if thread_status_for_process_gate(record, base, process_ptr)
            == Some(crate::abi::STATUS_FS as u32)
            && super::fs::pending_process_wide_gate(record.thread_ptr)
        {
            return true;
        }
    }
    false
}

pub(super) fn process_has_process_wide_fs_gate_for_thread(vm: &crate::types::ThreadState) -> bool {
    if vm.process_ptr == 0 {
        return false;
    }
    let ps = unsafe {
        &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState)
    };
    process_has_process_wide_fs_gate(ps, vm.guest_base, vm.process_ptr)
}

fn runnable_thread_selection_from_record(
    record: &crate::types::ThreadRecord,
    base: u32,
    process_ptr: u32,
) -> Option<RunnableThreadSelection> {
    if let Some(status) =
        super::state::validated_thread_status_from_record(record, base, process_ptr)
    {
        return Some(RunnableThreadSelection {
            status,
            process_ptr,
        });
    }
    active_vfork_child_selection_from_record(record, base)
}

fn active_vfork_child_selection_from_record(
    record: &crate::types::ThreadRecord,
    base: u32,
) -> Option<RunnableThreadSelection> {
    let thread = super::thread::state_from_ptr(record.thread_ptr)?;
    if thread.guest_base != base
        || thread.status != crate::abi::STATUS_VFORK_WAIT
        || !crate::syscall::process::vfork_active()
    {
        return None;
    }
    let child_pid = crate::syscall::process::vfork_child_pid();
    if child_pid <= 0 {
        return None;
    }
    if record.tid != child_pid {
        return None;
    }
    if crate::syscall::process::current_process_pid(thread, thread.guest_base) != child_pid {
        return None;
    }
    Some(RunnableThreadSelection {
        status: thread.status as u32,
        process_ptr: thread.process_ptr,
    })
}

pub(super) fn has_selection(vm_ptr: u32) -> Result<bool, i32> {
    find_from_supervisor_state(vm_ptr, false, 0, 0).map(|selection| selection.is_some())
}

pub(super) fn has_other_selection(vm_ptr: u32) -> Result<bool, i32> {
    let vm = super::thread::state_from_ptr(vm_ptr).ok_or(crate::abi::EFAULT as i32)?;
    find_from_supervisor_state(vm_ptr, false, vm_ptr, vm.tid).map(|selection| selection.is_some())
}

pub(super) fn select_from_supervisor_state(vm_ptr: u32) -> Result<Option<RunnableSelection>, i32> {
    find_from_supervisor_state(vm_ptr, true, 0, 0)
}
