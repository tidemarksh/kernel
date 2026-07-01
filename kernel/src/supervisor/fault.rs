use core::sync::atomic::{AtomicU64, Ordering};

static DECISION_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) fn init() {
    DECISION_COUNT.store(0, Ordering::Relaxed);
}

fn exit_priority(thread: &crate::types::ThreadState) -> u32 {
    if thread.fault_signal != 0 {
        return 4;
    }
    if thread.fault_kind != 0 {
        return 3;
    }
    if thread.fault_pc != 0 || thread.fault_addr != 0 {
        return 2;
    }
    if thread.term_signal != 0 {
        return 1;
    }
    0
}

fn select_decision(vm_ptr: u32) -> Result<super::SupervisorFaultExitDecision, i32> {
    let vm = super::thread::state_from_ptr(vm_ptr).ok_or(crate::abi::EFAULT as i32)?;
    if vm.process_ptr == 0 {
        return Err(crate::abi::EINVAL as i32);
    }
    let ps = unsafe {
        &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState)
    };
    let remaining_threads = ps.thread_count.load(Ordering::Acquire);
    let mut live_threads = 0u32;
    let mut selected_vm_ptr = vm_ptr;
    let mut selected = vm;
    let mut selected_priority = exit_priority(vm);
    for record in ps.threads.iter() {
        if matches!(
            record.state,
            crate::types::THREAD_NONE | crate::types::THREAD_DEAD
        ) || record.thread_ptr == 0
        {
            continue;
        }
        let Some(thread) =
            super::state::validated_thread_from_record(record, vm.guest_base, vm.process_ptr)
        else {
            continue;
        };
        live_threads = live_threads.saturating_add(1);
        let priority = exit_priority(thread);
        if priority > selected_priority {
            selected_priority = priority;
            selected_vm_ptr = record.thread_ptr;
            selected = thread;
        }
    }
    let kind = if remaining_threads == 0 || live_threads == 0 {
        super::SUPERVISOR_FAULT_EXIT_KIND_PROCESS_EXIT
    } else {
        super::SUPERVISOR_FAULT_EXIT_KIND_THREAD_EXIT
    };
    let exit_vm_ptr = if kind == super::SUPERVISOR_FAULT_EXIT_KIND_PROCESS_EXIT {
        selected_vm_ptr
    } else {
        vm_ptr
    };
    let exit_thread = if kind == super::SUPERVISOR_FAULT_EXIT_KIND_PROCESS_EXIT {
        selected
    } else {
        vm
    };
    let seq = DECISION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    Ok(super::SupervisorFaultExitDecision {
        kind,
        seq,
        vm_ptr,
        exit_vm_ptr,
        tid: exit_thread.tid as u32,
        process_ptr: vm.process_ptr,
        remaining_threads,
        live_threads,
        exit_code: exit_thread.exit_code,
        term_signal: exit_thread.term_signal,
        status: exit_thread.status as u32,
        fault_signal: exit_thread.fault_signal as u32,
        fault_kind: exit_thread.fault_kind,
        fault_pc: exit_thread.fault_pc,
        fault_addr: exit_thread.fault_addr,
    })
}

pub(super) fn write_decision(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_FAULT_EXIT_DECISION_BYTES as i32;
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_FAULT_EXIT_DECISION_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let decision = match select_decision(vm_ptr) {
        Ok(decision) => decision,
        Err(errno) => return errno,
    };
    let mut encoded = [0u8; super::SUPERVISOR_FAULT_EXIT_DECISION_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_FAULT_EXIT_DECISION_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_FAULT_EXIT_DECISION_BYTES);
    super::write_u32(&mut encoded, 12, decision.kind);
    super::write_u64(&mut encoded, 16, decision.seq);
    super::write_u32(&mut encoded, 24, decision.vm_ptr);
    super::write_u32(&mut encoded, 28, decision.exit_vm_ptr);
    super::write_u32(&mut encoded, 32, decision.tid);
    super::write_u32(&mut encoded, 36, decision.process_ptr);
    super::write_u32(&mut encoded, 40, decision.remaining_threads);
    super::write_u32(&mut encoded, 44, decision.live_threads);
    super::write_u32(&mut encoded, 48, decision.exit_code as u32);
    super::write_u32(&mut encoded, 52, decision.term_signal as u32);
    super::write_u32(&mut encoded, 56, decision.status);
    super::write_u32(&mut encoded, 60, decision.fault_signal);
    super::write_u32(&mut encoded, 64, decision.fault_kind);
    super::write_u32(&mut encoded, 68, 0);
    super::write_u64(&mut encoded, 72, decision.fault_pc);
    super::write_u64(&mut encoded, 80, decision.fault_addr);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_FAULT_EXIT_DECISION_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_FAULT_EXIT_DECISION_BYTES as i32
}
