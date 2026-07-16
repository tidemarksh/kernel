use core::sync::atomic::{AtomicU32, Ordering};

static AUTHORIZED_WAKE_VM_PTR: AtomicU32 = AtomicU32::new(0);

pub(super) fn init() {
    AUTHORIZED_WAKE_VM_PTR.store(0, Ordering::Relaxed);
}

pub(super) fn authorize_wake_completion(vm_ptr: u32) {
    AUTHORIZED_WAKE_VM_PTR.store(vm_ptr, Ordering::Release);
}

fn take_wake_completion_authorization(vm_ptr: u32) -> bool {
    vm_ptr != 0
        && AUTHORIZED_WAKE_VM_PTR
            .compare_exchange(vm_ptr, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

fn blocked_wait_signal_pending(vm: &crate::types::ThreadState, base: u32) -> bool {
    crate::syscall::signal::pending_signal_interrupts_blocked_syscall(vm, base)
        || vm.sig_pending != 0
}

pub(super) fn wait_word_mismatched(thread: &crate::types::ThreadState, addr: u64) -> bool {
    if addr == 0 || (addr & 3) != 0 {
        return true;
    }
    if !crate::syscall::memory::guest_range_permitted(
        thread,
        thread.guest_base,
        addr,
        4,
        crate::abi::PROT_READ,
    ) {
        return true;
    }
    let current = unsafe { crate::guest_mem::read_u32(thread.guest_base, addr) };
    current != thread.futex_wait_expected
}

pub(super) fn blocked_wait_word_mismatched(vm_ptr: u32) -> bool {
    let Some(thread) = super::thread::state_from_ptr(vm_ptr) else {
        return false;
    };
    if thread.status != crate::abi::STATUS_FUTEX_WAIT {
        return false;
    }
    let blocked_addr = thread.futex_wait_addr;
    blocked_addr != 0 && wait_word_mismatched(thread, blocked_addr)
}

pub(super) fn complete_wait_if_word_mismatched(vm_ptr: u32) -> bool {
    if !blocked_wait_word_mismatched(vm_ptr) {
        return false;
    }
    complete_wait(vm_ptr, super::SUPERVISOR_FUTEX_WAIT_COMPLETION_NOT_EQUAL)
        == crate::abi::STATUS_OK
}

pub(super) fn blocked_wait_signal_decision(vm_ptr: u32) -> i32 {
    if vm_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if blocked_wait_signal_pending(vm, vm.guest_base) {
        1
    } else {
        0
    }
}

pub(super) fn enqueue_resume(process_ptr: u32, vm_ptr: u32, tid: i32, futex_addr: u64) -> bool {
    if process_ptr == 0 || vm_ptr == 0 || tid <= 0 {
        return false;
    }
    let seq = super::resume::next_enqueue_seq();
    super::resume::push_record(super::SupervisorResumeRecord {
        kind: super::SUPERVISOR_RESUME_KIND_FUTEX_WAKE,
        seq,
        vm_ptr,
        tid: tid as u32,
        process_ptr,
        status: crate::abi::STATUS_OK as u32,
        detail0: futex_addr,
    })
}

fn thread_state_from_ptr_mut(vm_ptr: u32) -> Result<&'static mut crate::types::ThreadState, i32> {
    if vm_ptr == 0 {
        return Err(crate::abi::EFAULT as i32);
    }
    Ok(unsafe { &mut *(vm_ptr as *mut crate::types::ThreadState) })
}

pub(super) fn complete_wait(vm_ptr: u32, completion: u32) -> i32 {
    let vm = match thread_state_from_ptr_mut(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return errno,
    };
    let base = vm.guest_base;
    let process_ptr = vm.process_ptr;
    let tid = vm.tid;
    let futex_addr = vm.futex_wait_addr;
    let blocked_addr = super::thread::thread_record_blocked_addr(vm, base);
    let signal_pending = blocked_wait_signal_pending(vm, base);

    let result = if blocked_addr == 0 {
        Some(0)
    } else if completion == super::SUPERVISOR_FUTEX_WAIT_COMPLETION_WOKEN
        && take_wake_completion_authorization(vm_ptr)
    {
        Some(0)
    } else if completion == super::SUPERVISOR_FUTEX_WAIT_COMPLETION_WOKEN
        && vm.status == crate::abi::STATUS_OK
        && vm.futex_wait_addr == 0
    {
        Some(vm.x[10] as i64)
    } else if blocked_addr == u64::MAX {
        Some(crate::abi::EAGAIN)
    } else if signal_pending {
        let (thread_pending, process_pending, record_pending, deliverable) =
            crate::syscall::signal::pending_signal_snapshot(vm, base);
        super::record_signal_control(
            super::SUPERVISOR_SIGNAL_CONTROL_KIND_BLOCKED_WAIT_INTERRUPTED,
            vm,
            base,
            super::signal::first_signal_from_bits(deliverable | vm.sig_pending | record_pending),
            super::SUPERVISOR_SIGNAL_BOUNDARY_BLOCKED_WAIT,
            thread_pending,
            process_pending,
            record_pending,
            deliverable,
            completion as u64,
            blocked_addr,
        );
        Some(crate::abi::EINTR)
    } else if completion == super::SUPERVISOR_FUTEX_WAIT_COMPLETION_SIGNAL_CHECK {
        None
    } else {
        match completion {
            super::SUPERVISOR_FUTEX_WAIT_COMPLETION_NOT_EQUAL => Some(0),
            super::SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT => Some(crate::abi::ETIMEDOUT),
            super::SUPERVISOR_FUTEX_WAIT_COMPLETION_INVALID_ADDRESS => Some(crate::abi::EAGAIN),
            super::SUPERVISOR_FUTEX_WAIT_COMPLETION_WOKEN => None,
            _ => Some(crate::abi::EINVAL),
        }
    };

    if let Some(result) = result {
        crate::syscall::thread::resume_futex_wait_result(vm, base, result);
        super::event::clear_woken_futex_override(vm_ptr, tid as u32);
        if completion == super::SUPERVISOR_FUTEX_WAIT_COMPLETION_TIMED_OUT
            && vm.status == crate::abi::STATUS_OK
        {
            enqueue_resume(process_ptr, vm_ptr, tid, futex_addr);
        }
    }
    vm.status
}
