pub(super) fn state_from_ptr(vm_ptr: u32) -> Option<&'static crate::types::ThreadState> {
    if vm_ptr == 0 {
        return None;
    }
    let absolute = vm_ptr as usize;
    let align = core::mem::align_of::<crate::types::ThreadState>();
    if (absolute & (align - 1)) != 0 {
        return None;
    }
    let end = absolute.checked_add(core::mem::size_of::<crate::types::ThreadState>())?;
    let memory_size = crate::wasm::memory_size_bytes();
    if memory_size == 0 || end as u64 > memory_size {
        return None;
    }
    Some(unsafe { &*(absolute as *const crate::types::ThreadState) })
}

pub(super) fn state_mut_from_ptr(vm_ptr: u32) -> Option<&'static mut crate::types::ThreadState> {
    if vm_ptr == 0 {
        return None;
    }
    let absolute = vm_ptr as usize;
    if absolute < core::mem::size_of::<crate::types::ThreadState>() {
        return None;
    }
    Some(unsafe { &mut *(absolute as *mut crate::types::ThreadState) })
}

fn status_from_record(record: &crate::types::ThreadRecord, base: u32, process_ptr: u32) -> u32 {
    super::state::validated_thread_status_from_record(record, base, process_ptr).unwrap_or(0)
}

pub(super) fn write_state_snapshot(vm_ptr: u32, out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as i32;
    }
    if vm_ptr == 0 || out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let vm = unsafe { &*(vm_ptr as *const crate::types::ThreadState) };
    if vm.process_ptr == 0 {
        return crate::abi::EINVAL as i32;
    }
    let ps = unsafe {
        &*((vm.guest_base as u64 + vm.process_ptr as u64) as *const crate::types::ProcessState)
    };
    let mut snapshot = [0u8; super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as usize];
    super::write_u32(
        &mut snapshot,
        0,
        super::SUPERVISOR_THREAD_STATE_SNAPSHOT_MAGIC,
    );
    super::write_u32(&mut snapshot, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(
        &mut snapshot,
        8,
        super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES,
    );
    super::write_u32(&mut snapshot, 12, crate::abi::MAX_THREADS as u32);
    super::write_u32(&mut snapshot, 16, vm.process_ptr);
    super::write_u32(&mut snapshot, 20, vm_ptr);
    super::write_u32(
        &mut snapshot,
        24,
        super::SUPERVISOR_THREAD_STATE_RECORD_BYTES as u32,
    );
    super::write_u32(&mut snapshot, 28, 0);
    for slot in 0..crate::abi::MAX_THREADS {
        let record = ps.threads[slot];
        let offset = super::SUPERVISOR_THREAD_STATE_HEADER_BYTES
            + slot * super::SUPERVISOR_THREAD_STATE_RECORD_BYTES;
        super::write_u32(&mut snapshot, offset, record.tid as u32);
        super::write_u32(&mut snapshot, offset + 4, record.state as u32);
        super::write_u32(&mut snapshot, offset + 8, record.thread_ptr);
        super::write_u32(
            &mut snapshot,
            offset + 12,
            status_from_record(&record, vm.guest_base, vm.process_ptr),
        );
        super::write_u64(&mut snapshot, offset + 16, record.blocked_addr);
        super::write_u64(&mut snapshot, offset + 24, record.pending_sigset);
    }
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as usize,
        )
    };
    out.copy_from_slice(&snapshot);
    super::SUPERVISOR_THREAD_STATE_SNAPSHOT_BYTES as i32
}
