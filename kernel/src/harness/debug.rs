mod fd;
mod format;
mod memory;
mod process;
mod signal;
mod socket;
mod thread;

pub(crate) use fd::{
    fd_syscall_trace_entry, fd_syscall_trace_len, path_syscall_trace_entry, path_syscall_trace_len,
    path_syscall_trace_path_ptr,
};
pub(crate) use memory::{
    guest_write_overlap_trace_entry, guest_write_overlap_trace_len, memory_permit_cache_hits,
    memory_permit_cache_hits_by_prot, memory_permit_checks, memory_permit_checks_by_prot,
    memory_permit_cover_hits, memory_permit_cover_hits_by_prot, memory_permit_denied,
    memory_permit_denied_by_prot, memory_trace_entry, memory_trace_len, memory_trace_summary,
};
pub(crate) use process::*;
pub(crate) use thread::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::trace::{
        clear_cpu_trace, clear_memory_trace, record_memory_syscall, record_thread_step_entry_trace,
        record_thread_step_phase, record_thread_step_trace, THREAD_STEP_TRACE_CAP,
    };

    fn make_thread_state(
        tid: i32,
        status: i32,
        pc: u64,
        ra: u64,
        sp: u64,
        s11: u64,
    ) -> crate::types::ThreadState {
        let mut vm: crate::types::ThreadState = unsafe { core::mem::zeroed() };
        vm.tid = tid;
        vm.status = status;
        vm.pc = pc;
        vm.x[1] = ra;
        vm.x[2] = sp;
        vm.x[27] = s11;
        vm
    }

    #[test]
    fn last_thread_step_trace_for_vm_scans_recent_ring() {
        clear_cpu_trace();

        let vm1 = make_thread_state(1, 0, 0x111, 0x211, 0x311, 0x411);
        let vm2 = make_thread_state(2, 3, 0x122, 0x222, 0x322, 0x422);
        let vm1_ptr = &vm1 as *const crate::types::ThreadState as u32;
        let vm2_ptr = &vm2 as *const crate::types::ThreadState as u32;

        record_thread_step_trace(&vm1, 20000, 19999);
        record_thread_step_trace(&vm2, 20000, 19998);

        let vm1_entry = last_thread_step_trace_for_vm(vm1_ptr);
        assert_eq!(vm1_entry.vm_ptr, vm1_ptr);
        assert_eq!(vm1_entry.tid, 1);
        assert_eq!(vm1_entry.pc, 0x111);
        assert_eq!(vm1_entry.ra, 0x211);
        assert_eq!(vm1_entry.sp, 0x311);
        assert_eq!(vm1_entry.s11, 0x411);

        let vm2_entry = last_thread_step_trace_for_vm(vm2_ptr);
        assert_eq!(vm2_entry.vm_ptr, vm2_ptr);
        assert_eq!(vm2_entry.tid, 2);
        assert_eq!(vm2_entry.pc, 0x122);
        assert_eq!(vm2_entry.ra, 0x222);
        assert_eq!(vm2_entry.sp, 0x322);
        assert_eq!(vm2_entry.s11, 0x422);
    }

    #[test]
    fn clear_cpu_trace_resets_thread_step_ring() {
        clear_cpu_trace();

        let vm = make_thread_state(3, 0, 0x144, 0x244, 0x344, 0x444);
        let vm_ptr = &vm as *const crate::types::ThreadState as u32;
        record_thread_step_trace(&vm, 20000, 19997);
        assert_eq!(last_thread_step_trace_for_vm(vm_ptr).tid, 3);

        clear_cpu_trace();
        let cleared = last_thread_step_trace_for_vm(vm_ptr);
        assert_eq!(cleared.vm_ptr, 0);
        assert_eq!(cleared.tid, 0);
        assert_eq!(cleared.pc, 0);
    }

    #[test]
    fn last_thread_step_trace_for_vm_survives_recent_ring_churn() {
        clear_cpu_trace();

        let target = make_thread_state(3, 0, 0x144, 0x244, 0x344, 0x444);
        let target_ptr = &target as *const crate::types::ThreadState as u32;
        record_thread_step_trace(&target, 20000, 19997);

        for index in 0..(THREAD_STEP_TRACE_CAP + 8) {
            let vm = make_thread_state(
                10 + index as i32,
                0,
                0x1000 + index as u64,
                0x2000 + index as u64,
                0x3000 + index as u64,
                0x4000 + index as u64,
            );
            record_thread_step_trace(&vm, 20000, 19996 - index as i32);
        }

        let entry = last_thread_step_trace_for_vm(target_ptr);
        assert_eq!(entry.vm_ptr, target_ptr);
        assert_eq!(entry.tid, 3);
        assert_eq!(entry.pc, 0x144);
        assert_eq!(entry.ra, 0x244);
        assert_eq!(entry.sp, 0x344);
        assert_eq!(entry.s11, 0x444);
    }

    #[test]
    fn memory_trace_ring_keeps_recent_entries() {
        clear_memory_trace();

        record_memory_syscall(crate::abi::SYS_MMAP, 0x1000, 0x2000, 3, 0x22, 0x1000);
        record_memory_syscall(crate::abi::SYS_MPROTECT, 0x3000, 0x1000, 5, 0, 0);

        assert_eq!(memory_trace_len(), 2);
        let first = memory_trace_entry(0);
        assert_eq!(first.nr, crate::abi::SYS_MMAP);
        assert_eq!(first.arg0, 0x1000);
        assert_eq!(first.arg1, 0x2000);
        assert_eq!(first.arg2, 3);
        assert_eq!(first.arg3, 0x22);
        assert_eq!(first.result, 0x1000);

        let second = memory_trace_entry(1);
        assert_eq!(second.nr, crate::abi::SYS_MPROTECT);
        assert_eq!(second.arg0, 0x3000);
        assert_eq!(second.arg1, 0x1000);
        assert_eq!(second.arg2, 5);
        assert_eq!(second.result, 0);

        clear_memory_trace();
        assert_eq!(memory_trace_len(), 0);
    }

    #[test]
    fn last_thread_step_entry_trace_for_vm_survives_recent_ring_churn() {
        clear_cpu_trace();

        let target = make_thread_state(4, 20, 0x83336, 0x4d9b4, 0x37d6c000, 0xbfdc80);
        let target_ptr = &target as *const crate::types::ThreadState as u32;
        record_thread_step_entry_trace(&target, 20000);

        for index in 0..(THREAD_STEP_TRACE_CAP + 8) {
            let vm = make_thread_state(
                20 + index as i32,
                0,
                0x5000 + index as u64,
                0x6000 + index as u64,
                0x7000 + index as u64,
                0x8000 + index as u64,
            );
            record_thread_step_entry_trace(&vm, 20000 - index as i32);
        }

        let entry = last_thread_step_entry_trace_for_vm(target_ptr);
        assert_eq!(entry.vm_ptr, target_ptr);
        assert_eq!(entry.tid, 4);
        assert_eq!(entry.status, 20);
        assert_eq!(entry.pc, 0x83336);
        assert_eq!(entry.ra, 0x4d9b4);
        assert_eq!(entry.sp, 0x37d6c000);
        assert_eq!(entry.s11, 0xbfdc80);
    }

    #[test]
    fn last_thread_step_phase_for_vm_uses_direct_slot() {
        clear_cpu_trace();

        let vm = make_thread_state(5, 20, 0x83336, 0x4d9b4, 0x37d6c000, 0xbfdc80);
        let vm_ptr = &vm as *const crate::types::ThreadState as u32;
        record_thread_step_phase(&vm, 3, 20000, 0);

        let entry = last_thread_step_phase_for_vm(vm_ptr);
        assert_eq!(entry.vm_ptr, vm_ptr);
        assert_eq!(entry.tid, 5);
        assert_eq!(entry.phase, 3);
        assert_eq!(entry.status, 20);
        assert_eq!(entry.budget, 20000);
        assert_eq!(entry.pc, 0x83336);
        assert_eq!(entry.ra, 0x4d9b4);
        assert_eq!(entry.sp, 0x37d6c000);
        assert_eq!(entry.s11, 0xbfdc80);
    }
}
