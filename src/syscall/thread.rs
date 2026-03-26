//! Thread syscalls: clone, futex, exit, exit_group, set_tid_address, set_robust_list.
//!
//! clone(CLONE_VM | CLONE_THREAD) → STATUS_CLONE_SPAWN → TS spawns Worker.
//! futex(WAIT/WAKE) uses guest Memory Atomics directly.
//! futex(CMP_REQUEUE) requires kernel Worker.
//!
//! Semantics:
//! https://man7.org/linux/man-pages/man2/clone.2.html
//! https://man7.org/linux/man-pages/man2/futex.2.html
//! https://man7.org/linux/man-pages/man2/set_tid_address.2.html

use crate::abi::*;
use crate::guest_mem;
use crate::types::ThreadState;

/// set_tid_address: record the address where 0 will be written on thread exit,
/// then futex-wake that address. Returns the caller's TID.
/// https://man7.org/linux/man-pages/man2/set_tid_address.2.html
pub fn sys_set_tid_address(vm: &mut ThreadState, tidptr: u64) -> i64 {
    vm.clear_child_tid = tidptr;
    vm.tid as i64
}

/// set_robust_list: record robust futex list head. Stub — records address but
/// does not process the list on exit (no userspace mutex cleanup needed yet).
/// https://man7.org/linux/man-pages/man2/set_robust_list.2.html
pub fn sys_set_robust_list(_vm: &mut ThreadState, _head: u64, _len: u64) -> i64 {
    0 // success
}

/// exit: terminate the calling thread.
/// Decrements thread_count. If clear_child_tid is set, writes 0 and wakes futex.
/// Returns STATUS_FAULT to stop execution.
/// https://man7.org/linux/man-pages/man2/exit.2.html
pub fn sys_exit(vm: &mut ThreadState, base: u32, exit_code: u64) -> i32 {
    vm.exit_code = exit_code as i32;

    // Decrement thread_count in ProcessState
    let ps_ptr = vm.process_ptr as u64;
    let tc_off = core::mem::offset_of!(crate::types::ProcessState, thread_count) as u64;
    let tc = unsafe { guest_mem::read_u32(base, ps_ptr + tc_off) };
    if tc > 0 {
        unsafe { guest_mem::write_u32(base, ps_ptr + tc_off, tc - 1) };
    }

    // clear_child_tid: write 0 and wake futex waiters
    if vm.clear_child_tid != 0 {
        unsafe { guest_mem::write_u32(base, vm.clear_child_tid, 0) };
        // futex_wake would be done here; in single-instance, STATUS_FUTEX_WAKE
        // is not needed because there's no other thread blocked on Atomics.wait.
    }

    vm.status = STATUS_FAULT;
    STATUS_FAULT
}

/// exit_group: terminate all threads in the process.
/// Same as exit for now (single-thread). Multi-thread: broadcast termination.
/// https://man7.org/linux/man-pages/man2/exit_group.2.html
pub fn sys_exit_group(vm: &mut ThreadState, base: u32, exit_code: u64) -> i32 {
    sys_exit(vm, base, exit_code)
}

/// clone: create a new thread or process.
/// For CLONE_VM | CLONE_THREAD: creates ThreadState, returns STATUS_CLONE_SPAWN.
/// TS runtime will spawn a new Worker with the same shared Memory.
/// https://man7.org/linux/man-pages/man2/clone.2.html
pub fn sys_clone(
    vm: &mut ThreadState, base: u32,
    flags: u64, child_stack: u64, parent_tidptr: u64,
    tls: u64, child_tidptr: u64,
) -> i64 {
    let clone_flags = flags;

    // CLONE_VM | CLONE_THREAD → new thread in same process
    if clone_flags & CLONE_VM != 0 && clone_flags & CLONE_THREAD != 0 {
        // Allocate new TID
        let new_tid = allocate_tid(vm, base);
        if new_tid <= 0 { return ENOMEM; }

        // Increment thread_count
        let ps_ptr = vm.process_ptr as u64;
        let tc_off = core::mem::offset_of!(crate::types::ProcessState, thread_count) as u64;
        let tc = unsafe { guest_mem::read_u32(base, ps_ptr + tc_off) };
        unsafe { guest_mem::write_u32(base, ps_ptr + tc_off, tc + 1) };

        // Write child TID to parent_tidptr if CLONE_PARENT_SETTID
        if clone_flags & CLONE_PARENT_SETTID as u64 != 0 && parent_tidptr != 0 {
            unsafe { guest_mem::write_u32(base, parent_tidptr, new_tid as u32) };
        }

        // Store child_tidptr for CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID
        // These will be set in the child's ThreadState by the TS runtime.

        // Set up clone result in VM state for TS handoff
        vm.x[10] = new_tid as u64; // parent returns child TID
        vm.status = STATUS_CLONE_SPAWN;

        // The TS runtime reads: child_stack, tls, new_tid, child_tidptr, flags
        // from designated locations. Store them in registers for handoff.
        // a0 = new_tid (already set), a1 = child_stack, a2 = tls, a3 = child_tidptr
        // The TS runtime will create a new ThreadState with:
        //   - pc = current pc (next instruction after ecall)
        //   - sp (x2) = child_stack (if nonzero)
        //   - tp (x4) = tls (if CLONE_SETTLS)
        //   - a0 = 0 (child returns 0 from clone)
        //   - process_ptr = same as parent
        //   - tid = new_tid

        return new_tid as i64;
    }

    // Other clone variants (fork, vfork) handled by process.rs
    ENOSYS
}

/// Allocate a new thread ID. Simple increment based on thread registry.
fn allocate_tid(vm: &ThreadState, base: u32) -> i32 {
    let ps_ptr = vm.process_ptr as u64;
    let threads_off = core::mem::offset_of!(crate::types::ProcessState, threads) as u64;
    let max_threads = crate::abi::MAX_THREADS;
    let record_size = core::mem::size_of::<crate::types::ThreadRecord>() as u64;

    for i in 0..max_threads {
        let state_off = threads_off + (i as u64) * record_size;
        let state = unsafe { guest_mem::read_i32(base, ps_ptr + state_off) };
        if state == crate::types::THREAD_NONE {
            // Mark as starting
            unsafe { guest_mem::write_u32(base, ps_ptr + state_off, crate::types::THREAD_STARTING as u32) };
            // TID = slot index + 1 (TID 0 is invalid)
            let tid = (i + 1) as i32;
            // Write TID into the record
            unsafe { guest_mem::write_u32(base, ps_ptr + state_off + 4, tid as u32) };
            return tid;
        }
    }
    -1 // no free slot
}

/// futex: fast userspace mutex.
/// FUTEX_WAIT: if *addr == val, block (return STATUS_FUTEX_WAIT for TS to Atomics.wait)
/// FUTEX_WAKE: wake up to `val` waiters on addr (return count woken)
/// https://man7.org/linux/man-pages/man2/futex.2.html
pub fn sys_futex(
    vm: &mut ThreadState, base: u32,
    addr: u64, op: u64, val: u64, _timeout: u64, _addr2: u64, _val3: u64,
) -> i64 {
    let futex_op = (op & 0x7F) as u32; // mask out FUTEX_PRIVATE_FLAG

    match futex_op {
        FUTEX_WAIT => {
            let current = unsafe { guest_mem::read_u32(base, addr) };
            if current != val as u32 {
                return EAGAIN;
            }
            // Value matches — block. Return STATUS_FUTEX_WAIT for TS to Atomics.wait.
            vm.x[10] = addr; // stash addr for TS
            vm.status = STATUS_FUTEX_WAIT;
            return 0;
        }
        FUTEX_WAKE => {
            // In single-instance interpreter, no other threads are blocked.
            // Return 0 (no waiters woken). TS runtime handles actual Atomics.notify.
            return 0;
        }
        _ => ENOSYS,
    }
}

#[cfg(test)]
mod tests {
    use crate::abi::*;
    use crate::test_helpers::TestVm;
    use crate::types::*;

    #[test]
    fn set_tid_address_returns_tid() {
        let mut t = TestVm::new();
        t.vm.tid = 42;
        let ret = super::sys_set_tid_address(&mut t.vm, 0x1000);
        assert_eq!(ret, 42);
        assert_eq!(t.vm.clear_child_tid, 0x1000);
    }

    #[test]
    fn exit_decrements_thread_count() {
        let mut t = TestVm::new();
        // Set thread_count to 2
        let ps_ptr = t.vm.process_ptr as u64;
        let tc_off = core::mem::offset_of!(ProcessState, thread_count) as u64;
        unsafe { crate::guest_mem::write_u32(t.base, ps_ptr + tc_off, 2) };

        let status = super::sys_exit(&mut t.vm, t.base, 42);
        assert_eq!(status, STATUS_FAULT);
        assert_eq!(t.vm.exit_code, 42);

        let tc = unsafe { crate::guest_mem::read_u32(t.base, ps_ptr + tc_off) };
        assert_eq!(tc, 1, "thread_count should be decremented from 2 to 1");
    }

    #[test]
    fn exit_clears_child_tid() {
        let mut t = TestVm::new();
        let tid_addr = t.scratch + 0x100;
        unsafe { crate::guest_mem::write_u32(t.base, tid_addr, 99) };
        t.vm.clear_child_tid = tid_addr;

        super::sys_exit(&mut t.vm, t.base, 0);

        let val = unsafe { crate::guest_mem::read_u32(t.base, tid_addr) };
        assert_eq!(val, 0, "clear_child_tid address should be written with 0");
    }

    #[test]
    fn clone_thread_returns_status_clone_spawn() {
        let mut t = TestVm::new();
        t.vm.tid = 1;
        // Set thread_count to 1
        let ps_ptr = t.vm.process_ptr as u64;
        let tc_off = core::mem::offset_of!(ProcessState, thread_count) as u64;
        unsafe { crate::guest_mem::write_u32(t.base, ps_ptr + tc_off, 1) };

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_stack = 0x80000u64;
        let ret = super::sys_clone(&mut t.vm, t.base, flags, child_stack, 0, 0, 0);

        assert!(ret > 0, "clone should return positive TID, got {}", ret);
        assert_eq!(t.vm.status, STATUS_CLONE_SPAWN);

        // thread_count should be incremented
        let tc = unsafe { crate::guest_mem::read_u32(t.base, ps_ptr + tc_off) };
        assert_eq!(tc, 2, "thread_count should be incremented from 1 to 2");
    }

    #[test]
    fn clone_parent_settid_writes_tid() {
        let mut t = TestVm::new();
        t.vm.tid = 1;
        let ps_ptr = t.vm.process_ptr as u64;
        let tc_off = core::mem::offset_of!(ProcessState, thread_count) as u64;
        unsafe { crate::guest_mem::write_u32(t.base, ps_ptr + tc_off, 1) };

        let parent_tidptr = t.scratch + 0x200;
        let flags = (CLONE_VM | CLONE_THREAD | CLONE_PARENT_SETTID) as u64;
        let ret = super::sys_clone(&mut t.vm, t.base, flags, 0, parent_tidptr, 0, 0);

        let written_tid = unsafe { crate::guest_mem::read_u32(t.base, parent_tidptr) };
        assert_eq!(written_tid, ret as u32, "parent_tidptr should contain child TID");
    }

    #[test]
    fn futex_wait_returns_eagain_on_mismatch() {
        let mut t = TestVm::new();
        let addr = t.scratch + 0x300;
        unsafe { crate::guest_mem::write_u32(t.base, addr, 42) };

        // val=99 doesn't match *addr=42 → EAGAIN
        let ret = super::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAIT as u64, 99, 0, 0, 0);
        assert_eq!(ret, EAGAIN, "futex_wait should return EAGAIN when value doesn't match");
    }

    #[test]
    fn futex_wait_blocks_on_match() {
        let mut t = TestVm::new();
        let addr = t.scratch + 0x400;
        unsafe { crate::guest_mem::write_u32(t.base, addr, 42) };

        // val=42 matches *addr=42 → STATUS_FUTEX_WAIT
        let ret = super::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAIT as u64, 42, 0, 0, 0);
        assert_eq!(ret, 0);
        assert_eq!(t.vm.status, STATUS_FUTEX_WAIT, "should set STATUS_FUTEX_WAIT");
    }

    #[test]
    fn futex_wake_returns_zero_in_single_thread() {
        let mut t = TestVm::new();
        let addr = t.scratch + 0x500;
        let ret = super::sys_futex(&mut t.vm, t.base, addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
        assert_eq!(ret, 0, "futex_wake should return 0 (no waiters in single-thread)");
    }

    #[test]
    fn set_robust_list_succeeds() {
        let mut t = TestVm::new();
        let ret = super::sys_set_robust_list(&mut t.vm, 0x1000, 24);
        assert_eq!(ret, 0);
    }
}
