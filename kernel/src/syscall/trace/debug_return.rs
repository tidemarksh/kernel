use crate::abi;
use crate::abi::*;
use crate::fs::fd_table;
use crate::types::ThreadState;

#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(in crate::syscall) fn debug_return(
    vm: &mut ThreadState,
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    result: i64,
    status: i32,
) -> i32 {
    debug_return_with_fd_trace(vm, nr, a0, a1, a2, a3, a4, a5, result, status, 0, 0, 0, 0)
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(in crate::syscall) fn debug_return_fd_arg0(
    vm: &mut ThreadState,
    base: u32,
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    result: i64,
    status: i32,
) -> i32 {
    let (arg0_ofd_id, arg0_ofd_type) = super::fd::snapshot(base, vm, a0);
    debug_return_with_fd_trace(
        vm,
        nr,
        a0,
        a1,
        a2,
        a3,
        a4,
        a5,
        result,
        status,
        arg0_ofd_id,
        arg0_ofd_type,
        0,
        0,
    )
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn debug_return_with_fd_trace(
    vm: &mut ThreadState,
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    result: i64,
    status: i32,
    _arg0_ofd_id: u32,
    _arg0_ofd_type: i32,
    _arg2_ofd_id: u32,
    _arg2_ofd_type: i32,
) -> i32 {
    if nr != SYS_RT_SIGRETURN {
        vm.x[10] = result as u64;
    }
    crate::tracepoints::record_syscall(
        vm as *const ThreadState as u32,
        nr,
        a0,
        a1,
        a2,
        a3,
        a4,
        a5,
        result,
        status,
    );
    #[cfg(not(any(test, feature = "harness")))]
    super::fd::record(
        vm as *const ThreadState as u32,
        nr,
        a0,
        _arg0_ofd_id,
        _arg0_ofd_type,
        a1,
        a2,
        _arg2_ofd_id,
        _arg2_ofd_type,
        a3,
        result,
        status,
    );
    if fd_table::blocked_status_uses_ofd_pin(status) {
        save_blocked_syscall_args(vm, nr, a0, a1, a2, a3, a4, a5);
    } else if status == abi::STATUS_OK {
        fd_table::clear_blocked_ofd_pin(vm);
    } else {
        fd_table::clear_blocked_ofd_pin(vm);
    }
    status
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(in crate::syscall) fn save_blocked_syscall_args(
    vm: &mut ThreadState,
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) {
    vm.blocked_syscall_nr = nr;
    vm.blocked_syscall_args = [a0, a1, a2, a3, a4, a5];
}
