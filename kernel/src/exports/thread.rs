use crate::abi::*;
use crate::types::{ProcessState, ThreadState};

#[unsafe(no_mangle)]
pub extern "C" fn thread_step(vm_ptr: u32, budget: i32) -> i32 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        let base = vm.guest_base;
        crate::tracepoints::record_thread_step_entry_trace(vm, budget);
        crate::tracepoints::record_thread_step_phase(vm, 1, budget, 0);
        if vm.process_ptr != 0 {
            let ps = &*((base as u64 + vm.process_ptr as u64) as *const ProcessState);
            let gen_ptr =
                core::ptr::addr_of!(ps.reservation_gen) as *const core::sync::atomic::AtomicU32;
            let lock_ptr =
                core::ptr::addr_of!(ps.reservation_lock) as *const core::sync::atomic::AtomicU32;
            let tc_ptr = core::ptr::addr_of!(ps.thread_count);
            crate::guest_mem::init(gen_ptr, lock_ptr, tc_ptr);
        }
        crate::tracepoints::record_thread_step_phase(vm, 2, budget, 0);
        if !crate::syscall::thread::thread_may_step(vm, base) {
            crate::tracepoints::record_thread_step_phase(vm, 3, budget, budget);
            crate::tracepoints::record_thread_step_trace(vm, budget, budget);
            crate::tracepoints::record_thread_step_phase(vm, 5, budget, budget);
            return budget;
        }
        vm.status = STATUS_OK;
        crate::tracepoints::record_thread_step_phase(vm, 3, budget, 0);
        let remaining = crate::cpu::exec(vm, budget, None, None, None, None);
        crate::tracepoints::record_thread_step_phase(vm, 4, budget, remaining);
        crate::tracepoints::record_thread_step_trace(vm, budget, remaining);
        crate::tracepoints::record_thread_step_phase(vm, 5, budget, remaining);
        remaining
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_status(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const ThreadState)).status }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_exit_code(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const ThreadState)).exit_code }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_term_signal(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const ThreadState)).term_signal }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pc(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).pc }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_sig_pending(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).sig_pending }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_sp(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[2] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a0(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[10] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a1(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[11] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a2(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[12] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a3(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[13] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a4(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[14] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a5(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[15] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a6(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[16] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_a7(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).x[17] }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_blocked_fd(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).blocked_fd }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_blocked_ofd_id(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).blocked_ofd_id }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_from_clone(parent_vm_ptr: u32) -> u32 {
    unsafe {
        let parent = &*(parent_vm_ptr as *const ThreadState);
        crate::syscall::thread::spawn_from_clone(parent_vm_ptr, parent.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_process_thread_count(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::thread::process_thread_count(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_guest_base(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).guest_base }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_process_ptr(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).process_ptr }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_effects(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::fs::pending_request_effects(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_target_ino(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::fs::pending_request_target_ino(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_opcode(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::fs::pending_request_opcode(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_path_ptr(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::fs::pending_request_path_ptr(vm_ptr, vm.guest_base) as u32
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_path_len(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::fs::pending_request_path_len(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_absolute_path(vm_ptr: u32, buf_ptr: u32, buf_len: u32) -> i64 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::fs::pending_request_absolute_path(vm_ptr, vm.guest_base, buf_ptr, buf_len)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_pending_fs_secondary_absolute_path(
    vm_ptr: u32,
    buf_ptr: u32,
    buf_len: u32,
) -> i64 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::fs::pending_request_secondary_absolute_path(
            vm_ptr,
            vm.guest_base,
            buf_ptr,
            buf_len,
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_process_fs(vm_ptr: u32) {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::fs::process_pending_requests(vm_ptr, vm.guest_base);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_fs(vm_ptr: u32) -> i64 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::fs::resume_from_fs(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_wait4(vm_ptr: u32) -> i64 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::process::resume_wait4(vm_ptr, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_epoll_wait_timeout(vm_ptr: u32) -> i64 {
    unsafe { (*(vm_ptr as *const ThreadState)).epoll_timeout_ms }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_socket_wait_timeout(vm_ptr: u32) -> i64 {
    unsafe { (*(vm_ptr as *const ThreadState)).socket_timeout_ms }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_epoll_wait_timeout(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::syscall::epoll::resume_timeout(vm);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_socket_wait_timeout(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        if vm.x[17] == SYS_CONNECT {
            crate::syscall::socket::resume_connect_result(vm, vm.guest_base, ETIMEDOUT);
        } else {
            crate::fs::fd_table::clear_blocked_ofd_pin(vm);
            vm.socket_timeout_ms = -1;
            vm.fault_pc = 0;
            vm.fault_addr = 0;
            vm.x[10] = EAGAIN as u64;
            vm.status = STATUS_OK;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_interrupt_epoll_wait(vm_ptr: u32, errno: i32) -> i32 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::fs::fd_table::clear_blocked_ofd_pin(vm);
        vm.epoll_timeout_ms = 0;
        vm.epoll_maxevents = 0;
        vm.fault_pc = 0;
        vm.fault_addr = 0;
        crate::syscall::signal::patch_current_signal_frame_a0(vm, vm.guest_base, errno as i64)
            as i32
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_blocked_syscall(vm_ptr: u32) -> i64 {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        let saved_fd_entry =
            crate::fs::fd_table::patch_blocked_fd_entry_for_resume(vm.guest_base, vm);
        let status = if vm.status == STATUS_EPOLL_WAIT {
            crate::syscall::epoll::resume_wait(vm, vm.guest_base);
            vm.status
        } else {
            vm.status = STATUS_OK;
            crate::syscall::dispatch(vm, vm.guest_base)
        };
        crate::fs::fd_table::restore_blocked_fd_entry(vm.guest_base, vm, saved_fd_entry);
        vm.status = status;
        if !crate::fs::fd_table::blocked_status_uses_ofd_pin(status) {
            crate::fs::fd_table::clear_blocked_ofd_pin(vm);
        }
        if status == STATUS_OK {
            vm.x[10] as i64
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_sleep(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        vm.fault_addr = 0;
        vm.fault_pc = 0;
        vm.status = STATUS_OK;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_connect_result(vm_ptr: u32, result: i64) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::syscall::socket::resume_connect_result(vm, vm.guest_base, result);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_kind(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).spawn_kind }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_guest_ram_limit(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).guest_ram_limit }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_set_guest_ram_limit(vm_ptr: u32, ram_size: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        vm.guest_ram_limit = ram_size;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_clone_flags(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).clone_flags }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_clone_child_stack(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).clone_child_stack }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_clone_tls(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).clone_tls }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_clone_child_tidptr(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).clone_child_tidptr }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_child_pid(vm_ptr: u32) -> i32 {
    unsafe { (*(vm_ptr as *const ThreadState)).spawn_child_pid }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_path(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).spawn_path }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_argv(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).spawn_argv }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_envp(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).spawn_envp }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_spawn_ram_size(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).spawn_ram_size }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_set_execve_handoff(
    vm_ptr: u32,
    process_ptr: u32,
    path_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
    ram_size: u32,
) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        vm.process_ptr = process_ptr;
        vm.spawn_kind = SPAWN_KIND_EXECVE;
        vm.spawn_ram_size = ram_size;
        vm.spawn_path = path_addr;
        vm.spawn_argv = argv_addr;
        vm.spawn_envp = envp_addr;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_clear_spawn_handoff(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        vm.spawn_kind = SPAWN_KIND_NONE;
        vm.spawn_ram_size = 0;
        vm.spawn_child_pid = 0;
        vm.spawn_path = 0;
        vm.spawn_argv = 0;
        vm.spawn_envp = 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_vfork_parent(vm_ptr: u32, child_pid: i32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::syscall::process::vfork_parent_resume(vm, child_pid);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_restore_vfork_parent_without_cleanup(vm_ptr: u32, child_pid: i32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::syscall::process::vfork_parent_restore_without_cleanup(vm, child_pid);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_complete_execve_handoff(vm_ptr: u32) -> i64 {
    unsafe {
        crate::syscall::process::clear_vfork_runtime_state();
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::syscall::process::complete_execve_in_place_from_handoff(
            vm,
            vm.guest_base,
            if vm.spawn_ram_size != 0 {
                vm.spawn_ram_size as u64
            } else {
                crate::syscall::process::max_execve_ram_limit(vm.guest_base)
            },
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_prepare_fork_child(vm_ptr: u32, pid: i32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::syscall::process::prepare_fork_child_after_handoff(vm, vm.guest_base, pid);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_restore_fork_parent(
    vm_ptr: u32,
    process_ptr: u32,
    pid: i32,
    ppid: i32,
) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::syscall::process::restore_fork_parent_after_handoff(
            vm,
            vm.guest_base,
            process_ptr,
            pid,
            ppid,
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_futex_wait_addr(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).futex_wait_addr }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_futex_wait_timeout(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).futex_wait_timeout }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_futex_wait_expected(vm_ptr: u32) -> u32 {
    unsafe { (*(vm_ptr as *const ThreadState)).futex_wait_expected }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_futex_wait(vm_ptr: u32) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::syscall::thread::resume_futex_wait(vm, vm.guest_base);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_resume_futex_wait_result(vm_ptr: u32, result: i64) {
    unsafe {
        let vm = &mut *(vm_ptr as *mut ThreadState);
        crate::syscall::thread::resume_futex_wait_result(vm, vm.guest_base, result);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_sleep_seconds(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).fault_addr }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_sleep_nanoseconds(vm_ptr: u32) -> u64 {
    unsafe { (*(vm_ptr as *const ThreadState)).fault_pc }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_sleep_deadline_ticks(vm_ptr: u32) -> u64 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::time::sleep_deadline_ticks(vm.fault_addr, vm.fault_pc)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_record_blocked_addr(vm_ptr: u32) -> u32 {
    unsafe {
        let vm = &*(vm_ptr as *const ThreadState);
        crate::syscall::thread::thread_record_blocked_addr(vm, vm.guest_base)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn thread_vfork_child_pid() -> i32 {
    crate::syscall::process::vfork_child_pid()
}
