use super::handoff::clear_spawn_handoff;
use super::lifecycle::{
    alloc_pid, current_process_state_mut, ensure_current_process, inherit_process, record_child,
};
use super::runtime::{empty_vfork_snapshot, prs};
use crate::abi::*;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::{ProcessState, THREAD_RUNNING, ThreadRecord, ThreadState};

pub(super) fn reattach_guest_thread_count(vm: &mut ThreadState, base: u32) {
    if let Some(ps) = current_process_state_mut(vm, base) {
        let gen_ptr =
            core::ptr::addr_of!(ps.reservation_gen) as *const core::sync::atomic::AtomicU32;
        let lock_ptr =
            core::ptr::addr_of!(ps.reservation_lock) as *const core::sync::atomic::AtomicU32;
        let tc_ptr = core::ptr::addr_of!(ps.thread_count);
        unsafe {
            guest_mem::init(gen_ptr, lock_ptr, tc_ptr);
        }
    }
}

fn retain_process_ofds(base: u32, process_ptr: u32) {
    let ps = unsafe { &*((base as u64 + process_ptr as u64) as *const ProcessState) };
    let mut seen = [false; MAX_FDS];
    for entry in ps.fd_table.iter() {
        if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS || seen[entry.ofd_id as usize] {
            continue;
        }
        seen[entry.ofd_id as usize] = true;
        fd_table::retain_ofd_id(entry.ofd_id);
    }
}

fn clone_process_state_for_vfork(
    vm: &ThreadState,
    base: u32,
    parent_pid: i32,
    child_pid: i32,
) -> Option<u32> {
    let parent_ps_addr = vm.process_ptr as u64;
    if parent_ps_addr == 0 {
        return None;
    }

    let ps_size = core::mem::size_of::<ProcessState>() as u64;
    let ps_align = core::mem::align_of::<ProcessState>() as u64;
    let brk = crate::syscall::memory::current_brk();
    let child_ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
    if crate::syscall::memory::grow_brk(base, child_ps_addr + ps_size)
        < (child_ps_addr + ps_size) as i64
    {
        return None;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            (base as u64 + parent_ps_addr) as *const u8,
            (base as u64 + child_ps_addr) as *mut u8,
            ps_size as usize,
        );
    }

    let child_ps = unsafe { &mut *((base as u64 + child_ps_addr) as *mut ProcessState) };
    child_ps.pid = child_pid;
    child_ps.ppid = parent_pid;
    child_ps
        .thread_count
        .store(1, core::sync::atomic::Ordering::Release);
    for record in child_ps.threads.iter_mut() {
        *record = ThreadRecord::empty();
    }
    if vm.tid > 0 && vm.tid as usize <= MAX_THREADS {
        child_ps.threads[(vm.tid - 1) as usize] = ThreadRecord::new(
            vm.tid,
            THREAD_RUNNING,
            vm as *const ThreadState as u32,
            vm.clear_child_tid as u32,
            0,
        );
    }

    retain_process_ofds(base, child_ps_addr as u32);
    Some(child_ps_addr as u32)
}

pub fn sys_vfork(vm: &mut ThreadState, base: u32) -> i32 {
    clear_spawn_handoff(vm);
    let parent_pid = ensure_current_process(vm, base)
        .map(|slot| slot.pid)
        .unwrap_or(0);
    let child_pid = if parent_pid > 0 {
        let pid = alloc_pid();
        record_child(parent_pid, pid);
        inherit_process(parent_pid, parent_pid, pid, false);
        crate::syscall::signal::fork_from_parent(parent_pid, pid);
        crate::syscall::resource::fork_from_parent(parent_pid, pid);
        pid
    } else {
        0
    };
    let child_process_ptr = if child_pid > 0 {
        match clone_process_state_for_vfork(vm, base, parent_pid, child_pid) {
            Some(ptr) => ptr,
            None => return STATUS_FAULT,
        }
    } else {
        vm.process_ptr
    };
    prs().vfork_snapshot = super::runtime::VforkSnapshot {
        x: vm.x,
        pc: vm.pc,
        f: vm.f,
        fcsr: vm.fcsr,
        status: vm.status,
        exit_code: vm.exit_code,
        term_signal: vm.term_signal,
        tid: vm.tid,
        uid: vm.uid,
        euid: vm.euid,
        gid: vm.gid,
        egid: vm.egid,
        tls_base: vm.tls_base,
        clear_child_tid: vm.clear_child_tid,
        robust_list_head: vm.robust_list_head,
        robust_list_len: vm.robust_list_len,
        sig_mask: vm.sig_mask,
        sig_pending: vm.sig_pending,
        sig_info_code: vm.sig_info_code,
        sigaltstack_sp: vm.sigaltstack_sp,
        sigaltstack_size: vm.sigaltstack_size,
        sigaltstack_flags: vm.sigaltstack_flags,
        lr_addr: vm.lr_addr,
        lr_val: vm.lr_val,
        lr_gen: vm.lr_gen,
        lr_gen_end: vm.lr_gen_end,
        insn_budget: vm.insn_budget,
        fault_pc: vm.fault_pc,
        fault_addr: vm.fault_addr,
        guest_base: vm.guest_base,
        guest_ram_limit: vm.guest_ram_limit,
        process_ptr: vm.process_ptr,
        clone_flags: vm.clone_flags,
        clone_child_stack: vm.clone_child_stack,
        clone_tls: vm.clone_tls,
        clone_child_tidptr: vm.clone_child_tidptr,
        clone_child_tid: vm.clone_child_tid,
        clone_pending: vm.clone_pending,
        spawn_kind: vm.spawn_kind,
        spawn_ram_size: vm.spawn_ram_size,
        spawn_child_pid: vm.spawn_child_pid,
        spawn_path: vm.spawn_path,
        spawn_argv: vm.spawn_argv,
        spawn_envp: vm.spawn_envp,
        wait_pid: vm.wait_pid,
        wait_kind: vm.wait_kind,
        wait_idtype: vm.wait_idtype,
        wait_wstatus_addr: vm.wait_wstatus_addr,
        wait_options: vm.wait_options,
        wait_rusage_addr: vm.wait_rusage_addr,
        futex_wait_addr: vm.futex_wait_addr,
        futex_wait_timeout: vm.futex_wait_timeout,
        futex_wait_expected: vm.futex_wait_expected,
        futex_wait_bitset: vm.futex_wait_bitset,
        futex_wait_absolute: vm.futex_wait_absolute,
        futex_wait_flags: vm.futex_wait_flags,
        epoll_timeout_ms: vm.epoll_timeout_ms,
        socket_timeout_ms: vm.socket_timeout_ms,
        epoll_maxevents: vm.epoll_maxevents,
        blocked_fd: vm.blocked_fd,
        blocked_ofd_id: vm.blocked_ofd_id,
        child_pid,
    };
    prs().vfork_active = 1;
    vm.sig_pending = 0;
    vm.process_ptr = child_process_ptr;
    reattach_guest_thread_count(vm, base);
    vm.x[10] = 0;
    vm.status = STATUS_VFORK_WAIT;
    STATUS_VFORK_WAIT
}

fn vfork_parent_resume_inner(vm: &mut ThreadState, child_pid: i32, cleanup_child_fds: bool) {
    if prs().vfork_active == 0 {
        return;
    }
    let snap = prs().vfork_snapshot;
    prs().vfork_active = 0;
    if cleanup_child_fds && vm.process_ptr != 0 && vm.process_ptr != snap.process_ptr {
        crate::fs::fd_table::close_all_for_process(vm.guest_base, vm);
    }
    vm.x = snap.x;
    vm.pc = snap.pc;
    vm.f = snap.f;
    vm.fcsr = snap.fcsr;
    vm.status = snap.status;
    vm.exit_code = snap.exit_code;
    vm.term_signal = snap.term_signal;
    vm.tid = snap.tid;
    vm.uid = snap.uid;
    vm.euid = snap.euid;
    vm.gid = snap.gid;
    vm.egid = snap.egid;
    vm.tls_base = snap.tls_base;
    vm.clear_child_tid = snap.clear_child_tid;
    vm.robust_list_head = snap.robust_list_head;
    vm.robust_list_len = snap.robust_list_len;
    vm.sig_mask = snap.sig_mask;
    vm.sig_pending = snap.sig_pending;
    vm.sig_info_code = snap.sig_info_code;
    vm.sigaltstack_sp = snap.sigaltstack_sp;
    vm.sigaltstack_size = snap.sigaltstack_size;
    vm.sigaltstack_flags = snap.sigaltstack_flags;
    vm.lr_addr = snap.lr_addr;
    vm.lr_val = snap.lr_val;
    vm.lr_gen = snap.lr_gen;
    vm.lr_gen_end = snap.lr_gen_end;
    vm.insn_budget = snap.insn_budget;
    vm.fault_pc = snap.fault_pc;
    vm.fault_addr = snap.fault_addr;
    vm.guest_base = snap.guest_base;
    vm.guest_ram_limit = snap.guest_ram_limit;
    vm.process_ptr = snap.process_ptr;
    vm.clone_flags = snap.clone_flags;
    vm.clone_child_stack = snap.clone_child_stack;
    vm.clone_tls = snap.clone_tls;
    vm.clone_child_tidptr = snap.clone_child_tidptr;
    vm.clone_child_tid = snap.clone_child_tid;
    vm.clone_pending = snap.clone_pending;
    vm.spawn_kind = snap.spawn_kind;
    vm.spawn_ram_size = snap.spawn_ram_size;
    vm.spawn_child_pid = snap.spawn_child_pid;
    vm.spawn_path = snap.spawn_path;
    vm.spawn_argv = snap.spawn_argv;
    vm.spawn_envp = snap.spawn_envp;
    vm.wait_pid = snap.wait_pid;
    vm.wait_kind = snap.wait_kind;
    vm.wait_idtype = snap.wait_idtype;
    vm.wait_wstatus_addr = snap.wait_wstatus_addr;
    vm.wait_options = snap.wait_options;
    vm.wait_rusage_addr = snap.wait_rusage_addr;
    vm.futex_wait_addr = snap.futex_wait_addr;
    vm.futex_wait_timeout = snap.futex_wait_timeout;
    vm.futex_wait_expected = snap.futex_wait_expected;
    vm.futex_wait_bitset = snap.futex_wait_bitset;
    vm.futex_wait_absolute = snap.futex_wait_absolute;
    vm.futex_wait_flags = snap.futex_wait_flags;
    vm.epoll_timeout_ms = snap.epoll_timeout_ms;
    vm.socket_timeout_ms = snap.socket_timeout_ms;
    vm.epoll_maxevents = snap.epoll_maxevents;
    vm.blocked_fd = snap.blocked_fd;
    vm.blocked_ofd_id = snap.blocked_ofd_id;
    reattach_guest_thread_count(vm, vm.guest_base);
    vm.x[10] = child_pid as u64;
    clear_spawn_handoff(vm);
    vm.status = STATUS_OK;
}

pub fn vfork_parent_resume(vm: &mut ThreadState, child_pid: i32) {
    vfork_parent_resume_inner(vm, child_pid, true);
}

pub fn vfork_parent_restore_without_cleanup(vm: &mut ThreadState, child_pid: i32) {
    if prs().vfork_active == 0 {
        return;
    }
    let snap = prs().vfork_snapshot;
    if vm.process_ptr != 0 && vm.process_ptr != snap.process_ptr {
        crate::fs::fd_table::close_all_for_process_without_backend_cleanup(vm.guest_base, vm);
    }
    vfork_parent_resume_inner(vm, child_pid, false);
}

pub fn clear_vfork_runtime_state() {
    prs().vfork_active = 0;
    prs().vfork_snapshot = empty_vfork_snapshot();
}
