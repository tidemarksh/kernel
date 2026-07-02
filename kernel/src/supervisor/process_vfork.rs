use crate::abi::*;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::supervisor::process_lifecycle::{
    alloc_pid_avoiding_live_threads, current_process_state_mut, ensure_current_process,
    inherit_process, record_child,
};
use crate::syscall::memory::AddressSpaceStateImage;
use crate::syscall::process::execve;
use crate::syscall::process::handoff::clear_spawn_handoff;
use crate::syscall::process::runtime::{
    capture_thread_snapshot, clear_vfork_proc_self_exe_snapshot, clear_vfork_runtime_snapshot, prs,
    restore_thread_snapshot, store_vfork_proc_self_exe_snapshot, vfork_proc_self_exe_snapshot,
};
use crate::types::{ProcessState, THREAD_NONE, THREAD_RUNNING, ThreadRecord, ThreadState};
use core::sync::atomic::Ordering;

const VFORK_EXECVE_HANDOFF_FAILURE_WAIT_STATUS: i32 = 127 << 8;

static mut VFORK_ADDRESS_SPACE_SNAPSHOT: Option<AddressSpaceStateImage> = None;

fn store_vfork_address_space_snapshot(snapshot: AddressSpaceStateImage) {
    unsafe {
        let slot = core::ptr::addr_of_mut!(VFORK_ADDRESS_SPACE_SNAPSHOT);
        if let Some(old) = (*slot).take() {
            drop(old);
        }
        *slot = Some(snapshot);
    }
}

fn restore_vfork_address_space_snapshot() {
    unsafe {
        let slot = core::ptr::addr_of_mut!(VFORK_ADDRESS_SPACE_SNAPSHOT);
        if let Some(snapshot) = (*slot).take() {
            crate::syscall::memory::restore_state_from_image(&snapshot);
        }
    }
}

fn clear_vfork_address_space_snapshot() {
    unsafe {
        let slot = core::ptr::addr_of_mut!(VFORK_ADDRESS_SPACE_SNAPSHOT);
        if let Some(snapshot) = (*slot).take() {
            drop(snapshot);
        }
    }
}

pub(crate) fn reattach_guest_thread_count(vm: &mut ThreadState, base: u32) {
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

fn detach_parent_thread_for_vfork(base: u32, process_ptr: u32, tid: i32) {
    if process_ptr == 0 || tid <= 0 || tid as usize > MAX_THREADS {
        return;
    }
    let ps = unsafe { &mut *((base as u64 + process_ptr as u64) as *mut ProcessState) };
    let record = &mut ps.threads[(tid - 1) as usize];
    if record.thread_ptr == 0 && record.state == THREAD_NONE {
        return;
    }
    *record = ThreadRecord::empty();
    ps.thread_count
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            Some(count.saturating_sub(1))
        })
        .ok();
}

fn restore_parent_thread_after_vfork(vm: &ThreadState, base: u32) {
    if vm.process_ptr == 0 || vm.tid <= 0 || vm.tid as usize > MAX_THREADS {
        return;
    }
    let ps = unsafe { &mut *((base as u64 + vm.process_ptr as u64) as *mut ProcessState) };
    let record = &mut ps.threads[(vm.tid - 1) as usize];
    let needs_count_restore = record.thread_ptr == 0 || record.state == THREAD_NONE;
    *record = ThreadRecord::new(
        vm.tid,
        THREAD_RUNNING,
        vm as *const ThreadState as u32,
        vm.clear_child_tid,
        0,
    );
    if needs_count_restore {
        ps.thread_count.fetch_add(1, Ordering::AcqRel);
    }
}

fn retain_process_ofds(base: u32, process_ptr: u32) {
    let ps = unsafe { &*((base as u64 + process_ptr as u64) as *const ProcessState) };
    for entry in ps.fd_table.iter() {
        if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS {
            continue;
        }
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
    let hidden_end = child_ps_addr + ps_size;
    let public_brk = crate::syscall::memory::user_brk_start_after_hidden_prefix(hidden_end);
    if crate::syscall::memory::grow_brk(base, public_brk) < public_brk as i64 {
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
    if child_pid > 0 && child_pid as usize <= MAX_THREADS {
        child_ps.threads[(child_pid - 1) as usize] = ThreadRecord::new(
            child_pid,
            THREAD_RUNNING,
            vm as *const ThreadState as u32,
            0,
            0,
        );
    }

    retain_process_ofds(base, child_ps_addr as u32);
    Some(child_ps_addr as u32)
}

fn retire_vfork_child_process(base: u32, child_process_ptr: u32) {
    if child_process_ptr == 0 {
        return;
    }

    let absolute = base as u64 + child_process_ptr as u64;
    unsafe {
        core::ptr::write_bytes(absolute as *mut u8, 0, core::mem::size_of::<ProcessState>());
    }
}

fn sys_vfork_inner(
    vm: &mut ThreadState,
    base: u32,
    flags: u64,
    child_stack: u64,
    parent_tidptr: u64,
    tls: u64,
    child_tidptr: u64,
) -> i32 {
    clear_spawn_handoff(vm);
    let parent_process_ptr = vm.process_ptr;
    let parent_tid = vm.tid;
    let parent_pid = ensure_current_process(vm, base)
        .map(|slot| slot.pid)
        .unwrap_or(0);
    let child_pid = if parent_pid > 0 {
        let pid = alloc_pid_avoiding_live_threads(vm, base);
        record_child(parent_pid, pid);
        inherit_process(parent_pid, parent_pid, pid, false);
        crate::syscall::signal::fork_from_parent(parent_pid, pid);
        crate::syscall::resource::fork_from_parent(parent_pid, pid);
        pid
    } else {
        0
    };
    let mut parent_address_space = AddressSpaceStateImage::empty();
    if child_pid > 0 {
        crate::syscall::memory::capture_state_image_into(&mut parent_address_space);
    }
    let child_process_ptr = if child_pid > 0 {
        match clone_process_state_for_vfork(vm, base, parent_pid, child_pid) {
            Some(ptr) => ptr,
            None => return STATUS_FAULT,
        }
    } else {
        vm.process_ptr
    };
    if flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 && child_pid > 0 {
        unsafe { guest_mem::write_u32(base, parent_tidptr, child_pid as u32) };
    }
    let mut proc_self_exe_target = [0u8; execve::PROC_SELF_EXE_SNAPSHOT_MAX];
    let proc_self_exe_len = execve::snapshot_proc_self_exe_target(&mut proc_self_exe_target);
    if proc_self_exe_len == 0 {
        clear_vfork_proc_self_exe_snapshot();
    } else {
        store_vfork_proc_self_exe_snapshot(&proc_self_exe_target[..proc_self_exe_len]);
    }
    prs().vfork_snapshot = capture_thread_snapshot(vm, child_pid);
    prs().vfork_active = 1;
    if child_pid > 0 {
        store_vfork_address_space_snapshot(parent_address_space);
    }
    detach_parent_thread_for_vfork(base, parent_process_ptr, parent_tid);
    vm.sig_pending = 0;
    vm.tid = child_pid;
    vm.process_ptr = child_process_ptr;
    vm.clone_flags = flags;
    vm.clone_child_stack = child_stack;
    vm.clone_tls = tls;
    vm.clone_child_tidptr = child_tidptr;
    vm.clone_child_tid = child_pid;
    vm.clone_pending = 0;
    if child_stack != 0 {
        vm.x[2] = child_stack;
    }
    if flags & CLONE_SETTLS != 0 {
        vm.x[4] = tls;
        vm.tls_base = tls;
    }
    if flags & CLONE_CHILD_CLEARTID != 0 {
        vm.clear_child_tid = child_tidptr;
    } else {
        vm.clear_child_tid = 0;
    }
    if flags & CLONE_CHILD_SETTID != 0 && child_tidptr != 0 && child_pid > 0 {
        unsafe { guest_mem::write_u32(base, child_tidptr, child_pid as u32) };
    }
    reattach_guest_thread_count(vm, base);
    vm.x[10] = 0;
    vm.status = STATUS_VFORK_WAIT;
    STATUS_VFORK_WAIT
}

pub fn sys_vfork(vm: &mut ThreadState, base: u32) -> i32 {
    sys_vfork_inner(vm, base, 0, 0, 0, 0, 0)
}

pub fn sys_clone_vfork(
    vm: &mut ThreadState,
    base: u32,
    flags: u64,
    child_stack: u64,
    parent_tidptr: u64,
    tls: u64,
    child_tidptr: u64,
) -> i32 {
    sys_vfork_inner(
        vm,
        base,
        flags,
        child_stack,
        parent_tidptr,
        tls,
        child_tidptr,
    )
}

fn vfork_parent_resume_inner(vm: &mut ThreadState, child_pid: i32, cleanup_child_fds: bool) {
    if prs().vfork_active == 0 {
        return;
    }
    let snap = prs().vfork_snapshot;
    prs().vfork_active = 0;
    let child_process_ptr = if vm.process_ptr != 0 && vm.process_ptr != snap.process_ptr {
        vm.process_ptr
    } else {
        0
    };
    if cleanup_child_fds && child_process_ptr != 0 {
        crate::fs::fd_table::close_all_for_process(vm.guest_base, vm);
    }
    restore_thread_snapshot(vm, snap);
    let proc_self_exe = vfork_proc_self_exe_snapshot();
    execve::restore_proc_self_exe_target((!proc_self_exe.is_empty()).then_some(proc_self_exe));
    clear_vfork_proc_self_exe_snapshot();
    if child_process_ptr != 0 {
        retire_vfork_child_process(vm.guest_base, child_process_ptr);
    }
    restore_vfork_address_space_snapshot();
    restore_parent_thread_after_vfork(vm, vm.guest_base);
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

pub fn vfork_restore_parent_proc_self_exe_snapshot() {
    if prs().vfork_active == 0 {
        return;
    }
    let proc_self_exe = vfork_proc_self_exe_snapshot();
    execve::restore_proc_self_exe_target((!proc_self_exe.is_empty()).then_some(proc_self_exe));
}

pub fn clear_vfork_runtime_state() {
    clear_vfork_runtime_snapshot();
    clear_vfork_address_space_snapshot();
}

pub fn vfork_execve_handoff_failure_wait_status() -> i32 {
    VFORK_EXECVE_HANDOFF_FAILURE_WAIT_STATUS
}

pub fn rollback_execve_handoff(vm: &mut ThreadState, child_pid: i32) -> i32 {
    if child_pid <= 0 {
        return -(crate::abi::EINVAL as i32);
    }
    crate::supervisor::process_lifecycle::record_child_exit(
        child_pid,
        VFORK_EXECVE_HANDOFF_FAILURE_WAIT_STATUS,
    );
    vfork_parent_restore_without_cleanup(vm, child_pid);
    clear_vfork_runtime_state();
    VFORK_EXECVE_HANDOFF_FAILURE_WAIT_STATUS
}
