//! Resource limit syscalls: getrlimit, setrlimit, prlimit64.
//!
//! Linux UAPI reference:
//! - include/uapi/asm-generic/resource.h
//! - include/uapi/linux/resource.h

use crate::abi::*;
use crate::guest_mem;
use crate::types::{MAX_SIGNALS, ThreadState};

const RLIMIT_DATA: usize = 2;
const RLIMIT_STACK: usize = 3;
const RLIMIT_CORE: usize = 4;
const RLIMIT_NPROC: usize = 6;
const RLIMIT_NOFILE: usize = 7;
const RLIMIT_MEMLOCK: usize = 8;
const RLIMIT_AS: usize = 9;
const RLIMIT_SIGPENDING: usize = 11;
const RLIMIT_NLIMITS: usize = 16;
const RLIM64_INFINITY: u64 = !0u64;
const LINUX_DEFAULT_STACK_LIMIT: u64 = 8 * 1024 * 1024;
const LINUX_DEFAULT_MEMLOCK_LIMIT: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Rlimit64 {
    cur: u64,
    max: u64,
}

static mut RLIMIT_SLOTS_PTR: *mut [*mut [Rlimit64; RLIMIT_NLIMITS]; MAX_PROCESSES] =
    core::ptr::null_mut();

#[cfg(any(test, feature = "harness"))]
#[derive(Clone, Copy)]
pub(crate) struct ProcessResourceSnapshot {
    slots: [u32; MAX_PROCESSES],
}

#[cfg(any(test, feature = "harness"))]
impl ProcessResourceSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            slots: [0; MAX_PROCESSES],
        }
    }
}

fn default_limits() -> [Rlimit64; RLIMIT_NLIMITS] {
    let mut limits = [Rlimit64 {
        cur: RLIM64_INFINITY,
        max: RLIM64_INFINITY,
    }; RLIMIT_NLIMITS];
    limits[RLIMIT_STACK] = Rlimit64 {
        cur: LINUX_DEFAULT_STACK_LIMIT,
        max: RLIM64_INFINITY,
    };
    limits[RLIMIT_CORE] = Rlimit64 { cur: 0, max: 0 };
    limits[RLIMIT_NOFILE] = Rlimit64 {
        cur: MAX_FDS as u64,
        max: MAX_FDS as u64,
    };
    limits[RLIMIT_DATA] = Rlimit64 {
        cur: crate::syscall::process::EXECVE_RAM_LIMIT,
        max: crate::syscall::process::EXECVE_RAM_LIMIT,
    };
    limits[RLIMIT_AS] = Rlimit64 {
        cur: crate::syscall::process::EXECVE_RAM_LIMIT,
        max: crate::syscall::process::EXECVE_RAM_LIMIT,
    };
    limits[RLIMIT_NPROC] = Rlimit64 {
        cur: MAX_PROCESSES as u64,
        max: MAX_PROCESSES as u64,
    };
    limits[RLIMIT_MEMLOCK] = Rlimit64 {
        cur: LINUX_DEFAULT_MEMLOCK_LIMIT,
        max: LINUX_DEFAULT_MEMLOCK_LIMIT,
    };
    limits[RLIMIT_SIGPENDING] = Rlimit64 {
        cur: MAX_SIGNALS as u64,
        max: MAX_SIGNALS as u64,
    };
    limits
}

fn ensure_rlimit_slots() -> *mut [*mut [Rlimit64; RLIMIT_NLIMITS]; MAX_PROCESSES] {
    unsafe {
        let ptr = core::ptr::read(core::ptr::addr_of!(RLIMIT_SLOTS_PTR));
        if !ptr.is_null() {
            return ptr;
        }
        let size = core::mem::size_of::<[*mut [Rlimit64; RLIMIT_NLIMITS]; MAX_PROCESSES]>() as u32;
        let align = core::mem::align_of::<*mut [Rlimit64; RLIMIT_NLIMITS]>() as u32;
        let fresh = crate::alloc::alloc_zeroed(size, align);
        if fresh == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(RLIMIT_SLOTS_PTR),
            fresh as *mut [*mut [Rlimit64; RLIMIT_NLIMITS]; MAX_PROCESSES],
        );
        fresh as *mut [*mut [Rlimit64; RLIMIT_NLIMITS]; MAX_PROCESSES]
    }
}

fn rlimit_slots() -> &'static mut [*mut [Rlimit64; RLIMIT_NLIMITS]; MAX_PROCESSES] {
    unsafe { &mut *ensure_rlimit_slots() }
}

fn limits_for(pid: i32) -> Option<&'static mut [Rlimit64; RLIMIT_NLIMITS]> {
    if pid <= 0 {
        return None;
    }
    let index = (pid - 1) as usize;
    if index >= MAX_PROCESSES {
        return None;
    }
    let slot = rlimit_slots()[index];
    if slot.is_null() {
        return None;
    }
    unsafe { Some(&mut *slot) }
}

fn resolve_target_pid(vm: &ThreadState, base: u32, pid: i32) -> i32 {
    if pid == 0 {
        crate::syscall::signal::pid_from_vm(vm, base)
    } else {
        pid
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn snapshot_process_context_into(snapshot: &mut ProcessResourceSnapshot) {
    for (idx, slot) in rlimit_slots().iter().enumerate() {
        snapshot.slots[idx] = *slot as u32;
    }
}

#[cfg(any(test, feature = "harness"))]
pub(crate) fn restore_process_context(snapshot: &ProcessResourceSnapshot) {
    for (idx, slot) in rlimit_slots().iter_mut().enumerate() {
        *slot = snapshot.slots[idx] as *mut [Rlimit64; RLIMIT_NLIMITS];
    }
}

fn write_limit(base: u32, addr: u64, limit: Rlimit64) {
    unsafe {
        guest_mem::write_u64(base, addr, limit.cur);
        guest_mem::write_u64(base, addr + 8, limit.max);
    }
}

fn read_limit(base: u32, addr: u64) -> Rlimit64 {
    unsafe {
        Rlimit64 {
            cur: guest_mem::read_u64(base, addr),
            max: guest_mem::read_u64(base, addr + 8),
        }
    }
}

pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(RLIMIT_SLOTS_PTR),
            core::ptr::null_mut(),
        );
    }
    let _ = ensure_rlimit_slots();
}

pub fn init_for_process(pid: i32) {
    if pid <= 0 {
        return;
    }
    let index = (pid - 1) as usize;
    if index >= MAX_PROCESSES {
        return;
    }
    let slot = rlimit_slots()[index];
    if !slot.is_null() {
        unsafe {
            core::ptr::write(slot, default_limits());
        }
        return;
    }
    unsafe {
        let size = core::mem::size_of::<[Rlimit64; RLIMIT_NLIMITS]>() as u32;
        let align = core::mem::align_of::<Rlimit64>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            panic!(
                "resource::init_for_process oom pid={} index={} size={} align={} heap_base=0x{:x} heap_ptr=0x{:x} heap_used={}",
                pid,
                index,
                size,
                align,
                crate::alloc::heap_base(),
                crate::alloc::heap_ptr(),
                crate::alloc::heap_used(),
            );
        }
        core::ptr::write(ptr as *mut [Rlimit64; RLIMIT_NLIMITS], default_limits());
        rlimit_slots()[index] = ptr as *mut [Rlimit64; RLIMIT_NLIMITS];
    }
}

pub fn fork_from_parent(parent_pid: i32, child_pid: i32) {
    let Some(parent_limits) = limits_for(parent_pid) else {
        return;
    };
    init_for_process(child_pid);
    if let Some(child_limits) = limits_for(child_pid) {
        child_limits.copy_from_slice(parent_limits);
    }
}

pub fn reassign_process_pid(old_pid: i32, new_pid: i32) {
    if old_pid <= 0 || new_pid <= 0 || old_pid == new_pid {
        return;
    }
    let old_index = (old_pid - 1) as usize;
    let new_index = (new_pid - 1) as usize;
    if old_index >= MAX_PROCESSES || new_index >= MAX_PROCESSES {
        return;
    }
    if !rlimit_slots()[new_index].is_null() {
        return;
    }
    let old_slot = rlimit_slots()[old_index];
    if !old_slot.is_null() {
        rlimit_slots()[new_index] = old_slot;
        rlimit_slots()[old_index] = core::ptr::null_mut();
        return;
    }
    if rlimit_slots()[new_index].is_null() {
        init_for_process(new_pid);
    }
}

pub fn sys_prlimit64(
    vm: &ThreadState,
    base: u32,
    pid: i32,
    resource: u64,
    new_limit_addr: u64,
    old_limit_addr: u64,
) -> i64 {
    let target_pid = resolve_target_pid(vm, base, pid);
    let current_pid = crate::syscall::signal::pid_from_vm(vm, base);
    if target_pid <= 0 || target_pid != current_pid {
        return ESRCH;
    }

    let resource = resource as usize;
    if resource >= RLIMIT_NLIMITS {
        return EINVAL;
    }

    let Some(limits) = limits_for(target_pid) else {
        return ESRCH;
    };

    if old_limit_addr != 0 {
        write_limit(base, old_limit_addr, limits[resource]);
    }

    if new_limit_addr != 0 {
        let next = read_limit(base, new_limit_addr);
        if next.cur > next.max {
            return EINVAL;
        }
        limits[resource] = next;
    }

    0
}

pub fn sys_getrlimit(vm: &ThreadState, base: u32, resource: u64, rlimit_addr: u64) -> i64 {
    sys_prlimit64(vm, base, 0, resource, 0, rlimit_addr)
}

pub fn sys_setrlimit(vm: &ThreadState, base: u32, resource: u64, rlimit_addr: u64) -> i64 {
    sys_prlimit64(vm, base, 0, resource, rlimit_addr, 0)
}
