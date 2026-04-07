//! Epoll syscalls: epoll_create1, epoll_ctl, epoll_pwait.
//!
//! Struct layout (RV64 Linux):
//!
//! struct epoll_event {                  // 16 bytes total
//!     events: u32,                      // offset 0
//!     pad:    u32,                      // offset 4
//!     data:   u64,                      // offset 8
//! };
//!
//! Linux UAPI only packs this structure on x86_64. RISC-V uses the natural
//! alignment, so user ABI is 16-byte stride with `data` at +8.
//! See `include/uapi/linux/eventpoll.h`.

use crate::abi::*;
use crate::alloc;
use crate::fs::fd_table;
use crate::guest_mem;
use crate::types::{OpenFileDesc, ThreadState};

pub(crate) const EPOLL_CTL_ADD: u64 = 1;
pub(crate) const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;

pub(crate) const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;
const EPOLL_EVENT_DATA_OFFSET: u64 = 8;
const EPOLL_EVENT_SIZE: u64 = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct EpollEntry {
    fd: u32,
    ofd_id: u32,
    events: u32,
    data: u64,
    last_revents: u32,
}

/// Epoll instance state, allocated via alloc.rs.
#[repr(C)]
struct EpollInstance {
    entries: [EpollEntry; MAX_EPOLL_ENTRIES],
    count: u32,
}

/// Pointer to epoll pointer table, allocated via alloc.rs in kernel Worker memory.
static mut EPOLL_TABLE_PTR: *mut *mut EpollInstance = core::ptr::null_mut();

/// Initialize epoll table. Allocates via alloc.rs.
pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(EPOLL_TABLE_PTR),
            core::ptr::null_mut(),
        );

        let size = (MAX_EPOLL_ENTRIES * core::mem::size_of::<*mut EpollInstance>()) as u32;
        let ptr = alloc::alloc_zeroed(size, core::mem::align_of::<*mut EpollInstance>() as u32);
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(EPOLL_TABLE_PTR),
            ptr as *mut *mut EpollInstance,
        );
    }
}

fn epoll_ptr(idx: usize) -> *mut EpollInstance {
    unsafe {
        let table = core::ptr::read(core::ptr::addr_of!(EPOLL_TABLE_PTR));
        core::ptr::read(table.add(idx))
    }
}

fn set_epoll_ptr(idx: usize, val: *mut EpollInstance) {
    unsafe {
        let table = core::ptr::read(core::ptr::addr_of!(EPOLL_TABLE_PTR));
        core::ptr::write(table.add(idx), val);
    }
}

fn validated_epoll_instance(epoll_idx: usize) -> Option<&'static mut EpollInstance> {
    let ptr = epoll_ptr(epoll_idx);
    if ptr.is_null() {
        return None;
    }
    let inst = unsafe { &mut *ptr };
    if inst.count as usize > MAX_EPOLL_ENTRIES {
        close_epoll(epoll_idx as u32);
        return None;
    }
    Some(inst)
}

pub fn epoll_table_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(EPOLL_TABLE_PTR)) as u32 }
}

pub fn epoll_table_bytes() -> u32 {
    (MAX_EPOLL_ENTRIES * core::mem::size_of::<*mut EpollInstance>()) as u32
}

pub fn epoll_instance_bytes() -> u32 {
    core::mem::size_of::<EpollInstance>() as u32
}

pub fn attach_epoll_table_ptr(ptr: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(EPOLL_TABLE_PTR),
            ptr as *mut *mut EpollInstance,
        );
    }
}

pub fn close_epoll(epoll_idx: u32) {
    if epoll_idx as usize >= MAX_EPOLL_ENTRIES {
        return;
    }
    set_epoll_ptr(epoll_idx as usize, core::ptr::null_mut());
}

pub fn epoll_slot_allocated(epoll_idx: u32) -> bool {
    if epoll_idx as usize >= MAX_EPOLL_ENTRIES {
        return false;
    }
    !epoll_ptr(epoll_idx as usize).is_null()
}

fn remove_entry(inst: &mut EpollInstance, idx: usize) {
    let last = inst.count as usize - 1;
    inst.entries[idx] = inst.entries[last];
    inst.count -= 1;
}

fn epoll_supports_fd_type(fd_type: i32) -> bool {
    matches!(fd_type, FD_TYPE_PIPE | FD_TYPE_SOCKET | FD_TYPE_EVENTFD)
}

pub fn release_interest_for_ofd(ofd_id: u32) {
    if ofd_id == 0 {
        return;
    }
    for epoll_idx in 0..MAX_EPOLL_ENTRIES {
        let Some(inst) = validated_epoll_instance(epoll_idx) else {
            continue;
        };
        let mut idx = 0usize;
        while idx < inst.count as usize {
            if inst.entries[idx].ofd_id == ofd_id {
                remove_entry(inst, idx);
            } else {
                idx += 1;
            }
        }
    }
}

// =========================================================================
// epoll_create1
// =========================================================================

/// epoll_create1: create a new epoll instance and return its FD.
pub fn sys_epoll_create1(vm: &mut ThreadState, base: u32, flags: u64) -> i64 {
    if flags & !(O_CLOEXEC as u64) != 0 {
        return EINVAL;
    }

    // Find free epoll slot
    let mut slot_idx = usize::MAX;
    for i in 0..MAX_EPOLL_ENTRIES {
        if epoll_ptr(i).is_null() {
            slot_idx = i;
            break;
        }
    }
    if slot_idx == usize::MAX {
        return ENOMEM;
    }

    unsafe {
        let size = core::mem::size_of::<EpollInstance>() as u32;
        let ptr = alloc::alloc_zeroed(size, 8);
        if ptr == 0 {
            return ENOMEM;
        }
        set_epoll_ptr(slot_idx, ptr as *mut EpollInstance);
    }

    // Create an FD for this epoll instance
    fd_table::open_epoll(vm, base, slot_idx as u32, flags as i32)
}

// =========================================================================
// epoll_ctl
// =========================================================================

/// epoll_ctl: add, modify, or delete an entry in the epoll interest list.
pub fn sys_epoll_ctl(
    vm: &mut ThreadState,
    base: u32,
    epfd: u64,
    op: u64,
    fd: u64,
    event_addr: u64,
) -> i64 {
    let epoll_ofd = match fd_table::get_ofd(base, vm, epfd) {
        Some(o) => o,
        None => return EBADF,
    };
    if epoll_ofd.fd_type != FD_TYPE_EPOLL {
        return EINVAL;
    }
    let watched_ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if !epoll_supports_fd_type(watched_ofd.fd_type) {
        return EPERM;
    }
    let watched_ofd_id = match fd_table::get_ofd_id(base, vm, fd) {
        Some(id) => id,
        None => return EBADF,
    };

    let Some(inst) = validated_epoll_instance(epoll_ofd.ino as usize) else {
        return EBADF;
    };

    match op {
        EPOLL_CTL_ADD => {
            if inst.count as usize >= MAX_EPOLL_ENTRIES {
                return ENOMEM;
            }
            // Check for duplicate
            for i in 0..inst.count as usize {
                if inst.entries[i].fd == fd as u32 && inst.entries[i].ofd_id == watched_ofd_id {
                    return EEXIST;
                }
            }
            let events = unsafe { guest_mem::read_u32(base, event_addr) };
            let data = unsafe { guest_mem::read_u64(base, event_addr + EPOLL_EVENT_DATA_OFFSET) };
            let idx = inst.count as usize;
            inst.entries[idx] = EpollEntry {
                fd: fd as u32,
                ofd_id: watched_ofd_id,
                events,
                data,
                last_revents: 0,
            };
            inst.count += 1;
            0
        }
        EPOLL_CTL_DEL => {
            for i in 0..inst.count as usize {
                if inst.entries[i].fd == fd as u32 && inst.entries[i].ofd_id == watched_ofd_id {
                    remove_entry(inst, i);
                    return 0;
                }
            }
            ENOENT
        }
        EPOLL_CTL_MOD => {
            for i in 0..inst.count as usize {
                if inst.entries[i].fd == fd as u32 && inst.entries[i].ofd_id == watched_ofd_id {
                    inst.entries[i].events = unsafe { guest_mem::read_u32(base, event_addr) };
                    inst.entries[i].data =
                        unsafe { guest_mem::read_u64(base, event_addr + EPOLL_EVENT_DATA_OFFSET) };
                    inst.entries[i].last_revents = 0;
                    return 0;
                }
            }
            ENOENT
        }
        _ => EINVAL,
    }
}

// =========================================================================
// epoll_pwait
// =========================================================================

/// epoll_pwait: wait for events on an epoll instance.
///
/// Returns number of ready events, or blocks via STATUS_EPOLL_WAIT if
/// no events are ready and timeout != 0.
///
/// Blocking info stored in ThreadState:
///   fault_addr = epfd, fault_pc = events_addr (repacked for resume)
pub fn sys_epoll_pwait(
    vm: &mut ThreadState,
    base: u32,
    epfd: u64,
    events_addr: u64,
    maxevents: u64,
    timeout: i64,
    _sigmask: u64,
) -> i64 {
    const EPOLL_WAIT_REASON_NO_OFD: u32 = 1;
    const EPOLL_WAIT_REASON_WRONG_TYPE: u32 = 2;
    const EPOLL_WAIT_REASON_MISSING_INSTANCE: u32 = 3;
    const EPOLL_WAIT_REASON_READY: u32 = 4;
    const EPOLL_WAIT_REASON_BLOCKED: u32 = 5;

    let epoll_ofd_id = fd_table::get_ofd_id(base, vm, epfd).unwrap_or(0);
    let epoll_ofd = match fd_table::get_ofd(base, vm, epfd) {
        Some(o) => o,
        None => {
            crate::harness_hooks::record_epoll_wait(
                0,
                epfd,
                epoll_ofd_id,
                0,
                0,
                0,
                0,
                EBADF,
                EPOLL_WAIT_REASON_NO_OFD,
            );
            return EBADF;
        }
    };
    if epoll_ofd.fd_type != FD_TYPE_EPOLL {
        crate::harness_hooks::record_epoll_wait(
            0,
            epfd,
            epoll_ofd_id,
            epoll_ofd.fd_type,
            epoll_ofd.ino,
            epoll_ptr(epoll_ofd.ino as usize) as u32,
            0,
            EINVAL,
            EPOLL_WAIT_REASON_WRONG_TYPE,
        );
        return EINVAL;
    }

    let epoll_idx = epoll_ofd.ino as usize;
    let epoll_ptr_value = epoll_ptr(epoll_idx);
    let epoll_count = if epoll_ptr_value.is_null() {
        0
    } else {
        unsafe { (*epoll_ptr_value).count }
    };
    let Some(inst) = validated_epoll_instance(epoll_ofd.ino as usize) else {
        crate::harness_hooks::record_epoll_wait(
            0,
            epfd,
            epoll_ofd_id,
            epoll_ofd.fd_type,
            epoll_ofd.ino,
            epoll_ptr_value as u32,
            epoll_count,
            EBADF,
            EPOLL_WAIT_REASON_MISSING_INSTANCE,
        );
        return EBADF;
    };
    let max = maxevents as usize;
    let mut ready = 0usize;

    for i in 0..inst.count as usize {
        if ready >= max {
            break;
        }
        let entry = inst.entries[i];
        let Some(ofd) = fd_table::get_ofd_by_id(entry.ofd_id) else {
            continue;
        };
        let polled_revents = poll_ofd(&ofd, entry.events);
        let revents = if entry.events & EPOLLET != 0 {
            polled_revents & !entry.last_revents
        } else {
            polled_revents
        };
        inst.entries[i].last_revents = polled_revents;
        if revents != 0 {
            let out_addr = events_addr + (ready as u64) * EPOLL_EVENT_SIZE;
            unsafe {
                guest_mem::write_u32(base, out_addr, revents);
                guest_mem::write_u64(base, out_addr + EPOLL_EVENT_DATA_OFFSET, entry.data);
            }
            if entry.events & EPOLLONESHOT != 0 {
                inst.entries[i].events = 0;
                inst.entries[i].last_revents = 0;
            }
            ready += 1;
        }
    }

    if ready > 0 || timeout == 0 {
        vm.status = STATUS_OK;
        vm.epoll_timeout_ms = 0;
        vm.epoll_maxevents = 0;
        crate::harness_hooks::record_epoll_wait(
            0,
            epfd,
            epoll_ofd_id,
            epoll_ofd.fd_type,
            epoll_ofd.ino,
            epoll_ptr_value as u32,
            inst.count,
            ready as i64,
            EPOLL_WAIT_REASON_READY,
        );
        return ready as i64;
    }

    // No events ready and timeout != 0: block via STATUS_EPOLL_WAIT.
    // Store context for resume by the TS runtime.
    fd_table::pin_blocked_fd(base, vm, epfd);
    vm.fault_addr = epfd;
    vm.fault_pc = events_addr;
    vm.epoll_timeout_ms = timeout;
    vm.epoll_maxevents = maxevents as u32;
    vm.status = STATUS_EPOLL_WAIT;
    crate::harness_hooks::record_epoll_wait(
        0,
        epfd,
        epoll_ofd_id,
        epoll_ofd.fd_type,
        epoll_ofd.ino,
        epoll_ptr_value as u32,
        inst.count,
        0,
        EPOLL_WAIT_REASON_BLOCKED,
    );
    0 // dispatch() checks vm.status and returns it
}

pub fn resume_timeout(vm: &mut ThreadState) {
    fd_table::clear_blocked_ofd_pin(vm);
    vm.epoll_timeout_ms = 0;
    vm.epoll_maxevents = 0;
    vm.x[10] = 0;
    vm.status = STATUS_OK;
}

pub fn resume_wait(vm: &mut ThreadState, base: u32) -> i64 {
    let result = sys_epoll_pwait(
        vm,
        base,
        vm.fault_addr,
        vm.fault_pc,
        vm.epoll_maxevents as u64,
        vm.epoll_timeout_ms,
        0,
    );
    if vm.status == STATUS_OK {
        vm.x[10] = result as u64;
    }
    result
}

/// Poll a single watched object for readiness using its OFD snapshot.
fn poll_ofd(ofd: &OpenFileDesc, interest: u32) -> u32 {
    let mut revents = 0u32;

    if ofd.fd_type == FD_TYPE_PIPE {
        let pipe_idx = ofd.ino;
        let is_read = fd_table::is_pipe_read(ofd);

        if is_read {
            let peek = super::pipe::pipe_peek(pipe_idx);
            if peek == 0 {
                revents |= EPOLLHUP; // EOF: write end closed, no data
            } else if peek > 0 {
                revents |= EPOLLIN; // data available
            }
            // peek == EAGAIN: empty, write end open → not ready
        } else {
            if super::pipe::pipe_writable(pipe_idx) {
                revents |= EPOLLOUT;
            }
            // Check if read end closed → EPOLLERR
            let addr = super::pipe::slot_addr(pipe_idx);
            if super::pipe::read_open_ptr(addr).load(core::sync::atomic::Ordering::Acquire) <= 0 {
                revents |= EPOLLERR;
            }
        }
    } else if ofd.fd_type == FD_TYPE_FILE {
        // Files are always ready
        if interest & EPOLLIN != 0 {
            revents |= EPOLLIN;
        }
        if interest & EPOLLOUT != 0 {
            revents |= EPOLLOUT;
        }
    } else if ofd.fd_type == FD_TYPE_EVENTFD {
        let counter = ofd.offset as u64;
        if counter > 0 && interest & EPOLLIN != 0 {
            revents |= EPOLLIN;
        }
        if counter < u64::MAX - 1 && interest & EPOLLOUT != 0 {
            revents |= EPOLLOUT;
        }
    } else if ofd.fd_type == FD_TYPE_SOCKET {
        revents |= super::socket::poll_revents_ofd(ofd, interest);
    }

    revents & (interest | EPOLLERR | EPOLLHUP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::reset_default_state;

    #[test]
    fn epoll_instance_lifecycle() {
        unsafe {
            reset_default_state();
        }

        // Allocate an instance
        let size = core::mem::size_of::<EpollInstance>() as u32;
        let ptr = unsafe { alloc::alloc_zeroed(size, 8) };
        assert!(ptr != 0);
        set_epoll_ptr(0, ptr as *mut EpollInstance);

        let inst = unsafe { &mut *epoll_ptr(0) };

        // Add entry
        inst.entries[0] = EpollEntry {
            fd: 7,
            ofd_id: 5,
            events: EPOLLIN,
            data: 0x42,
            last_revents: 0,
        };
        inst.count = 1;
        assert_eq!(inst.count, 1);
        assert_eq!(inst.entries[0].ofd_id, 5);

        // Delete entry
        inst.count = 0;
        set_epoll_ptr(0, core::ptr::null_mut());
    }
}
