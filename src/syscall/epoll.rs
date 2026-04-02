//! Epoll syscalls: epoll_create1, epoll_ctl, epoll_pwait.
//!
//! Struct layout (RV64):
//!
//! struct epoll_event {                  // 16 bytes total
//!     events: u32,                      // offset 0
//!     _pad:   u32,                      // offset 4 (alignment)
//!     data:   u64,                      // offset 8
//! };
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/eventpoll.h

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

#[repr(C)]
#[derive(Clone, Copy)]
struct EpollEntry {
    ofd_id: u32,
    events: u32,
    data: u64,
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
                if inst.entries[i].ofd_id == watched_ofd_id {
                    return EEXIST;
                }
            }
            let events = unsafe { guest_mem::read_u32(base, event_addr) };
            let data = unsafe { guest_mem::read_u64(base, event_addr + 8) };
            let idx = inst.count as usize;
            inst.entries[idx] = EpollEntry {
                ofd_id: watched_ofd_id,
                events,
                data,
            };
            inst.count += 1;
            0
        }
        EPOLL_CTL_DEL => {
            for i in 0..inst.count as usize {
                if inst.entries[i].ofd_id == watched_ofd_id {
                    remove_entry(inst, i);
                    return 0;
                }
            }
            ENOENT
        }
        EPOLL_CTL_MOD => {
            for i in 0..inst.count as usize {
                if inst.entries[i].ofd_id == watched_ofd_id {
                    inst.entries[i].events = unsafe { guest_mem::read_u32(base, event_addr) };
                    inst.entries[i].data = unsafe { guest_mem::read_u64(base, event_addr + 8) };
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
    let epoll_ofd = match fd_table::get_ofd(base, vm, epfd) {
        Some(o) => o,
        None => return EBADF,
    };
    if epoll_ofd.fd_type != FD_TYPE_EPOLL {
        return EINVAL;
    }

    let Some(inst) = validated_epoll_instance(epoll_ofd.ino as usize) else {
        return EBADF;
    };
    let max = maxevents as usize;
    let mut ready = 0usize;

    for i in 0..inst.count as usize {
        if ready >= max {
            break;
        }
        let e = &inst.entries[i];
        let Some(ofd) = fd_table::get_ofd_by_id(e.ofd_id) else {
            continue;
        };
        let revents = poll_ofd(&ofd, e.events);
        if revents != 0 {
            let out_addr = events_addr + (ready as u64) * 16;
            unsafe {
                guest_mem::write_u32(base, out_addr, revents);
                guest_mem::write_u64(base, out_addr + 8, e.data);
            }
            ready += 1;
        }
    }

    if ready > 0 || timeout == 0 {
        vm.epoll_timeout_ms = 0;
        return ready as i64;
    }

    // No events ready and timeout != 0: block via STATUS_EPOLL_WAIT.
    // Store context for resume by the TS runtime.
    vm.fault_addr = epfd;
    vm.fault_pc = events_addr;
    vm.epoll_timeout_ms = timeout;
    vm.epoll_maxevents = maxevents as u32;
    vm.status = STATUS_EPOLL_WAIT;
    return 0; // dispatch() checks vm.status and returns it
}

pub fn resume_timeout(vm: &mut ThreadState) {
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
    use crate::test_helpers::TestVm;

    #[test]
    fn epoll_instance_lifecycle() {
        let _ = TestVm::new();

        // Allocate an instance
        let size = core::mem::size_of::<EpollInstance>() as u32;
        let ptr = unsafe { alloc::alloc_zeroed(size, 8) };
        assert!(ptr != 0);
        set_epoll_ptr(0, ptr as *mut EpollInstance);

        let inst = unsafe { &mut *epoll_ptr(0) };

        // Add entry
        inst.entries[0] = EpollEntry {
            ofd_id: 5,
            events: EPOLLIN,
            data: 0x42,
        };
        inst.count = 1;
        assert_eq!(inst.count, 1);
        assert_eq!(inst.entries[0].ofd_id, 5);

        // Delete entry
        inst.count = 0;
        set_epoll_ptr(0, core::ptr::null_mut());
    }

    #[test]
    fn close_epoll_clears_instance_slot() {
        let mut t = TestVm::new();
        let epfd = super::sys_epoll_create1(&mut t.vm, t.base, 0);
        assert!(epfd >= 3);

        let epoll_idx = crate::fs::fd_table::get_ofd(t.base, &t.vm, epfd as u64)
            .expect("epoll OFD should exist")
            .ino;
        assert!(super::epoll_slot_allocated(epoll_idx));

        super::close_epoll(epoll_idx);
        assert!(!super::epoll_slot_allocated(epoll_idx));
    }

    #[test]
    fn epoll_pwait_reports_ready_pipe() {
        let mut t = TestVm::new();
        let pipefd_addr = t.scratch + 0x1000;
        assert_eq!(
            crate::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
            0
        );
        let read_fd = unsafe { crate::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
        let write_fd = unsafe { crate::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;

        let epfd = super::sys_epoll_create1(&mut t.vm, t.base, 0);
        assert!(epfd >= 3);

        let event_addr = t.scratch + 0x2000;
        let out_addr = t.scratch + 0x3000;
        unsafe {
            crate::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
            crate::guest_mem::write_u64(t.base, event_addr + 8, 0x1234);
        }

        assert_eq!(
            super::sys_epoll_ctl(
                &mut t.vm,
                t.base,
                epfd as u64,
                EPOLL_CTL_ADD,
                read_fd,
                event_addr,
            ),
            0
        );
        assert_eq!(
            super::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
            0
        );

        assert_eq!(t.sys_write_data(write_fd, b"x"), 1);
        assert_eq!(
            super::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
            1
        );
        assert_eq!(
            unsafe { crate::guest_mem::read_u32(t.base, out_addr) },
            EPOLLIN
        );
        assert_eq!(
            unsafe { crate::guest_mem::read_u64(t.base, out_addr + 8) },
            0x1234
        );
    }

    #[test]
    fn epoll_pwait_sets_wait_status_for_blocking_calls() {
        let mut t = TestVm::new();
        let pipefd_addr = t.scratch + 0x1000;
        assert_eq!(
            crate::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
            0
        );
        let read_fd = unsafe { crate::guest_mem::read_u32(t.base, pipefd_addr) } as u64;

        let epfd = super::sys_epoll_create1(&mut t.vm, t.base, 0);
        assert!(epfd >= 3);

        let event_addr = t.scratch + 0x2000;
        let out_addr = t.scratch + 0x3000;
        unsafe {
            crate::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
            crate::guest_mem::write_u64(t.base, event_addr + 8, 0x55);
        }

        assert_eq!(
            super::sys_epoll_ctl(
                &mut t.vm,
                t.base,
                epfd as u64,
                EPOLL_CTL_ADD,
                read_fd,
                event_addr,
            ),
            0
        );

        assert_eq!(
            super::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 10, 0),
            0
        );
        assert_eq!(t.vm.status, STATUS_EPOLL_WAIT);
        assert_eq!(t.vm.fault_addr, epfd as u64);
        assert_eq!(t.vm.fault_pc, out_addr);
    }

    #[test]
    fn epoll_interest_follows_ofd_until_last_alias_and_not_reused_fd() {
        let mut t = TestVm::new();
        let pipefd_addr = t.scratch + 0x1000;
        assert_eq!(
            crate::syscall::pipe::sys_pipe2(&mut t.vm, t.base, pipefd_addr, 0),
            0
        );
        let read_fd = unsafe { crate::guest_mem::read_u32(t.base, pipefd_addr) } as u64;
        let write_fd = unsafe { crate::guest_mem::read_u32(t.base, pipefd_addr + 4) } as i64;
        let dup_fd = t.sys_dup(read_fd);
        assert!(dup_fd >= 3);

        let epfd = super::sys_epoll_create1(&mut t.vm, t.base, 0);
        assert!(epfd >= 3);

        let event_addr = t.scratch + 0x2000;
        let out_addr = t.scratch + 0x3000;
        unsafe {
            crate::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
            crate::guest_mem::write_u64(t.base, event_addr + 8, 0x66);
        }
        assert_eq!(
            super::sys_epoll_ctl(
                &mut t.vm,
                t.base,
                epfd as u64,
                EPOLL_CTL_ADD,
                read_fd,
                event_addr,
            ),
            0
        );

        assert_eq!(t.sys_close(read_fd as i64), 0);
        assert_eq!(t.sys_write_data(write_fd, b"x"), 1);
        assert_eq!(
            super::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
            1
        );
        assert_eq!(
            unsafe { crate::guest_mem::read_u64(t.base, out_addr + 8) },
            0x66
        );

        let mut buf = [0u8; 1];
        assert_eq!(t.sys_read(dup_fd, &mut buf), 1);
        assert_eq!(buf, [b'x']);
        assert_eq!(t.sys_close(dup_fd), 0);

        let new_pipefd_addr = t.scratch + 0x1100;
        assert_eq!(
            crate::syscall::pipe::sys_pipe2(&mut t.vm, t.base, new_pipefd_addr, 0),
            0
        );
        let new_read_fd = unsafe { crate::guest_mem::read_u32(t.base, new_pipefd_addr) } as u64;
        let new_write_fd =
            unsafe { crate::guest_mem::read_u32(t.base, new_pipefd_addr + 4) } as i64;
        assert_eq!(new_read_fd, read_fd);

        assert_eq!(t.sys_write_data(new_write_fd, b"y"), 1);
        assert_eq!(
            super::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
            0
        );
    }

    #[test]
    fn epoll_pwait_reports_ready_eventfd() {
        let mut t = TestVm::new();
        let efd = crate::syscall::pipe::sys_eventfd2(
            &mut t.vm,
            t.base,
            0,
            (O_NONBLOCK | O_CLOEXEC) as u64,
        );
        assert!(efd >= 3);

        let epfd = super::sys_epoll_create1(&mut t.vm, t.base, 0);
        assert!(epfd >= 3);

        let event_addr = t.scratch + 0x2000;
        let out_addr = t.scratch + 0x3000;
        let buf_addr = t.scratch + 0x4000;
        unsafe {
            crate::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
            crate::guest_mem::write_u64(t.base, event_addr + 8, 0x9876);
            crate::guest_mem::write_u64(t.base, buf_addr, 1);
        }

        assert_eq!(
            super::sys_epoll_ctl(
                &mut t.vm,
                t.base,
                epfd as u64,
                EPOLL_CTL_ADD,
                efd as u64,
                event_addr,
            ),
            0
        );
        assert_eq!(
            super::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
            0
        );

        assert_eq!(
            crate::syscall::fs::sys_write(&mut t.vm, t.base, efd as u64, buf_addr, 8, SYS_WRITE),
            8
        );
        assert_eq!(
            super::sys_epoll_pwait(&mut t.vm, t.base, epfd as u64, out_addr, 1, 0, 0),
            1
        );
        assert_eq!(
            unsafe { crate::guest_mem::read_u32(t.base, out_addr) },
            EPOLLIN
        );
        assert_eq!(
            unsafe { crate::guest_mem::read_u64(t.base, out_addr + 8) },
            0x9876
        );
    }

    #[test]
    fn epoll_ctl_rejects_regular_files_with_eperm() {
        let mut t = TestVm::new();
        t.memfs.create_file(b"regular.txt", b"hello");
        let file_fd = t.sys_openat(b"/regular.txt", O_RDONLY);
        assert!(file_fd >= 3);

        let epfd = super::sys_epoll_create1(&mut t.vm, t.base, 0);
        assert!(epfd >= 3);

        let event_addr = t.scratch + 0x2000;
        unsafe {
            crate::guest_mem::write_u32(t.base, event_addr, EPOLLIN);
            crate::guest_mem::write_u64(t.base, event_addr + 8, 0x44);
        }

        assert_eq!(
            super::sys_epoll_ctl(
                &mut t.vm,
                t.base,
                epfd as u64,
                EPOLL_CTL_ADD,
                file_fd as u64,
                event_addr,
            ),
            EPERM
        );
    }
}
