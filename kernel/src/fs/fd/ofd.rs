use super::alloc::OPEN_ACCESS_MODE_MASK;
use super::close::release_ofd_id;
use super::entry::{
    get_fd_entry, get_process_state, load_fd_entry_ptr, store_process_fd_entry_ptr,
};
use crate::abi::*;
use crate::types::{FdEntry, OpenFileDesc, ThreadState};
use core::sync::atomic::{AtomicU32, Ordering};

const OFD_PIPE_EPIPE_SYNCED: u32 = 1 << 31;
const OFD_PIPE_EOF_SYNCED: u32 = 1 << 30;
const OFD_RESERVED_WORDS: usize = (MAX_FDS + 63) / 64;

#[repr(C)]
struct OfdState {
    table: [OpenFileDesc; MAX_FDS],
    reserved: [u64; OFD_RESERVED_WORDS],
    offset_floor: [u64; MAX_FDS],
    allocation_lock: AtomicU32,
}

/// Pointer to OFD state in kernel Worker linear memory.
static mut OFD_STATE_PTR: *mut OfdState = core::ptr::null_mut();

fn state() -> &'static mut OfdState {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(OFD_STATE_PTR));
        &mut *p
    }
}

pub(in crate::fs) fn table() -> &'static mut [OpenFileDesc; MAX_FDS] {
    &mut state().table
}

pub(in crate::fs) fn with_allocation_lock<T>(f: impl FnOnce() -> T) -> T {
    let lock = &state().allocation_lock;
    while lock
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let result = f();
    lock.store(0, Ordering::Release);
    result
}

pub fn ofd_table_ptr() -> u32 {
    core::ptr::addr_of_mut!(state().table) as u32
}

pub fn ofd_table_bytes() -> u32 {
    core::mem::size_of::<[OpenFileDesc; MAX_FDS]>() as u32
}

pub fn ofd_state_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(OFD_STATE_PTR)) as u32 }
}

pub fn ofd_state_bytes() -> u32 {
    core::mem::offset_of!(OfdState, allocation_lock) as u32
}

pub fn attach_ofd_state_ptr(ptr: u32) {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(OFD_STATE_PTR), ptr as *mut OfdState);
    }
}

/// Initialize OFD state. Allocates via alloc.rs.
pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(OFD_STATE_PTR),
            core::ptr::null_mut(),
        );

        let size = core::mem::size_of::<OfdState>() as u32;
        let align = core::mem::align_of::<OfdState>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            crate::wasm::unreachable();
        }
        core::ptr::write(core::ptr::addr_of_mut!(OFD_STATE_PTR), ptr as *mut OfdState);
    }
}

fn reserved_index(ofd_id: usize) -> bool {
    if ofd_id >= MAX_FDS {
        return false;
    }
    let word = state().reserved[ofd_id / 64];
    (word & (1u64 << (ofd_id % 64))) != 0
}

pub fn ofd_reserved_ptr() -> u32 {
    core::ptr::addr_of_mut!(state().reserved) as u32
}

pub fn ofd_reserved_bytes() -> u32 {
    core::mem::size_of::<[u64; OFD_RESERVED_WORDS]>() as u32
}

pub fn ofd_offset_floor_ptr() -> u32 {
    core::ptr::addr_of_mut!(state().offset_floor) as u32
}

pub fn ofd_offset_floor_bytes() -> u32 {
    core::mem::size_of::<[u64; MAX_FDS]>() as u32
}

pub fn reserve_ofd_id(ofd_id: u32) {
    let ofd_id = ofd_id as usize;
    if ofd_id == 0 || ofd_id >= MAX_FDS {
        return;
    }
    let reserved = &mut state().reserved;
    reserved[ofd_id / 64] |= 1u64 << (ofd_id % 64);
}

pub fn unreserve_ofd_id(ofd_id: u32) {
    let ofd_id = ofd_id as usize;
    if ofd_id == 0 || ofd_id >= MAX_FDS {
        return;
    }
    let reserved = &mut state().reserved;
    reserved[ofd_id / 64] &= !(1u64 << (ofd_id % 64));
    if table()[ofd_id].refcount <= 0 {
        clear(&mut table()[ofd_id]);
    }
}

pub fn is_ofd_reserved(ofd_id: u32) -> bool {
    reserved_index(ofd_id as usize)
}

/// Increment the OFD refcount for an additional file descriptor reference.
/// Linux dup/fork create another fd referring to the same open file
/// description: https://man7.org/linux/man-pages/man2/dup.2.html
pub fn retain_ofd_id(ofd_id: u32) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    let slot = ofd_id as usize;
    let ofd = &mut table()[slot];
    if ofd.refcount > 0 || (ofd.refcount == 0 && is_ofd_reserved(ofd_id) && ofd.fd_type != 0) {
        ofd.refcount += 1;
    }
}

pub fn blocked_status_uses_ofd_pin(status: i32) -> bool {
    matches!(
        status,
        STATUS_FS
            | STATUS_PIPE_WAIT
            | STATUS_EPOLL_WAIT
            | STATUS_CONNECT
            | STATUS_SOCKET_RECV
            | STATUS_SOCKET_SEND
            | STATUS_FLOCK_WAIT
    )
}

pub fn clear_blocked_ofd_pin(vm: &mut ThreadState) {
    let ofd_id = vm.blocked_ofd_id;
    vm.blocked_fd = 0;
    vm.blocked_ofd_id = 0;
    vm.blocked_syscall_nr = 0;
    vm.blocked_syscall_args = [0; 6];
    if ofd_id != 0 {
        release_ofd_id(ofd_id);
    }
}

pub fn pin_blocked_fd(base: u32, vm: &mut ThreadState, fd: u64) {
    let Some(ofd_id) = get_ofd_id(base, vm, fd) else {
        clear_blocked_ofd_pin(vm);
        return;
    };
    let blocked_fd = fd as u32;
    if vm.blocked_ofd_id == ofd_id && vm.blocked_fd == blocked_fd {
        return;
    }
    clear_blocked_ofd_pin(vm);
    retain_ofd_id(ofd_id);
    vm.blocked_fd = blocked_fd;
    vm.blocked_ofd_id = ofd_id;
}

pub fn patch_blocked_fd_entry_for_resume(base: u32, vm: &ThreadState) -> Option<(u32, FdEntry)> {
    unsafe {
        let ofd_id = vm.blocked_ofd_id;
        let fd = vm.blocked_fd as usize;
        if ofd_id == 0 || fd >= MAX_FDS {
            return None;
        }

        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return None;
        }

        let entry = core::ptr::addr_of_mut!((*ps).fd_table[fd]);
        let saved = load_fd_entry_ptr(entry);
        if saved.ofd_id != ofd_id {
            store_process_fd_entry_ptr(
                ps,
                fd,
                FdEntry {
                    ofd_id,
                    fd_flags: saved.fd_flags,
                },
            );
        }
        Some((fd as u32, saved))
    }
}

pub fn restore_blocked_fd_entry(base: u32, vm: &ThreadState, saved: Option<(u32, FdEntry)>) {
    unsafe {
        let Some((fd, saved)) = saved else {
            return;
        };
        let fd = fd as usize;
        if fd >= MAX_FDS {
            return;
        }

        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return;
        }

        store_process_fd_entry_ptr(ps, fd, saved);
    }
}

pub fn inode_has_write_open(ino: u32) -> bool {
    table().iter().any(|ofd| {
        ofd.refcount > 0
            && ofd.fd_type == FD_TYPE_FILE
            && ofd.ino == ino
            && (ofd.status_flags & OPEN_ACCESS_MODE_MASK) != O_RDONLY
    })
}

/// Check if an OFD is a pipe read-end (host_fd >= 0 and fd_type == PIPE).
pub fn is_pipe_read(ofd: &OpenFileDesc) -> bool {
    ofd.fd_type == FD_TYPE_PIPE
        && ofd.host_fd >= 0
        && crate::syscall::pipe::pipe_generation_matches(ofd.ino, ofd.offset as u32)
}

/// Check if an OFD is a pipe write-end (host_fd < 0 and fd_type == PIPE).
pub fn is_pipe_write(ofd: &OpenFileDesc) -> bool {
    ofd.fd_type == FD_TYPE_PIPE
        && ofd.host_fd < 0
        && crate::syscall::pipe::pipe_generation_matches(ofd.ino, ofd.offset as u32)
}

/// Get OFD for a file descriptor (read-only snapshot).
pub fn get_ofd(base: u32, vm: &ThreadState, fd: u64) -> Option<OpenFileDesc> {
    let entry = unsafe { get_fd_entry(base, vm, fd)? };
    let ofd = &table()[entry.ofd_id as usize];
    Some(*ofd)
}

/// Get the internal OFD id for a file descriptor.
pub fn get_ofd_id(base: u32, vm: &ThreadState, fd: u64) -> Option<u32> {
    unsafe { Some(get_fd_entry(base, vm, fd)?.ofd_id) }
}

pub fn pipe_epipe_synced(ofd_id: u32) -> bool {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return false;
    }
    let ofd = &table()[ofd_id as usize];
    ofd.fd_type == FD_TYPE_PIPE && ofd.host_fd < 0 && (ofd.flock_state & OFD_PIPE_EPIPE_SYNCED) != 0
}

pub fn set_pipe_epipe_synced(ofd_id: u32, synced: bool) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    let ofd = &mut table()[ofd_id as usize];
    if ofd.fd_type != FD_TYPE_PIPE || ofd.host_fd >= 0 {
        return;
    }
    if synced {
        ofd.flock_state |= OFD_PIPE_EPIPE_SYNCED;
    } else {
        ofd.flock_state &= !OFD_PIPE_EPIPE_SYNCED;
    }
}

pub fn pipe_eof_synced(ofd_id: u32) -> bool {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return false;
    }
    let ofd = &table()[ofd_id as usize];
    ofd.fd_type == FD_TYPE_PIPE && ofd.host_fd >= 0 && (ofd.flock_state & OFD_PIPE_EOF_SYNCED) != 0
}

pub fn set_pipe_eof_synced(ofd_id: u32, synced: bool) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    let ofd = &mut table()[ofd_id as usize];
    if ofd.fd_type != FD_TYPE_PIPE || ofd.host_fd < 0 {
        return;
    }
    if synced {
        ofd.flock_state |= OFD_PIPE_EOF_SYNCED;
    } else {
        ofd.flock_state &= !OFD_PIPE_EOF_SYNCED;
    }
}

pub fn set_fd_nonblock(base: u32, vm: &ThreadState, fd: u64, enabled: bool) -> i64 {
    unsafe {
        let entry = match get_fd_entry(base, vm, fd) {
            Some(entry) => entry,
            None => return EBADF,
        };
        let ofd = &mut table()[entry.ofd_id as usize];
        if enabled {
            ofd.status_flags |= O_NONBLOCK;
        } else {
            ofd.status_flags &= !O_NONBLOCK;
        }
        0
    }
}

/// Increment OFD refcounts for every fd held by the process.
///
/// Used when emulating fork(): the child receives a copy of the parent's
/// FD table, and each copied fd holds a reference to its open file
/// description. See https://man7.org/linux/man-pages/man2/fork.2.html
pub fn retain_fds_for_fork(base: u32, vm: &ThreadState) {
    unsafe {
        let ps = get_process_state(base, vm);
        if ps.is_null() {
            return;
        }

        for index in 0..MAX_FDS {
            let entry = load_fd_entry_ptr(core::ptr::addr_of!((*ps).fd_table[index]));
            if entry.ofd_id == 0 || entry.ofd_id as usize >= MAX_FDS {
                continue;
            }
            retain_ofd_id(entry.ofd_id);
        }
    }
}

/// Allocate a new OFD slot. Returns ofd_id (1-based), or 0 on failure.
pub(in crate::fs) unsafe fn alloc(fd_type: i32, status_flags: i32) -> u32 {
    for i in 1..MAX_FDS {
        if table()[i].refcount == 0 && !reserved_index(i) {
            set_offset_floor_by_id(i as u32, 0);
            table()[i] = OpenFileDesc {
                fd_type,
                host_fd: -1,
                status_flags,
                refcount: 1,
                offset: 0,
                ino: 0,
                flock_state: 0,
            };
            return i as u32;
        }
    }
    0
}

pub(in crate::fs) fn clear(ofd: &mut OpenFileDesc) {
    ofd.fd_type = 0;
    ofd.host_fd = -1;
    ofd.status_flags = 0;
    ofd.refcount = 0;
    ofd.offset = 0;
    ofd.ino = 0;
    ofd.flock_state = 0;
}

/// Get OFD by internal OFD id (for mmap file-backed without FD context).
pub fn get_ofd_by_id(ofd_id: u32) -> Option<OpenFileDesc> {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return None;
    }
    let ofd = &table()[ofd_id as usize];
    if ofd.fd_type == FD_TYPE_NONE {
        return None;
    }
    Some(*ofd)
}

pub fn get_offset_by_id(ofd_id: u32) -> u64 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    table()[ofd_id as usize].offset as u64
}

pub fn get_offset_floor_by_id(ofd_id: u32) -> u64 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    state().offset_floor[ofd_id as usize]
}

pub fn set_offset_floor_by_id(ofd_id: u32, offset: u64) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    state().offset_floor[ofd_id as usize] = offset;
}

pub fn set_offset_by_id(ofd_id: u32, offset: u64) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    table()[ofd_id as usize].offset = offset as i64;
    set_offset_floor_by_id(ofd_id, offset);
}

/// Get the current offset of the OFD associated with fd.
pub fn get_offset(base: u32, vm: &ThreadState, fd: u64) -> u64 {
    unsafe {
        get_fd_entry(base, vm, fd).map_or(0, |entry| {
            let ofd = table()[entry.ofd_id as usize];
            let offset = ofd.offset as u64;
            if ofd.fd_type == FD_TYPE_FILE {
                offset.max(get_offset_floor_by_id(entry.ofd_id))
            } else {
                offset
            }
        })
    }
}

/// Advance the offset of the OFD associated with fd.
pub fn advance_offset(base: u32, vm: &ThreadState, fd: u64, delta: u64) {
    unsafe {
        if let Some(entry) = get_fd_entry(base, vm, fd) {
            table()[entry.ofd_id as usize].offset += delta as i64;
            set_offset_floor_by_id(entry.ofd_id, table()[entry.ofd_id as usize].offset as u64);
        }
    }
}

/// Set the offset of the OFD associated with fd.
pub fn set_offset(base: u32, vm: &ThreadState, fd: u64, offset: u64) {
    unsafe {
        if let Some(entry) = get_fd_entry(base, vm, fd) {
            table()[entry.ofd_id as usize].offset = offset as i64;
            set_offset_floor_by_id(entry.ofd_id, offset);
        }
    }
}
