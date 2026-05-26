use crate::abi::*;
use crate::types::OpenFileDesc;

/// Pointer to OFD table in kernel Worker linear memory.
static mut OFD_TABLE_PTR: *mut [OpenFileDesc; MAX_FDS] = core::ptr::null_mut();
static mut OFD_RESERVED: [u64; (MAX_FDS + 63) / 64] = [0; (MAX_FDS + 63) / 64];
static mut OFD_OFFSET_FLOOR: [u64; MAX_FDS] = [0; MAX_FDS];

pub(in crate::fs) fn table() -> &'static mut [OpenFileDesc; MAX_FDS] {
    unsafe {
        let p = core::ptr::read(core::ptr::addr_of!(OFD_TABLE_PTR));
        &mut *p
    }
}

pub fn ofd_table_ptr() -> u32 {
    unsafe { core::ptr::read(core::ptr::addr_of!(OFD_TABLE_PTR)) as u32 }
}

pub fn ofd_table_bytes() -> u32 {
    core::mem::size_of::<[OpenFileDesc; MAX_FDS]>() as u32
}

pub fn attach_ofd_table_ptr(ptr: u32) {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(OFD_TABLE_PTR),
            ptr as *mut [OpenFileDesc; MAX_FDS],
        );
    }
}

/// Initialize OFD table. Allocates via alloc.rs.
pub fn init() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(OFD_TABLE_PTR),
            core::ptr::null_mut(),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(OFD_RESERVED),
            [0; (MAX_FDS + 63) / 64],
        );
        core::ptr::write(core::ptr::addr_of_mut!(OFD_OFFSET_FLOOR), [0; MAX_FDS]);

        let size = core::mem::size_of::<[OpenFileDesc; MAX_FDS]>() as u32;
        let align = core::mem::align_of::<OpenFileDesc>() as u32;
        let ptr = crate::alloc::alloc_zeroed(size, align);
        if ptr == 0 {
            core::arch::wasm32::unreachable();
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(OFD_TABLE_PTR),
            ptr as *mut [OpenFileDesc; MAX_FDS],
        );
    }
}

fn reserved_index(ofd_id: usize) -> bool {
    if ofd_id >= MAX_FDS {
        return false;
    }
    unsafe {
        let word = core::ptr::read(core::ptr::addr_of!(OFD_RESERVED[ofd_id / 64]));
        (word & (1u64 << (ofd_id % 64))) != 0
    }
}

pub fn ofd_reserved_ptr() -> u32 {
    core::ptr::addr_of!(OFD_RESERVED) as u32
}

pub fn ofd_reserved_bytes() -> u32 {
    core::mem::size_of::<[u64; (MAX_FDS + 63) / 64]>() as u32
}

pub fn reserve_ofd_id(ofd_id: u32) {
    let ofd_id = ofd_id as usize;
    if ofd_id == 0 || ofd_id >= MAX_FDS {
        return;
    }
    unsafe {
        let word_ptr = core::ptr::addr_of_mut!(OFD_RESERVED[ofd_id / 64]);
        let word = core::ptr::read(word_ptr);
        core::ptr::write(word_ptr, word | (1u64 << (ofd_id % 64)));
    }
}

pub fn unreserve_ofd_id(ofd_id: u32) {
    let ofd_id = ofd_id as usize;
    if ofd_id == 0 || ofd_id >= MAX_FDS {
        return;
    }
    unsafe {
        let word_ptr = core::ptr::addr_of_mut!(OFD_RESERVED[ofd_id / 64]);
        let word = core::ptr::read(word_ptr);
        core::ptr::write(word_ptr, word & !(1u64 << (ofd_id % 64)));
        if table()[ofd_id].refcount <= 0 {
            clear(&mut table()[ofd_id]);
        }
    }
}

pub fn is_ofd_reserved(ofd_id: u32) -> bool {
    reserved_index(ofd_id as usize)
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
    unsafe { core::ptr::read(core::ptr::addr_of!(OFD_OFFSET_FLOOR[ofd_id as usize])) }
}

pub fn set_offset_floor_by_id(ofd_id: u32, offset: u64) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(OFD_OFFSET_FLOOR[ofd_id as usize]),
            offset,
        );
    }
}

pub fn set_offset_by_id(ofd_id: u32, offset: u64) {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return;
    }
    table()[ofd_id as usize].offset = offset as i64;
    set_offset_floor_by_id(ofd_id, offset);
}
