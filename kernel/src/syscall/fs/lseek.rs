use super::read_write::mark_fork_shared_ofd_sync_effect;
use crate::abi::*;
use crate::fs::{fd_table, memfs};
use crate::types::ThreadState;

// =========================================================================
// lseek
// =========================================================================

/// lseek: reposition OFD offset. Supports SEEK_SET (0), SEEK_CUR (1), SEEK_END (2).
pub fn sys_lseek(vm: &mut ThreadState, base: u32, fd: u64, offset: i64, whence: u64) -> i64 {
    let ofd_id = match fd_table::get_ofd_id(base, vm, fd) {
        Some(id) => id,
        None => return EBADF,
    };
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };
    if fd_table::is_nonseekable_fd_type(ofd.fd_type) {
        return ESPIPE;
    }
    let current_offset = if ofd.fd_type == FD_TYPE_FILE {
        (ofd.offset as u64).max(fd_table::get_offset_floor_by_id(ofd_id))
    } else {
        ofd.offset as u64
    };

    let new_offset_i64 = match whence {
        0 => offset,                         // SEEK_SET
        1 => current_offset as i64 + offset, // SEEK_CUR
        2 => {
            // SEEK_END
            let st = memfs::stat(ofd.ino);
            match st {
                Some(s) => s.size as i64 + offset,
                None => return EINVAL,
            }
        }
        _ => return EINVAL,
    };
    if new_offset_i64 < 0 {
        return EINVAL;
    }
    let new_offset = new_offset_i64 as u64;

    fd_table::set_offset(base, vm, fd, new_offset);
    mark_fork_shared_ofd_sync_effect(vm);
    new_offset as i64
}
