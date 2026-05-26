use crate::abi::*;
use crate::fs::{fd_table, memfs};
use crate::guest_mem;
use crate::types::ThreadState;

const DT_UNKNOWN: u8 = 0;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

// =========================================================================
// getdents64
// =========================================================================

fn write_dirent64(
    base: u32,
    buf: u64,
    offset: u64,
    max: u64,
    ino: u64,
    d_type: u8,
    name: &[u8],
) -> Option<u64> {
    // d_reclen = 19 + name_len + 1 (NUL) + padding to 8-byte alignment.
    let reclen = ((19 + name.len() + 1) + 7) & !7;
    if offset + reclen as u64 > max {
        return None;
    }

    let entry_addr = buf + offset;
    unsafe {
        guest_mem::zero_mem(base, entry_addr, reclen);
        guest_mem::write_u64(base, entry_addr, ino);
        guest_mem::write_u64(base, entry_addr + 8, offset + reclen as u64);
        guest_mem::write_u16(base, entry_addr + 16, reclen as u16);
        guest_mem::write_u8(base, entry_addr + 18, d_type);
        guest_mem::write_bytes(base, entry_addr + 19, name);
        guest_mem::write_u8(base, entry_addr + 19 + name.len() as u64, 0);
    }
    Some(reclen as u64)
}

fn proc_self_fd_dir_ino() -> u32 {
    memfs::resolve_path(b"/proc/self/fd")
}

fn u32_decimal_bytes(value: u32, out: &mut [u8; 10]) -> &[u8] {
    if value == 0 {
        out[9] = b'0';
        return &out[9..10];
    }

    let mut value = value;
    let mut cursor = out.len();
    while value > 0 {
        cursor -= 1;
        out[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    &out[cursor..]
}

fn sys_getdents64_proc_self_fd(
    vm: &mut ThreadState,
    base: u32,
    fd: u64,
    start_index: u64,
    buf: u64,
    buf_size: u64,
) -> i64 {
    let mut offset = 0u64;
    let mut entry_index = 0u64;

    for proc_fd in 0..MAX_FDS {
        let entry = fd_table::load_process_fd_entry(base, vm.process_ptr, proc_fd);
        if entry.ofd_id == 0 {
            continue;
        }
        if entry_index < start_index {
            entry_index += 1;
            continue;
        }

        let mut name_buf = [0u8; 10];
        let name = u32_decimal_bytes(proc_fd as u32, &mut name_buf);
        match write_dirent64(base, buf, offset, buf_size, proc_fd as u64, DT_LNK, name) {
            Some(written) => {
                offset += written;
                entry_index += 1;
            }
            None => {
                break;
            }
        }
    }

    fd_table::set_offset(base, vm, fd, entry_index);
    offset as i64
}

/// getdents64: read directory entries into guest buffer.
/// Writes linux_dirent64 records (variable-size, 8-byte aligned).
pub fn sys_getdents64(vm: &mut ThreadState, base: u32, fd: u64, buf: u64, buf_size: u64) -> i64 {
    let ofd = match fd_table::get_ofd(base, vm, fd) {
        Some(o) => o,
        None => return EBADF,
    };

    let dir_ino = ofd.ino;
    let start_index = ofd.offset.max(0) as u64;
    if dir_ino == proc_self_fd_dir_ino() {
        return sys_getdents64_proc_self_fd(vm, base, fd, start_index, buf, buf_size);
    }

    let mut offset = 0u64;
    let max = buf_size;
    let mut entry_index = 0u64;
    let mut buffer_full = false;

    let readdir_result = memfs::readdir(dir_ino, |name, ino| {
        if buffer_full {
            return;
        }
        if entry_index < start_index {
            entry_index += 1;
            return;
        }

        let st = memfs::stat(ino);
        let d_type = match st {
            Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFDIR => DT_DIR,
            Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFREG => DT_REG,
            Some(ref s) if s.mode & memfs::S_IFMT == memfs::S_IFLNK => DT_LNK,
            _ => DT_UNKNOWN,
        };
        match write_dirent64(base, buf, offset, max, ino as u64, d_type, name) {
            Some(written) => {
                offset += written;
                entry_index += 1;
            }
            None => {
                buffer_full = true;
            }
        }
    });
    if readdir_result < 0 {
        return readdir_result;
    }

    fd_table::set_offset(base, vm, fd, entry_index);
    offset as i64
}
