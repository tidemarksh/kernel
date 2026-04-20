use crate::abi::*;

#[unsafe(no_mangle)]
pub extern "C" fn memfs_resolve_path(path_ptr: u32, path_len: u32) -> u32 {
    let path = unsafe { core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize) };
    crate::fs::memfs::resolve_path(path)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_lookup(parent_ino: u32, name_ptr: u32, name_len: u32) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    crate::fs::memfs::lookup(parent_ino, name)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_create_file(parent_ino: u32, name_ptr: u32, name_len: u32) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    crate::fs::memfs::create_file(parent_ino, name, 0o644)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_unlink(parent_ino: u32, name_ptr: u32, name_len: u32) -> i64 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    crate::fs::memfs::unlink(parent_ino, name)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_rmdir(parent_ino: u32, name_ptr: u32, name_len: u32) -> i64 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    crate::fs::memfs::rmdir(parent_ino, name)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_inode_count() -> u32 {
    crate::fs::memfs::memfs_inode_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_dir_entry_count() -> u32 {
    crate::fs::memfs::memfs_dir_entry_count()
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_data_used() -> u32 {
    crate::fs::memfs::memfs_data_used()
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_data_cap() -> u32 {
    crate::fs::memfs::memfs_data_cap()
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_last_create_symlink_stage() -> u32 {
    crate::fs::memfs::last_create_symlink_stage()
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_last_create_symlink_arg0() -> u64 {
    crate::fs::memfs::last_create_symlink_arg0()
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_last_create_symlink_arg1() -> u64 {
    crate::fs::memfs::last_create_symlink_arg1()
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_reserve_inode_until(target_ino: u32) -> i64 {
    crate::fs::memfs::reserve_inode_until(target_ino)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_write_file_at(ino: u32, offset: u64, data_ptr: u32, data_len: u32) -> i64 {
    let data = unsafe { core::slice::from_raw_parts(data_ptr as *const u8, data_len as usize) };
    crate::fs::memfs::write_file(ino, offset, data)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_read_file_to(ino: u32, offset: u64, buf_ptr: u32, buf_len: u32) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize) };
    crate::fs::memfs::read_file(ino, offset, buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_file_size(ino: u32) -> u64 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.size)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_truncate_file(ino: u32, size: u64) -> i64 {
    crate::fs::memfs::truncate(ino, size)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_set_file_size_shallow(ino: u32, size: u64) -> i64 {
    crate::fs::memfs::set_file_size_shallow(ino, size)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_set_file_external(ino: u32, size: u64) -> i64 {
    crate::fs::memfs::set_file_external(ino, size)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_inode_mode(ino: u32) -> u32 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_inode_nlink(ino: u32) -> u32 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.nlink)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_inode_uid(ino: u32) -> u32 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.uid)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_inode_gid(ino: u32) -> u32 {
    crate::fs::memfs::stat(ino).map_or(0, |s| s.gid)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_read_link(ino: u32, buf_ptr: u32, buf_len: u32) -> i64 {
    if buf_ptr == 0 {
        return EFAULT;
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize) };
    crate::fs::memfs::read_link(ino, buf) as i64
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_set_mode(ino: u32, mode: u32) -> i64 {
    crate::fs::memfs::set_mode(ino, mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_ensure_dir(
    parent_ino: u32,
    name_ptr: u32,
    name_len: u32,
    mode: u32,
) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    let existing = crate::fs::memfs::lookup(parent_ino, name);
    if existing != 0 {
        return existing;
    }
    crate::fs::memfs::create_dir(parent_ino, name, mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_create_symlink(
    parent_ino: u32,
    name_ptr: u32,
    name_len: u32,
    target_ptr: u32,
    target_len: u32,
) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    let target =
        unsafe { core::slice::from_raw_parts(target_ptr as *const u8, target_len as usize) };
    crate::fs::memfs::create_symlink(parent_ino, name, target)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_create_file_with_data(
    parent_ino: u32,
    name_ptr: u32,
    name_len: u32,
    data_ptr: u32,
    data_len: u32,
) -> u32 {
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    let data = unsafe { core::slice::from_raw_parts(data_ptr as *const u8, data_len as usize) };
    crate::fs::memfs::create_file_with_data(parent_ino, name, data)
}

#[unsafe(no_mangle)]
pub extern "C" fn memfs_readdir_names(dir_ino: u32, buf_ptr: u32, buf_len: u32) -> i64 {
    if buf_ptr == 0 {
        return EFAULT;
    }

    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize) };
    let mut written = 0usize;
    let mut overflow = false;

    let result = crate::fs::memfs::readdir(dir_ino, |name, _ino| {
        let needed = name.len().saturating_add(1);
        if overflow || written.saturating_add(needed) > buf.len() {
            overflow = true;
            return;
        }

        buf[written..written + name.len()].copy_from_slice(name);
        written += name.len();
        buf[written] = 0;
        written += 1;
    });

    if result < 0 {
        return result;
    }
    if overflow {
        return ENOSPC;
    }

    written as i64
}
