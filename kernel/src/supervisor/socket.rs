use crate::abi::{FD_TYPE_SOCKET, MAX_FDS};
use crate::fs::fd_table;

fn is_socket_ofd_id(ofd_id: u32) -> bool {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return false;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return false;
    };
    ofd.fd_type == FD_TYPE_SOCKET && crate::syscall::socket::is_slot_used(ofd.ino)
}

pub fn socket_ofd_is_socket(ofd_id: u32) -> i32 {
    i32::from(is_socket_ofd_id(ofd_id))
}

pub fn process_socket_ofd_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    let vm = match thread_state(vm_ptr) {
        Ok(vm) => vm,
        Err(_) => return 0,
    };
    let ofd_id = fd_table::get_ofd_id(vm.guest_base, vm, fd as u64).unwrap_or(0);
    if is_socket_ofd_id(ofd_id) { ofd_id } else { 0 }
}

pub fn process_socket_drain_fd(vm_ptr: u32, connected_fd: u32, index: u32) -> i32 {
    let vm = match thread_state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    let connected_ofd = fd_table::get_ofd_id(vm.guest_base, vm, connected_fd as u64).unwrap_or(0);
    if !is_socket_ofd_id(connected_ofd) {
        return crate::abi::ENOENT as i32;
    }
    let mut cursor = 0u32;
    let mut result = crate::abi::ENOENT as i32;
    if cursor == index {
        return connected_fd as i32;
    }
    cursor = cursor.saturating_add(1);
    for fd in 0..MAX_FDS {
        if fd as u32 == connected_fd {
            continue;
        }
        if fd_table::get_ofd_id(vm.guest_base, vm, fd as u64).unwrap_or(0) != connected_ofd {
            continue;
        }
        if cursor == index {
            result = fd as i32;
            break;
        }
        cursor = cursor.saturating_add(1);
    }
    result
}

pub fn process_socket_held_ofd(vm_ptr: u32, index: u32) -> u32 {
    let mut seen = [false; MAX_FDS];
    let mut cursor = 0u32;
    let mut result = 0u32;
    super::fd::for_each_process_held_ofd(vm_ptr, |ofd_id, ofd| {
        if result != 0 || ofd_id as usize >= MAX_FDS || seen[ofd_id as usize] {
            return;
        }
        seen[ofd_id as usize] = true;
        if ofd.fd_type != FD_TYPE_SOCKET {
            return;
        }
        if !is_socket_ofd_id(ofd_id) {
            return;
        }
        if cursor == index {
            result = ofd_id;
        }
        cursor = cursor.saturating_add(1);
    });
    result
}

fn thread_state(vm_ptr: u32) -> Result<&'static crate::types::ThreadState, i32> {
    super::thread::state_from_ptr(vm_ptr).ok_or(crate::abi::EFAULT as i32)
}

pub fn connect_fd(vm_ptr: u32) -> i32 {
    match thread_state(vm_ptr) {
        Ok(vm) => crate::syscall::socket::thread_connect_fd(vm),
        Err(errno) => -errno,
    }
}

pub fn connect_peer_addr(vm_ptr: u32, dst_ptr: u32, dst_len: u32) -> i32 {
    let vm = match thread_state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    let Some(dst_end) = (dst_ptr as usize).checked_add(dst_len as usize) else {
        return crate::abi::EFAULT as i32;
    };
    let memory_size = crate::wasm::memory_size_bytes() as usize;
    if dst_ptr == 0 || dst_end > memory_size {
        return crate::abi::EFAULT as i32;
    }
    let dst = unsafe { core::slice::from_raw_parts_mut(dst_ptr as *mut u8, dst_len as usize) };
    crate::syscall::socket::connect_peer_addr(vm, dst)
}

pub fn connect_peer_addr_for_fd(vm_ptr: u32, fd: u32, dst_ptr: u32, dst_len: u32) -> i32 {
    let vm = match thread_state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    let Some(dst_end) = (dst_ptr as usize).checked_add(dst_len as usize) else {
        return crate::abi::EFAULT as i32;
    };
    let memory_size = crate::wasm::memory_size_bytes() as usize;
    if dst_ptr == 0 || dst_end > memory_size {
        return crate::abi::EFAULT as i32;
    }
    let dst = unsafe { core::slice::from_raw_parts_mut(dst_ptr as *mut u8, dst_len as usize) };
    crate::syscall::socket::connect_peer_addr_for_fd(vm.guest_base, vm, fd as u64, dst)
}

pub fn prepare_external_peer(vm_ptr: u32, fd: u32) -> i32 {
    let vm = match thread_state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    let result = crate::syscall::socket::mark_external_peer_for_fd(vm.guest_base, vm, fd as u64);
    if result == 0 {
        return 0;
    }
    crate::syscall::socket::commit_external_connect_for_fd(vm.guest_base, vm, fd as u64)
}

pub fn commit_external_connect_result(vm_ptr: u32, fd: u32, result: i64) -> i32 {
    let vm = match thread_state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    if result != 0 && result != crate::abi::EINPROGRESS {
        return 0;
    }
    i32::from(prepare_external_peer(vm_ptr, fd) == 0 && vm.status == crate::abi::STATUS_OK)
}

pub fn close_external_peer(vm_ptr: u32, fd: u32) -> i32 {
    let vm = match thread_state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    crate::syscall::socket::close_external_peer_for_fd(vm.guest_base, vm, fd as u64)
}

pub fn force_shutdown(vm_ptr: u32, fd: u32) -> i32 {
    let vm = match thread_state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    crate::syscall::socket::force_shutdown_for_fd(vm.guest_base, vm, fd as u64)
}

pub fn bridge_active_fd(
    vm_ptr: u32,
    preferred_fd: u32,
    expected_ofd: u32,
    pending_connect: u32,
) -> i32 {
    let vm = match thread_state(vm_ptr) {
        Ok(vm) => vm,
        Err(errno) => return -errno,
    };
    if expected_ofd > 0
        && fd_table::get_ofd_id(vm.guest_base, vm, preferred_fd as u64).unwrap_or(0) == expected_ofd
    {
        return preferred_fd as i32;
    }
    if expected_ofd > 0 {
        for fd in 0..MAX_FDS {
            if fd as u32 == preferred_fd {
                continue;
            }
            if fd_table::get_ofd_id(vm.guest_base, vm, fd as u64).unwrap_or(0) == expected_ofd {
                return fd as i32;
            }
        }
    }
    let current_ofd = fd_table::get_ofd_id(vm.guest_base, vm, preferred_fd as u64).unwrap_or(0);
    if current_ofd > 0 && pending_connect == 0 {
        if is_socket_ofd_id(current_ofd) {
            return preferred_fd as i32;
        }
    }
    crate::abi::ENOENT as i32
}
