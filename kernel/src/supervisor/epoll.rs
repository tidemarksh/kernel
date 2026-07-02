use crate::abi::{FD_TYPE_EPOLL, MAX_FDS};

pub fn process_epoll_held_ofd(vm_ptr: u32, index: u32) -> u32 {
    let mut seen = [false; MAX_FDS];
    let mut cursor = 0u32;
    let mut result = 0u32;
    super::fd::for_each_process_held_ofd(vm_ptr, |ofd_id, ofd| {
        if result != 0 || ofd_id as usize >= MAX_FDS || seen[ofd_id as usize] {
            return;
        }
        seen[ofd_id as usize] = true;
        if ofd.fd_type != FD_TYPE_EPOLL {
            return;
        }
        if cursor == index {
            result = ofd_id;
        }
        cursor = cursor.saturating_add(1);
    });
    result
}
