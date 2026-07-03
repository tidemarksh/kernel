use crate::abi::{FD_TYPE_EPOLL, FD_TYPE_EVENTFD, FD_TYPE_TIMERFD, MAX_FDS};
use crate::fs::fd_table;
use crate::types::OpenFileDesc;

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

fn for_each_unique_watched_ofd<F>(epoll_ofd: OpenFileDesc, seen: &mut [bool; MAX_FDS], mut f: F)
where
    F: FnMut(u32),
{
    if epoll_ofd.fd_type != FD_TYPE_EPOLL {
        return;
    }
    crate::syscall::epoll::for_each_watched_ofd(epoll_ofd.ino, |watched_ofd_id| {
        if watched_ofd_id == 0 || watched_ofd_id as usize >= MAX_FDS {
            return;
        }
        if seen[watched_ofd_id as usize] {
            return;
        }
        seen[watched_ofd_id as usize] = true;
        f(watched_ofd_id);
    });
}

pub fn process_epoll_dependent_ofd(vm_ptr: u32, index: u32) -> u32 {
    let mut seen_epoll = [false; MAX_FDS];
    let mut seen_dependent = [false; MAX_FDS];
    let mut cursor = 0u32;
    let mut result = 0u32;
    super::fd::for_each_process_held_ofd(vm_ptr, |epoll_ofd_id, epoll_ofd| {
        if result != 0 || epoll_ofd_id as usize >= MAX_FDS || seen_epoll[epoll_ofd_id as usize] {
            return;
        }
        seen_epoll[epoll_ofd_id as usize] = true;
        if epoll_ofd.fd_type != FD_TYPE_EPOLL {
            return;
        }
        for_each_unique_watched_ofd(epoll_ofd, &mut seen_dependent, |watched_ofd_id| {
            if result != 0 {
                return;
            }
            if cursor == index {
                result = watched_ofd_id;
            }
            cursor = cursor.saturating_add(1);
        });
    });
    result
}

fn blocked_epoll_ofd(vm_ptr: u32) -> Option<OpenFileDesc> {
    let vm = super::thread::state_from_ptr(vm_ptr)?;
    let ofd = if vm.blocked_ofd_id != 0 {
        fd_table::get_ofd_by_id(vm.blocked_ofd_id)
    } else {
        let fd = if vm.blocked_fd != 0 {
            vm.blocked_fd as u64
        } else {
            vm.fault_addr
        };
        fd_table::get_ofd(vm.guest_base, vm, fd)
    }?;
    (ofd.fd_type == FD_TYPE_EPOLL).then_some(ofd)
}

pub fn blocked_epoll_watched_ofd(vm_ptr: u32, index: u32) -> u32 {
    let Some(epoll_ofd) = blocked_epoll_ofd(vm_ptr) else {
        return 0;
    };
    let mut seen = [false; MAX_FDS];
    let mut cursor = 0u32;
    let mut result = 0u32;
    for_each_unique_watched_ofd(epoll_ofd, &mut seen, |watched_ofd_id| {
        if result != 0 {
            return;
        }
        if cursor == index {
            result = watched_ofd_id;
        }
        cursor = cursor.saturating_add(1);
    });
    result
}

pub fn blocked_epoll_dependent_sync_ofd(vm_ptr: u32, index: u32) -> u32 {
    let Some(epoll_ofd) = blocked_epoll_ofd(vm_ptr) else {
        return 0;
    };
    let mut seen = [false; MAX_FDS];
    let mut cursor = 0u32;
    let mut result = 0u32;
    for_each_unique_watched_ofd(epoll_ofd, &mut seen, |watched_ofd_id| {
        if result != 0 {
            return;
        }
        let Some(ofd) = fd_table::get_ofd_by_id(watched_ofd_id) else {
            return;
        };
        if ofd.fd_type != FD_TYPE_EVENTFD && ofd.fd_type != FD_TYPE_TIMERFD {
            return;
        }
        if cursor == index {
            result = watched_ofd_id;
        }
        cursor = cursor.saturating_add(1);
    });
    result
}

pub fn blocked_epoll_watches_pipe(vm_ptr: u32) -> u32 {
    let Some(epoll_ofd) = blocked_epoll_ofd(vm_ptr) else {
        return 0;
    };
    let mut seen = [false; MAX_FDS];
    let mut watches_pipe = false;
    for_each_unique_watched_ofd(epoll_ofd, &mut seen, |watched_ofd_id| {
        if watches_pipe {
            return;
        }
        if let Some(ofd) = fd_table::get_ofd_by_id(watched_ofd_id) {
            watches_pipe = ofd.fd_type == crate::abi::FD_TYPE_PIPE;
        }
    });
    watches_pipe as u32
}
