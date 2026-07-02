use crate::abi::{
    FD_TYPE_PIPE, FD_TYPE_PTY_MASTER, FD_TYPE_PTY_SLAVE, MAX_FDS, MAX_PIPES, O_RDONLY, O_WRONLY,
    STATUS_PIPE_WAIT, SYS_READ,
};
use crate::fs::fd_table;
use crate::types::{OpenFileDesc, ProcessState, ThreadState};

fn valid_pipe_slot(pipe_slot: u32) -> bool {
    pipe_slot > 0 && (pipe_slot as usize) < MAX_PIPES && pipe_slot < 64
}

fn pipe_bit(pipe_slot: u32) -> u64 {
    if valid_pipe_slot(pipe_slot) {
        1u64 << pipe_slot
    } else {
        0
    }
}

fn private_pipe_slot_mask_for_process(ps: &ProcessState) -> u64 {
    pipe_bit(ps.stdin_pipe_slot) | pipe_bit(ps.stdout_pipe_slot) | pipe_bit(ps.stderr_pipe_slot)
}

fn private_pipe_source_mode_for_process(ps: &ProcessState, pipe_slot: u32) -> u32 {
    if pipe_bit(pipe_slot) & private_pipe_slot_mask_for_process(ps) == 0 {
        return 0;
    }
    super::SUPERVISOR_PIPE_SLOT_MODE_READ | super::SUPERVISOR_PIPE_SLOT_MODE_WRITE
}

fn private_pipe_target_mode_for_process(ps: &ProcessState, pipe_slot: u32) -> u32 {
    if pipe_bit(pipe_slot) & private_pipe_slot_mask_for_process(ps) == 0 {
        return 0;
    }
    super::SUPERVISOR_PIPE_SLOT_MODE_READ
}

fn for_each_ofd_pipe_mode<F>(ofd: OpenFileDesc, mut f: F)
where
    F: FnMut(u32, u32),
{
    if ofd.fd_type == FD_TYPE_PIPE {
        if fd_table::is_pipe_read(&ofd) {
            f(ofd.ino, super::SUPERVISOR_PIPE_SLOT_MODE_READ);
        } else if fd_table::is_pipe_write(&ofd) {
            f(ofd.ino, super::SUPERVISOR_PIPE_SLOT_MODE_WRITE);
        }
        return;
    }

    if ofd.fd_type != FD_TYPE_PTY_SLAVE && ofd.fd_type != FD_TYPE_PTY_MASTER {
        return;
    }

    let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
    let input_pipe = crate::syscall::pty::input_pipe_slot(ofd.ino);
    let output_pipe = crate::syscall::pty::output_pipe_slot(ofd.ino);
    if ofd.fd_type == FD_TYPE_PTY_SLAVE {
        if access_mode != O_WRONLY {
            f(input_pipe, super::SUPERVISOR_PIPE_SLOT_MODE_READ);
        }
        if access_mode != O_RDONLY {
            f(output_pipe, super::SUPERVISOR_PIPE_SLOT_MODE_WRITE);
        }
        return;
    }

    if access_mode != O_WRONLY {
        f(output_pipe, super::SUPERVISOR_PIPE_SLOT_MODE_READ);
    }
    if access_mode != O_RDONLY {
        f(input_pipe, super::SUPERVISOR_PIPE_SLOT_MODE_WRITE);
    }
}

pub fn process_private_pipe_slot_mask(vm_ptr: u32) -> u64 {
    super::fd::process_state_from_vm_ptr(vm_ptr).map_or(0, private_pipe_slot_mask_for_process)
}

pub fn process_private_pipe_source_mode(vm_ptr: u32, pipe_slot: u32) -> u32 {
    if !valid_pipe_slot(pipe_slot) {
        return 0;
    }
    super::fd::process_state_from_vm_ptr(vm_ptr)
        .map_or(0, |ps| private_pipe_source_mode_for_process(ps, pipe_slot))
}

pub fn process_private_pipe_target_mode(vm_ptr: u32, pipe_slot: u32) -> u32 {
    if !valid_pipe_slot(pipe_slot) {
        return 0;
    }
    super::fd::process_state_from_vm_ptr(vm_ptr)
        .map_or(0, |ps| private_pipe_target_mode_for_process(ps, pipe_slot))
}

pub fn process_held_pipe_slot_mask(vm_ptr: u32) -> u64 {
    let private_mask = process_private_pipe_slot_mask(vm_ptr);
    let mut mask = 0u64;
    super::fd::for_each_process_held_ofd(vm_ptr, |_ofd_id, ofd| {
        for_each_ofd_pipe_mode(ofd, |pipe_slot, _mode| {
            let bit = pipe_bit(pipe_slot);
            if bit != 0 && (private_mask & bit) == 0 {
                mask |= bit;
            }
        });
    });
    mask
}

pub fn process_pipe_used_mask(vm_ptr: u32) -> u64 {
    1 | process_private_pipe_slot_mask(vm_ptr) | process_held_pipe_slot_mask(vm_ptr)
}

pub fn process_pipe_slot_mode(vm_ptr: u32, pipe_slot: u32) -> u32 {
    if !valid_pipe_slot(pipe_slot) {
        return 0;
    }
    let private_mask = process_private_pipe_slot_mask(vm_ptr);
    if (private_mask & pipe_bit(pipe_slot)) != 0 {
        return 0;
    }

    let mut mode = 0u32;
    super::fd::for_each_process_held_ofd(vm_ptr, |_ofd_id, ofd| {
        for_each_ofd_pipe_mode(ofd, |candidate, candidate_mode| {
            if candidate == pipe_slot {
                mode |= candidate_mode;
            }
        });
    });
    mode
}

fn process_pipe_open_count(vm_ptr: u32, pipe_slot: u32, requested_mode: u32) -> i32 {
    if !valid_pipe_slot(pipe_slot) {
        return 0;
    }
    let private_count = super::fd::process_state_from_vm_ptr(vm_ptr).map_or(0, |ps| {
        let mut count = 0i32;
        if ps.stdin_pipe_slot == pipe_slot
            && (requested_mode & super::SUPERVISOR_PIPE_SLOT_MODE_WRITE) != 0
        {
            count += 1;
        }
        if ps.stdout_pipe_slot == pipe_slot
            && (requested_mode & super::SUPERVISOR_PIPE_SLOT_MODE_READ) != 0
        {
            count += 1;
        }
        if ps.stderr_pipe_slot == pipe_slot
            && (requested_mode & super::SUPERVISOR_PIPE_SLOT_MODE_READ) != 0
        {
            count += 1;
        }
        count
    });
    let mut seen = [false; MAX_FDS];
    super::fd::for_each_process_held_ofd(vm_ptr, |ofd_id, ofd| {
        if ofd_id as usize >= MAX_FDS || seen[ofd_id as usize] {
            return;
        }
        let mut matched = false;
        for_each_ofd_pipe_mode(ofd, |candidate, mode| {
            if candidate == pipe_slot && (mode & requested_mode) != 0 {
                matched = true;
            }
        });
        if matched {
            seen[ofd_id as usize] = true;
        }
    });
    private_count + seen.iter().filter(|held| **held).count() as i32
}

pub fn process_pipe_read_open_count(vm_ptr: u32, pipe_slot: u32) -> i32 {
    process_pipe_open_count(vm_ptr, pipe_slot, super::SUPERVISOR_PIPE_SLOT_MODE_READ)
}

pub fn process_pipe_write_open_count(vm_ptr: u32, pipe_slot: u32) -> i32 {
    process_pipe_open_count(vm_ptr, pipe_slot, super::SUPERVISOR_PIPE_SLOT_MODE_WRITE)
}

fn blocked_pipe_fd(vm: &ThreadState) -> u64 {
    if vm.blocked_ofd_id != 0 {
        vm.blocked_fd as u64
    } else if vm.blocked_syscall_nr != 0 {
        vm.blocked_syscall_args[0]
    } else {
        vm.x[10]
    }
}

fn blocked_pipe_ofd(vm: &ThreadState) -> Option<OpenFileDesc> {
    if vm.blocked_ofd_id != 0 {
        return fd_table::get_ofd_by_id(vm.blocked_ofd_id);
    }
    fd_table::get_ofd(vm.guest_base, vm, blocked_pipe_fd(vm))
}

fn blocked_pipe_read_syscall(vm: &ThreadState) -> bool {
    vm.blocked_syscall_nr == SYS_READ || (vm.blocked_syscall_nr == 0 && vm.x[17] == SYS_READ)
}

fn blocked_pipe_directly_ready(vm_ptr: u32, vm: &ThreadState) -> bool {
    if crate::syscall::poll::wait_set_ready_count(vm, vm.guest_base) > 0 {
        return true;
    }
    if crate::exports::thread::thread_blocked_pipe_read_ready(vm_ptr) == 1
        || crate::exports::thread::thread_blocked_pipe_write_ready(vm_ptr) == 1
    {
        return true;
    }
    if !blocked_pipe_read_syscall(vm) {
        return false;
    }
    let Some(ofd) = blocked_pipe_ofd(vm) else {
        return false;
    };
    if ofd.fd_type != FD_TYPE_PIPE || !fd_table::is_pipe_read(&ofd) {
        return false;
    }
    crate::syscall::pipe::pipe_buffered_len(ofd.ino) > 0
        || crate::syscall::pipe::debug_write_open(ofd.ino) <= 0
}

pub fn blocked_pipe_resume_action(vm_ptr: u32) -> i32 {
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return -(crate::abi::EFAULT as i32);
    };
    if vm.status != STATUS_PIPE_WAIT {
        return super::SUPERVISOR_BLOCKED_PIPE_RESUME_ACTION_DEFER as i32;
    }
    if super::blocked::blocked_wait_active_child_pid(vm_ptr) > 0 {
        return super::SUPERVISOR_BLOCKED_PIPE_RESUME_ACTION_DEFER as i32;
    }
    if blocked_pipe_directly_ready(vm_ptr, vm) {
        return super::SUPERVISOR_BLOCKED_PIPE_RESUME_ACTION_DIRECT as i32;
    }
    super::SUPERVISOR_BLOCKED_PIPE_RESUME_ACTION_DEFER as i32
}
