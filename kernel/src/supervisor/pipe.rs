use core::sync::atomic::{AtomicU32, Ordering};

use crate::abi::{
    FD_TYPE_PIPE, FD_TYPE_PTY_MASTER, FD_TYPE_PTY_SLAVE, MAX_FDS, MAX_PIPES, O_RDONLY, O_RDWR,
    O_WRONLY, STATUS_PIPE_WAIT, SYS_READ,
};
use crate::fs::fd_table;
use crate::types::{OpenFileDesc, ProcessState, ThreadState};

const PIPE_SYNC_BEFORE_RETRY_CAP: usize = 256;

#[derive(Clone, Copy)]
struct PipeSyncBeforeRetryState {
    vm_ptr: u32,
    status: i32,
    syscall_nr: u64,
    args: [u64; 6],
    timeout_ms: i64,
    fault_addr: u64,
    sync_requested: u32,
}

impl PipeSyncBeforeRetryState {
    const fn empty() -> Self {
        Self {
            vm_ptr: 0,
            status: 0,
            syscall_nr: 0,
            args: [0; 6],
            timeout_ms: 0,
            fault_addr: 0,
            sync_requested: 0,
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.vm_ptr == other.vm_ptr
            && self.status == other.status
            && self.syscall_nr == other.syscall_nr
            && self.args == other.args
            && self.timeout_ms == other.timeout_ms
            && self.fault_addr == other.fault_addr
    }
}

static PIPE_SYNC_BEFORE_RETRY_LOCK: AtomicU32 = AtomicU32::new(0);
static PIPE_SYNC_BEFORE_RETRY_CURSOR: AtomicU32 = AtomicU32::new(0);
static mut PIPE_SYNC_BEFORE_RETRY_STATE: [PipeSyncBeforeRetryState; PIPE_SYNC_BEFORE_RETRY_CAP] =
    [PipeSyncBeforeRetryState::empty(); PIPE_SYNC_BEFORE_RETRY_CAP];

fn with_pipe_sync_before_retry_lock<T>(
    f: impl FnOnce(&mut [PipeSyncBeforeRetryState; PIPE_SYNC_BEFORE_RETRY_CAP]) -> T,
) -> T {
    loop {
        if PIPE_SYNC_BEFORE_RETRY_LOCK
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
    let state_ptr = core::ptr::addr_of_mut!(PIPE_SYNC_BEFORE_RETRY_STATE);
    let result = unsafe { f(&mut *state_ptr) };
    PIPE_SYNC_BEFORE_RETRY_LOCK.store(0, Ordering::Release);
    result
}

pub(super) fn init() {
    with_pipe_sync_before_retry_lock(|states| {
        PIPE_SYNC_BEFORE_RETRY_CURSOR.store(0, Ordering::Relaxed);
        for state in states.iter_mut() {
            *state = PipeSyncBeforeRetryState::empty();
        }
    });
}

fn blocked_or_current_syscall_nr(vm: &ThreadState) -> u64 {
    if vm.blocked_syscall_nr != 0 {
        vm.blocked_syscall_nr
    } else {
        vm.x[17]
    }
}

fn blocked_or_current_syscall_args(vm: &ThreadState) -> [u64; 6] {
    if vm.blocked_syscall_nr != 0 {
        vm.blocked_syscall_args
    } else {
        [vm.x[10], vm.x[11], vm.x[12], vm.x[13], vm.x[14], vm.x[15]]
    }
}

fn pipe_sync_before_retry_signature(vm_ptr: u32, vm: &ThreadState) -> PipeSyncBeforeRetryState {
    PipeSyncBeforeRetryState {
        vm_ptr,
        status: vm.status,
        syscall_nr: blocked_or_current_syscall_nr(vm),
        args: blocked_or_current_syscall_args(vm),
        timeout_ms: vm.epoll_timeout_ms,
        fault_addr: vm.fault_addr,
        sync_requested: 0,
    }
}

fn pipe_sync_before_retry_slot(
    states: &mut [PipeSyncBeforeRetryState; PIPE_SYNC_BEFORE_RETRY_CAP],
    signature: PipeSyncBeforeRetryState,
) -> usize {
    for (idx, state) in states.iter().enumerate() {
        if state.matches(&signature) {
            return idx;
        }
    }
    for (idx, state) in states.iter_mut().enumerate() {
        if state.vm_ptr == 0 {
            *state = signature;
            return idx;
        }
    }
    let idx = PIPE_SYNC_BEFORE_RETRY_CURSOR.fetch_add(1, Ordering::Relaxed) as usize
        % PIPE_SYNC_BEFORE_RETRY_CAP;
    states[idx] = signature;
    idx
}

fn pipe_sync_before_retry_requested_for_signature(signature: PipeSyncBeforeRetryState) -> bool {
    with_pipe_sync_before_retry_lock(|states| {
        states
            .iter()
            .any(|state| state.matches(&signature) && state.sync_requested != 0)
    })
}

fn pipe_sync_before_retry_clear_for_vm(vm_ptr: u32) {
    with_pipe_sync_before_retry_lock(|states| {
        for state in states.iter_mut() {
            if state.vm_ptr == vm_ptr {
                *state = PipeSyncBeforeRetryState::empty();
            }
        }
    });
}

fn pipe_sync_before_retry_readiness_sync_pending(vm: &ThreadState) -> bool {
    vm.fault_addr == crate::syscall::fs::PIPE_READ_EOF_SYNC_RETRY_MARKER
        || crate::syscall::poll::poll_hup_sync_pending(vm)
}

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

pub fn ofd_pipe_slot_mask(ofd_id: u32) -> u64 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    let mut mask = 0u64;
    for_each_ofd_pipe_mode(ofd, |pipe_slot, _mode| {
        mask |= pipe_bit(pipe_slot);
    });
    mask
}

pub fn ofd_pipe_slot_mode(ofd_id: u32, pipe_slot: u32) -> u32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS || !valid_pipe_slot(pipe_slot) {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    let mut mode = 0u32;
    for_each_ofd_pipe_mode(ofd, |candidate, candidate_mode| {
        if candidate == pipe_slot {
            mode |= candidate_mode;
        }
    });
    mode
}

pub fn ofd_pipe_generation_slot(ofd_id: u32) -> u32 {
    if ofd_id == 0 || ofd_id as usize >= MAX_FDS {
        return 0;
    }
    let Some(ofd) = fd_table::get_ofd_by_id(ofd_id) else {
        return 0;
    };
    if ofd.fd_type == FD_TYPE_PIPE && valid_pipe_slot(ofd.ino) {
        ofd.ino
    } else {
        0
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

fn process_fd_stdio_pipe_slot(fd: u32, ofd: OpenFileDesc) -> u32 {
    if ofd.fd_type == FD_TYPE_PIPE {
        return if valid_pipe_slot(ofd.ino) { ofd.ino } else { 0 };
    }
    if ofd.fd_type != FD_TYPE_PTY_SLAVE && ofd.fd_type != FD_TYPE_PTY_MASTER {
        return 0;
    }

    let access_mode = ofd.status_flags & fd_table::OPEN_ACCESS_MODE_MASK;
    let input_pipe = crate::syscall::pty::input_pipe_slot(ofd.ino);
    let output_pipe = crate::syscall::pty::output_pipe_slot(ofd.ino);
    let fd_writes_to_stdio_output =
        fd == 1 || fd == 2 || access_mode == O_WRONLY || access_mode == O_RDWR;
    let pipe_slot = if ofd.fd_type == FD_TYPE_PTY_SLAVE {
        if fd_writes_to_stdio_output {
            output_pipe
        } else {
            input_pipe
        }
    } else if fd_writes_to_stdio_output {
        input_pipe
    } else {
        output_pipe
    };
    if valid_pipe_slot(pipe_slot) {
        pipe_slot
    } else {
        0
    }
}

pub fn process_pipe_slot_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    super::fd::process_fd_ofd(vm_ptr, fd).map_or(0, |(_, ofd)| process_fd_stdio_pipe_slot(fd, ofd))
}

pub fn process_pipe_ofd_for_fd(vm_ptr: u32, fd: u32) -> u32 {
    super::fd::process_fd_ofd(vm_ptr, fd).map_or(0, |(ofd_id, ofd)| {
        if process_fd_stdio_pipe_slot(fd, ofd) != 0 {
            ofd_id
        } else {
            0
        }
    })
}

pub fn process_pipe_host_fd_for_fd(vm_ptr: u32, fd: u32) -> i32 {
    super::fd::process_fd_ofd(vm_ptr, fd).map_or(-1, |(_, ofd)| {
        if process_fd_stdio_pipe_slot(fd, ofd) != 0 {
            ofd.host_fd
        } else {
            -1
        }
    })
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

pub fn pipe_reconcile_control(pipe_slot: u32, read_open: i32, write_open: i32) -> i32 {
    if !valid_pipe_slot(pipe_slot) {
        return 0;
    }
    crate::syscall::pipe::reconcile_pipe_control(pipe_slot, read_open, write_open)
}

fn pipe_counter_ahead(source_value: u32, target_value: u32) -> bool {
    source_value > target_value
        || (source_value < target_value
            && target_value > (crate::syscall::pipe::PIPE_BUF_SIZE as u32 / 2)
            && source_value < (crate::syscall::pipe::PIPE_BUF_SIZE as u32 / 2))
}

fn pipe_generation_ahead(source_value: u32, target_value: u32) -> bool {
    target_value == 0
        || source_value > target_value
        || (source_value < target_value && target_value > 0x8000_0000 && source_value < 0x8000_0000)
}

#[allow(clippy::too_many_arguments)]
pub fn pipe_slot_snapshot_merge_action(
    context: u32,
    mode: u32,
    fresh: u32,
    source_head: u32,
    source_tail: u32,
    source_read_open: i32,
    source_write_open: i32,
    source_generation: u32,
    mut target_head: u32,
    mut target_tail: u32,
    target_read_open: i32,
    target_write_open: i32,
    target_generation: u32,
) -> u32 {
    let fresh = fresh != 0;
    let read_mode = (mode & super::SUPERVISOR_PIPE_SLOT_MODE_READ) != 0;
    let write_mode = (mode & super::SUPERVISOR_PIPE_SLOT_MODE_WRITE) != 0;
    let control_mode = (mode & super::SUPERVISOR_PIPE_SLOT_MODE_CONTROL) != 0;
    let shared_state_context = context == super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_SHARED_STATE;
    let thread_step_context = context == super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_THREAD_STEP;
    let kernel_worker_apply_context =
        context == super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_KERNEL_WORKER_APPLY;
    let kernel_worker_process_context =
        context == super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_KERNEL_WORKER_PROCESS;
    let kernel_worker_canonical_context =
        context == super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_CONTEXT_KERNEL_WORKER_CANONICAL;
    let sync_generation_without_apply =
        shared_state_context || kernel_worker_process_context || kernel_worker_canonical_context;

    if source_generation != 0 && source_generation != target_generation {
        if source_head == 0
            && source_tail == 0
            && !pipe_generation_ahead(source_generation, target_generation)
        {
            if kernel_worker_canonical_context {
                if target_read_open > 0 && target_write_open > 0 && target_head != target_tail {
                    return super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SKIP
                        | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_STOP;
                }
            } else if target_head != target_tail && !fresh {
                return super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SKIP
                    | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_STOP;
            }
        }
        let mut action = super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_STOP;
        if fresh
            || pipe_generation_ahead(source_generation, target_generation)
            || (target_read_open <= 0 && target_write_open <= 0)
        {
            action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_APPLY_SLOT
                | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION;
        } else if sync_generation_without_apply {
            action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION;
        }
        return action;
    }

    if (fresh
        || ((kernel_worker_process_context || kernel_worker_canonical_context)
            && target_read_open <= 0
            && target_write_open <= 0))
        && source_head == 0
        && source_tail == 0
        && target_head == target_tail
        && source_read_open > 0
        && source_write_open > 0
        && read_mode
        && write_mode
    {
        return super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_APPLY_SLOT
            | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION
            | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_STOP;
    }

    if kernel_worker_process_context
        && source_head == 0
        && source_tail == 0
        && (target_head != 0 || target_tail != 0)
    {
        let mut action = super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION
            | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_STOP;
        if target_read_open <= 0 && target_write_open <= 0 {
            action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_APPLY_SLOT;
        }
        return action;
    }

    if kernel_worker_apply_context
        && source_head == 0
        && source_tail == 0
        && (target_head != 0 || target_tail != 0)
        && target_read_open <= 0
        && target_write_open <= 0
    {
        return super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_APPLY_SLOT
            | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION
            | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_STOP;
    }

    if (thread_step_context || kernel_worker_apply_context)
        && target_read_open <= 0
        && target_write_open <= 0
        && target_head == target_tail
        && (source_read_open > 0 || source_write_open > 0)
        && (write_mode || control_mode)
    {
        return super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_APPLY_SLOT
            | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION
            | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_STOP;
    }

    let mut action = 0u32;
    if control_mode && (shared_state_context || thread_step_context || kernel_worker_apply_context)
    {
        action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_APPLY_CONTROL;
    }
    if read_mode
        && (!write_mode || kernel_worker_process_context)
        && source_head != 0
        && source_head == source_tail
        && target_tail != source_tail
        && pipe_counter_ahead(source_tail, target_tail)
    {
        action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_HEAD_TO_SOURCE
            | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_TAIL_TO_SOURCE;
        target_head = source_head;
        target_tail = source_tail;
    }
    if write_mode
        && !read_mode
        && source_head == 0
        && source_tail != 0
        && target_head != 0
        && (target_head == target_tail || target_tail == 0)
        && pipe_counter_ahead(source_tail, target_tail)
    {
        action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_HEAD_ZERO;
        target_head = 0;
    }

    if shared_state_context {
        let mut read_head_advanced = false;
        if read_mode {
            if pipe_counter_ahead(source_head, target_head)
                && (source_head != source_tail || target_tail == source_tail)
            {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_HEAD_TO_SOURCE;
                target_head = source_head;
                read_head_advanced = true;
            }
            if pipe_counter_ahead(source_tail, target_tail)
                || (read_head_advanced && source_head != source_tail)
            {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_TAIL_TO_SOURCE
                    | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
                target_tail = source_tail;
            } else if source_tail == target_tail
                && source_head != source_tail
                && !(read_mode && pipe_counter_ahead(target_head, source_head))
            {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
            }
        }
        if write_mode {
            if pipe_counter_ahead(source_tail, target_tail) {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_TAIL_TO_SOURCE
                    | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
            } else if source_tail == target_tail
                && source_head != source_tail
                && !(read_mode && pipe_counter_ahead(target_head, source_head))
            {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
            }
        }
        return action | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION;
    }

    if kernel_worker_process_context {
        if read_mode
            && pipe_counter_ahead(source_head, target_head)
            && (source_head != source_tail || target_tail == source_tail)
        {
            action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_HEAD_TO_SOURCE;
        }
        if write_mode && pipe_counter_ahead(source_tail, target_tail) {
            action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_TAIL_TO_SOURCE
                | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
        } else if write_mode && source_tail == target_tail && source_head != source_tail {
            action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
        }
        return action | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION;
    }

    if kernel_worker_canonical_context {
        if read_mode {
            if pipe_counter_ahead(source_head, target_head)
                && (source_head != source_tail || target_tail == source_tail)
            {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_HEAD_TO_SOURCE;
                target_head = source_head;
            }
            if pipe_counter_ahead(source_tail, target_tail) {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_TAIL_TO_SOURCE
                    | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
            }
        }
        if write_mode {
            let mut repaired_head = false;
            if pipe_counter_ahead(source_head, target_head)
                && (source_head != source_tail || target_tail == source_tail)
            {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_HEAD_TO_SOURCE;
                repaired_head = true;
            }
            if pipe_counter_ahead(source_tail, target_tail)
                || (repaired_head && source_head != source_tail)
            {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_TAIL_TO_SOURCE
                    | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
            } else if source_tail == target_tail && source_head != source_tail {
                action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
            }
        }
        return action | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION;
    }

    if read_mode
        && pipe_counter_ahead(source_head, target_head)
        && (source_head != source_tail || target_tail == source_tail)
    {
        action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_HEAD_TO_SOURCE;
    }
    if write_mode && pipe_counter_ahead(source_tail, target_tail) {
        action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SET_TAIL_TO_SOURCE
            | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_TAIL_DELTA;
    } else if write_mode
        && source_tail == target_tail
        && source_head != source_tail
        && !(read_mode && pipe_counter_ahead(target_head, source_head))
    {
        action |= super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_COPY_FULL;
    }
    action | super::SUPERVISOR_PIPE_SLOT_SNAPSHOT_ACTION_SYNC_GENERATION
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

fn blocked_pipe_poll_timeout_syscall(vm: &ThreadState) -> bool {
    matches!(
        if vm.blocked_syscall_nr != 0 {
            vm.blocked_syscall_nr
        } else {
            vm.x[17]
        },
        crate::abi::SYS_PPOLL | crate::abi::SYS_PSELECT6
    )
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

pub fn blocked_pipe_sync_before_retry_action(vm_ptr: u32, flags: u32) -> i32 {
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return -(crate::abi::EFAULT as i32);
    };
    if vm.status != STATUS_PIPE_WAIT {
        pipe_sync_before_retry_clear_for_vm(vm_ptr);
        return super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_NONE as i32;
    }

    let signature = pipe_sync_before_retry_signature(vm_ptr, vm);
    let sync_requested = with_pipe_sync_before_retry_lock(|states| {
        let idx = pipe_sync_before_retry_slot(states, signature);
        states[idx].sync_requested != 0
    });
    let kernel_worker_available = (flags
        & super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_FLAG_KERNEL_WORKER_AVAILABLE)
        != 0;
    let ready_count = crate::syscall::poll::wait_set_ready_count(vm, vm.guest_base);
    let timed_no_ready_without_pending_sync = blocked_pipe_poll_timeout_syscall(vm)
        && vm.epoll_timeout_ms >= 0
        && ready_count <= 0
        && !pipe_sync_before_retry_readiness_sync_pending(vm);

    if !sync_requested && kernel_worker_available {
        let action = if timed_no_ready_without_pending_sync {
            super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_REQUEST_SYNC
        } else {
            super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_REQUEST_SYNC_AND_DRAIN_OUTPUT
        };
        with_pipe_sync_before_retry_lock(|states| {
            let idx = pipe_sync_before_retry_slot(states, signature);
            states[idx].sync_requested = 1;
        });
        return action as i32;
    }

    if timed_no_ready_without_pending_sync {
        return super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_SCHEDULE_RETRY as i32;
    }

    super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_ACTION_NONE as i32
}

pub fn blocked_pipe_sync_before_retry_requested(vm_ptr: u32) -> i32 {
    let Some(vm) = super::thread::state_from_ptr(vm_ptr) else {
        return -(crate::abi::EFAULT as i32);
    };
    if vm.status != STATUS_PIPE_WAIT {
        return 0;
    }
    let signature = pipe_sync_before_retry_signature(vm_ptr, vm);
    i32::from(pipe_sync_before_retry_requested_for_signature(signature))
}

pub fn blocked_pipe_sync_before_retry_clear(vm_ptr: u32) -> i32 {
    let Some(_vm) = super::thread::state_from_ptr(vm_ptr) else {
        return -(crate::abi::EFAULT as i32);
    };
    pipe_sync_before_retry_clear_for_vm(vm_ptr);
    0
}

pub fn blocked_pipe_sync_before_retry_completion_action(flags: u32) -> i32 {
    let requested_drain = (flags
        & super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_COMPLETION_FLAG_REQUESTED_DRAIN_OUTPUT)
        != 0;
    let kernel_worker_available = (flags
        & super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_COMPLETION_FLAG_KERNEL_WORKER_AVAILABLE)
        != 0;
    let mut action =
        super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_COMPLETION_ACTION_SCHEDULE_RETRY;
    if requested_drain || !kernel_worker_available {
        action |=
            super::SUPERVISOR_BLOCKED_PIPE_SYNC_BEFORE_RETRY_COMPLETION_ACTION_DRAIN_LOCAL_PIPE;
    }
    action as i32
}
