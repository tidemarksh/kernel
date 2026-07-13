use alloc_crate::vec::Vec;

use crate::abi::*;
use crate::types::{ProcessState, ThreadState};

const FORK_CHILD_EXECVE_HEADROOM_BYTES: u64 = 16 * 1024 * 1024;
const FORK_STACK_BELOW_SP_BYTES: u64 = 1024 * 1024;
const FORK_STACK_COPY_WINDOW_BYTES: u64 = 8 * 1024 * 1024;
const EXECVE_CHILD_MIN_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const EXECVE_CHILD_HANDOFF_HEADROOM_BYTES: u64 = 0x10000;
const WASM_PAGE_BYTES: u64 = 65536;

#[derive(Clone, Copy)]
struct MemoryRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Copy)]
struct ProcessMemoryRecord {
    kind: u32,
    seq: u64,
    parent_vm_ptr: u32,
    child_pid: u32,
    process_ptr: u32,
    status: u32,
    detail0: u64,
    detail1: u64,
}

fn add_range(ranges: &mut Vec<MemoryRange>, start: u64, end: u64, limit: u64) {
    let bounded_start = start.min(limit);
    let bounded_end = end.min(limit).max(bounded_start);
    if bounded_end > bounded_start {
        ranges.push(MemoryRange {
            start: bounded_start,
            end: bounded_end,
        });
    }
}

fn page_align_down(value: u64) -> u64 {
    value & !(WASM_PAGE_BYTES - 1)
}

fn coalesce_ranges(mut ranges: Vec<MemoryRange>) -> Vec<MemoryRange> {
    ranges.retain(|range| range.end > range.start);
    ranges.sort_by(|left, right| left.start.cmp(&right.start).then(left.end.cmp(&right.end)));
    let mut coalesced: Vec<MemoryRange> = Vec::new();
    for range in ranges {
        if let Some(last) = coalesced.last_mut() {
            if range.start <= last.end {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        coalesced.push(range);
    }
    coalesced
}

fn add_kernel_runtime_ranges(
    ranges: &mut Vec<MemoryRange>,
    limit: u64,
    memfs_data_used_only: bool,
) {
    add_range(ranges, 0, crate::alloc::heap_ptr() as u64, limit);
    add_range(
        ranges,
        crate::fs::fd_table::ofd_table_ptr() as u64,
        crate::fs::fd_table::ofd_table_ptr() as u64 + crate::fs::fd_table::ofd_table_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::fs::memfs::memfs_ptr() as u64,
        crate::fs::memfs::memfs_ptr() as u64
            + crate::fs::memfs::memfs_header_bytes() as u64
            + crate::fs::memfs::memfs_inodes_bytes() as u64
            + crate::fs::memfs::memfs_first_child_bytes() as u64
            + crate::fs::memfs::memfs_dir_entries_bytes() as u64
            + if memfs_data_used_only {
                0
            } else {
                crate::fs::memfs::memfs_data_bytes() as u64
            },
        limit,
    );
    add_range(
        ranges,
        crate::fs::memfs::memfs_ptr() as u64,
        crate::fs::memfs::memfs_ptr() as u64 + crate::fs::memfs::memfs_header_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::fs::memfs::memfs_inodes_ptr() as u64,
        crate::fs::memfs::memfs_inodes_ptr() as u64 + crate::fs::memfs::memfs_inodes_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::fs::memfs::memfs_first_child_ptr() as u64,
        crate::fs::memfs::memfs_first_child_ptr() as u64
            + crate::fs::memfs::memfs_first_child_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::fs::memfs::memfs_dir_entries_ptr() as u64,
        crate::fs::memfs::memfs_dir_entries_ptr() as u64
            + crate::fs::memfs::memfs_dir_entries_bytes() as u64,
        limit,
    );
    let memfs_data_len = if memfs_data_used_only {
        crate::fs::memfs::memfs_data_used() as u64
    } else {
        crate::fs::memfs::memfs_data_bytes() as u64
    };
    add_range(
        ranges,
        crate::fs::memfs::memfs_data_ptr() as u64,
        crate::fs::memfs::memfs_data_ptr() as u64 + memfs_data_len,
        limit,
    );
    add_range(
        ranges,
        crate::syscall::epoll::epoll_table_ptr() as u64,
        crate::syscall::epoll::epoll_table_ptr() as u64
            + crate::syscall::epoll::epoll_table_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::syscall::socket::socket_table_ptr() as u64,
        crate::syscall::socket::socket_table_ptr() as u64
            + crate::syscall::socket::socket_table_bytes() as u64,
        limit,
    );
    let (pipe_base, _) = crate::syscall::pipe::pipe_state();
    add_range(
        ranges,
        pipe_base as u64,
        pipe_base as u64 + crate::syscall::pipe::pipe_region_bytes() as u64,
        limit,
    );
    let (net_buf_base, _) = crate::net::ring_buffer::net_buffer_state();
    add_range(
        ranges,
        net_buf_base as u64,
        net_buf_base as u64 + crate::net::ring_buffer::net_buffer_pool_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::syscall::signal::sig_slots_ptr() as u64,
        crate::syscall::signal::sig_slots_ptr() as u64
            + crate::syscall::signal::signal_slots_bytes() as u64
            + crate::syscall::signal::signal_action_table_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::syscall::signal::process_pending_ptr() as u64,
        crate::syscall::signal::process_pending_ptr() as u64
            + crate::syscall::signal::process_pending_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::syscall::signal::signalfd_state_ptr() as u64,
        crate::syscall::signal::signalfd_state_ptr() as u64
            + crate::syscall::signal::signalfd_state_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::syscall::process::process_runtime_state_ptr() as u64,
        crate::syscall::process::process_runtime_state_ptr() as u64
            + crate::syscall::process::process_runtime_state_bytes() as u64,
        limit,
    );
    add_range(
        ranges,
        crate::syscall::time::time_state_ptr() as u64,
        crate::syscall::time::time_state_ptr() as u64
            + crate::syscall::time::time_state_bytes() as u64,
        limit,
    );
}

fn is_sparse_anonymous_reservation(index: u32) -> bool {
    crate::syscall::memory::address_space_vma_prot(index) == PROT_NONE
        && crate::syscall::memory::address_space_vma_fd(index) < 0
        && (crate::syscall::memory::address_space_vma_flags(index) as u64 & MAP_ANONYMOUS) != 0
}

fn fork_copy_ranges(vm: &ThreadState) -> Vec<MemoryRange> {
    let limit = crate::wasm::memory_size_bytes();
    let mut ranges = Vec::new();
    add_kernel_runtime_ranges(&mut ranges, limit, true);

    let low_guest_end = crate::syscall::memory::current_brk()
        .max(vm.process_ptr as u64 + core::mem::size_of::<ProcessState>() as u64);
    add_range(
        &mut ranges,
        vm.guest_base as u64,
        vm.guest_base as u64 + low_guest_end,
        limit,
    );

    let vma_len = crate::syscall::memory::address_space_vma_len();
    for index in 0..vma_len {
        if is_sparse_anonymous_reservation(index) {
            continue;
        }
        let start = crate::syscall::memory::address_space_vma_start(index);
        let end = crate::syscall::memory::address_space_vma_end(index);
        add_range(
            &mut ranges,
            vm.guest_base as u64 + start,
            vm.guest_base as u64 + end,
            limit,
        );
    }

    let stack_guest_ptr = vm.x[2];
    let guest_backing_bytes = limit.saturating_sub(vm.guest_base as u64);
    if stack_guest_ptr > 0 && stack_guest_ptr < guest_backing_bytes {
        let stack_start_guest =
            page_align_down(stack_guest_ptr).saturating_sub(FORK_STACK_BELOW_SP_BYTES);
        let stack_end_guest =
            guest_backing_bytes.min(stack_start_guest + FORK_STACK_COPY_WINDOW_BYTES);
        add_range(
            &mut ranges,
            vm.guest_base as u64 + stack_start_guest,
            vm.guest_base as u64 + stack_end_guest,
            limit,
        );
    }

    coalesce_ranges(ranges)
}

fn execve_copy_ranges(_vm: &ThreadState) -> Vec<MemoryRange> {
    let limit = crate::wasm::memory_size_bytes();
    let mut ranges = Vec::new();
    add_kernel_runtime_ranges(&mut ranges, limit, false);
    coalesce_ranges(ranges)
}

fn copy_ranges_for_spawn(vm: &ThreadState) -> Option<Vec<MemoryRange>> {
    match vm.spawn_kind {
        SPAWN_KIND_FORK => Some(fork_copy_ranges(vm)),
        SPAWN_KIND_EXECVE => Some(execve_copy_ranges(vm)),
        _ => None,
    }
}

fn child_initial_memory_bytes(vm: &ThreadState, ranges: &[MemoryRange]) -> u64 {
    match vm.spawn_kind {
        SPAWN_KIND_FORK => {
            let end = ranges.iter().map(|range| range.end).max().unwrap_or(0);
            (end + FORK_CHILD_EXECVE_HEADROOM_BYTES).max(vm.guest_base as u64)
        }
        SPAWN_KIND_EXECVE => EXECVE_CHILD_MIN_MEMORY_BYTES
            .max(crate::alloc::heap_ptr() as u64)
            .max(vm.guest_base as u64 + EXECVE_CHILD_HANDOFF_HEADROOM_BYTES),
        _ => 0,
    }
}

fn process_max_memory_pages(vm: &ThreadState) -> u64 {
    let pages = if vm.spawn_process_max_memory_pages != 0 {
        vm.spawn_process_max_memory_pages
    } else {
        vm.process_max_memory_pages
    };
    pages as u64
}

fn record_for_index(vm_ptr: u32, index: u32) -> Option<ProcessMemoryRecord> {
    let vm = super::thread::state_from_ptr(vm_ptr)?;
    if vm.spawn_kind == SPAWN_KIND_NONE || vm.spawn_child_pid <= 0 {
        return None;
    }
    let ranges = copy_ranges_for_spawn(vm)?;
    if index == 0 {
        return Some(ProcessMemoryRecord {
            kind: super::SUPERVISOR_HOST_OP_KIND_CREATE_PROCESS_MEMORY,
            seq: 1,
            parent_vm_ptr: vm_ptr,
            child_pid: vm.spawn_child_pid as u32,
            process_ptr: vm.process_ptr,
            status: vm.status as u32,
            detail0: child_initial_memory_bytes(vm, &ranges),
            detail1: process_max_memory_pages(vm),
        });
    }
    let range = ranges.get(index.saturating_sub(1) as usize)?;
    Some(ProcessMemoryRecord {
        kind: super::SUPERVISOR_HOST_OP_KIND_COPY_MEMORY_RANGES,
        seq: index as u64 + 1,
        parent_vm_ptr: vm_ptr,
        child_pid: vm.spawn_child_pid as u32,
        process_ptr: vm.process_ptr,
        status: vm.spawn_kind,
        detail0: range.start,
        detail1: range.end,
    })
}

pub(super) fn write_record(vm_ptr: u32, index: u32, out_ptr: u32, out_len: u32) -> i32 {
    if out_len == 0 {
        return if record_for_index(vm_ptr, index).is_some() {
            super::SUPERVISOR_HOST_OP_RECORD_BYTES as i32
        } else {
            0
        };
    }
    if out_ptr == 0 {
        return crate::abi::EFAULT as i32;
    }
    if out_len < super::SUPERVISOR_HOST_OP_RECORD_BYTES {
        return crate::abi::ENOSPC as i32;
    }
    let Some(record) = record_for_index(vm_ptr, index) else {
        return 0;
    };
    let mut encoded = [0u8; super::SUPERVISOR_HOST_OP_RECORD_BYTES as usize];
    super::write_u32(&mut encoded, 0, super::SUPERVISOR_HOST_OP_RECORD_MAGIC);
    super::write_u32(&mut encoded, 4, super::SUPERVISOR_ABI_VERSION);
    super::write_u32(&mut encoded, 8, super::SUPERVISOR_HOST_OP_RECORD_BYTES);
    super::write_u32(&mut encoded, 12, record.kind);
    super::write_u64(&mut encoded, 16, record.seq);
    super::write_u32(&mut encoded, 24, record.parent_vm_ptr);
    super::write_u32(&mut encoded, 28, 0);
    super::write_u32(&mut encoded, 32, record.child_pid);
    super::write_u32(&mut encoded, 36, record.process_ptr);
    super::write_u32(&mut encoded, 40, record.status);
    super::write_u32(&mut encoded, 44, 0);
    super::write_u64(&mut encoded, 48, record.detail0);
    super::write_u64(&mut encoded, 56, record.detail1);
    super::log::record_host_op(&encoded, super::SUPERVISOR_HOST_OP_RECORD_BYTES);
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            out_ptr as usize as *mut u8,
            super::SUPERVISOR_HOST_OP_RECORD_BYTES as usize,
        )
    };
    out.copy_from_slice(&encoded);
    super::SUPERVISOR_HOST_OP_RECORD_BYTES as i32
}
