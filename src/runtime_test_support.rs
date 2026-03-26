//! Runtime/mock support for wasm32-wasi integration tests.
//!
//! This module keeps plain-fork handoff helpers out of the Linux syscall
//! semantics layer while still allowing the integration-test harness to model
//! the TS/runtime side of `STATUS_EXECVE_SPAWN`.

use alloc_crate::vec::Vec;

use crate::abi::MAP_SHARED;
use crate::guest_mem;
use crate::syscall::memory;

struct SharedMappingSnapshot {
    start: u64,
    bytes: Vec<u8>,
}

pub struct PlainForkSnapshot {
    mm_state: memory::MemStateSnapshot,
}

pub fn snapshot_plain_fork() -> PlainForkSnapshot {
    PlainForkSnapshot {
        mm_state: memory::snapshot_for_plain_fork(),
    }
}

pub fn restore_plain_fork_parent(
    base: u32,
    guest_limit: u64,
    parent_memory: &[u8],
    snapshot: &PlainForkSnapshot,
) {
    let shared_mappings = snapshot_shared_mappings(base, guest_limit, &snapshot.mm_state);
    unsafe {
        guest_mem::write_bytes(base, 0, parent_memory);
    }
    memory::restore_after_plain_fork(&snapshot.mm_state);
    restore_shared_mappings(base, &shared_mappings);
}

fn snapshot_shared_mappings(
    base: u32,
    guest_limit: u64,
    snapshot: &memory::MemStateSnapshot,
) -> Vec<SharedMappingSnapshot> {
    let mut snapshots = Vec::new();

    for vma in snapshot.vmas() {
        if (vma.flags as u64 & MAP_SHARED) == 0 {
            continue;
        }

        let start = vma.start.min(guest_limit);
        let end = vma.end.min(guest_limit);
        if start >= end {
            continue;
        }

        let mut bytes = vec![0u8; (end - start) as usize];
        unsafe {
            guest_mem::read_bytes(base, start, &mut bytes);
        }
        snapshots.push(SharedMappingSnapshot { start, bytes });
    }

    snapshots
}

fn restore_shared_mappings(base: u32, snapshots: &[SharedMappingSnapshot]) {
    for snapshot in snapshots {
        unsafe {
            guest_mem::write_bytes(base, snapshot.start, &snapshot.bytes);
        }
    }
}
