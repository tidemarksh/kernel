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

struct PlainForkFutexWait {
    pid: i32,
    addr: u32,
    woken: bool,
}

pub struct PlainForkSnapshot {
    mm_state: memory::MemStateSnapshot,
}

static mut GUEST_OUTPUT: Option<Vec<u8>> = None;
static mut PLAIN_FORK_FUTEX_WAITS: Option<Vec<PlainForkFutexWait>> = None;

pub fn snapshot_plain_fork() -> PlainForkSnapshot {
    PlainForkSnapshot {
        mm_state: memory::snapshot_for_plain_fork(),
    }
}

pub fn clear_guest_output() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(GUEST_OUTPUT), Some(Vec::new()));
    }
}

pub fn clear_plain_fork_futex_waits() {
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS),
            Some(Vec::new()),
        );
    }
}

pub fn register_plain_fork_futex_wait(pid: i32, addr: u32) {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        if slot.is_none() {
            *slot = Some(Vec::new());
        }
        if let Some(waits) = slot.as_mut() {
            if let Some(wait) = waits.iter_mut().find(|wait| wait.pid == pid) {
                wait.addr = addr;
                wait.woken = false;
                return;
            }
            waits.push(PlainForkFutexWait {
                pid,
                addr,
                woken: false,
            });
        }
    }
}

pub fn clear_plain_fork_futex_wait(pid: i32) {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        if let Some(waits) = slot.as_mut() {
            waits.retain(|wait| wait.pid != pid);
        }
    }
}

pub fn wake_plain_fork_futex_waits(addr: u32, max_wake: u32) -> u32 {
    if max_wake == 0 {
        return 0;
    }

    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return 0;
        };

        let mut woken = 0;
        for wait in waits.iter_mut() {
            if wait.addr != addr || wait.woken {
                continue;
            }
            wait.woken = true;
            woken += 1;
            if woken == max_wake {
                break;
            }
        }
        woken
    }
}

pub fn take_plain_fork_futex_wake(pid: i32, addr: u32) -> bool {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return false;
        };

        if let Some(idx) = waits
            .iter()
            .position(|wait| wait.pid == pid && wait.addr == addr && wait.woken)
        {
            waits.remove(idx);
            true
        } else {
            false
        }
    }
}

pub fn append_guest_output(bytes: &[u8]) {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(GUEST_OUTPUT);
        if slot.is_none() {
            *slot = Some(Vec::new());
        }
        if let Some(buf) = slot.as_mut() {
            buf.extend_from_slice(bytes);
        }
    }
}

pub fn take_guest_output() -> Vec<u8> {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(GUEST_OUTPUT);
        slot.take().unwrap_or_default()
    }
}

pub fn restore_plain_fork_parent<F, E>(
    base: u32,
    guest_limit: u64,
    snapshot: &PlainForkSnapshot,
    restore_guest_memory: F,
) -> Result<(), E>
where
    F: FnOnce() -> Result<(), E>,
{
    memory::flush_shared_mappings(base);
    let shared_mappings = snapshot_shared_mappings(base, guest_limit, &snapshot.mm_state);
    restore_guest_memory()?;
    memory::restore_after_plain_fork(&snapshot.mm_state);
    memory::refresh_shared_file_mappings(base, guest_limit);
    restore_shared_mappings(base, &shared_mappings);
    Ok(())
}

fn snapshot_shared_mappings(
    base: u32,
    guest_limit: u64,
    snapshot: &memory::MemStateSnapshot,
) -> Vec<SharedMappingSnapshot> {
    let mut snapshots = Vec::new();

    for vma in snapshot.vmas() {
        if (vma.flags as u64 & MAP_SHARED) == 0 || vma.fd >= 0 {
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
