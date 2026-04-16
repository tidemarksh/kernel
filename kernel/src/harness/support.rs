#[cfg(any(test, feature = "harness"))]
use alloc_crate::vec;
use alloc_crate::vec::Vec;

#[cfg(any(test, feature = "harness"))]
use crate::abi::MAP_SHARED;
#[cfg(any(test, feature = "harness"))]
use crate::guest_mem;
#[cfg(any(test, feature = "harness"))]
use crate::syscall::memory;

const HARNESS_RUNTIME_SUPPORT_ENABLED: bool = cfg!(any(test, feature = "harness"));

#[cfg(any(test, feature = "harness"))]
struct SharedMappingSnapshot {
    start: u64,
    bytes: Vec<u8>,
}

struct PlainForkFutexWait {
    #[cfg_attr(not(any(test, feature = "harness")), allow(dead_code))]
    pid: i32,
    addr: u32,
    woken: bool,
}

#[cfg(any(test, feature = "harness"))]
pub struct PlainForkSnapshot {
    mm_state: memory::AddressSpaceSnapshot,
}

static mut PLAIN_FORK_FUTEX_WAITS: Option<Vec<PlainForkFutexWait>> = None;

#[cfg(any(test, feature = "harness"))]
pub fn snapshot_plain_fork() -> PlainForkSnapshot {
    PlainForkSnapshot {
        mm_state: memory::snapshot_for_plain_fork(),
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn clear_plain_fork_futex_waits() {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS),
            Some(Vec::new()),
        );
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn register_plain_fork_futex_wait(pid: i32, addr: u32) {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return;
    }
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

#[cfg(any(test, feature = "harness"))]
pub fn clear_plain_fork_futex_wait(pid: i32) {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return;
    }
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        if let Some(waits) = slot.as_mut() {
            waits.retain(|wait| wait.pid != pid);
        }
    }
}

pub fn wake_plain_fork_futex_waits(addr: u32, max_wake: u32) -> u32 {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return 0;
    }
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

pub fn requeue_plain_fork_futex_waits(addr: u32, new_addr: u32, max_requeue: u32) -> u32 {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return 0;
    }
    if max_requeue == 0 || addr == new_addr {
        return 0;
    }

    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(PLAIN_FORK_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return 0;
        };

        let mut requeued = 0;
        for wait in waits.iter_mut() {
            if wait.addr != addr || wait.woken {
                continue;
            }
            wait.addr = new_addr;
            requeued += 1;
            if requeued == max_requeue {
                break;
            }
        }
        requeued
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn take_plain_fork_futex_wake(pid: i32, addr: u32) -> bool {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return false;
    }
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

#[cfg(any(test, feature = "harness"))]
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

#[cfg(any(test, feature = "harness"))]
fn snapshot_shared_mappings(
    base: u32,
    guest_limit: u64,
    snapshot: &memory::AddressSpaceSnapshot,
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

#[cfg(any(test, feature = "harness"))]
fn restore_shared_mappings(base: u32, snapshots: &[SharedMappingSnapshot]) {
    for snapshot in snapshots {
        unsafe {
            guest_mem::write_bytes(base, snapshot.start, &snapshot.bytes);
        }
    }
}
