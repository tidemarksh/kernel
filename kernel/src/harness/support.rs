#[cfg(any(test, feature = "harness"))]
use alloc_crate::boxed::Box;
#[cfg(any(test, feature = "harness"))]
use alloc_crate::vec;
use alloc_crate::vec::Vec;

#[cfg(any(test, feature = "harness"))]
use crate::abi::MAP_SHARED;
#[cfg(any(test, feature = "harness"))]
use crate::guest_mem;
#[cfg(any(test, feature = "harness"))]
use crate::harness::{memory, resource, signal};

const HARNESS_RUNTIME_SUPPORT_ENABLED: bool = cfg!(any(test, feature = "harness"));

#[cfg(any(test, feature = "harness"))]
struct SharedMappingSnapshot {
    start: u64,
    bytes: Vec<u8>,
}

#[cfg(any(test, feature = "harness"))]
pub struct SharedMappingOverlay {
    snapshots: Vec<SharedMappingSnapshot>,
}

struct ExternalFutexWait {
    #[cfg_attr(not(any(test, feature = "harness")), allow(dead_code))]
    pid: i32,
    addrs: Vec<u32>,
    woken: bool,
    woken_addr: u32,
}

#[cfg(any(test, feature = "harness"))]
pub struct ProcessContextSnapshot {
    mm_state: memory::AddressSpaceSnapshot,
    process_state: crate::harness::process::ProcessRuntimeSnapshot,
    signal_state: signal::ProcessSignalSnapshot,
    resource_state: resource::ProcessResourceSnapshot,
}

#[cfg(any(test, feature = "harness"))]
impl ProcessContextSnapshot {
    fn empty() -> Self {
        Self {
            mm_state: memory::AddressSpaceSnapshot::empty(),
            process_state: crate::harness::process::ProcessRuntimeSnapshot::empty(),
            signal_state: signal::ProcessSignalSnapshot::empty(),
            resource_state: resource::ProcessResourceSnapshot::empty(),
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn debug_validate_process_context_snapshot(
    snapshot: &ProcessContextSnapshot,
) -> Result<(), String> {
    let (len, cap, ptr) = snapshot.mm_state.debug_vma_vec_meta();
    let elem = core::mem::size_of::<crate::types::Vma>();
    let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
    if len > cap {
        return Err(format!(
            "process context snapshot invalid vmas len={} cap={} ptr=0x{:x}",
            len, cap, ptr
        ));
    }
    if cap == 0 {
        return Ok(());
    }
    if ptr == 0 {
        return Err(format!(
            "process context snapshot invalid vmas null ptr len={} cap={}",
            len, cap
        ));
    }
    let bytes = cap.checked_mul(elem).ok_or_else(|| {
        format!(
            "process context snapshot invalid vmas cap overflow cap={} elem={}",
            cap, elem
        )
    })?;
    let end = ptr.checked_add(bytes).ok_or_else(|| {
        format!(
            "process context snapshot invalid vmas ptr overflow ptr=0x{:x} bytes={}",
            ptr, bytes
        )
    })?;
    if end > mem_size {
        return Err(format!(
            "process context snapshot invalid vmas out of wasm range ptr=0x{:x} len={} cap={} bytes={} mem_size=0x{:x}",
            ptr, len, cap, bytes, mem_size
        ));
    }
    Ok(())
}

static mut EXTERNAL_FUTEX_WAITS: Option<Vec<ExternalFutexWait>> = None;

#[cfg(any(test, feature = "harness"))]
pub fn snapshot_process_context() -> ProcessContextSnapshot {
    *snapshot_process_context_boxed()
}

#[cfg(any(test, feature = "harness"))]
pub fn snapshot_process_context_boxed() -> Box<ProcessContextSnapshot> {
    let mut snapshot = Box::new(ProcessContextSnapshot::empty());
    snapshot_process_context_fill(snapshot.as_mut());
    snapshot
}

#[cfg(any(test, feature = "harness"))]
#[inline(never)]
fn snapshot_process_context_fill(snapshot: &mut ProcessContextSnapshot) {
    memory::snapshot_process_context_into(&mut snapshot.mm_state);
    crate::harness::process::snapshot_process_context_into(&mut snapshot.process_state);
    signal::snapshot_process_context_into(&mut snapshot.signal_state);
    resource::snapshot_process_context_into(&mut snapshot.resource_state);
}

#[cfg(any(test, feature = "harness"))]
pub fn refresh_process_context_runtime_state(snapshot: &mut ProcessContextSnapshot) {
    crate::harness::process::snapshot_process_context_into(&mut snapshot.process_state);
    signal::snapshot_process_context_into(&mut snapshot.signal_state);
    resource::snapshot_process_context_into(&mut snapshot.resource_state);
}

#[cfg(any(test, feature = "harness"))]
pub fn clear_external_futex_waits() {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return;
    }
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS),
            Some(Vec::new()),
        );
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn register_external_futex_wait(pid: i32, addr: u32) {
    register_external_futex_waitv(pid, &[addr]);
}

#[cfg(any(test, feature = "harness"))]
pub fn register_external_futex_waitv(pid: i32, addrs: &[u32]) {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return;
    }
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        if slot.is_none() {
            *slot = Some(Vec::new());
        }
        if let Some(waits) = slot.as_mut() {
            if let Some(wait) = waits.iter_mut().find(|wait| wait.pid == pid) {
                wait.addrs.clear();
                wait.addrs.extend_from_slice(addrs);
                wait.woken = false;
                wait.woken_addr = 0;
                return;
            }
            waits.push(ExternalFutexWait {
                pid,
                addrs: addrs.to_vec(),
                woken: false,
                woken_addr: 0,
            });
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn clear_external_futex_wait(pid: i32) {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return;
    }
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        if let Some(waits) = slot.as_mut() {
            waits.retain(|wait| wait.pid != pid);
        }
    }
}

pub fn wake_external_futex_waits(addr: u32, max_wake: u32) -> u32 {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return 0;
    }
    if max_wake == 0 {
        return 0;
    }

    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return 0;
        };

        let mut woken = 0;
        for wait in waits.iter_mut() {
            if wait.woken || !wait.addrs.contains(&addr) {
                continue;
            }
            wait.woken = true;
            wait.woken_addr = addr;
            woken += 1;
            if woken == max_wake {
                break;
            }
        }
        woken
    }
}

pub fn requeue_external_futex_waits(addr: u32, new_addr: u32, max_requeue: u32) -> u32 {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return 0;
    }
    if max_requeue == 0 || addr == new_addr {
        return 0;
    }

    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return 0;
        };

        let mut requeued = 0;
        for wait in waits.iter_mut() {
            if wait.woken || !wait.addrs.contains(&addr) {
                continue;
            }
            for futex_addr in wait.addrs.iter_mut() {
                if *futex_addr == addr {
                    *futex_addr = new_addr;
                }
            }
            requeued += 1;
            if requeued == max_requeue {
                break;
            }
        }
        requeued
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn take_external_futex_wake(pid: i32, addr: u32) -> bool {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return false;
    }
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return false;
        };

        if let Some(idx) = waits.iter().position(|wait| {
            wait.pid == pid && wait.woken && wait.woken_addr == addr && wait.addrs.contains(&addr)
        }) {
            waits.remove(idx);
            true
        } else {
            false
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn has_external_futex_wait(pid: i32) -> bool {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return false;
    }
    unsafe {
        let slot = &*core::ptr::addr_of!(EXTERNAL_FUTEX_WAITS);
        let Some(waits) = slot.as_ref() else {
            return false;
        };

        waits.iter().any(|wait| wait.pid == pid)
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn take_external_futex_wake_for_pid(pid: i32) -> bool {
    take_external_futex_wake_addr_for_pid(pid).is_some()
}

#[cfg(any(test, feature = "harness"))]
pub fn take_external_futex_wake_addr_for_pid(pid: i32) -> Option<u32> {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return None;
    }
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return None;
        };

        if let Some(idx) = waits.iter().position(|wait| wait.pid == pid && wait.woken) {
            Some(waits.remove(idx).woken_addr)
        } else {
            None
        }
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn restore_process_context_parent<F, E>(
    base: u32,
    guest_limit: u64,
    snapshot: &ProcessContextSnapshot,
    restore_guest_memory: F,
) -> Result<(), E>
where
    F: FnOnce() -> Result<(), E>,
{
    crate::harness::process::restore_process_context(&snapshot.process_state);
    signal::restore_process_context(&snapshot.signal_state);
    resource::restore_process_context(&snapshot.resource_state);
    memory::flush_shared_mappings(base);
    let shared_mappings = snapshot_shared_mappings(base, guest_limit, &snapshot.mm_state);
    restore_guest_memory()?;
    memory::restore_process_context(&snapshot.mm_state);
    memory::refresh_shared_file_mappings(base, guest_limit);
    restore_shared_mappings(base, &shared_mappings);
    Ok(())
}

#[cfg(any(test, feature = "harness"))]
pub fn restore_process_context_parent_without_shared_snapshot<F, E>(
    base: u32,
    guest_limit: u64,
    snapshot: &ProcessContextSnapshot,
    restore_guest_memory: F,
) -> Result<(), E>
where
    F: FnOnce() -> Result<(), E>,
{
    crate::harness::process::restore_process_context(&snapshot.process_state);
    signal::restore_process_context(&snapshot.signal_state);
    resource::restore_process_context(&snapshot.resource_state);
    memory::flush_shared_mappings(base);
    restore_guest_memory()?;
    memory::restore_process_context(&snapshot.mm_state);
    memory::refresh_shared_file_mappings(base, guest_limit);
    Ok(())
}

#[cfg(any(test, feature = "harness"))]
pub fn restore_process_context_mm_only<F, E>(
    base: u32,
    guest_limit: u64,
    snapshot: &ProcessContextSnapshot,
    restore_guest_memory: F,
) -> Result<(), E>
where
    F: FnOnce() -> Result<(), E>,
{
    memory::flush_shared_mappings(base);
    let shared_mappings = snapshot_shared_mappings(base, guest_limit, &snapshot.mm_state);
    restore_guest_memory()?;
    memory::restore_process_context(&snapshot.mm_state);
    memory::refresh_shared_file_mappings(base, guest_limit);
    restore_shared_mappings(base, &shared_mappings);
    Ok(())
}

#[cfg(any(test, feature = "harness"))]
pub fn restore_process_context_mm_only_from_guest_snapshot<F, E>(
    base: u32,
    guest_limit: u64,
    snapshot: &ProcessContextSnapshot,
    restore_guest_memory: F,
) -> Result<(), E>
where
    F: FnOnce() -> Result<(), E>,
{
    memory::flush_shared_mappings(base);
    restore_guest_memory()?;
    memory::restore_process_context(&snapshot.mm_state);
    memory::refresh_shared_file_mappings(base, guest_limit);
    Ok(())
}

#[cfg(any(test, feature = "harness"))]
pub fn flush_shared_mapping_overlay(base: u32) {
    memory::flush_shared_mappings(base);
}

#[cfg(any(test, feature = "harness"))]
pub fn restore_process_context_mm_state(snapshot: &ProcessContextSnapshot) {
    memory::restore_process_context(&snapshot.mm_state);
}

#[cfg(any(test, feature = "harness"))]
pub fn refresh_shared_mapping_file_mappings(base: u32, guest_limit: u64) {
    memory::refresh_shared_file_mappings(base, guest_limit);
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
pub fn capture_live_shared_mapping_overlay(
    base: u32,
    guest_limit: u64,
    snapshot: &ProcessContextSnapshot,
) -> SharedMappingOverlay {
    SharedMappingOverlay {
        snapshots: snapshot_shared_mappings(base, guest_limit, &snapshot.mm_state),
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn restore_live_shared_mapping_overlay(base: u32, mappings: &SharedMappingOverlay) {
    restore_shared_mappings(base, &mappings.snapshots);
}

#[cfg(any(test, feature = "harness"))]
pub fn read_u32_from_shared_mapping_overlay(
    mappings: &SharedMappingOverlay,
    addr: u64,
) -> Option<u32> {
    let end = addr.checked_add(4)?;
    for snapshot in mappings.snapshots.iter() {
        let snap_end = snapshot.start.checked_add(snapshot.bytes.len() as u64)?;
        if addr < snapshot.start || end > snap_end {
            continue;
        }
        let off = (addr - snapshot.start) as usize;
        let bytes = snapshot.bytes.get(off..off + 4)?;
        return Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }
    None
}

#[cfg(any(test, feature = "harness"))]
pub fn cmp_requeue_shared_words_from_shared_mapping_overlay(
    mappings: &SharedMappingOverlay,
    futex_addr: u32,
) -> Option<(u32, u32, u32, u32)> {
    let addr = futex_addr as u64;
    Some((
        read_u32_from_shared_mapping_overlay(mappings, addr)?,
        read_u32_from_shared_mapping_overlay(mappings, addr + 4)?,
        read_u32_from_shared_mapping_overlay(mappings, addr + 8)?,
        read_u32_from_shared_mapping_overlay(mappings, addr + 12)?,
    ))
}

#[cfg(any(test, feature = "harness"))]
fn restore_shared_mappings(base: u32, snapshots: &[SharedMappingSnapshot]) {
    for snapshot in snapshots {
        unsafe {
            guest_mem::write_bytes(base, snapshot.start, &snapshot.bytes);
        }
    }
}
