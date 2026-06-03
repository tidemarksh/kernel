#[cfg(any(test, feature = "harness"))]
use alloc_crate::boxed::Box;
#[cfg(any(test, feature = "harness"))]
use alloc_crate::format;
#[cfg(any(test, feature = "harness"))]
use alloc_crate::string::String;
#[cfg(any(test, feature = "harness"))]
use alloc_crate::string::ToString;
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
    addr: u64,
    woken: bool,
}

#[cfg(any(test, feature = "harness"))]
#[derive(Clone, Copy)]
struct ExternalFutexTraceEntry {
    op: u32,
    pid: i32,
    addr: u64,
    value: u32,
}

#[cfg(any(test, feature = "harness"))]
const EXTERNAL_FUTEX_TRACE_CAP: usize = 128;

#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_TRACE: [ExternalFutexTraceEntry; EXTERNAL_FUTEX_TRACE_CAP] =
    [ExternalFutexTraceEntry {
        op: 0,
        pid: 0,
        addr: 0,
        value: 0,
    }; EXTERNAL_FUTEX_TRACE_CAP];

#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_TRACE_NEXT: u32 = 0;

#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_TRACE_LEN: u32 = 0;
#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_REG_COUNT: u32 = 0;
#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_WAKE_COUNT: u32 = 0;
#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_REQUEUE_COUNT: u32 = 0;
#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_TAKE_COUNT: u32 = 0;
#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_LAST_REG_PID: i32 = 0;
#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_LAST_REG_ADDR: u64 = 0;
#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_LAST_WAKE_ADDR: u64 = 0;
#[cfg(any(test, feature = "harness"))]
static mut EXTERNAL_FUTEX_LAST_WAKE_RESULT: u32 = 0;

#[cfg(any(test, feature = "harness"))]
fn record_external_futex_trace(op: u32, pid: i32, addr: u64, value: u32) {
    unsafe {
        if EXTERNAL_FUTEX_TRACE_LEN < EXTERNAL_FUTEX_TRACE_CAP as u32 {
            let idx = EXTERNAL_FUTEX_TRACE_LEN as usize;
            EXTERNAL_FUTEX_TRACE[idx] = ExternalFutexTraceEntry {
                op,
                pid,
                addr,
                value,
            };
            EXTERNAL_FUTEX_TRACE_LEN += 1;
        }
        EXTERNAL_FUTEX_TRACE_NEXT = EXTERNAL_FUTEX_TRACE_NEXT.saturating_add(1);
    }
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
    let mem_size = crate::wasm::memory_size_bytes() as usize;
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
        EXTERNAL_FUTEX_TRACE_NEXT = 0;
        EXTERNAL_FUTEX_TRACE_LEN = 0;
        EXTERNAL_FUTEX_REG_COUNT = 0;
        EXTERNAL_FUTEX_WAKE_COUNT = 0;
        EXTERNAL_FUTEX_REQUEUE_COUNT = 0;
        EXTERNAL_FUTEX_TAKE_COUNT = 0;
        EXTERNAL_FUTEX_LAST_REG_PID = 0;
        EXTERNAL_FUTEX_LAST_REG_ADDR = 0;
        EXTERNAL_FUTEX_LAST_WAKE_ADDR = 0;
        EXTERNAL_FUTEX_LAST_WAKE_RESULT = 0;
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn register_external_futex_wait(pid: i32, addr: u64) {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return;
    }
    unsafe {
        EXTERNAL_FUTEX_REG_COUNT = EXTERNAL_FUTEX_REG_COUNT.saturating_add(1);
        EXTERNAL_FUTEX_LAST_REG_PID = pid;
        EXTERNAL_FUTEX_LAST_REG_ADDR = addr;
        record_external_futex_trace(1, pid, addr, 0);
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        if slot.is_none() {
            *slot = Some(Vec::new());
        }
        if let Some(waits) = slot.as_mut() {
            if let Some(wait) = waits.iter_mut().find(|wait| wait.pid == pid) {
                wait.addr = addr;
                wait.woken = false;
                return;
            }
            waits.push(ExternalFutexWait {
                pid,
                addr,
                woken: false,
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
        record_external_futex_trace(2, pid, 0, 0);
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        if let Some(waits) = slot.as_mut() {
            waits.retain(|wait| wait.pid != pid);
        }
    }
}

pub fn wake_external_futex_waits(addr: u64, max_wake: u32) -> u32 {
    wake_external_futex_waits_from_pid(0, addr, max_wake)
}

pub fn wake_external_futex_waits_from_pid(caller_pid: i32, addr: u64, max_wake: u32) -> u32 {
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
            if wait.addr != addr || wait.woken {
                continue;
            }
            wait.woken = true;
            woken += 1;
            if woken == max_wake {
                break;
            }
        }
        EXTERNAL_FUTEX_WAKE_COUNT = EXTERNAL_FUTEX_WAKE_COUNT.saturating_add(1);
        EXTERNAL_FUTEX_LAST_WAKE_ADDR = addr;
        EXTERNAL_FUTEX_LAST_WAKE_RESULT = woken;
        record_external_futex_trace(3, caller_pid, addr, woken);
        woken
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn describe_external_futex_waits() -> String {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return "disabled".to_string();
    }
    unsafe {
        let slot = &*core::ptr::addr_of!(EXTERNAL_FUTEX_WAITS);
        let Some(waits) = slot.as_ref() else {
            return "none".to_string();
        };
        let mut parts = Vec::new();
        for wait in waits.iter() {
            parts.push(format!(
                "pid={} addr=0x{:x} woken={}",
                wait.pid, wait.addr, wait.woken
            ));
        }
        format!("[{}]", parts.join(" | "))
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn describe_external_futex_trace() -> String {
    unsafe {
        let len = EXTERNAL_FUTEX_TRACE_LEN as usize;
        let mut parts = Vec::new();
        for idx in 0..len {
            let entry = EXTERNAL_FUTEX_TRACE[idx];
            let op = match entry.op {
                1 => "reg",
                2 => "clear",
                3 => "wake",
                4 => "take",
                5 => "take_pid",
                6 => "requeue",
                _ => "?",
            };
            parts.push(format!(
                "{}(pid={} addr=0x{:x} value={})",
                op, entry.pid, entry.addr, entry.value
            ));
        }
        let reg_count = EXTERNAL_FUTEX_REG_COUNT;
        let wake_count = EXTERNAL_FUTEX_WAKE_COUNT;
        let requeue_count = EXTERNAL_FUTEX_REQUEUE_COUNT;
        let take_count = EXTERNAL_FUTEX_TAKE_COUNT;
        let last_reg_pid = EXTERNAL_FUTEX_LAST_REG_PID;
        let last_reg_addr = EXTERNAL_FUTEX_LAST_REG_ADDR;
        let last_wake_addr = EXTERNAL_FUTEX_LAST_WAKE_ADDR;
        let last_wake_result = EXTERNAL_FUTEX_LAST_WAKE_RESULT;
        format!(
            "counts(reg={} wake={} requeue={} take={} last_reg=pid{}@0x{:x} last_wake=0x{:x}/{}): {}",
            reg_count,
            wake_count,
            requeue_count,
            take_count,
            last_reg_pid,
            last_reg_addr,
            last_wake_addr,
            last_wake_result,
            parts.join(" -> ")
        )
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn describe_last_jalr_trace() -> String {
    let entry = crate::harness::debug::last_jalr_trace();
    format!(
        "vm_ptr=0x{:x} pc=0x{:x} rd={} rs1={} rs1_value=0x{:x} target=0x{:x}",
        entry.vm_ptr, entry.pc, entry.rd, entry.rs1, entry.rs1_value, entry.target
    )
}

#[cfg(any(test, feature = "harness"))]
pub fn describe_fault_exec_trace_for_vm(vm_ptr: u32) -> String {
    let len = crate::harness::debug::fault_exec_trace_len_for_vm(vm_ptr);
    if len == 0 {
        return format!("vm_ptr=0x{vm_ptr:x} len=0");
    }
    let start = len.saturating_sub(64);
    let mut parts = Vec::new();
    for idx in start..len {
        let entry = crate::harness::debug::fault_exec_trace_entry_for_vm(vm_ptr, idx);
        parts.push(format!(
            "pc=0x{:x} raw=0x{:08x} step={} a0=0x{:x} a4=0x{:x} a5=0x{:x} ra=0x{:x} sp=0x{:x}",
            entry.pc, entry.raw, entry.step, entry.a0, entry.a4, entry.a5, entry.ra, entry.sp
        ));
    }
    format!("vm_ptr=0x{vm_ptr:x} len={len} [{}]", parts.join(" | "))
}

#[cfg(any(test, feature = "harness"))]
pub fn describe_execve_stage_trace() -> String {
    let len = crate::harness::debug::execve_stage_trace_len();
    if len == 0 {
        return "len=0".to_string();
    }
    let start = len.saturating_sub(48);
    let mut parts = Vec::new();
    for idx in start..len {
        let entry = crate::harness::debug::execve_stage_trace_entry(idx);
        parts.push(format!(
            "{}:0x{:x}/0x{:x}",
            entry.stage, entry.value0, entry.value1
        ));
    }
    format!("len={len} [{}]", parts.join(" | "))
}

#[cfg(any(test, feature = "harness"))]
pub fn describe_exec_trace_tail() -> String {
    let len = crate::harness::debug::exec_trace_len();
    if len == 0 {
        return "len=0".to_string();
    }
    let start = len.saturating_sub(16);
    let mut parts = Vec::new();
    for idx in start..len {
        let entry = crate::harness::debug::exec_trace_entry(idx);
        parts.push(format!(
            "vm=0x{:x} pc=0x{:x} raw=0x{:08x} step={} a0=0x{:x} a4=0x{:x} a5=0x{:x} ra=0x{:x} sp=0x{:x}",
            entry.vm_ptr, entry.pc, entry.raw, entry.step, entry.a0, entry.a4, entry.a5, entry.ra, entry.sp
        ));
    }
    format!("len={len} [{}]", parts.join(" | "))
}

#[cfg(any(test, feature = "harness"))]
pub fn describe_exec_trace_for_vm(vm_ptr: u32) -> String {
    let len = crate::harness::debug::exec_trace_len();
    if len == 0 {
        return format!("vm_ptr=0x{vm_ptr:x} len=0");
    }
    let mut total = 0u32;
    let mut parts = Vec::new();
    for idx in 0..len {
        let entry = crate::harness::debug::exec_trace_entry(idx);
        if entry.vm_ptr != vm_ptr {
            continue;
        }
        total = total.saturating_add(1);
        if parts.len() == 32 {
            parts.remove(0);
        }
        parts.push(format!(
            "epoch={} pc=0x{:x} raw=0x{:08x} step={} a0=0x{:x} a4=0x{:x} a5=0x{:x} ra=0x{:x} sp=0x{:x}",
            entry.epoch, entry.pc, entry.raw, entry.step, entry.a0, entry.a4, entry.a5, entry.ra, entry.sp
        ));
    }
    if total == 0 {
        format!("vm_ptr=0x{vm_ptr:x} matches=0 ring_len={len}")
    } else {
        format!(
            "vm_ptr=0x{vm_ptr:x} matches={total} ring_len={len} [{}]",
            parts.join(" | ")
        )
    }
}

pub fn requeue_external_futex_waits(addr: u64, new_addr: u64, max_requeue: u32) -> u32 {
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
            if wait.addr != addr || wait.woken {
                continue;
            }
            wait.addr = new_addr;
            requeued += 1;
            if requeued == max_requeue {
                break;
            }
        }
        EXTERNAL_FUTEX_REQUEUE_COUNT = EXTERNAL_FUTEX_REQUEUE_COUNT.saturating_add(1);
        record_external_futex_trace(6, 0, addr, requeued);
        requeued
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn take_external_futex_wake(pid: i32, addr: u64) -> bool {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return false;
    }
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return false;
        };

        if let Some(idx) = waits
            .iter()
            .position(|wait| wait.pid == pid && wait.addr == addr && wait.woken)
        {
            waits.remove(idx);
            EXTERNAL_FUTEX_TAKE_COUNT = EXTERNAL_FUTEX_TAKE_COUNT.saturating_add(1);
            record_external_futex_trace(4, pid, addr, 1);
            true
        } else {
            record_external_futex_trace(4, pid, addr, 0);
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
pub fn has_external_futex_wake(pid: i32) -> bool {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return false;
    }
    unsafe {
        let slot = &*core::ptr::addr_of!(EXTERNAL_FUTEX_WAITS);
        let Some(waits) = slot.as_ref() else {
            return false;
        };

        waits.iter().any(|wait| wait.pid == pid && wait.woken)
    }
}

#[cfg(any(test, feature = "harness"))]
pub fn take_external_futex_wake_for_pid(pid: i32) -> bool {
    if !HARNESS_RUNTIME_SUPPORT_ENABLED {
        return false;
    }
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EXTERNAL_FUTEX_WAITS);
        let Some(waits) = slot.as_mut() else {
            return false;
        };

        if let Some(idx) = waits.iter().position(|wait| wait.pid == pid && wait.woken) {
            let addr = waits[idx].addr;
            waits.remove(idx);
            EXTERNAL_FUTEX_TAKE_COUNT = EXTERNAL_FUTEX_TAKE_COUNT.saturating_add(1);
            record_external_futex_trace(5, pid, addr, 1);
            true
        } else {
            record_external_futex_trace(5, pid, 0, 0);
            false
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
    futex_addr: u64,
) -> Option<(u32, u32, u32, u32)> {
    let addr = futex_addr;
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
