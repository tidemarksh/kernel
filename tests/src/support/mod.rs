//! ELF test helpers for integration tests.
//! Uses Result<(), String> to avoid panics (wasm32-wasip1 uses panic=abort,
//! so any panic causes a WASM trap that terminates the entire test binary).

use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tidemark_kernel::abi::*;
use tidemark_kernel::fs::memfs;
use tidemark_kernel::guest_mem;
use tidemark_kernel::types::*;

const GUEST_RAM_SIZE: u32 = 0x1000_0000;
const GUEST_RAM_ALIGN: u32 = 0x20_0000;
// The LTP harness uses std-backed Vec/Box allocations after guest setup
// (notably process memory snapshots). On wasm32-wasip1 those allocations grow
// below guest_base, so keep enough headroom before the guest window for
// high-fanout process tests.
const GUEST_BASE_PADDING: u32 = 0x4000_0000;
// Keep the kernel bump heap far enough above the guest window to avoid aliasing
// kernel-owned allocations with guest RAM.
const HOST_HEAP_PADDING: u32 = 0x4000_0000;
const GUEST_SNAPSHOT_CHUNK: usize = 64 * 1024;
const TEST_MEMORY_PAGES: usize = 512; // 32 MiB
const INITIAL_PID: i32 = 2;
const INITIAL_PPID: i32 = 1;
const MAX_VM_INSTRUCTIONS: i64 = 500_000_000;
const SYNC_EFFECT_PROCESS_LIFECYCLE: u32 = 1 << 4;

static mut TEST_GUEST_BASE: u32 = 0;

#[derive(Clone, Copy)]
struct LtpVmIdentityTrace {
    vm_ptr: u32,
    label: u32,
    pid: i32,
    ppid: i32,
    tid: i32,
    status: i32,
    process_ptr: u32,
    pc: u64,
    sp: u64,
}

#[derive(Clone, Copy)]
struct LtpMemoryProbeTrace {
    label: u32,
    pid: i32,
    snapshot_len: usize,
    snapshot_word: u32,
    live_word: u32,
}

const LTP_VM_IDENTITY_TRACE_CAP: usize = 256;
static mut LTP_VM_IDENTITY_TRACE: [LtpVmIdentityTrace; LTP_VM_IDENTITY_TRACE_CAP] =
    [LtpVmIdentityTrace {
        vm_ptr: 0,
        label: 0,
        pid: 0,
        ppid: 0,
        tid: 0,
        status: 0,
        process_ptr: 0,
        pc: 0,
        sp: 0,
    }; LTP_VM_IDENTITY_TRACE_CAP];
static mut LTP_VM_IDENTITY_TRACE_NEXT: u32 = 0;
static mut LTP_VM_IDENTITY_TRACE_LEN: u32 = 0;

pub(crate) const LTP_VM_ID_ROOT: u32 = 1;
pub(crate) const LTP_VM_ID_SAVED_STEP: u32 = 2;
pub(crate) const LTP_VM_ID_SPAWN: u32 = 3;
pub(crate) const LTP_VM_ID_PLACEHOLDER: u32 = 4;
const LTP_MEM_PROBE_SAVED_PRE_RESTORE: u32 = 1;
const LTP_MEM_PROBE_SAVED_POST_RESTORE: u32 = 2;
const LTP_MEM_PROBE_SAVED_PRE_RUN: u32 = 3;
const LTP_MEM_PROBE_SPAWN_SNAPSHOT: u32 = 4;
const LTP_MEM_PROBE_PARENT_SCRATCH_SPAWN: u32 = 5;
const LTP_MEM_PROBE_DEFERRED_SERVICE_BEFORE: u32 = 6;
const LTP_MEM_PROBE_DEFERRED_SERVICE_AFTER: u32 = 7;
const LTP_MEM_PROBE_SPAWN_BEFORE_FLUSH: u32 = 8;
const LTP_MEM_PROBE_SPAWN_AFTER_FLUSH: u32 = 9;
const LTP_MEM_PROBE_PARENT_SCRATCH_CAPTURE: u32 = 10;
const LTP_MEM_PROBE_PARENT_SCRATCH_AFTER_CHILD: u32 = 11;
const LTP_MEM_PROBE_PARENT_SCRATCH_AFTER_RESTORE: u32 = 12;
const LTP_MEM_PROBE_ADDR: usize = 0xd9000;
const LTP_MEMORY_PROBE_TRACE_CAP: usize = 512;
static mut LTP_MEMORY_PROBE_TRACE: [LtpMemoryProbeTrace; LTP_MEMORY_PROBE_TRACE_CAP] =
    [LtpMemoryProbeTrace {
        label: 0,
        pid: 0,
        snapshot_len: 0,
        snapshot_word: 0,
        live_word: 0,
    }; LTP_MEMORY_PROBE_TRACE_CAP];
static mut LTP_MEMORY_PROBE_TRACE_NEXT: u32 = 0;
static mut LTP_MEMORY_PROBE_TRACE_LEN: u32 = 0;

fn ltp_vm_identity_label(label: u32) -> &'static str {
    match label {
        LTP_VM_ID_ROOT => "root",
        LTP_VM_ID_SAVED_STEP => "saved-step",
        LTP_VM_ID_SPAWN => "spawn",
        LTP_VM_ID_PLACEHOLDER => "placeholder",
        _ => "unknown",
    }
}

fn record_ltp_vm_identity_entry(entry: LtpVmIdentityTrace) {
    unsafe {
        let idx = (LTP_VM_IDENTITY_TRACE_NEXT as usize) % LTP_VM_IDENTITY_TRACE_CAP;
        LTP_VM_IDENTITY_TRACE[idx] = entry;
        LTP_VM_IDENTITY_TRACE_NEXT = ((idx + 1) % LTP_VM_IDENTITY_TRACE_CAP) as u32;
        if LTP_VM_IDENTITY_TRACE_LEN < LTP_VM_IDENTITY_TRACE_CAP as u32 {
            LTP_VM_IDENTITY_TRACE_LEN += 1;
        }
    }
}

fn ltp_memory_probe_label(label: u32) -> &'static str {
    match label {
        LTP_MEM_PROBE_SAVED_PRE_RESTORE => "saved-pre-restore",
        LTP_MEM_PROBE_SAVED_POST_RESTORE => "saved-post-restore",
        LTP_MEM_PROBE_SAVED_PRE_RUN => "saved-pre-run",
        LTP_MEM_PROBE_SPAWN_SNAPSHOT => "spawn-snapshot",
        LTP_MEM_PROBE_PARENT_SCRATCH_SPAWN => "parent-scratch-spawn",
        LTP_MEM_PROBE_DEFERRED_SERVICE_BEFORE => "deferred-service-before",
        LTP_MEM_PROBE_DEFERRED_SERVICE_AFTER => "deferred-service-after",
        LTP_MEM_PROBE_SPAWN_BEFORE_FLUSH => "spawn-before-flush",
        LTP_MEM_PROBE_SPAWN_AFTER_FLUSH => "spawn-after-flush",
        LTP_MEM_PROBE_PARENT_SCRATCH_CAPTURE => "parent-scratch-capture",
        LTP_MEM_PROBE_PARENT_SCRATCH_AFTER_CHILD => "parent-scratch-after-child",
        LTP_MEM_PROBE_PARENT_SCRATCH_AFTER_RESTORE => "parent-scratch-after-restore",
        _ => "unknown",
    }
}

fn record_ltp_memory_probe(
    label: u32,
    pid: i32,
    snapshot_len: usize,
    snapshot_word: u32,
    live_word: u32,
) {
    unsafe {
        let idx = (LTP_MEMORY_PROBE_TRACE_NEXT as usize) % LTP_MEMORY_PROBE_TRACE_CAP;
        LTP_MEMORY_PROBE_TRACE[idx] = LtpMemoryProbeTrace {
            label,
            pid,
            snapshot_len,
            snapshot_word,
            live_word,
        };
        LTP_MEMORY_PROBE_TRACE_NEXT = ((idx + 1) % LTP_MEMORY_PROBE_TRACE_CAP) as u32;
        if LTP_MEMORY_PROBE_TRACE_LEN < LTP_MEMORY_PROBE_TRACE_CAP as u32 {
            LTP_MEMORY_PROBE_TRACE_LEN += 1;
        }
    }
}

fn record_ltp_thread_state_identity(
    base: u32,
    vm: &ThreadState,
    fallback_pid: i32,
    fallback_ppid: i32,
    label: u32,
) {
    record_ltp_vm_identity_entry(LtpVmIdentityTrace {
        vm_ptr: vm as *const ThreadState as u32,
        label,
        pid: process_pid_or(base, vm.process_ptr, fallback_pid),
        ppid: process_ppid_or(base, vm.process_ptr, fallback_ppid),
        tid: vm.tid,
        status: vm.status,
        process_ptr: vm.process_ptr,
        pc: vm.pc,
        sp: vm.x[2],
    });
}

fn process_pid_or(base: u32, process_ptr: u32, fallback_pid: i32) -> i32 {
    if process_ptr != 0 {
        process_pid(base, process_ptr)
    } else {
        fallback_pid
    }
}

fn process_ppid_or(base: u32, process_ptr: u32, fallback_ppid: i32) -> i32 {
    if process_ptr != 0 {
        process_ppid(base, process_ptr)
    } else {
        fallback_ppid
    }
}

pub fn describe_ltp_vm_identity(vm_ptr: u32) -> String {
    unsafe {
        let len = LTP_VM_IDENTITY_TRACE_LEN;
        let next = LTP_VM_IDENTITY_TRACE_NEXT as usize;
        let mut matches = Vec::new();
        for offset in 0..len as usize {
            let slot = if (len as usize) < LTP_VM_IDENTITY_TRACE_CAP {
                offset
            } else {
                (next + offset) % LTP_VM_IDENTITY_TRACE_CAP
            };
            let entry = LTP_VM_IDENTITY_TRACE[slot];
            if entry.vm_ptr != vm_ptr {
                continue;
            }
            if matches.len() == 16 {
                matches.remove(0);
            }
            matches.push(format!(
                "{} pid={} ppid={} tid={} status={} process_ptr=0x{:x} pc=0x{:x} sp=0x{:x}",
                ltp_vm_identity_label(entry.label),
                entry.pid,
                entry.ppid,
                entry.tid,
                entry.status,
                entry.process_ptr,
                entry.pc,
                entry.sp
            ));
        }
        if matches.is_empty() {
            format!("vm_ptr=0x{vm_ptr:x} not found")
        } else {
            format!("vm_ptr=0x{vm_ptr:x} [{}]", matches.join(" | "))
        }
    }
}

pub fn describe_ltp_memory_probe() -> String {
    unsafe {
        let len = LTP_MEMORY_PROBE_TRACE_LEN;
        let next = LTP_MEMORY_PROBE_TRACE_NEXT as usize;
        let mut parts = Vec::new();
        for offset in 0..len {
            let slot = if (len as usize) < LTP_MEMORY_PROBE_TRACE_CAP {
                offset as usize
            } else {
                (next + offset as usize) % LTP_MEMORY_PROBE_TRACE_CAP
            };
            let entry = LTP_MEMORY_PROBE_TRACE[slot];
            if entry.pid != 3 && offset < len.saturating_sub(16) {
                continue;
            }
            if parts.len() == 32 {
                parts.remove(0);
            }
            parts.push(format!(
                "{} pid={} snapshot_len=0x{:x} snapshot[0x{:x}]=0x{:08x} live=0x{:08x}",
                ltp_memory_probe_label(entry.label),
                entry.pid,
                entry.snapshot_len,
                LTP_MEM_PROBE_ADDR,
                entry.snapshot_word,
                entry.live_word
            ));
        }
        if parts.is_empty() {
            "len=0".to_string()
        } else {
            parts.join(" | ")
        }
    }
}

fn saved_ctx_validation_enabled() -> bool {
    std::env::var_os("TIDEMARK_VALIDATE_SAVED_CTX").is_some()
}

pub(crate) fn cmp_requeue_shared_words(base: u32, futex_addr: u32) -> Option<(u32, u32, u32, u32)> {
    if futex_addr == 0 {
        return None;
    }
    unsafe {
        Some((
            guest_mem::read_u32(base, futex_addr as u64),
            guest_mem::read_u32(base, futex_addr as u64 + 4),
            guest_mem::read_u32(base, futex_addr as u64 + 8),
            guest_mem::read_u32(base, futex_addr as u64 + 12),
        ))
    }
}

fn snapshot_probe_word(snapshot: &GuestMemorySnapshot) -> u32 {
    if LTP_MEM_PROBE_ADDR + 4 > snapshot.len {
        return 0xffff_fffe;
    }
    let mut word = [0u8; 4];
    if snapshot.copy_out(LTP_MEM_PROBE_ADDR, &mut word).is_err() {
        return 0xffff_fffd;
    }
    u32::from_le_bytes(word)
}

fn live_probe_word(base: u32) -> u32 {
    unsafe { guest_mem::read_u32(base, LTP_MEM_PROBE_ADDR as u64) }
}

pub fn describe_current_guest_u32_words(start: u32, count: usize) -> String {
    let base = unsafe { TEST_GUEST_BASE };
    if base == 0 {
        return "guest_base=0".to_string();
    }
    let limit = guest_window_size(base) as u64;
    let mut parts = Vec::new();
    for idx in 0..count {
        let addr = start as u64 + (idx as u64) * 4;
        if addr + 4 > limit {
            parts.push(format!("0x{addr:x}=<out-of-range>"));
            continue;
        }
        let value = unsafe { guest_mem::read_u32(base, addr) };
        parts.push(format!("0x{addr:x}=0x{value:08x}"));
    }
    format!("guest_base=0x{base:x} {}", parts.join(" "))
}

pub fn describe_current_guest_u64_words(start: u64, count: usize) -> String {
    let base = unsafe { TEST_GUEST_BASE };
    if base == 0 {
        return "guest_base=0".to_string();
    }
    let limit = guest_window_size(base) as u64;
    let mut parts = Vec::new();
    for idx in 0..count {
        let addr = start.saturating_add((idx as u64) * 8);
        if addr + 8 > limit
            || !tidemark_kernel::syscall::memory::guest_range_accessible(base, addr, 8)
        {
            parts.push(format!("0x{addr:x}=<inaccessible>"));
            continue;
        }
        let value = unsafe { guest_mem::read_u64(base, addr) };
        parts.push(format!("0x{addr:x}=0x{value:016x}"));
    }
    format!("guest_base=0x{base:x} {}", parts.join(" "))
}

pub(crate) struct SavedProcessCtx {
    pub(crate) pid: i32,
    #[allow(dead_code)]
    pub(crate) parent_pid: i32,
    pub(crate) process_group: i32,
    pub(crate) shared_overlay_key: i32,
    child_entries: Vec<(i32, bool, i32)>,
    vm: ThreadState,
    last_futex_addr: u32,
    // True when this saved child no longer needs a full guest-memory snapshot
    // because the harness will only wait for `test_done` and then record exit.
    waiter_placeholder: bool,
    guest_memory: Box<GuestMemorySnapshot>,
    mm_state: Box<tidemark_kernel::harness::support::ProcessContextSnapshot>,
}

// Reusable waiter shape for large futex cohorts. The harness executes one
// representative child to the wait state, then clones this template for later
// siblings that would otherwise repeat the same setup work.
pub(crate) struct SavedWaiterTemplate {
    vm: ThreadState,
    last_futex_addr: u32,
}

impl SavedProcessCtx {
    pub(crate) fn record_vm_identity(&self, base: u32, label: u32) {
        record_ltp_thread_state_identity(base, &self.vm, self.pid, self.parent_pid, label);
    }

    pub(crate) fn normalize_process_leader_vm(&mut self) {
        if self.pid > 0 && self.vm.process_ptr != 0 && self.vm.tid <= 0 {
            self.vm.tid = self.pid;
        }
    }

    pub(crate) fn status(&self) -> i32 {
        self.vm.status
    }

    pub(crate) fn a0(&self) -> u64 {
        self.vm.x[10]
    }

    pub(crate) fn a7(&self) -> u64 {
        self.vm.x[17]
    }

    pub(crate) fn wait_kind(&self) -> u32 {
        self.vm.wait_kind
    }

    pub(crate) fn wait_pid(&self) -> i64 {
        self.vm.wait_pid
    }

    pub(crate) fn tid(&self) -> i32 {
        self.vm.tid
    }

    pub(crate) fn process_ptr(&self) -> u32 {
        self.vm.process_ptr
    }

    pub(crate) fn describe_threads(&self, base: u32) -> String {
        describe_process_threads(&self.vm, base)
    }

    pub(crate) fn describe_snapshot_threads(&self) -> String {
        if self.vm.process_ptr == 0 || self.guest_memory.len == 0 {
            return "snapshot unavailable".to_string();
        }
        let process_ptr = self.vm.process_ptr as usize;
        let thread_count_off = process_ptr + core::mem::offset_of!(ProcessState, thread_count);
        let thread_count = self
            .guest_memory
            .read_i32(thread_count_off)
            .unwrap_or_default();
        let threads_off = process_ptr + core::mem::offset_of!(ProcessState, threads);
        let record_size = core::mem::size_of::<ThreadRecord>();
        let mut parts = Vec::new();
        for idx in 0..MAX_THREADS {
            let off = threads_off + idx * record_size;
            let mut bytes = [0u8; core::mem::size_of::<ThreadRecord>()];
            if self.guest_memory.copy_out(off, &mut bytes).is_err() {
                break;
            }
            let record =
                unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const ThreadRecord) };
            if matches!(record.state, THREAD_NONE | THREAD_DEAD) {
                continue;
            }
            parts.push(format!(
                "slot={} tid={} state={} thread_ptr=0x{:x} blocked=0x{:x} clear_child_tid=0x{:x}",
                idx + 1,
                record.tid,
                record.state,
                record.thread_ptr,
                record.blocked_addr,
                record.clear_child_tid,
            ));
        }
        format!(
            "snapshot_thread_count={} [{}]",
            thread_count,
            parts.join(" | ")
        )
    }

    pub(crate) fn guest_memory_len(&self) -> usize {
        self.guest_memory.len
    }

    pub(crate) fn is_waiter_placeholder(&self) -> bool {
        self.waiter_placeholder
    }

    pub(crate) fn last_futex_addr(&self) -> u32 {
        self.last_futex_addr
    }

    pub(crate) fn downgrade_to_waiter_placeholder(&mut self) {
        let old_guest_memory =
            core::mem::replace(&mut self.guest_memory, GuestMemorySnapshot::empty_box());
        core::mem::forget(old_guest_memory);
        let old_mm_state = core::mem::replace(
            &mut self.mm_state,
            tidemark_kernel::harness::support::snapshot_process_context_boxed(),
        );
        core::mem::forget(old_mm_state);
        self.waiter_placeholder = true;
        self.child_entries.clear();
    }

    pub(crate) fn capture_waiter_template(&self) -> SavedWaiterTemplate {
        SavedWaiterTemplate {
            vm: unsafe { core::ptr::read(&self.vm as *const _) },
            last_futex_addr: self.last_futex_addr,
        }
    }

    pub(crate) fn from_waiter_template(
        template: &SavedWaiterTemplate,
        identity: &SavedProcessCtx,
        parent_pid: i32,
    ) -> Self {
        let mut vm: ThreadState = unsafe { core::ptr::read(&identity.vm as *const _) };
        vm.status = template.vm.status;
        vm.futex_wait_addr = template.vm.futex_wait_addr;
        vm.futex_wait_timeout = template.vm.futex_wait_timeout;
        vm.futex_wait_expected = template.vm.futex_wait_expected;
        vm.futex_wait_bitset = template.vm.futex_wait_bitset;
        vm.futex_wait_absolute = template.vm.futex_wait_absolute;
        vm.futex_wait_flags = template.vm.futex_wait_flags;
        vm.tid = identity.pid;
        vm.spawn_child_pid = 0;
        vm.spawn_kind = 0;
        vm.clone_pending = 0;
        vm.wait_pid = 0;
        let futex_addr = if template.last_futex_addr != 0 {
            template.last_futex_addr
        } else {
            vm.futex_wait_addr as u32
        };
        if vm.status == STATUS_FUTEX_WAIT && futex_addr != 0 {
            tidemark_kernel::harness::support::register_external_futex_wait(
                identity.pid,
                futex_addr,
            );
        }
        Self {
            pid: identity.pid,
            parent_pid,
            process_group: identity.process_group,
            shared_overlay_key: identity.shared_overlay_key,
            child_entries: Vec::new(),
            vm,
            last_futex_addr: futex_addr,
            waiter_placeholder: true,
            guest_memory: GuestMemorySnapshot::empty_box(),
            mm_state: tidemark_kernel::harness::support::snapshot_process_context_boxed(),
        }
    }

    pub(crate) fn resume_wait4(&mut self, base: u32) {
        let vm_ptr = &mut self.vm as *mut ThreadState as u32;
        tidemark_kernel::syscall::process::resume_wait4(vm_ptr, base);
    }

    pub(crate) fn resume_wait4_and_refresh_snapshot_with_children_from_current_snapshot(
        &mut self,
        current: &PreparedElfVm,
        current_memory: &GuestMemorySnapshot,
        current_mm_state: &tidemark_kernel::harness::support::ProcessContextSnapshot,
        current_child_proc_stats: &[(i32, i32, u8, i32)],
        current_child_entries: &mut Vec<(i32, bool, i32)>,
        child_proc_stats: &[(i32, i32, u8, i32)],
        shared_overlay: Option<&tidemark_kernel::harness::support::SharedMappingOverlay>,
    ) -> Result<tidemark_kernel::harness::support::SharedMappingOverlay, String> {
        let base = current.base;
        for (pid, exited, wait_status) in current_child_entries.iter_mut() {
            if *exited {
                continue;
            }
            if let Some((_, recorded_exited, recorded_wait_status)) =
                tidemark_kernel::harness::process::debug_child_entry(*pid)
            {
                if recorded_exited {
                    *exited = true;
                    *wait_status = recorded_wait_status;
                    continue;
                }
            }
            let still_queued = child_proc_stats
                .iter()
                .any(|(child_pid, _, _, _)| *child_pid == *pid);
            if still_queued {
                continue;
            }
            if !tidemark_kernel::harness::process::debug_process_entry_exists(*pid) {
                *exited = true;
                *wait_status = 0;
            }
        }
        let current_shared_mappings =
            tidemark_kernel::harness::support::capture_live_shared_mapping_overlay(
                base,
                guest_window_size(base) as u64,
                current_mm_state,
            );

        tidemark_kernel::harness::support::restore_process_context_mm_only_from_guest_snapshot(
            base,
            guest_window_size(base) as u64,
            &self.mm_state,
            || {
                self.guest_memory.restore(base).map_err(|e| {
                    format!(
                        "restore saved process pid {} guest memory for wait4 refresh: {}",
                        self.pid, e
                    )
                })
            },
        )?;
        if let Some(shared_overlay) = shared_overlay {
            tidemark_kernel::harness::support::restore_live_shared_mapping_overlay(
                base,
                shared_overlay,
            );
        } else {
            tidemark_kernel::harness::support::restore_live_shared_mapping_overlay(
                base,
                &current_shared_mappings,
            );
        }
        restore_process_state_snapshot(&self.guest_memory, base, self.vm.process_ptr)?;
        for (pid, ppid, state, pgrp) in current_child_proc_stats.iter().copied() {
            ensure_proc_pid_stat(pid, ppid, state, pgrp)?;
        }
        for (pid, ppid, state, pgrp) in child_proc_stats.iter().copied() {
            ensure_proc_pid_stat(pid, ppid, state, pgrp)?;
        }
        for (pid, exited, wait_status) in current_child_entries.iter().copied() {
            tidemark_kernel::harness::process::sync_child_entry_for_parent(
                self.pid,
                pid,
                exited,
                wait_status,
            );
        }
        refresh_proc_pid_stat(&self.vm, base, b'R')?;
        self.resume_wait4(base);
        refresh_proc_pid_stat(
            &self.vm,
            base,
            if self.status() == STATUS_WAIT4 {
                b'S'
            } else {
                b'R'
            },
        )?;
        self.guest_memory
            .recapture_into_scratch_for_vm(base, &self.vm);
        self.mm_state = tidemark_kernel::harness::support::snapshot_process_context_boxed();
        self.child_entries = capture_live_child_entries(self.pid);
        current_child_entries.clear();
        current_child_entries.extend(self.child_entries.iter().copied());
        let saved_shared_mappings =
            tidemark_kernel::harness::support::capture_live_shared_mapping_overlay(
                base,
                guest_window_size(base) as u64,
                self.mm_state.as_ref(),
            );

        tidemark_kernel::harness::support::restore_process_context_mm_only_from_guest_snapshot(
            base,
            guest_window_size(base) as u64,
            current_mm_state,
            || {
                current_memory.restore(base).map_err(|e| {
                    format!(
                        "restore current guest memory after wait4 refresh for saved pid {}: {}",
                        self.pid, e
                    )
                })
            },
        )?;
        tidemark_kernel::harness::support::restore_live_shared_mapping_overlay(
            base,
            &saved_shared_mappings,
        );
        restore_process_state_snapshot(&current_memory, base, current.vm.process_ptr)?;
        ensure_saved_proc_pid_stat(self, proc_pid_stat_state_for_status(self.vm.status))?;
        repair_current_main_thread_record(&current.vm, base);
        Ok(saved_shared_mappings)
    }

    pub(crate) fn refresh_runtime_snapshot(&mut self) {
        tidemark_kernel::harness::support::refresh_process_context_runtime_state(
            self.mm_state.as_mut(),
        );
    }

    pub(crate) fn refresh_child_entries_from_live(&mut self) {
        self.child_entries = capture_live_child_entries(self.pid);
    }

    pub(crate) fn discard_exit_only_state(&mut self) {
        let old_guest_memory =
            core::mem::replace(&mut self.guest_memory, GuestMemorySnapshot::empty_box());
        core::mem::forget(old_guest_memory);
        self.pid = 0;
        self.parent_pid = 0;
        self.process_group = 0;
        self.shared_overlay_key = 0;
        self.child_entries.clear();
        self.vm.tid = 0;
        self.vm.process_ptr = 0;
        self.vm.status = STATUS_OK;
        self.vm.wait_pid = 0;
        self.vm.futex_wait_addr = 0;
        self.vm.futex_wait_expected = 0;
        self.vm.futex_wait_timeout = 0;
        self.last_futex_addr = 0;
        self.waiter_placeholder = false;
    }
}

impl Drop for SavedProcessCtx {
    fn drop(&mut self) {
        let guest_memory = unsafe { core::ptr::read(&self.guest_memory) };
        core::mem::forget(guest_memory);
        self.guest_memory = GuestMemorySnapshot::empty_box();
        let mm_state = unsafe { core::ptr::read(&self.mm_state) };
        core::mem::forget(mm_state);
        self.mm_state = tidemark_kernel::harness::support::snapshot_process_context_boxed();
    }
}

pub(crate) fn validate_saved_process_ctx(
    saved: &SavedProcessCtx,
    label: &str,
) -> Result<(), String> {
    let saved_ptr = saved as *const SavedProcessCtx as usize;
    let snapshot_ptr = saved.guest_memory.as_ref() as *const GuestMemorySnapshot as usize;
    if saved.pid <= 0 {
        return Err(format!(
            "{label}: invalid saved process pid={} ppid={} tid={} process_ptr=0x{:x} status={} wait_pid={} a0={} a7={} snapshot_len=0x{:x} saved_ptr=0x{:x} snapshot_ptr=0x{:x}",
            saved.pid,
            saved.parent_pid,
            saved.tid(),
            saved.process_ptr(),
            saved.status(),
            saved.wait_pid(),
            saved.a0(),
            saved.a7(),
            saved.guest_memory.len,
            saved_ptr,
            snapshot_ptr,
        ));
    }
    if saved.tid() <= 0 {
        return Err(format!(
            "{label}: invalid saved process tid pid={} ppid={} tid={} process_ptr=0x{:x} status={} wait_pid={} a0={} a7={} snapshot_len=0x{:x} saved_ptr=0x{:x} snapshot_ptr=0x{:x}",
            saved.pid,
            saved.parent_pid,
            saved.tid(),
            saved.process_ptr(),
            saved.status(),
            saved.wait_pid(),
            saved.a0(),
            saved.a7(),
            saved.guest_memory.len,
            saved_ptr,
            snapshot_ptr,
        ));
    }
    if saved.process_ptr() == 0 {
        return Err(format!(
            "{label}: invalid saved process process_ptr pid={} ppid={} tid={} process_ptr=0x{:x} status={} wait_pid={} a0={} a7={} snapshot_len=0x{:x} saved_ptr=0x{:x} snapshot_ptr=0x{:x}",
            saved.pid,
            saved.parent_pid,
            saved.tid(),
            saved.process_ptr(),
            saved.status(),
            saved.wait_pid(),
            saved.a0(),
            saved.a7(),
            saved.guest_memory.len,
            saved_ptr,
            snapshot_ptr,
        ));
    }
    if saved.waiter_placeholder {
        return Ok(());
    }
    if saved.guest_memory.len == 0 {
        return Err(format!(
            "{label}: invalid saved process empty snapshot pid={} ppid={} tid={} process_ptr=0x{:x} status={} wait_pid={} a0={} a7={} snapshot_len=0x{:x} saved_ptr=0x{:x} snapshot_ptr=0x{:x}",
            saved.pid,
            saved.parent_pid,
            saved.tid(),
            saved.process_ptr(),
            saved.status(),
            saved.wait_pid(),
            saved.a0(),
            saved.a7(),
            saved.guest_memory.len,
            saved_ptr,
            snapshot_ptr,
        ));
    }
    if !saved_ctx_validation_enabled() {
        return Ok(());
    }
    Ok(())
}

type PreparedProcessSpawn = Box<SavedProcessCtx>;

#[derive(Clone, Copy)]
struct DeferredCloneThread {
    owner_pid: i32,
    child_ptr: u32,
}

fn enqueue_deferred_clone_thread(
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
    owner_pid: i32,
    child_ptr: u32,
) {
    if child_ptr != 0
        && !deferred_clone_threads
            .iter()
            .any(|queued| queued.owner_pid == owner_pid && queued.child_ptr == child_ptr)
    {
        deferred_clone_threads.push_back(DeferredCloneThread {
            owner_pid,
            child_ptr,
        });
    }
}

enum VmRunOutcome {
    Exited(i32, u64),
    Deferred(u64),
    ProcessSpawn(PreparedProcessSpawn),
}

pub(crate) enum LtpVmOutcome {
    Exited(i32, u64),
    Deferred,
    ProcessSpawn(PreparedProcessSpawn),
}

impl LtpVmOutcome {
    fn label(&self) -> &'static str {
        match self {
            Self::Exited(_, _) => "exited",
            Self::Deferred => "deferred",
            Self::ProcessSpawn(_) => "spawn",
        }
    }
}

#[derive(Clone, Copy)]
enum ProcessSpawnMode {
    Disallow,
    Yield,
}

pub(crate) struct LtpSchedulerState {
    deferred_clone_threads: VecDeque<DeferredCloneThread>,
    guest_memory_scratch: Box<GuestMemorySnapshot>,
    parent_memory_scratch: Box<GuestMemorySnapshot>,
    wait4_current_memory_scratch: Box<GuestMemorySnapshot>,
    current_snapshot_pid: i32,
    current_snapshot_process_ptr: u32,
    current_snapshot_pc: u64,
    current_snapshot_sp: u64,
    current_snapshot_wait_pid: i64,
    shared_mapping_overlays: Vec<(i32, tidemark_kernel::harness::support::SharedMappingOverlay)>,
    retain_exited_saved_children: bool,
    retired_saved_children: Vec<Box<SavedProcessCtx>>,
}

impl LtpSchedulerState {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::new_with_options(false)
    }

    pub(crate) fn new_with_options(retain_exited_saved_children: bool) -> Self {
        Self {
            deferred_clone_threads: VecDeque::new(),
            guest_memory_scratch: GuestMemorySnapshot::empty_box(),
            parent_memory_scratch: GuestMemorySnapshot::empty_box(),
            wait4_current_memory_scratch: GuestMemorySnapshot::empty_box(),
            current_snapshot_pid: 0,
            current_snapshot_process_ptr: 0,
            current_snapshot_pc: 0,
            current_snapshot_sp: 0,
            current_snapshot_wait_pid: 0,
            shared_mapping_overlays: Vec::new(),
            retain_exited_saved_children,
            retired_saved_children: Vec::new(),
        }
    }

    pub(crate) fn retain_exited_saved_children(&self) -> bool {
        self.retain_exited_saved_children
    }

    pub(crate) fn invalidate_current_snapshot(&mut self) {
        self.current_snapshot_pid = 0;
        self.current_snapshot_process_ptr = 0;
        self.current_snapshot_pc = 0;
        self.current_snapshot_sp = 0;
        self.current_snapshot_wait_pid = 0;
        self.guest_memory_scratch.len = 0;
    }

    pub(crate) fn retire_exited_saved_child(&mut self, child: Box<SavedProcessCtx>) {
        self.retired_saved_children.push(child);
    }

    pub(crate) fn shared_mapping_overlay(
        &self,
        process_group: i32,
    ) -> Option<&tidemark_kernel::harness::support::SharedMappingOverlay> {
        self.shared_mapping_overlays
            .iter()
            .find(|(pgrp, _)| *pgrp == process_group)
            .map(|(_, mappings)| mappings)
    }

    pub(crate) fn update_shared_mapping_overlay(
        &mut self,
        process_group: i32,
        mappings: tidemark_kernel::harness::support::SharedMappingOverlay,
    ) {
        if let Some((_, current)) = self
            .shared_mapping_overlays
            .iter_mut()
            .find(|(pgrp, _)| *pgrp == process_group)
        {
            *current = mappings;
            return;
        }
        self.shared_mapping_overlays.push((process_group, mappings));
    }

    pub(crate) fn deferred_clone_thread_count_for_process(&self, pid: i32) -> usize {
        count_deferred_clone_threads_for_process(&self.deferred_clone_threads, pid)
    }

    pub(crate) fn has_any_deferred_clone_threads(&self) -> bool {
        !self.deferred_clone_threads.is_empty()
    }

    pub(crate) fn take_wait4_current_memory_scratch(&mut self) -> Box<GuestMemorySnapshot> {
        core::mem::replace(
            &mut self.wait4_current_memory_scratch,
            GuestMemorySnapshot::empty_box(),
        )
    }

    pub(crate) fn restore_wait4_current_memory_scratch(
        &mut self,
        scratch: Box<GuestMemorySnapshot>,
    ) {
        self.wait4_current_memory_scratch = scratch;
    }

    pub(crate) fn service_ready_deferred_clone_threads_for_process(
        &mut self,
        base: u32,
        use_cache: bool,
        pid: i32,
    ) -> Result<u32, String> {
        service_ready_deferred_clone_threads(base, use_cache, &mut self.deferred_clone_threads, pid)
    }
}

impl Drop for LtpSchedulerState {
    fn drop(&mut self) {
        let guest_memory_scratch = core::mem::replace(
            &mut self.guest_memory_scratch,
            GuestMemorySnapshot::empty_box(),
        );
        core::mem::forget(guest_memory_scratch);
        let parent_memory_scratch = core::mem::replace(
            &mut self.parent_memory_scratch,
            GuestMemorySnapshot::empty_box(),
        );
        core::mem::forget(parent_memory_scratch);
        let wait4_current_memory_scratch = core::mem::replace(
            &mut self.wait4_current_memory_scratch,
            GuestMemorySnapshot::empty_box(),
        );
        core::mem::forget(wait4_current_memory_scratch);
        if self.retain_exited_saved_children {
            for child in self.retired_saved_children.drain(..) {
                core::mem::forget(child);
            }
        }
    }
}

struct HostHelperBinary {
    name: String,
    bytes: Vec<u8>,
}

pub(crate) struct PreparedElfVm {
    pub base: u32,
    pub vm: Box<ThreadState>,
}

impl PreparedElfVm {
    pub(crate) fn record_vm_identity(&self, label: u32) {
        record_ltp_thread_state_identity(self.base, self.vm.as_ref(), 0, 0, label);
    }
}

#[cfg(test)]
pub(crate) struct PreparedRootHandoffSnapshot {
    pub pid: i32,
    pub tid: i32,
    pub status: i32,
    pub guest_snapshot_len: usize,
    pub scheduler_deferred_clones: usize,
    pub thread_count: u32,
}

pub(crate) struct GuestMemorySnapshot {
    chunks: Vec<Option<Box<[u8]>>>,
    len: usize,
}

struct PreparedParentSnapshotState {
    parent_pid: i32,
    parent_memory: Box<GuestMemorySnapshot>,
    parent_mm_state: Box<tidemark_kernel::harness::support::ProcessContextSnapshot>,
    snapshot_parent_pid: i32,
}

struct PreparedParentScratchState {
    parent_pid: i32,
    parent_mm_state: Box<tidemark_kernel::harness::support::ProcessContextSnapshot>,
    snapshot_parent_pid: i32,
}

impl GuestMemorySnapshot {
    pub(crate) fn empty_box() -> Box<Self> {
        Box::new(Self {
            chunks: Vec::new(),
            len: 0,
        })
    }

    fn capture(base: u32) -> Result<Box<Self>, String> {
        let len = current_guest_snapshot_len(base);
        let mut snapshot = Self::allocate_boxed(len);
        Self::fill_from_guest(base, &mut snapshot);
        Ok(snapshot)
    }

    fn capture_for_vm(base: u32, vm: &ThreadState) -> Result<Box<Self>, String> {
        let len = current_guest_snapshot_len_with_vm_floor(base, vm);
        let mut snapshot = Self::allocate_boxed(len);
        Self::fill_from_guest(base, &mut snapshot);
        Ok(snapshot)
    }

    #[inline(never)]
    fn allocate_boxed(len: usize) -> Box<Self> {
        let mut snapshot = Box::new(Self {
            chunks: Vec::new(),
            len,
        });
        allocate_snapshot_chunks_into(&mut snapshot.chunks, len);
        snapshot
    }

    #[inline(never)]
    fn fill_from_guest(base: u32, snapshot: &mut Self) {
        let mut off = 0usize;
        for chunk in snapshot.chunks.iter_mut() {
            let chunk_len = (snapshot.len - off).min(GUEST_SNAPSHOT_CHUNK);
            let mut buf = vec![0u8; chunk_len].into_boxed_slice();
            unsafe {
                tidemark_kernel::guest_mem::read_bytes(base, off as u64, &mut buf[..]);
            }
            if buf.iter().any(|&byte| byte != 0) {
                *chunk = Some(buf);
            }
            off += chunk_len;
        }
    }

    pub(crate) fn recapture_into_scratch_for_vm(&mut self, base: u32, vm: &ThreadState) {
        let len = current_guest_snapshot_len_with_vm_floor(base, vm);
        self.recapture_into_scratch_with_len(base, len);
    }

    fn recapture_into_scratch_with_len(&mut self, base: u32, len: usize) {
        self.len = len;
        let required_chunks = len.div_ceil(GUEST_SNAPSHOT_CHUNK);
        while self.chunks.len() < required_chunks {
            self.chunks.push(None);
        }
        for chunk in self.chunks.iter_mut().skip(required_chunks) {
            *chunk = None;
        }
        let mut scratch = vec![0u8; GUEST_SNAPSHOT_CHUNK].into_boxed_slice();
        let mut off = 0usize;
        for idx in 0..required_chunks {
            let chunk_len = (len - off).min(GUEST_SNAPSHOT_CHUNK);
            let buf = &mut scratch[..chunk_len];
            unsafe {
                tidemark_kernel::guest_mem::read_bytes(base, off as u64, buf);
            }
            if buf.iter().all(|&byte| byte == 0) {
                self.chunks[idx] = None;
            } else if let Some(chunk) = self.chunks[idx].as_mut() {
                if chunk.len() != chunk_len {
                    *chunk = vec![0u8; chunk_len].into_boxed_slice();
                }
                chunk.copy_from_slice(buf);
            } else {
                self.chunks[idx] = Some(buf.to_vec().into_boxed_slice());
            }
            off += chunk_len;
        }
    }

    fn clone_from_snapshot(&mut self, other: &GuestMemorySnapshot) {
        self.len = other.len;
        while self.chunks.len() < other.chunks.len() {
            self.chunks.push(None);
        }
        for idx in 0..other.chunks.len() {
            self.chunks[idx] = other.chunks[idx]
                .as_ref()
                .map(|chunk| chunk.to_vec().into_boxed_slice());
        }
        for chunk in self.chunks.iter_mut().skip(other.chunks.len()) {
            *chunk = None;
        }
    }

    fn restore(&self, base: u32) -> Result<(), String> {
        let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
        let guest_limit = linear_guest_window_size(base);
        let mut off = 0usize;
        let required_chunks = self.len.div_ceil(GUEST_SNAPSHOT_CHUNK);
        for chunk in self.chunks.iter().take(required_chunks) {
            let chunk_len = (self.len - off).min(GUEST_SNAPSHOT_CHUNK);
            let guest_end = off.checked_add(chunk_len).ok_or_else(|| {
                format!("snapshot restore guest-range overflow: off=0x{off:x} len=0x{chunk_len:x}")
            })?;
            if guest_end > guest_limit {
                return Err(format!(
                    "snapshot restore exceeds guest window: base=0x{base:x} off=0x{off:x} len=0x{chunk_len:x} guest_end=0x{guest_end:x} guest_limit=0x{guest_limit:x} snapshot_len=0x{:x}",
                    self.len
                ));
            }
            let dst_off = (base as usize).checked_add(off).ok_or_else(|| {
                format!("snapshot restore address overflow: base=0x{base:x} off=0x{off:x}")
            })?;
            let dst_end = dst_off.checked_add(chunk_len).ok_or_else(|| {
                format!("snapshot restore end overflow: dst=0x{dst_off:x} len=0x{chunk_len:x}")
            })?;
            if dst_end > mem_size {
                return Err(format!(
                    "snapshot restore out of wasm range: base=0x{base:x} off=0x{off:x} len=0x{chunk_len:x} end=0x{dst_end:x} mem_size=0x{mem_size:x} snapshot_len=0x{:x}",
                    self.len
                ));
            }
            unsafe {
                let dst = (base as usize + off) as *mut u8;
                let mut chunk_off = 0usize;
                while chunk_off < chunk_len {
                    let sub_len = (chunk_len - chunk_off).min(4096);
                    let guest_off = off + chunk_off;
                    if let Some(bytes) = chunk.as_ref() {
                        core::ptr::copy(bytes.as_ptr().add(chunk_off), dst.add(chunk_off), sub_len);
                    } else if guest_off < GUEST_RAM_SIZE as usize {
                        core::ptr::write_bytes(dst.add(chunk_off), 0, sub_len);
                    }
                    chunk_off += sub_len;
                }
            }
            off += chunk_len;
        }
        Ok(())
    }

    fn read_i32(&self, guest_addr: usize) -> Result<i32, String> {
        let end = guest_addr
            .checked_add(core::mem::size_of::<i32>())
            .ok_or_else(|| "snapshot offset overflow".to_string())?;
        if end > self.len {
            return Err(format!(
                "snapshot read out of range: off={} len={}",
                guest_addr, self.len
            ));
        }
        let mut word = [0u8; 4];
        self.copy_out(guest_addr, &mut word)?;
        Ok(i32::from_le_bytes(word))
    }

    fn restore_range(&self, base: u32, guest_addr: usize, len: usize) -> Result<(), String> {
        let end = guest_addr
            .checked_add(len)
            .ok_or_else(|| "snapshot restore range overflow".to_string())?;
        if end > self.len {
            return Err(format!(
                "snapshot restore out of range: off={} len={} snapshot_len={}",
                guest_addr, len, self.len
            ));
        }
        let guest_limit = guest_window_size(base);
        if end > guest_limit {
            return Err(format!(
                "snapshot restore_range exceeds guest window: off=0x{guest_addr:x} len=0x{len:x} end=0x{end:x} guest_limit=0x{guest_limit:x} snapshot_len=0x{:x}",
                self.len
            ));
        }
        let mut buf = vec![0u8; len];
        self.copy_out(guest_addr, &mut buf)?;
        let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
        let dst_off = (base as usize).checked_add(guest_addr).ok_or_else(|| {
            format!("snapshot restore_range address overflow: base=0x{base:x} off=0x{guest_addr:x}")
        })?;
        let dst_end = dst_off.checked_add(len).ok_or_else(|| {
            format!("snapshot restore_range end overflow: dst=0x{dst_off:x} len=0x{len:x}")
        })?;
        if dst_end > mem_size {
            return Err(format!(
                "snapshot restore_range out of wasm range: base=0x{base:x} off=0x{guest_addr:x} len=0x{len:x} end=0x{dst_end:x} mem_size=0x{mem_size:x} snapshot_len=0x{:x}",
                self.len
            ));
        }
        unsafe {
            let dst = (base + guest_addr as u32) as *mut u8;
            core::ptr::copy(buf.as_ptr(), dst, len);
        }
        Ok(())
    }

    fn copy_out(&self, guest_addr: usize, out: &mut [u8]) -> Result<(), String> {
        let end = guest_addr
            .checked_add(out.len())
            .ok_or_else(|| "snapshot copy overflow".to_string())?;
        if end > self.len {
            return Err(format!(
                "snapshot copy out of range: off={} len={} snapshot_len={}",
                guest_addr,
                out.len(),
                self.len
            ));
        }
        let mut src_off = guest_addr;
        let mut dst_off = 0usize;
        while dst_off < out.len() {
            let chunk_idx = src_off / GUEST_SNAPSHOT_CHUNK;
            let chunk_off = src_off % GUEST_SNAPSHOT_CHUNK;
            let chunk_len = (self.len - chunk_idx * GUEST_SNAPSHOT_CHUNK).min(GUEST_SNAPSHOT_CHUNK);
            let copy_len = (out.len() - dst_off).min(chunk_len - chunk_off);
            if let Some(chunk) = self.chunks[chunk_idx].as_ref() {
                out[dst_off..dst_off + copy_len]
                    .copy_from_slice(&chunk[chunk_off..chunk_off + copy_len]);
            } else {
                out[dst_off..dst_off + copy_len].fill(0);
            }
            src_off += copy_len;
            dst_off += copy_len;
        }
        Ok(())
    }
}

#[inline(never)]
fn allocate_snapshot_chunks_into(chunks: &mut Vec<Option<Box<[u8]>>>, len: usize) {
    let mut off = 0usize;
    while off < len {
        let chunk_len = (len - off).min(GUEST_SNAPSHOT_CHUNK);
        chunks.push(None);
        off += chunk_len;
    }
}

fn ensure_dir(parent_ino: u32, name: &[u8], mode: u32) -> Result<u32, String> {
    let ino = tidemark_kernel::fs::memfs::lookup(parent_ino, name);
    if ino != 0 {
        return Ok(ino);
    }

    let ino = tidemark_kernel::fs::memfs::create_dir(parent_ino, name, mode);
    if ino == 0 {
        return Err(format!("failed to create directory {:?}", name));
    }
    Ok(ino)
}

fn ensure_file(parent_ino: u32, name: &[u8], data: &[u8], mode: u32) -> Result<u32, String> {
    let ino = match tidemark_kernel::fs::memfs::lookup(parent_ino, name) {
        0 => {
            let ino = tidemark_kernel::fs::memfs::create_file(parent_ino, name, mode);
            if ino == 0 {
                return Err(format!("failed to create file {:?}", name));
            }
            ino
        }
        ino => ino,
    };

    let truncate_ret = tidemark_kernel::fs::memfs::truncate(ino, 0);
    if truncate_ret != 0 {
        return Err(format!(
            "failed to truncate file {:?}: {}",
            name, truncate_ret
        ));
    }

    let written = tidemark_kernel::fs::memfs::write_file(ino, 0, data);
    if written != data.len() as i64 {
        return Err(format!(
            "failed to populate file {:?}: wrote {} of {} bytes",
            name,
            written,
            data.len()
        ));
    }

    Ok(ino)
}
const PROC_MEMINFO_BYTES: &[u8] =
    b"MemTotal: 262144 kB\nMemFree: 131072 kB\nMemAvailable: 131072 kB\nCached: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n";
const PROC_CPUINFO_BYTES: &[u8] =
    b"processor\t: 0\nhart\t\t: 0\nisa\t\t: rv64imafdc_zicsr_zifencei_zmmul_zaamo_zalrsc_zca_zcd\nmmu\t\t: sv39\n";
const PROC_PID1_STAT_BYTES: &[u8] = b"1 (init) S 0 1\n";
const ETC_PASSWD_BYTES: &[u8] = b"root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/bin/sh\ndaemon:x:2:2:daemon:/usr/sbin:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/sh\n";
const ETC_GROUP_BYTES: &[u8] = b"root:x:0:\nbin:x:1:\ndaemon:x:2:\nnobody:x:65534:\n";

fn proc_kernel_tainted() -> &'static str {
    "0\n"
}

fn write_i32_decimal(value: i32, buf: &mut [u8]) -> usize {
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut n = value.unsigned_abs();
    let mut rev = [0u8; 10];
    let mut rev_len = 0usize;
    while n != 0 {
        rev[rev_len] = b'0' + (n % 10) as u8;
        rev_len += 1;
        n /= 10;
    }

    let mut pos = 0usize;
    if value < 0 {
        buf[pos] = b'-';
        pos += 1;
    }
    for idx in (0..rev_len).rev() {
        buf[pos] = rev[idx];
        pos += 1;
    }
    pos
}

fn proc_pid_max_bytes(buf: &mut [u8; 24]) -> &[u8] {
    let mut len = write_i32_decimal(tidemark_kernel::abi::MAX_PROCESSES as i32, buf);
    buf[len] = b'\n';
    len += 1;
    &buf[..len]
}

fn proc_pid_stat_bytes<'a>(
    pid: i32,
    ppid: i32,
    state: u8,
    pgrp: i32,
    buf: &'a mut [u8; 64],
) -> &'a [u8] {
    let mut pos = 0usize;
    pos += write_i32_decimal(pid, &mut buf[pos..]);
    buf[pos..pos + 6].copy_from_slice(b" (proc");
    pos += 6;
    pos += write_i32_decimal(pid, &mut buf[pos..]);
    buf[pos..pos + 2].copy_from_slice(b") ");
    pos += 2;
    buf[pos] = state;
    pos += 1;
    buf[pos] = b' ';
    pos += 1;
    pos += write_i32_decimal(ppid, &mut buf[pos..]);
    buf[pos] = b' ';
    pos += 1;
    pos += write_i32_decimal(pgrp, &mut buf[pos..]);
    buf[pos] = b'\n';
    pos += 1;
    &buf[..pos]
}

fn ensure_proc_pid_stat(pid: i32, ppid: i32, state: u8, pgrp: i32) -> Result<(), String> {
    let proc_ino = ensure_dir(1, b"proc", 0o555)?;
    let mut pid_dir_name = [0u8; 16];
    let pid_dir_name_len = write_i32_decimal(pid, &mut pid_dir_name);
    let pid_ino = ensure_dir(proc_ino, &pid_dir_name[..pid_dir_name_len], 0o555)?;
    let mut stat = [0u8; 64];
    let stat_bytes = proc_pid_stat_bytes(pid, ppid, state, pgrp, &mut stat);
    let _ = ensure_file(pid_ino, b"stat", stat_bytes, 0o444)?;
    Ok(())
}

fn ensure_saved_proc_pid_stat(saved: &SavedProcessCtx, state: u8) -> Result<(), String> {
    ensure_proc_pid_stat(saved.pid, saved.parent_pid, state, saved.process_group)
}

fn read_live_proc_pid_stat(pid: i32) -> Option<(i32, u8, i32)> {
    let proc_ino = memfs::lookup(1, b"proc");
    if proc_ino == 0 {
        return None;
    }
    let pid_name = pid.to_string();
    let pid_ino = memfs::lookup(proc_ino, pid_name.as_bytes());
    if pid_ino == 0 {
        return None;
    }
    let stat_ino = memfs::lookup(pid_ino, b"stat");
    if stat_ino == 0 {
        return None;
    }
    let st = memfs::stat(stat_ino)?;
    let len = usize::try_from(st.size).ok()?;
    let mut bytes = vec![0u8; len];
    let read = memfs::read_file(stat_ino, 0, &mut bytes);
    if read < 0 {
        return None;
    }
    bytes.truncate(read as usize);
    let close_paren = bytes.iter().rposition(|&byte| byte == b')')?;
    let rest = core::str::from_utf8(bytes.get(close_paren + 2..)?).ok()?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.as_bytes().first().copied()?;
    let ppid = fields.next()?.parse::<i32>().ok()?;
    let pgrp = fields.next()?.parse::<i32>().ok()?;
    Some((ppid, state, pgrp))
}

pub(crate) fn capture_live_child_proc_stats(parent_pid: i32) -> Vec<(i32, i32, u8, i32)> {
    let mut stats = Vec::new();
    if parent_pid <= 0 {
        return stats;
    }
    for pid in 1..=tidemark_kernel::abi::MAX_PROCESSES as i32 {
        let Some((ppid, state, pgrp)) = read_live_proc_pid_stat(pid) else {
            continue;
        };
        if ppid == parent_pid {
            stats.push((pid, ppid, state, pgrp));
        }
    }
    stats
}

pub(crate) fn capture_live_child_entries(parent_pid: i32) -> Vec<(i32, bool, i32)> {
    tidemark_kernel::harness::process::debug_child_entries_for_parent(parent_pid)
}

fn remove_proc_pid_task_entry(task_ino: u32, tid: i32) {
    let mut tid_name = [0u8; 16];
    let tid_name_len = write_i32_decimal(tid, &mut tid_name);
    let tid_name = &tid_name[..tid_name_len];
    let tid_ino = tidemark_kernel::fs::memfs::lookup(task_ino, tid_name);
    if tid_ino == 0 {
        return;
    }
    let _ = tidemark_kernel::fs::memfs::unlink(tid_ino, b"stat");
    let _ = tidemark_kernel::fs::memfs::rmdir(task_ino, tid_name);
}

fn proc_thread_state_char(
    vm: &ThreadState,
    base: u32,
    record: &ThreadRecord,
    current_state: u8,
) -> Option<u8> {
    if record.tid <= 0 || matches!(record.state, THREAD_NONE | THREAD_DEAD) {
        return None;
    }
    if record.tid == vm.tid {
        return Some(current_state);
    }

    let state = match record.state {
        THREAD_BLOCKED_FUTEX | THREAD_BLOCKED_POLL | THREAD_EXITING => b'S',
        THREAD_STARTING => b'R',
        THREAD_RUNNING => {
            if record.thread_ptr != 0 {
                let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
                let thread_ptr = record.thread_ptr as usize;
                let thread_state_size = core::mem::size_of::<ThreadState>();
                if thread_ptr
                    .checked_add(thread_state_size)
                    .is_some_and(|end| end <= mem_size)
                {
                    let thread_vm = unsafe { &*(record.thread_ptr as *const ThreadState) };
                    match thread_vm.status {
                        STATUS_SLEEP | STATUS_WAIT4 | STATUS_FUTEX_WAIT | STATUS_PIPE_WAIT
                        | STATUS_EPOLL_WAIT => b'S',
                        _ => b'R',
                    }
                } else {
                    b'R'
                }
            } else {
                b'R'
            }
        }
        _ => b'R',
    };
    let _ = base;
    Some(state)
}

fn proc_state_for_tid(vm: &ThreadState, base: u32, tid: i32, current_state: u8) -> Option<u8> {
    if vm.process_ptr == 0 || tid <= 0 || tid as usize > MAX_THREADS {
        return None;
    }

    let Ok(ps) = process_state_ref(vm, base) else {
        return None;
    };
    let record = &ps.threads[(tid - 1) as usize];
    proc_thread_state_char(vm, base, record, current_state)
}

fn ensure_proc_pid_task_entries(
    vm: &ThreadState,
    base: u32,
    current_state: u8,
) -> Result<(), String> {
    if vm.process_ptr == 0 {
        return Ok(());
    }

    let pid = process_pid(base, vm.process_ptr);
    let ppid = process_ppid(base, vm.process_ptr);
    let pgrp = process_pgid(vm, base);

    let proc_ino = ensure_dir(1, b"proc", 0o555)?;
    let mut pid_dir_name = [0u8; 16];
    let pid_dir_name_len = write_i32_decimal(pid, &mut pid_dir_name);
    let pid_ino = ensure_dir(proc_ino, &pid_dir_name[..pid_dir_name_len], 0o555)?;
    let task_ino = ensure_dir(pid_ino, b"task", 0o555)?;

    let ps = process_state_ref(vm, base)?;
    let mut present = [false; MAX_THREADS + 1];

    for record in ps.threads.iter() {
        let Some(state) = proc_thread_state_char(vm, base, record, current_state) else {
            continue;
        };
        let tid = record.tid;
        if tid <= 0 || tid as usize > MAX_THREADS {
            continue;
        }
        present[tid as usize] = true;

        let mut tid_name = [0u8; 16];
        let tid_name_len = write_i32_decimal(tid, &mut tid_name);
        let tid_ino = ensure_dir(task_ino, &tid_name[..tid_name_len], 0o555)?;
        let mut stat = [0u8; 64];
        let stat_bytes = proc_pid_stat_bytes(tid, ppid, state, pgrp, &mut stat);
        let _ = ensure_file(tid_ino, b"stat", stat_bytes, 0o444)?;
    }

    for tid in 1..=MAX_THREADS as i32 {
        if !present[tid as usize] {
            remove_proc_pid_task_entry(task_ino, tid);
        }
    }

    Ok(())
}

fn load_ltp_helper_binaries() -> Result<Vec<HostHelperBinary>, String> {
    let ltp_dir = std::path::Path::new(env!("OUT_DIR")).join("ltp");
    let entries = match std::fs::read_dir(&ltp_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("failed to list {}: {}", ltp_dir.display(), err)),
    };

    let mut helpers = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read {}: {}", ltp_dir.display(), e))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("failed to stat {}: {}", entry.path().display(), e))?;
        if !file_type.is_file() {
            continue;
        }

        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| format!("non-utf8 LTP binary name: {:?}", name))?;
        if !name.ends_with("_child") {
            continue;
        }

        let bytes = std::fs::read(entry.path())
            .map_err(|e| format!("failed to read {}: {}", entry.path().display(), e))?;
        helpers.push(HostHelperBinary {
            name: name.to_string(),
            bytes,
        });
    }

    helpers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(helpers)
}

fn stage_ltp_helper_binaries(bin_ino: u32, helpers: &[HostHelperBinary]) -> Result<(), String> {
    for helper in helpers {
        let _ = ensure_file(1, helper.name.as_bytes(), &helper.bytes, 0o755)?;
        let _ = ensure_file(bin_ino, helper.name.as_bytes(), &helper.bytes, 0o755)?;
    }

    Ok(())
}

struct LocalBlockCache {
    cache: tidemark_kernel::cpu::block_cache::BlockCache,
    ptr: std::ptr::NonNull<u8>,
    layout: std::alloc::Layout,
}

impl LocalBlockCache {
    fn cache_mut(&mut self) -> &mut tidemark_kernel::cpu::block_cache::BlockCache {
        &mut self.cache
    }

    fn clear(&mut self) {
        self.cache.clear();
    }
}

impl Drop for LocalBlockCache {
    fn drop(&mut self) {
        unsafe {
            std::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

fn allocate_cache(use_cache: bool) -> Option<LocalBlockCache> {
    if !use_cache {
        return None;
    }

    let layout = std::alloc::Layout::from_size_align(
        tidemark_kernel::cpu::block_cache::BlockCache::allocation_size(),
        core::mem::align_of::<tidemark_kernel::cpu::block_cache::BlockEntry>(),
    )
    .ok()?;
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    let ptr = std::ptr::NonNull::new(ptr)?;
    Some(LocalBlockCache {
        cache: unsafe {
            tidemark_kernel::cpu::block_cache::BlockCache::from_ptr(
                ptr.as_ptr() as *mut tidemark_kernel::cpu::block_cache::BlockEntry
            )
        },
        ptr,
        layout,
    })
}

pub(crate) fn process_pid(base: u32, process_ptr: u32) -> i32 {
    process_pid_impl(base, process_ptr)
}

#[inline(never)]
fn process_pid_impl(base: u32, process_ptr: u32) -> i32 {
    let Some(linear_ptr) = process_state_linear_ptr(base, process_ptr) else {
        return 0;
    };
    let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
    unsafe { ((linear_ptr + pid_off as usize) as *const i32).read_unaligned() }
}

pub(crate) fn process_ppid(base: u32, process_ptr: u32) -> i32 {
    let Some(linear_ptr) = process_state_linear_ptr(base, process_ptr) else {
        return 0;
    };
    let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
    unsafe { ((linear_ptr + ppid_off as usize) as *const i32).read_unaligned() }
}

fn process_state_linear_ptr(base: u32, process_ptr: u32) -> Option<usize> {
    if process_ptr == 0 {
        return None;
    }
    let process_ptr_usize = process_ptr as usize;
    let ps_size = core::mem::size_of::<ProcessState>();
    let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
    let guest_limit = guest_window_size(base);

    if process_ptr_usize
        .checked_add(ps_size)
        .is_some_and(|end| end <= guest_limit)
    {
        let linear = base as usize + process_ptr_usize;
        if linear
            .checked_add(ps_size)
            .is_some_and(|end| end <= mem_size)
        {
            return Some(linear);
        }
    }

    if process_ptr_usize >= base as usize
        && process_ptr_usize
            .checked_add(ps_size)
            .is_some_and(|end| end <= mem_size)
    {
        return Some(process_ptr_usize);
    }

    None
}

fn process_state_ref<'a>(vm: &'a ThreadState, base: u32) -> Result<&'a ProcessState, String> {
    if vm.process_ptr == 0 {
        return Err("process_ptr=0".into());
    }
    let process_ptr = vm.process_ptr as usize;
    let ps_size = core::mem::size_of::<ProcessState>();
    let guest_limit = guest_window_size(base);
    let Some(process_end) = process_ptr.checked_add(ps_size) else {
        return Err(format!(
            "process_ptr overflow ptr=0x{:x} size=0x{:x}",
            vm.process_ptr, ps_size
        ));
    };
    if process_end > guest_limit {
        return Err(format!(
            "process_ptr out of guest range ptr=0x{:x} end=0x{:x} guest_limit=0x{:x}",
            vm.process_ptr, process_end, guest_limit
        ));
    }
    Ok(unsafe { &*((base as u64 + vm.process_ptr as u64) as *const ProcessState) })
}

#[cfg(test)]
pub(crate) fn capture_prepared_root_handoff(
    prepared: &PreparedElfVm,
    scheduler: &LtpSchedulerState,
) -> Result<PreparedRootHandoffSnapshot, String> {
    let vm = prepared.vm.as_ref();
    let ps = process_state_ref(vm, prepared.base)?;
    Ok(PreparedRootHandoffSnapshot {
        pid: process_pid(prepared.base, vm.process_ptr),
        tid: vm.tid,
        status: vm.status,
        guest_snapshot_len: current_guest_snapshot_len(prepared.base),
        scheduler_deferred_clones: scheduler.deferred_clone_threads.len(),
        thread_count: ps.thread_count.load(std::sync::atomic::Ordering::Acquire),
    })
}

pub(crate) fn validate_prepared_root_handoff(
    prepared: &PreparedElfVm,
    scheduler: &LtpSchedulerState,
) -> Result<(), String> {
    let vm = prepared.vm.as_ref();
    validate_process_thread_ptrs(vm, prepared.base)?;
    let ps = process_state_ref(vm, prepared.base)?;
    let pid = process_pid(prepared.base, vm.process_ptr);
    if pid <= 0 {
        return Err(format!(
            "root handoff invalid pid pid={} tid={} process_ptr=0x{:x}",
            pid, vm.tid, vm.process_ptr
        ));
    }
    if vm.tid != pid {
        return Err(format!(
            "root handoff tid/pid mismatch pid={} tid={} process_ptr=0x{:x}",
            pid, vm.tid, vm.process_ptr
        ));
    }
    if vm.status != STATUS_OK {
        return Err(format!(
            "root handoff status mismatch pid={} tid={} status={}",
            pid, vm.tid, vm.status
        ));
    }
    let thread_count = ps.thread_count.load(std::sync::atomic::Ordering::Acquire);
    if thread_count == 0 {
        return Err(format!(
            "root handoff empty thread table pid={} tid={} process_ptr=0x{:x}",
            pid, vm.tid, vm.process_ptr
        ));
    }
    if scheduler
        .deferred_clone_threads
        .iter()
        .any(|queued| queued.owner_pid == pid)
    {
        return Err(format!(
            "root handoff already has deferred clone threads pid={} tid={} clones={}",
            pid,
            vm.tid,
            scheduler.deferred_clone_threads.len()
        ));
    }
    Ok(())
}

pub(crate) fn process_pgid(vm: &ThreadState, base: u32) -> i32 {
    let pgid = tidemark_kernel::syscall::process::sys_getpgid(vm, base, 0);
    if pgid > 0 {
        pgid as i32
    } else if vm.process_ptr != 0 {
        process_pid(base, vm.process_ptr)
    } else {
        0
    }
}

fn vm_pid(vm: &ThreadState, base: u32) -> i32 {
    if vm.process_ptr != 0 {
        process_pid(base, vm.process_ptr)
    } else {
        0
    }
}

fn refresh_proc_pid_stat(vm: &ThreadState, base: u32, state: u8) -> Result<(), String> {
    if vm.process_ptr == 0 {
        return Ok(());
    }
    let _ = process_state_ref(vm, base)?;
    let pid = process_pid(base, vm.process_ptr);
    let ppid = process_ppid(base, vm.process_ptr);
    let pgrp = process_pgid(vm, base);
    let leader_state = proc_state_for_tid(vm, base, pid, state).unwrap_or(state);
    ensure_proc_pid_stat(pid, ppid, leader_state, pgrp)?;
    ensure_proc_pid_task_entries(vm, base, state)
}

pub(crate) fn proc_pid_stat_state_for_status(status: i32) -> u8 {
    match status {
        STATUS_SLEEP | STATUS_WAIT4 | STATUS_FUTEX_WAIT | STATUS_PIPE_WAIT | STATUS_EPOLL_WAIT => {
            b'S'
        }
        _ => b'R',
    }
}

pub(crate) fn describe_process_threads(vm: &ThreadState, base: u32) -> String {
    if vm.process_ptr == 0 {
        return "process_ptr=0".to_string();
    }
    let Ok(ps) = process_state_ref(vm, base) else {
        return format!("invalid process_ptr=0x{:x}", vm.process_ptr);
    };
    let thread_count = ps.thread_count.load(std::sync::atomic::Ordering::Acquire);
    let mut parts = Vec::new();
    for record in ps.threads.iter() {
        if matches!(record.state, THREAD_NONE | THREAD_DEAD) {
            continue;
        }
        parts.push(format!(
            "tid={} state={} thread_ptr=0x{:x} blocked=0x{:x} clear_child_tid=0x{:x}",
            record.tid,
            record.state,
            record.thread_ptr,
            record.blocked_addr,
            record.clear_child_tid
        ));
    }
    format!("thread_count={} [{}]", thread_count, parts.join(" | "))
}

fn validate_process_thread_ptrs(vm: &ThreadState, base: u32) -> Result<(), String> {
    let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
    let thread_state_size = core::mem::size_of::<ThreadState>();
    let vm_ptr = vm as *const ThreadState as usize;
    let Some(vm_end) = vm_ptr.checked_add(thread_state_size) else {
        return Err(format!(
            "current vm thread_ptr overflow tid={} ptr=0x{:x} size=0x{:x} process_ptr=0x{:x}",
            vm.tid, vm_ptr, thread_state_size, vm.process_ptr,
        ));
    };
    if vm_end > mem_size {
        return Err(format!(
            "current vm thread_ptr out of wasm range tid={} ptr=0x{:x} end=0x{:x} mem_size=0x{:x} process_ptr=0x{:x}",
            vm.tid, vm_ptr, vm_end, mem_size, vm.process_ptr,
        ));
    }
    if vm.process_ptr == 0 {
        return Ok(());
    }
    let ps = process_state_ref(vm, base)?;
    for record in ps.threads.iter() {
        if matches!(record.state, THREAD_NONE | THREAD_DEAD) || record.thread_ptr == 0 {
            continue;
        }
        let thread_ptr = record.thread_ptr as usize;
        let Some(thread_end) = thread_ptr.checked_add(thread_state_size) else {
            return Err(format!(
                "thread_ptr overflow pid={} tid={} ptr=0x{:x} size=0x{:x} process_ptr=0x{:x}",
                process_pid(base, vm.process_ptr),
                record.tid,
                record.thread_ptr,
                thread_state_size,
                vm.process_ptr,
            ));
        };
        if thread_end > mem_size {
            return Err(format!(
                "thread_ptr out of wasm range pid={} tid={} ptr=0x{:x} end=0x{:x} mem_size=0x{:x} process_ptr=0x{:x} threads={}",
                process_pid(base, vm.process_ptr),
                record.tid,
                record.thread_ptr,
                thread_end,
                mem_size,
                vm.process_ptr,
                describe_process_threads(vm, base),
            ));
        }
    }
    Ok(())
}

fn set_process_identity(base: u32, process_ptr: u32, pid: i32, ppid: i32) {
    let ps_addr = process_ptr as u64;
    let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
    let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
    let thread_count_off = core::mem::offset_of!(ProcessState, thread_count) as u64;

    unsafe {
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + pid_off, pid as u32);
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + ppid_off, ppid as u32);
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + thread_count_off, 1);
    }
}

pub(crate) fn guest_window_size(base: u32) -> usize {
    let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
    (GUEST_RAM_SIZE as usize).min(mem_size.saturating_sub(base as usize))
}

fn linear_guest_window_size(base: u32) -> usize {
    let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
    let wasm_window = mem_size.saturating_sub(base as usize);
    let u32_window = ((u32::MAX as u64 + 1)
        .saturating_sub(base as u64)
        .min(usize::MAX as u64)) as usize;
    wasm_window.min(u32_window)
}

fn current_guest_snapshot_len(base: u32) -> usize {
    let mut high = tidemark_kernel::syscall::memory::current_brk() as usize;
    let vma_len = tidemark_kernel::harness::memory::debug_vma_len();
    for idx in 0..vma_len {
        high = high.max(tidemark_kernel::harness::memory::debug_vma_end(idx) as usize);
    }
    high.min(linear_guest_window_size(base))
}

fn current_guest_snapshot_len_with_vm_floor(base: u32, vm: &ThreadState) -> usize {
    let mut high = current_guest_snapshot_len(base);
    let process_end =
        (vm.process_ptr as usize).saturating_add(core::mem::size_of::<ProcessState>());
    high = high.max(process_end);
    let stack_end = (vm.x[2] as usize).saturating_add(0x20_000);
    high = high.max(stack_end);
    let pc_end = (vm.pc as usize).saturating_add(0x1000);
    high = high.max(pc_end);
    high.min(linear_guest_window_size(base))
}

fn snapshot_guest_memory(base: u32) -> Result<Box<GuestMemorySnapshot>, String> {
    GuestMemorySnapshot::capture(base)
}

pub(crate) fn snapshot_guest_memory_for_vm(
    base: u32,
    vm: &ThreadState,
) -> Result<Box<GuestMemorySnapshot>, String> {
    GuestMemorySnapshot::capture_for_vm(base, vm)
}

#[inline(never)]
fn probe_snapshot_chunk_alloc() {
    let chunk = vec![0u8; GUEST_SNAPSHOT_CHUNK].into_boxed_slice();
    core::hint::black_box(&chunk);
}

fn ensure_shared_heap_sane(stage: &str) -> Result<(), String> {
    let heap_base = tidemark_kernel::alloc::heap_base() as usize;
    let heap_ptr = tidemark_kernel::alloc::heap_ptr() as usize;
    let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
    if heap_ptr < heap_base || heap_ptr > mem_size {
        return Err(format!(
            "shared heap corrupt at {}: heap_base=0x{:x} heap_ptr=0x{:x} mem_size=0x{:x}",
            stage, heap_base, heap_ptr, mem_size
        ));
    }
    Ok(())
}

fn child_wait_status(vm: &ThreadState, exit_code: i32) -> i32 {
    if vm.term_signal != 0 {
        vm.term_signal
    } else {
        ((exit_code as u32) << 8) as i32
    }
}

fn pre_exec_stack_probe(vm: &ThreadState) -> (u64, u64, u64, u32) {
    let x = vm.x;
    let f = vm.f;
    let pc = vm.pc;
    let fcsr = vm.fcsr;
    (x[2], f[0], pc, fcsr)
}

fn snapshot_pid(snapshot: &GuestMemorySnapshot, process_ptr: u32) -> Result<i32, String> {
    let off = process_ptr as usize + core::mem::offset_of!(ProcessState, pid);
    snapshot.read_i32(off)
}

fn restore_process_state_snapshot(
    snapshot: &GuestMemorySnapshot,
    base: u32,
    process_ptr: u32,
) -> Result<(), String> {
    snapshot.restore_range(
        base,
        process_ptr as usize,
        core::mem::size_of::<ProcessState>(),
    )?;

    let pid_off = process_ptr as usize + core::mem::offset_of!(ProcessState, pid);
    let ppid_off = process_ptr as usize + core::mem::offset_of!(ProcessState, ppid);
    let thread_count_off = process_ptr as usize + core::mem::offset_of!(ProcessState, thread_count);
    let pid = snapshot.read_i32(pid_off)? as u32;
    let ppid = snapshot.read_i32(ppid_off)? as u32;
    let thread_count = snapshot.read_i32(thread_count_off)? as u32;

    unsafe {
        guest_mem::write_u32(
            base,
            process_ptr as u64 + core::mem::offset_of!(ProcessState, pid) as u64,
            pid,
        );
        guest_mem::write_u32(
            base,
            process_ptr as u64 + core::mem::offset_of!(ProcessState, ppid) as u64,
            ppid,
        );
        guest_mem::write_u32(
            base,
            process_ptr as u64 + core::mem::offset_of!(ProcessState, thread_count) as u64,
            thread_count,
        );
    }
    Ok(())
}

fn repair_current_main_thread_record(vm: &ThreadState, base: u32) {
    if vm.process_ptr == 0 || vm.tid <= 0 || vm.tid as usize > MAX_THREADS {
        return;
    }
    let vm_ptr = vm as *const ThreadState as u32;
    let Ok(ps) = process_state_ref(vm, base) else {
        return;
    };
    let idx = (vm.tid - 1) as usize;
    let record = &ps.threads[idx];
    let valid = record.tid == vm.tid
        && !matches!(record.state, THREAD_NONE | THREAD_DEAD)
        && record.thread_ptr == vm_ptr;
    if valid && ps.thread_count.load(std::sync::atomic::Ordering::Acquire) > 0 {
        return;
    }
    let ps_ptr = (base as u64 + vm.process_ptr as u64) as *mut ProcessState;
    unsafe {
        let ps = &mut *ps_ptr;
        if ps.thread_count.load(std::sync::atomic::Ordering::Acquire) <= 1 {
            for record in ps.threads.iter_mut() {
                *record = ThreadRecord::empty();
            }
        }
        ps.threads[idx] =
            ThreadRecord::new(vm.tid, THREAD_RUNNING, vm_ptr, vm.clear_child_tid as u32, 0);
        ps.thread_count
            .store(1, std::sync::atomic::Ordering::Release);
    }
}

fn run_vm(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
) -> Result<(i32, u64), String> {
    match run_vm_inner(
        vm,
        base,
        use_cache,
        deferred_clone_threads,
        false,
        ProcessSpawnMode::Disallow,
        true,
        None,
    )? {
        VmRunOutcome::Exited(code, pc) => Ok((code, pc)),
        VmRunOutcome::Deferred(pc) => {
            Err(format!("top-level VM deferred unexpectedly at 0x{pc:x}"))
        }
        VmRunOutcome::ProcessSpawn(_) => {
            Err("top-level VM yielded a process spawn unexpectedly".into())
        }
    }
}

fn run_vm_root_for_ltp(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    scheduler: &mut LtpSchedulerState,
) -> Result<VmRunOutcome, String> {
    let deferred_clone_threads = &mut scheduler.deferred_clone_threads;
    let parent_memory_scratch = scheduler.parent_memory_scratch.as_mut();
    run_vm_inner(
        vm,
        base,
        use_cache,
        deferred_clone_threads,
        true,
        ProcessSpawnMode::Yield,
        true,
        Some(parent_memory_scratch),
    )
}

fn run_vm_inner(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
    yield_blocked_status: bool,
    process_spawn_mode: ProcessSpawnMode,
    service_deferred_clones: bool,
    mut parent_memory_scratch: Option<&mut GuestMemorySnapshot>,
) -> Result<VmRunOutcome, String> {
    let mut cache = if use_cache {
        allocate_cache(true)
    } else {
        None
    };
    let mut total = 0i64;
    let vm_ptr = vm as *mut ThreadState as u32;
    let mut vfork_child_active = false;
    let mut skip_deferred_clone_service_once = false;

    loop {
        if vm.status == STATUS_FAULT {
            return Ok(VmRunOutcome::Exited(vm.exit_code, vm.pc));
        }
        if service_deferred_clones
            && !skip_deferred_clone_service_once
            && !deferred_clone_threads.is_empty()
        {
            let current_pid = vm_pid(vm, base);
            record_ltp_memory_probe(
                LTP_MEM_PROBE_DEFERRED_SERVICE_BEFORE,
                current_pid,
                deferred_clone_threads.len(),
                0,
                live_probe_word(base),
            );
            let progressed = service_ready_deferred_clone_threads(
                base,
                use_cache,
                deferred_clone_threads,
                current_pid,
            )?;
            record_ltp_memory_probe(
                LTP_MEM_PROBE_DEFERRED_SERVICE_AFTER,
                current_pid,
                deferred_clone_threads.len(),
                progressed,
                live_probe_word(base),
            );
        }
        skip_deferred_clone_service_once = false;
        validate_process_thread_ptrs(vm, base)?;
        refresh_proc_pid_stat(vm, base, b'R')?;
        ensure_shared_heap_sane("before exec_at_base")?;
        let guest_limit = guest_window_size(base) as u64;
        if vm.pc >= guest_limit {
            return Err(format!(
                "vm.pc out of guest range pid={} pc=0x{:x} guest_limit=0x{:x} status={} process_ptr=0x{:x}",
                vm_pid(vm, base),
                vm.pc,
                guest_limit,
                vm.status,
                vm.process_ptr,
            ));
        }
        if vm.x[2] != 0
            && !tidemark_kernel::syscall::memory::guest_range_accessible(
                base,
                vm.x[2].saturating_sub(8),
                8,
            )
        {
            return Err(format!(
                "vm.sp inaccessible pid={} sp=0x{:x} guest_limit=0x{:x} pc=0x{:x} process_ptr=0x{:x}",
                vm_pid(vm, base),
                vm.x[2],
                guest_limit,
                vm.pc,
                vm.process_ptr,
            ));
        }
        let _ = pre_exec_stack_probe(vm);
        let budget = 500_000i32;
        vm.status = STATUS_OK;
        let rem = unsafe {
            tidemark_kernel::cpu::exec_at_base(
                vm,
                budget,
                base,
                cache.as_mut().map(LocalBlockCache::cache_mut),
                None,
                None,
                None,
            )
        };
        total += (budget - rem) as i64;
        if vm.completed_sync_effects & SYNC_EFFECT_PROCESS_LIFECYCLE != 0 {
            if let Some(cache) = cache.as_mut() {
                cache.clear();
            }
        }

        match vm.status {
            STATUS_OK => {
                if yield_blocked_status && rem == 0 {
                    return Ok(VmRunOutcome::Deferred(vm.pc));
                }
                if total > MAX_VM_INSTRUCTIONS {
                    if yield_blocked_status {
                        return Ok(VmRunOutcome::Deferred(vm.pc));
                    }
                    let pid = if vm.process_ptr != 0 {
                        process_pid(base, vm.process_ptr)
                    } else {
                        -1
                    };
                    return Err(format!(
                        "instruction budget exhausted pid={} pc=0x{:x} ra=0x{:x} sp=0x{:x} s0=0x{:x} a0=0x{:x}",
                        pid, vm.pc, vm.x[1], vm.x[2], vm.x[8], vm.x[10]
                    ));
                }
            }
            STATUS_FS => {
                tidemark_kernel::syscall::fs::process_pending_requests(vm_ptr, base);
                tidemark_kernel::syscall::fs::resume_from_fs(vm_ptr, base);
            }
            STATUS_VFORK_WAIT => {
                vfork_child_active = true;
            }
            STATUS_EXECVE_SPAWN => {
                if let Some(spawn) = handle_process_spawn(
                    vm,
                    base,
                    use_cache,
                    vfork_child_active,
                    deferred_clone_threads,
                    process_spawn_mode,
                    parent_memory_scratch.as_deref_mut(),
                )? {
                    return Ok(VmRunOutcome::ProcessSpawn(spawn));
                }
                vfork_child_active = false;
            }
            STATUS_CLONE_SPAWN => {
                let child_ptr = tidemark_kernel::syscall::thread::spawn_from_clone(vm_ptr, base);
                if child_ptr == 0 {
                    return Err("spawn_from_clone failed".into());
                }
                let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
                enqueue_deferred_clone_thread(
                    deferred_clone_threads,
                    process_pid(base, child_vm.process_ptr),
                    child_ptr,
                );
                refresh_proc_pid_stat(child_vm, base, b'R')?;
                refresh_proc_pid_stat(vm, base, b'R')?;
                vm.status = STATUS_OK;
                skip_deferred_clone_service_once = true;
            }
            STATUS_WAIT4 if yield_blocked_status => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_WAIT4 => return Err("wait4 blocked outside ltp_runner".into()),
            STATUS_FUTEX_WAIT if yield_blocked_status => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                if vm.process_ptr != 0 && process_pid(base, vm.process_ptr) == vm.tid {
                    let futex_addr = vm.futex_wait_addr as u32;
                    tidemark_kernel::harness::support::register_external_futex_wait(
                        process_pid(base, vm.process_ptr),
                        futex_addr,
                    );
                }
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_FUTEX_WAIT => return Err("futex wait blocked outside ltp_runner".into()),
            STATUS_PIPE_WAIT if yield_blocked_status => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_PIPE_WAIT => return Err("pipe wait blocked outside ltp_runner".into()),
            STATUS_FAULT if vfork_child_active => {
                let child_pid = tidemark_kernel::syscall::process::vfork_child_pid();
                if child_pid <= 0 {
                    return Err("vfork child exited without an allocated child pid".into());
                }
                tidemark_kernel::syscall::process::record_child_exit(
                    child_pid,
                    child_wait_status(vm, vm.exit_code),
                );
                tidemark_kernel::syscall::process::vfork_parent_resume(vm, child_pid);
                vfork_child_active = false;
            }
            STATUS_FAULT => return Ok(VmRunOutcome::Exited(vm.exit_code, vm.pc)),
            STATUS_SLEEP if yield_blocked_status => {
                refresh_proc_pid_stat(vm, base, b'S')?;
                return Ok(VmRunOutcome::Deferred(vm.pc));
            }
            STATUS_SLEEP => {
                consume_sleep_duration(vm)?;
                vm.status = STATUS_OK;
            }
            _ => return Ok(VmRunOutcome::Exited(-vm.status, vm.pc)),
        }
    }
}

fn handle_process_spawn(
    vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    vfork_child_active: bool,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
    process_spawn_mode: ProcessSpawnMode,
    parent_memory_scratch: Option<&mut GuestMemorySnapshot>,
) -> Result<Option<PreparedProcessSpawn>, String> {
    match vm.spawn_kind {
        SPAWN_KIND_FORK if matches!(process_spawn_mode, ProcessSpawnMode::Disallow) => {
            Err("process spawn is disabled for the generic ELF runner".into())
        }
        SPAWN_KIND_FORK if matches!(process_spawn_mode, ProcessSpawnMode::Yield) => {
            if let Some(parent_memory_scratch) = parent_memory_scratch {
                prepare_process_spawn_with_parent_memory_scratch(
                    vm,
                    base,
                    false,
                    parent_memory_scratch,
                )
                .map(Some)
            } else {
                prepare_process_spawn(vm, base, false).map(Some)
            }
        }
        SPAWN_KIND_EXECVE if vfork_child_active => {
            handle_vfork_execve_spawn(vm, base, use_cache, deferred_clone_threads)?;
            Ok(None)
        }
        SPAWN_KIND_EXECVE => Err("unexpected execve spawn outside vfork path".into()),
        kind => Err(format!(
            "unsupported spawn_kind {} for STATUS_EXECVE_SPAWN",
            kind
        )),
    }
}

fn prepare_process_spawn(
    parent_vm: &mut ThreadState,
    base: u32,
    preserve_live_shared_mappings: bool,
) -> Result<PreparedProcessSpawn, String> {
    prepare_process_spawn_impl(parent_vm, base, preserve_live_shared_mappings)
}

fn prepare_process_spawn_with_parent_memory_scratch(
    parent_vm: &mut ThreadState,
    base: u32,
    preserve_live_shared_mappings: bool,
    parent_memory_scratch: &mut GuestMemorySnapshot,
) -> Result<PreparedProcessSpawn, String> {
    prepare_process_spawn_impl_with_parent_memory_scratch(
        parent_vm,
        base,
        preserve_live_shared_mappings,
        parent_memory_scratch,
    )
}

#[inline(never)]
fn prepare_process_spawn_impl(
    parent_vm: &mut ThreadState,
    base: u32,
    preserve_live_shared_mappings: bool,
) -> Result<PreparedProcessSpawn, String> {
    let child_pid = parent_vm.x[10] as i32;
    if child_pid <= 0 {
        return Err(format!("fork returned invalid child pid {}", child_pid));
    }

    let process_ptr = parent_vm.process_ptr;
    if process_ptr == 0 {
        return Err("fork without ProcessState".into());
    }
    prepare_process_spawn_body(
        parent_vm,
        base,
        process_ptr,
        child_pid,
        preserve_live_shared_mappings,
    )
}

#[inline(never)]
fn prepare_process_spawn_impl_with_parent_memory_scratch(
    parent_vm: &mut ThreadState,
    base: u32,
    preserve_live_shared_mappings: bool,
    parent_memory_scratch: &mut GuestMemorySnapshot,
) -> Result<PreparedProcessSpawn, String> {
    let child_pid = parent_vm.x[10] as i32;
    if child_pid <= 0 {
        return Err(format!("fork returned invalid child pid {}", child_pid));
    }

    let process_ptr = parent_vm.process_ptr;
    if process_ptr == 0 {
        return Err("fork without ProcessState".into());
    }
    prepare_process_spawn_body_with_parent_memory_scratch(
        parent_vm,
        base,
        process_ptr,
        child_pid,
        preserve_live_shared_mappings,
        parent_memory_scratch,
    )
}

#[inline(never)]
fn prepare_process_spawn_body(
    parent_vm: &mut ThreadState,
    base: u32,
    process_ptr: u32,
    child_pid: i32,
    preserve_live_shared_mappings: bool,
) -> Result<PreparedProcessSpawn, String> {
    tidemark_kernel::syscall::memory::flush_shared_mappings(base);
    prepare_process_spawn_after_flush(
        parent_vm,
        base,
        process_ptr,
        child_pid,
        preserve_live_shared_mappings,
    )
}

#[inline(never)]
fn prepare_process_spawn_body_with_parent_memory_scratch(
    parent_vm: &mut ThreadState,
    base: u32,
    process_ptr: u32,
    child_pid: i32,
    preserve_live_shared_mappings: bool,
    parent_memory_scratch: &mut GuestMemorySnapshot,
) -> Result<PreparedProcessSpawn, String> {
    let parent_pid = process_pid(base, process_ptr);
    record_ltp_memory_probe(
        LTP_MEM_PROBE_SPAWN_BEFORE_FLUSH,
        parent_pid,
        child_pid as usize,
        0,
        live_probe_word(base),
    );
    tidemark_kernel::syscall::memory::flush_shared_mappings(base);
    record_ltp_memory_probe(
        LTP_MEM_PROBE_SPAWN_AFTER_FLUSH,
        parent_pid,
        child_pid as usize,
        0,
        live_probe_word(base),
    );
    prepare_process_spawn_after_flush_with_parent_memory_scratch(
        parent_vm,
        base,
        process_ptr,
        child_pid,
        preserve_live_shared_mappings,
        parent_memory_scratch,
    )
}

#[inline(never)]
fn prepare_process_spawn_after_flush(
    parent_vm: &mut ThreadState,
    base: u32,
    process_ptr: u32,
    child_pid: i32,
    preserve_live_shared_mappings: bool,
) -> Result<PreparedProcessSpawn, String> {
    let parent_state = prepare_parent_snapshot(parent_vm, base, process_ptr)?;

    let child_vm = prepare_child_vm_for_spawn(
        parent_vm,
        base,
        process_ptr,
        parent_state.parent_pid,
        child_pid,
    )?;

    let child_spawn =
        finalize_process_spawn_snapshot(child_vm, child_pid, parent_state.parent_pid, base)?;

    let restored_pid = restore_process_context_parent_after_snapshot(
        parent_vm,
        base,
        process_ptr,
        &parent_state,
        preserve_live_shared_mappings,
    )?;
    if restored_pid != parent_state.parent_pid {
        return Err(format!(
            "process context restore corrupted parent pid: expected {}, got {}; snapshot_pid={} process_ptr=0x{:x}",
            parent_state.parent_pid, restored_pid, parent_state.snapshot_parent_pid, process_ptr
        ));
    }
    refresh_proc_pid_stat(parent_vm, base, b'R')?;
    parent_vm.clone_flags = 0;
    parent_vm.clone_child_stack = 0;
    parent_vm.clone_tls = 0;
    parent_vm.clone_child_tidptr = 0;
    parent_vm.clone_child_tid = 0;
    parent_vm.clone_pending = 0;
    parent_vm.spawn_kind = 0;
    parent_vm.spawn_ram_size = 0;
    parent_vm.spawn_child_pid = 0;
    parent_vm.spawn_path = 0;
    parent_vm.spawn_argv = 0;
    parent_vm.spawn_envp = 0;
    parent_vm.status = STATUS_OK;
    parent_vm.x[10] = child_pid as u64;

    Ok(child_spawn)
}

#[inline(never)]
fn prepare_process_spawn_after_flush_with_parent_memory_scratch(
    parent_vm: &mut ThreadState,
    base: u32,
    process_ptr: u32,
    child_pid: i32,
    preserve_live_shared_mappings: bool,
    parent_memory_scratch: &mut GuestMemorySnapshot,
) -> Result<PreparedProcessSpawn, String> {
    let parent_state =
        prepare_parent_snapshot_into_scratch(parent_vm, base, process_ptr, parent_memory_scratch)?;

    let child_vm = prepare_child_vm_for_spawn(
        parent_vm,
        base,
        process_ptr,
        parent_state.parent_pid,
        child_pid,
    )?;

    let child_spawn =
        finalize_process_spawn_snapshot(child_vm, child_pid, parent_state.parent_pid, base)?;
    record_ltp_memory_probe(
        LTP_MEM_PROBE_PARENT_SCRATCH_AFTER_CHILD,
        parent_state.parent_pid,
        parent_memory_scratch.len,
        snapshot_probe_word(parent_memory_scratch),
        live_probe_word(base),
    );

    let restored_pid = restore_process_context_parent_after_snapshot_from_scratch(
        parent_vm,
        base,
        process_ptr,
        &parent_state,
        parent_memory_scratch,
        preserve_live_shared_mappings,
    )?;
    record_ltp_memory_probe(
        LTP_MEM_PROBE_PARENT_SCRATCH_AFTER_RESTORE,
        parent_state.parent_pid,
        parent_memory_scratch.len,
        snapshot_probe_word(parent_memory_scratch),
        live_probe_word(base),
    );
    if restored_pid != parent_state.parent_pid {
        return Err(format!(
            "process context restore corrupted parent pid: expected {}, got {}; snapshot_pid={} process_ptr=0x{:x}",
            parent_state.parent_pid, restored_pid, parent_state.snapshot_parent_pid, process_ptr
        ));
    }
    refresh_proc_pid_stat(parent_vm, base, b'R')?;
    parent_vm.clone_flags = 0;
    parent_vm.clone_child_stack = 0;
    parent_vm.clone_tls = 0;
    parent_vm.clone_child_tidptr = 0;
    parent_vm.clone_child_tid = 0;
    parent_vm.clone_pending = 0;
    parent_vm.spawn_kind = 0;
    parent_vm.spawn_ram_size = 0;
    parent_vm.spawn_child_pid = 0;
    parent_vm.spawn_path = 0;
    parent_vm.spawn_argv = 0;
    parent_vm.spawn_envp = 0;
    parent_vm.status = STATUS_OK;
    parent_vm.x[10] = child_pid as u64;

    Ok(child_spawn)
}

#[inline(never)]
fn prepare_parent_snapshot(
    parent_vm: &ThreadState,
    base: u32,
    process_ptr: u32,
) -> Result<Box<PreparedParentSnapshotState>, String> {
    let parent_pid = process_pid(base, process_ptr);
    prepare_parent_snapshot_after_pid(parent_vm, base, process_ptr, parent_pid)
}

#[inline(never)]
fn prepare_parent_snapshot_into_scratch(
    parent_vm: &ThreadState,
    base: u32,
    process_ptr: u32,
    parent_memory_scratch: &mut GuestMemorySnapshot,
) -> Result<PreparedParentScratchState, String> {
    let parent_pid = process_pid(base, process_ptr);
    parent_memory_scratch.recapture_into_scratch_for_vm(base, parent_vm);
    record_ltp_memory_probe(
        LTP_MEM_PROBE_PARENT_SCRATCH_CAPTURE,
        parent_pid,
        parent_memory_scratch.len,
        snapshot_probe_word(parent_memory_scratch),
        live_probe_word(base),
    );
    let snapshot_parent_pid =
        prepare_parent_snapshot_validate_pid(parent_memory_scratch, process_ptr, parent_pid)?;
    let parent_mm_state = prepare_parent_mm_snapshot();
    refresh_proc_pid_stat(parent_vm, base, b'S')?;
    Ok(PreparedParentScratchState {
        parent_pid,
        parent_mm_state,
        snapshot_parent_pid,
    })
}

#[inline(never)]
fn prepare_parent_snapshot_after_pid(
    parent_vm: &ThreadState,
    base: u32,
    process_ptr: u32,
    parent_pid: i32,
) -> Result<Box<PreparedParentSnapshotState>, String> {
    let parent_memory = prepare_parent_memory_snapshot(base, parent_vm)?;
    prepare_parent_snapshot_finalize(parent_vm, base, process_ptr, parent_pid, parent_memory)
}

#[inline(never)]
fn prepare_parent_memory_snapshot(
    base: u32,
    parent_vm: &ThreadState,
) -> Result<Box<GuestMemorySnapshot>, String> {
    snapshot_guest_memory_for_vm(base, parent_vm)
}

#[inline(never)]
fn prepare_parent_snapshot_finalize(
    parent_vm: &ThreadState,
    base: u32,
    process_ptr: u32,
    parent_pid: i32,
    parent_memory: Box<GuestMemorySnapshot>,
) -> Result<Box<PreparedParentSnapshotState>, String> {
    let snapshot_parent_pid =
        prepare_parent_snapshot_validate_pid(&parent_memory, process_ptr, parent_pid)?;
    let parent_mm_state = prepare_parent_mm_snapshot();
    prepare_parent_snapshot_finish(
        parent_vm,
        base,
        parent_pid,
        parent_memory,
        parent_mm_state,
        snapshot_parent_pid,
    )
}

#[inline(never)]
fn prepare_parent_snapshot_validate_pid(
    parent_memory: &GuestMemorySnapshot,
    process_ptr: u32,
    parent_pid: i32,
) -> Result<i32, String> {
    let snapshot_parent_pid = snapshot_pid(parent_memory, process_ptr)?;
    if snapshot_parent_pid != parent_pid {
        return Err(format!(
            "process context snapshot corrupted parent pid: expected {}, got {}",
            parent_pid, snapshot_parent_pid
        ));
    }
    Ok(snapshot_parent_pid)
}

#[inline(never)]
fn prepare_parent_mm_snapshot() -> Box<tidemark_kernel::harness::support::ProcessContextSnapshot> {
    tidemark_kernel::harness::support::snapshot_process_context_boxed()
}

#[inline(never)]
fn prepare_parent_snapshot_finish(
    parent_vm: &ThreadState,
    base: u32,
    parent_pid: i32,
    parent_memory: Box<GuestMemorySnapshot>,
    parent_mm_state: Box<tidemark_kernel::harness::support::ProcessContextSnapshot>,
    snapshot_parent_pid: i32,
) -> Result<Box<PreparedParentSnapshotState>, String> {
    refresh_proc_pid_stat(parent_vm, base, b'S')?;
    Ok(Box::new(PreparedParentSnapshotState {
        parent_pid,
        parent_memory,
        parent_mm_state,
        snapshot_parent_pid,
    }))
}

#[inline(never)]
fn prepare_child_vm_for_spawn(
    parent_vm: &mut ThreadState,
    base: u32,
    process_ptr: u32,
    parent_pid: i32,
    child_pid: i32,
) -> Result<Box<ThreadState>, String> {
    tidemark_kernel::fs::fd_table::retain_fds_for_fork(base, parent_vm);
    tidemark_kernel::syscall::signal::fork_from_parent(parent_pid, child_pid);

    let fork_clone_flags = parent_vm.clone_flags;
    let fork_child_stack = parent_vm.clone_child_stack;
    let fork_tls = parent_vm.clone_tls;
    let fork_child_tidptr = parent_vm.clone_child_tidptr;
    let mut child_vm = Box::new(unsafe { core::ptr::read(parent_vm as *const ThreadState) });
    child_vm.process_ptr = process_ptr;
    child_vm.x[10] = 0;
    child_vm.tid = child_pid;
    child_vm.status = STATUS_OK;
    child_vm.exit_code = 0;
    child_vm.term_signal = 0;
    child_vm.sig_pending = 0;
    child_vm.clone_flags = 0;
    child_vm.clone_child_stack = 0;
    child_vm.clone_tls = 0;
    child_vm.clone_child_tidptr = 0;
    child_vm.clone_child_tid = 0;
    child_vm.clone_pending = 0;
    child_vm.clear_child_tid = if fork_clone_flags & CLONE_CHILD_CLEARTID != 0 {
        fork_child_tidptr
    } else {
        0
    };
    if fork_child_stack != 0 {
        child_vm.x[2] = fork_child_stack;
    }
    if fork_clone_flags & CLONE_SETTLS != 0 {
        child_vm.x[4] = fork_tls;
        child_vm.tls_base = fork_tls;
    }
    if fork_clone_flags & CLONE_CHILD_SETTID != 0 && fork_child_tidptr != 0 {
        unsafe {
            tidemark_kernel::guest_mem::write_u32(base, fork_child_tidptr, child_pid as u32);
        }
    }

    let child_ppid = if fork_clone_flags & CLONE_PARENT != 0 {
        process_ppid(base, process_ptr)
    } else {
        parent_pid
    };
    set_process_identity(base, process_ptr, child_pid, child_ppid);
    tidemark_kernel::syscall::thread::init_main_thread(
        &mut *child_vm as *mut ThreadState as u32,
        base,
    );
    if child_vm.process_ptr != process_ptr {
        return Err(format!(
            "prepare_child_vm_for_spawn corrupted process_ptr: expected=0x{:x} actual=0x{:x} pid={} ppid={}",
            process_ptr, child_vm.process_ptr, child_pid, child_ppid,
        ));
    }
    refresh_proc_pid_stat(&child_vm, base, b'R')?;
    Ok(child_vm)
}

#[inline(never)]
fn finalize_process_spawn_snapshot(
    child_vm: Box<ThreadState>,
    child_pid: i32,
    parent_pid: i32,
    base: u32,
) -> Result<PreparedProcessSpawn, String> {
    ensure_shared_heap_sane("before process context child snapshot")?;
    probe_snapshot_chunk_alloc();
    let guest_memory = snapshot_guest_memory_for_vm(base, &child_vm)?;
    record_ltp_memory_probe(
        LTP_MEM_PROBE_SPAWN_SNAPSHOT,
        child_pid,
        guest_memory.len,
        snapshot_probe_word(&guest_memory),
        live_probe_word(base),
    );
    let spawn = Box::new(SavedProcessCtx {
        pid: child_pid,
        parent_pid,
        process_group: process_pgid(&child_vm, base),
        shared_overlay_key: child_pid,
        child_entries: capture_live_child_entries(child_pid),
        vm: *child_vm,
        last_futex_addr: 0,
        waiter_placeholder: false,
        guest_memory,
        mm_state: tidemark_kernel::harness::support::snapshot_process_context_boxed(),
    });
    validate_saved_process_ctx(&spawn, "finalize_process_spawn_snapshot")?;
    Ok(spawn)
}

#[inline(never)]
fn restore_process_context_parent_after_snapshot(
    parent_vm: &ThreadState,
    base: u32,
    process_ptr: u32,
    parent_state: &PreparedParentSnapshotState,
    preserve_live_shared_mappings: bool,
) -> Result<i32, String> {
    tidemark_kernel::harness::support::debug_validate_process_context_snapshot(
        parent_state.parent_mm_state.as_ref(),
    )
    .map_err(|err| {
        format!("restore_process_context_parent_after_snapshot invalid parent_mm_state: {err}")
    })?;
    if preserve_live_shared_mappings {
        tidemark_kernel::harness::support::restore_process_context_parent(
            base,
            guest_window_size(base) as u64,
            parent_state.parent_mm_state.as_ref(),
            || parent_state.parent_memory.restore(base),
        )?;
    } else {
        tidemark_kernel::harness::support::restore_process_context_parent_without_shared_snapshot(
            base,
            guest_window_size(base) as u64,
            parent_state.parent_mm_state.as_ref(),
            || parent_state.parent_memory.restore(base),
        )?;
    }
    let snapshot_parent_pid_after_child = snapshot_pid(&parent_state.parent_memory, process_ptr)?;
    let pid_after_parent_restore = process_pid(base, process_ptr);
    restore_process_state_snapshot(&parent_state.parent_memory, base, process_ptr)?;
    repair_current_main_thread_record(parent_vm, base);
    let restored_pid = process_pid(base, process_ptr);
    if restored_pid != parent_state.parent_pid {
        return Err(format!(
            "process context restore corrupted parent pid: expected {}, got {}; snapshot_pid={} snapshot_pid_after_child={} pid_after_parent_restore={} process_ptr=0x{:x}",
            parent_state.parent_pid,
            restored_pid,
            parent_state.snapshot_parent_pid,
            snapshot_parent_pid_after_child,
            pid_after_parent_restore,
            process_ptr
        ));
    }
    Ok(restored_pid)
}

#[inline(never)]
fn restore_process_context_parent_after_snapshot_from_scratch(
    parent_vm: &ThreadState,
    base: u32,
    process_ptr: u32,
    parent_state: &PreparedParentScratchState,
    parent_memory: &GuestMemorySnapshot,
    preserve_live_shared_mappings: bool,
) -> Result<i32, String> {
    tidemark_kernel::harness::support::debug_validate_process_context_snapshot(
        parent_state.parent_mm_state.as_ref(),
    )
    .map_err(|err| {
        format!("restore_process_context_parent_after_snapshot invalid parent_mm_state: {err}")
    })?;
    if preserve_live_shared_mappings {
        tidemark_kernel::harness::support::restore_process_context_parent(
            base,
            guest_window_size(base) as u64,
            parent_state.parent_mm_state.as_ref(),
            || parent_memory.restore(base),
        )?;
    } else {
        tidemark_kernel::harness::support::restore_process_context_parent_without_shared_snapshot(
            base,
            guest_window_size(base) as u64,
            parent_state.parent_mm_state.as_ref(),
            || parent_memory.restore(base),
        )?;
    }
    let snapshot_parent_pid_after_child = snapshot_pid(parent_memory, process_ptr)?;
    let pid_after_parent_restore = process_pid(base, process_ptr);
    restore_process_state_snapshot(parent_memory, base, process_ptr)?;
    repair_current_main_thread_record(parent_vm, base);
    let restored_pid = process_pid(base, process_ptr);
    if restored_pid != parent_state.parent_pid {
        return Err(format!(
            "process context restore corrupted parent pid: expected {}, got {}; snapshot_pid={} snapshot_pid_after_child={} pid_after_parent_restore={} process_ptr=0x{:x}",
            parent_state.parent_pid,
            restored_pid,
            parent_state.snapshot_parent_pid,
            snapshot_parent_pid_after_child,
            pid_after_parent_restore,
            process_ptr
        ));
    }
    Ok(restored_pid)
}

fn handle_vfork_execve_spawn(
    parent_vm: &mut ThreadState,
    base: u32,
    use_cache: bool,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
) -> Result<(), String> {
    let child_pid = parent_vm.spawn_child_pid;
    if child_pid <= 0 {
        return Err(format!(
            "execve spawn returned invalid child pid {}",
            child_pid
        ));
    }

    let process_ptr = parent_vm.process_ptr;
    if process_ptr == 0 {
        return Err("execve spawn without ProcessState".into());
    }

    let parent_pid = process_pid(base, process_ptr);
    let parent_memory = snapshot_guest_memory(base)?;
    let parent_mm_state = tidemark_kernel::harness::support::snapshot_process_context();

    let mut child_vm = unsafe { core::ptr::read(parent_vm as *const ThreadState) };
    set_process_identity(base, process_ptr, child_pid, parent_pid);

    let ret = tidemark_kernel::syscall::process::complete_execve_in_place(
        &mut child_vm,
        base,
        GUEST_RAM_SIZE as u64,
    );
    if ret < 0 {
        tidemark_kernel::harness::support::restore_process_context_parent(
            base,
            guest_window_size(base) as u64,
            &parent_mm_state,
            || parent_memory.restore(base),
        )?;
        return Err(format!("complete_execve_in_place failed with {}", ret));
    }

    child_vm.tid = child_pid;
    tidemark_kernel::syscall::thread::init_main_thread(
        &mut child_vm as *mut ThreadState as u32,
        base,
    );

    let (child_exit, _child_pc) = run_vm(&mut child_vm, base, use_cache, deferred_clone_threads)?;
    tidemark_kernel::syscall::process::record_child_exit(
        child_pid,
        child_wait_status(&child_vm, child_exit),
    );

    tidemark_kernel::harness::support::restore_process_context_parent(
        base,
        guest_window_size(base) as u64,
        &parent_mm_state,
        || parent_memory.restore(base),
    )?;
    restore_process_state_snapshot(&parent_memory, base, process_ptr)?;
    repair_current_main_thread_record(parent_vm, base);
    tidemark_kernel::syscall::process::vfork_parent_resume(parent_vm, child_pid);

    Ok(())
}

fn service_ready_deferred_clone_threads(
    base: u32,
    use_cache: bool,
    deferred_clone_threads: &mut VecDeque<DeferredCloneThread>,
    current_pid: i32,
) -> Result<u32, String> {
    let mut progressed = 0u32;
    let initial_len = deferred_clone_threads.len();

    for _ in 0..initial_len {
        let Some(deferred_thread) = deferred_clone_threads.pop_front() else {
            break;
        };
        if deferred_thread.owner_pid != current_pid {
            deferred_clone_threads.push_back(deferred_thread);
            continue;
        }
        let child_ptr = deferred_thread.child_ptr;
        let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
        let child_ptr_usize = child_ptr as usize;
        let child_vm_size = core::mem::size_of::<ThreadState>();
        let Some(child_end) = child_ptr_usize.checked_add(child_vm_size) else {
            return Err(format!(
                "deferred clone child_ptr overflow owner_pid={} child_ptr=0x{:x} size=0x{:x}",
                current_pid, child_ptr, child_vm_size
            ));
        };
        if child_end > mem_size {
            return Err(format!(
                "deferred clone child_ptr out of wasm range owner_pid={} child_ptr=0x{:x} end=0x{:x} mem_size=0x{:x}",
                current_pid, child_ptr, child_end, mem_size
            ));
        }
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        validate_process_thread_ptrs(child_vm, base).map_err(|err| {
            format!(
                "deferred clone child state invalid owner_pid={} child_ptr=0x{:x}: {}",
                current_pid, child_ptr, err
            )
        })?;
        let guest_limit = guest_window_size(base) as u64;
        if child_vm.pc >= guest_limit {
            return Err(format!(
                "deferred clone child pc out of range owner_pid={} child_ptr=0x{:x} pc=0x{:x} guest_limit=0x{:x}",
                current_pid, child_ptr, child_vm.pc, guest_limit
            ));
        }
        if child_vm.x[2] != 0
            && !tidemark_kernel::syscall::memory::guest_range_accessible(
                base,
                child_vm.x[2].saturating_sub(8),
                8,
            )
        {
            return Err(format!(
                "deferred clone child sp inaccessible owner_pid={} child_ptr=0x{:x} sp=0x{:x} guest_limit=0x{:x}",
                current_pid, child_ptr, child_vm.x[2], guest_limit,
            ));
        }

        let runnable = match child_vm.status {
            STATUS_OK => true,
            STATUS_SLEEP => {
                consume_sleep_duration(child_vm)?;
                child_vm.status = STATUS_OK;
                true
            }
            STATUS_WAIT4 => {
                tidemark_kernel::syscall::process::resume_wait4(child_ptr, base);
                child_vm.status != STATUS_WAIT4
            }
            STATUS_FUTEX_WAIT => {
                if tidemark_kernel::syscall::thread::thread_record_blocked_addr(child_vm, base) == 0
                {
                    tidemark_kernel::syscall::thread::resume_futex_wait(child_vm, base);
                    true
                } else if child_vm.futex_wait_addr != 0
                    && unsafe { guest_mem::read_u32(base, child_vm.futex_wait_addr) }
                        != child_vm.futex_wait_expected
                {
                    tidemark_kernel::syscall::thread::resume_futex_wait(child_vm, base);
                    true
                } else {
                    false
                }
            }
            STATUS_PIPE_WAIT | STATUS_EPOLL_WAIT => {
                tidemark_kernel::abi::thread_resume_blocked_syscall(child_ptr);
                child_vm.status != STATUS_PIPE_WAIT && child_vm.status != STATUS_EPOLL_WAIT
            }
            _ => false,
        };

        if !runnable {
            deferred_clone_threads.push_back(deferred_thread);
            continue;
        }

        progressed += 1;
        match run_vm_inner(
            child_vm,
            base,
            use_cache,
            deferred_clone_threads,
            true,
            ProcessSpawnMode::Disallow,
            false,
            None,
        )? {
            VmRunOutcome::Exited(_, _) => {
                refresh_proc_pid_stat(child_vm, base, b'R')?;
            }
            VmRunOutcome::Deferred(_) => {
                enqueue_deferred_clone_thread(deferred_clone_threads, current_pid, child_ptr);
                refresh_proc_pid_stat(child_vm, base, b'S')?;
            }
            VmRunOutcome::ProcessSpawn(_) => {
                return Err("deferred clone thread yielded a process spawn unexpectedly".into());
            }
        }
    }

    Ok(progressed)
}

fn count_deferred_clone_threads_for_process(
    deferred_clone_threads: &VecDeque<DeferredCloneThread>,
    pid: i32,
) -> usize {
    deferred_clone_threads
        .iter()
        .filter(|queued| queued.owner_pid == pid && queued.child_ptr != 0)
        .count()
}

pub(crate) fn consume_relative_futex_timeout(
    vm: &ThreadState,
    base: u32,
    _started_at: Instant,
) -> Result<(), String> {
    let Some(timeout) = read_guest_timespec_duration(base, vm.futex_wait_timeout)? else {
        return Ok(());
    };
    if vm.futex_wait_absolute != 0 {
        let clock_id = if (vm.futex_wait_flags & FUTEX_CLOCK_REALTIME) != 0 {
            0
        } else {
            1
        };
        let Some((now_sec, now_nsec)) = tidemark_kernel::syscall::time::current_timespec(clock_id)
        else {
            return Err(format!("unsupported futex wait clock id {}", clock_id));
        };
        let target_sec =
            unsafe { tidemark_kernel::guest_mem::read_u64(base, vm.futex_wait_timeout) };
        let target_nsec =
            unsafe { tidemark_kernel::guest_mem::read_u64(base, vm.futex_wait_timeout + 8) };
        if target_nsec >= 1_000_000_000 {
            return Err(format!(
                "invalid absolute futex timeout timespec: sec={} nsec={}",
                target_sec, target_nsec
            ));
        }
        let remaining = if (target_sec, target_nsec) <= (now_sec, now_nsec) {
            Duration::ZERO
        } else {
            let sec_delta = target_sec - now_sec;
            let (sec_delta, nsec_delta) = if target_nsec >= now_nsec {
                (sec_delta, target_nsec - now_nsec)
            } else {
                (
                    sec_delta.saturating_sub(1),
                    1_000_000_000 + target_nsec - now_nsec,
                )
            };
            Duration::new(sec_delta, nsec_delta as u32)
        };
        tidemark_kernel::syscall::time::advance_monotonic_duration(remaining);
        return Ok(());
    }
    tidemark_kernel::syscall::time::advance_monotonic_duration(timeout);
    Ok(())
}

pub(crate) fn consume_sleep_duration(vm: &ThreadState) -> Result<(), String> {
    if vm.fault_pc >= 1_000_000_000 {
        return Err(format!(
            "invalid sleep duration timespec: sec={} nsec={}",
            vm.fault_addr, vm.fault_pc
        ));
    }
    tidemark_kernel::syscall::time::advance_monotonic_duration(Duration::new(
        vm.fault_addr,
        vm.fault_pc as u32,
    ));
    Ok(())
}

fn read_guest_timespec_duration(base: u32, guest_addr: u64) -> Result<Option<Duration>, String> {
    if guest_addr == 0 {
        return Ok(None);
    }
    let sec = unsafe { tidemark_kernel::guest_mem::read_u64(base, guest_addr) };
    let nsec = unsafe { tidemark_kernel::guest_mem::read_u64(base, guest_addr + 8) };
    if nsec >= 1_000_000_000 {
        return Err(format!(
            "invalid futex timeout timespec: sec={} nsec={}",
            sec, nsec
        ));
    }
    Ok(Some(Duration::new(sec, nsec as u32)))
}

/// Load an ELF, run the interpreter with block cache, return (exit_code, last_pc).
pub fn run_elf(elf_bytes: &[u8]) -> Result<(i32, u64), String> {
    let (code, pc, _) = run_elf_inner(elf_bytes, true)?;
    Ok((code, pc))
}

pub fn run_elf_with_output(elf_bytes: &[u8]) -> Result<(i32, u64, Vec<u8>), String> {
    run_elf_inner(elf_bytes, true)
}

/// Load an ELF, run the interpreter without block cache (baseline).
pub fn run_elf_no_cache(elf_bytes: &[u8]) -> Result<(i32, u64), String> {
    let (code, pc, _) = run_elf_inner(elf_bytes, false)?;
    Ok((code, pc))
}

pub fn run_elf_no_cache_with_output(elf_bytes: &[u8]) -> Result<(i32, u64, Vec<u8>), String> {
    run_elf_inner(elf_bytes, false)
}

fn drain_pipe_slot(pipe_slot: u32, out: &mut Vec<u8>) {
    if pipe_slot == 0 {
        return;
    }
    let mut buf = [0u8; 512];
    loop {
        let n = tidemark_kernel::syscall::pipe::pipe_read(pipe_slot, &mut buf);
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
}

fn collect_guest_stdio(vm: &ThreadState) -> Vec<u8> {
    let vm_ptr = vm as *const ThreadState as u32;
    let stdout = tidemark_kernel::abi::process_stdout_pipe(vm_ptr);
    let stderr = tidemark_kernel::abi::process_stderr_pipe(vm_ptr);
    let mut out = Vec::new();
    drain_pipe_slot(stdout, &mut out);
    if stderr != 0 && stderr != stdout {
        drain_pipe_slot(stderr, &mut out);
    }
    out
}

pub(crate) fn prepare_elf_vm(elf_bytes: &[u8], use_cache: bool) -> Result<PreparedElfVm, String> {
    let helper_binaries = load_ltp_helper_binaries()?;
    unsafe {
        tidemark_kernel::guest_mem::init(core::ptr::null(), core::ptr::null(), core::ptr::null());

        let current_pages = core::arch::wasm32::memory_size(0);
        let current_bytes = (current_pages as u64).saturating_mul(65536);
        let guest_base_hint = current_bytes.saturating_add(GUEST_BASE_PADDING as u64);
        let aligned = guest_base_hint.saturating_add((GUEST_RAM_ALIGN - 1) as u64)
            & !((GUEST_RAM_ALIGN - 1) as u64);
        let candidate_base = aligned.min(u32::MAX as u64) as u32;
        let base = if TEST_GUEST_BASE != 0 {
            TEST_GUEST_BASE
        } else {
            candidate_base
        };
        TEST_GUEST_BASE = base;
        let target_bytes = (base as u64).saturating_add(GUEST_RAM_SIZE as u64);
        let target_pages = ((target_bytes + 65535) / 65536) as usize;
        let target_pages = target_pages.max(TEST_MEMORY_PAGES);
        if current_pages < target_pages {
            let grown = core::arch::wasm32::memory_grow(0, target_pages - current_pages);
            if grown == usize::MAX {
                return Err("memory_grow failed".into());
            }
        }

        tidemark_kernel::guest_mem::zero_mem(base, 0, GUEST_RAM_SIZE as usize);

        let elf_load_addr: u64 = 0xC0_0000;
        tidemark_kernel::guest_mem::write_bytes(base, elf_load_addr, elf_bytes);

        let load_segments = tidemark_kernel::elf::collect_load_segments(
            (base as u64 + elf_load_addr) as u32,
            elf_bytes.len() as u32,
            0,
        )
        .map_err(|e| format!("ELF segment inspection failed: {}", e))?;

        let elf_result = tidemark_kernel::elf::load_elf(
            base,
            GUEST_RAM_SIZE as u64,
            (base as u64 + elf_load_addr) as u32,
            elf_bytes.len() as u32,
        )
        .map_err(|e| format!("ELF load failed: {}", e))?;
        tidemark_kernel::elf::zero_fill_load_padding(
            base,
            elf_result.load_end,
            elf_result.brk_start,
        );

        let host_heap_base = base
            .saturating_add(GUEST_RAM_SIZE)
            .saturating_add(HOST_HEAP_PADDING);
        tidemark_kernel::alloc::reset(host_heap_base);
        let guest_brk_start = elf_result.brk_start;
        tidemark_kernel::syscall::time::init();
        tidemark_kernel::syscall::memory::init(guest_brk_start);
        for segment in load_segments {
            tidemark_kernel::syscall::memory::register_elf_load_segment(
                segment.start,
                segment.end,
                segment.prot | tidemark_kernel::abi::PROT_EXEC,
            );
        }
        tidemark_kernel::syscall::process::init();
        tidemark_kernel::syscall::thread::init();
        tidemark_kernel::syscall::signal::init();
        tidemark_kernel::syscall::epoll::init();
        tidemark_kernel::syscall::pipe::init();
        tidemark_kernel::syscall::pty::init();
        tidemark_kernel::syscall::socket::init();
        tidemark_kernel::net::ring_buffer::init();
        tidemark_kernel::fs::fd_table::init();
        tidemark_kernel::fs::memfs::init();
        ensure_shared_heap_sane("after subsystem init")?;
        let tmp_ino = ensure_dir(1, b"tmp", 0o1777)?;
        let bin_ino = ensure_dir(1, b"bin", 0o755)?;
        let dev_ino = ensure_dir(1, b"dev", 0o755)?;
        let etc_ino = ensure_dir(1, b"etc", 0o755)?;
        let proc_ino = ensure_dir(1, b"proc", 0o555)?;
        let proc_sys_ino = ensure_dir(proc_ino, b"sys", 0o555)?;
        let proc_kernel_ino = ensure_dir(proc_sys_ino, b"kernel", 0o555)?;
        let _ = ensure_dir(dev_ino, b"shm", 0o1777)?;
        let _ = ensure_file(etc_ino, b"passwd", ETC_PASSWD_BYTES, 0o644)?;
        let _ = ensure_file(etc_ino, b"group", ETC_GROUP_BYTES, 0o644)?;
        let meminfo_ino = match tidemark_kernel::fs::memfs::lookup(proc_ino, b"meminfo") {
            0 => {
                let ino = tidemark_kernel::fs::memfs::create_file(proc_ino, b"meminfo", 0o444);
                if ino == 0 {
                    return Err("failed to create meminfo".into());
                }
                ino
            }
            ino => ino,
        };
        let meminfo_truncate = tidemark_kernel::fs::memfs::truncate(meminfo_ino, 0);
        if meminfo_truncate != 0 {
            return Err(format!("failed to truncate meminfo: {meminfo_truncate}"));
        }
        let meminfo_written =
            tidemark_kernel::fs::memfs::write_file(meminfo_ino, 0, PROC_MEMINFO_BYTES);
        if meminfo_written != PROC_MEMINFO_BYTES.len() as i64 {
            return Err(format!(
                "failed to write meminfo: wrote {} of {}",
                meminfo_written,
                PROC_MEMINFO_BYTES.len()
            ));
        }
        let _ = ensure_file(proc_ino, b"cpuinfo", PROC_CPUINFO_BYTES, 0o444)?;
        let mut pid_max = [0u8; 24];
        let _ = ensure_file(
            proc_kernel_ino,
            b"pid_max",
            proc_pid_max_bytes(&mut pid_max),
            0o444,
        )?;
        let _ = ensure_file(
            proc_kernel_ino,
            b"tainted",
            proc_kernel_tainted().as_bytes(),
            0o444,
        )?;
        let proc1_ino = ensure_dir(proc_ino, b"1", 0o555)?;
        let _ = ensure_file(proc1_ino, b"stat", PROC_PID1_STAT_BYTES, 0o444)?;
        ensure_proc_pid_stat(INITIAL_PID, INITIAL_PPID, b'R', INITIAL_PID)?;
        let _ = tmp_ino;
        stage_ltp_helper_binaries(bin_ino, &helper_binaries)?;
        ensure_shared_heap_sane("after helper staging")?;
        drop(helper_binaries);

        let stack_top = tidemark_kernel::syscall::memory::map_initial_stack(
            base,
            GUEST_RAM_SIZE as u64,
            tidemark_kernel::syscall::memory::DEFAULT_STACK_SIZE,
        );
        if stack_top < 0 {
            return Err(format!("initial stack mapping failed: {}", stack_top));
        }
        let stack_top = stack_top as u64;

        let random_addr = stack_top.saturating_sub(0x100);
        tidemark_kernel::guest_mem::write_bytes(base, random_addr, &[0x42u8; 16]);

        let argv0_addr = stack_top.saturating_sub(0x200);
        tidemark_kernel::guest_mem::write_bytes(base, argv0_addr, b"test\0");
        let env_path_addr = stack_top.saturating_sub(0x220);
        tidemark_kernel::guest_mem::write_bytes(base, env_path_addr, b"PATH=/bin\0");
        let env_virt_override_addr = stack_top.saturating_sub(0x240);
        tidemark_kernel::guest_mem::write_bytes(
            base,
            env_virt_override_addr,
            b"LTP_VIRT_OVERRIDE=\0",
        );

        let sp = tidemark_kernel::elf::setup_stack(
            base,
            stack_top.saturating_sub(0x300),
            &[argv0_addr],
            &[env_path_addr, env_virt_override_addr],
            &elf_result,
            random_addr,
            argv0_addr,
        );

        let mut vm: ThreadState = core::mem::zeroed();
        vm.pc = elf_result.entry;
        vm.x[2] = sp;
        vm.status = STATUS_OK;
        vm.tid = INITIAL_PID;
        vm.guest_base = base;
        vm.guest_ram_limit = GUEST_RAM_SIZE;

        let ps_size = core::mem::size_of::<ProcessState>() as u64;
        let ps_align = core::mem::align_of::<ProcessState>() as u64;
        let brk = tidemark_kernel::syscall::memory::current_brk();
        let ps_addr = (brk + ps_align - 1) & !(ps_align - 1);
        if ps_addr
            .checked_add(ps_size)
            .is_none_or(|end| end > guest_window_size(base) as u64)
        {
            return Err(format!(
                "process state out of guest range brk=0x{:x} ps_addr=0x{:x} ps_size=0x{:x} guest_limit=0x{:x}",
                brk,
                ps_addr,
                ps_size,
                guest_window_size(base),
            ));
        }
        let brk_ret = tidemark_kernel::syscall::memory::grow_brk(base, ps_addr + ps_size);
        if brk_ret < (ps_addr + ps_size) as i64 {
            return Err("ProcessState brk allocation failed".into());
        }
        tidemark_kernel::guest_mem::zero_mem(base, ps_addr, ps_size as usize);
        vm.process_ptr = ps_addr as u32;

        let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + pid_off, INITIAL_PID as u32);
        let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + ppid_off, INITIAL_PPID as u32);
        let cwd_off = core::mem::offset_of!(ProcessState, cwd_ino) as u64;
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + cwd_off, 1);
        let fs_ring_off = core::mem::offset_of!(ProcessState, fs_ring_base) as u64;
        let fs_ring_base = tidemark_kernel::alloc::alloc_zeroed(
            tidemark_kernel::fs::ring_buffer::RING_BUFFER_SIZE as u32,
            16,
        );
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + fs_ring_off, fs_ring_base);
        let umask_off = core::mem::offset_of!(ProcessState, umask) as u64;
        tidemark_kernel::guest_mem::write_u32(base, ps_addr + umask_off, 0o022);
        tidemark_kernel::syscall::signal::init_for_process(INITIAL_PID);

        tidemark_kernel::fs::fd_table::init_stdio(base, &mut vm);
        let vm_ptr = &mut vm as *mut ThreadState as usize;
        let vm_size = core::mem::size_of::<ThreadState>();
        let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
        if vm_ptr.checked_add(vm_size).is_none_or(|end| end > mem_size) {
            return Err(format!(
                "vm ptr out of wasm range vm_ptr=0x{:x} vm_size=0x{:x} mem_size=0x{:x}",
                vm_ptr, vm_size, mem_size
            ));
        }
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut vm as *mut ThreadState as u32,
            base,
        );
        ensure_shared_heap_sane("before block cache alloc")?;

        let cache_size = tidemark_kernel::cpu::block_cache::BlockCache::allocation_size() as u32;
        let _cache_ptr = if use_cache {
            let ptr = tidemark_kernel::alloc::alloc(cache_size, 8);
            if ptr == 0 {
                return Err(format!(
                    "block cache alloc failed size=0x{:x} heap_base=0x{:x} heap_ptr=0x{:x}",
                    cache_size,
                    tidemark_kernel::alloc::heap_base(),
                    tidemark_kernel::alloc::heap_ptr(),
                ));
            }
            let mem_size = (core::arch::wasm32::memory_size(0) as usize).saturating_mul(65536);
            let ptr_usize = ptr as usize;
            let Some(end) = ptr_usize.checked_add(cache_size as usize) else {
                return Err(format!(
                    "block cache alloc overflow ptr=0x{:x} size=0x{:x} heap_base=0x{:x} heap_ptr=0x{:x}",
                    ptr,
                    cache_size,
                    tidemark_kernel::alloc::heap_base(),
                    tidemark_kernel::alloc::heap_ptr(),
                ));
            };
            if end > mem_size {
                return Err(format!(
                    "block cache alloc out of wasm range ptr=0x{:x} end=0x{:x} mem_size=0x{:x} heap_base=0x{:x} heap_ptr=0x{:x}",
                    ptr,
                    end,
                    mem_size,
                    tidemark_kernel::alloc::heap_base(),
                    tidemark_kernel::alloc::heap_ptr(),
                ));
            }
            core::ptr::write_bytes(ptr as *mut u8, 0, cache_size as usize);
            ptr
        } else {
            0
        };
        let _ = _cache_ptr;

        let vm = Box::new(vm);
        repair_current_main_thread_record(&vm, base);
        Ok(PreparedElfVm { base, vm })
    }
}

pub(crate) fn run_prepared_elf_vm(
    prepared: PreparedElfVm,
    use_cache: bool,
) -> Result<(i32, u64, Vec<u8>), String> {
    tidemark_kernel::harness::support::clear_external_futex_waits();
    let mut deferred_clone_threads = VecDeque::new();
    let PreparedElfVm { base, vm } = prepared;
    let mut vm = vm;
    let (code, pc) = run_vm(&mut vm, base, use_cache, &mut deferred_clone_threads)?;
    let output = collect_guest_stdio(&vm);
    Ok((code, pc, output))
}

pub(crate) fn step_prepared_elf_vm_for_ltp(
    prepared: &mut PreparedElfVm,
    use_cache: bool,
    scheduler: &mut LtpSchedulerState,
) -> Result<LtpVmOutcome, String> {
    let mut vm = unsafe { core::ptr::read(prepared.vm.as_ref()) };
    record_ltp_thread_state_identity(prepared.base, &vm, 0, 0, LTP_VM_ID_ROOT);
    let outcome = run_vm_root_for_ltp(&mut vm, prepared.base, use_cache, scheduler)?;
    record_ltp_thread_state_identity(prepared.base, &vm, 0, 0, LTP_VM_ID_ROOT);
    *prepared.vm = vm;
    scheduler.invalidate_current_snapshot();
    Ok(match outcome {
        VmRunOutcome::Exited(code, pc) => LtpVmOutcome::Exited(code, pc),
        VmRunOutcome::Deferred(_) => LtpVmOutcome::Deferred,
        VmRunOutcome::ProcessSpawn(spawn) => LtpVmOutcome::ProcessSpawn(spawn),
    })
}

pub(crate) fn step_saved_process_ctx_for_ltp(
    current: &mut PreparedElfVm,
    saved: &mut SavedProcessCtx,
    use_cache: bool,
    scheduler: &mut LtpSchedulerState,
    sibling_proc_stats: &[(i32, i32, u8, i32)],
    mut validate_siblings: impl FnMut(&str) -> Result<(), String>,
) -> Result<LtpVmOutcome, String> {
    validate_siblings("step_saved_process_ctx_for_ltp entry siblings")?;
    validate_saved_process_ctx(saved, "step_saved_process_ctx_for_ltp entry")?;
    saved.record_vm_identity(current.base, LTP_VM_ID_SAVED_STEP);
    let mut saved_guest_memory =
        core::mem::replace(&mut saved.guest_memory, GuestMemorySnapshot::empty_box());
    let mut saved_mm_state = core::mem::replace(
        &mut saved.mm_state,
        tidemark_kernel::harness::support::snapshot_process_context_boxed(),
    );
    let base = current.base;
    let result = (|| -> Result<LtpVmOutcome, String> {
        let pre_restore_exited_children =
            tidemark_kernel::harness::process::debug_exited_children_for_parent(saved.pid);
        let current_child_proc_stats = capture_live_child_proc_stats(saved.pid);
        let current_parent_proc_stat = if saved.parent_pid > 0 && saved.parent_pid != saved.pid {
            read_live_proc_pid_stat(saved.parent_pid)
                .map(|(ppid, state, pgrp)| (saved.parent_pid, ppid, state, pgrp))
        } else {
            None
        };
        let current_pid = if current.vm.process_ptr != 0 {
            process_pid(base, current.vm.process_ptr)
        } else {
            0
        };
        let reuse_current_snapshot = scheduler.guest_memory_scratch.len != 0
            && scheduler.current_snapshot_pid == current_pid
            && scheduler.current_snapshot_process_ptr == current.vm.process_ptr
            && scheduler.current_snapshot_pc == current.vm.pc
            && scheduler.current_snapshot_sp == current.vm.x[2]
            && scheduler.current_snapshot_wait_pid == current.vm.wait_pid;
        if !reuse_current_snapshot {
            scheduler
                .guest_memory_scratch
                .recapture_into_scratch_for_vm(base, current.vm.as_ref());
            scheduler.current_snapshot_pid = current_pid;
            scheduler.current_snapshot_process_ptr = current.vm.process_ptr;
            scheduler.current_snapshot_pc = current.vm.pc;
            scheduler.current_snapshot_sp = current.vm.x[2];
            scheduler.current_snapshot_wait_pid = current.vm.wait_pid;
        }
        let current_memory = scheduler.guest_memory_scratch.as_ref();
        let current_mm_state = tidemark_kernel::harness::support::snapshot_process_context();
        let current_shared_mappings =
            tidemark_kernel::harness::support::capture_live_shared_mapping_overlay(
                base,
                guest_window_size(base) as u64,
                &current_mm_state,
            );
        let mut exited_child_record: Option<(i32, i32, i32)> = None;
        record_ltp_memory_probe(
            LTP_MEM_PROBE_SAVED_PRE_RESTORE,
            saved.pid,
            saved_guest_memory.len,
            snapshot_probe_word(&saved_guest_memory),
            live_probe_word(base),
        );

        tidemark_kernel::harness::support::restore_process_context_mm_only_from_guest_snapshot(
            base,
            guest_window_size(base) as u64,
            &saved_mm_state,
            || {
                saved_guest_memory.restore(base).map_err(|e| {
                    format!(
                        "restore saved process pid {} guest memory: {}",
                        saved.pid, e
                    )
                })
            },
        )?;
        record_ltp_memory_probe(
            LTP_MEM_PROBE_SAVED_POST_RESTORE,
            saved.pid,
            saved_guest_memory.len,
            snapshot_probe_word(&saved_guest_memory),
            live_probe_word(base),
        );
        validate_siblings("step_saved_process_ctx_for_ltp after restore saved mm")?;
        tidemark_kernel::harness::support::restore_live_shared_mapping_overlay(
            base,
            &current_shared_mappings,
        );
        if let Some(shared_overlay) = scheduler.shared_mapping_overlay(saved.shared_overlay_key) {
            tidemark_kernel::harness::support::restore_live_shared_mapping_overlay(
                base,
                shared_overlay,
            );
        }
        restore_process_state_snapshot(&saved_guest_memory, base, saved.vm.process_ptr).map_err(
            |e| {
                format!(
                    "restore saved process state pid={} process_ptr=0x{:x} snapshot_len=0x{:x} saved_ptr=0x{:x} snapshot_ptr=0x{:x} guest_base=0x{:x} guest_limit=0x{:x}: {}",
                    saved.pid,
                    saved.vm.process_ptr,
                    saved_guest_memory.len,
                    saved as *const SavedProcessCtx as usize,
                    saved_guest_memory.as_ref() as *const GuestMemorySnapshot as usize,
                    base,
                    guest_window_size(base),
                    e
                )
            },
        )?;
        repair_current_main_thread_record(&saved.vm, base);
        saved.record_vm_identity(base, LTP_VM_ID_SAVED_STEP);
        validate_siblings("step_saved_process_ctx_for_ltp after restore saved process state")?;
        for (pid, ppid, state, pgrp) in current_child_proc_stats.iter().copied() {
            ensure_proc_pid_stat(pid, ppid, state, pgrp)?;
        }
        if let Some((pid, ppid, state, pgrp)) = current_parent_proc_stat {
            if !sibling_proc_stats
                .iter()
                .any(|(sibling_pid, _, _, _)| *sibling_pid == pid)
            {
                ensure_proc_pid_stat(pid, ppid, state, pgrp)?;
            }
        }
        for (pid, ppid, state, pgrp) in sibling_proc_stats.iter().copied() {
            ensure_proc_pid_stat(pid, ppid, state, pgrp)?;
        }
        for (pid, exited, wait_status) in saved.child_entries.iter().copied() {
            tidemark_kernel::harness::process::sync_child_entry_for_parent(
                saved.pid,
                pid,
                exited,
                wait_status,
            );
        }
        refresh_proc_pid_stat(&saved.vm, base, b'R')?;
        let mut reapplied_exited_child = false;
        for (child_pid, wait_status) in pre_restore_exited_children {
            let post_exited = tidemark_kernel::harness::process::debug_child_entry(child_pid)
                .map(|(_, exited, _)| exited)
                .unwrap_or(false);
            if !post_exited {
                tidemark_kernel::syscall::process::record_child_exit_for_parent(
                    saved.pid,
                    child_pid,
                    wait_status,
                );
                reapplied_exited_child = true;
            }
        }
        if reapplied_exited_child {
            saved.refresh_runtime_snapshot();
        }

        let mut iteration_budget = 100_000usize;
        let outcome = loop {
            iteration_budget -= 1;
            if iteration_budget == 0 {
                return Err(format!(
                    "saved process step budget exhausted: pid={} ppid={} status={} a0={} a7={} futex_addr=0x{:x} futex_expected={} futex_timeout={} deferred_clone_threads={}",
                    saved.pid,
                    saved.parent_pid,
                    saved.status(),
                    saved.a0(),
                    saved.a7(),
                    saved.vm.futex_wait_addr,
                    saved.vm.futex_wait_expected,
                    saved.vm.futex_wait_timeout,
                    count_deferred_clone_threads_for_process(
                        &scheduler.deferred_clone_threads,
                        saved.pid
                    ),
                ));
            }
            match saved.vm.status {
                STATUS_SLEEP => {
                    consume_sleep_duration(&saved.vm)?;
                    saved.vm.status = STATUS_OK;
                }
                STATUS_WAIT4 => {
                    let vm_ptr = &mut saved.vm as *mut ThreadState as u32;
                    tidemark_kernel::syscall::process::resume_wait4(vm_ptr, base);
                }
                STATUS_FUTEX_WAIT => {
                    let futex_addr = saved.vm.futex_wait_addr as u32;
                    if futex_addr != 0 {
                        saved.last_futex_addr = futex_addr;
                    }
                    let is_process_leader = saved.pid > 0 && saved.vm.tid == saved.pid;
                    if tidemark_kernel::syscall::thread::thread_record_blocked_addr(&saved.vm, base)
                        == 0
                    {
                        tidemark_kernel::syscall::thread::resume_futex_wait(&mut saved.vm, base);
                    } else if is_process_leader
                        && (tidemark_kernel::harness::support::take_external_futex_wake(
                            saved.pid, futex_addr,
                        )
                            || tidemark_kernel::harness::support::take_external_futex_wake_for_pid(
                                saved.pid,
                            ))
                    {
                        tidemark_kernel::syscall::thread::resume_futex_wait(&mut saved.vm, base);
                    } else if count_deferred_clone_threads_for_process(
                        &scheduler.deferred_clone_threads,
                        saved.pid,
                    ) > 0
                    {
                        tidemark_kernel::harness::support::clear_external_futex_wait(saved.pid);
                        let _ = service_ready_deferred_clone_threads(
                            base,
                            use_cache,
                            &mut scheduler.deferred_clone_threads,
                            saved.pid,
                        )?;
                        if tidemark_kernel::syscall::thread::thread_record_blocked_addr(
                            &saved.vm, base,
                        ) == 0
                        {
                            tidemark_kernel::syscall::thread::resume_futex_wait(
                                &mut saved.vm,
                                base,
                            );
                        } else if saved.vm.futex_wait_addr != 0
                            && unsafe { guest_mem::read_u32(base, saved.vm.futex_wait_addr) }
                                != saved.vm.futex_wait_expected
                        {
                            tidemark_kernel::syscall::thread::resume_futex_wait(
                                &mut saved.vm,
                                base,
                            );
                        } else {
                            refresh_proc_pid_stat(&saved.vm, base, b'S')?;
                            saved_guest_memory.recapture_into_scratch_for_vm(base, &saved.vm);
                            saved_mm_state =
                                tidemark_kernel::harness::support::snapshot_process_context_boxed();
                            break LtpVmOutcome::Deferred;
                        }
                    } else if saved.vm.futex_wait_timeout != 0 {
                        if current.vm.status == STATUS_WAIT4
                            && (saved.parent_pid <= 0
                                || !tidemark_kernel::harness::support::has_external_futex_wake(
                                    saved.parent_pid,
                                ))
                        {
                            tidemark_kernel::harness::support::clear_external_futex_wait(saved.pid);
                            consume_relative_futex_timeout(&saved.vm, base, Instant::now())?;
                            tidemark_kernel::syscall::thread::resume_futex_wait_result(
                                &mut saved.vm,
                                base,
                                ETIMEDOUT,
                            );
                        } else {
                            if !tidemark_kernel::harness::support::has_external_futex_wait(
                                saved.pid,
                            ) {
                                tidemark_kernel::harness::support::register_external_futex_wait(
                                    saved.pid, futex_addr,
                                );
                            }
                            refresh_proc_pid_stat(&saved.vm, base, b'S')?;
                            saved_guest_memory.recapture_into_scratch_for_vm(base, &saved.vm);
                            saved_mm_state =
                                tidemark_kernel::harness::support::snapshot_process_context_boxed();
                            break LtpVmOutcome::Deferred;
                        }
                    } else {
                        if !tidemark_kernel::harness::support::has_external_futex_wait(saved.pid) {
                            tidemark_kernel::harness::support::register_external_futex_wait(
                                saved.pid, futex_addr,
                            );
                        }
                        refresh_proc_pid_stat(&saved.vm, base, b'S')?;
                        saved_guest_memory.recapture_into_scratch_for_vm(base, &saved.vm);
                        saved_mm_state =
                            tidemark_kernel::harness::support::snapshot_process_context_boxed();
                        break LtpVmOutcome::Deferred;
                    }
                }
                STATUS_PIPE_WAIT => {
                    let vm_ptr = &mut saved.vm as *mut ThreadState as u32;
                    tidemark_kernel::abi::thread_resume_blocked_syscall(vm_ptr);
                    if saved.vm.status == STATUS_PIPE_WAIT {
                        refresh_proc_pid_stat(&saved.vm, base, b'S')?;
                        saved_guest_memory.recapture_into_scratch_for_vm(base, &saved.vm);
                        saved_mm_state =
                            tidemark_kernel::harness::support::snapshot_process_context_boxed();
                        break LtpVmOutcome::Deferred;
                    }
                }
                _ => {}
            }

            if saved.vm.status == STATUS_WAIT4 {
                refresh_proc_pid_stat(&saved.vm, base, b'S')?;
                saved_guest_memory.recapture_into_scratch_for_vm(base, &saved.vm);
                saved_mm_state =
                    tidemark_kernel::harness::support::snapshot_process_context_boxed();
                break LtpVmOutcome::Deferred;
            }

            validate_siblings("step_saved_process_ctx_for_ltp before run_vm_inner")?;
            record_ltp_memory_probe(
                LTP_MEM_PROBE_SAVED_PRE_RUN,
                saved.pid,
                saved_guest_memory.len,
                snapshot_probe_word(&saved_guest_memory),
                live_probe_word(base),
            );
            let vm_outcome = run_vm_inner(
                &mut saved.vm,
                base,
                use_cache,
                &mut scheduler.deferred_clone_threads,
                true,
                ProcessSpawnMode::Yield,
                true,
                Some(scheduler.parent_memory_scratch.as_mut()),
            )?;
            validate_siblings("step_saved_process_ctx_for_ltp after run_vm_inner")?;
            match vm_outcome {
                VmRunOutcome::Exited(child_exit, child_pc) => {
                    if saved.vm.term_signal == SIGSEGV {
                        let (sig, code, pc, ra, sp, gp, tp, s11, fault_pc, fault_addr) =
                            tidemark_kernel::harness::signal::last_default_signal();
                        let default_vm_ptr =
                            tidemark_kernel::harness::signal::last_default_signal_vm_ptr();
                        let (
                            clone_tid,
                            clone_flags,
                            clone_pc,
                            clone_sp,
                            clone_tls,
                            clone_child_tidptr,
                        ) = tidemark_kernel::syscall::thread::last_clone_spawn_details();
                        return Err(format!(
                            "saved child killed by SIGSEGV pid={} ppid={} tid={} exit={} child_pc=0x{:x} fault_pc=0x{:x} fault_addr=0x{:x} regs(a0=0x{:x} a1=0x{:x} a2=0x{:x} a3=0x{:x} a4=0x{:x} a5=0x{:x} a6=0x{:x} a7=0x{:x} t3=0x{:x}) default_signal(vm_ptr=0x{:x} sig={} code={} pc=0x{:x} ra=0x{:x} sp=0x{:x} gp=0x{:x} tp=0x{:x} s11=0x{:x} fault_pc=0x{:x} fault_addr=0x{:x}) stack_words={} pc_words={} aux_fault_words={} tst_brk_handler_words={} fault_exec_trace={} execve_stage_trace={} ltp_memory_probe={} last_clone(tid={} flags=0x{:x} pc=0x{:x} sp=0x{:x} tls=0x{:x} child_tidptr=0x{:x})",
                            saved.pid,
                            saved.parent_pid,
                            saved.vm.tid,
                            child_exit,
                            child_pc,
                            saved.vm.fault_pc,
                            saved.vm.fault_addr,
                            saved.vm.x[10],
                            saved.vm.x[11],
                            saved.vm.x[12],
                            saved.vm.x[13],
                            saved.vm.x[14],
                            saved.vm.x[15],
                            saved.vm.x[16],
                            saved.vm.x[17],
                            saved.vm.x[28],
                            default_vm_ptr,
                            sig,
                            code,
                            pc,
                            ra,
                            sp,
                            gp,
                            tp,
                            s11,
                            fault_pc,
                            fault_addr,
                            describe_current_guest_u64_words(sp, 24),
                            describe_current_guest_u32_words(
                                fault_pc.saturating_sub(16) as u32,
                                16
                            ),
                            describe_current_guest_u64_words(fault_addr.saturating_sub(16), 8),
                            describe_current_guest_u32_words(0xd91c0, 4),
                            tidemark_kernel::harness::support::describe_fault_exec_trace_for_vm(
                                default_vm_ptr,
                            ),
                            tidemark_kernel::harness::support::describe_execve_stage_trace(),
                            describe_ltp_memory_probe(),
                            clone_tid,
                            clone_flags,
                            clone_pc,
                            clone_sp,
                            clone_tls,
                            clone_child_tidptr,
                        ));
                    }
                    tidemark_kernel::harness::support::clear_external_futex_wait(saved.pid);
                    let wait_status = child_wait_status(&saved.vm, child_exit);
                    let parent_pid = if saved.parent_pid > 0 {
                        saved.parent_pid
                    } else if saved.vm.process_ptr != 0 {
                        process_ppid(base, saved.vm.process_ptr)
                    } else {
                        0
                    };
                    exited_child_record = Some((parent_pid, saved.pid, wait_status));
                    break LtpVmOutcome::Exited(child_exit, child_pc);
                }
                VmRunOutcome::Deferred(_) => {
                    if count_deferred_clone_threads_for_process(
                        &scheduler.deferred_clone_threads,
                        saved.pid,
                    ) > 0
                    {
                        continue;
                    }
                    if current.vm.status == STATUS_WAIT4
                        && saved.vm.status == STATUS_FUTEX_WAIT
                        && saved.vm.futex_wait_timeout != 0
                    {
                        continue;
                    }
                    if saved.vm.status == STATUS_FUTEX_WAIT
                        && !tidemark_kernel::harness::support::has_external_futex_wait(saved.pid)
                    {
                        tidemark_kernel::harness::support::register_external_futex_wait(
                            saved.pid,
                            saved.vm.futex_wait_addr as u32,
                        );
                    }
                    refresh_proc_pid_stat(&saved.vm, base, b'S')?;
                    saved_guest_memory.recapture_into_scratch_for_vm(base, &saved.vm);
                    saved_mm_state =
                        tidemark_kernel::harness::support::snapshot_process_context_boxed();
                    break LtpVmOutcome::Deferred;
                }
                VmRunOutcome::ProcessSpawn(spawn) => {
                    validate_saved_process_ctx(
                        &spawn,
                        "step_saved_process_ctx_for_ltp spawn outcome",
                    )?;
                    record_ltp_memory_probe(
                        LTP_MEM_PROBE_PARENT_SCRATCH_SPAWN,
                        saved.pid,
                        scheduler.parent_memory_scratch.len,
                        snapshot_probe_word(scheduler.parent_memory_scratch.as_ref()),
                        live_probe_word(base),
                    );
                    refresh_proc_pid_stat(&saved.vm, base, b'R')?;
                    saved_guest_memory
                        .clone_from_snapshot(scheduler.parent_memory_scratch.as_ref());
                    saved_mm_state =
                        tidemark_kernel::harness::support::snapshot_process_context_boxed();
                    break LtpVmOutcome::ProcessSpawn(spawn);
                }
            }
        };

        validate_siblings("step_saved_process_ctx_for_ltp after outcome before saved snapshot")?;
        let saved_live_mm_state = tidemark_kernel::harness::support::snapshot_process_context();
        validate_siblings("step_saved_process_ctx_for_ltp after snapshot saved mm state")?;
        saved.child_entries = capture_live_child_entries(saved.pid);
        validate_siblings("step_saved_process_ctx_for_ltp after capture saved child entries")?;
        let saved_shared_mappings =
            tidemark_kernel::harness::support::capture_live_shared_mapping_overlay(
                base,
                guest_window_size(base) as u64,
                &saved_live_mm_state,
            );
        validate_siblings("step_saved_process_ctx_for_ltp after capture saved shared mappings")?;
        validate_siblings("step_saved_process_ctx_for_ltp before restore current mm")?;

        tidemark_kernel::harness::support::flush_shared_mapping_overlay(base);
        validate_siblings("step_saved_process_ctx_for_ltp after flush current shared mappings")?;
        current_memory.restore(base).map_err(|e| {
            format!(
                "restore current guest memory after stepping saved pid {}: {}",
                saved.pid, e
            )
        })?;
        validate_siblings("step_saved_process_ctx_for_ltp after restore current guest memory")?;
        tidemark_kernel::harness::support::restore_process_context_mm_state(&current_mm_state);
        validate_siblings("step_saved_process_ctx_for_ltp after restore current mm state")?;
        tidemark_kernel::harness::support::refresh_shared_mapping_file_mappings(
            base,
            guest_window_size(base) as u64,
        );
        validate_siblings(
            "step_saved_process_ctx_for_ltp after refresh current shared file mappings",
        )?;
        if let Some(shared_overlay) = scheduler.shared_mapping_overlay(saved.shared_overlay_key) {
            tidemark_kernel::harness::support::restore_live_shared_mapping_overlay(
                base,
                shared_overlay,
            );
        }
        restore_process_state_snapshot(&current_memory, base, current.vm.process_ptr).map_err(
            |e| {
                format!(
                    "restore current process state pid={} process_ptr=0x{:x} snapshot_len=0x{:x}: {}",
                    process_pid(base, current.vm.process_ptr),
                    current.vm.process_ptr,
                    current_memory.len,
                    e
                )
            },
        )?;
        validate_siblings("step_saved_process_ctx_for_ltp after restore current process state")?;
        scheduler.update_shared_mapping_overlay(saved.shared_overlay_key, saved_shared_mappings);
        repair_current_main_thread_record(&current.vm, base);
        if !matches!(outcome, LtpVmOutcome::Exited(_, _)) {
            ensure_saved_proc_pid_stat(saved, proc_pid_stat_state_for_status(saved.vm.status))?;
        }
        if let Some((parent_pid, pid, wait_status)) = exited_child_record {
            tidemark_kernel::syscall::process::record_child_exit(pid, wait_status);
            tidemark_kernel::syscall::process::record_child_exit_for_parent(
                parent_pid,
                pid,
                wait_status,
            );
        }
        current.vm.status = STATUS_OK;
        Ok(outcome)
    })();
    if !matches!(&result, Ok(LtpVmOutcome::Exited(_, _))) && saved_guest_memory.len == 0 {
        return Err(format!(
            "step_saved_process_ctx_for_ltp produced empty snapshot: result={} pid={} ppid={} tid={} status={} pc=0x{:x} sp=0x{:x} process_ptr=0x{:x} wait_pid={} futex_addr=0x{:x} a0={} a7={}",
            match &result {
                Ok(outcome) => outcome.label(),
                Err(_) => "error",
            },
            saved.pid,
            saved.parent_pid,
            saved.tid(),
            saved.vm.status,
            saved.vm.pc,
            saved.vm.x[2],
            saved.process_ptr(),
            saved.vm.wait_pid,
            saved.last_futex_addr,
            saved.vm.x[10],
            saved.vm.x[17],
        ));
    }
    saved.guest_memory = saved_guest_memory;
    saved.mm_state = saved_mm_state;
    result
}

pub(crate) fn collect_prepared_elf_stdio(prepared: &PreparedElfVm) -> Vec<u8> {
    collect_guest_stdio(&prepared.vm)
}

fn run_elf_inner(elf_bytes: &[u8], use_cache: bool) -> Result<(i32, u64, Vec<u8>), String> {
    let result = (|| -> Result<(i32, u64, Vec<u8>), String> {
        let prepared = prepare_elf_vm(elf_bytes, use_cache)?;
        run_prepared_elf_vm(prepared, use_cache)
    })();

    match result {
        Ok((code, pc, output)) => Ok((code, pc, output)),
        Err(err) => Err(err),
    }
}

pub fn assert_elf_pass(name: &str, elf_bytes: &[u8]) -> Result<(), String> {
    let (code, pc) = run_elf(elf_bytes)?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{} failed: exit_code={}, last_pc=0x{:x}",
            name, code, pc
        ))
    }
}

pub fn assert_elf_pass_no_cache(name: &str, elf_bytes: &[u8]) -> Result<(), String> {
    let (code, pc) = run_elf_no_cache(elf_bytes)?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{} (no cache) failed: exit_code={}, last_pc=0x{:x}",
            name, code, pc
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidemark_kernel::abi::{
        CLONE_FS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VM, FUTEX_CMP_REQUEUE, FUTEX_WAIT, FUTEX_WAKE,
        MAP_ANONYMOUS, MAP_PRIVATE, PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE, STATUS_FUTEX_WAIT,
    };
    use tidemark_kernel::fs::memfs;
    use tidemark_kernel::guest_mem;
    use tidemark_kernel::harness::TestVm;
    use tidemark_kernel::syscall::process as process_impl;
    use tidemark_kernel::syscall::thread as thread_impl;
    use tidemark_kernel::types::{ProcessState, THREAD_NONE};

    fn alloc_exec_code_page(t: &mut TestVm) -> u64 {
        let mapped = t.sys_mmap(
            0,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert!(mapped >= 0);
        mapped as u64 + 0x80
    }

    fn read_memfs_file(ino: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 128];
        let n = memfs::read_file(ino, 0, &mut buf);
        assert!(n >= 0);
        buf.truncate(n as usize);
        buf
    }

    fn proc_task_stat_ino(pid: i32, tid: i32) -> u32 {
        let proc_ino = memfs::lookup(1, b"proc");
        assert_ne!(proc_ino, 0);
        let pid_name = pid.to_string();
        let pid_ino = memfs::lookup(proc_ino, pid_name.as_bytes());
        assert_ne!(pid_ino, 0);
        let task_ino = memfs::lookup(pid_ino, b"task");
        assert_ne!(task_ino, 0);
        let tid_name = tid.to_string();
        let tid_ino = memfs::lookup(task_ino, tid_name.as_bytes());
        if tid_ino == 0 {
            return 0;
        }
        memfs::lookup(tid_ino, b"stat")
    }

    fn proc_pid_stat_bytes(pid: i32) -> Vec<u8> {
        let proc_ino = memfs::lookup(1, b"proc");
        assert_ne!(proc_ino, 0);
        let pid_name = pid.to_string();
        let pid_ino = memfs::lookup(proc_ino, pid_name.as_bytes());
        assert_ne!(pid_ino, 0);
        let stat_ino = memfs::lookup(pid_ino, b"stat");
        assert_ne!(stat_ino, 0);
        read_memfs_file(stat_ino)
    }

    fn write_exit_program(base: u32, pc: u64, exit_code: u8) {
        let code = [
            0x13,
            0x05,
            exit_code << 4,
            0x00, // addi a0, zero, exit_code
            0x93,
            0x08,
            0xd0,
            0x05, // addi a7, zero, 93 (SYS_exit)
            0x73,
            0x00,
            0x00,
            0x00, // ecall
        ];
        unsafe {
            guest_mem::write_bytes(base, pc, &code);
        }
    }

    fn encode_i(opcode: u32, rd: u32, funct3: u32, rs1: u32, imm: i32) -> u32 {
        (((imm as u32) & 0x0fff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }

    fn encode_u(opcode: u32, rd: u32, imm20: u32) -> u32 {
        (imm20 << 12) | (rd << 7) | opcode
    }

    fn encode_li(rd: u32, value: u32) -> [u32; 2] {
        let upper = (value.wrapping_add(0x800)) >> 12;
        let lower = value.wrapping_sub(upper << 12) as i32;
        [encode_u(0x37, rd, upper), encode_i(0x13, rd, 0, rd, lower)]
    }

    fn write_futex_wake_then_exit_program(base: u32, pc: u64, exit_code: u8) {
        let code = [
            0x73,
            0x00,
            0x00,
            0x00, // ecall (futex)
            0x13,
            0x05,
            exit_code << 4,
            0x00, // addi a0, zero, exit_code
            0x93,
            0x08,
            0xd0,
            0x05, // addi a7, zero, 93 (SYS_exit)
            0x73,
            0x00,
            0x00,
            0x00, // ecall
        ];
        unsafe {
            guest_mem::write_bytes(base, pc, &code);
        }
    }

    fn write_futex_wake_return_then_exit_program(base: u32, pc: u64) {
        let code = [
            0x73, 0x00, 0x00, 0x00, // ecall (futex)
            0x93, 0x08, 0xd0, 0x05, // addi a7, zero, 93 (SYS_exit)
            0x73, 0x00, 0x00, 0x00, // ecall
        ];
        unsafe {
            guest_mem::write_bytes(base, pc, &code);
        }
    }

    fn write_futex_wait_return_then_exit_program(base: u32, pc: u64, futex_addr: u32) {
        let li_a0 = encode_li(10, futex_addr);
        unsafe {
            guest_mem::write_u32(base, pc, li_a0[0]);
            guest_mem::write_u32(base, pc + 4, li_a0[1]);
            guest_mem::write_u32(base, pc + 8, 0x0000_0073); // ecall
            guest_mem::write_u32(base, pc + 12, 0x05d0_0893); // addi a7, zero, 93
            guest_mem::write_u32(base, pc + 16, 0x0000_0073); // ecall
        }
    }

    #[test]
    fn deferred_clone_thread_resumes_after_futex_wake() {
        let mut t = TestVm::new();
        let pid = process_pid(t.base, t.vm.process_ptr);
        let futex_addr = t.scratch + 0x400;
        let code_addr = alloc_exec_code_page(&mut t);
        write_exit_program(t.base, code_addr, 9);
        unsafe {
            guest_mem::write_u32(t.base, futex_addr, 0);
        }

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);

        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        child_vm.pc = code_addr;

        let wait_ret =
            thread_impl::sys_futex(child_vm, t.base, futex_addr, FUTEX_WAIT as u64, 0, 0, 0, 0);
        assert_eq!(wait_ret, 0);
        assert_eq!(child_vm.status, STATUS_FUTEX_WAIT);

        let mut deferred_clone_threads = VecDeque::new();
        enqueue_deferred_clone_thread(&mut deferred_clone_threads, pid, child_ptr);

        let wake_ret =
            thread_impl::sys_futex(&mut t.vm, t.base, futex_addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
        assert_eq!(wake_ret, 1);

        let progressed =
            service_ready_deferred_clone_threads(t.base, false, &mut deferred_clone_threads, pid)
                .expect("deferred clone wake service should succeed");
        assert_eq!(progressed, 1);
        assert!(deferred_clone_threads.is_empty());

        let ps = unsafe { &*((t.base as u64 + t.vm.process_ptr as u64) as *const ProcessState) };
        assert_eq!(
            ps.thread_count.load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert_eq!(ps.threads[(child_tid - 1) as usize].state, THREAD_DEAD);
    }

    #[test]
    fn deferred_clone_thread_is_not_serviced_under_foreign_pid_image() {
        let mut t = TestVm::new();
        let pid = 2;
        set_process_identity(t.base, t.vm.process_ptr, pid, 1);
        t.vm.tid = pid;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);
        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        child_vm.status = STATUS_OK;

        let mut deferred_clone_threads = VecDeque::new();
        enqueue_deferred_clone_thread(&mut deferred_clone_threads, pid + 1, child_ptr);

        let progressed =
            service_ready_deferred_clone_threads(t.base, false, &mut deferred_clone_threads, pid)
                .expect("foreign-owned clone thread should be skipped cleanly");

        assert_eq!(progressed, 0);
        assert_eq!(deferred_clone_threads.len(), 1);
        assert_eq!(
            deferred_clone_threads
                .front()
                .map(|queued| queued.owner_pid),
            Some(pid + 1)
        );
        assert_eq!(
            deferred_clone_threads
                .front()
                .map(|queued| queued.child_ptr),
            Some(child_ptr)
        );
    }

    #[test]
    fn proc_pid_stat_uses_leader_state_not_current_running_thread() {
        let mut t = TestVm::new();
        let pid = 2;
        set_process_identity(t.base, t.vm.process_ptr, pid, 1);
        t.vm.tid = pid;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        let futex_addr = t.scratch + 0x480;
        unsafe {
            guest_mem::write_u32(t.base, futex_addr, 0);
        }
        let wait_ret =
            thread_impl::sys_futex(&mut t.vm, t.base, futex_addr, FUTEX_WAIT as u64, 0, 0, 0, 0);
        assert_eq!(wait_ret, 0);
        assert_eq!(t.vm.status, STATUS_FUTEX_WAIT);

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);
        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };
        refresh_proc_pid_stat(child_vm, t.base, b'R').expect("proc refresh should succeed");

        let stat = proc_pid_stat_bytes(pid);
        let text = String::from_utf8(stat).expect("pid stat should be utf8");
        assert!(
            text.contains(" S "),
            "expected sleeping leader state, got {text:?}"
        );
    }

    #[test]
    fn proc_task_entry_disappears_after_clone_thread_exit() {
        let mut t = TestVm::new();
        let pid = 2;
        set_process_identity(t.base, t.vm.process_ptr, pid, 1);
        t.vm.tid = pid;
        tidemark_kernel::syscall::thread::init_main_thread(
            &mut t.vm as *mut ThreadState as u32,
            t.base,
        );

        let flags = (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS) as u64;
        let child_tid = thread_impl::sys_clone(&mut t.vm, t.base, flags, 0, 0, 0, 0) as i32;
        assert!(child_tid > 0);
        let child_ptr = thread_impl::spawn_from_clone(&mut t.vm as *mut ThreadState as u32, t.base);
        assert_ne!(child_ptr, 0);
        let child_vm = unsafe { &mut *(child_ptr as *mut ThreadState) };

        refresh_proc_pid_stat(child_vm, t.base, b'R').expect("proc refresh should succeed");
        assert_ne!(proc_task_stat_ino(pid, child_tid), 0);

        assert_eq!(
            thread_impl::sys_exit(child_vm, t.base, 0),
            tidemark_kernel::abi::STATUS_FAULT
        );
        refresh_proc_pid_stat(child_vm, t.base, b'R')
            .expect("proc refresh after exit should succeed");
        assert_eq!(proc_task_stat_ino(pid, child_tid), 0);
    }

    #[test]
    fn repair_current_main_thread_record_restores_parent_slot() {
        let t = TestVm::new();
        let tid = t.vm.tid;
        let vm_ptr = &t.vm as *const ThreadState as u32;
        let ps = unsafe { &mut *((t.base as u64 + t.vm.process_ptr as u64) as *mut ProcessState) };
        ps.thread_count
            .store(0, std::sync::atomic::Ordering::Release);
        ps.threads[(tid - 1) as usize] = ThreadRecord::new(0, THREAD_NONE, 0, 0, 0);

        repair_current_main_thread_record(&t.vm, t.base);

        assert_eq!(
            ps.thread_count.load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert_eq!(ps.threads[(tid - 1) as usize].tid, tid);
        assert_eq!(ps.threads[(tid - 1) as usize].thread_ptr, vm_ptr);
    }
}

pub fn write_process_ids(t: &tidemark_kernel::harness::TestVm, pid: i32, ppid: i32) {
    let ps_ptr = t.vm.process_ptr as u64;
    let pid_off = core::mem::offset_of!(ProcessState, pid) as u64;
    let ppid_off = core::mem::offset_of!(ProcessState, ppid) as u64;
    unsafe {
        guest_mem::write_u32(t.base, ps_ptr + pid_off, pid as u32);
        guest_mem::write_u32(t.base, ps_ptr + ppid_off, ppid as u32);
    }
}

pub fn ensure_memfs_dir(parent: u32, name: &[u8]) -> u32 {
    let ino = memfs::lookup(parent, name);
    if ino != 0 {
        ino
    } else {
        memfs::create_dir(parent, name, 0o755)
    }
}

pub fn install_memfs_file_at(path: &[u8], bytes: &[u8], mode: u32) -> u32 {
    let trimmed = path.strip_prefix(b"/").unwrap_or(path);
    let mut parts = trimmed.split(|b| *b == b'/').peekable();
    let mut parent = 1u32;
    let mut final_name = b"".as_slice();
    while let Some(part) = parts.next() {
        if parts.peek().is_some() {
            parent = ensure_memfs_dir(parent, part);
        } else {
            final_name = part;
        }
    }
    let ino = match memfs::lookup(parent, final_name) {
        0 => memfs::create_file(parent, final_name, mode),
        ino => ino,
    };
    assert_ne!(ino, 0);
    assert_eq!(memfs::truncate(ino, 0), 0);
    assert_eq!(memfs::write_file(ino, 0, bytes), bytes.len() as i64);
    ino
}

pub fn install_exec_file_at(
    t: &tidemark_kernel::harness::TestVm,
    path: &[u8],
    elf_bytes: &[u8],
) -> u64 {
    install_memfs_file_at(path, elf_bytes, 0o755);
    let mut c_path = Vec::from(path);
    c_path.push(0);
    let path_addr = t.scratch;
    t.write_mem(path_addr, &c_path);
    path_addr
}

pub fn install_exec_file(
    t: &tidemark_kernel::harness::TestVm,
    name: &[u8],
    elf_bytes: &[u8],
) -> u64 {
    let mut path = Vec::from(&b"/bin/"[..]);
    path.extend_from_slice(name);
    install_exec_file_at(t, &path, elf_bytes)
}

pub fn find_auxv_value(base: u32, sp: u64, tag: u64) -> Option<u64> {
    let argc = unsafe { guest_mem::read_u64(base, sp) };
    let mut cursor = sp + 8;
    cursor += argc * 8 + 8;
    while unsafe { guest_mem::read_u64(base, cursor) } != 0 {
        cursor += 8;
    }
    cursor += 8;
    for _ in 0..32 {
        let aux_tag = unsafe { guest_mem::read_u64(base, cursor) };
        let aux_val = unsafe { guest_mem::read_u64(base, cursor + 8) };
        if aux_tag == tidemark_kernel::elf::AT_NULL {
            return None;
        }
        if aux_tag == tag {
            return Some(aux_val);
        }
        cursor += 16;
    }
    None
}

pub fn find_vm_auxv_value(t: &tidemark_kernel::harness::TestVm, tag: u64) -> Option<u64> {
    find_auxv_value(t.base, t.vm.x[2], tag)
}

pub fn write_strvec(t: &tidemark_kernel::harness::TestVm, offset: u64, values: &[&[u8]]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let vec_addr = t.scratch + offset;
    let mut data_cursor = vec_addr + ((values.len() + 1) as u64) * 8;
    for (idx, value) in values.iter().enumerate() {
        unsafe {
            guest_mem::write_u64(t.base, vec_addr + (idx as u64) * 8, data_cursor);
            guest_mem::write_bytes(t.base, data_cursor, value);
            guest_mem::write_u8(t.base, data_cursor + value.len() as u64, 0);
        }
        data_cursor += value.len() as u64 + 1;
    }
    unsafe {
        guest_mem::write_u64(t.base, vec_addr + (values.len() as u64) * 8, 0);
    }
    vec_addr
}

// Shared synthetic ELF builders for kernel integration tests.
pub fn build_test_elf(code: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut elf = vec![0u8; 0x100 + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x1000);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0x100);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[0x100..0x100 + code.len()].copy_from_slice(code);
    elf
}

pub fn build_test_elf_with_tls(code: &[u8], tls_init: &[u8], tls_memsz: u64) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let code_off = 0x100usize;
    let data_off = 0x200usize;
    let entry = 0x1000u64 + code_off as u64;
    let code_filesz = (code_off + code.len()) as u64;
    let data_vaddr = 0x3000u64;
    let data_filesz = tls_init.len() as u64;
    let data_memsz = tls_memsz.max(data_filesz);
    let total_len = data_off + tls_init.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 3);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code_filesz);
    put_u64(&mut elf, 104, code_filesz);
    put_u64(&mut elf, 112, 0x1000);

    put_u32(&mut elf, 120, 1);
    put_u32(&mut elf, 124, 6);
    put_u64(&mut elf, 128, data_off as u64);
    put_u64(&mut elf, 136, data_vaddr);
    put_u64(&mut elf, 152, data_filesz);
    put_u64(&mut elf, 160, data_memsz);
    put_u64(&mut elf, 168, 0x1000);

    put_u32(&mut elf, 176, 7);
    put_u32(&mut elf, 180, 4);
    put_u64(&mut elf, 184, data_off as u64);
    put_u64(&mut elf, 192, data_vaddr);
    put_u64(&mut elf, 208, data_filesz);
    put_u64(&mut elf, 216, tls_memsz);
    put_u64(&mut elf, 224, 8);

    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + tls_init.len()].copy_from_slice(tls_init);
    elf
}

pub fn build_test_elf_with_interp(code: &[u8], interp_path: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let ph_num = 2usize;
    let interp_off = 0x100usize;
    let code_off = 0x200usize;
    let entry = 0x1000u64 + code_off as u64;
    let code_end = code_off + code.len();
    let total_len = code_end.max(interp_off + interp_path.len() + 1);
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, ph_num as u16);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let load_off = ph_off + 56;
    put_u32(&mut elf, load_off, 1);
    put_u32(&mut elf, load_off + 4, 5);
    put_u64(&mut elf, load_off + 8, 0);
    put_u64(&mut elf, load_off + 16, 0x1000);
    put_u64(&mut elf, load_off + 32, code_end as u64);
    put_u64(&mut elf, load_off + 40, code_end as u64);
    put_u64(&mut elf, load_off + 48, 0x1000);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf
}

pub fn build_test_elf_with_interp_and_tls(
    code: &[u8],
    interp_path: &[u8],
    tls_init: &[u8],
    tls_memsz: u64,
) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let interp_off = 0x200usize;
    let code_off = 0x300usize;
    let data_off = 0x400usize;
    let entry = 0x1000u64 + code_off as u64;
    let total_len = data_off + tls_init.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 4);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let code_ph = ph_off + 56;
    put_u32(&mut elf, code_ph, 1);
    put_u32(&mut elf, code_ph + 4, 5);
    put_u64(&mut elf, code_ph + 8, 0);
    put_u64(&mut elf, code_ph + 16, 0x1000);
    put_u64(&mut elf, code_ph + 32, data_off as u64);
    put_u64(&mut elf, code_ph + 40, data_off as u64);
    put_u64(&mut elf, code_ph + 48, 0x1000);

    let data_ph = ph_off + 112;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, tls_init.len() as u64);
    put_u64(&mut elf, data_ph + 40, tls_memsz);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    let tls_ph = ph_off + 168;
    put_u32(&mut elf, tls_ph, 7);
    put_u32(&mut elf, tls_ph + 4, 4);
    put_u64(&mut elf, tls_ph + 8, data_off as u64);
    put_u64(&mut elf, tls_ph + 16, 0x3000);
    put_u64(&mut elf, tls_ph + 32, tls_init.len() as u64);
    put_u64(&mut elf, tls_ph + 40, tls_memsz);
    put_u64(&mut elf, tls_ph + 48, 8);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + tls_init.len()].copy_from_slice(tls_init);
    elf
}

pub fn build_test_elf_dyn_with_interp(code: &[u8], interp_path: &[u8]) -> Vec<u8> {
    let mut elf = build_test_elf_with_interp(code, interp_path);
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
    elf
}

pub fn build_test_elf_dyn_with_interp_and_tls(
    code: &[u8],
    interp_path: &[u8],
    tls_init: &[u8],
    tls_memsz: u64,
) -> Vec<u8> {
    let mut elf = build_test_elf_with_interp_and_tls(code, interp_path, tls_init, tls_memsz);
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
    elf
}

pub fn build_test_elf_dyn(code: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut elf = vec![0u8; 0x100 + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x1000);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0x100);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[0x100..0x100 + code.len()].copy_from_slice(code);
    elf
}

pub fn build_test_elf_dyn_low(code: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let code_off = 0x100usize;
    let mut elf = vec![0u8; code_off + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x40);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, code_off as u64);
    put_u64(&mut elf, 80, 0);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf
}

pub fn build_test_elf_dyn_two_loads(code: &[u8], data: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let code_off = 0x100usize;
    let data_off = 0x300usize;
    let entry = 0x1000u64;
    let total_len = data_off + data.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 2);

    put_u32(&mut elf, ph_off, 1);
    put_u32(&mut elf, ph_off + 4, 5);
    put_u64(&mut elf, ph_off + 8, code_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1000);
    put_u64(&mut elf, ph_off + 32, code.len() as u64);
    put_u64(&mut elf, ph_off + 40, code.len() as u64);
    put_u64(&mut elf, ph_off + 48, 0x1000);

    let data_ph = ph_off + 56;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, data.len() as u64);
    put_u64(&mut elf, data_ph + 40, data.len() as u64 + 0x100);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + data.len()].copy_from_slice(data);
    elf
}

pub fn build_test_elf_dyn_with_interp_two_loads(
    code: &[u8],
    data: &[u8],
    interp_path: &[u8],
) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let interp_off = 0x100usize;
    let code_off = 0x200usize;
    let data_off = 0x300usize;
    let entry = 0x1000u64 + code_off as u64;
    let total_len = data_off + data.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 3);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let code_ph = ph_off + 56;
    put_u32(&mut elf, code_ph, 1);
    put_u32(&mut elf, code_ph + 4, 5);
    put_u64(&mut elf, code_ph + 8, 0);
    put_u64(&mut elf, code_ph + 16, 0x1000);
    put_u64(&mut elf, code_ph + 32, data_off as u64);
    put_u64(&mut elf, code_ph + 40, data_off as u64);
    put_u64(&mut elf, code_ph + 48, 0x1000);

    let data_ph = ph_off + 112;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, data.len() as u64);
    put_u64(&mut elf, data_ph + 40, data.len() as u64 + 0x100);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + data.len()].copy_from_slice(data);
    elf
}

pub fn build_test_elf_dyn_with_interp_dynamic(
    code: &[u8],
    data: &[u8],
    interp_path: &[u8],
) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let interp_off = 0x100usize;
    let code_off = 0x200usize;
    let data_off = 0x300usize;
    let dynamic_off = 0x320usize;
    let dynamic_vaddr = 0x3020u64;
    let entry = 0x1000u64 + code_off as u64;
    let second_filesz = (dynamic_off + 64 - data_off).max(data.len());
    let total_len = data_off + second_filesz;
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 4);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let code_ph = ph_off + 56;
    put_u32(&mut elf, code_ph, 1);
    put_u32(&mut elf, code_ph + 4, 5);
    put_u64(&mut elf, code_ph + 8, 0);
    put_u64(&mut elf, code_ph + 16, 0x1000);
    put_u64(&mut elf, code_ph + 32, data_off as u64);
    put_u64(&mut elf, code_ph + 40, data_off as u64);
    put_u64(&mut elf, code_ph + 48, 0x1000);

    let data_ph = ph_off + 112;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, second_filesz as u64);
    put_u64(&mut elf, data_ph + 40, second_filesz as u64 + 0x100);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    let dynamic_ph = ph_off + 168;
    put_u32(&mut elf, dynamic_ph, 2);
    put_u32(&mut elf, dynamic_ph + 4, 6);
    put_u64(&mut elf, dynamic_ph + 8, dynamic_off as u64);
    put_u64(&mut elf, dynamic_ph + 16, dynamic_vaddr);
    put_u64(&mut elf, dynamic_ph + 32, 4 * 16);
    put_u64(&mut elf, dynamic_ph + 40, 4 * 16);
    put_u64(&mut elf, dynamic_ph + 48, 8);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + data.len()].copy_from_slice(data);
    put_u64(&mut elf, dynamic_off, 7);
    put_u64(&mut elf, dynamic_off + 8, 0x3300);
    put_u64(&mut elf, dynamic_off + 16, 8);
    put_u64(&mut elf, dynamic_off + 24, 24);
    put_u64(&mut elf, dynamic_off + 32, 0x6fff_ffff);
    put_u64(&mut elf, dynamic_off + 40, 5);
    put_u64(&mut elf, dynamic_off + 48, 0);
    put_u64(&mut elf, dynamic_off + 56, 0);
    elf
}
