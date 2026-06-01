use std::collections::VecDeque;
use std::time::Instant;

use tidemark_kernel::abi::{
    ETIMEDOUT, STATUS_FUTEX_WAIT, STATUS_OK, STATUS_PIPE_WAIT, STATUS_SLEEP, STATUS_WAIT4,
};

use crate::support;

const LTP_PROCESS_TREE_WATCHDOG_SECS: u64 = 300;

type SavedChildCtx = support::SavedProcessCtx;

struct SavedChildren {
    queue: VecDeque<SavedChildCtx>,
}

impl SavedChildren {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn iter(&self) -> impl Iterator<Item = &SavedChildCtx> {
        self.queue.iter()
    }

    fn find_by_pid(&self, pid: i32) -> Option<&SavedChildCtx> {
        self.iter().find(|child| child.pid == pid)
    }

    fn position(&self, predicate: impl FnMut(&SavedChildCtx) -> bool) -> Option<usize> {
        self.queue.iter().position(predicate)
    }

    fn any(&self, predicate: impl FnMut(&SavedChildCtx) -> bool) -> bool {
        self.iter().any(predicate)
    }

    fn all(&self, predicate: impl FnMut(&SavedChildCtx) -> bool) -> bool {
        self.iter().all(predicate)
    }

    fn pop_front(&mut self) -> Option<SavedChildCtx> {
        self.queue.pop_front()
    }

    fn remove(&mut self, idx: usize) -> Option<SavedChildCtx> {
        self.queue.remove(idx)
    }

    fn pop_selected_or_front(&mut self, selected_idx: Option<usize>) -> Option<SavedChildCtx> {
        selected_idx
            .and_then(|idx| self.remove(idx))
            .or_else(|| self.pop_front())
    }

    fn remove_matching(
        &mut self,
        mut predicate: impl FnMut(&SavedChildCtx) -> bool,
    ) -> Vec<SavedChildCtx> {
        let mut drained = Vec::new();
        let mut idx = 0usize;
        while idx < self.queue.len() {
            if predicate(&self.queue[idx]) {
                drained.push(self.queue.remove(idx).expect("queue index must exist"));
            } else {
                idx += 1;
            }
        }
        drained
    }

    fn validate(&self, label: &str) -> Result<(), String> {
        if std::env::var_os("TIDEMARK_VALIDATE_SAVED_CHILDREN_QUEUE").is_none() {
            return Ok(());
        }
        self.validate_strict(label)
    }

    fn validate_strict(&self, label: &str) -> Result<(), String> {
        for child in self.iter() {
            support::validate_saved_process_ctx(child, label)?;
        }
        Ok(())
    }

    fn push_back(&mut self, mut child: SavedChildCtx, label: &str) -> Result<(), String> {
        child.normalize_process_leader_vm();
        self.validate(&format!("{label} pre-queue"))?;
        ensure_saved_child_has_snapshot(&child, label)?;
        validate_saved_child_debug(&child, label)?;
        self.queue.push_back(child);
        self.validate(&format!("{label} post-queue"))
    }

    fn push_front(&mut self, mut child: SavedChildCtx, label: &str) -> Result<(), String> {
        child.normalize_process_leader_vm();
        self.validate(&format!("{label} pre-queue"))?;
        ensure_saved_child_has_snapshot(&child, label)?;
        validate_saved_child_debug(&child, label)?;
        self.queue.push_front(child);
        self.validate(&format!("{label} post-queue"))
    }

    fn prioritize_parent(&mut self, parent_pid: i32) -> Result<(), String> {
        if parent_pid <= 0 {
            return Ok(());
        }
        let Some(idx) = self.position(|child| child.pid == parent_pid) else {
            return Ok(());
        };
        let Some(parent) = self.remove(idx) else {
            return Ok(());
        };
        self.push_front(parent, "prioritize_saved_parent push_front parent")
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        for child in self.iter().take(16) {
            let child_entry = tidemark_kernel::harness::process::debug_child_entry(child.pid)
                .map(|(parent_pid, exited, wait_status)| {
                    format!(
                        "entry(parent={} exited={} wait_status={})",
                        parent_pid, exited, wait_status
                    )
                })
                .unwrap_or_else(|| "entry(missing)".to_string());
            let wait_target = child.a0() as i32;
            let wait_target_entry = if wait_target > 0 {
                tidemark_kernel::harness::process::debug_child_entry(wait_target)
                    .map(|(parent_pid, exited, wait_status)| {
                        format!(
                            "wait_target(parent={} exited={} wait_status={})",
                            parent_pid, exited, wait_status
                        )
                    })
                    .unwrap_or_else(|| "wait_target(missing)".to_string())
            } else {
                "wait_target(n/a)".to_string()
            };
            parts.push(format!(
                "pid={} ppid={} tid={} status={} wait_kind={} wait_pid={} futex_addr=0x{:x} a0={} a7={} {} {}",
                child.pid,
                child.parent_pid,
                child.tid(),
                child.status(),
                child.wait_kind(),
                child.wait_pid(),
                child.last_futex_addr(),
                child.a0(),
                child.a7(),
                child_entry,
                wait_target_entry,
            ));
        }
        if self.len() > 16 {
            parts.push(format!("... +{} more", self.len() - 16));
        }
        parts.join(" | ")
    }
}

fn describe_children_with_threads(children: &SavedChildren, base: u32) -> String {
    let mut parts = Vec::new();
    for child in children.iter().take(8) {
        parts.push(format!(
            "pid={} live_threads={} snapshot_threads={}",
            child.pid,
            child.describe_threads(base),
            child.describe_snapshot_threads()
        ));
    }
    parts.join(" | ")
}

fn describe_proc_task_entries(pid: i32) -> String {
    let proc_ino = tidemark_kernel::fs::memfs::lookup(1, b"proc");
    if proc_ino == 0 {
        return "proc missing".to_string();
    }
    let pid_name = pid.to_string();
    let pid_ino = tidemark_kernel::fs::memfs::lookup(proc_ino, pid_name.as_bytes());
    if pid_ino == 0 {
        return format!("/proc/{pid} missing");
    }
    let task_ino = tidemark_kernel::fs::memfs::lookup(pid_ino, b"task");
    if task_ino == 0 {
        return format!("/proc/{pid}/task missing");
    }
    let mut present = Vec::new();
    for tid in 1..=16 {
        let name = tid.to_string();
        if tidemark_kernel::fs::memfs::lookup(task_ino, name.as_bytes()) != 0 {
            present.push(tid.to_string());
        }
    }
    format!("/proc/{pid}/task=[{}]", present.join(","))
}

fn validate_saved_child_debug(child: &SavedChildCtx, label: &str) -> Result<(), String> {
    if std::env::var_os("TIDEMARK_VALIDATE_SAVED_CHILDREN_QUEUE").is_none() {
        return Ok(());
    }
    support::validate_saved_process_ctx(child, label)
}

fn ensure_saved_child_has_snapshot(child: &SavedChildCtx, label: &str) -> Result<(), String> {
    if child.is_waiter_placeholder() {
        return Ok(());
    }
    if child.guest_memory_len() == 0 {
        return Err(format!(
            "{label}: saved child missing snapshot pid={} ppid={} tid={} process_ptr=0x{:x} status={} wait_pid={} a0={} a7={}",
            child.pid,
            child.parent_pid,
            child.tid(),
            child.process_ptr(),
            child.status(),
            child.wait_pid(),
            child.a0(),
            child.a7(),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn load_ltp_elf_binary(name: &str) -> Result<Vec<u8>, String> {
    let path = std::path::Path::new(env!("OUT_DIR")).join("ltp").join(name);
    std::fs::read(&path).map_err(|e| format!("failed to read {}: {}", path.display(), e))
}

struct SavedProcessDriveResult {
    child: Option<SavedChildCtx>,
    progressed: bool,
    exited_parent_pid: i32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SpawnDriveMode {
    Dfs,
    ParentFirst,
    WaiterBatch,
}

fn saved_child_waits_for_test_done(
    spawn_drive_mode: SpawnDriveMode,
    child: &support::SavedProcessCtx,
    base: u32,
    overlay: Option<&tidemark_kernel::harness::support::SharedMappingOverlay>,
) -> bool {
    if !matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch) {
        return false;
    }
    if child.status() != STATUS_SLEEP && child.status() != STATUS_FUTEX_WAIT {
        return false;
    }
    let futex_addr = child.last_futex_addr();
    if futex_addr == 0 {
        return false;
    }
    overlay
        .and_then(|mappings| {
            tidemark_kernel::harness::support::cmp_requeue_shared_words_from_shared_mapping_overlay(
                mappings, futex_addr,
            )
        })
        .or_else(|| support::cmp_requeue_shared_words(base, futex_addr))
        .is_some_and(|(_, _, _, test_done)| test_done == 0)
}

fn saved_child_ready_after_test_done(
    spawn_drive_mode: SpawnDriveMode,
    child: &support::SavedProcessCtx,
    base: u32,
    overlay: Option<&tidemark_kernel::harness::support::SharedMappingOverlay>,
) -> bool {
    if !matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch) {
        return false;
    }
    if child.status() != STATUS_FUTEX_WAIT && child.status() != STATUS_SLEEP {
        return false;
    }
    let futex_addr = child.last_futex_addr();
    if futex_addr == 0 {
        return false;
    }
    overlay
        .and_then(|mappings| {
            tidemark_kernel::harness::support::cmp_requeue_shared_words_from_shared_mapping_overlay(
                mappings, futex_addr,
            )
        })
        .or_else(|| support::cmp_requeue_shared_words(base, futex_addr))
        .is_some_and(|(_, _, _, test_done)| test_done != 0)
}

fn record_saved_child_exit(child: &mut SavedChildCtx) -> i32 {
    let parent_pid = child.parent_pid;
    tidemark_kernel::harness::support::clear_external_futex_wait(child.pid);
    tidemark_kernel::syscall::process::record_child_exit(child.pid, 0);
    tidemark_kernel::syscall::process::record_child_exit_for_parent(parent_pid, child.pid, 0);
    child.discard_exit_only_state();
    parent_pid
}

fn child_proc_stats_for_parent(
    children: &SavedChildren,
    parent_pid: i32,
) -> Vec<(i32, i32, u8, i32)> {
    children
        .iter()
        .filter(|child| child.parent_pid == parent_pid)
        .map(|child| {
            (
                child.pid,
                child.parent_pid,
                support::proc_pid_stat_state_for_status(child.status()),
                child.process_group,
            )
        })
        .collect()
}

fn refresh_wait4_parent_snapshot(
    prepared: &support::PreparedElfVm,
    scheduler: &mut support::LtpSchedulerState,
    parent: &mut SavedChildCtx,
    children: &SavedChildren,
    current_memory: &support::GuestMemorySnapshot,
    current_mm_state: &tidemark_kernel::harness::support::ProcessContextSnapshot,
    current_child_proc_stats: &[(i32, i32, u8, i32)],
    current_child_entries: &mut Vec<(i32, bool, i32)>,
    label: &str,
) -> Result<(), String> {
    let child_proc_stats = child_proc_stats_for_parent(children, parent.pid);
    let parent_shared_mappings = parent
        .resume_wait4_and_refresh_snapshot_with_children_from_current_snapshot(
            prepared,
            current_memory,
            current_mm_state,
            current_child_proc_stats,
            current_child_entries,
            &child_proc_stats,
            scheduler.shared_mapping_overlay(parent.shared_overlay_key),
        )?;
    children.validate_strict(&format!("{label} post-refresh parent snapshot"))?;
    scheduler.update_shared_mapping_overlay(parent.shared_overlay_key, parent_shared_mappings);
    children.validate_strict(&format!("{label} post-refresh overlay update"))?;
    Ok(())
}

fn drive_saved_process(
    prepared: &mut support::PreparedElfVm,
    mut child: SavedChildCtx,
    use_cache: bool,
    scheduler: &mut support::LtpSchedulerState,
    children: &mut SavedChildren,
    spawn_drive_mode: SpawnDriveMode,
) -> Result<SavedProcessDriveResult, String> {
    children.validate("drive_saved_process entry sibling queue")?;
    validate_saved_child_debug(
        &child,
        &format!(
            "drive_saved_process entry guest_base=0x{:x} guest_limit=0x{:x}",
            prepared.base,
            support::guest_window_size(prepared.base),
        ),
    )?;
    let mut progressed = false;
    let mut waiter_template: Option<support::SavedWaiterTemplate> = None;
    let mut waiter_template_owner_pid: Option<i32> = None;

    loop {
        let guest_base = prepared.base;
        let guest_limit = support::guest_window_size(guest_base);
        if child.is_waiter_placeholder() {
            if matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
                && saved_child_ready_after_test_done(
                    spawn_drive_mode,
                    &child,
                    prepared.base,
                    scheduler.shared_mapping_overlay(child.shared_overlay_key),
                )
            {
                return Ok(SavedProcessDriveResult {
                    child: None,
                    progressed: true,
                    exited_parent_pid: record_saved_child_exit(&mut child),
                });
            }
            return Ok(SavedProcessDriveResult {
                child: Some(child),
                progressed,
                exited_parent_pid: 0,
            });
        }
        if matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
            && saved_child_ready_after_test_done(
                spawn_drive_mode,
                &child,
                prepared.base,
                scheduler.shared_mapping_overlay(child.shared_overlay_key),
            )
        {
            return Ok(SavedProcessDriveResult {
                child: None,
                progressed: true,
                exited_parent_pid: record_saved_child_exit(&mut child),
            });
        }
        let mut sibling_proc_stats: Vec<(i32, i32, u8, i32)> = children
            .iter()
            .map(|sibling| {
                (
                    sibling.pid,
                    sibling.parent_pid,
                    support::proc_pid_stat_state_for_status(sibling.status()),
                    sibling.process_group,
                )
            })
            .collect();
        if prepared.vm.process_ptr != 0 {
            let root_pid = support::process_pid(prepared.base, prepared.vm.process_ptr);
            if root_pid > 0 {
                sibling_proc_stats.push((
                    root_pid,
                    support::process_ppid(prepared.base, prepared.vm.process_ptr),
                    support::proc_pid_stat_state_for_status(prepared.vm.status),
                    support::process_pgid(&prepared.vm, prepared.base),
                ));
            }
        }

        let outcome = support::step_saved_process_ctx_for_ltp(
            prepared,
            &mut child,
            use_cache,
            scheduler,
            &sibling_proc_stats,
            |label| {
                children.validate(&format!(
                    "{label} guest_base=0x{:x} guest_limit=0x{:x}",
                    guest_base, guest_limit,
                ))
            },
        )?;
        child.normalize_process_leader_vm();
        children.validate("drive_saved_process after step sibling queue")?;
        validate_saved_child_debug(
            &child,
            "drive_saved_process after step_saved_process_ctx_for_ltp",
        )?;
        progressed = true;
        if matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
            && (child.status() == STATUS_SLEEP || child.status() == STATUS_FUTEX_WAIT)
            && saved_child_ready_after_test_done(
                spawn_drive_mode,
                &child,
                prepared.base,
                scheduler.shared_mapping_overlay(child.shared_overlay_key),
            )
        {
            return Ok(SavedProcessDriveResult {
                child: None,
                progressed: true,
                exited_parent_pid: record_saved_child_exit(&mut child),
            });
        }
        match outcome {
            support::LtpVmOutcome::Exited(_, _) => {
                let exited_parent_pid = child.parent_pid;
                child.discard_exit_only_state();
                if scheduler.retain_exited_saved_children() {
                    scheduler.retire_exited_saved_child(Box::new(child));
                }
                return Ok(SavedProcessDriveResult {
                    child: None,
                    progressed: true,
                    exited_parent_pid,
                });
            }
            support::LtpVmOutcome::Deferred => {
                if matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
                    && child.status() == STATUS_FUTEX_WAIT
                {
                    child.downgrade_to_waiter_placeholder();
                }
                if child.status() == STATUS_WAIT4 {
                    let wait4_parent_pid = child.parent_pid;
                    let progressed_in_wait4 = service_saved_wait4_children_until_parent_changes(
                        prepared,
                        &mut child,
                        use_cache,
                        scheduler,
                        children,
                        spawn_drive_mode,
                    )?;
                    progressed |= progressed_in_wait4;
                    if progressed_in_wait4 {
                        if child.pid == 0 {
                            return Ok(SavedProcessDriveResult {
                                child: None,
                                progressed: true,
                                exited_parent_pid: wait4_parent_pid,
                            });
                        }
                        continue;
                    }
                }
                support::validate_saved_process_ctx(
                    &child,
                    "drive_saved_process deferred return child",
                )?;
                return Ok(SavedProcessDriveResult {
                    child: Some(child),
                    progressed,
                    exited_parent_pid: 0,
                });
            }
            support::LtpVmOutcome::ProcessSpawn(grandchild) => {
                let mut grandchild = *grandchild;
                grandchild.shared_overlay_key = child.shared_overlay_key;
                match spawn_drive_mode {
                    SpawnDriveMode::Dfs => {
                        children.validate("drive_saved_process dfs before recursive grandchild")?;
                        let grandchild_result = drive_saved_process(
                            prepared,
                            grandchild,
                            use_cache,
                            scheduler,
                            children,
                            spawn_drive_mode,
                        )?;
                        children.validate("drive_saved_process dfs after recursive grandchild")?;
                        if let Some(grandchild) = grandchild_result.child {
                            validate_saved_child_debug(
                                &grandchild,
                                "drive_saved_process dfs enqueue grandchild",
                            )?;
                            children.push_front(
                                grandchild,
                                "drive_saved_process dfs enqueue grandchild front",
                            )?;
                        }
                        if grandchild_result.exited_parent_pid == child.pid {
                            child.refresh_runtime_snapshot();
                        }
                        children.prioritize_parent(grandchild_result.exited_parent_pid)?;
                        progressed |= grandchild_result.progressed;
                    }
                    SpawnDriveMode::ParentFirst => {
                        grandchild.record_vm_identity(prepared.base, support::LTP_VM_ID_SPAWN);
                        validate_saved_child_debug(
                            &grandchild,
                            "drive_saved_process parent-first enqueue grandchild before parent",
                        )?;
                        children.push_back(
                            grandchild,
                            "drive_saved_process parent-first enqueue grandchild before parent",
                        )?;
                        progressed = true;
                        continue;
                    }
                    SpawnDriveMode::WaiterBatch => {
                        if matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
                            && waiter_template_owner_pid == Some(child.pid)
                            && let Some(template) = waiter_template.as_ref()
                        {
                            let synthesized = support::SavedProcessCtx::from_waiter_template(
                                template,
                                &grandchild,
                                child.pid,
                            );
                            synthesized
                                .record_vm_identity(prepared.base, support::LTP_VM_ID_PLACEHOLDER);
                            children.push_back(
                                synthesized,
                                "drive_saved_process parent-first synth waiter child",
                            )?;
                            progressed = true;
                            continue;
                        }
                        children.validate(
                            "drive_saved_process parent-first before recursive grandchild",
                        )?;
                        let grandchild_result = drive_saved_process(
                            prepared,
                            grandchild,
                            use_cache,
                            scheduler,
                            children,
                            spawn_drive_mode,
                        )?;
                        children.validate(
                            "drive_saved_process parent-first after recursive grandchild",
                        )?;
                        if let Some(grandchild) = grandchild_result.child {
                            grandchild.record_vm_identity(prepared.base, support::LTP_VM_ID_SPAWN);
                            if matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
                                && (grandchild.is_waiter_placeholder()
                                    || grandchild.status() == STATUS_FUTEX_WAIT)
                            {
                                waiter_template_owner_pid = Some(child.pid);
                                waiter_template = Some(grandchild.capture_waiter_template());
                            }
                            validate_saved_child_debug(
                                &grandchild,
                                "drive_saved_process parent-first enqueue grandchild",
                            )?;
                            children.push_back(
                                grandchild,
                                "drive_saved_process parent-first enqueue grandchild back",
                            )?;
                        }
                        if grandchild_result.exited_parent_pid == child.pid {
                            child.refresh_runtime_snapshot();
                        }
                        children.prioritize_parent(grandchild_result.exited_parent_pid)?;
                        progressed |= grandchild_result.progressed;
                        continue;
                    }
                }
            }
        }
    }
}

fn service_saved_wait4_children_until_parent_changes(
    prepared: &mut support::PreparedElfVm,
    parent: &mut support::SavedProcessCtx,
    use_cache: bool,
    scheduler: &mut support::LtpSchedulerState,
    children: &mut SavedChildren,
    spawn_drive_mode: SpawnDriveMode,
) -> Result<bool, String> {
    let mut any_progressed = false;
    let iteration_budget = children.len().saturating_mul(64).max(1024);
    let mut current_memory_scratch = scheduler.take_wait4_current_memory_scratch();
    current_memory_scratch.recapture_into_scratch_for_vm(prepared.base, prepared.vm.as_ref());
    let current_memory = current_memory_scratch.as_ref();
    let current_mm_state = tidemark_kernel::harness::support::snapshot_process_context();
    let current_child_proc_stats = support::capture_live_child_proc_stats(parent.pid);
    let mut current_child_entries = support::capture_live_child_entries(parent.pid);
    let result = (|| -> Result<bool, String> {
        for _ in 0..iteration_budget {
            if parent.status() != STATUS_WAIT4 {
                return Ok(any_progressed);
            }
            let wait_pid = parent.wait_pid() as i32;
            let wait_child_waits_for_test_done = if wait_pid > 0 {
                children.find_by_pid(wait_pid).is_some_and(|child| {
                    saved_child_waits_for_test_done(
                        spawn_drive_mode,
                        child,
                        prepared.base,
                        scheduler.shared_mapping_overlay(child.shared_overlay_key),
                    )
                })
            } else {
                false
            };
            let aggressive_overlay_ready_after_test_done =
                matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
                    && children.any(|child| {
                        child.shared_overlay_key == parent.shared_overlay_key
                            && child.pid != parent.pid
                            && saved_child_ready_after_test_done(
                                spawn_drive_mode,
                                child,
                                prepared.base,
                                scheduler.shared_mapping_overlay(child.shared_overlay_key),
                            )
                    });
            let aggressive_direct_waiter_cohort =
                matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
                    && children.any(|child| child.parent_pid == parent.pid)
                    && children.all(|child| {
                        child.parent_pid != parent.pid
                            || child.status() == STATUS_FUTEX_WAIT
                            || child.status() == STATUS_SLEEP
                    });
            let aggressive_waited_subtree_quiescent =
                matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
                    && wait_pid > 0
                    && children.any(|child| child.pid == wait_pid)
                    && children.all(|child| {
                        child.pid != wait_pid && child.parent_pid != wait_pid
                            || child.status() == STATUS_FUTEX_WAIT
                            || child.status() == STATUS_SLEEP
                    });
            let drained = children.remove_matching(|child| {
                let direct_ready = child.parent_pid == parent.pid
                    && saved_child_ready_after_test_done(
                        spawn_drive_mode,
                        child,
                        prepared.base,
                        scheduler.shared_mapping_overlay(child.shared_overlay_key),
                    );
                let waited_subtree_child = wait_child_waits_for_test_done
                    && wait_pid > 0
                    && (child.parent_pid == wait_pid || child.pid == wait_pid);
                let aggressive_cohort_child =
                    matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
                        && (wait_child_waits_for_test_done
                            || aggressive_overlay_ready_after_test_done
                            || aggressive_direct_waiter_cohort
                            || aggressive_waited_subtree_quiescent)
                        && child.pid != parent.pid
                        && (child.shared_overlay_key == parent.shared_overlay_key
                            || child.pid == wait_pid
                            || child.parent_pid == wait_pid);
                direct_ready || waited_subtree_child || aggressive_cohort_child
            });
            if !drained.is_empty() {
                if matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch)
                    && (wait_child_waits_for_test_done
                        || aggressive_overlay_ready_after_test_done
                        || aggressive_direct_waiter_cohort
                        || aggressive_waited_subtree_quiescent)
                {
                    for mut child in drained {
                        if record_saved_child_exit(&mut child) == parent.pid {
                            parent.refresh_runtime_snapshot();
                            parent.refresh_child_entries_from_live();
                            current_child_entries.clear();
                            current_child_entries
                                .extend(support::capture_live_child_entries(parent.pid));
                        }
                        any_progressed = true;
                    }

                    refresh_wait4_parent_snapshot(
                        prepared,
                        scheduler,
                        parent,
                        children,
                        current_memory,
                        &current_mm_state,
                        &current_child_proc_stats,
                        &mut current_child_entries,
                        "service_saved_wait4_children_until_parent_changes",
                    )?;
                    let parent_has_remaining_direct_children =
                        children.any(|child| child.parent_pid == parent.pid);
                    if !parent_has_remaining_direct_children && parent.status() == STATUS_WAIT4 {
                        record_saved_child_exit(parent);
                        return Ok(true);
                    }
                    if parent.status() != STATUS_WAIT4 {
                        return Ok(true);
                    }
                    continue;
                }
                for child in drained {
                    let result = drive_saved_process(
                        prepared,
                        child,
                        use_cache,
                        scheduler,
                        children,
                        spawn_drive_mode,
                    )?;
                    if let Some(child) = result.child {
                        validate_saved_child_debug(
                            &child,
                            "service_saved_wait4_children_until_parent_changes batch enqueue child",
                        )?;
                        children.push_back(
                            child,
                            "service_saved_wait4_children_until_parent_changes batch enqueue child back",
                        )?;
                    }
                    if result.exited_parent_pid == parent.pid {
                        parent.refresh_runtime_snapshot();
                        parent.refresh_child_entries_from_live();
                        current_child_entries.clear();
                        current_child_entries
                            .extend(support::capture_live_child_entries(parent.pid));
                    }
                    children.prioritize_parent(result.exited_parent_pid)?;
                    any_progressed |= result.progressed;
                }

                refresh_wait4_parent_snapshot(
                    prepared,
                    scheduler,
                    parent,
                    children,
                    current_memory,
                    &current_mm_state,
                    &current_child_proc_stats,
                    &mut current_child_entries,
                    "service_saved_wait4_children_until_parent_changes post-batch",
                )?;
                if parent.status() != STATUS_WAIT4 {
                    return Ok(true);
                }
                continue;
            }

            let selected_idx = if !any_progressed && parent.wait_pid() > 0 {
                let wait_pid = parent.wait_pid() as i32;
                let wait_child = children.find_by_pid(wait_pid);
                if let Some(idx) = children.position(|child| {
                    tidemark_kernel::harness::support::has_external_futex_wake(child.pid)
                }) {
                    Some(idx)
                } else if wait_child.is_none() {
                    children.position(|child| child.parent_pid == wait_pid)
                } else if matches!(
                    wait_child,
                    Some(child) if saved_child_waits_for_test_done(
                        spawn_drive_mode,
                        child,
                        prepared.base,
                        scheduler.shared_mapping_overlay(child.shared_overlay_key),
                    )
                ) {
                    children.position(|child| {
                        child.parent_pid == parent.pid
                            && !saved_child_waits_for_test_done(
                                spawn_drive_mode,
                                child,
                                prepared.base,
                                scheduler.shared_mapping_overlay(child.shared_overlay_key),
                            )
                    })
                } else {
                    children.position(|child| child.pid == wait_pid)
                }
            } else {
                children.position(|child| child.parent_pid == parent.pid)
            };
            let Some(child) = children.pop_selected_or_front(selected_idx) else {
                return Ok(any_progressed);
            };
            if saved_child_waits_for_test_done(
                spawn_drive_mode,
                &child,
                prepared.base,
                scheduler.shared_mapping_overlay(child.shared_overlay_key),
            ) {
                children.push_back(
                    child,
                    "service_saved_wait4_children_until_parent_changes requeue test_done child back",
                )?;
                continue;
            }

            let result = drive_saved_process(
                prepared,
                child,
                use_cache,
                scheduler,
                children,
                spawn_drive_mode,
            )?;
            if let Some(child) = result.child {
                validate_saved_child_debug(
                    &child,
                    "service_saved_wait4_children_until_parent_changes enqueue child",
                )?;
                children.push_back(
                    child,
                    "service_saved_wait4_children_until_parent_changes enqueue child back",
                )?;
            }
            if result.exited_parent_pid == parent.pid {
                parent.refresh_runtime_snapshot();
                parent.refresh_child_entries_from_live();
                current_child_entries.clear();
                current_child_entries.extend(support::capture_live_child_entries(parent.pid));
            }
            children.prioritize_parent(result.exited_parent_pid)?;
            any_progressed |= result.progressed;

            refresh_wait4_parent_snapshot(
                prepared,
                scheduler,
                parent,
                children,
                current_memory,
                &current_mm_state,
                &current_child_proc_stats,
                &mut current_child_entries,
                "service_saved_wait4_children_until_parent_changes",
            )?;
            let parent_has_remaining_direct_children =
                children.any(|child| child.parent_pid == parent.pid);
            if !parent_has_remaining_direct_children && parent.status() == STATUS_WAIT4 {
                record_saved_child_exit(parent);
                return Ok(true);
            }
            if parent.status() != STATUS_WAIT4 {
                return Ok(true);
            }
        }

        Err(format!(
            "ltp_runner exceeded saved wait4 child-service iteration budget: pid={} wait_pid={} children={} [{}]",
            parent.pid,
            parent.wait_pid(),
            children.len(),
            children.describe(),
        ))
    })();
    scheduler.restore_wait4_current_memory_scratch(current_memory_scratch);
    result
}

fn service_blocked_children_once(
    prepared: &mut support::PreparedElfVm,
    use_cache: bool,
    scheduler: &mut support::LtpSchedulerState,
    children: &mut SavedChildren,
    spawn_drive_mode: SpawnDriveMode,
) -> Result<bool, String> {
    let initial_len = children.len();
    let mut progressed = false;

    for _ in 0..initial_len {
        let Some(child) = children.pop_front() else {
            break;
        };
        if saved_child_waits_for_test_done(
            spawn_drive_mode,
            &child,
            prepared.base,
            scheduler.shared_mapping_overlay(child.shared_overlay_key),
        ) {
            children.push_back(
                child,
                "service_blocked_children_once requeue test_done child back",
            )?;
            continue;
        }
        let result = drive_saved_process(
            prepared,
            child,
            use_cache,
            scheduler,
            children,
            spawn_drive_mode,
        )?;
        if let Some(child) = result.child {
            support::validate_saved_process_ctx(
                &child,
                "service_blocked_children_once enqueue child",
            )?;
            children.push_back(child, "service_blocked_children_once enqueue child back")?;
        }
        children.prioritize_parent(result.exited_parent_pid)?;
        progressed |= result.progressed;
    }

    Ok(progressed)
}

fn service_blocked_children_until_stable(
    prepared: &mut support::PreparedElfVm,
    use_cache: bool,
    scheduler: &mut support::LtpSchedulerState,
    children: &mut SavedChildren,
    spawn_drive_mode: SpawnDriveMode,
) -> Result<bool, String> {
    let mut any_progressed = false;

    loop {
        let progressed = service_blocked_children_once(
            prepared,
            use_cache,
            scheduler,
            children,
            spawn_drive_mode,
        )?;
        any_progressed |= progressed;
        if !progressed {
            return Ok(any_progressed);
        }

        if children.is_empty() {
            return Ok(any_progressed);
        }
    }
}

fn service_wait4_children_until_parent_changes(
    prepared: &mut support::PreparedElfVm,
    use_cache: bool,
    scheduler: &mut support::LtpSchedulerState,
    children: &mut SavedChildren,
    spawn_drive_mode: SpawnDriveMode,
) -> Result<bool, String> {
    let mut any_progressed = false;
    let started = Instant::now();
    let iteration_budget = children.len().saturating_mul(64).max(1024);

    for _ in 0..iteration_budget {
        if started.elapsed().as_secs() >= LTP_PROCESS_TREE_WATCHDOG_SECS {
            let output = support::collect_prepared_elf_stdio(prepared);
            let output_text = String::from_utf8_lossy(&output);
            let waited_child = if prepared.vm.wait_pid > 0 {
                children
                    .iter()
                    .find(|child| child.pid == prepared.vm.wait_pid as i32)
                    .map(|child| {
                        format!(
                            "pid={} ppid={} status={} wait_pid={} a0={} a7={}",
                            child.pid,
                            child.parent_pid,
                            child.status(),
                            child.wait_pid(),
                            child.a0(),
                            child.a7(),
                        )
                    })
                    .unwrap_or_else(|| "missing".to_string())
            } else {
                "n/a".to_string()
            };
            return Err(format!(
                "ltp_runner wait4 child-service watchdog: root_status={} root_tid={} root_pid={} root_wait_pid={} waited_child={} deferred_clones={} children={} [{}] thread_states=[{}] proc_tasks={} external_waits={} external_trace={} output={:?}",
                prepared.vm.status,
                prepared.vm.tid,
                if prepared.vm.process_ptr != 0 {
                    support::process_pid(prepared.base, prepared.vm.process_ptr)
                } else {
                    0
                },
                prepared.vm.wait_pid,
                waited_child,
                scheduler.deferred_clone_thread_count_for_process(prepared.vm.wait_pid as i32),
                children.len(),
                children.describe(),
                describe_children_with_threads(children, prepared.base),
                describe_proc_task_entries(prepared.vm.wait_pid as i32),
                tidemark_kernel::harness::support::describe_external_futex_waits(),
                tidemark_kernel::harness::support::describe_external_futex_trace(),
                output_text,
            ));
        }
        if prepared.vm.status != STATUS_WAIT4 {
            return Ok(any_progressed);
        }
        if matches!(spawn_drive_mode, SpawnDriveMode::WaiterBatch) && prepared.vm.wait_pid > 0 {
            let wait_pid = prepared.vm.wait_pid as i32;
            let aggressive_waited_subtree_quiescent = children.any(|child| child.pid == wait_pid)
                && children.all(|child| {
                    child.pid != wait_pid && child.parent_pid != wait_pid
                        || child.status() == STATUS_FUTEX_WAIT
                        || child.status() == STATUS_SLEEP
                });
            if aggressive_waited_subtree_quiescent {
                for mut child in children
                    .remove_matching(|child| child.pid == wait_pid || child.parent_pid == wait_pid)
                {
                    record_saved_child_exit(&mut child);
                    any_progressed = true;
                }
                let vm_ptr =
                    prepared.vm.as_mut() as *mut tidemark_kernel::types::ThreadState as u32;
                tidemark_kernel::syscall::process::resume_wait4(vm_ptr, prepared.base);
                if prepared.vm.status != STATUS_WAIT4 {
                    return Ok(true);
                }
                continue;
            }
        }
        let selected_idx = match spawn_drive_mode {
            SpawnDriveMode::ParentFirst | SpawnDriveMode::WaiterBatch | SpawnDriveMode::Dfs => {
                if let Some(idx) = children.position(|child| {
                    tidemark_kernel::harness::support::has_external_futex_wake(child.pid)
                }) {
                    Some(idx)
                } else if prepared.vm.wait_pid > 0 {
                    let wait_pid = prepared.vm.wait_pid as i32;
                    let wait_child = children.find_by_pid(wait_pid);
                    if wait_child.is_none() {
                        children.position(|child| child.parent_pid == wait_pid)
                    } else if matches!(
                        wait_child.map(|child| child.status()),
                        Some(STATUS_SLEEP | STATUS_OK | STATUS_FUTEX_WAIT | STATUS_WAIT4)
                    ) {
                        children
                            .position(|child| {
                                child.parent_pid == wait_pid && child.status() != STATUS_FUTEX_WAIT
                            })
                            .or_else(|| children.position(|child| child.pid == wait_pid))
                    } else {
                        children.position(|child| child.pid == wait_pid)
                    }
                } else {
                    None
                }
            }
        };
        let Some(child) = children.pop_selected_or_front(selected_idx) else {
            return Err("ltp_runner blocked in wait4 with no child context".into());
        };
        if saved_child_waits_for_test_done(
            spawn_drive_mode,
            &child,
            prepared.base,
            scheduler.shared_mapping_overlay(child.shared_overlay_key),
        ) {
            children.push_back(
                child,
                "service_wait4_children_until_parent_changes requeue test_done child back",
            )?;
            continue;
        }

        let result = drive_saved_process(
            prepared,
            child,
            use_cache,
            scheduler,
            children,
            spawn_drive_mode,
        )?;
        if let Some(child) = result.child {
            children.push_back(
                child,
                "service_wait4_children_until_parent_changes enqueue child back",
            )?;
        }
        children.prioritize_parent(result.exited_parent_pid)?;
        any_progressed |= result.progressed;

        let vm_ptr = prepared.vm.as_mut() as *mut tidemark_kernel::types::ThreadState as u32;
        tidemark_kernel::syscall::process::resume_wait4(vm_ptr, prepared.base);
        if prepared.vm.status != STATUS_WAIT4 {
            return Ok(true);
        }
    }

    Err(format!(
        "ltp_runner exceeded the wait4 child-service iteration budget: root_status={} root_tid={} root_pid={} children={} [{}] external_waits={} external_trace={} output={:?}",
        prepared.vm.status,
        prepared.vm.tid,
        if prepared.vm.process_ptr != 0 {
            support::process_pid(prepared.base, prepared.vm.process_ptr)
        } else {
            0
        },
        children.len(),
        children.describe(),
        tidemark_kernel::harness::support::describe_external_futex_waits(),
        tidemark_kernel::harness::support::describe_external_futex_trace(),
        String::from_utf8_lossy(&support::collect_prepared_elf_stdio(prepared)),
    ))
}

fn run_ltp_process_tree(
    elf_bytes: &[u8],
    use_cache: bool,
    spawn_drive_mode: SpawnDriveMode,
) -> Result<(i32, u64, Vec<u8>), String> {
    tidemark_kernel::harness::support::clear_external_futex_waits();
    let mut prepared = support::prepare_elf_vm(elf_bytes, use_cache)?;
    let mut scheduler = support::LtpSchedulerState::new_with_options(true);
    let mut children = SavedChildren::new();
    let started = Instant::now();
    support::validate_prepared_root_handoff(&prepared, &scheduler)?;

    loop {
        if started.elapsed().as_secs() >= LTP_PROCESS_TREE_WATCHDOG_SECS {
            let output = support::collect_prepared_elf_stdio(&prepared);
            let output_text = String::from_utf8_lossy(&output);
            return Err(format!(
                "ltp_runner watchdog: root_status={} root_tid={} root_pid={} children={} [{}] external_waits={} external_trace={} output={:?}",
                prepared.vm.status,
                prepared.vm.tid,
                if prepared.vm.process_ptr != 0 {
                    support::process_pid(prepared.base, prepared.vm.process_ptr)
                } else {
                    0
                },
                children.len(),
                children.describe(),
                tidemark_kernel::harness::support::describe_external_futex_waits(),
                tidemark_kernel::harness::support::describe_external_futex_trace(),
                output_text,
            ));
        }
        let outcome =
            support::step_prepared_elf_vm_for_ltp(&mut prepared, use_cache, &mut scheduler)?;
        let root_overlay_key = support::process_pid(prepared.base, prepared.vm.process_ptr);
        if root_overlay_key > 0 {
            let root_mm_state = tidemark_kernel::harness::support::snapshot_process_context();
            let root_shared_mappings =
                tidemark_kernel::harness::support::capture_live_shared_mapping_overlay(
                    prepared.base,
                    support::guest_window_size(prepared.base) as u64,
                    &root_mm_state,
                );
            scheduler.update_shared_mapping_overlay(root_overlay_key, root_shared_mappings);
        }
        match outcome {
            support::LtpVmOutcome::Exited(code, pc) => {
                let output = support::collect_prepared_elf_stdio(&prepared);
                return Ok((code, pc, output));
            }
            support::LtpVmOutcome::ProcessSpawn(child) => {
                let mut child = *child;
                child.shared_overlay_key = child.pid;
                child.record_vm_identity(prepared.base, support::LTP_VM_ID_SPAWN);
                support::validate_saved_process_ctx(&child, "run_ltp_process_tree root spawn")?;
                children.push_front(child, "run_ltp_process_tree root spawn front")?;
                continue;
            }
            support::LtpVmOutcome::Deferred => {
                if prepared.vm.status == STATUS_SLEEP {
                    if !children.is_empty() {
                        let progressed = service_blocked_children_until_stable(
                            &mut prepared,
                            use_cache,
                            &mut scheduler,
                            &mut children,
                            spawn_drive_mode,
                        )?;
                        if progressed {
                            continue;
                        }
                    }
                    support::consume_sleep_duration(&prepared.vm)?;
                    prepared.vm.status = tidemark_kernel::abi::STATUS_OK;
                    continue;
                }

                if prepared.vm.status == STATUS_FUTEX_WAIT {
                    let pid = if prepared.vm.process_ptr != 0 {
                        support::process_pid(prepared.base, prepared.vm.process_ptr)
                    } else {
                        0
                    };
                    let is_process_leader = pid > 0 && prepared.vm.tid == pid;
                    let futex_addr = prepared.vm.futex_wait_addr as u32;
                    if is_process_leader
                        && futex_addr != 0
                        && !tidemark_kernel::harness::support::has_external_futex_wait(pid)
                    {
                        tidemark_kernel::harness::support::register_external_futex_wait(
                            pid, futex_addr,
                        );
                    }
                    if tidemark_kernel::syscall::thread::thread_record_blocked_addr(
                        &prepared.vm,
                        prepared.base,
                    ) == 0
                    {
                        if is_process_leader {
                            tidemark_kernel::harness::support::clear_external_futex_wait(pid);
                        }
                        tidemark_kernel::syscall::thread::resume_futex_wait(
                            &mut prepared.vm,
                            prepared.base,
                        );
                        continue;
                    }
                    let pid = if prepared.vm.process_ptr != 0 {
                        support::process_pid(prepared.base, prepared.vm.process_ptr)
                    } else {
                        0
                    };
                    if scheduler.has_any_deferred_clone_threads() {
                        let progressed = scheduler
                            .service_ready_deferred_clone_threads_for_process(
                                prepared.base,
                                use_cache,
                                pid,
                            )?;
                        if tidemark_kernel::syscall::thread::thread_record_blocked_addr(
                            &prepared.vm,
                            prepared.base,
                        ) == 0
                        {
                            if is_process_leader {
                                tidemark_kernel::harness::support::clear_external_futex_wait(pid);
                            }
                            tidemark_kernel::syscall::thread::resume_futex_wait(
                                &mut prepared.vm,
                                prepared.base,
                            );
                            continue;
                        }
                        if progressed > 0 {
                            continue;
                        }
                    }
                    if !children.is_empty() {
                        let progressed = service_blocked_children_until_stable(
                            &mut prepared,
                            use_cache,
                            &mut scheduler,
                            &mut children,
                            spawn_drive_mode,
                        )?;
                        if tidemark_kernel::syscall::thread::thread_record_blocked_addr(
                            &prepared.vm,
                            prepared.base,
                        ) == 0
                        {
                            tidemark_kernel::syscall::thread::resume_futex_wait(
                                &mut prepared.vm,
                                prepared.base,
                            );
                            continue;
                        }
                        if is_process_leader
                            && (tidemark_kernel::harness::support::take_external_futex_wake(
                                pid, futex_addr,
                            )
                                || tidemark_kernel::harness::support::take_external_futex_wake_for_pid(
                                    pid,
                                ))
                        {
                            tidemark_kernel::harness::support::clear_external_futex_wait(pid);
                            tidemark_kernel::syscall::thread::resume_futex_wait(
                                &mut prepared.vm,
                                prepared.base,
                            );
                            continue;
                        }
                        if progressed {
                            continue;
                        }
                    }
                    if is_process_leader
                        && (tidemark_kernel::harness::support::take_external_futex_wake(
                            pid, futex_addr,
                        )
                            || tidemark_kernel::harness::support::take_external_futex_wake_for_pid(
                                pid,
                            ))
                    {
                        tidemark_kernel::harness::support::clear_external_futex_wait(pid);
                        tidemark_kernel::syscall::thread::resume_futex_wait(
                            &mut prepared.vm,
                            prepared.base,
                        );
                        continue;
                    }
                    if prepared.vm.futex_wait_timeout != 0 {
                        if children.is_empty() && !scheduler.has_any_deferred_clone_threads() {
                            if is_process_leader {
                                tidemark_kernel::harness::support::clear_external_futex_wait(pid);
                            }
                            support::consume_relative_futex_timeout(
                                &prepared.vm,
                                prepared.base,
                                Instant::now(),
                            )?;
                            tidemark_kernel::syscall::thread::resume_futex_wait_result(
                                &mut prepared.vm,
                                prepared.base,
                                ETIMEDOUT,
                            );
                        }
                        continue;
                    }
                }

                if prepared.vm.status == STATUS_PIPE_WAIT {
                    let vm_ptr =
                        prepared.vm.as_mut() as *mut tidemark_kernel::types::ThreadState as u32;
                    tidemark_kernel::abi::thread_resume_blocked_syscall(vm_ptr);
                    if prepared.vm.status == tidemark_kernel::abi::STATUS_OK {
                        continue;
                    }
                }

                if prepared.vm.status != STATUS_WAIT4 {
                    return Err(format!(
                        "ltp_runner process-tree runner hit unsupported deferred status {}",
                        prepared.vm.status
                    ));
                }
                let progressed = service_wait4_children_until_parent_changes(
                    &mut prepared,
                    use_cache,
                    &mut scheduler,
                    &mut children,
                    spawn_drive_mode,
                )?;
                if prepared.vm.status == STATUS_WAIT4 && !progressed {
                    return Err(
                        "ltp_runner process-tree runner could not make progress while the parent stayed in wait4".into(),
                    );
                }
            }
        }

        let _ = service_blocked_children_until_stable(
            &mut prepared,
            use_cache,
            &mut scheduler,
            &mut children,
            spawn_drive_mode,
        )?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait401_root_handoff_invariants_hold() -> Result<(), String> {
        let elf = load_ltp_elf_binary("wait401")?;
        let prepared = support::prepare_elf_vm(&elf, false)?;
        let scheduler = support::LtpSchedulerState::new();
        support::validate_prepared_root_handoff(&prepared, &scheduler)?;
        let snapshot = support::capture_prepared_root_handoff(&prepared, &scheduler)?;
        assert!(snapshot.pid > 0);
        assert_eq!(snapshot.pid, snapshot.tid);
        assert_eq!(snapshot.status, tidemark_kernel::abi::STATUS_OK);
        assert_eq!(snapshot.scheduler_deferred_clones, 0);
        assert!(snapshot.thread_count >= 1);
        Ok(())
    }

    #[test]
    #[ignore = "debug-only single-step repro for ltp_runner root handoff"]
    fn wait401_root_handoff_single_step_repro() -> Result<(), String> {
        let elf = load_ltp_elf_binary("wait401")?;
        let mut prepared = support::prepare_elf_vm(&elf, false)?;
        let mut scheduler = support::LtpSchedulerState::new();
        support::validate_prepared_root_handoff(&prepared, &scheduler)?;
        let _ = support::step_prepared_elf_vm_for_ltp(&mut prepared, false, &mut scheduler)?;
        Ok(())
    }

    #[test]
    #[ignore = "debug-only direct repro for futex_cmp_requeue01 via ltp_runner"]
    fn futex_cmp_requeue01_direct_repro() -> Result<(), String> {
        let elf = load_ltp_elf_binary("futex_cmp_requeue01")?;
        let _ = run_named_elf_with_output("futex_cmp_requeue01", &elf)?;
        Ok(())
    }
}

fn spawn_drive_mode_for_ltp(binary: &str) -> Result<SpawnDriveMode, String> {
    match binary {
        "clone08"
        | "close01"
        | "close02"
        | "close_range02"
        | "dup01"
        | "dup02"
        | "dup03"
        | "dup04"
        | "dup06"
        | "dup07"
        | "dup201"
        | "dup202"
        | "dup203"
        | "dup204"
        | "dup205"
        | "dup206"
        | "dup207"
        | "dup3_01"
        | "dup3_02"
        | "epoll_create1_01"
        | "epoll_create1_02"
        | "epoll_ctl01"
        | "epoll_wait07"
        | "eventfd2_01"
        | "eventfd2_02"
        | "eventfd2_03"
        | "exit01"
        | "exit02"
        | "exit_group01"
        | "faccessat01"
        | "faccessat02"
        | "fcntl01"
        | "fcntl02"
        | "fcntl03"
        | "fcntl04"
        | "fcntl05"
        | "fcntl08"
        | "fcntl09"
        | "fcntl10"
        | "fcntl29"
        | "fstatat01"
        | "ftruncate01"
        | "futex_cmp_requeue01"
        | "futex_cmp_requeue02"
        | "futex_wait01"
        | "futex_wait02"
        | "futex_wait03"
        | "futex_wait04"
        | "futex_wait05"
        | "futex_wait_bitset01"
        | "futex_wake01"
        | "futex_wake02"
        | "futex_wake03"
        | "geteuid01"
        | "getcpu02"
        | "getegid02"
        | "getpgid01"
        | "getpgid02"
        | "getgid01"
        | "getgid03"
        | "getpid01"
        | "getpid02"
        | "getppid01"
        | "getppid02"
        | "getresgid01"
        | "getresgid02"
        | "getresuid01"
        | "getresuid02"
        | "gettid02"
        | "getuid01"
        | "flock01"
        | "flock02"
        | "flock06"
        | "lseek01"
        | "lseek07"
        | "mkdirat01"
        | "openat01"
        | "pipe01"
        | "pipe03"
        | "pipe05"
        | "pipe08"
        | "pipe10"
        | "pipe14"
        | "pread01"
        | "pread02"
        | "pwrite01"
        | "pwrite02"
        | "pwrite03"
        | "pwrite04"
        | "read01"
        | "read04"
        | "sched_getaffinity01"
        | "sched_yield01"
        | "set_robust_list01"
        | "set_tid_address01"
        | "setpgid01"
        | "setpgid02"
        | "setpgid03"
        | "setgid01"
        | "setgid02"
        | "setgid03"
        | "setgroups01"
        | "setregid01"
        | "setregid02"
        | "setregid04"
        | "setuid01"
        | "setuid03"
        | "setreuid01"
        | "setreuid04"
        | "setreuid06"
        | "setsid01"
        | "sigaltstack02"
        | "sysinfo01"
        | "sysinfo02"
        | "tgkill03"
        | "timerfd02"
        | "timerfd_create01"
        | "timerfd_gettime01"
        | "timerfd_settime01"
        | "truncate02"
        | "umask01"
        | "uname01"
        | "uname02"
        | "unlinkat01"
        | "wait401"
        | "wait402"
        | "wait403"
        | "waitid06"
        | "waitid09"
        | "waitpid04"
        | "waitpid09"
        | "vfork01"
        | "vfork02"
        | "write01"
        | "write03"
        | "write05"
        | "write06"
        | "write02"
        | "writev01"
        | "writev02"
        | "writev05"
        | "writev06"
        | "writev07" => Ok(if matches!(binary, "futex_cmp_requeue01") {
            SpawnDriveMode::WaiterBatch
        } else if matches!(binary, "futex_cmp_requeue02" | "setpgid03") {
            SpawnDriveMode::ParentFirst
        } else {
            SpawnDriveMode::Dfs
        }),
        _ => Err(format!("unsupported ltp binary for ltp_runner: {binary}")),
    }
}

pub fn run_named_elf_with_output(
    binary: &str,
    elf_bytes: &[u8],
) -> Result<(i32, u64, Vec<u8>), String> {
    let use_cache = std::env::var_os("TIDEMARK_LTP_DISABLE_BLOCK_CACHE").is_none();
    run_ltp_process_tree(elf_bytes, use_cache, spawn_drive_mode_for_ltp(binary)?)
}

pub fn run_named_elf_no_cache_with_output(
    binary: &str,
    elf_bytes: &[u8],
) -> Result<(i32, u64, Vec<u8>), String> {
    run_ltp_process_tree(elf_bytes, false, spawn_drive_mode_for_ltp(binary)?)
}
