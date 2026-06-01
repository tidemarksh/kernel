use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const TESTCASES_ROOT: &str = "vendor/ltp/testcases";
const UNSUPPORTED_PATH: &str = "tests/fixtures/ltp/unsupported.txt";
const CONFORM_PATH: &str = "tests/fixtures/ltp/conform.txt";
const EQUIVALENT_PATH: &str = "tests/fixtures/ltp/equivalent.txt";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Primitive {
    ProcessLifecycle,
    Wait4Reap,
    ProcTaskVisibility,
    ThreadSleepVisibility,
    PthreadThreadFanout,
    PrivateFutexFanout,
    SharedProcessFutexFanout,
    CloneFallback,
    SocketLoopbackConnect,
    LegacySocketcallAbi,
    TimerfdBlockedDeadline,
    TimeNamespace,
    CancelOnSet,
}

impl Primitive {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessLifecycle => "process_lifecycle",
            Self::Wait4Reap => "wait4_reap",
            Self::ProcTaskVisibility => "proc_task_visibility",
            Self::ThreadSleepVisibility => "thread_sleep_visibility",
            Self::PthreadThreadFanout => "pthread_thread_fanout",
            Self::PrivateFutexFanout => "private_futex_fanout",
            Self::SharedProcessFutexFanout => "shared_process_futex_fanout",
            Self::CloneFallback => "clone_fallback",
            Self::SocketLoopbackConnect => "socket_loopback_connect",
            Self::LegacySocketcallAbi => "legacy_socketcall_abi",
            Self::TimerfdBlockedDeadline => "timerfd_blocked_deadline",
            Self::TimeNamespace => "time_namespace",
            Self::CancelOnSet => "cancel_on_set",
        }
    }

    fn is_wrapper(self) -> bool {
        matches!(
            self,
            Self::ProcessLifecycle | Self::Wait4Reap | Self::CloneFallback
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CaseStatus {
    Conform,
    Equivalent,
    Unsupported,
    Unknown,
}

impl CaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conform => "conform",
            Self::Equivalent => "equivalent",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }
}

pub struct Report {
    pub case_name: String,
    pub source_path: PathBuf,
    pub status: CaseStatus,
    pub required: BTreeSet<Primitive>,
    pub blocked: BTreeSet<Primitive>,
    pub reason: Option<String>,
}

pub fn resolve_kernel_root(kernel_root: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(root) = kernel_root {
        return Ok(root.to_path_buf());
    }

    let cwd =
        std::env::current_dir().map_err(|err| format!("failed to read current_dir: {err}"))?;
    if let Some(root) = std::env::var_os("TIDEMARK_KERNEL_ROOT") {
        let root = PathBuf::from(root);
        if root.join("tests/fixtures/ltp").is_dir() && root.join("vendor/ltp/testcases").is_dir() {
            return Ok(root);
        }
        if root.join("fixtures/ltp").is_dir() {
            if let Some(parent) = root.parent() {
                if parent.join("vendor/ltp/testcases").is_dir() {
                    return Ok(parent.to_path_buf());
                }
            }
        }
    }
    if cwd.join("tests/fixtures/ltp").is_dir() && cwd.join("vendor/ltp/testcases").is_dir() {
        return Ok(cwd);
    }
    if cwd.join("kernel/tests/fixtures/ltp").is_dir()
        && cwd.join("kernel/vendor/ltp/testcases").is_dir()
    {
        return Ok(cwd.join("kernel"));
    }

    let env_root = std::env::var("TIDEMARK_KERNEL_ROOT").ok();
    Err(format!(
        "failed to resolve kernel root from cwd {}; TIDEMARK_KERNEL_ROOT={:?}; pass --kernel-root explicitly",
        cwd.display(),
        env_root,
    ))
}

pub fn build_report(kernel_root: &Path, case_name: &str) -> Result<Report, String> {
    let source_path = find_case_source(kernel_root, case_name)?;
    let source_bundle = load_source_bundle(&source_path)?;
    let required = extract_required_primitives(&source_bundle);
    let (status, reason) = read_case_status(kernel_root, case_name)?;
    let blocked = match status {
        CaseStatus::Unsupported | CaseStatus::Equivalent => reason
            .as_deref()
            .map(extract_blocked_primitives)
            .unwrap_or_default(),
        CaseStatus::Conform | CaseStatus::Unknown => BTreeSet::new(),
    };

    Ok(Report {
        case_name: case_name.to_string(),
        source_path,
        status,
        required,
        blocked,
        reason,
    })
}

pub fn print_report(report: &Report) {
    println!("case: {}", report.case_name);
    println!("source: {}", report.source_path.display());
    println!("status: {}", report.status.as_str());
    println!("required_primitives:");
    if report.required.is_empty() {
        println!("  - <none>");
    } else {
        for primitive in &report.required {
            println!("  - {}", primitive.as_str());
        }
    }
    println!("blocked_primitives:");
    if report.blocked.is_empty() {
        println!("  - <none>");
    } else {
        for primitive in &report.blocked {
            println!("  - {}", primitive.as_str());
        }
    }
    let primary = primary_blocked_primitives(report);
    println!("primary_blocked_primitives:");
    if primary.is_empty() {
        println!("  - <none>");
    } else {
        for primitive in &primary {
            println!("  - {}", primitive.as_str());
        }
    }
    match &report.reason {
        Some(reason) => println!("reason: {}", reason.trim()),
        None => println!("reason: <none>"),
    }
    println!(
        "rerun: {}",
        if rerun_allowed(report) {
            "allowed"
        } else {
            "blocked"
        }
    );
}

pub fn rerun_allowed(report: &Report) -> bool {
    !matches!(report.status, CaseStatus::Unsupported) || report.blocked.is_empty()
}

pub fn primary_blocked_primitives(report: &Report) -> BTreeSet<Primitive> {
    let direct: BTreeSet<Primitive> = report
        .blocked
        .iter()
        .copied()
        .filter(|primitive| !primitive.is_wrapper())
        .collect();
    if direct.is_empty() {
        report.blocked.clone()
    } else {
        direct
    }
}

pub fn implemented_case_reports(kernel_root: &Path) -> Result<Vec<Report>, String> {
    let mut cases = BTreeSet::new();
    collect_cases_from_manifest(&kernel_root.join(CONFORM_PATH), &mut cases)?;
    collect_cases_from_manifest(&kernel_root.join(EQUIVALENT_PATH), &mut cases)?;
    collect_implemented_unsupported_cases(&kernel_root.join(UNSUPPORTED_PATH), &mut cases)?;

    let mut reports = Vec::with_capacity(cases.len());
    for case_name in cases {
        reports.push(build_report(kernel_root, &case_name)?);
    }
    Ok(reports)
}

pub fn print_batch_report(reports: &[Report]) {
    let total = reports.len();
    let allowed = reports
        .iter()
        .filter(|report| rerun_allowed(report))
        .count();
    let blocked = total.saturating_sub(allowed);

    let mut primary_clusters = BTreeSet::new();
    for report in reports.iter().filter(|report| !rerun_allowed(report)) {
        for primitive in primary_blocked_primitives(report) {
            primary_clusters.insert(primitive);
        }
    }

    println!("implemented_cases: {total}");
    println!("rerun_allowed: {allowed}");
    println!("rerun_blocked: {blocked}");
    println!("blocked_cases:");
    for report in reports.iter().filter(|report| !rerun_allowed(report)) {
        println!("  - {}", report.case_name);
    }
    println!("primary_blocker_clusters:");
    if primary_clusters.is_empty() {
        println!("  - <none>");
    } else {
        for primitive in primary_clusters {
            println!("  - {}", primitive.as_str());
        }
    }
}

pub fn guard_case(kernel_root: &Path, case_name: &str) -> Result<Report, String> {
    let report = build_report(kernel_root, case_name)?;
    if rerun_allowed(&report) {
        Ok(report)
    } else {
        let primary: Vec<&str> = primary_blocked_primitives(&report)
            .iter()
            .map(|primitive| primitive.as_str())
            .collect();
        Err(format!(
            "ltp_gate blocked {case_name}: primary_blocked_primitives=[{}]; reason={}",
            primary.join(", "),
            report.reason.as_deref().unwrap_or("<none>").trim()
        ))
    }
}

fn find_case_source(kernel_root: &Path, case_name: &str) -> Result<PathBuf, String> {
    let mut stack = vec![kernel_root.join(TESTCASES_ROOT)];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)
            .map_err(|err| format!("failed to read {}: {}", dir.display(), err))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("failed to read dir entry: {}", err))?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_stem().and_then(|stem| stem.to_str()) == Some(case_name)
                && path.extension().and_then(|ext| ext.to_str()) == Some("c")
            {
                return Ok(path);
            }
        }
    }
    Err(format!(
        "could not find LTP testcase source for {}",
        case_name
    ))
}

fn load_source_bundle(source_path: &Path) -> Result<String, String> {
    let mut bundle = read_text(source_path)?;
    let parent = source_path
        .parent()
        .ok_or_else(|| format!("no parent for {}", source_path.display()))?;
    for header in included_local_headers(&bundle) {
        let header_path = parent.join(&header);
        if header_path.exists() {
            bundle.push('\n');
            bundle.push_str(&read_text(&header_path)?);
        }
    }
    Ok(bundle)
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|err| format!("failed to read {}: {}", path.display(), err))
}

fn included_local_headers(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("#include \"") {
                return None;
            }
            let rest = &line["#include \"".len()..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        })
        .collect()
}

fn extract_required_primitives(source: &str) -> BTreeSet<Primitive> {
    let mut set = BTreeSet::new();
    if source.contains("SAFE_FORK(") {
        set.insert(Primitive::ProcessLifecycle);
    }
    if source.contains("waitpid(-1") || source.contains("wait4(") {
        set.insert(Primitive::Wait4Reap);
    }
    if source.contains("/proc/%i/task") || source.contains("/proc/self/task") {
        set.insert(Primitive::ProcTaskVisibility);
    }
    if source.contains("TST_PROCESS_STATE_WAIT") || source.contains("wait_for_threads(") {
        set.insert(Primitive::ThreadSleepVisibility);
    }
    if source.contains("pthread_create")
        || source.contains("SAFE_PTHREAD_CREATE")
        || source.contains("pthread_join")
        || source.contains("SAFE_PTHREAD_JOIN")
    {
        set.insert(Primitive::PthreadThreadFanout);
    }
    if source.contains("FUTEX_PRIVATE_FLAG") {
        set.insert(Primitive::PrivateFutexFanout);
    }
    if (source.contains("MAP_SHARED") || source.contains("waitpid(-1"))
        && (source.contains("futex_wait") || source.contains("futex_wake"))
    {
        set.insert(Primitive::SharedProcessFutexFanout);
    }
    if source.contains("clone3(") || source.contains("clone(") || source.contains("safe_clone") {
        set.insert(Primitive::CloneFallback);
    }
    set
}

fn read_case_status(
    kernel_root: &Path,
    case_name: &str,
) -> Result<(CaseStatus, Option<String>), String> {
    if let Some(line) = find_case_line(&kernel_root.join(CONFORM_PATH), case_name)? {
        return Ok((CaseStatus::Conform, Some(line)));
    }
    if let Some(line) = find_case_line(&kernel_root.join(EQUIVALENT_PATH), case_name)? {
        return Ok((CaseStatus::Equivalent, Some(line)));
    }
    if let Some(line) = find_case_line(&kernel_root.join(UNSUPPORTED_PATH), case_name)? {
        return Ok((CaseStatus::Unsupported, Some(line)));
    }
    Ok((CaseStatus::Unknown, None))
}

fn find_case_line(path: &Path, case_name: &str) -> Result<Option<String>, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {}", path.display(), err))?;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let needle = format!("/{case_name}.c");
        if line.contains(&needle) {
            return Ok(Some(line.to_string()));
        }
    }
    Ok(None)
}

fn extract_blocked_primitives(reason: &str) -> BTreeSet<Primitive> {
    let mut set = BTreeSet::new();
    let lower = reason.to_ascii_lowercase();

    if lower.contains("process") {
        set.insert(Primitive::ProcessLifecycle);
    }
    if lower.contains("wait4/reap") || lower.contains("wake/reap") {
        set.insert(Primitive::Wait4Reap);
    }
    if lower.contains("/proc/<pid>/task")
        || lower.contains("/proc/%i/task")
        || lower.contains("defunct-thread visibility")
    {
        set.insert(Primitive::ProcTaskVisibility);
    }
    if lower.contains("wait_for_threads")
        || lower.contains("thread not sleeping")
        || lower.contains("sleeping")
        || lower.contains("checkpoint wake/wait")
        || lower.contains("checkpoint waiter")
    {
        set.insert(Primitive::ThreadSleepVisibility);
    }
    if lower.contains("pthread-backed")
        || lower.contains("private-futex fanout")
        || lower.contains("pthread helper")
        || lower.contains("pthread-thread-fanout")
    {
        set.insert(Primitive::PthreadThreadFanout);
        set.insert(Primitive::PrivateFutexFanout);
    }
    if lower.contains("shared-futex") || lower.contains("multi-process") {
        set.insert(Primitive::SharedProcessFutexFanout);
    }
    if lower.contains("clone3") || lower.contains("clone fallback") {
        set.insert(Primitive::CloneFallback);
    }
    if lower.contains("af_inet loopback") || lower.contains("loopback connect") {
        set.insert(Primitive::SocketLoopbackConnect);
    }
    if lower.contains("socketcall") {
        set.insert(Primitive::LegacySocketcallAbi);
    }
    if lower.contains("timerfd deadline")
        || lower.contains("timerfd deadlines")
        || lower.contains("blocked in poll/read")
    {
        set.insert(Primitive::TimerfdBlockedDeadline);
    }
    if lower.contains("clone_newtime")
        || lower.contains("time namespace")
        || lower.contains("timens_offsets")
    {
        set.insert(Primitive::TimeNamespace);
    }
    if lower.contains("cancel_on_set") {
        set.insert(Primitive::CancelOnSet);
    }

    set
}

fn collect_cases_from_manifest(path: &Path, out: &mut BTreeSet<String>) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {}", path.display(), err))?;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(case_name) = case_name_from_manifest_line(line) {
            out.insert(case_name);
        }
    }
    Ok(())
}

fn collect_implemented_unsupported_cases(
    path: &Path,
    out: &mut BTreeSet<String>,
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {}", path.display(), err))?;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("not yet enabled")
            || lower.contains("currently returns enosys")
            || lower.contains("not yet implemented in syscall dispatch")
            || lower.contains("helper binary")
        {
            continue;
        }
        if let Some(case_name) = case_name_from_manifest_line(line) {
            out.insert(case_name);
        }
    }
    Ok(())
}

fn case_name_from_manifest_line(line: &str) -> Option<String> {
    let path_end = line.find(".c")? + 2;
    let path = &line[..path_end];
    let name = Path::new(path).file_stem()?.to_str()?;
    Some(name.to_string())
}
