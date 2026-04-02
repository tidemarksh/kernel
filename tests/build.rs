use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct LtpManifest {
    conform: Vec<String>,
    equivalent: Vec<String>,
    unsupported: Vec<String>,
    divergent: Vec<String>,
}

impl LtpManifest {
    fn pass_required(&self) -> &[String] {
        &self.conform
    }

    fn pass_optional(&self) -> &[String] {
        &self.equivalent
    }
}

struct LtpTestTarget {
    binary_name: String,
    rel_dir: PathBuf,
    rel_path: PathBuf,
}

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ltp_manifest_dir = Path::new("fixtures/ltp");
    let ltp_manifest =
        load_ltp_manifest(ltp_manifest_dir).expect("failed to load LTP classification files");
    let pass_required = ltp_manifest.pass_required();
    let pass_optional = ltp_manifest.pass_optional();

    println!("cargo:rerun-if-changed=../vendor/riscv-tests");
    println!("cargo:rerun-if-changed=../vendor/ltp");
    println!("cargo:rerun-if-changed=fixtures/riscv/link.ld");
    println!("cargo:rerun-if-changed=fixtures/riscv/riscv_test.h");
    println!("cargo:rerun-if-changed=fixtures/ltp/conform.txt");
    println!("cargo:rerun-if-changed=fixtures/ltp/equivalent.txt");
    println!("cargo:rerun-if-changed=fixtures/ltp/unsupported.txt");
    println!("cargo:rerun-if-changed=fixtures/ltp/divergent.txt");

    let has_cross_gcc = Command::new("riscv64-linux-gnu-gcc")
        .arg("--version")
        .output()
        .is_ok();

    if !has_cross_gcc {
        eprintln!("riscv64-linux-gnu-gcc not found, skipping riscv-tests build");
        eprintln!("riscv64-linux-gnu-gcc not found, skipping ltp build");
        return;
    }

    build_riscv_tests(&out_dir);
    build_ltp_tests(&out_dir, pass_required, pass_optional);
}

fn build_riscv_tests(out_dir: &Path) {
    let riscv_tests = Path::new("../vendor/riscv-tests");
    let src_dir = riscv_tests.join("isa");

    if !src_dir.join("rv64ui").exists() {
        return;
    }

    let macros = src_dir.join("macros/scalar");
    let fixtures = Path::new("fixtures/riscv");
    let link_ld = fixtures.join("link.ld");

    for suite in &["rv64ui", "rv64um", "rv64ua", "rv64uf", "rv64ud"] {
        let suite_out = out_dir.join(suite);
        std::fs::create_dir_all(&suite_out).unwrap();

        let suite_src = src_dir.join(suite);
        if !suite_src.exists() {
            continue;
        }

        for entry in std::fs::read_dir(&suite_src).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().map_or(true, |e| e != "S") {
                continue;
            }

            let name = path.file_stem().unwrap().to_str().unwrap();
            let elf_path = suite_out.join(format!("{}.elf", name));

            let status = Command::new("riscv64-linux-gnu-gcc")
                .args(&[
                    "-march=rv64gc",
                    "-mabi=lp64d",
                    "-nostdlib",
                    "-nostartfiles",
                    "-static",
                    "-T",
                    link_ld.to_str().unwrap(),
                    "-I",
                    fixtures.to_str().unwrap(),
                    "-I",
                    macros.to_str().unwrap(),
                    "-o",
                    elf_path.to_str().unwrap(),
                    path.to_str().unwrap(),
                ])
                .status();

            if let Ok(s) = status {
                if !s.success() {
                    eprintln!("Failed to build {}/{}", suite, name);
                }
            }
        }
    }
}

fn build_ltp_tests(out_dir: &Path, pass_required: &[String], pass_optional: &[String]) {
    let ltp_root = Path::new("../vendor/ltp");
    if (pass_required.is_empty() && pass_optional.is_empty())
        || !ltp_root.join("configure.ac").exists()
    {
        return;
    }

    let tests = pass_required
        .iter()
        .chain(pass_optional.iter())
        .cloned()
        .collect::<Vec<_>>();
    let test_targets =
        resolve_ltp_test_targets(ltp_root, &tests).expect("failed to resolve LTP test targets");
    let helper_targets = discover_ltp_helper_targets(ltp_root, &test_targets)
        .expect("failed to resolve LTP helper targets");
    let build_targets = merge_ltp_targets(&test_targets, &helper_targets);
    let ltp_work = out_dir.join("ltp-work");

    if let Err(err) = prepare_ltp_workspace(ltp_root, &ltp_work) {
        eprintln!("Failed to prepare ltp workspace: {}", err);
        return;
    }

    if let Err(err) = run_command(
        Command::new("make").current_dir(&ltp_work).arg("autotools"),
        "make autotools",
    ) {
        eprintln!("Failed to prepare ltp autotools: {}", err);
        return;
    }

    if let Err(err) = run_command(
        Command::new("./configure")
            .current_dir(&ltp_work)
            .env("CC", "riscv64-linux-gnu-gcc")
            .arg("--host=riscv64-linux-gnu"),
        "configure ltp",
    ) {
        eprintln!("Failed to configure ltp: {}", err);
        return;
    }

    if let Err(err) = run_command(
        Command::new("make")
            .current_dir(ltp_work.join("lib"))
            .env("CC", "riscv64-linux-gnu-gcc")
            .arg("all"),
        "build ltp lib",
    ) {
        eprintln!("Failed to build ltp lib: {}", err);
        return;
    }

    let ltp_lib_dir = ltp_work.join("lib");
    let ltp_wldflags = format!("-L{} -static -no-pie", ltp_lib_dir.display());
    let ltp_out = out_dir.join("ltp");
    std::fs::create_dir_all(&ltp_out).unwrap();

    for target in build_targets {
        let test_dir = ltp_work.join(&target.rel_dir);
        if let Err(err) = run_command(
            Command::new("make")
                .current_dir(&test_dir)
                .env("CC", "riscv64-linux-gnu-gcc")
                .arg(format!("WLDFLAGS={}", ltp_wldflags))
                .arg(&target.binary_name),
            &format!("build ltp test {}", target.binary_name),
        ) {
            eprintln!("Failed to build ltp test {}: {}", target.binary_name, err);
            continue;
        }

        let src = test_dir.join(&target.binary_name);
        let dst = ltp_out.join(&target.binary_name);
        if let Err(err) = std::fs::copy(&src, &dst) {
            eprintln!("Failed to stage ltp test {}: {}", target.binary_name, err);
        }
    }
}

fn load_ltp_manifest(dir: &Path) -> Result<LtpManifest, String> {
    let manifest = LtpManifest {
        conform: parse_ltp_test_list(&dir.join("conform.txt"))?,
        equivalent: parse_ltp_test_list(&dir.join("equivalent.txt"))?,
        unsupported: parse_ltp_test_list(&dir.join("unsupported.txt"))?,
        divergent: parse_ltp_test_list(&dir.join("divergent.txt"))?,
    };
    validate_ltp_manifest(&manifest)?;
    Ok(manifest)
}

fn parse_ltp_test_list(path: &Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    let mut tests = Vec::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let selector = line
            .split_whitespace()
            .next()
            .ok_or_else(|| format!("{}:{} invalid entry", path.display(), idx + 1))?;
        if !selector
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '.'))
        {
            return Err(format!(
                "{}:{} invalid test selector {:?}",
                path.display(),
                idx + 1,
                selector
            ));
        }
        tests.push(selector.to_string());
    }

    Ok(tests)
}

fn validate_ltp_manifest(manifest: &LtpManifest) -> Result<(), String> {
    let mut seen = BTreeMap::new();
    for (category, tests) in [
        ("conform", &manifest.conform),
        ("equivalent", &manifest.equivalent),
        ("unsupported", &manifest.unsupported),
        ("divergent", &manifest.divergent),
    ] {
        for test in tests {
            if let Some(prev) = seen.insert(test.clone(), category) {
                return Err(format!(
                    "LTP test {} is listed in both {} and {}",
                    test, prev, category
                ));
            }
        }
    }
    Ok(())
}

fn resolve_ltp_test_targets(
    ltp_root: &Path,
    tests: &[String],
) -> Result<Vec<LtpTestTarget>, String> {
    let mut targets = Vec::with_capacity(tests.len());
    for selector in tests {
        targets.push(resolve_ltp_test_target(ltp_root, selector)?);
    }
    Ok(targets)
}

fn resolve_ltp_test_target(ltp_root: &Path, selector: &str) -> Result<LtpTestTarget, String> {
    if selector.contains('/') || selector.ends_with(".c") {
        let rel_path = PathBuf::from(selector);
        let full_path = ltp_root.join(&rel_path);
        if !full_path.exists() {
            return Err(format!("LTP source {} not found", full_path.display()));
        }
        let binary_name = selector_binary_name(selector)?;
        let rel_dir = rel_path
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", rel_path.display()))?
            .to_path_buf();
        return Ok(LtpTestTarget {
            binary_name,
            rel_dir,
            rel_path,
        });
    }

    let rel_path = find_ltp_test_source(ltp_root, selector)?;
    let binary_name = selector_binary_name(selector)?;
    let rel_dir = rel_path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", rel_path.display()))?
        .to_path_buf();
    Ok(LtpTestTarget {
        binary_name,
        rel_dir,
        rel_path,
    })
}

fn discover_ltp_helper_targets(
    ltp_root: &Path,
    test_targets: &[LtpTestTarget],
) -> Result<Vec<LtpTestTarget>, String> {
    let mut helpers = BTreeMap::new();

    for target in test_targets {
        let source_path = ltp_root.join(&target.rel_path);
        for helper in scan_ltp_helpers(&source_path)? {
            let helper_target = resolve_ltp_test_target(ltp_root, &helper)?;
            helpers
                .entry(helper_target.binary_name.clone())
                .or_insert(helper_target);
        }
    }

    Ok(helpers.into_values().collect())
}

fn merge_ltp_targets(
    test_targets: &[LtpTestTarget],
    helper_targets: &[LtpTestTarget],
) -> Vec<LtpTestTarget> {
    let mut merged = BTreeMap::new();

    for target in test_targets.iter().chain(helper_targets.iter()) {
        merged
            .entry(target.binary_name.clone())
            .or_insert_with(|| LtpTestTarget {
                binary_name: target.binary_name.clone(),
                rel_dir: target.rel_dir.clone(),
                rel_path: target.rel_path.clone(),
            });
    }

    merged.into_values().collect()
}

fn scan_ltp_helpers(source_path: &Path) -> Result<Vec<String>, String> {
    let text =
        fs::read_to_string(source_path).map_err(|e| format!("{}: {}", source_path.display(), e))?;
    let defines = scan_string_defines(&text);
    let mut helpers = Vec::new();
    scan_tst_get_path_helpers(text.as_str(), &mut helpers);
    scan_execlp_helpers(text.as_str(), &defines, &mut helpers);
    scan_resource_file_helpers(text.as_str(), &defines, &mut helpers);
    Ok(helpers)
}

fn scan_tst_get_path_helpers(text: &str, helpers: &mut Vec<String>) {
    let mut rest = text;
    let needle = "tst_get_path(\"";
    while let Some(idx) = rest.find(needle) {
        rest = &rest[idx + needle.len()..];
        let Some(end) = rest.find('"') else {
            break;
        };
        let helper = &rest[..end];
        push_helper(helpers, helper);
        rest = &rest[end + 1..];
    }
}

fn scan_string_defines(text: &str) -> BTreeMap<String, String> {
    let mut defines = BTreeMap::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("#define ") {
            continue;
        }
        let mut parts = trimmed["#define ".len()..].split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next() else {
            continue;
        };
        if let Some(helper) = parse_helper_token(value, &BTreeMap::new()) {
            defines.insert(name.to_string(), helper);
        }
    }

    defines
}

fn scan_execlp_helpers(text: &str, defines: &BTreeMap<String, String>, helpers: &mut Vec<String>) {
    for needle in ["SAFE_EXECLP(", "execlp("] {
        let mut rest = text;
        while let Some(idx) = rest.find(needle) {
            rest = &rest[idx + needle.len()..];
            let Some(end) = rest.find(',') else {
                break;
            };
            let token = rest[..end].trim();
            if let Some(helper) = parse_helper_token(token, defines) {
                push_helper(helpers, &helper);
            }
            rest = &rest[end + 1..];
        }
    }
}

fn scan_resource_file_helpers(
    text: &str,
    defines: &BTreeMap<String, String>,
    helpers: &mut Vec<String>,
) {
    let mut rest = text;
    let needle = ".resource_files";

    while let Some(idx) = rest.find(needle) {
        rest = &rest[idx + needle.len()..];
        let Some(open_brace) = rest.find('{') else {
            break;
        };
        rest = &rest[open_brace + 1..];
        let Some(close_brace) = rest.find('}') else {
            break;
        };
        let entries = &rest[..close_brace];
        for token in entries.split(',') {
            let token = token.trim();
            if token.is_empty() || token == "NULL" {
                continue;
            }
            if let Some(helper) = parse_helper_token(token, defines) {
                push_helper(helpers, &helper);
            }
        }
        rest = &rest[close_brace + 1..];
    }
}

fn parse_helper_token(token: &str, defines: &BTreeMap<String, String>) -> Option<String> {
    let token = token.trim();
    if token.len() >= 2 && token.starts_with('"') && token.ends_with('"') {
        return Some(token[1..token.len() - 1].to_string());
    }
    defines.get(token).cloned()
}

fn push_helper(helpers: &mut Vec<String>, helper: &str) {
    if !helper.is_empty()
        && helper
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
        && !helpers.iter().any(|existing| existing == helper)
    {
        helpers.push(helper.to_string());
    }
}

fn selector_binary_name(selector: &str) -> Result<String, String> {
    let path = Path::new(selector);
    let stem = path
        .file_stem()
        .or_else(|| path.file_name())
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("invalid LTP selector {:?}", selector))?;
    Ok(stem.to_string())
}

fn find_ltp_test_source(ltp_root: &Path, test_name: &str) -> Result<PathBuf, String> {
    let mut matches = Vec::new();
    let needle = format!("{}.c", test_name);
    for dir in [
        ltp_root.join("testcases"),
        ltp_root.join("lib/newlib_tests"),
    ] {
        if dir.exists() {
            find_ltp_test_source_recursive(&dir, &needle, &mut matches)?;
        }
    }

    match matches.len() {
        0 => Err(format!(
            "LTP test {} not found under {}",
            test_name,
            ltp_root.display()
        )),
        1 => matches[0]
            .strip_prefix(ltp_root)
            .map(Path::to_path_buf)
            .map_err(|e| e.to_string()),
        _ => Err(format!(
            "LTP test {} is ambiguous: {}",
            test_name,
            matches
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn find_ltp_test_source_recursive(
    dir: &Path,
    needle: &str,
    matches: &mut Vec<PathBuf>,
) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| e.to_string())?;
        if file_type.is_dir() {
            find_ltp_test_source_recursive(&path, needle, matches)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some(needle) {
            matches.push(path);
        }
    }
    Ok(())
}

fn prepare_ltp_workspace(src: &Path, dst: &Path) -> Result<(), String> {
    if dst.exists() {
        std::fs::remove_dir_all(dst).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    copy_ltp_tree(src, dst)
}

fn copy_ltp_tree(src: &Path, dst: &Path) -> Result<(), String> {
    for entry in fs::read_dir(src).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = entry.file_name();
        let file_type = entry.file_type().map_err(|e| e.to_string())?;

        if name.to_str() == Some(".git") {
            continue;
        }

        let dst_path = dst.join(&name);
        if file_type.is_dir() {
            fs::create_dir_all(&dst_path).map_err(|e| e.to_string())?;
            copy_ltp_tree(&path, &dst_path)?;
            continue;
        }

        if file_type.is_symlink() {
            let target = fs::read_link(&path).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dst_path).map_err(|e| e.to_string())?;
            #[cfg(not(unix))]
            {
                let resolved = path.parent().unwrap_or(src).join(&target);
                fs::copy(&resolved, &dst_path).map_err(|e| e.to_string())?;
            }
            continue;
        }

        fs::copy(&path, &dst_path).map_err(|e| e.to_string())?;
    }

    Ok(())
}

fn run_command(cmd: &mut Command, label: &str) -> Result<(), String> {
    let status = cmd.status().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} exited with {}", label, status))
    }
}
