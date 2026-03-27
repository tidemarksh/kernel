use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
}

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ltp_manifest_dir = Path::new("tests/support/ltp");
    let ltp_manifest =
        load_ltp_manifest(ltp_manifest_dir).expect("failed to load LTP classification files");
    let pass_required = ltp_manifest.pass_required();
    let pass_optional = ltp_manifest.pass_optional();

    println!("cargo:rerun-if-changed=tests/riscv-tests");
    println!("cargo:rerun-if-changed=tests/ltp-tests");
    println!("cargo:rerun-if-changed=tests/support/ltp/conform.txt");
    println!("cargo:rerun-if-changed=tests/support/ltp/equivalent.txt");
    println!("cargo:rerun-if-changed=tests/support/ltp/unsupported.txt");
    println!("cargo:rerun-if-changed=tests/support/ltp/divergent.txt");

    write_ltp_test_harness(&out_dir, pass_required, pass_optional)
        .expect("failed to generate ltp test harness");

    let has_cross_gcc = Command::new("riscv64-linux-gnu-gcc")
        .arg("--version")
        .output()
        .is_ok();

    if !has_cross_gcc {
        eprintln!("riscv64-linux-gnu-gcc not found, skipping riscv-tests build");
        eprintln!("riscv64-linux-gnu-gcc not found, skipping ltp-tests build");
        return;
    }

    build_riscv_tests(&out_dir);
    build_ltp_tests(&out_dir, pass_required, pass_optional);
}

fn build_riscv_tests(out_dir: &Path) {
    let riscv_tests = Path::new("tests/riscv-tests");
    let src_dir = riscv_tests.join("src/isa");

    if !src_dir.join("rv64ui").exists() {
        return;
    }

    let macros = src_dir.join("macros/scalar");
    let link_ld = riscv_tests.join("link.ld");

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
                    riscv_tests.to_str().unwrap(),
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
    let ltp_root = Path::new("tests/ltp-tests");
    if (pass_required.is_empty() && pass_optional.is_empty()) || !ltp_root.join("configure.ac").exists() {
        return;
    }

    let tests = pass_required
        .iter()
        .chain(pass_optional.iter())
        .cloned()
        .collect::<Vec<_>>();
    let test_targets =
        resolve_ltp_test_targets(ltp_root, &tests).expect("failed to resolve LTP test targets");
    let ltp_out = out_dir.join("ltp");
    std::fs::create_dir_all(&ltp_out).unwrap();
    let ltp_work = out_dir.join("ltp-tests-work");

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

    for target in test_targets {
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

fn write_ltp_test_harness(
    out_dir: &Path,
    pass_required: &[String],
    pass_optional: &[String],
) -> Result<(), String> {
    let generated = out_dir.join("ltp_tests_generated.rs");
    let tests = pass_required
        .iter()
        .chain(pass_optional.iter())
        .cloned()
        .collect::<Vec<_>>();
    let mut source = String::from("// @generated by build.rs\n");
    let mut binary_counts = BTreeMap::new();

    for selector in &tests {
        let binary = selector_binary_name(selector)?;
        *binary_counts.entry(binary).or_insert(0usize) += 1;
    }

    for selector in &tests {
        let binary = selector_binary_name(selector)?;
        let rust_name = if binary_counts.get(&binary).copied().unwrap_or(0) == 1 {
            format!("ltp_{}", binary)
        } else {
            format!("ltp_{}", selector)
        };
        source.push_str(&format!(
            "ltp_test!({}, {:?});\n",
            sanitize_rust_ident(&rust_name),
            binary
        ));
    }

    fs::write(generated, source).map_err(|e| e.to_string())
}

fn sanitize_rust_ident(name: &str) -> String {
    let mut ident = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            ident.push(ch);
        } else {
            ident.push('_');
        }
    }
    ident
}

fn resolve_ltp_test_targets(ltp_root: &Path, tests: &[String]) -> Result<Vec<LtpTestTarget>, String> {
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
        return Ok(LtpTestTarget { binary_name, rel_dir });
    }

    let rel_path = find_ltp_test_source(ltp_root, selector)?;
    let binary_name = selector_binary_name(selector)?;
    let rel_dir = rel_path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", rel_path.display()))?
        .to_path_buf();
    Ok(LtpTestTarget { binary_name, rel_dir })
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
    find_ltp_test_source_recursive(&ltp_root.join("testcases"), &needle, &mut matches)?;

    match matches.len() {
        0 => Err(format!("LTP test {} not found under {}", test_name, ltp_root.display())),
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

    let mut archive = Command::new("git")
        .arg("-C")
        .arg(src)
        .args(["archive", "--format=tar", "HEAD"])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;

    let archive_stdout = archive.stdout.take().ok_or("git archive stdout missing")?;
    let tar_status = Command::new("tar")
        .args(["-x", "-C"])
        .arg(dst)
        .stdin(archive_stdout)
        .status()
        .map_err(|e| e.to_string())?;
    let archive_status = archive.wait().map_err(|e| e.to_string())?;

    if !archive_status.success() {
        return Err(format!("git archive exited with {}", archive_status));
    }
    if !tar_status.success() {
        return Err(format!("tar exited with {}", tar_status));
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
