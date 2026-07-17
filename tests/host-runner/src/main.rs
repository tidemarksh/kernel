use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use wasmparser::{Imports, Parser, Payload, TypeRef};

const EXPECTED_VALUES: [i32; 4] = [0, 3, 1, 0];
const WASM32_MEMORY_MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x02, 0x10, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x06,
    0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01, 0x01,
];

fn main() {
    if let Err(error) = run() {
        eprintln!("memory64 host validation failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "host runner has no workspace parent".to_string())?;
    let artifact = workspace.join("target/wasm64-unknown-unknown/release/tidemark_kernel.wasm");
    let env_module = workspace.join("tests/fixtures/wasm/memory64-env.wat");
    let smoke_module = workspace.join("tests/fixtures/wasm/memory64-smoke.wat");
    let runner_source = workspace.join("tests/host-runner/src/main.rs");
    let wasmtime = env::var_os("WASMTIME").unwrap_or_else(|| "wasmtime".into());

    build_kernel(workspace)?;

    let bytes = fs::read(&artifact)
        .map_err(|error| format!("cannot read {}: {error}", artifact.display()))?;
    verify_memory64(&bytes)?;

    let artifact_identity = sha256(&artifact)?;
    let first_identity = artifact_identity.clone();
    let output = run_engine(&wasmtime, true, &artifact, &env_module, &smoke_module)?;
    let second_identity = sha256(&artifact)?;
    require_identity(&first_identity, &second_identity)?;

    let observed = parse_values(&output)?;
    validate_values(&EXPECTED_VALUES, &observed)?;
    validate_counters(observed[2], observed[3])?;

    negative_conformance(
        &wasmtime,
        &artifact,
        &env_module,
        &smoke_module,
        &artifact_identity,
        &observed,
    )?;

    println!("memory64=true");
    println!("shared_memory=true");
    println!("production_entry=thread_step");
    println!("return_value={}", observed[0]);
    println!("status={}", observed[1]);
    println!("requested_budget={}", observed[2]);
    println!("remaining_budget={}", observed[3]);
    println!("consumed_budget={}", observed[2] - observed[3]);
    println!("artifact_sha256={artifact_identity}");
    println!("runner_sha256={}", sha256(&runner_source)?);
    println!("env_module_sha256={}", sha256(&env_module)?);
    println!("smoke_module_sha256={}", sha256(&smoke_module)?);
    println!(
        "git_head={}",
        command_line(workspace, "git", &["rev-parse", "HEAD"])?
    );
    println!(
        "git_tree={}",
        command_line(workspace, "git", &["rev-parse", "HEAD^{tree}"])?
    );
    println!(
        "rustc_version={}",
        command_line(workspace, "rustup", &["run", "nightly", "rustc", "-Vv"])?
    );
    println!(
        "cargo_version={}",
        command_line(workspace, "rustup", &["run", "nightly", "cargo", "-V"])?
    );
    println!(
        "wasmtime_version={}",
        command_line_path(workspace, &wasmtime, &["--version"])?
    );
    println!("negative_wasm32=pass");
    println!("negative_memory64_disabled=pass");
    println!("negative_identity_drift=pass");
    println!("negative_oracle_mismatch=pass");
    println!("negative_counter_mismatch=pass");
    println!("outer_timeout_seconds=300");
    println!("resource_profile=host-default");
    Ok(())
}

fn build_kernel(workspace: &Path) -> Result<(), String> {
    let status = Command::new("rustup")
        .current_dir(workspace)
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--release",
            "-Zbuild-std=core,alloc",
            "-p",
            "tidemark-kernel",
            "--features",
            "harness",
        ])
        .status()
        .map_err(|error| format!("cannot launch Memory64 Kernel build: {error}"))?;
    if !status.success() {
        return Err(format!("Memory64 Kernel build exited with {status}"));
    }
    Ok(())
}

fn verify_memory64(bytes: &[u8]) -> Result<(), String> {
    let mut memory = None;
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::ImportSection(section) =
            payload.map_err(|error| format!("cannot parse Kernel artifact: {error}"))?
        {
            for import in section {
                let import =
                    import.map_err(|error| format!("cannot parse Kernel import: {error}"))?;
                if let Imports::Single(_, import) = import
                    && import.module == "env"
                    && import.name == "memory"
                    && let TypeRef::Memory(candidate) = import.ty
                {
                    memory = Some(candidate);
                }
            }
        }
    }
    let memory = memory.ok_or_else(|| "Kernel artifact does not import env.memory".to_string())?;
    if !memory.memory64 {
        return Err("Kernel artifact env.memory is wasm32".to_string());
    }
    if !memory.shared {
        return Err("Kernel artifact env.memory is not shared".to_string());
    }
    Ok(())
}

fn run_engine(
    wasmtime: &std::ffi::OsStr,
    memory64: bool,
    artifact: &Path,
    env_module: &Path,
    smoke_module: &Path,
) -> Result<Output, String> {
    Command::new(wasmtime)
        .args([
            "run",
            "-W",
            if memory64 {
                "memory64=y,threads=y"
            } else {
                "memory64=n,threads=y"
            },
            "--preload",
        ])
        .arg(format!("env={}", env_module.display()))
        .arg("--preload")
        .arg(format!("kernel={}", artifact.display()))
        .args(["--invoke", "run"])
        .arg(smoke_module)
        .output()
        .map_err(|error| format!("cannot launch wasmtime: {error}"))
}

fn parse_values(output: &Output) -> Result<[i32; 4], String> {
    if !output.status.success() {
        return Err(format!(
            "Memory64 smoke exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let values = String::from_utf8(output.stdout.clone())
        .map_err(|error| format!("smoke output is not UTF-8: {error}"))?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse::<i32>()
                .map_err(|error| format!("invalid smoke value {line:?}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    values
        .try_into()
        .map_err(|values: Vec<i32>| format!("expected four smoke values, got {values:?}"))
}

fn validate_values(expected: &[i32; 4], observed: &[i32; 4]) -> Result<(), String> {
    if expected != observed {
        return Err(format!(
            "smoke oracle mismatch: expected {expected:?}, observed {observed:?}"
        ));
    }
    Ok(())
}

fn validate_counters(requested: i32, remaining: i32) -> Result<(), String> {
    if requested != 1 || remaining != 0 || requested - remaining != 1 {
        return Err(format!(
            "smoke counter mismatch: requested={requested}, remaining={remaining}"
        ));
    }
    Ok(())
}

fn require_identity(expected: &str, observed: &str) -> Result<(), String> {
    if expected != observed {
        return Err(format!(
            "artifact identity mismatch: expected {expected}, observed {observed}"
        ));
    }
    Ok(())
}

fn negative_conformance(
    wasmtime: &std::ffi::OsStr,
    artifact: &Path,
    env_module: &Path,
    smoke_module: &Path,
    artifact_identity: &str,
    observed: &[i32; 4],
) -> Result<(), String> {
    expect_rejection("wasm32 artifact", verify_memory64(WASM32_MEMORY_MODULE))?;

    let disabled = run_engine(wasmtime, false, artifact, env_module, smoke_module)?;
    if disabled.status.success() {
        return Err("Memory64-disabled engine accepted the smoke".to_string());
    }
    if !String::from_utf8_lossy(&disabled.stderr).contains("memory64 must be enabled") {
        return Err(format!(
            "Memory64-disabled engine failed for the wrong reason: {}",
            String::from_utf8_lossy(&disabled.stderr).trim()
        ));
    }

    let wrong_identity = "0".repeat(64);
    expect_rejection(
        "wrong artifact identity",
        require_identity(&wrong_identity, artifact_identity),
    )?;

    let mut wrong_oracle = *observed;
    wrong_oracle[0] = wrong_oracle[0].wrapping_add(1);
    expect_rejection("oracle mismatch", validate_values(&wrong_oracle, observed))?;

    expect_rejection(
        "counter mismatch",
        validate_counters(observed[2].wrapping_add(1), observed[3]),
    )?;
    Ok(())
}

fn expect_rejection(label: &str, result: Result<(), String>) -> Result<(), String> {
    if result.is_ok() {
        return Err(format!("negative conformance did not reject {label}"));
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String, String> {
    let line = command_line_path(
        path.parent().unwrap_or_else(|| Path::new(".")),
        Path::new("sha256sum").as_os_str(),
        &[path.to_string_lossy().as_ref()],
    )?;
    line.split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| format!("sha256sum returned no digest for {}", path.display()))
}

fn command_line(cwd: &Path, program: &str, args: &[&str]) -> Result<String, String> {
    command_line_path(cwd, Path::new(program).as_os_str(), args)
}

fn command_line_path(
    cwd: &Path,
    program: &std::ffi::OsStr,
    args: &[&str],
) -> Result<String, String> {
    let output = Command::new(program)
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(|error| {
            format!(
                "cannot launch {}: {error}",
                PathBuf::from(program).display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "{} exited with {}: {}",
            PathBuf::from(program).display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().replace('\n', " | "))
        .map_err(|error| format!("command output is not UTF-8: {error}"))
}
