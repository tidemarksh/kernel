use regex::Regex;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_TEST_TARGET: &str = "wasm32-wasip1";

#[derive(Clone, Copy)]
enum TestTarget<'a> {
    Binary(&'a str),
    Lib,
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("xtask: {}", err);
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_help();
        return Ok(());
    };

    match command.as_str() {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "ltp-conform" => {
            let pattern = optional_pattern(args)?;
            run_test_target(TestTarget::Binary("ltp_tests"), pattern.as_deref())
        }
        "test-binary" => {
            let binary = args.next().ok_or_else(|| {
                "usage: cargo xtask test-binary <binary> [test-name-regex]".to_string()
            })?;
            let pattern = optional_pattern(args)?;
            run_test_target(TestTarget::Binary(&binary), pattern.as_deref())
        }
        "test-lib" => {
            let pattern = optional_pattern(args)?;
            run_test_target(TestTarget::Lib, pattern.as_deref())
        }
        other => Err(format!("unknown xtask command {:?}", other)),
    }
}

fn optional_pattern(mut args: impl Iterator<Item = String>) -> Result<Option<String>, String> {
    let pattern = args.next();
    if let Some(extra) = args.next() {
        return Err(format!("unexpected extra argument {:?}", extra));
    }
    Ok(pattern)
}

fn print_help() {
    eprintln!("usage:");
    eprintln!("  cargo xtask ltp-conform [test-name-regex]");
    eprintln!("  cargo xtask test-binary <binary> [test-name-regex]");
    eprintln!("  cargo xtask test-lib [test-name-regex]");
}

fn run_test_target(target: TestTarget<'_>, pattern: Option<&str>) -> Result<(), String> {
    let matcher = match pattern {
        Some(raw) => Some(Regex::new(raw).map_err(|e| format!("invalid regex {:?}: {}", raw, e))?),
        None => None,
    };

    let mut tests = list_tests(target)?;
    if let Some(matcher) = &matcher {
        tests.retain(|name| matcher.is_match(name));
    }

    if tests.is_empty() {
        return Err(format!(
            "no tests matched for {}",
            target_description(target)
        ));
    }

    for test_name in tests {
        println!("==> {} :: {}", target_description(target), test_name);
        let mut command = cargo_command();
        command.arg("test");
        match target {
            TestTarget::Binary(binary) => {
                command.args(["--test", binary]);
            }
            TestTarget::Lib => {
                command.arg("--lib");
            }
        }
        let status = command
            .args([
                "--target",
                DEFAULT_TEST_TARGET,
                &test_name,
                "--",
                "--exact",
                "--nocapture",
            ])
            .status()
            .map_err(|e| format!("failed to run cargo test for {}: {}", test_name, e))?;

        if !status.success() {
            return Err(match status.code() {
                Some(code) => format!(
                    "{} :: {} failed with exit code {}",
                    target_description(target),
                    test_name,
                    code
                ),
                None => format!(
                    "{} :: {} terminated by signal",
                    target_description(target),
                    test_name
                ),
            });
        }
    }

    Ok(())
}

fn list_tests(target: TestTarget<'_>) -> Result<Vec<String>, String> {
    let mut command = cargo_command();
    command.arg("test");
    match target {
        TestTarget::Binary(binary) => {
            command.args(["--test", binary]);
        }
        TestTarget::Lib => {
            command.arg("--lib");
        }
    }
    let output = command
        .args(["--target", DEFAULT_TEST_TARGET, "--", "--list"])
        .output()
        .map_err(|e| format!("failed to list tests for {}: {}", target_description(target), e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "failed to list tests for {}:\n{}{}",
            target_description(target),
            stdout,
            stderr
        ));
    }

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(parse_test_names(&combined))
}

fn target_description(target: TestTarget<'_>) -> String {
    match target {
        TestTarget::Binary(binary) => format!("test binary {:?}", binary),
        TestTarget::Lib => "lib tests".to_string(),
    }
}

fn parse_test_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim_end();
            let name = trimmed.strip_suffix(": test")?;
            if name.is_empty() || name.starts_with(char::is_whitespace) {
                return None;
            }
            Some(name.to_string())
        })
        .collect()
}

fn cargo_command() -> Command {
    let mut command = Command::new("cargo");
    command.current_dir(repo_root());
    command
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate must live under kernel/")
        .to_path_buf()
}
