use regex::Regex;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_TEST_TARGET: &str = "wasm32-wasip1";

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
            run_test_binary("ltp_tests", pattern.as_deref())
        }
        "test-binary" => {
            let binary = args
                .next()
                .ok_or_else(|| "usage: cargo xtask test-binary <binary> [test-name-regex]".to_string())?;
            let pattern = optional_pattern(args)?;
            run_test_binary(&binary, pattern.as_deref())
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
}

fn run_test_binary(binary: &str, pattern: Option<&str>) -> Result<(), String> {
    let matcher = match pattern {
        Some(raw) => Some(Regex::new(raw).map_err(|e| format!("invalid regex {:?}: {}", raw, e))?),
        None => None,
    };

    let mut tests = list_tests(binary)?;
    if let Some(matcher) = &matcher {
        tests.retain(|name| matcher.is_match(name));
    }

    if tests.is_empty() {
        return Err(format!("no tests matched for binary {:?}", binary));
    }

    for test_name in tests {
        println!("==> {} :: {}", binary, test_name);
        let status = cargo_command()
            .args([
                "test",
                "--test",
                binary,
                "--target",
                DEFAULT_TEST_TARGET,
                &test_name,
                "--",
                "--nocapture",
            ])
            .status()
            .map_err(|e| format!("failed to run cargo test for {}: {}", test_name, e))?;

        if !status.success() {
            return Err(match status.code() {
                Some(code) => format!("{} :: {} failed with exit code {}", binary, test_name, code),
                None => format!("{} :: {} terminated by signal", binary, test_name),
            });
        }
    }

    Ok(())
}

fn list_tests(binary: &str) -> Result<Vec<String>, String> {
    let output = cargo_command()
        .args(["test", "--test", binary, "--target", DEFAULT_TEST_TARGET, "--", "--list"])
        .output()
        .map_err(|e| format!("failed to list tests for {}: {}", binary, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "failed to list tests for {}:\n{}{}",
            binary, stdout, stderr
        ));
    }

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(parse_test_names(&combined))
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
