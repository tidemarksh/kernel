use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=tests/riscv-tests");
    println!("cargo:rerun-if-changed=tests/ltp-src");

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
    build_ltp_tests(&out_dir);
}

fn build_riscv_tests(out_dir: &Path) {
    let riscv_tests = Path::new("tests/riscv-tests");
    let src_dir = riscv_tests.join("src/isa");

    if !src_dir.join("rv64ui").exists() {
        return; // submodule not initialized
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

fn build_ltp_tests(out_dir: &Path) {
    let ltp_root = Path::new("tests/ltp-src");
    if !ltp_root.join("configure.ac").exists() {
        return;
    }

    let ltp_out = out_dir.join("ltp");
    std::fs::create_dir_all(&ltp_out).unwrap();
    let ltp_work = out_dir.join("ltp-src-work");

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

    let tests = [("read01", Path::new("testcases/kernel/syscalls/read"))];
    let ltp_lib_dir = ltp_work.join("lib");
    let ltp_wldflags = format!("-L{} -static -no-pie", ltp_lib_dir.display());

    for (name, rel_dir) in tests {
        let test_dir = ltp_work.join(rel_dir);
        if let Err(err) = run_command(
            Command::new("make")
                .current_dir(&test_dir)
                .env("CC", "riscv64-linux-gnu-gcc")
                .arg(format!("WLDFLAGS={}", ltp_wldflags))
                .arg(name),
            &format!("build ltp test {}", name),
        ) {
            eprintln!("Failed to build ltp test {}: {}", name, err);
            continue;
        }

        let src = test_dir.join(name);
        let dst = ltp_out.join(name);
        if let Err(err) = std::fs::copy(&src, &dst) {
            eprintln!("Failed to stage ltp test {}: {}", name, err);
        }
    }
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
