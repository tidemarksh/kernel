use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let here = Path::new("tests/fixtures/riscv-tests");
    let src_dir = here.join("riscv-tests-src/isa");

    if !src_dir.join("rv64ui").exists() {
        // Submodule not initialized — skip riscv-tests build
        return;
    }

    // Check if cross compiler is available
    if Command::new("riscv64-linux-gnu-gcc").arg("--version").output().is_err() {
        eprintln!("riscv64-linux-gnu-gcc not found, skipping riscv-tests build");
        return;
    }

    let macros = src_dir.join("macros/scalar");
    let link_ld = here.join("link.ld");

    for suite in &["rv64ui", "rv64um", "rv64ua", "rv64uf", "rv64ud"] {
        let suite_out = out_dir.join(suite);
        std::fs::create_dir_all(&suite_out).unwrap();

        let suite_src = src_dir.join(suite);
        if !suite_src.exists() { continue; }

        for entry in std::fs::read_dir(&suite_src).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().map_or(true, |e| e != "S") { continue; }

            let name = path.file_stem().unwrap().to_str().unwrap();
            let elf_path = suite_out.join(format!("{}.elf", name));

            let status = Command::new("riscv64-linux-gnu-gcc")
                .args(&[
                    "-march=rv64gc", "-mabi=lp64d",
                    "-nostdlib", "-nostartfiles", "-static",
                    "-T", link_ld.to_str().unwrap(),
                    "-I", here.to_str().unwrap(),
                    "-I", macros.to_str().unwrap(),
                    "-o", elf_path.to_str().unwrap(),
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
