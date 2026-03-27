//! LTP (Linux Test Project) syscall conformance tests.
//!
//! Runs cross-compiled LTP test binaries as RISC-V ELF executables
//! using the same kernel interpreter as riscv-tests.
//!
//! https://github.com/linux-test-project/ltp

mod support;

fn run_ltp(name: &str, elf_bytes: &[u8]) -> Result<(), String> {
    let (code, pc) = support::run_elf_no_cache(elf_bytes)?;
    if code == 0 {
        Ok(())
    } else if code == 32 {
        Err(format!("{} TCONF", name))
    } else {
        Err(format!("{} exit_code={}, last_pc=0x{:x}", name, code, pc))
    }
}

macro_rules! ltp_test {
    ($name:ident, $test:expr) => {
        #[test]
        fn $name() -> Result<(), String> {
            let path = concat!(env!("OUT_DIR"), "/ltp/", $test);
            let bytes = std::fs::read(path).map_err(|e| format!("{} not built: {}", path, e))?;
            run_ltp(stringify!($name), &bytes)
        }
    };
}

include!(concat!(env!("OUT_DIR"), "/ltp_tests_generated.rs"));
