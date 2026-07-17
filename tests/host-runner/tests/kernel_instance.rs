use std::path::{Path, PathBuf};

use tidemark_kernel_host_runner::kernel::KernelInstance;

fn artifact() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("Kernel workspace")
        .join("target/wasm64-unknown-unknown/release/tidemark_kernel.wasm")
}

#[test]
fn loads_the_memory64_product_artifact_and_calls_an_export() {
    let mut kernel = KernelInstance::load(&artifact()).expect("Memory64 Kernel instance");
    let page_size = kernel
        .typed_func::<(), i32>("abi_page_size")
        .expect("abi_page_size export");
    assert_eq!(kernel.call(&page_size, ()).unwrap(), 4096);
}

#[test]
fn executes_a_fixed_riscv_program_through_thread_step() {
    let mut kernel = KernelInstance::load(&artifact()).expect("Memory64 Kernel instance");
    let program = [
        0x0050_0293, // addi x5, x0, 5
        0x0072_8313, // addi x6, x5, 7
    ];
    let outcome = kernel.run_program(&program, 2).expect("program outcome");
    assert_eq!(outcome.consumed_budget(), 2);
    assert_eq!(outcome.status, 0);
    assert_eq!(outcome.pc, 0x1_0008);
    assert_eq!(outcome.registers[5], 5);
    assert_eq!(outcome.registers[6], 12);
}
