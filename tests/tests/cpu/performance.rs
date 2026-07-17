use std::time::Duration;
use tidemark_kernel::cpu::block_cache::{BlockCache, BlockEntry};
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::{abi, guest_mem};
use tidemark_kernel_tests::performance::{
    BenchmarkProtocol, fnv1a64_words, protocol_key, report_json, run_benchmark, summarize_durations,
};

const WARMUP_RUNS: usize = 1;
const MEASUREMENT_RUNS: usize = 5;
const INTEGER_ITERATIONS: u64 = 8_000_000;
const MEMORY_ITERATIONS: u64 = 8_000_000;

fn alloc_block_cache() -> BlockCache {
    let alloc_size = BlockCache::allocation_size();
    let cache_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(alloc_size as u32, 8) };
    assert!(cache_ptr != 0);
    unsafe { BlockCache::from_ptr(cache_ptr as *mut BlockEntry) }
}

fn mmap(t: &mut TestVm, len: u64, prot: i32) -> u64 {
    let addr = t.sys_mmap(0, len, prot, abi::MAP_ANONYMOUS | abi::MAP_PRIVATE, -1, 0);
    assert!(addr > 0, "mmap failed: {addr}");
    addr as u64
}

fn encode_add(rd: u32, rs1: u32, rs2: u32) -> u32 {
    (rs2 << 20) | (rs1 << 15) | (rd << 7) | 0x33
}

fn encode_xor(rd: u32, rs1: u32, rs2: u32) -> u32 {
    (rs2 << 20) | (rs1 << 15) | (4 << 12) | (rd << 7) | 0x33
}

fn encode_addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0x0fff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
}

fn encode_load(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0x0fff) << 20) | (rs1 << 15) | (3 << 12) | (rd << 7) | 0x03
}

fn encode_store(rs2: u32, rs1: u32, imm: i32) -> u32 {
    let imm = imm as u32 & 0x0fff;
    ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | ((imm & 0x1f) << 7) | 0x23
}

fn encode_bne(rs1: u32, rs2: u32, imm: i32) -> u32 {
    let imm = imm as u32;
    ((imm >> 12) & 1) << 31
        | ((imm >> 5) & 0x3f) << 25
        | (rs2 << 20)
        | (rs1 << 15)
        | (1 << 12)
        | ((imm >> 1) & 0x0f) << 8
        | ((imm >> 11) & 1) << 7
        | 0x63
}

fn write_program(t: &TestVm, code: u64, words: &[u32]) {
    for (index, word) in words.iter().enumerate() {
        unsafe { guest_mem::write_u32(t.base, code + (index as u64 * 4), *word) };
    }
}

#[test]
fn benchmark_protocol_rejects_drift_and_reports_repeat_statistics() {
    let protocol = BenchmarkProtocol {
        id: "synthetic-protocol-self-test-v1",
        witness_hash: 0x1234,
        unit: "guest-instruction",
        units_per_run: 1_000,
        warmup_runs: 1,
        measurement_runs: 3,
    };
    let summary = summarize_durations(
        protocol,
        &[
            Duration::from_micros(10),
            Duration::from_micros(11),
            Duration::from_micros(9),
        ],
    )
    .expect("valid synthetic summary");

    assert!(protocol_key(protocol).unwrap().contains("0000000000001234"));
    assert_eq!(summary.elapsed_ns, vec![10_000, 11_000, 9_000]);
    assert!(summary.coefficient_of_variation > 0.09);
    assert!(summary.coefficient_of_variation < 0.11);
    let json = report_json(&summary).unwrap();
    assert!(json.starts_with("{\"schemaVersion\":1,"));
    assert!(json.contains("\"measurementRuns\":3"));
}

#[test]
fn synthetic_cached_integer_mix_benchmark() {
    let mut t = TestVm::new();
    let mut cache = alloc_block_cache();
    let code = mmap(
        &mut t,
        4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
    );
    let program = [
        encode_addi(5, 5, 1),
        encode_add(6, 6, 5),
        encode_xor(7, 7, 6),
        encode_addi(8, 8, 3),
        encode_add(9, 9, 8),
        encode_addi(10, 10, -1),
        encode_bne(10, 0, -24),
    ];
    write_program(&t, code, &program);
    let units_per_run = INTEGER_ITERATIONS * program.len() as u64;
    let protocol = BenchmarkProtocol {
        id: "kernel-cached-integer-mix-v1",
        witness_hash: fnv1a64_words(&program),
        unit: "guest-instruction",
        units_per_run,
        warmup_runs: WARMUP_RUNS,
        measurement_runs: MEASUREMENT_RUNS,
    };

    let summary = run_benchmark(protocol, || {
        t.vm.pc = code;
        t.vm.x = [0; 32];
        t.vm.x[10] = INTEGER_ITERATIONS;
        t.vm.status = abi::STATUS_OK;
        let remaining = unsafe {
            tidemark_kernel::cpu::exec_at_base(
                &mut t.vm,
                units_per_run as i32,
                t.base,
                Some(&mut cache),
                None,
                None,
                None,
            )
        };
        assert_eq!(remaining, 0);
        assert_eq!(t.vm.status, abi::STATUS_OK);
        assert_eq!(t.vm.pc, code + program.len() as u64 * 4);
        assert_eq!(t.vm.x[10], 0);
    })
    .expect("integer benchmark must produce a summary");

    println!("TIDEMARK_BENCHMARK {}", report_json(&summary).unwrap());
    assert_eq!(summary.elapsed_ns.len(), MEASUREMENT_RUNS);
    assert!(summary.median_units_per_second.is_finite());
}

#[test]
fn synthetic_interpreter_integer_mix_benchmark() {
    let mut t = TestVm::new();
    let code = mmap(
        &mut t,
        4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
    );
    let program = [
        encode_addi(5, 5, 1),
        encode_add(6, 6, 5),
        encode_xor(7, 7, 6),
        encode_addi(8, 8, 3),
        encode_add(9, 9, 8),
        encode_addi(10, 10, -1),
        encode_bne(10, 0, -24),
    ];
    write_program(&t, code, &program);
    let units_per_run = INTEGER_ITERATIONS * program.len() as u64;
    let protocol = BenchmarkProtocol {
        id: "kernel-interpreter-integer-mix-v1",
        witness_hash: fnv1a64_words(&program),
        unit: "guest-instruction",
        units_per_run,
        warmup_runs: WARMUP_RUNS,
        measurement_runs: MEASUREMENT_RUNS,
    };

    let summary = run_benchmark(protocol, || {
        t.vm.pc = code;
        t.vm.x = [0; 32];
        t.vm.x[10] = INTEGER_ITERATIONS;
        t.vm.status = abi::STATUS_OK;
        let remaining = unsafe {
            tidemark_kernel::cpu::exec_at_base(
                &mut t.vm,
                units_per_run as i32,
                t.base,
                None,
                None,
                None,
                None,
            )
        };
        assert_eq!(remaining, 0);
        assert_eq!(t.vm.status, abi::STATUS_OK);
        assert_eq!(t.vm.pc, code + program.len() as u64 * 4);
        assert_eq!(t.vm.x[10], 0);
    })
    .expect("interpreter integer benchmark must produce a summary");

    println!("TIDEMARK_BENCHMARK {}", report_json(&summary).unwrap());
    assert_eq!(summary.elapsed_ns.len(), MEASUREMENT_RUNS);
    assert!(summary.median_units_per_second.is_finite());
}

#[test]
fn synthetic_cached_load_store_benchmark() {
    let mut t = TestVm::new();
    let mut cache = alloc_block_cache();
    let code = mmap(
        &mut t,
        4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
    );
    let data = mmap(&mut t, 4096, abi::PROT_READ | abi::PROT_WRITE);
    let program = [
        encode_load(5, 11, 0),
        encode_addi(5, 5, 1),
        encode_store(5, 11, 0),
        encode_addi(10, 10, -1),
        encode_bne(10, 0, -16),
    ];
    write_program(&t, code, &program);
    let units_per_run = MEMORY_ITERATIONS * program.len() as u64;
    let protocol = BenchmarkProtocol {
        id: "kernel-cached-load-store-v1",
        witness_hash: fnv1a64_words(&program),
        unit: "guest-instruction",
        units_per_run,
        warmup_runs: WARMUP_RUNS,
        measurement_runs: MEASUREMENT_RUNS,
    };

    let summary = run_benchmark(protocol, || {
        unsafe { guest_mem::write_u64(t.base, data, 0) };
        t.vm.pc = code;
        t.vm.x = [0; 32];
        t.vm.x[10] = MEMORY_ITERATIONS;
        t.vm.x[11] = data;
        t.vm.status = abi::STATUS_OK;
        let remaining = unsafe {
            tidemark_kernel::cpu::exec_at_base(
                &mut t.vm,
                units_per_run as i32,
                t.base,
                Some(&mut cache),
                None,
                None,
                None,
            )
        };
        assert_eq!(remaining, 0);
        assert_eq!(t.vm.status, abi::STATUS_OK);
        assert_eq!(t.vm.pc, code + program.len() as u64 * 4);
        assert_eq!(t.vm.x[10], 0);
        assert_eq!(
            unsafe { guest_mem::read_u64(t.base, data) },
            MEMORY_ITERATIONS
        );
    })
    .expect("load/store benchmark must produce a summary");

    println!("TIDEMARK_BENCHMARK {}", report_json(&summary).unwrap());
    assert_eq!(summary.elapsed_ns.len(), MEASUREMENT_RUNS);
    assert!(summary.median_units_per_second.is_finite());
}

#[test]
fn synthetic_interpreter_load_store_benchmark() {
    let mut t = TestVm::new();
    let code = mmap(
        &mut t,
        4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
    );
    let data = mmap(&mut t, 4096, abi::PROT_READ | abi::PROT_WRITE);
    let program = [
        encode_load(5, 11, 0),
        encode_addi(5, 5, 1),
        encode_store(5, 11, 0),
        encode_addi(10, 10, -1),
        encode_bne(10, 0, -16),
    ];
    write_program(&t, code, &program);
    let units_per_run = MEMORY_ITERATIONS * program.len() as u64;
    let protocol = BenchmarkProtocol {
        id: "kernel-interpreter-load-store-v1",
        witness_hash: fnv1a64_words(&program),
        unit: "guest-instruction",
        units_per_run,
        warmup_runs: WARMUP_RUNS,
        measurement_runs: MEASUREMENT_RUNS,
    };

    let summary = run_benchmark(protocol, || {
        unsafe { guest_mem::write_u64(t.base, data, 0) };
        t.vm.pc = code;
        t.vm.x = [0; 32];
        t.vm.x[10] = MEMORY_ITERATIONS;
        t.vm.x[11] = data;
        t.vm.status = abi::STATUS_OK;
        let remaining = unsafe {
            tidemark_kernel::cpu::exec_at_base(
                &mut t.vm,
                units_per_run as i32,
                t.base,
                None,
                None,
                None,
                None,
            )
        };
        assert_eq!(remaining, 0);
        assert_eq!(t.vm.status, abi::STATUS_OK);
        assert_eq!(t.vm.pc, code + program.len() as u64 * 4);
        assert_eq!(t.vm.x[10], 0);
        assert_eq!(
            unsafe { guest_mem::read_u64(t.base, data) },
            MEMORY_ITERATIONS
        );
    })
    .expect("interpreter load/store benchmark must produce a summary");

    println!("TIDEMARK_BENCHMARK {}", report_json(&summary).unwrap());
    assert_eq!(summary.elapsed_ns.len(), MEASUREMENT_RUNS);
    assert!(summary.median_units_per_second.is_finite());
}
