use std::time::Duration;
use tidemark_kernel::cpu::block_cache::{BlockCache, BlockEntry};
use tidemark_kernel::harness::TestVm;
use tidemark_kernel::{abi, guest_mem};
use tidemark_kernel_tests::performance::{
    BENCHMARK_CASE_IDS, BENCHMARK_REPORT_PREFIX, BenchmarkIdentity, BenchmarkProtocol,
    ComparisonOptions, compare_saved_runs, comparison_json, fnv1a64_words, parse_saved_run,
    protocol_key, report_json, report_json_with_identity, run_benchmark, summarize_durations,
};

const WARMUP_RUNS: usize = 1;
const MEASUREMENT_RUNS: usize = 5;
const INTEGER_ITERATIONS: u64 = 8_000_000;
const MEMORY_ITERATIONS: u64 = 8_000_000;
const BLOCK_COLLISION_ITERATIONS: u64 = 250_000;
const BLOCK_COLLISION_STRIDE: u64 = 16 * 1024;
const LONG_BLOCK_ITERATIONS: u64 = 1_000_000;

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

fn encode_beq(rs1: u32, rs2: u32, imm: i32) -> u32 {
    let imm = imm as u32;
    ((imm >> 12) & 1) << 31
        | ((imm >> 5) & 0x3f) << 25
        | (rs2 << 20)
        | (rs1 << 15)
        | ((imm >> 1) & 0x0f) << 8
        | ((imm >> 11) & 1) << 7
        | 0x63
}

fn encode_jalr(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0x0fff) << 20) | (rs1 << 15) | (rd << 7) | 0x67
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
    assert!(json.starts_with("{\"schemaVersion\":2,"));
    assert!(json.contains("\"measurementRuns\":3"));
    assert!(json.contains("\"correctness\":\"pass\""));
}

#[test]
fn saved_result_reader_preserves_inventory_and_reports_numeric_differences() {
    fn saved_output(identity: BenchmarkIdentity<'_>, durations: [Duration; 3]) -> String {
        BENCHMARK_CASE_IDS
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let protocol = BenchmarkProtocol {
                    id,
                    witness_hash: 0x1000 + index as u64,
                    unit: "guest-instruction",
                    units_per_run: 1_000,
                    warmup_runs: 1,
                    measurement_runs: durations.len(),
                };
                let summary = summarize_durations(protocol, &durations).unwrap();
                let case_identity = BenchmarkIdentity {
                    engine: if id.contains("-interpreter-") {
                        "interpreter"
                    } else {
                        "cached"
                    },
                    ..identity
                };
                format!(
                    "{}{}",
                    BENCHMARK_REPORT_PREFIX,
                    report_json_with_identity(&summary, case_identity).unwrap()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    let baseline_output = saved_output(
        BenchmarkIdentity {
            engine: "interpreter",
            configuration: "test-configuration",
            artifact: "baseline-artifact",
        },
        [
            Duration::from_micros(10),
            Duration::from_micros(11),
            Duration::from_micros(9),
        ],
    );
    let baseline_output = format!("test complete_fixed_benchmark_run ... {baseline_output}");
    let candidate_output = saved_output(
        BenchmarkIdentity {
            engine: "interpreter",
            configuration: "test-configuration",
            artifact: "candidate-artifact",
        },
        [
            Duration::from_micros(8),
            Duration::from_micros(9),
            Duration::from_micros(7),
        ],
    );
    let baseline = parse_saved_run(&baseline_output).unwrap();
    let candidate = parse_saved_run(&candidate_output).unwrap();
    let comparison = compare_saved_runs(&baseline, &candidate, ComparisonOptions::default())
        .expect("compatible saved runs");

    assert_eq!(comparison.cases.len(), BENCHMARK_CASE_IDS.len());
    assert!(comparison.cases[0].median_units_per_second_delta > 0.0);
    assert!(comparison.cases[0].median_units_per_second_delta_percent > 0.0);
    assert_eq!(
        comparison.cases[0].baseline_coefficient_of_variation,
        baseline[0].coefficient_of_variation
    );
    assert_eq!(
        comparison.cases[0].candidate_coefficient_of_variation,
        candidate[0].coefficient_of_variation
    );
    let json = comparison_json(&comparison);
    assert!(json.contains("\"medianUnitsPerSecondDelta\""));
    assert!(!json.contains("verdict"));
    assert!(!json.contains("pass"));

    let mut reordered = baseline_output.lines().collect::<Vec<_>>();
    reordered.swap(0, 1);
    assert!(parse_saved_run(&reordered.join("\n")).is_err());
    let malformed = baseline_output.replacen("\"elapsedNs\":[10000", "\"elapsedNs\":[0", 1);
    assert!(parse_saved_run(&malformed).is_err());
    let changed_configuration = candidate_output.replace(
        "\"configuration\":\"test-configuration\"",
        "\"configuration\":\"other-configuration\"",
    );
    let changed_configuration = parse_saved_run(&changed_configuration).unwrap();
    assert!(
        compare_saved_runs(
            &baseline,
            &changed_configuration,
            ComparisonOptions::default()
        )
        .is_err()
    );
    assert!(
        compare_saved_runs(
            &baseline,
            &changed_configuration,
            ComparisonOptions {
                allow_configuration_change: true,
                ..ComparisonOptions::default()
            }
        )
        .is_ok()
    );
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
fn synthetic_cached_two_block_collision_benchmark() {
    let mut t = TestVm::new();
    let mut cache = alloc_block_cache();
    let code_a = mmap(
        &mut t,
        BLOCK_COLLISION_STRIDE + 4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
    );
    let code_b = code_a + BLOCK_COLLISION_STRIDE;

    let block_a = [encode_addi(5, 5, 1), encode_jalr(0, 12, 0)];
    let block_b = [
        encode_addi(6, 6, 1),
        encode_addi(10, 10, -1),
        encode_beq(10, 0, 8),
        encode_jalr(0, 11, 0),
    ];
    write_program(&t, code_a, &block_a);
    write_program(&t, code_b, &block_b);

    let witness = [
        block_a[0],
        block_a[1],
        block_b[0],
        block_b[1],
        block_b[2],
        block_b[3],
        BLOCK_COLLISION_STRIDE as u32,
    ];
    let units_per_run = BLOCK_COLLISION_ITERATIONS * 6 - 1;
    let protocol = BenchmarkProtocol {
        id: "kernel-cached-two-block-collision-v1",
        witness_hash: fnv1a64_words(&witness),
        unit: "guest-instruction",
        units_per_run,
        warmup_runs: WARMUP_RUNS,
        measurement_runs: MEASUREMENT_RUNS,
    };

    let summary = run_benchmark(protocol, || {
        t.vm.pc = code_a;
        t.vm.x = [0; 32];
        t.vm.x[10] = BLOCK_COLLISION_ITERATIONS;
        t.vm.x[11] = code_a;
        t.vm.x[12] = code_b;
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
        assert_eq!(t.vm.pc, code_b + block_b.len() as u64 * 4);
        assert_eq!(t.vm.x[5], BLOCK_COLLISION_ITERATIONS);
        assert_eq!(t.vm.x[6], BLOCK_COLLISION_ITERATIONS);
        assert_eq!(t.vm.x[10], 0);
    })
    .expect("two-block collision benchmark must produce a summary");

    println!("TIDEMARK_BENCHMARK {}", report_json(&summary).unwrap());
    assert_eq!(summary.elapsed_ns.len(), MEASUREMENT_RUNS);
    assert!(summary.median_units_per_second.is_finite());
}

#[test]
fn synthetic_cached_long_block_benchmark() {
    let mut t = TestVm::new();
    let mut cache = alloc_block_cache();
    let code = mmap(
        &mut t,
        4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
    );
    let mut program = [encode_addi(5, 5, 1); 32];
    program[30] = encode_addi(10, 10, -1);
    program[31] = encode_bne(10, 0, -124);
    write_program(&t, code, &program);

    let units_per_run = LONG_BLOCK_ITERATIONS * program.len() as u64;
    let protocol = BenchmarkProtocol {
        id: "kernel-cached-long-block-v1",
        witness_hash: fnv1a64_words(&program),
        unit: "guest-instruction",
        units_per_run,
        warmup_runs: WARMUP_RUNS,
        measurement_runs: MEASUREMENT_RUNS,
    };

    let summary = run_benchmark(protocol, || {
        t.vm.pc = code;
        t.vm.x = [0; 32];
        t.vm.x[10] = LONG_BLOCK_ITERATIONS;
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
        assert_eq!(t.vm.x[5], LONG_BLOCK_ITERATIONS * 30);
        assert_eq!(t.vm.x[10], 0);
    })
    .expect("long-block benchmark must produce a summary");

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
fn synthetic_cached_multi_thread_load_store_benchmark() {
    let mut t = TestVm::new();
    let process = unsafe {
        &*((t.base as u64 + t.vm.process_ptr as u64) as *const tidemark_kernel::types::ProcessState)
    };
    process
        .thread_count
        .store(2, std::sync::atomic::Ordering::Release);

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
        id: "kernel-cached-multi-thread-load-store-v1",
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
    .expect("multi-thread load/store benchmark must produce a summary");

    println!("TIDEMARK_BENCHMARK {}", report_json(&summary).unwrap());
    assert_eq!(summary.elapsed_ns.len(), MEASUREMENT_RUNS);
    assert!(summary.median_units_per_second.is_finite());
}

fn run_synthetic_cached_threaded_load_benchmark(multi_threaded: bool, id: &'static str) {
    let mut t = TestVm::new();
    let process = unsafe {
        &*((t.base as u64 + t.vm.process_ptr as u64) as *const tidemark_kernel::types::ProcessState)
    };
    process.thread_count.store(
        u32::from(multi_threaded) + 1,
        std::sync::atomic::Ordering::Release,
    );

    let mut cache = alloc_block_cache();
    let code = mmap(
        &mut t,
        4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
    );
    let data = mmap(&mut t, 4096, abi::PROT_READ | abi::PROT_WRITE);
    let program = [
        encode_load(5, 11, 0),
        encode_addi(6, 6, 1),
        encode_addi(10, 10, -1),
        encode_bne(10, 0, -12),
    ];
    write_program(&t, code, &program);
    let units_per_run = MEMORY_ITERATIONS * program.len() as u64;
    let protocol = BenchmarkProtocol {
        id,
        witness_hash: fnv1a64_words(&program),
        unit: "guest-instruction",
        units_per_run,
        warmup_runs: WARMUP_RUNS,
        measurement_runs: MEASUREMENT_RUNS,
    };

    let summary = run_benchmark(protocol, || {
        unsafe { guest_mem::write_u64(t.base, data, 0x1122_3344_5566_7788) };
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
        assert_eq!(t.vm.x[5], 0x1122_3344_5566_7788);
        assert_eq!(t.vm.x[6], MEMORY_ITERATIONS);
        assert_eq!(t.vm.x[10], 0);
    })
    .expect("threaded load benchmark must produce a summary");

    println!("TIDEMARK_BENCHMARK {}", report_json(&summary).unwrap());
    assert_eq!(summary.elapsed_ns.len(), MEASUREMENT_RUNS);
    assert!(summary.median_units_per_second.is_finite());
}

#[test]
fn synthetic_cached_single_thread_load_benchmark() {
    run_synthetic_cached_threaded_load_benchmark(false, "kernel-cached-single-thread-load-v1");
}

#[test]
fn synthetic_cached_multi_thread_load_benchmark() {
    run_synthetic_cached_threaded_load_benchmark(true, "kernel-cached-multi-thread-load-v1");
}

fn run_synthetic_cached_threaded_store_benchmark(multi_threaded: bool, id: &'static str) {
    let mut t = TestVm::new();
    let process = unsafe {
        &*((t.base as u64 + t.vm.process_ptr as u64) as *const tidemark_kernel::types::ProcessState)
    };
    process.thread_count.store(
        u32::from(multi_threaded) + 1,
        std::sync::atomic::Ordering::Release,
    );

    let mut cache = alloc_block_cache();
    let code = mmap(
        &mut t,
        4096,
        abi::PROT_READ | abi::PROT_WRITE | abi::PROT_EXEC,
    );
    let data = mmap(&mut t, 4096, abi::PROT_READ | abi::PROT_WRITE);
    let program = [
        encode_store(5, 11, 0),
        encode_addi(5, 5, 1),
        encode_addi(10, 10, -1),
        encode_bne(10, 0, -12),
    ];
    write_program(&t, code, &program);
    let units_per_run = MEMORY_ITERATIONS * program.len() as u64;
    let protocol = BenchmarkProtocol {
        id,
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
        t.vm.x[5] = 1;
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
        assert_eq!(t.vm.x[5], MEMORY_ITERATIONS + 1);
        assert_eq!(t.vm.x[10], 0);
        assert_eq!(
            unsafe { guest_mem::read_u64(t.base, data) },
            MEMORY_ITERATIONS
        );
    })
    .expect("threaded store benchmark must produce a summary");

    println!("TIDEMARK_BENCHMARK {}", report_json(&summary).unwrap());
    assert_eq!(summary.elapsed_ns.len(), MEASUREMENT_RUNS);
    assert!(summary.median_units_per_second.is_finite());
}

#[test]
fn synthetic_cached_single_thread_store_benchmark() {
    run_synthetic_cached_threaded_store_benchmark(false, "kernel-cached-single-thread-store-v1");
}

#[test]
fn synthetic_cached_multi_thread_store_benchmark() {
    run_synthetic_cached_threaded_store_benchmark(true, "kernel-cached-multi-thread-store-v1");
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

#[test]
fn complete_fixed_benchmark_run() {
    println!("TIDEMARK_BENCHMARK_RUN_BEGIN schemaVersion=2 cases=11");
    synthetic_cached_integer_mix_benchmark();
    synthetic_cached_two_block_collision_benchmark();
    synthetic_cached_long_block_benchmark();
    synthetic_interpreter_integer_mix_benchmark();
    synthetic_cached_load_store_benchmark();
    synthetic_cached_multi_thread_load_store_benchmark();
    synthetic_cached_single_thread_load_benchmark();
    synthetic_cached_multi_thread_load_benchmark();
    synthetic_cached_single_thread_store_benchmark();
    synthetic_cached_multi_thread_store_benchmark();
    synthetic_interpreter_load_store_benchmark();
    println!("TIDEMARK_BENCHMARK_RUN_END schemaVersion=2 cases=11");
}
