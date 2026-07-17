use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tidemark_kernel_host_runner::case::{
    CaseClass, ExecutionCase, ExecutionIdentity, ExpectedCounter, ObservedCounter,
    OperationObservation, measure_case, raw_result_json,
};
use tidemark_kernel_host_runner::kernel::KernelInstance;

const ADDI: u32 = 0x13;

fn artifact() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("target/wasm64-unknown-unknown/release/tidemark_kernel.wasm")
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn i(opcode: u32, rd: u32, funct3: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

fn r(opcode: u32, rd: u32, funct3: u32, rs1: u32, rs2: u32, funct7: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

fn s(opcode: u32, funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let imm = imm as u32 & 0xfff;
    ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((imm & 0x1f) << 7) | opcode
}

fn b(funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let imm = imm as u32 & 0x1fff;
    (((imm >> 12) & 1) << 31)
        | (((imm >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (((imm >> 1) & 0xf) << 8)
        | (((imm >> 11) & 1) << 7)
        | 0x63
}

fn jal(rd: u32, imm: i32) -> u32 {
    let imm = imm as u32 & 0x1f_ffff;
    (((imm >> 20) & 1) << 31)
        | (((imm >> 1) & 0x3ff) << 21)
        | (((imm >> 11) & 1) << 20)
        | (((imm >> 12) & 0xff) << 12)
        | (rd << 7)
        | 0x6f
}

struct SemanticCase {
    name: &'static str,
    words: Vec<u32>,
    budget: i32,
    expected_status: i32,
    register: usize,
    expected_register: i64,
}

fn semantic_cases() -> Vec<SemanticCase> {
    let mut medium = vec![i(ADDI, 5, 0, 0, 0)];
    medium.extend((0..31).map(|_| i(ADDI, 5, 0, 5, 1)));
    vec![
        SemanticCase {
            name: "integer-straight-line",
            words: vec![i(ADDI, 5, 0, 0, 5), r(0x33, 6, 0, 5, 5, 0)],
            budget: 2,
            expected_status: 0,
            register: 6,
            expected_register: 10,
        },
        SemanticCase {
            name: "integer-multiply",
            words: vec![
                i(ADDI, 5, 0, 0, 6),
                i(ADDI, 6, 0, 0, 7),
                r(0x33, 7, 0, 5, 6, 1),
            ],
            budget: 3,
            expected_status: 0,
            register: 7,
            expected_register: 42,
        },
        SemanticCase {
            name: "floating-arithmetic",
            words: vec![
                i(ADDI, 5, 0, 0, 3),
                (0x69 << 25) | (5 << 15) | (1 << 7) | 0x53,
                (1 << 25) | (1 << 20) | (1 << 15) | (2 << 7) | 0x53,
                (0x61 << 25) | (2 << 15) | (6 << 7) | 0x53,
            ],
            budget: 4,
            expected_status: 0,
            register: 6,
            expected_register: 6,
        },
        SemanticCase {
            name: "compressed-instruction",
            words: vec![0x0295_0295],
            budget: 2,
            expected_status: 0,
            register: 5,
            expected_register: 10,
        },
        SemanticCase {
            name: "branch-taken",
            words: vec![
                i(ADDI, 5, 0, 0, 1),
                b(0, 5, 5, 8),
                i(ADDI, 6, 0, 0, 9),
                i(ADDI, 6, 0, 0, 4),
            ],
            budget: 3,
            expected_status: 0,
            register: 6,
            expected_register: 4,
        },
        SemanticCase {
            name: "branch-not-taken",
            words: vec![i(ADDI, 5, 0, 0, 1), b(1, 5, 5, 8), i(ADDI, 6, 0, 0, 9)],
            budget: 3,
            expected_status: 0,
            register: 6,
            expected_register: 9,
        },
        SemanticCase {
            name: "indirect-call-return",
            words: vec![
                jal(1, 8),
                i(ADDI, 6, 0, 0, 7),
                i(ADDI, 5, 0, 0, 5),
                i(0x67, 0, 0, 1, 0),
            ],
            budget: 4,
            expected_status: 0,
            register: 6,
            expected_register: 7,
        },
        SemanticCase {
            name: "aligned-load-store",
            words: vec![
                i(ADDI, 5, 0, 2, -16),
                i(ADDI, 6, 0, 0, 42),
                s(0x23, 3, 5, 6, 0),
                i(0x03, 7, 3, 5, 0),
            ],
            budget: 4,
            expected_status: 0,
            register: 7,
            expected_register: 42,
        },
        SemanticCase {
            name: "unaligned-page-crossing",
            words: vec![
                i(ADDI, 5, 0, 2, -2048),
                i(ADDI, 5, 0, 5, -2048),
                i(ADDI, 5, 0, 5, -1),
                i(ADDI, 6, 0, 0, 43),
                s(0x23, 3, 5, 6, 0),
                i(0x03, 7, 3, 5, 0),
            ],
            budget: 6,
            expected_status: 0,
            register: 7,
            expected_register: 43,
        },
        SemanticCase {
            name: "floating-load-store",
            words: vec![
                i(ADDI, 5, 0, 2, -32),
                i(ADDI, 6, 0, 0, 44),
                s(0x23, 3, 5, 6, 0),
                i(0x07, 1, 3, 5, 0),
                s(0x27, 3, 5, 1, 8),
                i(0x03, 7, 3, 5, 8),
            ],
            budget: 6,
            expected_status: 0,
            register: 7,
            expected_register: 44,
        },
        SemanticCase {
            name: "atomic-rmw",
            words: vec![
                i(ADDI, 5, 0, 2, -32),
                i(ADDI, 6, 0, 0, 1),
                s(0x23, 3, 5, 6, 0),
                i(ADDI, 6, 0, 0, 2),
                r(0x2f, 7, 3, 5, 6, 0),
                i(0x03, 8, 3, 5, 0),
            ],
            budget: 6,
            expected_status: 0,
            register: 8,
            expected_register: 3,
        },
        SemanticCase {
            name: "short-block",
            words: vec![
                i(ADDI, 5, 0, 0, 1),
                i(ADDI, 5, 0, 5, 1),
                i(ADDI, 5, 0, 5, 1),
                i(ADDI, 5, 0, 5, 1),
            ],
            budget: 4,
            expected_status: 0,
            register: 5,
            expected_register: 4,
        },
        SemanticCase {
            name: "medium-block",
            words: medium,
            budget: 32,
            expected_status: 0,
            register: 5,
            expected_register: 31,
        },
        SemanticCase {
            name: "budget-exhaustion",
            words: vec![i(ADDI, 5, 0, 5, 1), jal(0, -4)],
            budget: 20,
            expected_status: 0,
            register: 5,
            expected_register: 10,
        },
        SemanticCase {
            name: "syscall-boundary",
            words: vec![i(ADDI, 17, 0, 0, 172), 0x0000_0073],
            budget: 2,
            expected_status: 0,
            register: 17,
            expected_register: 172,
        },
        SemanticCase {
            name: "signal-delivery-and-fault-boundaries",
            words: vec![
                i(ADDI, 17, 0, 0, 172), // getpid
                0x0000_0073,
                i(ADDI, 11, 0, 0, 23),  // SIGURG (default ignored)
                i(ADDI, 17, 0, 0, 129), // kill
                0x0000_0073,
                0xffff_ffff, // deterministic SIGILL boundary
            ],
            budget: 6,
            expected_status: 3,
            register: 0,
            expected_register: 0,
        },
    ]
}

#[test]
fn covers_all_kernel_semantic_mechanisms_through_memory64_product_artifact() {
    let artifact = artifact();
    let artifact_digest = digest(&fs::read(&artifact).unwrap());
    let mut emitted = Vec::new();
    for case in semantic_cases() {
        let mut code = Vec::new();
        for word in &case.words {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let input_digest = digest(&code);
        let kernel = RefCell::new(KernelInstance::load(&artifact).unwrap());
        let prepared = kernel.borrow_mut().prepare_program(&code).unwrap();
        let definition = ExecutionCase {
            technical_name: case.name.into(),
            class: CaseClass::Semantic,
            repository_owner: "kernel".into(),
            definition_source_digest: digest(case.name.as_bytes()),
            input_digest,
            useful_work_unit: "guest-instruction".into(),
            useful_work_count: case.budget as u64,
            calibrated_repetition_count: 1,
            oracle_contract_digest: digest(
                format!("{}:{}", case.expected_status, case.expected_register).as_bytes(),
            ),
            counter_contract_digest: digest(b"consumed-guest-instructions"),
            case_schedule_digest: digest(b"single-fixed-sample"),
        };
        let identity = ExecutionIdentity {
            engine: "interpreter".into(),
            configuration_digest: digest(b"memory64-harness-v1"),
            artifact_digest: artifact_digest.clone(),
        };
        let expected = [ExpectedCounter {
            name: "consumed-guest-instructions".into(),
            value: case.budget as u64,
        }];
        let result = measure_case(
            &definition,
            definition.clone(),
            &identity,
            identity.clone(),
            "semantic-oracle-pass",
            &expected,
            || {
                let mut remaining = case.budget;
                for _ in 0..4 {
                    if remaining == 0 {
                        break;
                    }
                    let next = kernel
                        .borrow_mut()
                        .step_program(prepared, remaining)
                        .unwrap();
                    if next == remaining {
                        break;
                    }
                    remaining = next;
                }
                remaining
            },
            |remaining| {
                let outcome = kernel
                    .borrow_mut()
                    .observe_program(prepared, case.budget, remaining)
                    .unwrap();
                assert_eq!(outcome.status, case.expected_status, "{} status", case.name);
                assert_eq!(
                    outcome.registers[case.register], case.expected_register,
                    "{} register",
                    case.name
                );
                OperationObservation {
                    oracle: "semantic-oracle-pass".into(),
                    counters: vec![ObservedCounter {
                        name: "consumed-guest-instructions".into(),
                        value: outcome.consumed_budget() as u64,
                    }],
                }
            },
        )
        .unwrap();
        emitted.push(raw_result_json(&result));
    }
    assert_eq!(emitted.len(), 16);
    assert!(
        emitted
            .iter()
            .all(|row| row.contains("\"correctness\":\"pass\""))
    );
}

struct DiagnosticCase {
    name: &'static str,
    words: Vec<u32>,
    budget: i32,
    counter_export: &'static str,
    counter_name: &'static str,
    expected_delta: u64,
}

#[test]
fn covers_all_kernel_diagnostic_mechanisms_with_exact_counters() {
    let artifact = artifact();
    let artifact_digest = digest(&fs::read(&artifact).unwrap());
    let cases = [
        DiagnosticCase {
            name: "interpreter-fetch-decode-dispatch",
            words: vec![i(ADDI, 17, 0, 0, 172), 0x73],
            budget: 2,
            counter_export: "debug_cpu_profile_interpreter_ops",
            counter_name: "interpreter-operations",
            expected_delta: 1,
        },
        DiagnosticCase {
            name: "cold-block-construction",
            words: vec![i(ADDI, 5, 0, 5, 1)],
            budget: 1,
            counter_export: "debug_cpu_profile_block_builds",
            counter_name: "block-builds",
            expected_delta: 1,
        },
        DiagnosticCase {
            name: "cached-block-reuse",
            words: vec![jal(0, 0)],
            budget: 2,
            counter_export: "debug_cpu_profile_block_hits",
            counter_name: "block-cache-hits",
            expected_delta: 1,
        },
        DiagnosticCase {
            name: "block-invalidation-rebuild",
            words: vec![i(ADDI, 17, 0, 0, 259), 0x73, jal(0, -8)],
            budget: 8,
            counter_export: "debug_cpu_profile_block_builds",
            counter_name: "block-builds",
            expected_delta: 2,
        },
        DiagnosticCase {
            name: "permission-cache-hit-miss",
            words: vec![
                i(ADDI, 5, 0, 2, -32),
                i(0x03, 6, 3, 5, 0),
                i(0x03, 7, 3, 5, 0),
            ],
            budget: 3,
            counter_export: "debug_memory_permit_cache_hits",
            counter_name: "permission-cache-hits",
            expected_delta: 1,
        },
        DiagnosticCase {
            name: "vma-hit-denial",
            words: vec![i(0x03, 6, 3, 0, 0)],
            budget: 1,
            counter_export: "debug_memory_permit_denied",
            counter_name: "permission-denials",
            expected_delta: 1,
        },
    ];
    let mut emitted = Vec::new();
    for case in cases {
        let mut code = Vec::new();
        for word in &case.words {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let kernel = RefCell::new(KernelInstance::load(&artifact).unwrap());
        let prepared = kernel.borrow_mut().prepare_program(&code).unwrap();
        let before = kernel.borrow_mut().counter(case.counter_export).unwrap();
        let definition = ExecutionCase {
            technical_name: case.name.into(),
            class: CaseClass::Diagnostic,
            repository_owner: "kernel".into(),
            definition_source_digest: digest(case.name.as_bytes()),
            input_digest: digest(&code),
            useful_work_unit: "guest-instruction".into(),
            useful_work_count: case.budget as u64,
            calibrated_repetition_count: 1,
            oracle_contract_digest: digest(b"diagnostic-step-completed"),
            counter_contract_digest: digest(
                format!("{}={}", case.counter_name, case.expected_delta).as_bytes(),
            ),
            case_schedule_digest: digest(b"single-fixed-sample"),
        };
        let identity = ExecutionIdentity {
            engine: "interpreter".into(),
            configuration_digest: digest(b"memory64-harness-v1"),
            artifact_digest: artifact_digest.clone(),
        };
        let expected = [ExpectedCounter {
            name: case.counter_name.into(),
            value: case.expected_delta,
        }];
        let result = measure_case(
            &definition,
            definition.clone(),
            &identity,
            identity.clone(),
            "diagnostic-step-completed",
            &expected,
            || {
                kernel
                    .borrow_mut()
                    .step_program(prepared, case.budget)
                    .unwrap()
            },
            |_| {
                let after = kernel.borrow_mut().counter(case.counter_export).unwrap();
                OperationObservation {
                    oracle: "diagnostic-step-completed".into(),
                    counters: vec![ObservedCounter {
                        name: case.counter_name.into(),
                        value: after - before,
                    }],
                }
            },
        )
        .unwrap();
        emitted.push(raw_result_json(&result));
    }
    assert_eq!(emitted.len(), 6);
    assert!(
        emitted
            .iter()
            .all(|row| row.contains("\"class\":\"diagnostic\""))
    );
}
