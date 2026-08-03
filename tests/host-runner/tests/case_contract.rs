use std::time::Duration;
use std::{cell::Cell, hint::black_box};

use tidemark_kernel_host_runner::case::{
    CaseClass, ExecutionCase, ExecutionIdentity, ExpectedCounter, ObservedCounter,
    OperationObservation, accept_case_result, measure_case, raw_result_json,
};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn case() -> ExecutionCase {
    ExecutionCase {
        technical_name: "cpu/interpreter/integer-contract".into(),
        class: CaseClass::Semantic,
        repository_owner: "kernel".into(),
        definition_source_digest: digest('1'),
        input_digest: digest('2'),
        useful_work_unit: "guest-instruction".into(),
        useful_work_count: 8,
        calibrated_repetition_count: 1,
        oracle_contract_digest: digest('3'),
        counter_contract_digest: digest('4'),
        case_schedule_digest: digest('5'),
    }
}

fn identity() -> ExecutionIdentity {
    ExecutionIdentity {
        engine: "interpreter".into(),
        configuration_digest: digest('6'),
        artifact_digest: digest('7'),
    }
}

fn observation() -> OperationObservation {
    OperationObservation {
        oracle: "x5=8;pc=32".into(),
        counters: vec![ObservedCounter {
            name: "instructions".into(),
            value: 8,
        }],
    }
}

fn counters() -> Vec<ExpectedCounter> {
    vec![ExpectedCounter {
        name: "instructions".into(),
        value: 8,
    }]
}

#[test]
fn accepts_exact_case_and_emits_raw_result() {
    let case = case();
    let identity = identity();
    let result = accept_case_result(
        &case,
        case.clone(),
        &identity,
        identity.clone(),
        Duration::from_nanos(125),
        "x5=8;pc=32",
        observation(),
        &counters(),
    )
    .expect("exact case result");
    let json = raw_result_json(&result);
    assert!(json.starts_with("{\"schema\":\"execution-case-result-v1\""));
    assert!(json.contains("\"technical_name\":\"cpu/interpreter/integer-contract\""));
    assert!(json.contains("\"elapsed_ns\":\"125\""));
    assert!(json.contains("\"correctness\":\"pass\""));
    assert!(json.contains("\"expected\":\"8\",\"observed\":\"8\""));
}

#[test]
fn emits_the_canonical_cross_language_raw_case_golden_bytes() {
    let case = ExecutionCase {
        technical_name: "runtime/worker/roundtrip-contract".into(),
        class: CaseClass::Diagnostic,
        repository_owner: "runtime".into(),
        definition_source_digest: digest('1'),
        input_digest: digest('2'),
        useful_work_unit: "worker-roundtrip".into(),
        useful_work_count: 4,
        calibrated_repetition_count: 1,
        oracle_contract_digest: digest('3'),
        counter_contract_digest: digest('4'),
        case_schedule_digest: digest('5'),
    };
    let identity = ExecutionIdentity {
        engine: "interpreter".into(),
        configuration_digest: digest('6'),
        artifact_digest: digest('7'),
    };
    let result = accept_case_result(
        &case,
        case.clone(),
        &identity,
        identity.clone(),
        Duration::from_nanos(125),
        "responses=4",
        OperationObservation {
            oracle: "responses=4".into(),
            counters: vec![ObservedCounter {
                name: "responses".into(),
                value: 4,
            }],
        },
        &[ExpectedCounter {
            name: "responses".into(),
            value: 4,
        }],
    )
    .expect("cross-language golden case");

    assert_eq!(
        raw_result_json(&result),
        "{\"schema\":\"execution-case-result-v1\",\"technical_name\":\"runtime/worker/roundtrip-contract\",\"class\":\"diagnostic\",\"repository_owner\":\"runtime\",\"definition_source_digest\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"input_digest\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"useful_work_unit\":\"worker-roundtrip\",\"useful_work_count\":\"4\",\"calibrated_repetition_count\":\"1\",\"oracle_contract_digest\":\"3333333333333333333333333333333333333333333333333333333333333333\",\"counter_contract_digest\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"case_schedule_digest\":\"5555555555555555555555555555555555555555555555555555555555555555\",\"engine\":\"interpreter\",\"configuration_digest\":\"6666666666666666666666666666666666666666666666666666666666666666\",\"artifact_digest\":\"7777777777777777777777777777777777777777777777777777777777777777\",\"elapsed_ns\":\"125\",\"correctness\":\"pass\",\"oracle_expected\":\"responses=4\",\"oracle_observed\":\"responses=4\",\"counters\":[{\"name\":\"responses\",\"expected\":\"4\",\"observed\":\"4\"}]}"
    );
}

#[test]
fn times_only_the_supplied_operation() {
    let case = case();
    let identity = identity();
    let stage = Cell::new(0);
    let result = measure_case(
        &case,
        case.clone(),
        &identity,
        identity.clone(),
        "x5=8;pc=32",
        &counters(),
        || {
            assert_eq!(stage.replace(1), 0);
            black_box(0..128).for_each(drop);
            12
        },
        |value| {
            assert_eq!(value, 12);
            assert_eq!(stage.replace(2), 1);
            observation()
        },
    )
    .expect("measured exact case result");
    assert_eq!(stage.get(), 2);
    assert!(result.elapsed_ns() > 0);
}

#[test]
fn rejects_oracle_counter_and_identity_drift() {
    let case = case();
    let identity = identity();

    let mut wrong_oracle = observation();
    wrong_oracle.oracle = "x5=7;pc=32".into();
    assert!(
        accept_case_result(
            &case,
            case.clone(),
            &identity,
            identity.clone(),
            Duration::from_nanos(1),
            "x5=8;pc=32",
            wrong_oracle,
            &counters(),
        )
        .unwrap_err()
        .contains("oracle mismatch")
    );

    let mut wrong_counter = observation();
    wrong_counter.counters[0].value = 7;
    assert!(
        accept_case_result(
            &case,
            case.clone(),
            &identity,
            identity.clone(),
            Duration::from_nanos(1),
            "x5=8;pc=32",
            wrong_counter,
            &counters(),
        )
        .unwrap_err()
        .contains("counter mismatch")
    );

    let mut drifted_identity = identity.clone();
    drifted_identity.engine = "alternate-interpreter".into();
    assert!(
        accept_case_result(
            &case,
            case.clone(),
            &identity,
            drifted_identity,
            Duration::from_nanos(1),
            "x5=8;pc=32",
            observation(),
            &counters(),
        )
        .unwrap_err()
        .contains("identity drift")
    );

    let mut drifted_case = case.clone();
    drifted_case.useful_work_count = 7;
    assert!(
        accept_case_result(
            &case,
            drifted_case,
            &identity,
            identity.clone(),
            Duration::from_nanos(1),
            "x5=8;pc=32",
            observation(),
            &counters(),
        )
        .unwrap_err()
        .contains("case identity drift")
    );
}

#[test]
fn rejects_incomplete_results_before_raw_emission() {
    let case = case();
    let identity = identity();

    let mut no_work = case.clone();
    no_work.useful_work_count = 0;
    assert!(
        accept_case_result(
            &no_work,
            no_work.clone(),
            &identity,
            identity.clone(),
            Duration::from_nanos(1),
            "x5=8;pc=32",
            observation(),
            &counters(),
        )
        .unwrap_err()
        .contains("useful_work_count")
    );

    assert!(
        accept_case_result(
            &case,
            case.clone(),
            &identity,
            identity.clone(),
            Duration::ZERO,
            "x5=8;pc=32",
            observation(),
            &counters(),
        )
        .unwrap_err()
        .contains("elapsed duration")
    );

    assert!(
        accept_case_result(
            &case,
            case.clone(),
            &identity,
            identity.clone(),
            Duration::from_nanos(1),
            "x5=8;pc=32",
            OperationObservation {
                oracle: "x5=8;pc=32".into(),
                counters: vec![],
            },
            &[],
        )
        .unwrap_err()
        .contains("at least one exact counter")
    );
}
