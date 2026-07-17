use std::time::{Duration, Instant};

pub const CASE_RESULT_SCHEMA: &str = "execution-case-result-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseClass {
    Semantic,
    Diagnostic,
}

impl CaseClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Semantic => "semantic",
            Self::Diagnostic => "diagnostic",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionCase {
    pub technical_name: String,
    pub class: CaseClass,
    pub repository_owner: String,
    pub definition_source_digest: String,
    pub input_digest: String,
    pub useful_work_unit: String,
    pub useful_work_count: u64,
    pub calibrated_repetition_count: u64,
    pub oracle_contract_digest: String,
    pub counter_contract_digest: String,
    pub case_schedule_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionIdentity {
    pub engine: String,
    pub configuration_digest: String,
    pub artifact_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedCounter {
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedCounter {
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationObservation {
    pub oracle: String,
    pub counters: Vec<ObservedCounter>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterResult {
    pub name: String,
    pub expected: u64,
    pub observed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawCaseResult {
    pub case: ExecutionCase,
    pub execution: ExecutionIdentity,
    pub elapsed_ns: u64,
    pub oracle_expected: String,
    pub oracle_observed: String,
    pub counters: Vec<CounterResult>,
}

pub fn measure_case(
    expected_case: &ExecutionCase,
    observed_case: ExecutionCase,
    expected_execution: &ExecutionIdentity,
    observed_execution: ExecutionIdentity,
    oracle_expected: &str,
    counters_expected: &[ExpectedCounter],
    operation: impl FnOnce() -> OperationObservation,
) -> Result<RawCaseResult, String> {
    let started = Instant::now();
    let observation = operation();
    let elapsed = started.elapsed();
    accept_case_result(
        expected_case,
        observed_case,
        expected_execution,
        observed_execution,
        elapsed,
        oracle_expected,
        observation,
        counters_expected,
    )
}

pub fn accept_case_result(
    expected_case: &ExecutionCase,
    observed_case: ExecutionCase,
    expected_execution: &ExecutionIdentity,
    observed_execution: ExecutionIdentity,
    elapsed: Duration,
    oracle_expected: &str,
    observation: OperationObservation,
    counters_expected: &[ExpectedCounter],
) -> Result<RawCaseResult, String> {
    validate_case(expected_case)?;
    validate_case(&observed_case)?;
    validate_execution_identity(expected_execution)?;
    validate_execution_identity(&observed_execution)?;
    if expected_case != &observed_case {
        return Err("case identity drift".into());
    }
    if expected_execution != &observed_execution {
        return Err("engine or configuration identity drift".into());
    }
    if oracle_expected != observation.oracle {
        return Err(format!(
            "oracle mismatch: expected {oracle_expected:?}, observed {:?}",
            observation.oracle
        ));
    }
    validate_expected_counters(counters_expected)?;
    if counters_expected.len() != observation.counters.len() {
        return Err(format!(
            "counter count mismatch: expected {}, observed {}",
            counters_expected.len(),
            observation.counters.len()
        ));
    }
    let mut counters = Vec::with_capacity(counters_expected.len());
    for (expected, observed) in counters_expected.iter().zip(&observation.counters) {
        if expected.name != observed.name || expected.value != observed.value {
            return Err(format!(
                "counter mismatch for {:?}: expected {}={}, observed {}={}",
                expected.name, expected.name, expected.value, observed.name, observed.value
            ));
        }
        counters.push(CounterResult {
            name: expected.name.clone(),
            expected: expected.value,
            observed: observed.value,
        });
    }
    let elapsed_ns = u64::try_from(elapsed.as_nanos())
        .map_err(|_| "elapsed duration does not fit u64 nanoseconds".to_string())?;
    if elapsed_ns == 0 {
        return Err("elapsed duration must be positive".into());
    }
    Ok(RawCaseResult {
        case: observed_case,
        execution: observed_execution,
        elapsed_ns,
        oracle_expected: oracle_expected.to_string(),
        oracle_observed: observation.oracle,
        counters,
    })
}

pub fn raw_result_json(result: &RawCaseResult) -> String {
    let counters = result
        .counters
        .iter()
        .map(|counter| {
            format!(
                "{{\"name\":{},\"expected\":\"{}\",\"observed\":\"{}\"}}",
                json_string(&counter.name),
                counter.expected,
                counter.observed
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        concat!(
            "{{\"schema\":{},\"technical_name\":{},\"class\":{},",
            "\"repository_owner\":{},\"definition_source_digest\":{},",
            "\"input_digest\":{},\"useful_work_unit\":{},",
            "\"useful_work_count\":\"{}\",\"calibrated_repetition_count\":\"{}\",",
            "\"oracle_contract_digest\":{},\"counter_contract_digest\":{},",
            "\"case_schedule_digest\":{},\"engine\":{},",
            "\"configuration_digest\":{},\"artifact_digest\":{},",
            "\"elapsed_ns\":\"{}\",\"correctness\":\"pass\",\"oracle_expected\":{},",
            "\"oracle_observed\":{},\"counters\":[{}]}}"
        ),
        json_string(CASE_RESULT_SCHEMA),
        json_string(&result.case.technical_name),
        json_string(result.case.class.as_str()),
        json_string(&result.case.repository_owner),
        json_string(&result.case.definition_source_digest),
        json_string(&result.case.input_digest),
        json_string(&result.case.useful_work_unit),
        result.case.useful_work_count,
        result.case.calibrated_repetition_count,
        json_string(&result.case.oracle_contract_digest),
        json_string(&result.case.counter_contract_digest),
        json_string(&result.case.case_schedule_digest),
        json_string(&result.execution.engine),
        json_string(&result.execution.configuration_digest),
        json_string(&result.execution.artifact_digest),
        result.elapsed_ns,
        json_string(&result.oracle_expected),
        json_string(&result.oracle_observed),
        counters,
    )
}

fn validate_case(case: &ExecutionCase) -> Result<(), String> {
    validate_technical_name(&case.technical_name, "technical_name")?;
    if !matches!(case.repository_owner.as_str(), "kernel" | "runtime") {
        return Err("repository_owner must be kernel or runtime".into());
    }
    validate_technical_name(&case.useful_work_unit, "useful_work_unit")?;
    if case.useful_work_count == 0 {
        return Err("useful_work_count must be positive".into());
    }
    if case.calibrated_repetition_count == 0 {
        return Err("calibrated_repetition_count must be positive".into());
    }
    for (label, digest) in [
        ("definition_source_digest", &case.definition_source_digest),
        ("input_digest", &case.input_digest),
        ("oracle_contract_digest", &case.oracle_contract_digest),
        ("counter_contract_digest", &case.counter_contract_digest),
        ("case_schedule_digest", &case.case_schedule_digest),
    ] {
        validate_digest(digest, label)?;
    }
    Ok(())
}

fn validate_execution_identity(identity: &ExecutionIdentity) -> Result<(), String> {
    validate_technical_name(&identity.engine, "engine")?;
    validate_digest(&identity.configuration_digest, "configuration_digest")?;
    validate_digest(&identity.artifact_digest, "artifact_digest")
}

fn validate_expected_counters(counters: &[ExpectedCounter]) -> Result<(), String> {
    if counters.is_empty() {
        return Err("at least one exact counter is required".into());
    }
    let mut previous = None;
    for counter in counters {
        validate_technical_name(&counter.name, "counter name")?;
        if previous.is_some_and(|name: &str| name >= counter.name.as_str()) {
            return Err("counter names must be sorted and unique".into());
        }
        previous = Some(counter.name.as_str());
    }
    Ok(())
}

fn validate_technical_name(value: &str, label: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                        || byte == b'_'
                })
        });
    if !valid {
        return Err(format!("{label} is not a stable technical name: {value:?}"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            value if value.is_control() => escaped.push_str(&format!("\\u{:04x}", value as u32)),
            value => escaped.push(value),
        }
    }
    escaped.push('"');
    escaped
}
