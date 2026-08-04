use std::path::Path;
use std::time::{Duration, Instant};

pub const BENCHMARK_REPORT_SCHEMA_VERSION: u32 = 2;
pub const BENCHMARK_REPORT_PREFIX: &str = "TIDEMARK_BENCHMARK ";
pub const BENCHMARK_CASE_IDS: [&str; 11] = [
    "kernel-cached-integer-mix-v1",
    "kernel-cached-two-block-collision-v1",
    "kernel-cached-long-block-v1",
    "kernel-interpreter-integer-mix-v1",
    "kernel-cached-load-store-v1",
    "kernel-cached-multi-thread-load-store-v1",
    "kernel-cached-single-thread-load-v1",
    "kernel-cached-multi-thread-load-v1",
    "kernel-cached-single-thread-store-v1",
    "kernel-cached-multi-thread-store-v1",
    "kernel-interpreter-load-store-v1",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchmarkProtocol<'a> {
    pub id: &'a str,
    pub witness_hash: u64,
    pub unit: &'a str,
    pub units_per_run: u64,
    pub warmup_runs: usize,
    pub measurement_runs: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchmarkIdentity<'a> {
    pub engine: &'a str,
    pub configuration: &'a str,
    pub artifact: &'a str,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BenchmarkSummary<'a> {
    pub protocol: BenchmarkProtocol<'a>,
    pub elapsed_ns: Vec<u64>,
    pub mean_units_per_second: f64,
    pub median_units_per_second: f64,
    pub min_units_per_second: f64,
    pub max_units_per_second: f64,
    pub sample_standard_deviation: f64,
    pub coefficient_of_variation: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SavedBenchmarkReport {
    pub protocol_key: String,
    pub id: String,
    pub witness_hash: u64,
    pub unit: String,
    pub units_per_run: u64,
    pub warmup_runs: usize,
    pub measurement_runs: usize,
    pub engine: String,
    pub configuration: String,
    pub artifact: String,
    pub elapsed_ns: Vec<u64>,
    pub mean_units_per_second: f64,
    pub median_units_per_second: f64,
    pub min_units_per_second: f64,
    pub max_units_per_second: f64,
    pub sample_standard_deviation: f64,
    pub coefficient_of_variation: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ComparisonOptions {
    pub allow_engine_change: bool,
    pub allow_configuration_change: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CaseComparison {
    pub id: String,
    pub baseline_engine: String,
    pub candidate_engine: String,
    pub baseline_median_units_per_second: f64,
    pub candidate_median_units_per_second: f64,
    pub median_units_per_second_delta: f64,
    pub median_units_per_second_delta_percent: f64,
    pub baseline_coefficient_of_variation: f64,
    pub candidate_coefficient_of_variation: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SavedRunComparison {
    pub baseline_configuration: String,
    pub candidate_configuration: String,
    pub baseline_artifact: String,
    pub candidate_artifact: String,
    pub cases: Vec<CaseComparison>,
}

pub fn validate_protocol(protocol: BenchmarkProtocol<'_>) -> Result<(), String> {
    if protocol.id.is_empty() {
        return Err("id must not be empty".into());
    }
    if protocol.witness_hash == 0 {
        return Err("witness_hash must not be zero".into());
    }
    if protocol.unit.is_empty() {
        return Err("unit must not be empty".into());
    }
    if protocol.units_per_run == 0 {
        return Err("units_per_run must be positive".into());
    }
    if protocol.measurement_runs < 3 {
        return Err("measurement_runs must be at least 3".into());
    }
    Ok(())
}

pub fn protocol_key(protocol: BenchmarkProtocol<'_>) -> Result<String, String> {
    validate_protocol(protocol)?;
    Ok(format!(
        "v{}:{}:{:016x}:{}:{}:{}:{}",
        BENCHMARK_REPORT_SCHEMA_VERSION,
        protocol.id,
        protocol.witness_hash,
        protocol.unit,
        protocol.units_per_run,
        protocol.warmup_runs,
        protocol.measurement_runs,
    ))
}

pub fn fnv1a64_words(words: &[u32]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for word in words {
        for byte in word.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
    }
    hash
}

pub fn summarize_durations<'a>(
    protocol: BenchmarkProtocol<'a>,
    durations: &[Duration],
) -> Result<BenchmarkSummary<'a>, String> {
    validate_protocol(protocol)?;
    if durations.len() != protocol.measurement_runs {
        return Err(format!(
            "expected {} measurement runs, received {}",
            protocol.measurement_runs,
            durations.len(),
        ));
    }

    let elapsed_ns: Vec<u64> = durations
        .iter()
        .map(|duration| {
            u64::try_from(duration.as_nanos())
                .map_err(|_| "elapsed duration does not fit u64 nanoseconds".to_string())
                .and_then(|value| {
                    if value == 0 {
                        Err("elapsed duration must be positive".to_string())
                    } else {
                        Ok(value)
                    }
                })
        })
        .collect::<Result<_, _>>()?;
    let mut throughputs: Vec<f64> = elapsed_ns
        .iter()
        .map(|elapsed| protocol.units_per_run as f64 * 1_000_000_000.0 / *elapsed as f64)
        .collect();
    throughputs.sort_by(f64::total_cmp);

    let mean = throughputs.iter().sum::<f64>() / throughputs.len() as f64;
    let midpoint = throughputs.len() / 2;
    let median = if throughputs.len().is_multiple_of(2) {
        (throughputs[midpoint - 1] + throughputs[midpoint]) / 2.0
    } else {
        throughputs[midpoint]
    };
    let sample_variance = throughputs
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / (throughputs.len() - 1) as f64;
    let sample_standard_deviation = sample_variance.sqrt();

    Ok(BenchmarkSummary {
        protocol,
        elapsed_ns,
        mean_units_per_second: mean,
        median_units_per_second: median,
        min_units_per_second: throughputs[0],
        max_units_per_second: throughputs[throughputs.len() - 1],
        sample_standard_deviation,
        coefficient_of_variation: sample_standard_deviation / mean,
    })
}

pub fn run_benchmark<'a>(
    protocol: BenchmarkProtocol<'a>,
    mut run: impl FnMut(),
) -> Result<BenchmarkSummary<'a>, String> {
    validate_protocol(protocol)?;
    for _ in 0..protocol.warmup_runs {
        run();
    }
    let mut durations = Vec::with_capacity(protocol.measurement_runs);
    for _ in 0..protocol.measurement_runs {
        let started = Instant::now();
        run();
        durations.push(started.elapsed());
    }
    summarize_durations(protocol, &durations)
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

fn default_engine(protocol: BenchmarkProtocol<'_>) -> &'static str {
    if protocol.id.contains("-interpreter-") {
        "interpreter"
    } else {
        "cached"
    }
}

pub fn report_json(summary: &BenchmarkSummary<'_>) -> Result<String, String> {
    let configuration =
        option_env!("TIDEMARK_BENCHMARK_CONFIGURATION_ID").unwrap_or("wasm32-wasip1-cargo-test");
    let artifact = option_env!("TIDEMARK_BENCHMARK_ARTIFACT_ID")
        .unwrap_or(concat!("tidemark-kernel-tests@", env!("CARGO_PKG_VERSION")));
    report_json_with_identity(
        summary,
        BenchmarkIdentity {
            engine: default_engine(summary.protocol),
            configuration,
            artifact,
        },
    )
}

pub fn report_json_with_identity(
    summary: &BenchmarkSummary<'_>,
    identity: BenchmarkIdentity<'_>,
) -> Result<String, String> {
    if identity.engine.is_empty()
        || identity.configuration.is_empty()
        || identity.artifact.is_empty()
    {
        return Err("benchmark identity fields must not be empty".into());
    }
    let key = protocol_key(summary.protocol)?;
    let elapsed = summary
        .elapsed_ns
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        concat!(
            "{{\"schemaVersion\":{},\"protocolKey\":{},\"id\":{},",
            "\"witnessHash\":\"{:016x}\",\"unit\":{},\"unitsPerRun\":{},",
            "\"warmupRuns\":{},\"measurementRuns\":{},\"engine\":{},",
            "\"configuration\":{},\"artifact\":{},\"correctness\":\"pass\",",
            "\"elapsedNs\":[{}],\"meanUnitsPerSecond\":{},",
            "\"medianUnitsPerSecond\":{},\"minUnitsPerSecond\":{},",
            "\"maxUnitsPerSecond\":{},\"sampleStandardDeviation\":{},",
            "\"coefficientOfVariation\":{}}}"
        ),
        BENCHMARK_REPORT_SCHEMA_VERSION,
        json_string(&key),
        json_string(summary.protocol.id),
        summary.protocol.witness_hash,
        json_string(summary.protocol.unit),
        summary.protocol.units_per_run,
        summary.protocol.warmup_runs,
        summary.protocol.measurement_runs,
        json_string(identity.engine),
        json_string(identity.configuration),
        json_string(identity.artifact),
        elapsed,
        summary.mean_units_per_second,
        summary.median_units_per_second,
        summary.min_units_per_second,
        summary.max_units_per_second,
        summary.sample_standard_deviation,
        summary.coefficient_of_variation,
    ))
}

fn object_member<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a serde_json::Value, String> {
    object
        .get(key)
        .ok_or_else(|| format!("benchmark report is missing {key}"))
}

fn string_member(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    object_member(object, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("benchmark report {key} must be a string"))
}

fn u64_member(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, String> {
    object_member(object, key)?
        .as_u64()
        .ok_or_else(|| format!("benchmark report {key} must be an unsigned integer"))
}

fn usize_member(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<usize, String> {
    usize::try_from(u64_member(object, key)?)
        .map_err(|_| format!("benchmark report {key} does not fit usize"))
}

fn f64_member(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<f64, String> {
    let value = object_member(object, key)?
        .as_f64()
        .ok_or_else(|| format!("benchmark report {key} must be numeric"))?;
    if !value.is_finite() {
        return Err(format!("benchmark report {key} must be finite"));
    }
    Ok(value)
}

fn same_float(actual: f64, expected: f64, label: &str) -> Result<(), String> {
    let tolerance = expected.abs().max(1.0) * 1e-12;
    if (actual - expected).abs() > tolerance {
        return Err(format!(
            "benchmark report {label} does not match elapsed samples"
        ));
    }
    Ok(())
}

pub fn parse_report_json(raw: &str) -> Result<SavedBenchmarkReport, String> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|error| error.to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "benchmark report must be a JSON object".to_string())?;
    if u64_member(object, "schemaVersion")? != u64::from(BENCHMARK_REPORT_SCHEMA_VERSION) {
        return Err("benchmark report schema version mismatch".into());
    }
    if string_member(object, "correctness")? != "pass" {
        return Err("benchmark report correctness must be pass".into());
    }
    let id = string_member(object, "id")?;
    let witness = string_member(object, "witnessHash")?;
    if witness.len() != 16 || !witness.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("benchmark report witnessHash must be sixteen hexadecimal digits".into());
    }
    let witness_hash = u64::from_str_radix(&witness, 16)
        .map_err(|_| "benchmark report witnessHash exceeds u64".to_string())?;
    let unit = string_member(object, "unit")?;
    let units_per_run = u64_member(object, "unitsPerRun")?;
    let warmup_runs = usize_member(object, "warmupRuns")?;
    let measurement_runs = usize_member(object, "measurementRuns")?;
    let protocol = BenchmarkProtocol {
        id: &id,
        witness_hash,
        unit: &unit,
        units_per_run,
        warmup_runs,
        measurement_runs,
    };
    validate_protocol(protocol)?;
    let protocol_key_value = string_member(object, "protocolKey")?;
    if protocol_key_value != protocol_key(protocol)? {
        return Err("benchmark report protocol key mismatch".into());
    }
    let elapsed_values = object_member(object, "elapsedNs")?
        .as_array()
        .ok_or_else(|| "benchmark report elapsedNs must be an array".to_string())?;
    let elapsed_ns = elapsed_values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or_else(|| "benchmark elapsed samples must be positive integers".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let durations = elapsed_ns
        .iter()
        .copied()
        .map(Duration::from_nanos)
        .collect::<Vec<_>>();
    let recomputed = summarize_durations(protocol, &durations)?;
    let mean_units_per_second = f64_member(object, "meanUnitsPerSecond")?;
    let median_units_per_second = f64_member(object, "medianUnitsPerSecond")?;
    let min_units_per_second = f64_member(object, "minUnitsPerSecond")?;
    let max_units_per_second = f64_member(object, "maxUnitsPerSecond")?;
    let sample_standard_deviation = f64_member(object, "sampleStandardDeviation")?;
    let coefficient_of_variation = f64_member(object, "coefficientOfVariation")?;
    same_float(
        mean_units_per_second,
        recomputed.mean_units_per_second,
        "meanUnitsPerSecond",
    )?;
    same_float(
        median_units_per_second,
        recomputed.median_units_per_second,
        "medianUnitsPerSecond",
    )?;
    same_float(
        min_units_per_second,
        recomputed.min_units_per_second,
        "minUnitsPerSecond",
    )?;
    same_float(
        max_units_per_second,
        recomputed.max_units_per_second,
        "maxUnitsPerSecond",
    )?;
    same_float(
        sample_standard_deviation,
        recomputed.sample_standard_deviation,
        "sampleStandardDeviation",
    )?;
    same_float(
        coefficient_of_variation,
        recomputed.coefficient_of_variation,
        "coefficientOfVariation",
    )?;
    let engine = string_member(object, "engine")?;
    let configuration = string_member(object, "configuration")?;
    let artifact = string_member(object, "artifact")?;
    if engine.is_empty() || configuration.is_empty() || artifact.is_empty() {
        return Err("benchmark report identity fields must not be empty".into());
    }
    Ok(SavedBenchmarkReport {
        protocol_key: protocol_key_value,
        id,
        witness_hash,
        unit,
        units_per_run,
        warmup_runs,
        measurement_runs,
        engine,
        configuration,
        artifact,
        elapsed_ns,
        mean_units_per_second,
        median_units_per_second,
        min_units_per_second,
        max_units_per_second,
        sample_standard_deviation,
        coefficient_of_variation,
    })
}

pub fn parse_saved_run(output: &str) -> Result<Vec<SavedBenchmarkReport>, String> {
    let reports = output
        .lines()
        .filter_map(|line| {
            line.find(BENCHMARK_REPORT_PREFIX)
                .map(|index| &line[index + BENCHMARK_REPORT_PREFIX.len()..])
        })
        .map(parse_report_json)
        .collect::<Result<Vec<_>, _>>()?;
    validate_saved_run(&reports)?;
    Ok(reports)
}

pub fn read_saved_run(path: impl AsRef<Path>) -> Result<Vec<SavedBenchmarkReport>, String> {
    let output = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    parse_saved_run(&output)
}

pub fn validate_saved_run(reports: &[SavedBenchmarkReport]) -> Result<(), String> {
    if reports.len() != BENCHMARK_CASE_IDS.len() {
        return Err(format!(
            "saved run must contain {} reports, received {}",
            BENCHMARK_CASE_IDS.len(),
            reports.len(),
        ));
    }
    for (index, (report, expected_id)) in reports.iter().zip(BENCHMARK_CASE_IDS).enumerate() {
        if report.id != expected_id {
            return Err(format!(
                "saved run case {} must be {}, received {}",
                index + 1,
                expected_id,
                report.id,
            ));
        }
    }
    let first = &reports[0];
    if reports.iter().any(|report| {
        report.configuration != first.configuration || report.artifact != first.artifact
    }) {
        return Err("saved run must use one configuration and artifact identity".into());
    }
    Ok(())
}

pub fn compare_saved_runs(
    baseline: &[SavedBenchmarkReport],
    candidate: &[SavedBenchmarkReport],
    options: ComparisonOptions,
) -> Result<SavedRunComparison, String> {
    validate_saved_run(baseline)?;
    validate_saved_run(candidate)?;
    if !options.allow_configuration_change
        && baseline[0].configuration != candidate[0].configuration
    {
        return Err("saved run configuration identity changed without explicit permission".into());
    }
    let mut cases = Vec::with_capacity(BENCHMARK_CASE_IDS.len());
    for (baseline_report, candidate_report) in baseline.iter().zip(candidate) {
        if baseline_report.protocol_key != candidate_report.protocol_key {
            return Err(format!("case definition drift for {}", baseline_report.id));
        }
        if !options.allow_engine_change && baseline_report.engine != candidate_report.engine {
            return Err(format!(
                "engine identity changed without explicit permission for {}",
                baseline_report.id
            ));
        }
        let baseline_median = baseline_report.median_units_per_second;
        if baseline_median <= 0.0 {
            return Err(format!(
                "baseline median throughput must be positive for {}",
                baseline_report.id
            ));
        }
        let candidate_median = candidate_report.median_units_per_second;
        let delta = candidate_median - baseline_median;
        cases.push(CaseComparison {
            id: baseline_report.id.clone(),
            baseline_engine: baseline_report.engine.clone(),
            candidate_engine: candidate_report.engine.clone(),
            baseline_median_units_per_second: baseline_median,
            candidate_median_units_per_second: candidate_median,
            median_units_per_second_delta: delta,
            median_units_per_second_delta_percent: 100.0 * delta / baseline_median,
            baseline_coefficient_of_variation: baseline_report.coefficient_of_variation,
            candidate_coefficient_of_variation: candidate_report.coefficient_of_variation,
        });
    }
    Ok(SavedRunComparison {
        baseline_configuration: baseline[0].configuration.clone(),
        candidate_configuration: candidate[0].configuration.clone(),
        baseline_artifact: baseline[0].artifact.clone(),
        candidate_artifact: candidate[0].artifact.clone(),
        cases,
    })
}

pub fn comparison_json(comparison: &SavedRunComparison) -> String {
    let cases = comparison
        .cases
        .iter()
        .map(|case| {
            format!(
                concat!(
                    "{{\"id\":{},\"baselineEngine\":{},\"candidateEngine\":{},",
                    "\"baselineMedianUnitsPerSecond\":{},",
                    "\"candidateMedianUnitsPerSecond\":{},",
                    "\"medianUnitsPerSecondDelta\":{},",
                    "\"medianUnitsPerSecondDeltaPercent\":{},",
                    "\"baselineCoefficientOfVariation\":{},",
                    "\"candidateCoefficientOfVariation\":{}}}"
                ),
                json_string(&case.id),
                json_string(&case.baseline_engine),
                json_string(&case.candidate_engine),
                case.baseline_median_units_per_second,
                case.candidate_median_units_per_second,
                case.median_units_per_second_delta,
                case.median_units_per_second_delta_percent,
                case.baseline_coefficient_of_variation,
                case.candidate_coefficient_of_variation,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        concat!(
            "{{\"baselineConfiguration\":{},\"candidateConfiguration\":{},",
            "\"baselineArtifact\":{},\"candidateArtifact\":{},\"cases\":[{}]}}"
        ),
        json_string(&comparison.baseline_configuration),
        json_string(&comparison.candidate_configuration),
        json_string(&comparison.baseline_artifact),
        json_string(&comparison.candidate_artifact),
        cases,
    )
}
