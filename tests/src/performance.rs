use std::time::{Duration, Instant};

pub const BENCHMARK_REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchmarkProtocol<'a> {
    pub id: &'a str,
    pub witness_hash: u64,
    pub unit: &'a str,
    pub units_per_run: u64,
    pub warmup_runs: usize,
    pub measurement_runs: usize,
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

pub fn report_json(summary: &BenchmarkSummary<'_>) -> Result<String, String> {
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
            "\"warmupRuns\":{},\"measurementRuns\":{},\"elapsedNs\":[{}],",
            "\"meanUnitsPerSecond\":{},\"medianUnitsPerSecond\":{},",
            "\"minUnitsPerSecond\":{},\"maxUnitsPerSecond\":{},",
            "\"sampleStandardDeviation\":{},\"coefficientOfVariation\":{}}}"
        ),
        BENCHMARK_REPORT_SCHEMA_VERSION,
        json_string(&key),
        json_string(summary.protocol.id),
        summary.protocol.witness_hash,
        json_string(summary.protocol.unit),
        summary.protocol.units_per_run,
        summary.protocol.warmup_runs,
        summary.protocol.measurement_runs,
        elapsed,
        summary.mean_units_per_second,
        summary.median_units_per_second,
        summary.min_units_per_second,
        summary.max_units_per_second,
        summary.sample_standard_deviation,
        summary.coefficient_of_variation,
    ))
}
