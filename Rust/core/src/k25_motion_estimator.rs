use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    GooseError, GooseResult,
    store::{DailyActivityMetricInput, GooseStore, MetricProvenanceInput},
};

pub const K25_IMU_ACTIVITY_ESTIMATE_REPORT_SCHEMA: &str =
    "goose.k25-imu-activity-estimate-report.v1";
pub const GOOSE_STEPS_K25_IMU_ESTIMATE_V0_ID: &str = "goose.steps.k25_imu_estimate.v0";
pub const GOOSE_STEPS_K25_IMU_ESTIMATE_V0_VERSION: &str = "0.1.0";

#[derive(Debug, Clone)]
pub struct K25ImuActivityEstimateOptions {
    pub sample_rate_hz: f64,
    pub peak_threshold_i16: f64,
    pub min_peak_spacing_samples: usize,
    pub min_activity_variance_i16: f64,
    pub min_sample_count: usize,
    pub walking_min_cadence_spm: f64,
    pub running_min_cadence_spm: f64,
    pub date_key: Option<String>,
    pub timezone: Option<String>,
    pub write_metric: bool,
}

impl Default for K25ImuActivityEstimateOptions {
    fn default() -> Self {
        Self {
            sample_rate_hz: 8.0,
            peak_threshold_i16: 0.0,
            min_peak_spacing_samples: 3,
            min_activity_variance_i16: 35.0,
            min_sample_count: 480,
            walking_min_cadence_spm: 35.0,
            running_min_cadence_spm: 155.0,
            date_key: None,
            timezone: None,
            write_metric: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct K25ImuActivityEstimateReport {
    pub schema: String,
    pub generated_by: String,
    pub pass: bool,
    pub database_path: String,
    pub start: String,
    pub end: String,
    pub algorithm_id: String,
    pub algorithm_version: String,
    pub source_kind_if_promoted: String,
    pub promotion_status: String,
    pub user_visible_value_allowed: bool,
    pub sample_rate_hz: f64,
    pub peak_threshold_i16: f64,
    pub min_peak_spacing_samples: usize,
    pub min_activity_variance_i16: f64,
    pub min_sample_count: usize,
    pub device_count: usize,
    pub frame_count: usize,
    pub sample_count: usize,
    pub estimated_steps: i64,
    pub estimated_cadence_spm: Option<f64>,
    pub activity_state_counts: BTreeMap<String, usize>,
    pub sedentary_seconds: f64,
    pub walking_seconds: f64,
    pub running_seconds: f64,
    pub confidence: f64,
    pub date_key: Option<String>,
    pub timezone: Option<String>,
    pub start_time_unix_ms: Option<i64>,
    pub end_time_unix_ms: Option<i64>,
    pub write_metric: bool,
    pub daily_metric_id: Option<String>,
    pub daily_metric_written: bool,
    pub metric_provenance_id: Option<String>,
    pub metric_provenance_written: bool,
    pub quality_flags: Vec<String>,
    pub frames: Vec<K25ImuFrameEstimate>,
    pub issues: Vec<String>,
    pub next_actions: Vec<K25ImuActivityNextAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct K25ImuFrameEstimate {
    pub device_id: String,
    pub ts: i64,
    pub sample_count: usize,
    pub magnitude_mean_i16: f64,
    pub magnitude_stddev_i16: f64,
    pub step_count: i64,
    pub cadence_spm: Option<f64>,
    pub activity_state: String,
    pub quality_flags: Vec<String>,
    pub provenance: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct K25ImuActivityNextAction {
    pub scope: String,
    pub reason: String,
    pub action: String,
}

pub fn run_k25_imu_activity_estimate_for_store(
    store: &GooseStore,
    database_path: &str,
    start: &str,
    end: &str,
    options: K25ImuActivityEstimateOptions,
) -> GooseResult<K25ImuActivityEstimateReport> {
    validate_options(&options)?;
    let start_time_unix_ms = parse_rfc3339_utc_unix_ms(start)
        .ok_or_else(|| GooseError::message("start must be an RFC3339 UTC timestamp"))?;
    let end_time_unix_ms = parse_rfc3339_utc_unix_ms(end)
        .ok_or_else(|| GooseError::message("end must be an RFC3339 UTC timestamp"))?;
    if end_time_unix_ms <= start_time_unix_ms {
        return Err(GooseError::message("end must be after start"));
    }
    let start_s = start_time_unix_ms / 1_000;
    let end_s = end_time_unix_ms / 1_000;
    let samples = store.query_gen4_k25_imu_all(start_s, end_s)?;
    let mut report = run_k25_imu_activity_estimate_from_samples(
        samples,
        database_path,
        start,
        end,
        options,
        start_time_unix_ms,
        end_time_unix_ms,
    )?;
    persist_validated_k25_imu_activity_metric(store, &mut report)?;
    Ok(report)
}

fn run_k25_imu_activity_estimate_from_samples(
    samples: Vec<(String, i64, i64, i64, i64)>,
    database_path: &str,
    start: &str,
    end: &str,
    options: K25ImuActivityEstimateOptions,
    start_time_unix_ms: i64,
    end_time_unix_ms: i64,
) -> GooseResult<K25ImuActivityEstimateReport> {
    let mut issues = Vec::new();
    let mut frames = Vec::new();
    let mut by_device: BTreeMap<String, Vec<(i64, i64, i64, i64)>> = BTreeMap::new();
    for (device_id, ts, x, y, z) in samples {
        by_device.entry(device_id).or_default().push((ts, x, y, z));
    }

    if by_device.is_empty() {
        issues.push("no_k25_imu_samples".to_string());
    }

    let device_count = by_device.len();

    for (device_id, mut device_samples) in by_device {
        device_samples.sort_by_key(|(ts, _, _, _)| *ts);
        let mut by_second: BTreeMap<i64, Vec<(i64, i64, i64)>> = BTreeMap::new();
        for (ts, x, y, z) in device_samples {
            by_second.entry(ts).or_default().push((x, y, z));
        }
        for (ts, triples) in by_second {
            frames.push(estimate_k25_frame(&device_id, ts, triples, &options));
        }
    }

    let sample_count = frames.iter().map(|frame| frame.sample_count).sum::<usize>();
    let estimated_steps = frames.iter().map(|frame| frame.step_count).sum::<i64>();
    let duration_seconds = frames.len() as f64;
    let estimated_cadence_spm = if duration_seconds > 0.0 && estimated_steps > 0 {
        Some(estimated_steps as f64 / duration_seconds * 60.0)
    } else {
        None
    };
    let mut activity_state_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut sedentary_seconds = 0.0;
    let mut walking_seconds = 0.0;
    let mut running_seconds = 0.0;
    for frame in &frames {
        *activity_state_counts.entry(frame.activity_state.clone()).or_insert(0) += 1;
        match frame.activity_state.as_str() {
            "sedentary" => sedentary_seconds += 1.0,
            "walking" => walking_seconds += 1.0,
            "running" => running_seconds += 1.0,
            _ => {}
        }
    }

    if sample_count < options.min_sample_count {
        issues.push("insufficient_k25_imu_sample_count".to_string());
    }
    if frames.is_empty() {
        issues.push("no_k25_imu_frames".to_string());
    }

    let mut quality_flags = frames
        .iter()
        .flat_map(|frame| frame.quality_flags.iter().cloned())
        .collect::<BTreeSet<_>>();
    quality_flags.insert("k25_imu_activity_estimate".to_string());
    quality_flags.insert("local_estimate_unvalidated".to_string());
    if estimated_cadence_spm.is_some_and(|cadence| !(30.0..=230.0).contains(&cadence)) {
        quality_flags.insert("aggregate_cadence_outside_plausible_step_range".to_string());
    }

    issues.sort();
    issues.dedup();
    let pass = !frames.is_empty() && sample_count >= options.min_sample_count && issues.is_empty();
    if pass {
        quality_flags.remove("local_estimate_unvalidated");
        quality_flags.insert("validated_local_estimate".to_string());
    }

    let confidence = k25_imu_confidence(
        pass,
        frames.len(),
        sample_count,
        options.min_sample_count,
        estimated_cadence_spm,
    );

    Ok(K25ImuActivityEstimateReport {
        schema: K25_IMU_ACTIVITY_ESTIMATE_REPORT_SCHEMA.to_string(),
        generated_by: "goose-k25-imu-activity-estimator".to_string(),
        pass,
        database_path: database_path.to_string(),
        start: start.to_string(),
        end: end.to_string(),
        algorithm_id: GOOSE_STEPS_K25_IMU_ESTIMATE_V0_ID.to_string(),
        algorithm_version: GOOSE_STEPS_K25_IMU_ESTIMATE_V0_VERSION.to_string(),
        source_kind_if_promoted: "local_estimate".to_string(),
        promotion_status: if pass {
            "validated_candidate"
        } else if !frames.is_empty() {
            "candidate_unvalidated"
        } else {
            "unavailable"
        }
        .to_string(),
        user_visible_value_allowed: pass,
        sample_rate_hz: options.sample_rate_hz,
        peak_threshold_i16: options.peak_threshold_i16,
        min_peak_spacing_samples: options.min_peak_spacing_samples,
        min_activity_variance_i16: options.min_activity_variance_i16,
        min_sample_count: options.min_sample_count,
        device_count,
        frame_count: frames.len(),
        sample_count,
        estimated_steps,
        estimated_cadence_spm,
        activity_state_counts,
        sedentary_seconds,
        walking_seconds,
        running_seconds,
        confidence,
        date_key: options.date_key.clone(),
        timezone: options.timezone.clone(),
        start_time_unix_ms: Some(start_time_unix_ms),
        end_time_unix_ms: Some(end_time_unix_ms),
        write_metric: options.write_metric,
        daily_metric_id: None,
        daily_metric_written: false,
        metric_provenance_id: None,
        metric_provenance_written: false,
        quality_flags: quality_flags.into_iter().collect(),
        frames,
        next_actions: next_actions(&issues),
        issues,
    })
}

fn persist_validated_k25_imu_activity_metric(
    store: &GooseStore,
    report: &mut K25ImuActivityEstimateReport,
) -> GooseResult<()> {
    if !report.write_metric || !report.pass {
        return Ok(());
    }
    let date_key = report
        .date_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GooseError::message("date_key is required when write_metric is true"))?;
    let timezone = report
        .timezone
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GooseError::message("timezone is required when write_metric is true"))?;
    let start_time_unix_ms = report.start_time_unix_ms.ok_or_else(|| {
        GooseError::message("start must be an RFC3339 UTC timestamp when write_metric is true")
    })?;
    let end_time_unix_ms = report.end_time_unix_ms.ok_or_else(|| {
        GooseError::message("end must be an RFC3339 UTC timestamp when write_metric is true")
    })?;
    if end_time_unix_ms <= start_time_unix_ms {
        return Err(GooseError::message(
            "end must be after start when write_metric is true",
        ));
    }
    let metric_id = daily_activity_metric_id(date_key, timezone);
    let provenance_id = format!("prov-{metric_id}");
    let inputs_json = json!({
        "frame_ids": report.frames.iter().map(|frame| format!("{}:{}", frame.device_id, frame.ts)).collect::<Vec<_>>(),
        "device_count": report.device_count,
        "frame_count": report.frame_count,
        "sample_count": report.sample_count,
        "sample_rate_hz": report.sample_rate_hz,
        "activity_state_counts": report.activity_state_counts,
        "sedentary_seconds": report.sedentary_seconds,
        "walking_seconds": report.walking_seconds,
        "running_seconds": report.running_seconds,
        "estimated_cadence_spm": report.estimated_cadence_spm,
        "peak_threshold_i16": report.peak_threshold_i16,
        "min_peak_spacing_samples": report.min_peak_spacing_samples,
        "min_activity_variance_i16": report.min_activity_variance_i16,
    })
    .to_string();
    let quality_flags_json = serde_json::to_string(&report.quality_flags).map_err(|error| {
        GooseError::message(format!(
            "cannot serialize k25 imu activity quality flags: {error}"
        ))
    })?;
    let provenance_json = json!({
        "algorithm": GOOSE_STEPS_K25_IMU_ESTIMATE_V0_ID,
        "algorithm_version": GOOSE_STEPS_K25_IMU_ESTIMATE_V0_VERSION,
        "source_kind": "local_estimate",
        "date_key": date_key,
        "timezone": timezone,
        "start": report.start,
        "end": report.end,
        "start_time_unix_ms": start_time_unix_ms,
        "end_time_unix_ms": end_time_unix_ms,
        "promotion_status": report.promotion_status,
        "sensor": "gen4_k25_samples.imu_json",
        "sample_rate_hz": report.sample_rate_hz,
    })
    .to_string();

    report.daily_metric_written = store.upsert_daily_activity_metric(DailyActivityMetricInput {
        daily_metric_id: &metric_id,
        date_key,
        timezone,
        start_time_unix_ms,
        end_time_unix_ms,
        steps: Some(report.estimated_steps),
        active_kcal: None,
        resting_kcal: None,
        total_kcal: None,
        average_cadence_spm: report.estimated_cadence_spm,
        source_kind: "local_estimate",
        confidence: report.confidence,
        inputs_json: &inputs_json,
        quality_flags_json: &quality_flags_json,
        provenance_json: &provenance_json,
    })?;
    report.metric_provenance_written = store.upsert_metric_provenance(MetricProvenanceInput {
        provenance_id: &provenance_id,
        metric_scope: "daily_activity",
        metric_id: &metric_id,
        source_kind: "local_estimate",
        source_detail: "validated K25 IMU local step/activity estimate",
        confidence: Some(report.confidence),
        inputs_json: &inputs_json,
        quality_flags_json: &quality_flags_json,
        provenance_json: &provenance_json,
    })?;
    report.daily_metric_id = Some(metric_id);
    report.metric_provenance_id = Some(provenance_id);
    Ok(())
}

fn estimate_k25_frame(
    device_id: &str,
    ts: i64,
    triples: Vec<(i64, i64, i64)>,
    options: &K25ImuActivityEstimateOptions,
) -> K25ImuFrameEstimate {
    let magnitudes = triples
        .iter()
        .map(|(x, y, z)| ((*x as f64).powi(2) + (*y as f64).powi(2) + (*z as f64).powi(2)).sqrt())
        .collect::<Vec<_>>();
    let sample_count = magnitudes.len();
    let mean = mean(&magnitudes);
    let stddev = stddev(&magnitudes, mean);
    let dynamic_threshold = options.peak_threshold_i16.max(mean + 0.12 * stddev);
    let step_count = count_step_peaks(
        &magnitudes,
        dynamic_threshold,
        options.min_peak_spacing_samples,
    ) as i64;
    let cadence_spm = if sample_count > 0 {
        Some(step_count as f64 / options.sample_rate_hz * 60.0)
    } else {
        None
    };
    let activity_state = classify_activity(stddev, cadence_spm, options);
    let mut quality_flags = BTreeSet::new();
    quality_flags.insert("k25_imu_frame_estimate".to_string());
    if sample_count < 8 {
        quality_flags.insert("partial_k25_imu_frame".to_string());
    }
    if stddev < options.min_activity_variance_i16 {
        quality_flags.insert("low_k25_imu_variance".to_string());
    }
    if step_count > 0 && cadence_spm.is_some_and(|cadence| !(30.0..=230.0).contains(&cadence)) {
        quality_flags.insert("frame_cadence_outside_plausible_step_range".to_string());
    }

    K25ImuFrameEstimate {
        device_id: device_id.to_string(),
        ts,
        sample_count,
        magnitude_mean_i16: mean,
        magnitude_stddev_i16: stddev,
        step_count,
        cadence_spm,
        activity_state,
        quality_flags: quality_flags.into_iter().collect(),
        provenance: json!({
            "sensor": "gen4_k25_samples.imu_json",
            "algorithm": GOOSE_STEPS_K25_IMU_ESTIMATE_V0_ID,
            "sample_rate_hz": options.sample_rate_hz,
            "dynamic_threshold_i16": dynamic_threshold,
        }),
    }
}

fn count_step_peaks(values: &[f64], threshold: f64, min_spacing: usize) -> usize {
    let mut peaks = Vec::new();
    for index in 1..values.len().saturating_sub(1) {
        let center = values[index];
        if center <= threshold {
            continue;
        }
        if center <= values[index - 1] || center <= values[index + 1] {
            continue;
        }
        if let Some(last) = peaks.last()
            && index.saturating_sub(*last) < min_spacing {
                if center > values[*last] {
                    *peaks.last_mut().expect("peak exists") = index;
                }
                continue;
            }
        peaks.push(index);
    }
    peaks.len()
}

fn classify_activity(
    stddev: f64,
    cadence_spm: Option<f64>,
    options: &K25ImuActivityEstimateOptions,
) -> String {
    if stddev < options.min_activity_variance_i16 {
        return "sedentary".to_string();
    }
    match cadence_spm {
        Some(cadence) if cadence >= options.running_min_cadence_spm => "running".to_string(),
        Some(cadence) if cadence >= options.walking_min_cadence_spm => "walking".to_string(),
        _ => "sedentary".to_string(),
    }
}

fn k25_imu_confidence(
    pass: bool,
    frame_count: usize,
    sample_count: usize,
    min_sample_count: usize,
    cadence_spm: Option<f64>,
) -> f64 {
    if !pass {
        return 0.0;
    }
    let coverage = (sample_count as f64 / min_sample_count as f64).clamp(0.0, 1.0);
    let cadence_score = cadence_spm
        .map(|cadence| if (35.0..=185.0).contains(&cadence) { 1.0 } else { 0.65 })
        .unwrap_or(0.75);
    let frame_score = (frame_count as f64 / 60.0).clamp(0.0, 1.0);
    (0.45 * coverage + 0.35 * cadence_score + 0.20 * frame_score).clamp(0.0, 1.0)
}

fn next_actions(issues: &[String]) -> Vec<K25ImuActivityNextAction> {
    let mut actions = Vec::new();
    if issues.iter().any(|issue| issue == "no_k25_imu_samples") {
        actions.push(K25ImuActivityNextAction {
            scope: "gen4_k25_samples".to_string(),
            reason: "no_k25_imu_samples".to_string(),
            action: "Capture WHOOP Gen4 historical packets that include K25/K26 pulse-info frames.".to_string(),
        });
    }
    if issues.iter().any(|issue| issue == "insufficient_k25_imu_sample_count") {
        actions.push(K25ImuActivityNextAction {
            scope: "k25_imu_activity_estimate".to_string(),
            reason: "insufficient_k25_imu_sample_count".to_string(),
            action: "Capture a longer continuous WHOOP Gen4 session so K25 IMU has at least one minute of samples.".to_string(),
        });
    }
    actions
}

fn validate_options(options: &K25ImuActivityEstimateOptions) -> GooseResult<()> {
    if !(4.0..=50.0).contains(&options.sample_rate_hz) {
        return Err(GooseError::message("sample_rate_hz must be between 4 and 50"));
    }
    if options.peak_threshold_i16 < 0.0 {
        return Err(GooseError::message("peak_threshold_i16 must be non-negative"));
    }
    if options.min_peak_spacing_samples == 0 {
        return Err(GooseError::message("min_peak_spacing_samples must be greater than zero"));
    }
    if options.min_activity_variance_i16 < 0.0 {
        return Err(GooseError::message("min_activity_variance_i16 must be non-negative"));
    }
    if options.min_sample_count == 0 {
        return Err(GooseError::message("min_sample_count must be greater than zero"));
    }
    Ok(())
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn stddev(values: &[f64], mean: f64) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / (values.len() - 1) as f64;
    variance.sqrt()
}

fn daily_activity_metric_id(date_key: &str, timezone: &str) -> String {
    format!("daily:{timezone}:{date_key}:steps:k25_imu_estimate")
}

fn parse_rfc3339_utc_unix_ms(value: &str) -> Option<i64> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once('T')?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i32>().ok()?;
    let month = date_parts.next()?.parse::<u32>().ok()?;
    let day = date_parts.next()?.parse::<u32>().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<u32>().ok()?;
    let minute = time_parts.next()?.parse::<u32>().ok()?;
    let seconds_part = time_parts.next()?;
    if time_parts.next().is_some() {
        return None;
    }
    let (second_text, fraction_text) = seconds_part
        .split_once('.')
        .map_or((seconds_part, ""), |(seconds, fraction)| (seconds, fraction));
    let second = second_text.parse::<u32>().ok()?;
    let millis = parse_millis_fraction(fraction_text)?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    days.checked_mul(86_400_000)?
            .checked_add(i64::from(hour) * 3_600_000)?
            .checked_add(i64::from(minute) * 60_000)?
            .checked_add(i64::from(second) * 1_000)?
            .checked_add(i64::from(millis))
}

fn parse_millis_fraction(value: &str) -> Option<u32> {
    if value.is_empty() {
        return Some(0);
    }
    if !value.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    let mut millis = 0_u32;
    let mut factor = 100_u32;
    for character in value.chars().take(3) {
        millis += character.to_digit(10)? * factor;
        factor /= 10;
    }
    Some(millis)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month_index = month as i64;
    let day_index = day as i64;
    let doy = (153 * (month_index + if month_index > 2 { -3 } else { 9 }) + 2) / 5 + day_index - 1;
    let doe = yoe as i64 * 365 + yoe as i64 / 4 - yoe as i64 / 100 + doy;
    era as i64 * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_regular_step_peaks() {
        let mut values = vec![100.0; 16];
        for peak in [4, 12] {
            values[peak] = 180.0;
        }
        assert_eq!(count_step_peaks(&values, 120.0, 4), 2);
    }

    #[test]
    fn classifies_low_variance_as_sedentary() {
        let options = K25ImuActivityEstimateOptions::default();
        assert_eq!(classify_activity(5.0, Some(100.0), &options), "sedentary");
    }

    #[test]
    fn parses_rfc3339_utc_millis() {
        assert_eq!(
            parse_rfc3339_utc_unix_ms("2026-06-02T00:00:00.123Z"),
            Some(1_780_358_400_123)
        );
    }
}
