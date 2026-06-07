//! Schema-driven decoder for WHOOP 4.0 (Gen4) frames.
//!
//! This is a faithful Rust port of the `my-whoop` reference decoder
//! (`Packages/WhoopProtocol`: `Interpreter.swift`, `PostHooks.swift`, `Schema.swift`),
//! driven by the same `whoop_protocol.json` schema (vendored alongside this module). Decode
//! and stream-extraction parity is verified against my-whoop's golden vectors in
//! `gen4_parity_tests` / `gen4_streams_parity_tests`. It exists so the Goose Rust core can
//! decode a WHOOP 4.0 device's frames; the v5 path in `protocol.rs` is untouched.
//!
//! Gen4 frame layout (the schema's field offsets are FRAME-ABSOLUTE for exactly this layout):
//! `[0xAA][len u16 LE][crc8(len)][type][seq][cmd?][payload..][crc32 LE]`, where `len` is the
//! value of the 2-byte length field and the total frame length is `len + 4`.
//!
//! Parity is validated against `my-whoop`'s golden vectors in `gen4_parity_tests`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{GooseError, GooseResult};

/// Canonical decode schema, vendored from my-whoop's `protocol/whoop_protocol.json`.
const SCHEMA_JSON: &str = include_str!("whoop_protocol.json");

// ---------------------------------------------------------------------------
// Schema model (mirrors Schema.swift's Raw* decodables)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct FieldSpec {
    off: usize,
    /// Field byte length from the schema. Retained for fidelity / future `fields[]` output;
    /// the `parsed` decode keys off `off`+`dtype` only.
    #[allow(dead_code)]
    len: usize,
    dtype: Option<String>,
    name: String,
    cat: String,
    #[serde(rename = "enum")]
    enum_key: Option<String>,
    /// Field annotation from the schema; not part of the `parsed` output.
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VariantSpec {
    kind: String,
    #[allow(dead_code)]
    note: Option<String>,
    hr_off: Option<usize>,
    rr_count_off: Option<usize>,
    rr_first_off: Option<usize>,
    samples: Option<usize>,
    /// Heterogeneous `[name, off, cat]` triples in the JSON.
    axes: Option<Vec<(String, usize, String)>>,
    tail_from: Option<usize>,
    ppg_off: Option<usize>,
    ppg_stride: Option<usize>,
    ppg_samples: Option<usize>,
    config_from: Option<usize>,
    #[allow(dead_code)]
    config_to: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct VersionSpec {
    #[allow(dead_code)]
    kind: Option<String>,
    #[serde(default)]
    fields: Vec<FieldSpec>,
    rr_first_off: Option<usize>,
    #[serde(rename = "ref")]
    ref_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PacketSpec {
    #[serde(rename = "type")]
    type_id: u8,
    #[serde(default)]
    aliases: Vec<u8>,
    post: Option<String>,
    #[serde(default)]
    fields: Vec<FieldSpec>,
    #[serde(default)]
    variants: BTreeMap<String, VariantSpec>,
    #[serde(default)]
    versions: BTreeMap<String, VersionSpec>,
}

#[derive(Debug, Deserialize)]
struct Schema {
    enums: BTreeMap<String, BTreeMap<String, String>>,
    #[allow(dead_code)]
    envelope: Vec<FieldSpec>,
    packets: BTreeMap<String, PacketSpec>,
    #[serde(skip)]
    by_type: BTreeMap<u8, String>,
}

impl Schema {
    fn build_index(&mut self) {
        let mut idx = BTreeMap::new();
        for (name, spec) in &self.packets {
            idx.insert(spec.type_id, name.clone());
            for alias in &spec.aliases {
                idx.insert(*alias, name.clone());
            }
        }
        self.by_type = idx;
    }

    fn type_name(&self, v: u8) -> String {
        self.enums
            .get("PacketType")
            .and_then(|m| m.get(&v.to_string()))
            .cloned()
            .unwrap_or_else(|| format!("type{v}"))
    }

    /// `"NAME(v)"`, or `"0xXX(d)"` when the value is not in the enum (mirrors Schema.enumName).
    fn enum_name(&self, enum_key: &str, v: i64) -> String {
        if let Some(name) = self.enums.get(enum_key).and_then(|m| m.get(&v.to_string())) {
            format!("{name}({v})")
        } else {
            format!("0x{v:02X}({v})")
        }
    }

    fn packet(&self, type_id: u8) -> Option<&PacketSpec> {
        self.by_type.get(&type_id).and_then(|n| self.packets.get(n))
    }
}

fn schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let mut s: Schema = serde_json::from_str(SCHEMA_JSON)
            .expect("vendored whoop_protocol.json is valid");
        s.build_index();
        s
    })
}

/// Resolve a type-47 version layout, following a `ref` chain (V12 -> V24). Returns
/// `(fields, rr_first_off)`. Mirrors Schema.resolveVersion.
fn resolve_version<'a>(
    versions: &'a BTreeMap<String, VersionSpec>,
    version: u8,
) -> Option<(&'a [FieldSpec], Option<usize>)> {
    let mut key = version.to_string();
    let mut seen: Vec<String> = Vec::new();
    let mut fields: Option<&[FieldSpec]> = None;
    let mut rr_first: Option<usize> = None;
    loop {
        let entry = versions.get(&key)?;
        if fields.is_none() && !entry.fields.is_empty() {
            fields = Some(&entry.fields);
        }
        if rr_first.is_none() {
            rr_first = entry.rr_first_off;
        }
        match &entry.ref_key {
            Some(r) if !seen.contains(r) && versions.contains_key(r) => {
                seen.push(r.clone());
                key = r.clone();
            }
            _ => break,
        }
    }
    // A version entry always resolves (even generic-only) as long as the key existed.
    Some((fields.unwrap_or(&[]), rr_first))
}

// ---------------------------------------------------------------------------
// Decoded output
// ---------------------------------------------------------------------------

/// A decoded Gen4 frame. `parsed` mirrors my-whoop's flat `parsed` dict; numeric values
/// are stored as `serde_json::Value` (ints as integers, f32/means/percentages as floats).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Gen4Frame {
    pub ok: bool,
    pub type_name: String,
    pub seq: Option<u8>,
    pub cmd_name: Option<String>,
    pub crc_ok: Option<bool>,
    pub len_bytes: usize,
    pub raw_hex: String,
    pub parsed: BTreeMap<String, Value>,
}

// ---------------------------------------------------------------------------
// Low-level little-endian readers (None when out of range; mirror interpreter._read)
// ---------------------------------------------------------------------------

fn u8_at(f: &[u8], off: usize) -> Option<i64> {
    f.get(off).map(|b| *b as i64)
}
fn u16_at(f: &[u8], off: usize) -> Option<i64> {
    if off + 2 <= f.len() {
        Some(f[off] as i64 | ((f[off + 1] as i64) << 8))
    } else {
        None
    }
}
fn u32_at(f: &[u8], off: usize) -> Option<i64> {
    if off + 4 <= f.len() {
        Some(
            f[off] as i64
                | ((f[off + 1] as i64) << 8)
                | ((f[off + 2] as i64) << 16)
                | ((f[off + 3] as i64) << 24),
        )
    } else {
        None
    }
}
fn i16_at(f: &[u8], off: usize) -> Option<i64> {
    if off + 2 <= f.len() {
        let raw = f[off] as u16 | ((f[off + 1] as u16) << 8);
        Some(raw as i16 as i64)
    } else {
        None
    }
}
/// Signed 24-bit little-endian (mirrors interpreter._read "s24").
fn s24_at(f: &[u8], off: usize) -> Option<i64> {
    if off + 3 <= f.len() {
        let v = f[off] as i64 | ((f[off + 1] as i64) << 8) | ((f[off + 2] as i64) << 16);
        Some(if v & 0x80_0000 != 0 { v - 0x100_0000 } else { v })
    } else {
        None
    }
}
/// IEEE-754 float32 LE -> f64 (exact, no rounding).
fn f32_at(f: &[u8], off: usize) -> Option<f64> {
    u32_at(f, off).map(|bits| f32::from_bits(bits as u32) as f64)
}
fn read_dtype_int(f: &[u8], off: usize, dtype: &str) -> Option<i64> {
    match dtype {
        "u8" => u8_at(f, off),
        "u16" => u16_at(f, off),
        "u32" => u32_at(f, off),
        "i16" => i16_at(f, off),
        _ => None,
    }
}

/// Read `count` signed i16 LE at `off`, clamping to available bytes (mirrors _i16_block).
fn i16_block(f: &[u8], off: usize, count: usize) -> Vec<i64> {
    let mut n = count;
    if off + n * 2 > f.len() {
        n = if f.len() > off { (f.len() - off) / 2 } else { 0 };
    }
    (0..n).map(|i| i16_at(f, off + i * 2).unwrap()).collect()
}

// ---------------------------------------------------------------------------
// Rounding: match Python's round(x, 1) exactly (mirrors PostHooks.round1)
// ---------------------------------------------------------------------------

fn two_product(a: f64, b: f64) -> (f64, f64) {
    let p = a * b;
    let split = 134_217_729.0_f64; // 2^27 + 1
    let ca = split * a;
    let ah = ca - (ca - a);
    let al = a - ah;
    let cb = split * b;
    let bh = cb - (cb - b);
    let bl = b - bh;
    let err = ((ah * bh - p) + ah * bl + al * bh) + al * bl;
    (p, err)
}

fn round1(x: f64) -> f64 {
    let y = x * 10.0;
    let fl = y.floor();
    let frac = y - fl;
    if (frac - 0.5).abs() >= 1e-14 {
        // round half to even
        return round_ties_even(y) / 10.0;
    }
    let (_, err) = two_product(x, 10.0);
    if err > 0.0 {
        y.ceil() / 10.0
    } else if err < 0.0 {
        fl / 10.0
    } else {
        let z = fl as i64;
        (if z % 2 == 0 { fl } else { fl + 1.0 }) / 10.0
    }
}

fn round_ties_even(y: f64) -> f64 {
    // Rust f64::round_ties_even is stable since 1.77.
    y.round_ties_even()
}

/// `String(format: "%.1f")` — one decimal place.
fn format_mean(x: f64) -> String {
    format!("{x:.1}")
}

// ---------------------------------------------------------------------------
// Field builder: accumulates the flat `parsed` dict applying the cat rule
// (mirrors FieldBuilder.add / .region: a field lands in `parsed` only when it has a
//  value and its category is neither "frame" nor "unknown").
// ---------------------------------------------------------------------------

struct Builder<'a> {
    frame: &'a [u8],
    parsed: BTreeMap<String, Value>,
}

impl<'a> Builder<'a> {
    fn new(frame: &'a [u8]) -> Self {
        Self { frame, parsed: BTreeMap::new() }
    }

    fn add(&mut self, name: &str, cat: &str, value: Value) {
        if cat != "frame" && cat != "unknown" {
            self.parsed.insert(name.to_string(), value);
        }
    }

    /// `region(start, end, ...)` -> `"[N bytes]"` when `start < end <= frame.len()`.
    fn region(&mut self, start: usize, end: usize, name: &str, cat: &str) {
        if start < end && end <= self.frame.len() {
            self.add(name, cat, Value::String(format!("[{} bytes]", end - start)));
        }
    }

    /// Direct insert, bypassing the cat rule (mirrors `fb.parsed[...] = ...`).
    fn put(&mut self, name: &str, value: Value) {
        self.parsed.insert(name.to_string(), value);
    }
}

fn int_val(v: i64) -> Value {
    Value::Number(v.into())
}
fn float_val(v: f64) -> Value {
    serde_json::Number::from_f64(v).map(Value::Number).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Decode a Gen4 frame from a hex string.
pub fn decode_frame_hex(hex_value: &str) -> GooseResult<Gen4Frame> {
    let raw = crate::protocol::decode_hex_with_whitespace(hex_value)?;
    Ok(decode_frame(&raw))
}

/// Decode a complete Gen4 frame (SOF .. crc32 trailer).
pub fn decode_frame(frame: &[u8]) -> Gen4Frame {
    let raw_hex = hex::encode(frame);
    if frame.len() < 8 || frame[0] != 0xAA {
        return Gen4Frame {
            ok: false,
            type_name: "INVALID/FRAGMENT".to_string(),
            seq: None,
            cmd_name: None,
            crc_ok: None,
            len_bytes: frame.len(),
            raw_hex,
            parsed: BTreeMap::new(),
        };
    }

    let schema = schema();

    // Envelope: length field (u16@1) is the index of the crc32 trailer; total = length + 4.
    let length = u16_at(frame, 1).map(|v| v as usize);
    let crc_ok = length.and_then(|len| {
        if len >= 4 && len + 4 <= frame.len() {
            let expected = crc32fast::hash(&frame[4..len]).to_le_bytes();
            Some(frame[len..len + 4] == expected)
        } else {
            None
        }
    });

    let t = frame[4];
    let type_name = schema.type_name(t);
    let seq = frame[5];

    let mut b = Builder::new(frame);

    match schema.packet(t) {
        None => {
            if let Some(len) = length {
                b.region(7, len, "payload", "unknown");
            }
        }
        Some(spec) => {
            // Static fields from the schema (u8/u16/u32/i16 only; f32/s24 live in post-hooks).
            for fld in &spec.fields {
                let Some(dtype) = fld.dtype.as_deref() else { continue };
                let Some(v) = read_dtype_int(frame, fld.off, dtype) else { continue };
                let value = match &fld.enum_key {
                    Some(key) => Value::String(schema.enum_name(key, v)),
                    None => int_val(v),
                };
                b.add(&fld.name, &fld.cat, value);
            }
            if let Some(post) = spec.post.as_deref() {
                run_post_hook(post, &mut b, frame, length, schema, spec);
            }
        }
    }

    let cmd_name = if t == 35 || t == 36 {
        let cmd_byte = frame.get(6).map(|b| *b as i64).unwrap_or(0);
        Some(schema.enum_name("CommandNumber", cmd_byte))
    } else {
        None
    };

    Gen4Frame {
        ok: true,
        type_name,
        seq: Some(seq),
        cmd_name,
        crc_ok,
        len_bytes: frame.len(),
        raw_hex,
        parsed: b.parsed,
    }
}

// ---------------------------------------------------------------------------
// Post-hooks (mirror PostHooks.swift)
// ---------------------------------------------------------------------------

fn run_post_hook(
    post: &str,
    b: &mut Builder,
    frame: &[u8],
    length: Option<usize>,
    schema: &Schema,
    spec: &PacketSpec,
) {
    match post {
        "realtime_data" => post_realtime_data(b, frame),
        "event" => post_event(b, frame, length, schema),
        "command_response" => post_command_response(b, frame, length, schema),
        "raw_data" => post_raw_data(b, frame, length, spec),
        "historical_data" => post_historical_data(b, frame, length, schema, spec),
        "metadata" => post_metadata(b, frame, length),
        "console_logs" => post_console_logs(b, frame, length),
        _ => {}
    }
}

fn post_realtime_data(b: &mut Builder, frame: &[u8]) {
    let rrn = u8_at(frame, 13).unwrap_or(0);
    let mut rrs = Vec::new();
    for i in 0..rrn {
        if let Some(v) = u16_at(frame, 14 + (i as usize) * 2) {
            b.add(&format!("rr[{i}]"), "rr", int_val(v));
            rrs.push(v);
        }
    }
    b.put("rr_intervals", Value::Array(rrs.into_iter().map(int_val).collect()));
}

fn post_event(b: &mut Builder, frame: &[u8], length: Option<usize>, schema: &Schema) {
    let ev_val = frame.get(6).map(|x| *x as i64);
    let ev_name = ev_val.map(|v| {
        schema.enums.get("EventNumber").and_then(|m| m.get(&v.to_string())).cloned()
    }).flatten();
    let Some(length) = length else { return };
    match ev_name.as_deref() {
        Some("BATTERY_LEVEL") => {
            b.region(7, length, "BATTERY_LEVEL payload", "battery");
            if let Some(raw) = u16_at(frame, 17) {
                if raw <= 1100 {
                    b.put("battery_pct", float_val(raw as f64 / 10.0));
                }
            }
            if let Some(mv) = u16_at(frame, 21) {
                if (3000..=4300).contains(&mv) {
                    b.put("battery_mV", int_val(mv));
                }
            }
            if let Some(ch) = u8_at(frame, 26) {
                if ch <= 1 {
                    b.put("battery_charging", int_val(ch & 1));
                }
            }
        }
        Some("EXTENDED_BATTERY_INFORMATION") => {
            let pay_end = length.min(frame.len());
            if 7 >= pay_end {
                return;
            }
            let pay = &frame[7..pay_end];
            b.region(7, length, "EXTENDED_BATTERY_INFORMATION payload", "battery");
            if pay.len() >= 2 {
                for o in 0..pay.len() - 1 {
                    let v = pay[o] as i64 | ((pay[o + 1] as i64) << 8);
                    if (3000..=4300).contains(&v) {
                        b.put("battery_mV?", int_val(v));
                        break;
                    }
                }
            }
        }
        _ => {}
    }
}

fn post_command_response(b: &mut Builder, frame: &[u8], length: Option<usize>, schema: &Schema) {
    let Some(length) = length else { return };
    let pay_end = length.min(frame.len());
    if 7 > pay_end {
        return;
    }
    let pay = &frame[7..pay_end];
    b.region(7, length, "response payload", "cmd");
    let cmd = frame.get(6).map(|x| *x as i64);
    let name = cmd.map(|v| {
        schema.enums.get("CommandNumber").and_then(|m| m.get(&v.to_string())).cloned()
    }).flatten();
    match name.as_deref() {
        Some("GET_BATTERY_LEVEL") if pay.len() >= 4 => {
            let v = pay[2] as i64 | ((pay[3] as i64) << 8);
            b.put("battery_pct", float_val(v as f64 / 10.0));
        }
        Some("GET_CLOCK") if pay.len() >= 6 => {
            let v = pay[2] as i64
                | ((pay[3] as i64) << 8)
                | ((pay[4] as i64) << 16)
                | ((pay[5] as i64) << 24);
            b.put("clock", int_val(v));
        }
        Some("GET_EXTENDED_BATTERY_INFO") if pay.len() >= 9 => {
            let v = pay[7] as i64 | ((pay[8] as i64) << 8);
            b.put("battery_mV", int_val(v));
        }
        Some("REPORT_VERSION_INFO") if pay.len() >= 31 => {
            let buf = if pay.len() >= 35 {
                pay[0..35].to_vec()
            } else {
                let mut v = pay[0..31].to_vec();
                v.extend_from_slice(&[0u8; 4]);
                v
            };
            let le32 = |buf: &[u8], at: usize| -> u32 {
                buf[at] as u32
                    | ((buf[at + 1] as u32) << 8)
                    | ((buf[at + 2] as u32) << 16)
                    | ((buf[at + 3] as u32) << 24)
            };
            let (h0, h1, h2, h3) = (le32(&buf, 3), le32(&buf, 7), le32(&buf, 11), le32(&buf, 15));
            let (b0, b1, b2, b3) = (le32(&buf, 19), le32(&buf, 23), le32(&buf, 27), le32(&buf, 31));
            b.put("fw_harvard", Value::String(format!("{h0}.{h1}.{h2}.{h3}")));
            b.put("fw_boylston", Value::String(format!("{b0}.{b1}.{b2}.{b3}")));
        }
        Some("GET_DATA_RANGE") => {
            let mut uniq: Vec<u32> = Vec::new();
            let mut o = 3usize;
            while o + 3 < pay.len() {
                let v = pay[o] as u32
                    | ((pay[o + 1] as u32) << 8)
                    | ((pay[o + 2] as u32) << 16)
                    | ((pay[o + 3] as u32) << 24);
                if (1_600_000_000..=1_800_000_000).contains(&v) && !uniq.contains(&v) {
                    uniq.push(v);
                }
                o += 1;
            }
            if let (Some(lo), Some(hi)) = (uniq.iter().min().copied(), uniq.iter().max().copied()) {
                b.put("history_oldest", Value::String(format_utc_minute(lo as i64)));
                b.put("history_newest", Value::String(format_utc_minute(hi as i64)));
            }
        }
        _ => {}
    }
}

fn post_raw_data(b: &mut Builder, frame: &[u8], length: Option<usize>, spec: &PacketSpec) {
    let Some(length) = length else { return };
    if length < 7 {
        return;
    }
    let data_len = length - 7;
    let Some(variant) = spec.variants.get(&data_len.to_string()) else {
        b.region(21, length, "sensor payload (short/alt subtype)", "unknown");
        return;
    };
    match variant.kind.as_str() {
        "imu" => {
            let (Some(hr_off), Some(rr_count_off), Some(rr_first_off), Some(samples), Some(tail_from)) = (
                variant.hr_off,
                variant.rr_count_off,
                variant.rr_first_off,
                variant.samples,
                variant.tail_from,
            ) else {
                return;
            };
            let hr = u8_at(frame, hr_off);
            let rrn = u8_at(frame, rr_count_off).unwrap_or(0);
            b.add("heart_rate", "hr", hr.map(int_val).unwrap_or(Value::Null));
            b.add("rr_count", "rr", int_val(rrn));
            let mut rr_vals = Vec::new();
            for i in 0..rrn.min(4) {
                let off = rr_first_off + (i as usize) * 2;
                if let Some(v) = u16_at(frame, off) {
                    b.add(&format!("rr[{i}]"), "rr", int_val(v));
                    rr_vals.push(v);
                }
            }
            if let Some(hr) = hr {
                b.put("heart_rate", int_val(hr));
            }
            b.put("rr_intervals", Value::Array(rr_vals.into_iter().map(int_val).collect()));
            for (name, off, cat) in variant.axes.iter().flatten() {
                let vals = i16_block(frame, *off, samples);
                let mean = if vals.is_empty() {
                    None
                } else {
                    Some(round1(vals.iter().sum::<i64>() as f64 / vals.len() as f64))
                };
                if let Some(mean) = mean {
                    b.add(
                        name,
                        cat,
                        Value::String(format!("mean={} ({}xi16)", format_mean(mean), vals.len())),
                    );
                    b.put(&format!("{name}_mean"), mean_value(mean));
                }
            }
            b.region(tail_from, length, "tail (optical? - not parsed by app)", "unknown");
        }
        "optical" => {
            let (Some(ppg_off), Some(ppg_stride), Some(ppg_samples), Some(config_from)) =
                (variant.ppg_off, variant.ppg_stride, variant.ppg_samples, variant.config_from)
            else {
                return;
            };
            b.region(config_from, ppg_off, "optical config header (UNKNOWN)", "unknown");
            let mut vals = Vec::new();
            for i in 0..ppg_samples {
                match s24_at(frame, ppg_off + i * ppg_stride) {
                    Some(v) => vals.push(v),
                    None => break,
                }
            }
            if !vals.is_empty() {
                let mean = round1(vals.iter().sum::<i64>() as f64 / vals.len() as f64);
                b.add(
                    "ppg_green_ac",
                    "ppg",
                    Value::String(format!("mean={} ({}xs24)", format_mean(mean), vals.len())),
                );
                b.put("ppg_sample_count", int_val(vals.len() as i64));
                b.put("ppg_mean", mean_value(mean));
            }
        }
        _ => {}
    }
}

/// Integral means are stored as integers (mirrors the .int(...) rule in PostHooks); others as floats.
fn mean_value(mean: f64) -> Value {
    if mean == mean.round() && !mean.is_nan() {
        int_val(mean as i64)
    } else {
        float_val(mean)
    }
}

fn post_historical_data(
    b: &mut Builder,
    frame: &[u8],
    length: Option<usize>,
    schema: &Schema,
    spec: &PacketSpec,
) {
    let Some(length) = length else { return };
    let version = frame[5];
    b.put("hist_version", int_val(version as i64));
    let Some((fields, rr_first)) = resolve_version(&spec.versions, version) else {
        b.region(7, length, &format!("HISTORICAL_DATA v{version} (unmapped layout)"), "unknown");
        return;
    };
    if fields.is_empty() {
        b.region(7, length, &format!("HISTORICAL_DATA v{version} (unmapped layout)"), "unknown");
        return;
    }
    for fld in fields {
        let Some(dtype) = fld.dtype.as_deref() else { continue };
        let value = match dtype {
            "u8" | "u16" | "u32" => {
                let Some(v) = read_dtype_int(frame, fld.off, dtype) else { continue };
                match &fld.enum_key {
                    Some(key) => Value::String(schema.enum_name(key, v)),
                    None => int_val(v),
                }
            }
            "f32" => {
                let Some(d) = f32_at(frame, fld.off) else { continue };
                float_val(d)
            }
            _ => continue,
        };
        b.add(&fld.name, &fld.cat, value);
    }
    let mut rr_vals = Vec::new();
    if let Some(rr_first) = rr_first {
        let rrn = b.parsed.get("rr_count").and_then(|v| v.as_i64()).unwrap_or(0);
        for i in 0..rrn.min(4) {
            let o = rr_first + (i as usize) * 2;
            if let Some(v) = u16_at(frame, o) {
                if v != 0 {
                    b.add(&format!("rr[{i}]"), "rr", int_val(v));
                    rr_vals.push(v);
                }
            }
        }
    }
    b.put("rr_intervals", Value::Array(rr_vals.into_iter().map(int_val).collect()));
}

fn post_metadata(b: &mut Builder, frame: &[u8], length: Option<usize>) {
    let Some(length) = length else { return };
    let pay_end = length.min(frame.len());
    if 7 >= pay_end {
        return;
    }
    let pay = &frame[7..pay_end];
    if pay.len() >= 14 {
        let unix = pay[0] as i64
            | ((pay[1] as i64) << 8)
            | ((pay[2] as i64) << 16)
            | ((pay[3] as i64) << 24);
        let ss = pay[4] as i64 | ((pay[5] as i64) << 8);
        let unk0 = pay[6] as i64
            | ((pay[7] as i64) << 8)
            | ((pay[8] as i64) << 16)
            | ((pay[9] as i64) << 24);
        let trim = pay[10] as i64
            | ((pay[11] as i64) << 8)
            | ((pay[12] as i64) << 16)
            | ((pay[13] as i64) << 24);
        b.add("unix", "time", int_val(unix));
        b.add("subsec", "time", int_val(ss));
        b.add("unk0", "meta", int_val(unk0));
        b.add("trim_cursor", "meta", int_val(trim));
    }
}

fn post_console_logs(b: &mut Builder, frame: &[u8], length: Option<usize>) {
    let Some(length) = length else { return };
    let mut txt = String::new();
    let lo = 11usize;
    if length >= 1 {
        let hi = length - 1;
        if lo < hi && hi <= frame.len() {
            txt = String::from_utf8_lossy(&frame[lo..hi]).into_owned();
        }
    }
    b.region(7, length, "console log text", "text");
    b.put("log", Value::String(txt));
}

/// Format a unix timestamp as `"yyyy-MM-dd HH:mm 'UTC'"` (matches the Swift DateFormatter
/// used by the GET_DATA_RANGE post-hook).
fn format_utc_minute(unix: i64) -> String {
    // days since epoch and seconds within the day
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (hh, mm) = (secs / 3600, (secs % 3600) / 60);
    // civil_from_days (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

/// Validate that the embedded schema is loadable (used by sync tests / startup checks).
pub fn schema_is_loadable() -> GooseResult<()> {
    serde_json::from_str::<Schema>(SCHEMA_JSON)
        .map(|_| ())
        .map_err(|e| GooseError::message(format!("embedded whoop_protocol.json invalid: {e}")))
}

// ===========================================================================
// Stream extraction — decoded frames -> durable, compact datastore rows.
// Faithful port of my-whoop's Streams.swift / HistoricalStreams.swift. The row
// shapes match the `streams_golden.json` / `biometric_streams_golden.json` vectors.
// ===========================================================================

/// Heart-rate sample (`ts` = wall-clock unix seconds).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HrSample {
    pub ts: i64,
    pub bpm: i64,
}

/// R-R interval (`ts` = wall-clock unix seconds, `rr_ms` = interval in ms).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RrInterval {
    pub ts: i64,
    pub rr_ms: i64,
}

/// A strap event (`ts` = real RTC unix seconds, never offset). `payload` is the
/// parsed dict minus the `event`/`event_timestamp` keys.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WhoopEvent {
    pub ts: i64,
    pub kind: String,
    pub payload: BTreeMap<String, Value>,
}

/// Battery telemetry. `charging` is only set when a BATTERY_LEVEL event reported it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BatterySample {
    pub ts: i64,
    pub soc: Option<f64>,
    pub mv: Option<i64>,
    pub charging: Option<bool>,
}

/// SpO2 raw-ADC pair from a type-47 V24 record.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Spo2Sample {
    pub ts: i64,
    pub red: i64,
    pub ir: i64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SkinTempSample {
    pub ts: i64,
    pub raw: i64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RespSample {
    pub ts: i64,
    pub raw: i64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GravitySample {
    pub ts: i64,
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub unit: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Streams {
    pub hr: Vec<HrSample>,
    pub rr: Vec<RrInterval>,
    pub spo2: Vec<Spo2Sample>,
    pub skin_temp: Vec<SkinTempSample>,
    pub resp: Vec<RespSample>,
    pub gravity: Vec<GravitySample>,
    pub events: Vec<WhoopEvent>,
    pub battery: Vec<BatterySample>,
}

const RAW_ADC: &str = "raw_adc";
const UNIT_G: &str = "g";

fn p_i64(p: &BTreeMap<String, Value>, key: &str) -> Option<i64> {
    p.get(key).and_then(Value::as_i64)
}
fn p_f64(p: &BTreeMap<String, Value>, key: &str) -> Option<f64> {
    p.get(key).and_then(Value::as_f64)
}
fn p_str<'a>(p: &'a BTreeMap<String, Value>, key: &str) -> Option<&'a str> {
    p.get(key).and_then(Value::as_str)
}
fn p_i64_array(p: &BTreeMap<String, Value>, key: &str) -> Option<Vec<i64>> {
    p.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).collect())
}

/// Map a device-epoch timestamp to wall-clock unix seconds (pure linear offset; mirrors `_to_wall`).
fn to_wall(device_ts: Option<i64>, device_ref: i64, wall_ref: i64) -> Option<i64> {
    device_ts.map(|d| wall_ref + (d - device_ref))
}

/// Append a BatterySample from a frame's battery_pct/battery_mV/battery_charging fields
/// (no-op when neither soc nor mv is present).
fn append_battery(out: &mut Streams, ts: i64, p: &BTreeMap<String, Value>) {
    let soc = p_f64(p, "battery_pct");
    let mv = p_i64(p, "battery_mV");
    if soc.is_none() && mv.is_none() {
        return;
    }
    let charging = p_i64(p, "battery_charging").map(|c| c != 0);
    out.battery.push(BatterySample { ts, soc, mv, charging });
}

fn push_event(out: &mut Streams, p: &BTreeMap<String, Value>) {
    let Some(ts) = p_i64(p, "event_timestamp") else { return };
    let kind = p_str(p, "event").unwrap_or("").to_string();
    if kind.starts_with("BATTERY_LEVEL") {
        append_battery(out, ts, p);
    }
    let mut payload = p.clone();
    payload.remove("event");
    payload.remove("event_timestamp");
    out.events.push(WhoopEvent { ts, kind, payload });
}

/// Realtime stream extraction. HR/R-R come ONLY from REALTIME_DATA (type 40); type-43 also
/// carries an HR byte but streams alongside type-40, so routing both would double-count.
/// CRC-failed / non-ok frames are skipped. Port of `extractStreams`.
pub fn extract_streams(frames: &[Gen4Frame], device_ref: i64, wall_ref: i64) -> Streams {
    let mut out = Streams::default();
    for r in frames {
        if !r.ok || r.crc_ok == Some(false) {
            continue;
        }
        let p = &r.parsed;
        match r.type_name.as_str() {
            "REALTIME_DATA" => {
                let ts = to_wall(p_i64(p, "timestamp"), device_ref, wall_ref);
                if let (Some(ts), Some(bpm)) = (ts, p_i64(p, "heart_rate")) {
                    out.hr.push(HrSample { ts, bpm });
                }
                if let (Some(ts), Some(rrs)) = (ts, p_i64_array(p, "rr_intervals")) {
                    for rr in rrs {
                        out.rr.push(RrInterval { ts, rr_ms: rr });
                    }
                }
            }
            "EVENT" => push_event(&mut out, p),
            "COMMAND_RESPONSE" => append_battery(&mut out, wall_ref, p),
            _ => {}
        }
    }
    out
}

/// Historical (offload) stream extraction. HR/R-R come from REALTIME_RAW_DATA (type 43)
/// headers during backfill; type-47 carries its own real unix ts + the full DSP record.
/// Port of `extractHistoricalStreams`.
pub fn extract_historical_streams(frames: &[Gen4Frame], device_ref: i64, wall_ref: i64) -> Streams {
    let mut out = Streams::default();
    for r in frames {
        if !r.ok || r.crc_ok == Some(false) {
            continue;
        }
        let p = &r.parsed;
        match r.type_name.as_str() {
            "HISTORICAL_DATA" => {
                let Some(ts) = p_i64(p, "unix") else { continue };
                if let Some(bpm) = p_i64(p, "heart_rate") {
                    if bpm != 0 {
                        out.hr.push(HrSample { ts, bpm });
                    }
                }
                if let Some(rrs) = p_i64_array(p, "rr_intervals") {
                    for rr in rrs {
                        out.rr.push(RrInterval { ts, rr_ms: rr });
                    }
                }
                if let Some(red) = p_i64(p, "spo2_red") {
                    out.spo2.push(Spo2Sample {
                        ts,
                        red,
                        ir: p_i64(p, "spo2_ir").unwrap_or(0),
                        unit: RAW_ADC.to_string(),
                    });
                }
                if let Some(raw) = p_i64(p, "skin_temp_raw") {
                    out.skin_temp.push(SkinTempSample { ts, raw, unit: RAW_ADC.to_string() });
                }
                if let Some(raw) = p_i64(p, "resp_rate_raw") {
                    out.resp.push(RespSample { ts, raw, unit: RAW_ADC.to_string() });
                }
                if let Some(gx) = p_f64(p, "gravity_x") {
                    out.gravity.push(GravitySample {
                        ts,
                        x: gx,
                        y: p_f64(p, "gravity_y").unwrap_or(0.0),
                        z: p_f64(p, "gravity_z").unwrap_or(0.0),
                        unit: UNIT_G.to_string(),
                    });
                }
            }
            "REALTIME_RAW_DATA" => {
                let ts = to_wall(p_i64(p, "timestamp"), device_ref, wall_ref);
                if let (Some(ts), Some(bpm)) = (ts, p_i64(p, "heart_rate")) {
                    out.hr.push(HrSample { ts, bpm });
                }
                if let (Some(ts), Some(rrs)) = (ts, p_i64_array(p, "rr_intervals")) {
                    for rr in rrs {
                        out.rr.push(RrInterval { ts, rr_ms: rr });
                    }
                }
            }
            "EVENT" => push_event(&mut out, p),
            "COMMAND_RESPONSE" => append_battery(&mut out, wall_ref, p),
            _ => {}
        }
    }
    out
}
