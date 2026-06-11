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
                b.put(
                    "ppg_samples",
                    Value::Array(vals.iter().copied().map(int_val).collect()),
                );
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
    let lo = 11usize;
    let hi = if length >= 1 { (length - 1).min(frame.len()) } else { 0 };
    let txt = if lo < hi { bytes_to_escaped_string(&frame[lo..hi]) } else { String::new() };
    b.region(7, length, "console log text", "text");
    b.put("log", Value::String(txt));
}

/// Converts bytes to a UTF-8 string, hex-escaping any invalid sequences as `\xNN`.
fn bytes_to_escaped_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match std::str::from_utf8(&bytes[i..]) {
            Ok(s) => { out.push_str(s); break; }
            Err(e) => {
                let valid = e.valid_up_to();
                if valid > 0 {
                    // SAFETY: from_utf8 confirmed these bytes are valid UTF-8
                    out.push_str(unsafe { std::str::from_utf8_unchecked(&bytes[i..i + valid]) });
                }
                i += valid;
                let skip = e.error_len().unwrap_or(bytes.len() - i);
                for &b in &bytes[i..i + skip] {
                    out.push_str(&format!("\\x{b:02x}"));
                }
                i += skip;
            }
        }
    }
    out
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

// ===========================================================================
// Per-record historical decode — one durable biometric row per HISTORICAL_DATA
// frame, for persistence + later metric computation. Each WHOOP 4.0 V24/V12
// record carries a real-unix timestamp and a full DSP block, so a row-per-record
// shape (keyed by ts) is the natural persistence unit.
// ===========================================================================

/// One decoded historical biometric record (a type-47 V24/V12 frame). Raw ADCs
/// (spo2/skin_temp/resp) are kept as-is — WHOOP converts those server-side.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Gen4HistoryRecord {
    pub ts: i64, // real unix seconds
    pub heart_rate: Option<i64>,
    pub rr_intervals_ms: Vec<i64>,
    pub spo2_red: Option<i64>,
    pub spo2_ir: Option<i64>,
    pub skin_temp_raw: Option<i64>,
    pub resp_rate_raw: Option<i64>,
    pub gravity_x: Option<f64>,
    pub gravity_y: Option<f64>,
    pub gravity_z: Option<f64>,
}

/// Build one `Gen4HistoryRecord` per decoded HISTORICAL_DATA frame, reading the
/// already-validated `parsed` dict. CRC-failed / non-ok / non-historical frames are skipped,
/// as are records without a real unix timestamp.
pub fn decode_history_records(frames: &[Gen4Frame]) -> Vec<Gen4HistoryRecord> {
    const BIOMETRIC_VERSIONS: &[i64] = &[5, 7, 9, 12, 24];
    let mut out = Vec::new();
    for frame in frames {
        if !frame.ok || frame.crc_ok == Some(false) || frame.type_name != "HISTORICAL_DATA" {
            continue;
        }
        let p = &frame.parsed;
        // K25/K26 are pulse-info packets with their own table — skip them here.
        if let Some(v) = p_i64(p, "hist_version") {
            if !BIOMETRIC_VERSIONS.contains(&v) {
                continue;
            }
        }
        let Some(ts) = p_i64(p, "unix") else { continue };
        out.push(Gen4HistoryRecord {
            ts,
            heart_rate: p_i64(p, "heart_rate"),
            rr_intervals_ms: p_i64_array(p, "rr_intervals").unwrap_or_default(),
            spo2_red: p_i64(p, "spo2_red"),
            spo2_ir: p_i64(p, "spo2_ir"),
            skin_temp_raw: p_i64(p, "skin_temp_raw"),
            resp_rate_raw: p_i64(p, "resp_rate_raw"),
            gravity_x: p_f64(p, "gravity_x"),
            gravity_y: p_f64(p, "gravity_y"),
            gravity_z: p_f64(p, "gravity_z"),
        });
    }
    out
}

/// Decode hex frames straight into historical biometric records.
pub fn decode_history_records_hex(frames: &[String]) -> GooseResult<Vec<Gen4HistoryRecord>> {
    let decoded = frames
        .iter()
        .map(|hex| decode_frame_hex(hex))
        .collect::<GooseResult<Vec<_>>>()?;
    Ok(decode_history_records(&decoded))
}

// ===========================================================================
// K25/K26 pulse-information historical decode — one row per frame,
// persisted separately from K24 biometric records.
// ===========================================================================

/// One decoded K25/K26 pulse-info record. optical_dc is the integrated
/// optical ADC (~254k–274k), skin_temp_raw is a slowly-varying ADC (~15400).
/// imu_samples holds 24 signed i16 values (8 XYZ triples at ~8 Hz):
/// [x0,y0,z0, x1,y1,z1, ..., x7,y7,z7] — raw accelerometer counts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Gen4K25Record {
    pub ts: i64,
    pub optical_dc: Option<i64>,
    pub skin_temp_raw: Option<i64>,
    pub imu_samples: Vec<i64>,
}

/// Decode all K25/K26 HISTORICAL_DATA frames into `Gen4K25Record`s.
pub fn decode_k25_records(frames: &[Gen4Frame]) -> Vec<Gen4K25Record> {
    let mut out = Vec::new();
    for frame in frames {
        if !frame.ok || frame.crc_ok == Some(false) || frame.type_name != "HISTORICAL_DATA" {
            continue;
        }
        let p = &frame.parsed;
        match p_i64(p, "hist_version") {
            Some(25) | Some(26) => {}
            _ => continue,
        }
        let Some(ts) = p_i64(p, "unix") else { continue };
        // Re-decode raw bytes to extract the 24×i16 IMU block at frame[23..71].
        let imu_samples = crate::protocol::decode_hex_with_whitespace(&frame.raw_hex)
            .map(|bytes| i16_block(&bytes, 23, 24))
            .unwrap_or_default();
        out.push(Gen4K25Record {
            ts,
            optical_dc: p_i64(p, "optical_dc"),
            skin_temp_raw: p_i64(p, "skin_temp_raw"),
            imu_samples,
        });
    }
    out
}

// ===========================================================================
// SpO2 — ratio-of-ratios over a sliding window of K24 records.
//
// Port of units.py §1 (TI SLAA655 / Mendelson & Ochs 1988).
// Constants are UN-CALIBRATED textbook starting points; expect several %
// error until fit_spo2() is run against a reference pulse-ox dataset.
// ===========================================================================

const SPO2_A: f64 = 110.0;
const SPO2_B: f64 = 25.0;
const SPO2_CLAMP_LO: f64 = 70.0;
const SPO2_CLAMP_HI: f64 = 100.0;
const SPO2_PERFUSION_CEILING: f64 = 0.10; // AC/DC > 10% → motion artefact

/// One computed SpO2 estimate anchored at `ts` (the last sample in its window).
#[derive(Debug, Clone, Serialize)]
pub struct Spo2Estimate {
    pub ts: i64,
    pub spo2: f64,
    pub r_value: f64,
    /// True when the window was motion-rejected and the crude DC ratio was used.
    pub motion_rejected: bool,
}

fn median_sorted(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 0 {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}

fn mad(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let med = median_sorted(&sorted);
    let mut devs: Vec<f64> = values.iter().map(|x| (x - med).abs()).collect();
    devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    median_sorted(&devs)
}

fn robust_spread(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mad(values);
    if m > 0.0 {
        return 1.4826 * m;
    }
    // MAD = 0 → constant segment; fall back to IQR
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len();
    sorted[(3 * n) / 4] - sorted[n / 4]
}

/// Remove linear trend (least-squares fit) from a slice of values.
fn detrend(values: &[f64]) -> Vec<f64> {
    let n = values.len();
    if n < 2 {
        return values.to_vec();
    }
    let n_f = n as f64;
    let mean_t = (n_f - 1.0) / 2.0;
    let mean_x: f64 = values.iter().sum::<f64>() / n_f;
    let var_t: f64 = (0..n).map(|i| { let d = i as f64 - mean_t; d * d }).sum();
    let cov: f64 = values
        .iter()
        .enumerate()
        .map(|(i, x)| (i as f64 - mean_t) * (x - mean_x))
        .sum();
    let slope = cov / var_t;
    values
        .iter()
        .enumerate()
        .map(|(i, x)| x - (slope * (i as f64 - mean_t) + mean_x))
        .collect()
}

fn spo2_from_r(r: f64) -> f64 {
    (SPO2_A - SPO2_B * r).clamp(SPO2_CLAMP_LO, SPO2_CLAMP_HI)
}

/// Compute the ratio-of-ratios R for a window of (red, ir) pairs.
/// Returns None if the window is degenerate or motion-rejected.
pub fn compute_spo2_window(reds: &[f64], irs: &[f64]) -> Option<f64> {
    if reds.len() != irs.len() || reds.len() < 2 {
        return None;
    }
    let dc_red: f64 = reds.iter().sum::<f64>() / reds.len() as f64;
    let dc_ir: f64 = irs.iter().sum::<f64>() / irs.len() as f64;
    if dc_red <= 0.0 || dc_ir <= 0.0 {
        return None;
    }
    let det_red = detrend(reds);
    let det_ir = detrend(irs);
    let ac_red = robust_spread(&det_red);
    let ac_ir = robust_spread(&det_ir);
    if ac_ir < 1e-6 * dc_ir {
        return None; // IR channel flat → R undefined
    }
    if ac_red / dc_red > SPO2_PERFUSION_CEILING || ac_ir / dc_ir > SPO2_PERFUSION_CEILING {
        return None; // motion artefact
    }
    Some((ac_red / dc_red) / (ac_ir / dc_ir))
}

/// Compute a SpO2 time series from K24 history records using a sliding window.
/// `window` is the number of 1 Hz samples per estimate (minimum 2, default 15).
/// Each output sample is anchored at the timestamp of the last record in its window.
pub fn compute_spo2_series(records: &[Gen4HistoryRecord], window: usize) -> Vec<Spo2Estimate> {
    let window = window.max(2);
    let mut out = Vec::new();
    for end in window..=records.len() {
        let slice = &records[end - window..end];
        let ts = slice.last().unwrap().ts;
        let reds: Vec<f64> = slice.iter().filter_map(|r| r.spo2_red.map(|v| v as f64)).collect();
        let irs: Vec<f64> = slice.iter().filter_map(|r| r.spo2_ir.map(|v| v as f64)).collect();
        if reds.len() < window || irs.len() < window {
            continue; // gap in data — skip window
        }
        if let Some(r) = compute_spo2_window(&reds, &irs) {
            out.push(Spo2Estimate { ts, spo2: spo2_from_r(r), r_value: r, motion_rejected: false });
        } else {
            // Motion-rejected fallback: crude DC ratio
            let dc_red: f64 = reds.iter().sum::<f64>() / reds.len() as f64;
            let dc_ir: f64 = irs.iter().sum::<f64>() / irs.len() as f64;
            if dc_ir > 0.0 {
                let r = dc_red / dc_ir;
                out.push(Spo2Estimate { ts, spo2: spo2_from_r(r), r_value: r, motion_rejected: true });
            }
        }
    }
    out
}

// ===========================================================================
// 437 Hz realtime green PPG — beat detection from type-43 REALTIME_RAW_DATA
// ===========================================================================

/// One detected heartbeat from the 437 Hz AC-coupled green PPG waveform.
#[derive(Debug, Clone, Serialize)]
pub struct Gen4PpgBeat {
    /// Unix timestamp of the R-peak in milliseconds.
    pub ts_ms: i64,
    /// RR interval from the previous beat in milliseconds (0 for the first beat in a buffer).
    pub rr_ms: i64,
}

/// Extract the 419 AC-coupled s24 samples from a type-43 REALTIME_RAW_DATA optical frame,
/// paired with the reception time of the packet's last sample.
///
/// `packets` is a slice of `(hex_string, received_ms)` where `received_ms` is the
/// wall-clock time the Swift layer received the BLE notification (not an embedded timestamp).
pub fn decode_ppg_packets(packets: &[(String, i64)]) -> Vec<(Vec<i64>, i64)> {
    const PPG_OFF: usize = 42;
    const PPG_STRIDE: usize = 4;
    const PPG_SAMPLES: usize = 419;

    let mut out = Vec::new();
    for (hex, received_ms) in packets {
        let Ok(bytes) = crate::protocol::decode_hex_with_whitespace(hex) else {
            continue;
        };
        if bytes.len() < PPG_OFF + PPG_SAMPLES * PPG_STRIDE {
            continue;
        }
        // byte[4] = packet type 0x2B (43 = REALTIME_RAW_DATA)
        // byte[5] = packet_k: 0x0A = K10 motion/HR (reject), 0x0B = K11 optical PPG (accept)
        if bytes.len() < 6 || bytes[4] != 0x2B || bytes[5] != 0x0B {
            continue;
        }
        let mut vals = Vec::with_capacity(PPG_SAMPLES);
        for i in 0..PPG_SAMPLES {
            let off = PPG_OFF + i * PPG_STRIDE;
            if off + 3 > bytes.len() {
                break;
            }
            let raw = (bytes[off] as i32)
                | ((bytes[off + 1] as i32) << 8)
                | ((bytes[off + 2] as i32) << 16);
            // Sign-extend from 24-bit two's complement
            let v = if raw & 0x0080_0000 != 0 { raw | -0x0100_0000i32 } else { raw };
            vals.push(v as i64);
        }
        if !vals.is_empty() {
            out.push((vals, *received_ms));
        }
    }
    out
}

/// Detect heartbeat peaks from a sequence of 437 Hz AC-coupled PPG packets.
///
/// Each `(samples, received_ms)` pair represents one type-43 packet where `received_ms`
/// is the wall-clock arrival of the packet (i.e., the timestamp of the *last* sample).
/// Returns one `Gen4PpgBeat` per detected R-peak with physiologically valid RR intervals.
pub fn detect_ppg_beats(packets: &[(Vec<i64>, i64)]) -> Vec<Gen4PpgBeat> {
    const RATE_HZ: f64 = 437.0;
    // 175 samples = 400 ms → caps at ~150 bpm. Smoothing (below) handles the dicrotic notch
    // so MIN_PEAK_DIST only needs to guard against sub-physiological noise.
    const MIN_PEAK_DIST: usize = 175;
    const RR_MIN_MS: i64 = 300;
    const RR_MAX_MS: i64 = 2500;

    if packets.is_empty() {
        return vec![];
    }

    let total: usize = packets.iter().map(|(s, _)| s.len()).sum();
    let mut all_samples: Vec<i64> = Vec::with_capacity(total);
    let mut all_ts_ms: Vec<i64> = Vec::with_capacity(total);
    for (samples, received_ms) in packets {
        let n = samples.len();
        for (j, &s) in samples.iter().enumerate() {
            let offset_ms = ((n - 1 - j) as f64 * 1000.0 / RATE_HZ).round() as i64;
            all_ts_ms.push(received_ms - offset_ms);
            all_samples.push(s);
        }
    }

    // 110-sample (~252 ms) box filter. First null at Fs/W = 437/110 ≈ 4 Hz, which falls
    // right on the 2nd harmonic of resting HR (~2 Hz at 60 bpm) — the frequency that
    // drives the dicrotic notch. The fundamental (1 Hz) passes at ~88% amplitude.
    let smooth_win = 110usize;
    let smoothed: Vec<i64> = (0..all_samples.len())
        .map(|i| {
            let lo = i.saturating_sub(smooth_win / 2);
            let hi = (i + smooth_win / 2 + 1).min(all_samples.len());
            let sum: i64 = all_samples[lo..hi].iter().sum();
            sum / (hi - lo) as i64
        })
        .collect();

    // Try both polarities — AC-coupled PPG may be inverted depending on the optical stack.
    let peak_pos = find_peaks_with_min_dist(&smoothed, MIN_PEAK_DIST, false);
    let peak_neg = find_peaks_with_min_dist(&smoothed, MIN_PEAK_DIST, true);
    let rms = |idxs: &[usize]| -> f64 {
        if idxs.is_empty() {
            return 0.0;
        }
        (idxs.iter().map(|&i| (smoothed[i] as f64).powi(2)).sum::<f64>()
            / idxs.len() as f64)
            .sqrt()
    };
    let peaks = if rms(&peak_pos) >= rms(&peak_neg) { peak_pos } else { peak_neg };

    // Compute RR from sample-index differences, not timestamp differences.
    // BLE notification delivery has jitter (±100 ms typical) so received_ms is only reliable
    // as an absolute anchor; consecutive timestamps can't be trusted for sub-second intervals.
    // Sample indices are crystal-accurate at 437 Hz.
    let mut beats = Vec::new();
    let mut prev_idx: Option<usize> = None;
    for &idx in &peaks {
        let ts_ms = all_ts_ms[idx];
        let rr_ms = match prev_idx {
            Some(p) => ((idx - p) as f64 * 1000.0 / RATE_HZ).round() as i64,
            None => 0,
        };
        if rr_ms == 0 || (rr_ms >= RR_MIN_MS && rr_ms <= RR_MAX_MS) {
            beats.push(Gen4PpgBeat { ts_ms, rr_ms });
            prev_idx = Some(idx);
        }
    }
    beats
}

// ---------------------------------------------------------------------------
// Strain — zone-weighted cardiovascular load from 1 Hz HR history
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct Gen4StrainResult {
    pub score_0_to_21: f64,
    pub zone_load: f64,
    pub duration_minutes: f64,
    pub average_hr_bpm: f64,
    pub max_hr_bpm: f64,
    pub resting_hr_bpm: f64,
    pub hr_zone_minutes: Vec<f64>,
}

/// Compute strain score from 1 Hz HR samples using the same 5-zone HRR model as
/// `goose_strain_v0`. Zone boundaries (% of HRR): <20 / 20–40 / 40–60 / 60–80 / ≥80.
/// `max_hr_bpm` should be the age-based estimate (220 – age) supplied by the caller;
/// the empirical max from `hr_samples` is used when it meaningfully exceeds resting HR.
pub fn compute_gen4_strain(
    hr_samples: &[(i64, i64)], // (ts_s, bpm)
    resting_hr_bpm: f64,
    max_hr_bpm: f64,
    start_s: i64,
    end_s: i64,
) -> Option<Gen4StrainResult> {
    if hr_samples.is_empty() || resting_hr_bpm <= 0.0 || max_hr_bpm <= resting_hr_bpm {
        return None;
    }

    let duration_minutes = (end_s - start_s) as f64 / 60.0;
    if duration_minutes <= 0.0 {
        return None;
    }

    let bpms: Vec<f64> = hr_samples.iter().map(|&(_, b)| b as f64).collect();
    let avg_hr = bpms.iter().sum::<f64>() / bpms.len() as f64;
    let obs_max = bpms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    // Prefer empirical max when it's meaningfully above resting; cap at supplied max_hr.
    let effective_max = if obs_max > resting_hr_bpm + 20.0 {
        obs_max.min(max_hr_bpm)
    } else {
        max_hr_bpm
    };

    let minutes_per_sample = duration_minutes / bpms.len() as f64;
    let mut zones = vec![0.0f64; 5];
    for bpm in &bpms {
        let reserve = ((bpm - resting_hr_bpm) / (effective_max - resting_hr_bpm)).clamp(0.0, 1.0);
        let z = if reserve < 0.20 {
            0
        } else if reserve < 0.40 {
            1
        } else if reserve < 0.60 {
            2
        } else if reserve < 0.80 {
            3
        } else {
            4
        };
        zones[z] += minutes_per_sample;
    }

    let zone_load: f64 = zones.iter().zip([1.0, 2.0, 3.0, 4.0, 5.0]).map(|(m, w)| m * w).sum();
    let score = (zone_load / 20.0).clamp(0.0, 21.0);

    Some(Gen4StrainResult {
        score_0_to_21: (score * 10.0).round() / 10.0,
        zone_load: (zone_load * 10.0).round() / 10.0,
        duration_minutes: (duration_minutes * 10.0).round() / 10.0,
        average_hr_bpm: (avg_hr * 10.0).round() / 10.0,
        max_hr_bpm: effective_max,
        resting_hr_bpm,
        hr_zone_minutes: zones.iter().map(|&v| (v * 10.0).round() / 10.0).collect(),
    })
}

// ---------------------------------------------------------------------------
// Skin temperature — ADC delta from personal baseline (no absolute °C conversion)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct Gen4SkinTempResult {
    pub latest_raw: i64,
    pub baseline_raw: f64,
    pub delta_raw: f64,
    /// Provisional linear approximation: ~0.004 °C per ADC unit.
    /// The actual conversion is computed server-side by WHOOP and is not publicly documented.
    pub delta_c_approx: f64,
    pub sample_count: usize,
}

/// Compute skin temp delta from a rolling ADC baseline.
/// Returns `None` when fewer than 2 samples are available.
pub fn compute_skin_temp_delta(raw_series: &[i64]) -> Option<Gen4SkinTempResult> {
    if raw_series.len() < 2 {
        return None;
    }
    let baseline: f64 = raw_series.iter().map(|&v| v as f64).sum::<f64>() / raw_series.len() as f64;
    let latest = *raw_series.last().unwrap();
    let delta_raw = latest as f64 - baseline;
    Some(Gen4SkinTempResult {
        latest_raw: latest,
        baseline_raw: (baseline * 10.0).round() / 10.0,
        delta_raw: (delta_raw * 10.0).round() / 10.0,
        delta_c_approx: (delta_raw * 0.004 * 10.0).round() / 10.0,
        sample_count: raw_series.len(),
    })
}

// ---------------------------------------------------------------------------
// Resting HR — minimum 10-minute rolling average from 1 Hz HR samples
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct Gen4RestingHrResult {
    pub bpm: f64,
    pub sample_count: usize,
}

/// Compute resting HR as the minimum 10-minute (600-sample) rolling average.
/// Returns `None` when fewer than 600 samples are available.
pub fn compute_resting_hr(hr_series: &[i64]) -> Option<Gen4RestingHrResult> {
    const WINDOW: usize = 600;
    if hr_series.len() < WINDOW {
        return None;
    }
    let mut window_sum: f64 = hr_series[..WINDOW].iter().map(|&v| v as f64).sum();
    let mut min_avg = window_sum / WINDOW as f64;
    for i in 1..=(hr_series.len() - WINDOW) {
        window_sum += hr_series[i + WINDOW - 1] as f64 - hr_series[i - 1] as f64;
        let avg = window_sum / WINDOW as f64;
        if avg < min_avg {
            min_avg = avg;
        }
    }
    Some(Gen4RestingHrResult {
        bpm: (min_avg * 10.0).round() / 10.0,
        sample_count: hr_series.len(),
    })
}

// ---------------------------------------------------------------------------
// HRV RMSSD — from Gen4 PPG beat RR intervals
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct Gen4HrvRmssdResult {
    pub rmssd_ms: f64,
    pub rr_count: usize,
    /// Always 1 for live computation; kept for interface parity with Gen5 path.
    pub chunk_count: usize,
}

/// Compute RMSSD from a slice of RR intervals (ms). Returns `None` when fewer
/// than 3 intervals are available (need ≥2 successive differences).
pub fn compute_hrv_rmssd(rr_series: &[i64]) -> Option<Gen4HrvRmssdResult> {
    if rr_series.len() < 3 {
        return None;
    }
    let diffs_sq: Vec<f64> = rr_series
        .windows(2)
        .map(|w| ((w[1] - w[0]) as f64).powi(2))
        .collect();
    let rmssd = (diffs_sq.iter().sum::<f64>() / diffs_sq.len() as f64).sqrt();
    Some(Gen4HrvRmssdResult {
        rmssd_ms: (rmssd * 10.0).round() / 10.0,
        rr_count: rr_series.len(),
        chunk_count: 1,
    })
}

// ===========================================================================
// Gen4 sleep staging — gravity + HR + RR + resp
// Port of noop/Packages/StrandAnalytics/Sources/StrandAnalytics/SleepStager.swift
// ===========================================================================

// Stage 0 constants
const SLP_STILL_G: f64 = 0.01;
const SLP_STILL_WIN_MIN: i64 = 15;
const SLP_STILL_FRAC: f64 = 0.70;
const SLP_MAX_GAP_S: i64 = 20 * 60;
const SLP_MERGE_S: i64 = 15 * 60;
const SLP_MIN_SLEEP_S: i64 = 60 * 60;
const SLP_HR_MULT: f64 = 1.05;
const SLP_HR_REFINE_MIN: usize = 30;
const SLP_ONSET_PERSIST: usize = 3;
// Stage 1-3 constants
const SLP_EPOCH_S: f64 = 30.0;
const SLP_FEAT_WIN_S: f64 = 300.0;
const SLP_CK_WEIGHTS: [f64; 7] = [106.0, 54.0, 58.0, 76.0, 230.0, 74.0, 67.0];
const SLP_CK_SCALE: f64 = 0.001;
const SLP_CK_DIV: f64 = 100.0;
const SLP_CK_CLIP: f64 = 300.0;
const SLP_CK_BACK: usize = 4;
const SLP_MOVE_G: f64 = 0.01;
const SLP_DOG_S1: f64 = 120.0;
const SLP_DOG_S2: f64 = 600.0;
const SLP_HR_LO_PCT: f64 = 25.0;
const SLP_HR_HI_PCT: f64 = 70.0;
const SLP_HRV_HI_PCT: f64 = 70.0;
const SLP_HRVAR_HI_PCT: f64 = 65.0;
const SLP_RRV_HI_PCT: f64 = 65.0;
const SLP_RRV_LO_PCT: f64 = 50.0;
const SLP_WAKE_MV: f64 = 0.15;
const SLP_STILL_MV: f64 = 0.10;
const SLP_SMOOTH: usize = 5;
const SLP_NO_REM_MIN: f64 = 15.0;
const SLP_DEEP_FRAC: f64 = 1.0 / 3.0;

#[derive(Debug, Serialize, Clone)]
pub struct Gen4StageSegment {
    pub start_s: i64,
    pub end_s: i64,
    /// "wake" | "light" | "deep" | "rem"
    pub stage: String,
}

#[derive(Debug, Serialize)]
pub struct Gen4SleepSession {
    pub start_s: i64,
    pub end_s: i64,
    /// Fraction of time in bed spent asleep (TST/TIB).
    pub efficiency: f64,
    pub stages: Vec<Gen4StageSegment>,
    pub resting_hr_bpm: Option<f64>,
    pub avg_hrv_ms: Option<f64>,
    pub tib_min: f64,
    pub tst_min: f64,
    pub wake_min: f64,
    pub light_min: f64,
    pub deep_min: f64,
    pub rem_min: f64,
}

#[derive(Debug, Serialize)]
pub struct Gen4SleepResult {
    pub sessions: Vec<Gen4SleepSession>,
}

/// Detect sleep sessions from Gen4 historical data.
/// `records` must be sorted by `ts` ASC. `rr_samples` is `(ts_ms, rr_ms)`.
/// `k25_imu` is optional raw-count accelerometer triples `(ts_s, x, y, z)` from K25 frames.
/// When provided and covering the data range, K25 IMU (8 Hz) is preferred over the
/// 1 Hz history gravity; the counts are auto-calibrated using median |accel| ≈ 1g.
pub fn detect_gen4_sleep(
    records: &[Gen4HistoryRecord],
    rr_samples: &[(i64, i64)],
    k25_imu: &[(i64, i64, i64, i64)],
) -> Gen4SleepResult {
    // Build gravity source — prefer K25 IMU when it provides denser coverage.
    let hist_grav: Vec<(i64, f64, f64, f64)> = records
        .iter()
        .filter_map(|r| Some((r.ts, r.gravity_x?, r.gravity_y?, r.gravity_z?)))
        .collect();

    let grav: Vec<(i64, f64, f64, f64)> = if let Some(scale) = slp_imu_scale(k25_imu) {
        // K25 has >= 2x the density of history gravity — use it, normalised to g.
        let k25_as_g: Vec<(i64, f64, f64, f64)> = k25_imu
            .iter()
            .map(|&(ts, x, y, z)| (ts, x as f64 / scale, y as f64 / scale, z as f64 / scale))
            .collect();
        if k25_as_g.len() >= hist_grav.len() * 2 {
            k25_as_g
        } else {
            hist_grav
        }
    } else {
        hist_grav
    };

    if grav.len() < 2 {
        return Gen4SleepResult { sessions: vec![] };
    }

    let hr: Vec<(i64, i64)> = records
        .iter()
        .filter_map(|r| Some((r.ts, r.heart_rate?)))
        .filter(|&(_, b)| b > 0)
        .collect();

    let resp: Vec<(i64, i64)> = records
        .iter()
        .filter_map(|r| Some((r.ts, r.resp_rate_raw?)))
        .collect();

    // Stage 0: gravity-stillness → candidate sleep periods
    let deltas = slp_gravity_deltas(&grav);
    let flags = slp_classify_still(&grav, &deltas);
    let mut runs = slp_build_runs(&grav, &flags);
    runs = slp_merge_periods(runs);

    let hr_baseline = slp_median_hr(&hr);

    let mut sessions = Vec::new();
    for run in &runs {
        if run.2 != "sleep" { continue; }
        if (run.1 - run.0) <= SLP_MIN_SLEEP_S { continue; }
        if !slp_confirm_hr(run.0, run.1, &hr, hr_baseline) { continue; }

        let stages = slp_stage_session(run.0, run.1, &grav, &deltas, &hr, rr_samples, &resp);
        let (tib, tst, wake_s, light_s, deep_s, rem_s) = slp_stage_times(run.0, run.1, &stages);
        let efficiency = if tib > 0.0 { (tst / tib).min(1.0) } else { 0.0 };
        let resting = slp_session_resting_hr(run.0, run.1, &hr);
        let avg_hrv = slp_session_avg_hrv(run.0, run.1, rr_samples);

        sessions.push(Gen4SleepSession {
            start_s: run.0,
            end_s: run.1,
            efficiency: (efficiency * 1000.0).round() / 1000.0,
            stages,
            resting_hr_bpm: resting,
            avg_hrv_ms: avg_hrv,
            tib_min: (tib / 60.0 * 10.0).round() / 10.0,
            tst_min: (tst / 60.0 * 10.0).round() / 10.0,
            wake_min: (wake_s / 60.0 * 10.0).round() / 10.0,
            light_min: (light_s / 60.0 * 10.0).round() / 10.0,
            deep_min: (deep_s / 60.0 * 10.0).round() / 10.0,
            rem_min: (rem_s / 60.0 * 10.0).round() / 10.0,
        });
    }
    Gen4SleepResult { sessions }
}

// (start_s, end_s, "sleep"|"active")
type SleepPeriod = (i64, i64, &'static str);

/// Estimate the raw-count-to-g scale factor from K25 IMU samples.
/// At rest, |accel| ≈ 1g, so `median(|accel|)` in raw counts gives the scale.
/// Returns None if the data is implausible (too few samples or out of range).
fn slp_imu_scale(imu: &[(i64, i64, i64, i64)]) -> Option<f64> {
    if imu.len() < 80 {
        return None; // need at least ~10 s at 8 Hz
    }
    let mut magnitudes: Vec<f64> = imu
        .iter()
        .map(|&(_, x, y, z)| {
            let fx = x as f64;
            let fy = y as f64;
            let fz = z as f64;
            (fx * fx + fy * fy + fz * fz).sqrt()
        })
        .collect();
    magnitudes.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let scale = magnitudes[magnitudes.len() / 2];
    // Sanity: typical WHOOP IMU at ±2g→±16g gives 200..20000 LSB/g
    if scale < 50.0 || scale > 50_000.0 {
        return None;
    }
    Some(scale)
}

fn slp_gravity_deltas(grav: &[(i64, f64, f64, f64)]) -> Vec<f64> {
    let mut d = vec![0.0f64; grav.len()];
    for i in 1..grav.len() {
        let dx = grav[i].1 - grav[i - 1].1;
        let dy = grav[i].2 - grav[i - 1].2;
        let dz = grav[i].3 - grav[i - 1].3;
        d[i] = (dx * dx + dy * dy + dz * dz).sqrt();
    }
    d
}

fn slp_window_samples(grav: &[(i64, f64, f64, f64)]) -> usize {
    if grav.len() < 2 {
        return 3;
    }
    let mut gaps: Vec<f64> = grav
        .windows(2)
        .map(|w| (w[1].0 - w[0].0) as f64)
        .filter(|&g| g > 0.0 && g < 300.0)
        .collect();
    if gaps.is_empty() {
        return 3;
    }
    gaps.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let interval = gaps[gaps.len() / 2].max(1.0);
    ((SLP_STILL_WIN_MIN * 60) as f64 / interval).max(3.0) as usize
}

fn slp_classify_still(grav: &[(i64, f64, f64, f64)], deltas: &[f64]) -> Vec<bool> {
    let n = grav.len();
    if n < 2 {
        return vec![false; n];
    }
    let half = slp_window_samples(grav) / 2;
    (0..n)
        .map(|i| {
            let lo = i.saturating_sub(half);
            let hi = (i + half + 1).min(n);
            let still = (lo..hi).filter(|&j| deltas[j] < SLP_STILL_G).count();
            still as f64 / (hi - lo) as f64 >= SLP_STILL_FRAC
        })
        .collect()
}

fn slp_build_runs(grav: &[(i64, f64, f64, f64)], flags: &[bool]) -> Vec<SleepPeriod> {
    let n = grav.len();
    if n == 0 {
        return vec![];
    }
    let mut periods = Vec::new();
    let mut run_start = 0usize;
    for i in 1..=n {
        let at_end = i == n;
        let gap = !at_end && (grav[i].0 - grav[i - 1].0) > SLP_MAX_GAP_S;
        let class_change = !at_end && flags[i] != flags[run_start];
        if at_end || gap || class_change {
            let stage: &'static str = if flags[run_start] { "sleep" } else { "active" };
            periods.push((grav[run_start].0, grav[i - 1].0, stage));
            run_start = i;
        }
    }
    periods
}

fn slp_merge_periods(periods: Vec<SleepPeriod>) -> Vec<SleepPeriod> {
    if periods.is_empty() {
        return periods;
    }
    let mut input = periods;
    let mut merged: Vec<SleepPeriod> = Vec::new();
    let mut i = 0;
    while i < input.len() {
        let (s, e, stage) = input[i];
        if e - s >= SLP_MERGE_S {
            merged.push((s, e, stage));
            i += 1;
            continue;
        }
        let has_prev = !merged.is_empty();
        let has_next = i + 1 < input.len();
        let bridges = has_prev && has_next && merged.last().unwrap().2 == input[i + 1].2;
        if bridges {
            let (prev_s, _, prev_stage) = merged.pop().unwrap();
            let next_e = input[i + 1].1;
            merged.push((prev_s, next_e, prev_stage));
            i += 2;
        } else if has_next {
            input[i + 1] = (s, input[i + 1].1, input[i + 1].2);
            i += 1;
        } else if has_prev {
            let (prev_s, _, prev_stage) = merged.pop().unwrap();
            merged.push((prev_s, e, prev_stage));
            i += 1;
        } else {
            i += 1;
        }
    }
    merged
}

fn slp_median_hr(hr: &[(i64, i64)]) -> Option<f64> {
    if hr.len() < 5 {
        return None;
    }
    let mut bpms: Vec<f64> = hr.iter().map(|&(_, b)| b as f64).collect();
    bpms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Some(bpms[bpms.len() / 2])
}

fn slp_confirm_hr(start: i64, end: i64, hr: &[(i64, i64)], baseline: Option<f64>) -> bool {
    let Some(bl) = baseline else { return true; };
    let seg: Vec<_> = hr.iter().filter(|&&(ts, _)| ts >= start && ts <= end).collect();
    if seg.len() < SLP_HR_REFINE_MIN { return true; }
    let mean = seg.iter().map(|&&(_, b)| b as f64).sum::<f64>() / seg.len() as f64;
    mean <= bl * SLP_HR_MULT
}

// ---- Stages 1-3: 30s epoch staging ----

struct SlpEpochFeats {
    move_frac: f64,
    ck_sleep: bool,
    hr: f64,
    hr_var: f64,
    rmssd: f64,
    resp_rate: f64,
    rrv: f64,
    clock: f64,
}

fn slp_stage_session(
    start: i64,
    end: i64,
    grav: &[(i64, f64, f64, f64)],
    all_deltas: &[f64],
    hr: &[(i64, i64)],
    rr: &[(i64, i64)],
    resp: &[(i64, i64)],
) -> Vec<Gen4StageSegment> {
    let fallback = || {
        vec![Gen4StageSegment { start_s: start, end_s: end, stage: "light".into() }]
    };

    let (g_seg, d_seg): (Vec<_>, Vec<_>) = grav
        .iter()
        .zip(all_deltas.iter())
        .filter(|&(&(ts, ..), _)| ts >= start && ts <= end)
        .map(|(&g, &d)| (g, d))
        .unzip();

    if g_seg.len() < 2 { return fallback(); }

    let hr_seg: Vec<(i64, i64)> = hr
        .iter()
        .filter(|&&(ts, _)| ts >= start && ts <= end)
        .copied()
        .collect();
    let rr_seg: Vec<(i64, i64)> = rr
        .iter()
        .filter(|&&(ts_ms, _)| {
            let ts_s = ts_ms / 1000;
            ts_s >= start && ts_s <= end
        })
        .copied()
        .collect();
    let resp_seg: Vec<(i64, i64)> = resp
        .iter()
        .filter(|&&(ts, _)| ts >= start && ts <= end)
        .copied()
        .collect();

    let n_ep = (((end - start) as f64 / SLP_EPOCH_S).ceil() as usize).max(1);
    let edges: Vec<f64> = (0..=n_ep)
        .map(|k| (start as f64 + k as f64 * SLP_EPOCH_S).min(end as f64))
        .collect();

    let ep_idx = |ts_s: f64| -> Option<usize> {
        if ts_s < start as f64 || ts_s > end as f64 { return None; }
        let i = ((ts_s - start as f64) / SLP_EPOCH_S) as usize;
        Some(i.min(n_ep - 1))
    };

    let mut counts = vec![0.0f64; n_ep];
    let mut grav_n = vec![0usize; n_ep];
    let mut move_n = vec![0usize; n_ep];
    let mut hr_sum = vec![0.0f64; n_ep];
    let mut hr_cnt = vec![0usize; n_ep];
    let mut rr_buck: Vec<Vec<f64>> = vec![vec![]; n_ep];
    let mut resp_buck: Vec<Vec<f64>> = vec![vec![]; n_ep];

    for (&(ts, ..), &d) in g_seg.iter().zip(d_seg.iter()) {
        if let Some(i) = ep_idx(ts as f64) {
            counts[i] += d;
            grav_n[i] += 1;
            if d >= SLP_MOVE_G { move_n[i] += 1; }
        }
    }
    for &(ts, bpm) in &hr_seg {
        if let Some(i) = ep_idx(ts as f64) {
            hr_sum[i] += bpm as f64;
            hr_cnt[i] += 1;
        }
    }
    for &(ts_ms, rr_ms) in &rr_seg {
        if let Some(i) = ep_idx((ts_ms / 1000) as f64) {
            if (300..=2500).contains(&rr_ms) {
                rr_buck[i].push(rr_ms as f64);
            }
        }
    }
    for &(ts, raw) in &resp_seg {
        if let Some(i) = ep_idx(ts as f64) {
            resp_buck[i].push(raw as f64);
        }
    }

    let hr_ep: Vec<f64> = (0..n_ep)
        .map(|i| if hr_cnt[i] > 0 { hr_sum[i] / hr_cnt[i] as f64 } else { f64::NAN })
        .collect();
    let mv_ep: Vec<f64> = (0..n_ep)
        .map(|i| if grav_n[i] > 0 { move_n[i] as f64 / grav_n[i] as f64 } else { 1.0 })
        .collect();

    // Cole-Kripke
    let rescaled: Vec<f64> = counts.iter().map(|&c| (c / SLP_CK_DIV).min(SLP_CK_CLIP)).collect();
    let ck: Vec<bool> = (0..n_ep)
        .map(|i| {
            let mut si = 0.0f64;
            for (k, &w) in SLP_CK_WEIGHTS.iter().enumerate() {
                let j = i as isize - SLP_CK_BACK as isize + k as isize;
                let a = if j >= 0 && (j as usize) < n_ep { rescaled[j as usize] } else { 0.0 };
                si += w * a;
            }
            si * SLP_CK_SCALE < 1.0
        })
        .collect();

    let (onset, final_w) = slp_onset_final(&ck);
    let dog = slp_dog_hr(&hr_ep);
    let half_w = ((SLP_FEAT_WIN_S / SLP_EPOCH_S / 2.0).round() as usize).max(1);
    let span = (final_w as f64 - onset as f64).max(1.0);

    let feats: Vec<SlpEpochFeats> = (0..n_ep)
        .map(|i| {
            let lo = i.saturating_sub(half_w);
            let hi = (i + half_w + 1).min(n_ep);

            let win_hr: Vec<f64> = (lo..hi).filter_map(|j| hr_ep[j].is_finite().then_some(hr_ep[j])).collect();
            let hr_mean = if win_hr.is_empty() { f64::NAN } else { win_hr.iter().sum::<f64>() / win_hr.len() as f64 };

            let win_dog: Vec<f64> = (lo..hi).map(|j| if dog.is_empty() { 0.0 } else { dog[j] }).collect();
            let hr_var = if win_dog.len() >= 2 { slp_std(&win_dog) } else { f64::NAN };

            let win_rr: Vec<f64> = (lo..hi).flat_map(|j| rr_buck[j].iter().copied()).collect();
            let rmssd = if win_rr.len() >= 5 { slp_rmssd(&win_rr) } else { f64::NAN };

            let win_resp: Vec<f64> = (lo..hi).flat_map(|j| resp_buck[j].iter().copied()).collect();
            let (resp_rate, rrv) = slp_resp_rate_rrv(&win_resp);

            let clock = ((i as f64 - onset as f64) / span).clamp(0.0, 1.0);
            SlpEpochFeats { move_frac: mv_ep[i], ck_sleep: ck[i], hr: hr_mean, hr_var, rmssd, resp_rate, rrv, clock }
        })
        .collect();

    // Session-relative percentile references over CK-sleep epochs
    let slp_feats: Vec<&SlpEpochFeats> = if feats.iter().any(|f| f.ck_sleep) {
        feats.iter().filter(|f| f.ck_sleep).collect()
    } else {
        feats.iter().collect()
    };

    let pct = |vals: Vec<f64>, p: f64| slp_percentile(vals, p);
    let hr_lo = pct(slp_feats.iter().filter_map(|f| f.hr.is_finite().then_some(f.hr)).collect(), SLP_HR_LO_PCT);
    let hr_hi = pct(slp_feats.iter().filter_map(|f| f.hr.is_finite().then_some(f.hr)).collect(), SLP_HR_HI_PCT);
    let rmssd_hi = pct(slp_feats.iter().filter_map(|f| f.rmssd.is_finite().then_some(f.rmssd)).collect(), SLP_HRV_HI_PCT);
    let hrvar_hi = pct(slp_feats.iter().filter_map(|f| f.hr_var.is_finite().then_some(f.hr_var)).collect(), SLP_HRVAR_HI_PCT);
    let rrv_hi = pct(slp_feats.iter().filter_map(|f| f.rrv.is_finite().then_some(f.rrv)).collect(), SLP_RRV_HI_PCT);
    let rrv_lo = pct(slp_feats.iter().filter_map(|f| f.rrv.is_finite().then_some(f.rrv)).collect(), SLP_RRV_LO_PCT);

    let mut labels: Vec<&'static str> = feats
        .iter()
        .map(|f| slp_classify(f, hr_lo, hr_hi, rmssd_hi, hrvar_hi, rrv_hi, rrv_lo))
        .collect();
    labels = slp_smooth(labels);
    labels = slp_physiology(labels, &feats, onset, final_w);
    for i in 0..labels.len() {
        if i < onset || i > final_w { labels[i] = "wake"; }
    }

    // Merge consecutive same-stage epochs into segments
    let mut segs: Vec<Gen4StageSegment> = Vec::new();
    for (i, &stage) in labels.iter().enumerate() {
        let seg_s = edges[i].round() as i64;
        let seg_e = edges[i + 1].round() as i64;
        if let Some(last) = segs.last_mut() {
            if last.stage == stage { last.end_s = seg_e; continue; }
        }
        segs.push(Gen4StageSegment { start_s: seg_s, end_s: seg_e, stage: stage.into() });
    }
    if let Some(last) = segs.last_mut() { last.end_s = end; }
    if segs.is_empty() { return fallback(); }
    segs
}

fn slp_onset_final(ck: &[bool]) -> (usize, usize) {
    let n = ck.len();
    if n == 0 { return (0, 0); }
    let mut onset = None;
    let mut run = 0usize;
    for (i, &s) in ck.iter().enumerate() {
        run = if s { run + 1 } else { 0 };
        if run >= SLP_ONSET_PERSIST { onset = Some(i + 1 - SLP_ONSET_PERSIST); break; }
    }
    let final_w = ck.iter().rposition(|&v| v).unwrap_or(n - 1);
    let o = onset.unwrap_or(0);
    (o, if final_w < o { n - 1 } else { final_w })
}

fn slp_dog_hr(hr_ep: &[f64]) -> Vec<f64> {
    let n = hr_ep.len();
    if n == 0 { return vec![]; }
    let known: Vec<usize> = (0..n).filter(|&i| hr_ep[i].is_finite()).collect();
    if known.is_empty() { return vec![0.0; n]; }
    let filled: Vec<f64> = (0..n).map(|i| {
        if hr_ep[i].is_finite() { return hr_ep[i]; }
        if i <= *known.first().unwrap() { return hr_ep[*known.first().unwrap()]; }
        if i >= *known.last().unwrap() { return hr_ep[*known.last().unwrap()]; }
        let lo = known.iter().copied().rev().find(|&k| k <= i).unwrap_or(0);
        let hi = known.iter().copied().find(|&k| k >= i).unwrap_or(n - 1);
        if hi == lo { return hr_ep[lo]; }
        let frac = (i - lo) as f64 / (hi - lo) as f64;
        hr_ep[lo] + frac * (hr_ep[hi] - hr_ep[lo])
    }).collect();
    let k1 = slp_gauss_kernel(SLP_DOG_S1);
    let k2 = slp_gauss_kernel(SLP_DOG_S2);
    let g1 = slp_convolve(&filled, &k1);
    let g2 = slp_convolve(&filled, &k2);
    (0..n).map(|i| g1[i] - g2[i]).collect()
}

fn slp_gauss_kernel(sigma_s: f64) -> Vec<f64> {
    let sigma = (sigma_s / SLP_EPOCH_S).max(1e-6);
    let r = ((3.0 * sigma).ceil() as usize).max(1);
    let mut k: Vec<f64> = (-(r as isize)..=(r as isize))
        .map(|x| (-0.5 * (x as f64 / sigma).powi(2)).exp())
        .collect();
    let s: f64 = k.iter().sum();
    k.iter_mut().for_each(|v| *v /= s);
    k
}

fn slp_convolve(x: &[f64], kernel: &[f64]) -> Vec<f64> {
    let r = kernel.len() / 2;
    if r == 0 || x.is_empty() { return x.to_vec(); }
    let mut pad = Vec::with_capacity(x.len() + 2 * r);
    for i in 0..r { pad.push(x[(r - i).min(x.len() - 1)]); }
    pad.extend_from_slice(x);
    for i in 0..r { pad.push(x[x.len().saturating_sub(2 + i)]); }
    let m = kernel.len();
    let mut out = Vec::with_capacity(x.len());
    for i in 0..=(pad.len().saturating_sub(m)) {
        let acc: f64 = (0..m).map(|j| pad[i + j] * kernel[m - 1 - j]).sum();
        out.push(acc);
        if out.len() == x.len() { break; }
    }
    // pad to x.len() if short (edge case)
    while out.len() < x.len() { out.push(*out.last().unwrap_or(&0.0)); }
    out
}

fn slp_classify(f: &SlpEpochFeats, hr_lo: Option<f64>, hr_hi: Option<f64>,
                rmssd_hi: Option<f64>, hrvar_hi: Option<f64>,
                rrv_hi: Option<f64>, rrv_lo: Option<f64>) -> &'static str {
    let has_hr = f.hr.is_finite();
    let hr_low = has_hr && hr_lo.map_or(false, |lo| f.hr <= lo);
    let hr_high = has_hr && hr_hi.map_or(false, |hi| f.hr >= hi);
    let parasynth_hi = f.rmssd.is_finite() && rmssd_hi.map_or(false, |hi| f.rmssd >= hi);
    let hrvar_high = f.hr_var.is_finite() && hrvar_hi.map_or(false, |hi| f.hr_var >= hi);
    let cardiac_act = hr_high || hrvar_high;
    let rrv_irr = f.rrv.is_finite() && rrv_hi.map_or(false, |hi| f.rrv >= hi);
    let rrv_reg = !f.rrv.is_finite() || rrv_lo.map_or(false, |lo| f.rrv <= lo);
    let still = f.move_frac <= SLP_STILL_MV;
    let moving = f.move_frac >= SLP_WAKE_MV;

    if moving && (cardiac_act || !has_hr) { return "wake"; }
    if still && parasynth_hi && hr_low && rrv_reg { return "deep"; }
    if still && cardiac_act && rrv_irr { return "rem"; }
    if still && hr_high && hrvar_high && !f.rrv.is_finite() { return "rem"; }
    "light"
}

fn slp_smooth(mut labels: Vec<&'static str>) -> Vec<&'static str> {
    let n = labels.len();
    if n == 0 { return labels; }
    let w = if SLP_SMOOTH % 2 == 0 { SLP_SMOOTH + 1 } else { SLP_SMOOTH };
    let half = w / 2;
    let orig = labels.clone();
    for i in 0..n {
        let lo = i.saturating_sub(half);
        let hi = (i + half + 1).min(n);
        let mut counts = std::collections::HashMap::<&str, usize>::new();
        let mut order: Vec<&str> = Vec::new();
        for &s in &orig[lo..hi] {
            if !counts.contains_key(s) { order.push(s); }
            *counts.entry(s).or_insert(0) += 1;
        }
        if let Some(&best) = counts.values().max() {
            let winners: Vec<&&str> = order.iter().filter(|&&s| counts[s] == best).collect();
            if !winners.iter().any(|&&w| w == orig[i]) {
                labels[i] = winners[0];
            }
        }
    }
    labels
}

fn slp_physiology(mut labels: Vec<&'static str>, feats: &[SlpEpochFeats], onset: usize, final_w: usize) -> Vec<&'static str> {
    let no_rem = (SLP_NO_REM_MIN * 60.0 / SLP_EPOCH_S).round() as usize;
    for (i, f) in feats.iter().enumerate() {
        if i < onset || i > final_w { continue; }
        if labels[i] == "rem" && (i - onset) < no_rem { labels[i] = "light"; }
        if labels[i] == "deep" && f.clock > SLP_DEEP_FRAC { labels[i] = "light"; }
    }
    labels
}

fn slp_resp_rate_rrv(raw: &[f64]) -> (f64, f64) {
    if raw.len() < 8 { return (f64::NAN, f64::NAN); }
    let mean = raw.iter().sum::<f64>() / raw.len() as f64;
    let x: Vec<f64> = raw.iter().map(|&v| v - mean).collect();
    if x.iter().all(|&v| v.abs() < 1e-12) { return (f64::NAN, f64::NAN); }
    let sd = slp_std(&x);
    if sd <= 0.0 { return (f64::NAN, f64::NAN); }
    let peaks = slp_find_peaks(&x, 2, 0.0);
    if peaks.len() < 3 { return (f64::NAN, f64::NAN); }
    let ivs: Vec<f64> = peaks.windows(2)
        .map(|w| (w[1] - w[0]) as f64)
        .filter(|&iv| iv >= 1.5 && iv <= 12.0)
        .collect();
    if ivs.len() < 2 { return (f64::NAN, f64::NAN); }
    let mut sorted = ivs.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (60.0 / sorted[sorted.len() / 2], slp_std(&ivs))
}

fn slp_find_peaks(x: &[f64], distance: usize, height: f64) -> Vec<usize> {
    let n = x.len();
    if n < 3 { return vec![]; }
    let mut candidates = Vec::new();
    let mut i = 1usize;
    while i < n - 1 {
        if x[i] > x[i - 1] && x[i] >= height {
            let mut j = i;
            while j + 1 < n && x[j + 1] == x[i] { j += 1; }
            if j + 1 < n && x[j + 1] < x[i] { candidates.push((i + j) / 2); }
            i = j + 1;
        } else { i += 1; }
    }
    if distance <= 1 || candidates.is_empty() { return candidates; }
    let mut by_h = candidates.clone();
    by_h.sort_by(|&a, &b| x[b].partial_cmp(&x[a]).unwrap_or(std::cmp::Ordering::Equal));
    let mut keep = vec![true; candidates.len()];
    let idx_of: std::collections::HashMap<usize, usize> =
        candidates.iter().enumerate().map(|(i, &v)| (v, i)).collect();
    for &p in &by_h {
        let pi = idx_of[&p];
        if !keep[pi] { continue; }
        for (qi, &q) in candidates.iter().enumerate() {
            if qi != pi && keep[qi] && (q as isize - p as isize).unsigned_abs() < distance {
                keep[qi] = false;
            }
        }
    }
    candidates.iter().zip(keep.iter()).filter(|&(_, &k)| k).map(|(&c, _)| c).collect()
}

fn slp_std(vals: &[f64]) -> f64 {
    if vals.is_empty() { return 0.0; }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    let var = vals.iter().map(|&v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64;
    var.sqrt()
}

fn slp_rmssd(rr: &[f64]) -> f64 {
    if rr.len() < 2 { return f64::NAN; }
    let sq: f64 = rr.windows(2).map(|w| (w[1] - w[0]).powi(2)).sum();
    (sq / (rr.len() - 1) as f64).sqrt()
}

fn slp_percentile(mut vals: Vec<f64>, pct: f64) -> Option<f64> {
    if vals.is_empty() { return None; }
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = vals.len();
    let idx = pct / 100.0 * (n - 1) as f64;
    let lo = idx.floor() as usize;
    let hi = (idx.ceil() as usize).min(n - 1);
    if lo == hi { return Some(vals[lo]); }
    Some(vals[lo] + (idx - lo as f64) * (vals[hi] - vals[lo]))
}

fn slp_stage_times(start: i64, end: i64, stages: &[Gen4StageSegment]) -> (f64, f64, f64, f64, f64, f64) {
    let tib = (end - start) as f64;
    let (mut wk, mut lt, mut dp, mut rm) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    for seg in stages {
        let d = (seg.end_s - seg.start_s) as f64;
        match seg.stage.as_str() {
            "wake" => wk += d, "light" => lt += d, "deep" => dp += d, "rem" => rm += d, _ => {}
        }
    }
    (tib, tib - wk, wk, lt, dp, rm)
}

fn slp_session_resting_hr(start: i64, end: i64, hr: &[(i64, i64)]) -> Option<f64> {
    let seg: Vec<_> = hr.iter().filter(|&&(ts, _)| ts >= start && ts <= end).collect();
    if seg.is_empty() { return None; }
    let win_s: i64 = 5 * 60;
    let mut means = Vec::new();
    let mut t = start;
    while t < end {
        let win: Vec<f64> = seg.iter()
            .filter(|&&&(ts, _)| ts >= t && ts < t + win_s)
            .map(|&&(_, b)| b as f64).collect();
        if !win.is_empty() { means.push(win.iter().sum::<f64>() / win.len() as f64); }
        t += win_s;
    }
    means.iter().copied().reduce(f64::min)
        .or_else(|| {
            let all: Vec<f64> = seg.iter().map(|&&(_, b)| b as f64).collect();
            Some(all.iter().sum::<f64>() / all.len() as f64)
        })
        .map(|v| (v * 10.0).round() / 10.0)
}

fn slp_session_avg_hrv(start: i64, end: i64, rr: &[(i64, i64)]) -> Option<f64> {
    let seg: Vec<_> = rr
        .iter()
        .filter(|&&(ts_ms, _)| { let s = ts_ms / 1000; s >= start && s <= end })
        .collect();
    if seg.is_empty() { return None; }
    let win_s: i64 = 5 * 60;
    let mut vals = Vec::new();
    let mut t = start;
    while t < end {
        let bucket: Vec<f64> = seg.iter()
            .filter(|&&&(ts_ms, _)| { let s = ts_ms / 1000; s >= t && s < t + win_s })
            .map(|&&(_, rr_ms)| rr_ms as f64).collect();
        let filtered: Vec<f64> = bucket.into_iter().filter(|&v| v >= 300.0 && v <= 2500.0).collect();
        if filtered.len() >= 2 {
            let r = slp_rmssd(&filtered);
            if r.is_finite() { vals.push(r); }
        }
        t += win_s;
    }
    if vals.is_empty() { return None; }
    Some((vals.iter().sum::<f64>() / vals.len() as f64 * 10.0).round() / 10.0)
}

// ===========================================================================
// Gen4 Recovery Score
// Same formula as goose_recovery_v0 (metrics.rs), applied to Gen4 inputs.
// Weights: HRV 35%, RHR 20%, sleep 15%, temp 10%, strain readiness 10%, resp 10%.
// ===========================================================================

#[derive(Debug, Serialize)]
pub struct Gen4RecoveryResult {
    pub score_0_to_100: f64,
    pub hrv_rmssd_ms: f64,
    pub hrv_baseline_ms: f64,
    pub resting_hr_bpm: f64,
    pub resting_hr_baseline_bpm: f64,
    pub sleep_score: f64,
    pub sleep_efficiency: f64,
    pub sleep_tst_min: f64,
    pub skin_temp_delta_c: f64,
    pub prior_strain: f64,
    pub component_hrv: f64,
    pub component_rhr: f64,
    pub component_sleep: f64,
    pub component_temperature: f64,
    pub component_strain: f64,
}

/// Compute Gen4 recovery score (0–100). Returns `None` when required baselines
/// or current readings are unavailable or implausible.
pub fn compute_gen4_recovery(
    hrv_rmssd_ms: f64,
    hrv_baseline_ms: f64,
    resting_hr_bpm: f64,
    resting_hr_baseline_bpm: f64,
    sleep_efficiency: f64, // 0..1
    sleep_tst_min: f64,
    skin_temp_delta_c: f64,
    prior_strain: f64, // 0..21
) -> Option<Gen4RecoveryResult> {
    if !hrv_rmssd_ms.is_finite() || hrv_rmssd_ms <= 0.0 { return None; }
    if !hrv_baseline_ms.is_finite() || hrv_baseline_ms <= 0.0 { return None; }
    if !resting_hr_bpm.is_finite() || resting_hr_bpm <= 0.0 { return None; }
    if !resting_hr_baseline_bpm.is_finite() || resting_hr_baseline_bpm <= 0.0 { return None; }

    let clamp = |v: f64| v.clamp(0.0, 100.0);

    let hrv_score = clamp(70.0 + (hrv_rmssd_ms / hrv_baseline_ms - 1.0) * 100.0);
    let rhr_score = clamp(70.0 + (resting_hr_baseline_bpm - resting_hr_bpm) * 5.0);
    // Sleep score: 50% efficiency + 50% duration vs 8 h target
    let sleep_score = clamp(
        sleep_efficiency.clamp(0.0, 1.0) * 50.0
            + (sleep_tst_min / 480.0).min(1.0) * 50.0,
    );
    let temperature_score = clamp(100.0 - skin_temp_delta_c.abs() * 50.0);
    let strain_score = clamp(100.0 - prior_strain.clamp(0.0, 21.0) / 21.0 * 60.0);
    // Respiratory contribution is neutral (10%) until calibrated resp rate is available
    let respiratory_score = 100.0_f64;

    let total = hrv_score * 0.35
        + rhr_score * 0.20
        + sleep_score * 0.15
        + temperature_score * 0.10
        + strain_score * 0.10
        + respiratory_score * 0.10;

    let r = |v: f64| (v * 10.0).round() / 10.0;
    Some(Gen4RecoveryResult {
        score_0_to_100: r(total),
        hrv_rmssd_ms: r(hrv_rmssd_ms),
        hrv_baseline_ms: r(hrv_baseline_ms),
        resting_hr_bpm: r(resting_hr_bpm),
        resting_hr_baseline_bpm: r(resting_hr_baseline_bpm),
        sleep_score: r(sleep_score),
        sleep_efficiency,
        sleep_tst_min: r(sleep_tst_min),
        skin_temp_delta_c: r(skin_temp_delta_c),
        prior_strain: r(prior_strain),
        component_hrv: r(hrv_score),
        component_rhr: r(rhr_score),
        component_sleep: r(sleep_score),
        component_temperature: r(temperature_score),
        component_strain: r(strain_score),
    })
}

fn find_peaks_with_min_dist(samples: &[i64], min_dist: usize, invert: bool) -> Vec<usize> {
    if samples.len() < 3 {
        return vec![];
    }
    let sig: Vec<i64> = if invert {
        samples.iter().map(|&x| -x).collect()
    } else {
        samples.to_vec()
    };

    let candidates: Vec<usize> = (1..sig.len() - 1)
        .filter(|&i| sig[i] > sig[i - 1] && sig[i] >= sig[i + 1])
        .collect();
    if candidates.is_empty() {
        return vec![];
    }

    let peak_vals: Vec<f64> = candidates.iter().map(|&i| sig[i] as f64).collect();
    let mean = peak_vals.iter().sum::<f64>() / peak_vals.len() as f64;
    let std = (peak_vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>()
        / peak_vals.len() as f64)
        .sqrt();
    let threshold = mean - 0.3 * std;

    let mut peaks: Vec<usize> = Vec::new();
    for &c in &candidates {
        if (sig[c] as f64) < threshold {
            continue;
        }
        if let Some(&last) = peaks.last() {
            if c - last < min_dist {
                if sig[c] > sig[last] {
                    *peaks.last_mut().unwrap() = c;
                }
                continue;
            }
        }
        peaks.push(c);
    }
    peaks
}
