//! Byte-for-byte parity of the Gen4 (WHOOP 4.0) decoder against my-whoop's golden vectors.
//!
//! `fixtures/gen4/frames.json` (hex inputs) and `fixtures/gen4/golden.json` (expected decode)
//! are copied verbatim from the my-whoop reference decoder's test resources. For every frame we
//! assert that our Rust decode matches the reference on `type_name`, `seq`, `cmd_name`,
//! `crc_ok`, and the full `parsed` dict. Numbers are compared semantically so that the golden's
//! integral floats (e.g. `4096.0`) equal our integer means.

use std::fs;
use std::path::Path;

use goose_core::gen4::decode_frame_hex;
use serde_json::Value;

fn load(name: &str) -> Value {
    let root = Path::new("fixtures/gen4");
    let raw = fs::read_to_string(root.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// Semantic equality: numbers compare by f64 value (so `4096` == `4096.0`); arrays/strings exact.
fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(xf), Some(yf)) => xf == yf,
            _ => x == y,
        },
        (Value::Array(xs), Value::Array(ys)) => {
            xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| values_equal(x, y))
        }
        _ => a == b,
    }
}

#[test]
fn schema_is_loadable() {
    goose_core::gen4::schema_is_loadable().expect("embedded schema loads");
}

#[test]
fn gen4_decode_matches_golden_vectors() {
    let frames = load("frames.json");
    let golden = load("golden.json");
    let frames = frames.as_array().expect("frames.json is an array");
    let golden = golden.as_array().expect("golden.json is an array");
    assert_eq!(frames.len(), golden.len(), "fixture length mismatch");
    assert!(!frames.is_empty(), "no fixtures loaded");

    let mut failures: Vec<String> = Vec::new();

    for (i, (frame, gold)) in frames.iter().zip(golden).enumerate() {
        let hex = frame["hex"].as_str().expect("frame.hex is a string");
        let decoded = match decode_frame_hex(hex) {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("[{i}] decode error: {e}"));
                continue;
            }
        };

        let mut errs: Vec<String> = Vec::new();

        // Headline fields.
        let want_type = gold["type_name"].as_str().unwrap_or("");
        if decoded.type_name != want_type {
            errs.push(format!("type_name: got {:?} want {want_type:?}", decoded.type_name));
        }
        let want_seq = gold["seq"].as_i64();
        if decoded.seq.map(|s| s as i64) != want_seq {
            errs.push(format!("seq: got {:?} want {want_seq:?}", decoded.seq));
        }
        let want_cmd = gold["cmd_name"].as_str();
        if decoded.cmd_name.as_deref() != want_cmd {
            errs.push(format!("cmd_name: got {:?} want {want_cmd:?}", decoded.cmd_name));
        }
        let want_crc = gold["crc_ok"].as_bool();
        if decoded.crc_ok != want_crc {
            errs.push(format!("crc_ok: got {:?} want {want_crc:?}", decoded.crc_ok));
        }

        // Full parsed dict (key sets + semantic value equality).
        let want_parsed = gold["parsed"].as_object().expect("golden parsed is an object");
        for (k, want_v) in want_parsed {
            match decoded.parsed.get(k) {
                None => errs.push(format!("parsed[{k:?}] missing (want {want_v})")),
                Some(got_v) => {
                    if !values_equal(got_v, want_v) {
                        errs.push(format!("parsed[{k:?}]: got {got_v} want {want_v}"));
                    }
                }
            }
        }
        for k in decoded.parsed.keys() {
            if !want_parsed.contains_key(k) {
                errs.push(format!("parsed[{k:?}] extra (got {})", decoded.parsed[k]));
            }
        }

        if !errs.is_empty() {
            failures.push(format!("[{i}] {} ({})\n    {}", want_type, hex, errs.join("\n    ")));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{}/{} Gen4 frames failed parity:\n{}",
            failures.len(),
            frames.len(),
            failures.join("\n")
        );
    }
}
