//! Parity of Gen4 stream extraction against my-whoop's golden vectors.
//!
//! `extract_streams` over all 96 frames must match `streams_golden.json`; `extract_historical_streams`
//! over the 60 type-47 records must match `biometric_streams_golden.json`. Clock-ref constants match
//! my-whoop's `gen_golden.py` (and its StreamsParityTests / BiometricStreamsParityTests).

use std::fs;
use std::path::Path;

use goose_core::gen4::{
    decode_frame_hex, extract_historical_streams, extract_streams, Streams,
};
use serde_json::Value;

const DEVICE_CLOCK_REF: i64 = 31_538_447;
const WALL_CLOCK_REF: i64 = 1_736_365_593;

fn load(name: &str) -> Value {
    let raw = fs::read_to_string(Path::new("fixtures/gen4").join(name))
        .unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn decode_all() -> Vec<goose_core::gen4::Gen4Frame> {
    load("frames.json")
        .as_array()
        .expect("frames array")
        .iter()
        .map(|f| decode_frame_hex(f["hex"].as_str().expect("hex")).expect("decode"))
        .collect()
}

fn nums_equal(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x == y,
        (None, None) => true,
        _ => false,
    }
}

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

fn arr<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key].as_array().unwrap_or_else(|| panic!("golden key {key} is not an array"))
}

fn check_hr_rr(s: &Streams, gold: &Value, errs: &mut Vec<String>) {
    let g_hr = arr(gold, "hr");
    if s.hr.len() != g_hr.len() {
        errs.push(format!("hr len: got {} want {}", s.hr.len(), g_hr.len()));
    }
    for (i, (got, want)) in s.hr.iter().zip(g_hr).enumerate() {
        if got.ts != want["ts"].as_i64().unwrap() || got.bpm != want["bpm"].as_i64().unwrap() {
            errs.push(format!("hr[{i}]: got (ts={},bpm={}) want {}", got.ts, got.bpm, want));
        }
    }
    let g_rr = arr(gold, "rr");
    if s.rr.len() != g_rr.len() {
        errs.push(format!("rr len: got {} want {}", s.rr.len(), g_rr.len()));
    }
    for (i, (got, want)) in s.rr.iter().zip(g_rr).enumerate() {
        if got.ts != want["ts"].as_i64().unwrap() || got.rr_ms != want["rr_ms"].as_i64().unwrap() {
            errs.push(format!("rr[{i}]: got (ts={},rr_ms={}) want {}", got.ts, got.rr_ms, want));
        }
    }
}

#[test]
fn realtime_streams_match_golden() {
    let frames = decode_all();
    let s = extract_streams(&frames, DEVICE_CLOCK_REF, WALL_CLOCK_REF);
    let gold = load("streams_golden.json");
    let mut errs = Vec::new();

    check_hr_rr(&s, &gold, &mut errs);

    // battery
    let g_bat = arr(&gold, "battery");
    if s.battery.len() != g_bat.len() {
        errs.push(format!("battery len: got {} want {}", s.battery.len(), g_bat.len()));
    }
    for (i, (got, want)) in s.battery.iter().zip(g_bat).enumerate() {
        let want_soc = want["soc"].as_f64();
        let want_mv = want["mv"].as_i64();
        let want_charging = want["charging"].as_bool();
        if got.ts != want["ts"].as_i64().unwrap()
            || !nums_equal(got.soc, want_soc)
            || got.mv != want_mv
            || got.charging != want_charging
        {
            errs.push(format!("battery[{i}]: got {got:?} want {want}"));
        }
    }

    // events (ts, kind, payload)
    let g_ev = arr(&gold, "events");
    if s.events.len() != g_ev.len() {
        errs.push(format!("events len: got {} want {}", s.events.len(), g_ev.len()));
    }
    for (i, (got, want)) in s.events.iter().zip(g_ev).enumerate() {
        if got.ts != want["ts"].as_i64().unwrap() {
            errs.push(format!("event[{i}] ts: got {} want {}", got.ts, want["ts"]));
        }
        if got.kind != want["kind"].as_str().unwrap() {
            errs.push(format!("event[{i}] kind: got {} want {}", got.kind, want["kind"]));
        }
        let want_payload = want["payload"].as_object().expect("event payload object");
        for (k, wv) in want_payload {
            match got.payload.get(k) {
                Some(gv) if values_equal(gv, wv) => {}
                Some(gv) => errs.push(format!("event[{i}] payload[{k:?}]: got {gv} want {wv}")),
                None => errs.push(format!("event[{i}] payload[{k:?}] missing (want {wv})")),
            }
        }
        for k in got.payload.keys() {
            if !want_payload.contains_key(k) {
                errs.push(format!("event[{i}] payload[{k:?}] extra"));
            }
        }
    }

    assert!(s.hr.len() > 0 && s.events.len() > 0 && s.battery.len() > 0, "fixture exercises streams");
    assert!(errs.is_empty(), "realtime stream parity failures:\n{}", errs.join("\n"));
}

#[test]
fn historical_biometric_streams_match_golden() {
    let frames = decode_all();
    let v24: Vec<_> = frames
        .into_iter()
        .filter(|f| f.ok && f.type_name == "HISTORICAL_DATA")
        .collect();
    assert_eq!(v24.len(), 60, "expected 60 V24 records");

    let s = extract_historical_streams(&v24, DEVICE_CLOCK_REF, WALL_CLOCK_REF);
    let gold = load("biometric_streams_golden.json");
    let mut errs = Vec::new();

    check_hr_rr(&s, &gold, &mut errs);

    let g_spo2 = arr(&gold, "spo2");
    for (i, (got, want)) in s.spo2.iter().zip(g_spo2).enumerate() {
        if got.ts != want["ts"].as_i64().unwrap()
            || got.red != want["red"].as_i64().unwrap()
            || got.ir != want["ir"].as_i64().unwrap()
            || got.unit != want["unit"].as_str().unwrap()
        {
            errs.push(format!("spo2[{i}]: got {got:?} want {want}"));
        }
    }
    if s.spo2.len() != g_spo2.len() {
        errs.push(format!("spo2 len: got {} want {}", s.spo2.len(), g_spo2.len()));
    }

    let g_temp = arr(&gold, "skin_temp");
    for (i, (got, want)) in s.skin_temp.iter().zip(g_temp).enumerate() {
        if got.ts != want["ts"].as_i64().unwrap()
            || got.raw != want["raw"].as_i64().unwrap()
            || got.unit != want["unit"].as_str().unwrap()
        {
            errs.push(format!("skin_temp[{i}]: got {got:?} want {want}"));
        }
    }
    if s.skin_temp.len() != g_temp.len() {
        errs.push(format!("skin_temp len: got {} want {}", s.skin_temp.len(), g_temp.len()));
    }

    let g_resp = arr(&gold, "resp");
    for (i, (got, want)) in s.resp.iter().zip(g_resp).enumerate() {
        if got.ts != want["ts"].as_i64().unwrap()
            || got.raw != want["raw"].as_i64().unwrap()
            || got.unit != want["unit"].as_str().unwrap()
        {
            errs.push(format!("resp[{i}]: got {got:?} want {want}"));
        }
    }
    if s.resp.len() != g_resp.len() {
        errs.push(format!("resp len: got {} want {}", s.resp.len(), g_resp.len()));
    }

    let g_grav = arr(&gold, "gravity");
    for (i, (got, want)) in s.gravity.iter().zip(g_grav).enumerate() {
        if got.ts != want["ts"].as_i64().unwrap()
            || got.x != want["x"].as_f64().unwrap()
            || got.y != want["y"].as_f64().unwrap()
            || got.z != want["z"].as_f64().unwrap()
            || got.unit != want["unit"].as_str().unwrap()
        {
            errs.push(format!("gravity[{i}]: got {got:?} want {want}"));
        }
    }
    if s.gravity.len() != g_grav.len() {
        errs.push(format!("gravity len: got {} want {}", s.gravity.len(), g_grav.len()));
    }

    assert!(s.hr.len() > 0 && s.spo2.len() > 0 && s.gravity.len() > 0, "fixture exercises streams");
    assert!(errs.is_empty(), "biometric stream parity failures:\n{}", errs.join("\n"));
}
