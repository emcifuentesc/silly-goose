//! End-to-end tests for the Gen4 bridge methods (the seam the Swift app calls for a 4.0 device).
//! Drives the public JSON entry point with real fixture frames.

use std::fs;
use std::path::Path;

use goose_core::bridge::handle_bridge_request_json;
use serde_json::{json, Value};

fn call(method: &str, args: Value) -> Value {
    let req = json!({
        "schema": "goose.bridge.request.v1",
        "request_id": "gen4-test",
        "method": method,
        "args": args,
    });
    serde_json::from_str(&handle_bridge_request_json(&req.to_string())).expect("response json")
}

fn frame_hexes() -> Vec<String> {
    let raw = fs::read_to_string(Path::new("fixtures/gen4/frames.json")).unwrap();
    let arr: Value = serde_json::from_str(&raw).unwrap();
    arr.as_array()
        .unwrap()
        .iter()
        .map(|f| f["hex"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn decode_frame_hex_method_returns_typed_parse() {
    // First fixture frame is a REALTIME_DATA with heart_rate 60.
    let hex = "aa1800ff28000f3de10100003c01e8030000000000000000c64efbea";
    let resp = call("gen4.decode_frame_hex", json!({ "frame_hex": hex }));
    assert!(resp["ok"].as_bool().unwrap(), "{resp}");
    let r = &resp["result"];
    assert_eq!(r["type_name"], "REALTIME_DATA");
    assert_eq!(r["crc_ok"], true);
    assert_eq!(r["parsed"]["heart_rate"], 60);
    assert_eq!(r["parsed"]["rr_intervals"], json!([1000]));
}

#[test]
fn decode_frame_hex_batch_method_reports_per_frame() {
    let frames = frame_hexes();
    let resp = call("gen4.decode_frame_hex_batch", json!({ "frames": frames.clone() }));
    assert!(resp["ok"].as_bool().unwrap(), "{resp}");
    let result = &resp["result"];
    assert_eq!(result["frame_count"].as_u64().unwrap() as usize, frames.len());
    let results = result["results"].as_array().unwrap();
    assert!(results.iter().all(|r| r["ok"].as_bool().unwrap()));
    // Spot-check that historical frames decoded into biometric fields.
    let hist = results
        .iter()
        .find(|r| r["result"]["type_name"] == "HISTORICAL_DATA")
        .expect("a historical frame");
    assert_eq!(hist["result"]["parsed"]["hist_version"], 24);
    assert!(hist["result"]["parsed"]["gravity_z"].is_number());
}

#[test]
fn extract_historical_streams_method_yields_biometric_series() {
    let frames = frame_hexes();
    let resp = call(
        "gen4.extract_historical_streams",
        json!({ "frames": frames, "device_clock_ref": 31_538_447, "wall_clock_ref": 1_736_365_593 }),
    );
    assert!(resp["ok"].as_bool().unwrap(), "{resp}");
    let s = &resp["result"];
    // 60 V24 records in the fixtures → 60 of each biometric series.
    assert_eq!(s["spo2"].as_array().unwrap().len(), 60);
    assert_eq!(s["gravity"].as_array().unwrap().len(), 60);
    assert_eq!(s["skin_temp"].as_array().unwrap().len(), 60);
    let g0 = &s["gravity"][0];
    assert_eq!(g0["unit"], "g");
    assert_eq!(g0["ts"], 1_700_000_000_i64);
    assert!(g0["x"].is_number() && g0["z"].is_number());
}

#[test]
fn extract_streams_method_yields_realtime_hr_and_battery() {
    let frames = frame_hexes();
    let resp = call(
        "gen4.extract_streams",
        json!({ "frames": frames, "device_clock_ref": 31_538_447, "wall_clock_ref": 1_736_365_593 }),
    );
    assert!(resp["ok"].as_bool().unwrap(), "{resp}");
    let s = &resp["result"];
    assert_eq!(s["hr"].as_array().unwrap().len(), 20);
    assert_eq!(s["battery"].as_array().unwrap().len(), 7);
    // First HR sample is stamped at the wall-clock ref (device ts == device ref).
    assert_eq!(s["hr"][0]["ts"], 1_736_365_593_i64);
    assert_eq!(s["hr"][0]["bpm"], 60);
}
