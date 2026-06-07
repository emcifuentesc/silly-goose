//! Regression: the Swift app sends `device_type: "GEN4"` (serde's SCREAMING_SNAKE_CASE for
//! `Gen4`, and the app's convention). `protocol.parse_frame_hex` must accept it — previously
//! `parse_device_type` only matched "GEN_4"/"Gen4"/"gen4", so every Gen4 frame errored at the
//! bridge with "unsupported device_type: GEN4".

use goose_core::bridge::handle_bridge_request_json;
use serde_json::{json, Value};

fn call(method: &str, args: Value) -> Value {
    let req = json!({
        "schema": "goose.bridge.request.v1",
        "request_id": "gen4-device-type",
        "method": method,
        "args": args,
    });
    serde_json::from_str(&handle_bridge_request_json(&req.to_string())).unwrap()
}

#[test]
fn parse_frame_hex_accepts_app_gen4_device_type_string() {
    // A real Gen4 REALTIME_DATA frame (4-byte header). Same vector used in the decode parity tests.
    let hex = "aa1800ff28000f3de10100003c01e8030000000000000000c64efbea";
    let resp = call(
        "protocol.parse_frame_hex",
        json!({ "device_type": "GEN4", "frame_hex": hex }),
    );
    assert!(resp["ok"].as_bool().unwrap(), "GEN4 must parse, got: {resp}");
    let r = &resp["result"];
    assert_eq!(r["device_type"], "GEN4"); // serde-serialized DeviceType::Gen4
    assert_eq!(r["header_len"], 4); // 4-byte Gen4 header, not the 8-byte v5 header
    assert_eq!(r["packet_type_name"], "REALTIME_DATA");
}

#[test]
fn parse_frame_hex_batch_accepts_gen4_device_type_string() {
    let hex = "aa1800ff28000f3de10100003c01e8030000000000000000c64efbea";
    let resp = call(
        "protocol.parse_frame_hex_batch",
        json!({ "device_type": "GEN4", "frames": [hex] }),
    );
    assert!(resp["ok"].as_bool().unwrap(), "{resp}");
    let results = resp["result"]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["result"]["header_len"], 4);
}
