//! Persistence round-trip for decoded WHOOP 4.0 historical biometric records.
//! Decodes the 60 golden V24 HISTORICAL_DATA frames, writes them to `gen4_history_samples`,
//! reads them back, and verifies values + idempotent re-sync (upsert by ts).

use std::fs;
use std::path::Path;

use goose_core::gen4::decode_history_records_hex;
use goose_core::store::GooseStore;
use serde_json::Value;

const DEVICE: &str = "whoop4-test";

fn historical_frame_hexes() -> Vec<String> {
    let raw = fs::read_to_string(Path::new("fixtures/gen4/frames.json")).unwrap();
    let arr: Value = serde_json::from_str(&raw).unwrap();
    arr.as_array()
        .unwrap()
        .iter()
        .map(|f| f["hex"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn gen4_history_records_persist_and_read_back() {
    let records = decode_history_records_hex(&historical_frame_hexes()).expect("decode");
    // frames.json holds 60 V24 HISTORICAL_DATA records (plus non-historical frames, which are skipped).
    assert_eq!(records.len(), 60, "expected 60 historical records");

    let store = GooseStore::open_in_memory().expect("open store");
    let written = store.insert_gen4_history_records(DEVICE, &records).expect("insert");
    assert_eq!(written, 60);

    let read = store
        .gen4_history_records_between(DEVICE, 1_700_000_000, 1_700_000_059)
        .expect("query");
    assert_eq!(read.len(), 60, "all 60 records round-trip");

    // Ordered by ts; values match the golden V24 decode.
    assert_eq!(read[0].ts, 1_700_000_000);
    assert_eq!(read[0].heart_rate, Some(60));
    assert_eq!(read[0].spo2_red, Some(18000));
    assert_eq!(read[0].spo2_ir, Some(17000));
    assert_eq!(read[0].skin_temp_raw, Some(900));
    assert_eq!(read[0].gravity_z, Some(0.9937340021133423)); // f32 0x3f7e655a → f64, exact
    assert_eq!(read[0].rr_intervals_ms, vec![1000]);
    assert_eq!(read.last().unwrap().ts, 1_700_000_059);
    assert_eq!(read.last().unwrap().heart_rate, Some(61));

    // A bounded window returns only that slice.
    let window = store
        .gen4_history_records_between(DEVICE, 1_700_000_010, 1_700_000_019)
        .expect("window query");
    assert_eq!(window.len(), 10);
    assert_eq!(window.first().unwrap().ts, 1_700_000_010);
    assert_eq!(window.last().unwrap().ts, 1_700_000_019);

    // Re-syncing the same window upserts (no duplicates).
    let rewritten = store.insert_gen4_history_records(DEVICE, &records).expect("re-insert");
    assert_eq!(rewritten, 60);
    let after = store
        .gen4_history_records_between(DEVICE, 1_700_000_000, 1_700_000_059)
        .expect("query after re-sync");
    assert_eq!(after.len(), 60, "upsert by (device_id, ts) — still 60 rows");
}
