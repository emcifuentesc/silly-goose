# WHOOP 4.0 (Gen4) Support — Integration Plan for silly-goose

**Status:** Analysis + plan. No code changed yet.
**Goal:** Let silly-goose (a WHOOP 5.0–first app) pair with and sync a **WHOOP 4.0** band, by completing the existing `DeviceType::Gen4` path in the Rust core and adding the 4.0 BLE connect/sync flow on the Swift side. **Phone-only** (no server in scope).
**Reference:** `my-whoop` — a verified, working 4.0 client. Its schema (`protocol/whoop_protocol.json`), Swift decoder (`Packages/WhoopProtocol`), golden test vectors, and BLE flow (`ios/OpenWhoop/BLE`, `ios/OpenWhoop/Collect`) are the source of truth and the parity oracle. We port the *behavior* into silly-goose's Rust core; we do **not** add a second Swift parser (that would drift).

---

## 1. Why this is tractable

silly-goose and my-whoop talk to hardware that shares more than expected:

| Aspect | WHOOP 4.0 (my-whoop) | WHOOP 5.0 (silly-goose) | Implication |
|---|---|---|---|
| Custom GATT service | `61080001-…` | shared `61080001-…` (+ v5-only `fd4b…`) | silly-goose already scans/subscribes the 6108 family |
| Characteristics | `0002` cmd-write, `0003` cmd-notify, `0004` event, `0005` data | same roles | reuse subscribe logic |
| Frame SOF | `0xAA` | `0xAA` | shared |
| Frame header | **4 bytes** + CRC8(len) header check + CRC32 trailer | **8 bytes** + CRC trailer | silly-goose Rust already models both (`DeviceType::Gen4` header_len=4) |
| Packet type enums | 36 CMD_RESP, 40 REALTIME, 43 RAW, 47 HISTORICAL, 48 EVENT, 49 META, 50 LOGS | identical numbers | same dispatch table |

The Rust core was built v5-first, but `DeviceType::Gen4` already exists with correct framing (`Rust/core/src/protocol.rs:26-59`), and `Gen4` is referenced in `historical_sync.rs`, `openwhoop_reference.rs`, `commands.rs`, `store.rs`, `capture_import.rs`. **The framing scaffolding is real; the field-level decode and the live BLE flow are not.**

---

## 2. Gap analysis

### 2A. Rust core — decode (`Rust/core/src`)

What works for Gen4 today:
- **Frame framing**: 4-byte header, `crc8(frame[1..3]) == frame[3]`, CRC32 trailer — fully implemented (`protocol.rs:34-59, 250-299, 812-825`).
- **Device-type threading at the framing boundary**: `parse_frame(device_type, …)` and `capture_import.rs:632` thread `DeviceType::Gen4` correctly; `bridge.rs` maps the `"GEN_4"` string.
- **Packet-type recognition**: all types parse to a generic envelope; K24 historical is recognized as `NormalHistory` (`protocol.rs:522-530`, HR marker at offset 17 in `protocol.rs:760-767`).
- **Storage**: `store.rs` is device-type-agnostic with a `device_type` column and `k24_count` tracking — Gen4 records flow through the same tables/metrics pipeline.

The real gaps (**"GEN4 DECODE GAPS"**):
1. **Payload field decode is not device-type-aware and is largely "body-as-hex".** `parse_data_packet_payload()` (`protocol.rs:481-510`) does not receive `device_type`; it extracts a generic `DataPacket` (`packet_k`, `domain`, `timestamp`, `body_hex`) with offsets that happen to coincide with v5 in some regions but are not validated for Gen4. There is **no typed per-field decode** equivalent to my-whoop's schema for: REALTIME_DATA (40), HISTORICAL_DATA V24/V12/V5 (47), REALTIME_RAW_DATA IMU/optical variants (43), EVENT (48), METADATA (49).
2. **No Gen4 field offsets / scales** for the V24 biometric record (HR, RR, ppg_green/red_ir, gravity f32 triplets, spo2/skin_temp/resp raw ADCs, signal_quality), the type-43 `1917` IMU (accel 1/4096 g, gyro 2000/32768 deg/s, signed i16 LE) and `1921` optical (s24 LE PPG @ stride 4) variants.
3. **No Gen4 command generation.** `HistoricalSyncGeneration::Gen4` and command constants (`get_data_range`=34, `send_historical_data`=22, `abort_historical_transmits`=20, `get_hello_harvard`=35) exist as scaffolding/dry-run only (`historical_sync.rs:1106,1349`). No RTC-set, no offload state machine wired to real BLE.
4. **No Gen4 fixtures.** Every fixture in `Rust/core/fixtures/` is labeled `WHOOP 5.0 Goose`; no test instantiates `DeviceType::Gen4`.

### 2B. Swift — BLE + bridge (`GooseSwift`)

What works:
- **Scan/subscribe already cover the 6108 family**: `serviceDiscoveryIDs` includes both `fd4b0001` and `61080001`, and the notify set includes `61080003/04/05/07` (`GooseBLEClient.swift:366-414`). No change needed to *reach* a 4.0 device's characteristics.

v5 hardwiring that breaks Gen4:
1. **Frame reassembly assumes the 8-byte v5 header**: `v5Frames()` / `v5Payload()` read length at `bytes[2..3]` and expect `declaredLength + 8` (`GooseBLEClient+Parsing.swift:865-900`). Gen4 length is at `bytes[1..2]` with a 4-byte header (`declaredLength + 4`). **Will mis-frame Gen4.**
2. **Command framing is v5-only**: `buildV5CommandFrame()` emits `[0xaa,0x01,len,len,0x00,0x01,crc16,…,crc32]` (8-byte header) (`…+Parsing.swift:903-929`). All command paths (clock, alarm, sensor, historical) are gated behind `isV5CommandCharacteristic()` (checks UUID starts with `fd4b0002`) and explicitly error for non-v5 (`…+Commands.swift:147-165, 209-211, 302-303, 393-395`). Gen4 needs the 4-byte command framing my-whoop uses (`[0xAA][len u16 LE][crc8(len)][35][seq][cmd][payload][crc32]`).
3. **No device-type discriminator flows to Rust.** `GooseRustBridge` never sets `device_type`; `bridge.rs:7569` defaults to `"GOOSE"` (v5). Gen4 frames would be parsed as v5.
4. **UI/model assumes gen5** (e.g. `whoop_gen5_front` image in `DeviceView.swift:166`, "WHOOP" default name). Cosmetic; enumerate but low priority.

### 2C. Notable spec discrepancy to resolve early
my-whoop's **schema** (`whoop_protocol.json`, the authoritative source with `golden.json` parity) places REALTIME_DATA (40) fields at: timestamp `off 6` (u32), subseconds `off 10`, heart_rate `off 12`, rr_count `off 13`, rr[] from `off 14`. Some `FINDINGS.md` prose lists different offsets ([4:8] unix, [14] HR). **Trust the schema + golden.json**, not the prose. Lock this by porting against the golden vectors (Phase 1).

---

## 3. Architecture decision

**Make the Rust core the single Gen4 decoder, driven by a schema embedded from my-whoop, validated byte-for-byte against my-whoop's golden fixtures.**

Two viable shapes; recommend **(A)**:

- **(A) Embed `whoop_protocol.json` + a small schema interpreter in Rust.** Mirror my-whoop's `Interpreter`/`PostHooks` design. Lowest drift: the same JSON that drives my-whoop drives silly-goose; a sync test asserts the embedded copy matches. Per-packet typed decode for Gen4 lives in one place and is data-described.
- **(B) Hand-write Gen4 decode in Rust** matching the schema. Faster to start, but two hand-maintained layouts (the JSON and the Rust) will drift; only choose if the schema interpreter proves too heavy for the perf budget.

Either way, decode is **branched on `DeviceType`**: v5 keeps its existing path; `Gen4` uses the schema/typed path. The decoded outputs must land in the **same store rows / metric inputs** the v5 path produces, so the existing Health/metrics UI works unchanged.

---

## 4. Phased plan

### Phase 0 — Scaffolding & fixtures (no behavior change) ✅ DONE
- [x] Extract my-whoop golden vectors into silly-goose Rust fixtures: `Rust/core/fixtures/gen4/frames.json` + `golden.json` (96 mixed frames: 20 REALTIME, 60 HISTORICAL, 9 EVENT, 3 METADATA, 2 RAW, 1 COMMAND_RESPONSE, 1 CONSOLE_LOGS) copied verbatim from `my-whoop/Packages/WhoopProtocol/Tests/WhoopProtocolTests/Resources/`.
- [x] `Rust/core/tests/gen4_parity_tests.rs` asserts, per frame, that `type_name`, `seq`, `crc_ok`, `cmd_name`, and the full `parsed` dict match golden (numeric-aware so golden's integral floats equal our int means). Mirrors `ParityTests.swift`.
- [x] Decided **(A)**: vendored `whoop_protocol.json` into `Rust/core/src/` and `include_str!`-embed it; a schema interpreter in `Rust/core/src/gen4.rs` drives decode. `schema_is_loadable` test guards the embed. (Cross-repo byte-identity SchemaSyncTest deferred — the golden parity test is the real guard.)
- [x] Enabled `serde_json` `float_roundtrip` feature (correctly-rounded float parsing) — required so the golden's f32 gravity values round-trip exactly; also strictly better for the core's own JSON.

### Phase 1 — Rust Gen4 decode ✅ DONE (decode); ⏳ store/stream mapping pending
`Rust/core/src/gen4.rs` is a faithful port of my-whoop's `Interpreter` + `PostHooks` + `Schema`. **All 96 golden frames pass byte-exact parity.**
- [x] **Dtype readers**: u8/u16/u32 LE, i16 LE, **s24 LE**, **f32 LE → f64** (exact). Out-of-bounds → `None`.
- [x] **CRC parity**: crc32 trailer validated via `crc32fast` over `frame[4..len]` (matches my-whoop's zlib CRC32); `len` = u16@1.
- [x] **REALTIME_DATA (40)**: timestamp/subseconds/HR/rr_count + variable rr[] + `rr_intervals`.
- [x] **HISTORICAL_DATA (47)**: version from seq byte; V24 full biometric record, V12 → ref V24, V5/7/9 generic (ref chain via `resolve_version`).
- [x] **REALTIME_RAW_DATA (43)**: variant by `len-7` — `1917` IMU (6 axes × 100 i16, per-axis means via Python-exact `round1`) and `1921` optical (s24 PPG mean). Integral-mean-as-int rule preserved.
- [x] **EVENT (48)**: event enum + timestamp; BATTERY_LEVEL + EXTENDED_BATTERY_INFORMATION sub-parse.
- [x] **COMMAND_RESPONSE (36)**: GET_BATTERY_LEVEL/GET_CLOCK/GET_EXTENDED_BATTERY_INFO/REPORT_VERSION_INFO/GET_DATA_RANGE (incl. UTC-minute formatting). **METADATA (49)**: HISTORY_START/END(unix+subsec+unk0+trim_cursor)/COMPLETE. **CONSOLE_LOGS (50)**.
- [x] Port stream-extraction (decoded frames → HR/RR/SpO2/skin-temp/resp/gravity time series + events/battery) — `extract_streams` / `extract_historical_streams` in `gen4.rs`, validated by `gen4_streams_parity_tests.rs` against `streams_golden.json` (realtime: HR/RR/events/battery) and `biometric_streams_golden.json` (60 V24 records, all biometric series). **All pass.**
- [x] **Bridge exposure** — `gen4.rs` decode + stream extraction are reachable through the C bridge: `gen4.decode_frame_hex`, `gen4.decode_frame_hex_batch`, `gen4.extract_streams`, `gen4.extract_historical_streams` (`bridge.rs`). `Gen4Frame`/`Streams` derive `Serialize`; JSON keys match my-whoop's Codable shapes. Covered by `gen4_bridge_tests.rs` (4 tests, all pass). This is the seam the Swift app calls for a 4.0 device — no v5 pipeline touched.
- [ ] Map decoded Gen4 records + extracted streams into the metric-algorithm inputs (`HrvInput`/`RecoveryInput`/`SleepInput`/…). **← next, but needs an architecture decision (below).**
- **Exit criteria**: full golden parity on frame decode ✅ (96/96), biometric/realtime stream extraction ✅, bridge exposure ✅.

> **Open decision — Gen4 → metric-algorithm wiring.** The v5 metrics pipeline does NOT consume a typed decoder; it re-extracts biometric fields from stored `decoded_frames` via **hardcoded-offset tables in `metric_features.rs`** (e.g. `normal_history_k24_body_3_skin_temperature_c`, `raw_absolute_offset`), then assembles `HrvInput`/`RecoveryInput`/etc. and calls `goose_*_v0`. Two ways to feed Gen4:
> - **(a) Device-type-aware offset tables** — add Gen4 offsets to the `metric_features.rs` plans (the audit's recommendation). Smallest diff, mirrors the v5 architecture, but **re-encodes Gen4 field layouts in a second place**, separate from `gen4.rs`/`whoop_protocol.json` → drift risk, against the "one engine" goal.
> - **(b) Feed `gen4.rs` streams into the inputs** — build `HrvInput`/`RecoveryInput`/… for Gen4 directly from the validated `extract_*_streams` output (a parallel input-assembly path keyed on `device_type`). Keeps Gen4 field knowledge solely in `gen4.rs`; v5 path untouched. More new code, but no drift. **Recommended.**
> Decode + streams already work via the bridge regardless; this only affects how the on-device *scores* (recovery/sleep/strain/stress) get their Gen4 inputs.

> **Note on toolchain:** the crate pins `rust-version = 1.94`; the machine's default stable is 1.88, so tests run under the installed nightly (`cargo +nightly test`). Unrelated pre-existing breakage: `command_tests.rs` `include_str!`s `docs/generated/protocol-command-map.md`, an ungenerated artifact — fails to compile independently of this work.

### Phase 2 — Device-type plumbing (Swift ↔ Rust) ✅ DONE
- [x] `DeviceGeneration` (`.gen4`/`.gen5`) inferred from the GATT family of the characteristic in play (`6108…` ⇒ gen4, else gen5) — `GooseBLEClient.generation(for:)` + `activeDeviceGeneration` in `GooseBLEClient+Parsing.swift`.
- [x] **`device_type` already threaded** — the app derives `rustDeviceType` per notification (`GooseBLETypes.swift`) and passes it to the parser; the primary reassembler (`gooseFrames`, `GooseAppModel+NotificationPipeline.swift`) already branches the 4-byte Gen4 header. **The real blocker was a string bug:** the app emits `"GEN4"` (serde's SCREAMING_SNAKE_CASE for `Gen4`) but Rust's `parse_device_type` only matched `"GEN_4"`/`"Gen4"`/`"gen4"` → every Gen4 frame errored at the bridge. Fixed `parse_device_type` to accept `"GEN4"` (`bridge.rs`); regression test `gen4_device_type_tests.rs` (a real Gen4 frame now parses with `header_len: 4`).
- [x] **Generation-aware reassembly for the secondary paths** — `gen4Frames()`/`gen4Payload()` + `frames(in:for:)`/`payload(in:for:)` dispatch (`+Parsing.swift`); rewired all `Self.v5Frames`/`Self.v5Payload` call sites (`+PeripheralDelegate`, `+HistoricalHandlers`, `+DebugAndSync`) to dispatch by generation. `fd4b` → `.gen5` → identical v5 behavior.
- [x] **Gen4 command framing primitive** — `buildGen4CommandFrame(sequence:command:data:)` + `crc8` (poly 0x07) in `+Parsing.swift`, ready for Phase 3 command sends.
- [x] **Verified:** full iOS **simulator build SUCCEEDED** (`xcodebuild … generic/platform=iOS Simulator`, Rust core built for `aarch64-apple-ios-sim` under nightly) — Swift + Rust compile and link end-to-end.

> **Note (toolchain) ✅ pinned:** the crate pins `rust-version = 1.94`; this machine's default is stable 1.88. Added `Rust/core/rust-toolchain.toml` (`channel = "1.94"`, targets host + `aarch64-apple-ios{,-sim}`). **Also fixed `Scripts/build_ios_rust.sh`** to run `cargo` from the crate dir (`cd "$CORE_DIR"`) — rustup keys toolchain selection off the working directory, not `--manifest-path`, so the Xcode build phase (cwd = project root) was falling back to 1.88 whenever it actually had to compile Rust (the device `.a`). Verified: `cargo test`, the **simulator build**, and the **device-arch build** (`aarch64-apple-ios`, release) all pick 1.94 automatically with no override.

### Phase 3 — Swift Gen4 command framing + connect/sync flow ✅ DONE (implemented; needs on-device validation)
The historical/clock command **numbers already match Gen4** (`GET_DATA_RANGE=34`, `SEND_HISTORICAL_DATA=22`, `HISTORICAL_DATA_RESULT=23`, `SET_CLOCK=10`, `GET_CLOCK=11`), so the existing historical state machine is reused — only the envelope, characteristic gating, one payload, and the connect hello differ.
- [x] `buildGen4CommandFrame` (Phase 2) + generation-aware `buildCommandFrame(sequence:command:data:)` (`+Parsing.swift`); **all 5 command-send call sites** (clock, alarm, sensor, historical, debug) now frame per generation.
- [x] Relaxed gates: `canSendStrapCommands` accepts either family; the four `supportsV5*` props delegate to it (Gen4's `61080002` is no longer blocked). `isV5CommandCharacteristic` retained only as the dual-mode *preference* (prefer `fd4b0002` when both exist).
- [x] Gen4 `SEND_HISTORICAL_DATA` payload `[0x00]` (v5 sends empty) in `writeHistoricalCommand`.
- [x] Gen4 connect handshake `sendGen4Handshake` (`+UserActions.swift`): `GET_HELLO_HARVARD(35)` → `SET_CLOCK(10)` (valid RTC, required before offload) → `GET_CLOCK(11)` → stop type-43 flood (`63 [0x00]`); dispatched via `sendConnectHandshakeIfNeeded` from the connect hook (gen5 keeps `CLIENT_HELLO`). `GET_DATA_RANGE` + `SEND_HISTORICAL_DATA` follow from the existing auto historical sync.
- [x] Historical offload state machine reused as-is (metadata 47/49 + `HISTORICAL_DATA_RESULT` ack, generation-aware reassembly + framing).
- [x] **Verified:** full iOS **simulator build SUCCEEDED** (Swift + Rust, pinned 1.94).
- [ ] **Clock correlation** for Gen4 realtime: the handshake's `GET_CLOCK` is fire-and-forget — the `ClockRef(device,wall)` mapping for realtime device-epoch timestamps isn't wired for Gen4 yet (historical type-47 carries real unix, so backfill timestamps are unaffected). ← refinement
- [ ] **Timing:** may need to defer auto historical sync ~1.5s after `SET_CLOCK` (my-whoop does) so the strap has a valid RTC before offload — tune on-device.
- [ ] Standard HR (180D/2A37) unbonded fallback already shared; confirm Gen4 prefers custom type-40 once bonded.

> **Net:** a WHOOP 4.0 band can now (by construction) connect → bond → handshake (RTC set) → reassemble 4-byte frames → decode → run the historical offload with Gen4 framing. **All paths compile; none are device-validated yet** (Phase 4). The typed `gen4.rs` biometrics still aren't fed to the metric algorithms (deferred metrics fork).

### Phase 4 — UX & validation
- [ ] Device-gen detection surfaced in UI; gate v5-only commands (alarm/clock variants) appropriately; add a gen4 device asset or fallback.
- [ ] On-device validation against a real 4.0 band (the only thing fixtures can't cover): live HR, full 14-day backfill, reconnect/resume, drift handling.
- [ ] Capture real 4.0 frames into the fixture set to lock regressions (currently zero real Gen4 captures exist in silly-goose).

---

## 5. Reference: my-whoop 4.0 connect + sync sequence (authoritative)

GATT: service `61080001-…`; `0002` cmd-write, `0003` cmd-notify, `0004` event, `0005` data(frag); std `180D/2A37` HR (works unbonded), `180F/2A19` battery.

Command frame: `[0xAA][len u16 LE][crc8(len)][0x23 type=COMMAND][seq][cmd][payload][crc32 LE]`.

1. Scan by service `61080001` → connect → discover services `[61080001,180D,180F]` → discover chars.
2. **Bond**: one confirmed write — GET_BATTERY_LEVEL (cmd 26) `[0x00]` to `0002`, `.withResponse`. The confirmed write triggers just-works bonding and unlocks 03/04/05.
3. Subscribe 03, 04, 05, 2A37, 2A19.
4. Handshake (seq increments): GET_HELLO_HARVARD(35) → GET_ADV_NAME(76) → SET_CLOCK(10) `[sec u32 LE][0,0,0,0]` → GET_CLOCK(11) **empty payload** → SEND_R10R11_REALTIME(63) `[0x00]` (stop raw flood) → GET_DATA_RANGE(34).
5. On GET_CLOCK response → `ClockRef(device, wall=now)`; re-SET_CLOCK if |drift| ≥ 2s.
6. After 1.5s → `requestSync(.connect)` → SEND_HISTORICAL_DATA(22) `[0x00]`, arm 60s watchdog.
7. Offload loop: HISTORY_START(49) → type-47 frames accumulate → HISTORY_END(49, unix+trim) → decode + persist + setCursor → ack HISTORICAL_DATA_RESULT(23) `[0x01]+endData[8]` → repeat → HISTORY_COMPLETE(49) ends session.

Command table, full field offsets, IMU/optical layouts, and the clock model are detailed in `my-whoop/FINDINGS.md`, `my-whoop/protocol/whoop_protocol.json`, `my-whoop/ios/OpenWhoop/BLE/{BLEManager,Commands,FrameRouter}.swift`, and `my-whoop/ios/OpenWhoop/Collect/{Collector,Backfiller,ClockCorrelation,ClockPolicy}.swift`.

---

## 6. Risks / open questions
- **No real Gen4 capture in silly-goose** — golden vectors cover decode correctness, but the live BLE bond/offload handshake can only be confirmed on a physical 4.0 band (you have one). Plan for an on-device validation pass (Phase 4) and capture real frames.
- **REALTIME_DATA offset discrepancy** (§2C) — resolve by trusting the schema + golden, lock in Phase 1.
- **Rounding/precision parity** — my-whoop matches Python `round(x,1)` via error-free transforms for IMU/PPG means. Only replicate where parity tests require it; raw storage may not need the means at all.
- **Metric pipeline assumptions** — confirm v5-specific rollups (e.g. K24 skin-temp field offset in `metric_features.rs:4110`) are correct for Gen4 V24 or branched.
- **Command framing confirmation** — verify on-device that the 4-byte command frame on `61080002` is accepted (my-whoop confirms this for 4.0; silly-goose has only ever sent v5 8-byte frames).
- **Schema-interpreter perf** — silly-goose has a perf budget (`perf_budget_tests.rs`); if a JSON-driven interpreter is too slow for type-43 (1917-byte, 100-sample) decode, fall back to hand-written Gen4 decode for the hot path only.

---

## 7. Suggested order of attack
1. Phase 0 + Phase 1 first — get **byte-exact Gen4 decode** in Rust against my-whoop's goldens with no device needed. This is the bulk of the value and fully testable offline.
2. Phase 2 plumbing, then Phase 3 BLE flow — get a real 4.0 band connecting and backfilling.
3. Phase 4 — polish + on-device regression capture.
