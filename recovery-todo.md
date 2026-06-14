# Recovery V2 TODO

## Completed

- [x] Wired Recovery V2 trend rows to the bridge-backed daily recovery, HRV, and resting HR series when the bridge exposes trusted daily values.
- [x] Replaced Recovery V2 zero-value trend cards with empty/no-data states until trusted local data exists.
- [x] Added a recovery timeline model that links the score to the primary sleep window and the packet/vitals inputs used by the score run.
- [x] Added Recovery V2 preview coverage for no-data, bridge-data, and packet-run-blocked states.
- [x] Kept live Recovery V2 free of fixture/sample values; preview-only synthetic data is isolated behind `HealthPreviewState`.
- [x] Confirmed the Recovery V2 vitals gate: respiratory rate and wrist-temperature are only shown from trusted packet-derived metrics; SpO2 remains blocked until a decoded/verified optical path exists.

## Remaining

- Replace the zero vitals cards with trusted packet-derived respiratory rate, SpO2, and wrist-temperature fields once their semantics are verified.
  - SpO2: K24 `spo2_red`/`spo2_ir` are a dead end; K25/K26 pulse-information packets are present but the SpO2 decoder/path is still not implemented.
  - Respiratory rate: K18 candidate exists, but units/semantics are still unverified.
  - Wrist/skin temperature: packet candidates exist, but °C delta semantics are still unverified.
- Add Recovery V2 snapshot tests or simulator screenshots for no-data, bridge-data, and packet-run-blocked states.
