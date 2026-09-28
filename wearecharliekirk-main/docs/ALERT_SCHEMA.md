# NetSentinel alert schema v1 (`netsentinel.alert/v1`)

PS 26145 constraint (e) asks for a standardized alert schema carrying a
timestamp, a flow identifier, the threat class, a confidence and supporting
evidence. Every alert the sensor raises — from an ONNX model, the port-scan
decision tree or one of the rule-based detectors — is built in this one shape
by `netsentinel/pipeline/alert_manager.py`.

* Machine-readable schema: [`alert_schema_v1.json`](alert_schema_v1.json)
  (JSON Schema draft 2020-12), also served live at `GET /api/schema/alert`.
* The code that defines it: `netsentinel/pipeline/alert_schema.py`.
* Every alert gets a light structural check as it is built (required fields,
  schema id, confidence range and kind, flow identifier, evidence object);
  the count of alerts that failed it is shown on the console's Overview (it
  should stay 0) and returned by `GET /api/stats` as `schema_violations`.
  The full JSON Schema validation runs in the tests.
* `tests/test_ps26145.py` validates alerts from every detector against the
  JSON Schema.

Nothing in an alert is invented. A field of the v1 record the sensor does
not know is `null` (the legacy `flow` block keeps `0` for an unknown port, as
older dashboards expect): the earlier version filled a missing destination
with a fixed demo address and attached a random made-up geolocation; both
were removed.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `netsentinel.alert/v1`. |
| `id` | string | UUID of this alert. |
| `timestamp` | ISO-8601 UTC | When the sensor raised the alert. Same instant as `detected_at`. |
| `detected_at` | ISO-8601 UTC | Explicit name for `timestamp`. |
| `event_time` | ISO-8601 UTC or null | Wire time of the last packet or event in the evidence, or the end of the detector's window (port scan). For a replayed capture this is when it happened on the network, not when it was replayed. |
| `event_window` | object or null | `start`, `end` (ISO-8601 UTC) and `duration_s` of the evidence: one flow, one DNS query, a detector's window (10 s DDoS, 60 s port scan, 5 min DNS behaviour, the C2 check-ins, the TLS sessions). |
| `flow_id` | object | The flow identifier. `scope` says what the alert is about: `flow` (one 5-tuple), `host_pair`, `source` (one host's behaviour), `destination` (a host under attack) or `dns_query`. Carries `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` (null when not applicable), and `community_id`. |
| `flow_id.community_id` | string or null | [Community ID v1](https://github.com/corelight/community-id-spec) hash of the 5-tuple when `scope` is `flow`, so the same flow can be found in Zeek, Suricata or Wireshark. Checked against the reference implementation in `tests/test_tls_fingerprints.py`. |
| `source_ip`, `dest_ip` | string or null | The addresses the evidence is about. `null` when unknown or when there is no single one (a flood from many sources in a rate/entropy alert, a sweep of many hosts). A DDoS alert from the XGBoost model carries the source of the flow that triggered it. |
| `flow` | object | Legacy 5-tuple block kept for older dashboards. |
| `threat_class` | string | `DDoS`, `C2 Beacon`, `DGA`, `DNS Tunnel`, `Encrypted Malware`, `Port Scan`, `Data Exfiltration` (and `VPN Traffic` only if `ETT_ALERT_ON_VPN` is switched on). |
| `threat_subtype` | string | The detector's finer label, e.g. `SYN flood (spoofed sources likely)`, `UDP reflection/amplification (NTP)`, `NXDOMAIN burst`, `record-type anomaly (TXT)`, `host sweep`, `asymmetric upload (out/in byte ratio)`. |
| `ps_category` | `a`–`f` or null | Which PS 26145 threat family the class belongs to. |
| `confidence` | number 0–1 | The detector's score. |
| `confidence_kind` | string | What that number is: `model_probability` (a classifier's output probability), `anomaly_score` (VAE reconstruction error mapped to 0–1), `weighted_score` (a fixed weighted sum, e.g. the C2 combined score) or `rule_score` (how far past a rule's thresholds). They are different kinds of number and are labelled as such. |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` — the class's default adjusted by confidence. |
| `detector` | string | Which detector raised it, e.g. `ddos_binary_xgboost`, `ddos_rate_entropy`, `c2_combined_score_v2`, `dns_behaviour_rules`, `tls_session_profile`, `exfil_byte_ratio`, `portscan_spsd`, `dga_cnn_bilstm_v2`, `exfil_vae`. |
| `model_name` | string | Legacy name of the same thing. |
| `evidence` | object | The detector's supporting evidence, as it produced it (rates, entropy, check-in gaps, JA3/JA4, record-type mix, byte counts, ...). |
| `mitre` | object | ATT&CK `tactic`, `technique`, `name`. |
| `latency_ms.pipeline` | number | Wall-clock time from the event entering the analyzer to the alert being built (0 for an alert built outside the analyzer). |
| `latency_ms.ingest_to_alert` | number or null | Wall-clock time from the extractor emitting the event (or the simulator generating it) to the alert. |
| `sensor_id` | string | Which sensor raised it. |
| `receipt_ref` | string or null | Digest of the signed receipt (integrity layer), when one was issued. Every detector now issues one. |

## Example

Generated by the synthetic simulator (`netsentinel/simulator`), so the
external address is from a documentation range and the numbers describe
made-up traffic. To keep it short, some evidence fields, the legacy `flow`
block and `model_name` are left out and the `iat` list is shortened.

```json
{
  "schema": "netsentinel.alert/v1",
  "id": "2436592e-113c-4100-b701-d76c93d40d55",
  "timestamp": "2026-09-27T01:35:36.539294+00:00",
  "detected_at": "2026-09-27T01:35:36.539294+00:00",
  "event_time": "2026-09-27T01:34:38.930069+00:00",
  "event_window": {"start": "2026-09-27T01:00:36.292044+00:00",
                   "end": "2026-09-27T01:34:38.930069+00:00", "duration_s": 2042.638025},
  "flow_id": {"scope": "host_pair", "src_ip": "192.168.1.71", "dst_ip": "203.0.113.151",
              "src_port": null, "dst_port": 443, "protocol": "TCP", "community_id": null},
  "source_ip": "192.168.1.71",
  "dest_ip": "203.0.113.151",
  "threat_class": "C2 Beacon",
  "threat_subtype": "periodic check-ins",
  "ps_category": "b",
  "confidence": 0.8291,
  "confidence_kind": "weighted_score",
  "severity": "MEDIUM",
  "detector": "c2_combined_score_v2",
  "evidence": {
    "score": 0.8291,
    "components": {"T": 0.986, "F": 0.1716, "S": 0.9951, "R": 1.0, "C": 1.0},
    "weights": {"T": 0.3, "F": 0.2, "S": 0.2, "R": 0.15, "C": 0.15},
    "threshold": 0.8,
    "checkins": 35,
    "median_gap_s": 60.221,
    "span_s": 2042.6,
    "iat": [58.261, 60.982, 60.499, 59.694],
    "bilstm": {"probability": 1.0, "is_beacon": true,
               "note": "BiLSTM+FFT verdict on the same check-ins; evidence, not the decision"}
  },
  "mitre": {"tactic": "Command and Control", "technique": "T1071", "name": "Application Layer Protocol"},
  "latency_ms": {"pipeline": 2.21, "ingest_to_alert": 227.048},
  "sensor_id": "sensor-07",
  "receipt_ref": null
}
```

(`receipt_ref` is null here because the example was produced without the
integrity layer; on a running sensor it holds the receipt digest.)

## Validating alerts outside the sensor

With `jsonschema` 4.0 or later (earlier releases have no draft 2020-12
validator):

```python
import json, jsonschema
schema = json.load(open("docs/alert_schema_v1.json"))
jsonschema.Draft202012Validator(schema).validate(alert)
```

## Versioning

A field added later that consumers can ignore keeps `v1`. Removing or
redefining a field, or changing a required field's meaning, is a new
`schema` value (`netsentinel.alert/v2`), so a consumer can tell which shape
it is reading.
