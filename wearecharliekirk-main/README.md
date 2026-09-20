# NetSentinel

**A passive, agentless network intrusion detection system for unidirectional and
air-gapped networks.**

NetSentinel monitors network traffic it can only *watch* — never inject into,
never query back. It is built for environments where an endpoint agent cannot be
installed and where traffic crosses a data diode in one direction only: nuclear
and power facilities, defence networks, SCADA and industrial control systems,
and the IoT/BYOD segments of a normal enterprise where nothing can be installed
on the device.

It does not decrypt traffic, does not rely on signature feeds, and runs on CPU.

---

## The problem

Most detection assumes things a diode-protected or OT network cannot give you:

| Common assumption | Reality behind a data diode |
|---|---|
| An agent runs on the endpoint | Nothing can be installed on a PLC, HMI or vendor appliance |
| Traffic can be queried or replayed | The link is physically one-way |
| Payloads can be inspected | Traffic is TLS/QUIC encrypted end to end |
| Signatures identify the threat | Living-off-the-land abuse uses legitimate services |
| Alerts can be trusted later | An audit trail that can be edited proves nothing |

NetSentinel is built around those constraints rather than in spite of them.

---

## Architecture

Two tiers. The first classifies traffic as it arrives; the second reasons about
how a host's behaviour changes over days.

```
                    ┌──────────────────────────────────────────────┐
   network tap ───▶ │  CAPTURE            pcap / live interface     │
   (one-way)        └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │  EXTRACTION                                   │
                    │  flow assembly · CIC / UNSW / DNS features    │
                    │  session windows · TLS + QUIC handshake meta  │
                    └──────────────────────┬───────────────────────┘
                                           │
      ╔════════════════════════════════════▼═══════════════════════╗
      ║  TIER 1 — live detection (per flow / per window)            ║
      ║  ┌──────────┬──────────┬───────────┬──────────┬──────────┐  ║
      ║  │  DDoS    │   DGA    │ C2 beacon │ Encrypted│ Port scan│  ║
      ║  └──────────┴──────────┴───────────┴──────────┴──────────┘  ║
      ║                      + exfiltration                         ║
      ╚════════════════════════════════════┬═══════════════════════╝
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │  ANALYZER      routing · gating · thresholds  │
                    │  ALERT MANAGER MITRE mapping · severity · dedup│
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │  INTEGRITY     Merkle log · Ed25519 ledger    │
                    │                proof-carrying alerts          │
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │  REST /api  ·  WebSocket /ws  ·  React UI     │
                    └──────────────────────────────────────────────┘

      ╔═════════════════════════════════════════════════════════════╗
      ║  TIER 2 — behavioural analysis  (tier2/)                     ║
      ║  Inspector (central, graph+attention) ──▶ Sentry (edge, GRU) ║
      ║  per-host baselining · cohort comparison · escalation budget ║
      ║  Telegram-C2 / living-off-trusted-services analysis          ║
      ╚═════════════════════════════════════════════════════════════╝
```

---

## Tier 1 — live detection

A streaming pipeline: packets become flows, flows become feature vectors,
feature vectors are scored by a set of specialised models, and surviving
detections become alerts.

**Detection modules**

| Module | Looks for |
|---|---|
| DDoS | Volumetric and protocol floods |
| DGA / DNS tunnelling | Algorithmically generated domains and data smuggled over DNS |
| C2 beacon | Machine-regular check-in rhythms, including jittered ones |
| Encrypted traffic | Malicious behaviour in TLS/QUIC flows without decrypting them |
| Port scan | Horizontal and vertical scanning, including slow scans |
| Exfiltration | Data leaving in volumes or shapes a host does not normally produce |

**Supporting stages**

- **Extraction** — flow assembly with idle/active timeouts, CIC-style and
  UNSW-style feature sets, DNS lexical features, session windows for
  sequence models, and TLS/QUIC handshake metadata (SNI only; no payload).
- **Analyzer** — routes events to the right modules and applies gating so a
  detector only fires when its preconditions hold.
- **Alert manager** — MITRE ATT&CK mapping, severity assignment, deduplication.
- **API layer** — REST under `/api` (health, alerts, stats, models, extractor
  stats, integrity verification) and a `/ws` WebSocket for live streaming.
- **Dashboard** — React + Vite: live alert feed, threat graph, evidence panels,
  MITRE heatmap, FFT spectrum for beacon evidence, and an integrity panel.

---

## Tier 2 — behavioural analysis (`tier2/`)

Tier 1 answers *"is this flow malicious?"*. Tier 2 answers a harder question:
*"has this host started behaving unlike itself, and unlike its peers?"* — the
case where an attacker uses only legitimate services and never trips a
per-flow detector.

**Inspector–Sentry cascade.** A central **Inspector** learns what normal looks
like for each host, using the host's own history plus a cohort of comparable
hosts. A small **Sentry** runs at the edge, scores continuously and cheaply, and
escalates only the most suspicious host-days to the Inspector within a fixed
budget. The split is not arbitrary: the Sentry is causal and can answer during
the day, while the Inspector reads a whole day at once and answers after it.

**Cross-service behaviour.** Traffic is resolved into service *categories*
(code repositories, messaging APIs, cloud storage, telemetry, and so on) and the
model reasons over the combination and shape of a host's category usage rather
than any single destination.

**Living-off-trusted-services analysis.** A dedicated track studies command and
control hidden inside services a host legitimately uses — for example a
Telegram Bot API channel on a machine whose owner really does use Telegram.
Where per-window classification is not possible even in principle, the analysis
produces a **bound** instead: it relates the bandwidth an implant can use to the
time it can remain unnoticed, so the limit is stated rather than assumed.

**Operational machinery.** Per-host score normalisation, a commissioning and
promotion state machine, a visibility gate that refuses to score when the sensor
view degrades, and guarded threshold recalibration.

Tier 2 currently runs as its own verified analysis track alongside the live
pipeline rather than inside it; wiring its detectors into the Tier 1 analyzer is
the next integration step.

---

## Integrity — alerts you can still trust later

A detection is only useful if it can be proved later that it was not altered.
NetSentinel maintains a tamper-evident transparency log:

- **Merkle transparency log (RFC 6962)** — every alert is a leaf; any alert can
  be proved to be in the log with an inclusion proof.
- **Append-only guarantee** — consistency proofs show the log grew by appending
  and was never rewritten.
- **Signed ledger** — alerts are batched into blocks, hash-chained, and signed
  with Ed25519; signed tree heads act as checkpoints.
- **Proof-carrying alerts** — an alert can travel with the evidence needed to
  verify it, and can be verified by a relying party without access to the
  ledger itself.
- **Replay** — recorded decisions can be re-derived and checked.

---

## Repository layout

```
netsentinel/              Tier 1 backend
  extractor/              flow assembly, CIC/UNSW/DNS features, pcap reader
  models/                 detection modules + model registry
  pipeline/               analyzer, alert manager, gating
  integrity/              Merkle log, Ed25519 ledger, receipts, replay
  api/                    REST routes and WebSocket hub
  netinfo/                network topology / subnet awareness
  simulator/              synthetic traffic generator
  main.py  config.py      app wiring and model resolution

tier2/                    Tier 2 behavioural analysis track
  netsentinel_v2/         Inspector-Sentry, cohort, calibration, loaders, QUIC
  telegram_c2.py          living-off-trusted-services analysis
  bench_evasion.py        evasion-ladder benchmark
  verify_all.py           one-command verification of the whole track
  HOW_THIS_FITS.md        how Tier 2 relates to Tier 1
  AUDIT.md                claim-by-claim evidence register
  INSPECTOR_SENTRY_SPEC.md  full Tier 2 specification

frontend/                 React + Vite dashboard
tests/                    backend test suite (conftest.py wires sys.path + --pcap)
scripts/                  training, diagnostics, dataset tooling
  evaluate_detection.py   per-class detection + false-positive harness
models/                   the 6 ONNX experts (vendored, no network needed)
docs/                     architecture, critique, guides, history
tools/                    verification utilities
integrity/                ledger state and signed tree heads

PIPELINE_TEST_20SEP.md    first full-pipeline run: throughput, integrity
PIPELINE_TEST_PART2.md    alert-volume and exfiltration findings + fixes
PIPELINE_TEST_PART3.md    what is and is not claimable  <- read this one
```

---

## Getting started

**Prerequisites** — Python 3.11, Node.js 18+, and libpcap (Linux) or Npcap
(Windows) for live capture.

### 1. Backend

```bash
pip install -r requirements.txt
python run.py                      # serves on http://localhost:8000
```

The six ONNX models ship in `models/` and load in about 1.5 seconds with **no
network access at all** — which is the point, for an air-gapped deployment.
`get_model_path()` resolves in this order:

1. `$NETSENTINEL_MODELS_DIR`
2. `<repo>/models/` ← the vendored copy, used by default
3. `~/.cache/netsentinel/models/`
4. Hugging Face (`Unded-17/netsentinel-models`), only if nothing local matched

A missing model is a hard startup failure, not a warning — a security product
that silently runs without its detectors is worse than one that refuses to start.

### 2. Dashboard

```bash
cd frontend
npm install
npm run dev
```

### 3. Tier 2

```bash
cd tier2
pip install -r requirements.txt
python verify_all.py               # runs every suite and re-derives every figure
```

### 4. Feeding it traffic

Point the backend at a capture file or a live interface, or use the built-in
traffic simulator under `netsentinel/simulator/` to drive the dashboard without
a live tap.

---

## Status and verification

Every figure here was measured on 20 September 2026 and is reproducible with the
commands above. Nothing in this section is an estimate.

| | measured |
|---|---|
| Test suite (`pytest tests/`) | **62 passed, 11 skipped, 0 errors** |
| Integrity: inclusion, append-only, signed ledger | **42 / 42** |
| Tier-2 Telegram-C2 bound | **17 / 17** |
| Models | 6 / 6 load in ~1.5 s, no network |
| Real 200 MB single-host capture | 2,113 flow events → **34 alerts (1.61%)**, 4 actionable |
| Throughput | ~49× real time, single core, 244 MB RSS |
| Analyzer errors on real traffic | **0** |

### What we do not claim

This is the part most projects skip, so it is stated plainly:

> **We do not claim an accuracy, a recall figure, or a false-positive rate.**
> Those require labelled data, and our capture has none. Everything measured
> above is *behaviour*, not accuracy.

Concretely:

- **Per-class recall numbers from `scripts/evaluate_detection.py` are circular.**
  The attack traffic comes from our own simulator, written by the same people as
  the detectors. That measures "does it fire on what we built it to fire on",
  not "does it catch real attacks". It is a wiring smoke test and an upper
  bound — the harness prints that warning next to its own output by design.
- **The 34 real-capture alerts are an upper bound on false positives**, not a
  false-positive rate. The capture has no ground truth, so we cannot verify it
  contains no intrusion.
- **Port scan's 99.03%** (in `PORT_SCAN_COMPLETE.md`) is the SPSD model on a
  CIDDS-001 *validation set*. It is not a NetSentinel detection rate.
- A publishable recall figure needs labelled real intrusion captures
  (CIC-IDS2017, CTU-13, UNSW-NB15). That work has not been done.

`PIPELINE_TEST_PART3.md` carries the full argument, the open defects, and a
correction to an earlier root-cause diagnosis of our own that turned out to be
wrong.

### Known open items

- **C2 beacon detection is throttled.** A hard-coded `prob > 0.90` gate in
  `models/c2_beacon.py` overrides the configured `0.80` threshold. The model
  tops out at 0.941 on clean beacons, so most true beacons are discarded.
- **The scikit-learn pin is not enforced** (1.3.2 pinned, 1.7.2 running). This
  skew has already produced two real defects; one silently corrupted a model's
  output while every test stayed green.
- Tier 2 runs as its own verified track; wiring it into the Tier-1 analyzer is
  the next integration step.

---

## Design decisions

**Detection only.** NetSentinel observes and reports. It does not block, reset
connections or modify traffic — on a one-way link it could not, and in an OT
environment an automated block is itself a safety risk.

**No decryption.** TLS and QUIC are read only as far as the handshake: service
names, not contents. Detection works on behaviour — volume, rhythm, direction,
which services a host touches and in what combination.

**CPU only.** No GPU is required anywhere in the live path.

**Complementary to EDR, not a replacement.** NetSentinel covers what an agent
cannot reach. Where endpoint telemetry exists, it remains the better source.

**Per-deployment calibration.** What counts as normal is a property of the
network being watched, so thresholds are established during a commissioning
window on site rather than shipped as constants.

---

## Prior art and attribution

This project builds on published work and says so:

- The Tier 2 Inspector follows the **GraphIDS** architecture
  (arXiv:2509.16625). It is prior art, not our design.
- The **teacher–student cascade**, **knowledge distillation** and **per-entity
  baselining** are all established techniques.
- The transparency log follows **RFC 6962 (Certificate Transparency)**.
- TLS/QUIC handling follows **RFC 9000 / RFC 9001**.
- Feature definitions draw on the **CICFlowMeter** and **UNSW-NB15** feature sets.

What we claim as our own contribution is narrower: the cross-service category
semantics used to reason about living-off-trusted-services behaviour, the
chained-behaviour dataset built to test it, and the bound relating an implant's
bandwidth to the time it can stay unnoticed.

---

## License

See `LICENSE`.
