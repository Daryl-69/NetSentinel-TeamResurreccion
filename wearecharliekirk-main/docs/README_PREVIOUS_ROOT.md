```
  _   _      _   ____             _   _            _
 | \ | | ___| |_/ ___|  ___ _ __ | |_(_)_ __   ___| |
 |  \| |/ _ \ __\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 | |\  |  __/ |_ ___) |  __/ | | | |_| | | | |  __/ |
 |_| \_|\___|\__|____/ \___|_| |_|\__|_|_| |_|\___|_|

 Passive. Offline. Correlated.
 A machine learning intrusion detection sensor for unidirectional IP traffic.
```

NetSentinel is a passive, offline network intrusion detection system (NIDS). It ingests
network traffic from a PCAP file or a mirror/TAP interface, extracts behavioral metadata,
and routes it through six specialized detection models. Alerts stream to a browser
dashboard in real time over a WebSocket. The system inspects no payloads, sits inline with
nothing, and sends no data off the monitored network.

The novelty is not any single model. DGA classification, volumetric DDoS detection, and
anomaly-based exfiltration detection are established techniques. The contribution is the
integration: fusing six independent threat signals into correlated attack chains on one
passive sensor that runs entirely on local hardware, so that a DGA lookup, a C2 beacon, and
a DNS tunnel from the same internal host read as a single kill chain rather than three
disconnected alerts.

---

## Status at a glance

| Property | State |
|---|---|
| Deployment posture | Passive sensor. Detection and alerting only. No block, quarantine, or mitigation. |
| Models wired and routed | 6 of 6 (DDoS, Port Scan, DGA, Exfiltration, C2 Beacon, Encrypted Traffic) |
| Inference runtime | ONNX Runtime, CPU only, no GPU required |
| External dependencies at runtime | None. No cloud, no API calls, no telemetry. Suitable for air-gapped networks. |
| Payload inspection | None. Headers, flow statistics, DNS strings, and timing metadata only. |
| Model distribution | HuggingFace Hub with local cache, offline capable after first fetch |
| Forensic integrity | Optional. 7 of 9 claims functional (DSSE receipts, replay, Merkle batching, Ed25519 ledger) |

---

## Table of contents

1. [Design principles](#design-principles)
2. [System architecture](#system-architecture)
3. [Detection models](#detection-models)
4. [Extraction pipeline](#extraction-pipeline)
5. [Validated results](#validated-results)
6. [Dashboard](#dashboard)
7. [How NetSentinel compares](#how-netsentinel-compares)
8. [Technology stack](#technology-stack)
9. [Installation](#installation)
10. [Running the system](#running-the-system)
11. [API reference](#api-reference)
12. [Configuration](#configuration)
13. [Project structure](#project-structure)
14. [🔒 Forensic integrity layer](#-forensic-integrity-layer-experimental)
15. [Known limitations](#known-limitations)
16. [Roadmap](#roadmap)
17. [License](#license)

---

## Design principles

Three constraints shape every part of the system.

**Passive observation.** NetSentinel operates on a copy of network traffic taken from a
mirror port or TAP. It is not inline, does not modify packets, and cannot cause network
disruption. Its output is detection and evidence. Response decisions stay with the analyst.

**Offline operation.** All six models run locally through ONNX Runtime on commodity CPUs.
There are no cloud dependencies and no outbound telemetry. This is a deliberate design
target for environments where cloud-backed security tooling is not permitted: government
networks, defence installations, and SCADA/ICS infrastructure.

**Metadata only.** NetSentinel never reads packet payloads. It works from headers, flow
statistics, DNS query strings, and timing. This allows detection on encrypted traffic,
including TLS 1.3, without decryption, and keeps the system privacy-preserving by design.

Every model is exported to ONNX, giving a single inference interface across three very
different architectures (gradient-boosted trees, recurrent networks, and a transformer).

---

## System architecture

```
                        +--------------------------------------+
   PCAP file  ------>   |            EXTRACTION LAYER           |
   Live TAP   ------>   |                                      |
                        |  Phase 1: CICFlowMeter               |
                        |    59 flow-statistic features        |
                        |    tag = "cicflowmeter"              |
                        |                                      |
                        |  Phase 2: Custom Scapy extractor     |
                        |    DNS query strings                 |
                        |    24 DNS lexical features           |
                        |    100-flow session time-series      |
                        |    tag = "custom"                    |
                        +------------------+-------------------+
                                           |
                              type + source-tag routing
                                           |
        +------------------+---------------+----------------+------------------+
        |                  |               |                |                  |
        v                  v               v                v                  v
   +---------+       +-----------+   +-----------+    +-----------+     +-------------+
   |  DDoS   |       | Port Scan |   |    DGA    |    | Exfil VAE |     | C2 Beacon   |
   | XGBoost |       | XGBoost + |   | CNN-BiLSTM|    | recon err |     | BiLSTM+FFT  |
   |         |       | fan-out   |   |  3-class  |    |           |     |             |
   +----+----+       +-----+-----+   +-----+-----+    +-----+-----+     +------+------+
        |                  |               |                |                  |
        |                  |         +-----------+          |                  |
        |                  |         | Encrypted |          |                  |
        |                  |         |    FT-    |          |                  |
        |                  |         | Transformer|         |                  |
        |                  |         +-----+-----+          |                  |
        +------------------+---------------+----------------+------------------+
                                           |
                                           v
                        +--------------------------------------+
                        |  ANALYZER  (correlation + evidence)  |
                        |  ALERT MANAGER  (severity, MITRE)    |
                        +------------------+-------------------+
                                           |
                                    WebSocket  ws://host:8000/ws
                                           |
                                           v
                        +--------------------------------------+
                        |  REACT DASHBOARD                     |
                        |  alert feed, 3D threat graph, FFT    |
                        |  spectrum, timeline, MITRE heatmap   |
                        +--------------------------------------+
```

The routing rule is strict and is the reason detection quality holds up on real captures:
CICFlowMeter events are only ever sent to models trained on CICFlowMeter data (DDoS, Port
Scan), and custom-extractor events are only ever sent to the models that need DNS strings
or session time-series (DGA, Exfiltration, C2, Encrypted Traffic). No model receives input
drawn from a distribution it was not trained on.

---

## Detection models

Each model targets one threat class. All six are wired into the registry and routed by the
analyzer.

| Model | Architecture | Training data | MITRE ATT&CK |
|---|---|---|---|
| DDoS | XGBoost binary classifier | CIC-DDoS2019 | T1498, T1499 |
| Port Scan | XGBoost + fan-out heuristic | CIC-IDS-2017 (CIC-native features) | T1046 |
| DGA | Char-level CNN + BiLSTM, 3-class | DGArchive 2024, Tranco 1M, synthetic tunnels | T1568.002 |
| Exfiltration | Variational Autoencoder | CIC-Bell-DNS-EXF-2021 | T1048, T1071.004 |
| C2 Beacon | BiLSTM with FFT spectral features | Synthetic and labeled beacon series | T1071, T1573 |
| Encrypted Traffic | FT-Transformer, 14 classes | Consolidated VPN / non-VPN dataset | T1573, T1572 |

### DDoS

Each flow is summarized by CICFlowMeter into 59 statistical features covering traffic
volume, inter-arrival timing, TCP flag counts, and packet-size distributions. Automated
flood tools produce sub-millisecond, highly regular intervals and uniform small packets;
amplification attacks show small requests against large responses. An alert requires three
conditions in series to keep production false positives low:

1. Model confidence above 98 percent. This is deliberately conservative and trades a small
   detection delay for far fewer false alerts.
2. A rate guard confirming the flow actually exhibits high throughput (`Flow Packets/s > 100`
   or `Flow Bytes/s > 50000`), so slow flows that merely resemble DDoS in their ratios do
   not trigger.
3. An all-zero guard that rejects degenerate flows with no valid feature data.

Source-IP diversity per destination is tracked as supplementary botnet evidence.

### Port Scan

Port scanning is the reconnaissance phase of an intrusion. The XGBoost model was retrained
on CIC-native features and scores 99.7 percent on held-out test data, but on real Nmap
scans replayed from PCAP it classifies the probes as benign at roughly 1 percent attack
probability even when one source fans out across hundreds of destination ports. The cause
is structural, not a tuning problem: port scanning is a cross-flow phenomenon. CICFlowMeter
turns each probe into its own single-SYN flow with no response, which is indistinguishable
at the per-flow level from an ordinary unanswered connection attempt. The scan signal only
appears when you aggregate across flows.

For that reason the operational detector is a destination-port fan-out heuristic that counts
unique destination ports per source IP within a window and alerts on high fan-out. This is
the same counting approach used by Zeek and RITA, precisely because reconnaissance is a
cross-flow behavior. The ML classifier is retained as a supplementary signal. Validated
end to end on a real 999-port Nmap scan (`172.16.0.1` to `192.168.10.50`, CIC-IDS-2017
Friday capture): the heuristic fired on the fan-out while the model reported benign.

### DGA

Domain Generation Algorithms let malware families such as Conficker, Necurs, Ramnit, and
Emotet rotate through hundreds of pseudo-random command-and-control domains per day, so
defenders cannot sinkhole a fixed address. The domain string is lowercased and encoded
character by character into a 128-element integer vector (vocabulary 40). A 1D CNN learns
local n-gram patterns that separate high-entropy generated strings from natural word
fragments, and a bidirectional LSTM captures domain-wide structure. The output is a 3-class
softmax: Benign, DGA, or DNS Tunnel.

The model is evaluated with family-wise holdout: 27 entire DGA families are held out of
training, which prevents the data leakage that random splits cause when near-identical
domains from one family land in both train and test. Under that honest split it reaches
0.9787 macro-F1, in the same 0.97 to 0.99 band reported by Cisco Umbrella, Elastic
(Endgame), and FANCI. The distinction is that NetSentinel classifies locally without
forwarding queries to an external resolver.

### Data Exfiltration over DNS

DNS tunneling encodes stolen data into DNS queries, using port 53 as a covert channel that
firewalls rarely block. Tools include dnscat2, iodine, dns2tcp, and Cobalt Strike DNS mode.
Detection is unsupervised. For each query, 24 lexical features are computed from the domain
string alone: Shannon and bigram entropy, character-composition ratios, length measures,
and structural counts. A Variational Autoencoder trained on benign DNS learns to reconstruct
normal query vectors; tunnel queries fall outside that distribution and reconstruct poorly,
producing high mean-squared error.

The separation is wide. Normal DNS lands at MSE 0.18 to 0.42; tunnel traffic at 0.99 to 140
(dns2tcp 0.99, iodine 1.44, dnscat2 61 to 140). The threshold sits at 0.70, with an
additional requirement that either the error exceeds 1.4 or the domain shows moderate
tunneling indicators (entropy above 4.0 with subdomain length above 20) before an alert
issues. Tested against the DNS-Tunnel-Datasets collection across seven tools and multiple
record types, the model reaches 100 percent true positive rate at 3.3 percent false
positive rate. An earlier build showed roughly 97.7 percent false positives because the
scaler was pickled with scikit-learn 1.6.1 and loaded under 1.3.2; that was resolved by
re-exporting the scaler under the pinned version and tuning the threshold from 0.15 to 0.70.

### C2 Beacon

After compromise, implants such as Cobalt Strike, Meterpreter, Sliver, and Brute Ratel
check in with their C2 at regular intervals. Even with jitter, this produces a periodicity
that human-driven traffic does not. The detector is dual-path. The temporal path is a
bidirectional LSTM over 100 consecutive flows between one source-destination pair, with four
features per timestep (inter-arrival time, packet size, byte count, direction). The spectral
path applies an FFT to the inter-arrival times and derives five features: FFT score,
dominant frequency, harmonic ratio, spectral entropy, and peak prominence.

Decision logic combines the two. A low-jitter beacon requires model probability above 90
percent with coefficient of variation below 0.05 and no match to a known benign periodic
pattern. An FFT-confirmed beacon requires probability above 90 percent with FFT score above
0.15, spectral entropy below 0.85, and peak prominence above 3.0. Known-benign periodic
traffic is explicitly excluded: NTP on port 123, TCP keepalives on 22/443/3389/5900, DNS
cache refresh on 53, and load-balancer health probes.

Status: the architecture and feature engineering are sound but the model has not yet been
validated against real botnet PCAP. CTU-13 Scenario 1 (Neris) is the recommended validation
target. The 100-flow activation threshold requires sustained capture, not brief snapshots.

### Encrypted Traffic

An FT-Transformer classifies encrypted flows into 14 application categories (chat, streaming,
file transfer, browsing, email, VoIP, P2P, and their VPN-tunneled variants) from 29 flow
metadata features, with no payload inspection. It reaches 88 percent accuracy. Its value is
encrypted-traffic visibility rather than a direct threat verdict: identifying traffic as VPN
is not itself malicious, but knowing what runs inside encrypted tunnels is operationally
useful in a SOC.

---

## Extraction pipeline

Four of the six models need features that CICFlowMeter cannot produce, so the pipeline is
hybrid and uses each tool where it is strongest.

| Requirement | CICFlowMeter | Custom Scapy extractor |
|---|---|---|
| Flow statistics for DDoS and Port Scan | Supported and required | Supported, but distribution differs |
| Individual DNS query strings for DGA | Not supported | Supported |
| 24 DNS lexical features for exfiltration | Not supported | Supported |
| 100-flow session time-series for C2 | Not supported | Supported |
| Real-time packet-by-packet live capture | Not supported | Supported |

**Phase 1, CICFlowMeter.** The PCAP is processed into flow features identical to those used
in training. A name-mapping wrapper translates the Python API output (`flow_byts_s`) to the
CIC CSV names the models expect (`Flow Bytes/s`). These events are tagged `cicflowmeter` and
routed only to DDoS and Port Scan.

**Phase 2, custom extractor.** The same PCAP is streamed packet by packet to produce DNS
events (to DGA and Exfiltration), flow events (to Encrypted Traffic), and session events, a
100-flow time-series per source-destination pair (to C2 Beacon).

### The covariate shift problem

When a model trained on CICFlowMeter features receives features computed by a different
implementation, the distributions diverge even when the feature names match. In testing, 92
percent of features showed statistically significant differences (Kolmogorov-Smirnov,
p < 0.05) between the custom extractor and CICFlowMeter, driven by differences in timeout
thresholds, TCP flag counting, and averaging windows. The resolution was to use CICFlowMeter
itself for the models trained on CICFlowMeter data, which removed the mismatch entirely.
This is why the routing rule described above is enforced strictly.

---

## Validated results

| Model | Evaluation dataset | Result | Method |
|---|---|---|---|
| DDoS | CIC-DDoS2019 test set, CIC-IDS-2017 PCAP | 99.97% F1, 0.998+ confidence on PCAP | XGBoost on CICFlowMeter features |
| DGA | DGArchive 2024, 137 families | 0.9787 macro-F1 | CNN-BiLSTM, char-level, family-wise split |
| Exfiltration | DNS-Tunnel-Datasets, 7 tools | 100% TPR, 3.3% FPR | VAE reconstruction error, threshold 0.70 |
| Port Scan | CIC-IDS-2017 Friday PCAP | 99.7% test, ~1% on real scans | ML supplementary; fan-out heuristic is primary |
| C2 Beacon | Not yet validated | Pending | Requires sustained botnet PCAP (CTU-13) |
| Encrypted Traffic | Consolidated VPN dataset | 88% accuracy, 14 classes | FT-Transformer |

The numbers above are reported honestly, including where they are weak. The port-scan ML
figure does not generalize and is documented as such; the C2 model is presented as
architecturally complete but not yet empirically confirmed.

---

## Dashboard

The React frontend connects over WebSocket and renders threat data live.

- **Alert feed.** Chronological, severity-colored stream with source and destination IPs,
  threat type, confidence, and MITRE technique IDs. This is the primary triage surface.
- **3D threat graph.** Force-directed topology where nodes are IPs and edges are detected
  threat connections. When one internal host appears across DGA, C2, and exfiltration
  edges, the kill chain becomes visible. This is the payoff of running six models at once.
- **FFT spectrum.** Frequency-domain view of inter-arrival times for suspected C2 sessions.
  A sharp peak (for example 0.0167 Hz for a 60-second beacon) lets an analyst confirm
  periodicity independently of the model verdict.
- **Attack timeline.** When each threat type fired over the capture, revealing phases:
  reconnaissance early, then C2 establishment, then exfiltration.
- **MITRE heatmap.** Detected threats mapped onto ATT&CK tactics and techniques.
- **Traffic charts.** Bandwidth, packet rate, and protocol distribution for baseline context.

---

## How NetSentinel compares

**Versus Wireshark.** Wireshark inspects individual packets for an expert. NetSentinel is
automated detection. They are complementary: NetSentinel flags, Wireshark investigates.

**Versus Snort and Suricata.** Signature systems match known-bad patterns with low false
positives but need constant rule updates and miss zero-days and unseen C2 frameworks.
NetSentinel's behavioral models flag anomalous patterns regardless of whether the specific
tool has been seen before. A new tunneling tool still produces high-entropy DNS queries.

**Versus commercial platforms (Cisco Umbrella, CrowdStrike, Darktrace).** These are mature,
better-resourced products, and NetSentinel does not claim higher per-model accuracy. The
practical differences are deployment (it runs in air-gapped networks that cloud platforms
cannot), auditability (every model, feature, and boundary is inspectable), data sovereignty
(no traffic leaves the network), and cost (no licensing fees).

---

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, uvicorn |
| Inference | ONNX Runtime, CPU execution |
| Packet processing | Scapy for dissection, CICFlowMeter for flow features |
| Frontend | React 19, Vite, Tailwind CSS |
| Visualization | Three.js for the 3D graph, Recharts for time-series and distributions |
| Real-time transport | WebSocket, server to client |
| Model distribution | HuggingFace Hub with local caching, offline capable |

---

## Installation

Prerequisites: Python 3.11, Node.js 18 or newer, and libpcap (Linux) or Npcap (Windows) for
live capture. PCAP-file analysis does not require capture drivers.

```
git clone https://github.com/qwertyuiopas17/wearecharliekirk.git
cd wearecharliekirk

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Model weights are not stored in the repository. On first run the backend downloads them from
the HuggingFace repository `Unded-17/netsentinel-models` into `~/.cache/netsentinel/models`
and reuses that cache on every subsequent start. After the first fetch the system runs fully
offline. To pre-stage weights for an air-gapped host, copy that cache directory across, or
download the repository manually and place the files under the same path.

Frontend:

```
cd frontend
npm install
```

Note on scikit-learn: `requirements.txt` pins `scikit-learn==1.3.2`. This pin is load-bearing.
The exfiltration scaler must be loaded under the same version it was exported with; a mismatch
was the cause of the earlier 97.7 percent false-positive rate.

---

## Running the system

Backend, from the repository root:

```
python run.py
```

This serves the API and WebSocket on port 8000. On startup the model registry loads all six
models and the console prints the health, WebSocket, PCAP-upload, and live-capture endpoints.

Frontend, in a second terminal:

```
cd frontend
npm run dev
```

Open the URL Vite prints. The dashboard connects to `ws://localhost:8000/ws` automatically.

Analyze a capture by uploading a PCAP through the dashboard or by posting it to
`/api/pcap/upload`. For a live source, start capture through `/api/capture/start`. A built-in
traffic simulator can drive the dashboard when no capture is available.

---

## API reference

Base URL `http://localhost:8000`. Interactive OpenAPI docs are served at `/docs`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness and model-load status |
| GET | `/api/alerts` | Recent alerts held in memory (most recent first) |
| GET | `/api/stats` | Aggregate detection statistics |
| POST | `/api/pcap/upload` | Upload a PCAP for offline analysis |
| POST | `/api/capture/start` | Start live capture on the configured interface |
| WS | `/ws` | Real-time alert and stats stream to the dashboard |

The WebSocket also accepts control messages from the client, for example
`{"action": "start_sim", "mode": "mixed"}` and `{"action": "stop_sim"}`, which drive the
traffic simulator.

---

## Configuration

All tunable constants live in `netsentinel/config.py`.

Detection thresholds (a model alerts when its confidence exceeds the threshold):

```
ddos               0.95     # the DDoS wrapper applies a stricter 98% gate plus a rate guard
c2_beacon          0.80
dga                0.70
encrypted_malware  0.70
port_scan          0.85     # conservative; the fan-out heuristic is the primary detector
exfiltration       0.70
```

Extraction and session parameters:

```
FLOW_IDLE_TIMEOUT     120    # seconds of inactivity before a flow is flushed
FLOW_ACTIVE_TIMEOUT   300    # maximum seconds a flow may stay open
SESSION_MIN_FLOWS     100    # flows per (src, dst) pair required before C2 detection runs
CAPTURE_INTERFACE     ...    # default capture interface; set per host and OS
```

Model paths, the HuggingFace repository ID, severity mapping, and the MITRE ATT&CK mapping
for all eight threat classes are also defined in this file.

---

## Project structure

```
wearecharliekirk/
├── run.py                          entry point, starts uvicorn on port 8000
├── requirements.txt                backend dependencies (scikit-learn pinned to 1.3.2)
├── netsentinel/
│   ├── main.py                     FastAPI app, startup model load, WebSocket, sim loop
│   ├── config.py                   paths, thresholds, severity and MITRE maps, HF repo
│   ├── models/
│   │   ├── registry.py             loads and holds all six ONNX models
│   │   ├── ddos.py                 XGBoost DDoS detector
│   │   ├── port_scan.py            XGBoost plus fan-out heuristic
│   │   ├── dga.py                  CNN-BiLSTM domain classifier
│   │   ├── exfiltration.py         VAE reconstruction-error detector
│   │   ├── c2_beacon.py            BiLSTM plus FFT beacon detector
│   │   └── encrypted.py            FT-Transformer traffic classifier
│   ├── extractor/
│   │   ├── cicflowmeter_wrapper.py Phase 1 flow-feature extraction
│   │   ├── flow_extractor.py       custom flow summaries
│   │   ├── dns_extractor.py        DNS query parsing
│   │   ├── dns_feature_builder.py  24 DNS lexical features
│   │   ├── session_builder.py      100-flow session time-series
│   │   ├── pcap_reader.py          PCAP ingestion
│   │   └── unsw_feature_builder.py legacy feature mapping
│   ├── pipeline/
│   │   ├── analyzer.py             routing, correlation, evidence assembly
│   │   └── alert_manager.py        severity assignment and alert retention
│   ├── api/
│   │   ├── routes.py               REST endpoints
│   │   └── websocket.py            WebSocket hub
│   └── simulator/
│       └── traffic_gen.py          synthetic traffic for demos
├── frontend/                       React 19 + Vite dashboard
├── scripts/                        operational and utility scripts
├── tests/                          test suite
└── dgatrain.ipynb                  DGA model training notebook
```

---

## 🔒 Forensic Integrity Layer (Experimental)

NetSentinel includes an **optional tamper-evident integrity layer** for forensic chain-of-custody, designed for high-assurance environments where cryptographic verification of detection provenance is required.

**Status:** 7 of 9 verification claims functional

### Quick Start

Enable with environment variable:
```bash
export INTEGRITY_ENABLED=true
python -m netsentinel.main
```

Visit the dashboard → click any alert → **"Verify" tab** → see cryptographic verification with expandable claim details.

### What Works (Phase 1)

- ✅ **Evidence integrity** (Claim 1) — Cryptographic detection of post-hoc evidence tampering
- ✅ **Feature integrity** (Claim 2) — Feature vector digest verification against committed receipt
- ✅ **Deterministic replay** (Claim 5) — Re-run inference on stored vectors, prove reproducibility
- ✅ **Policy verification** (Claim 6) — Detection thresholds/guards locked to receipts
- ✅ **Merkle inclusion** (Claim 7) — Windowed batching (60s), append-only ledger
- ✅ **Ledger consistency** (Claim 8) — Hash-chained blocks, Ed25519 signatures
- ✅ **External anchoring** (Claim 9) — Git-anchored checkpoints (demo; OpenTimestamps/RFC 3161 roadmapped)

### Phase 2 (In Progress)

- ⏳ **Model provenance** (Claim 3) — Signed release registry, model substitution detection
- ⏳ **Pipeline attestation** (Claim 4) — Code digest, schema freezing

### Architecture

Every alert receives a **DSSE-signed receipt** (in-toto Statement v1) containing cryptographic commitments to:
- Evidence digest
- Feature vector digest  
- Model digest (ONNX file hash)
- Policy digest (thresholds + decision gates)
- Decision (class, score in parts-per-million, threshold)

Receipts are Merkle-batched into 60-second windows and anchored to an append-only transparency log. The 9-claim verifier produces PASS/FAIL/UNVERIFIABLE verdicts for each guarantee. Any tampering — alert edits, model swaps, threshold changes — is cryptographically detectable.

**Design rationale:** See `docs/middle.md` (base layer), `PROOF_CARRYING_ALERTS_IMPLEMENTATION_PLAN.md` (provenance upgrade), and `docs/kj.md` (full integration) for threat model, industry precedent (Certificate Transparency, Guardtime KSI), and legal/evidentiary alignment (FRE 901/902, eIDAS).

**Key point:** This is **not** "blockchain for detection" (a misuse of the technology). It is a Certificate Transparency-style append-only log for forensic integrity — the one defensible use of blockchain patterns in intrusion detection.

---

## Known limitations

The system is honest about its boundaries.

- **Detection only.** NetSentinel does not block, quarantine, or otherwise act on traffic.
  It is a sensor, not an enforcement point.
- **Port-scan ML does not generalize.** The 99.7 percent test figure collapses on real
  scans because the phenomenon is cross-flow. The fan-out heuristic carries this class in
  production; the model is supplementary.
- **C2 beacon is not yet empirically validated.** The architecture is complete but needs
  validation against sustained real botnet PCAP such as CTU-13 Scenario 1.
- **C2 requires sustained capture.** The 100-flow activation threshold means brief snapshots
  will not trigger beacon detection.
- **Encrypted-traffic classification is not a threat verdict.** VPN usage is legitimate; the
  model provides visibility, not an accusation.
- **Scaler version coupling.** The exfiltration scaler is tied to scikit-learn 1.3.2. Do not
  bump that pin without re-exporting the scaler.

---

## Roadmap

With the pipeline now validated (covariate shift eliminated, exfiltration at 100 percent TPR
and 3.3 percent FPR, DGA corrected to an honest 0.9787 macro-F1), the foundation is stable
enough to extend. Near-term priorities:

- Validate C2 beacon detection against CTU-13 and other labeled botnet captures.
- Add a Legitimate Service Abuse detector for C2 and exfiltration that ride trusted services
  (Telegram bots, cloud storage, chat webhooks), where domain blocking is not viable.
- Broaden live-capture coverage and interface auto-detection across Linux and Windows.

---

## License

See [LICENSE](LICENSE).
```
