# PS 26145 — how NetSentinel meets the problem statement

**Problem statement 26145 (NTRO): AI-based detection of cyber threats in
unidirectional IP traffic.** This document maps every item of the expected
solution, every constraint and every threat family to the code that handles
it, the evidence an alert carries, the numbers that exist for it (with the
file each number comes from) and what is not claimed.

The console's **Overview** tab shows the same mapping live: the six threat
families with their alert counts, throughput, latency, and the five
constraints with values read from the running sensor (`GET /api/ps26145`).

Two kinds of detector are used and they are labelled everywhere:

* **Models** — trained networks and trees (ONNX / scikit-learn) with
  validation metrics from their training data (public datasets, partly
  synthetic — see section 5).
* **Rules** — deterministic detectors with thresholds set a priori, not
  fitted to data. They were added where the problem statement names a
  behaviour no model covers (source-IP entropy, record-type mix, JA3/JA4
  fingerprints, out/in byte ratio) and where a model did not hold up on real
  traffic (C2, see 3(b)). Apart from the C2 score's one labelled real
  beacon, none has been evaluated on labelled real attacks: their detection
  tests use synthetic scenarios, and their alert volume was measured on 40.5
  hours of the team's own traffic (section 4).

---

## 1. Expected solution

| The problem statement asks for | Where it is |
|---|---|
| A working prototype repository covering ingest, feature extraction, model inference and alert output | Ingest: `netsentinel/extractor/` (pcap/pcapng replay with a fast struct-level reader, live receive-only capture). Features: `flow_extractor.py` (59 CIC + 29 ISCX flow features, TLS/QUIC handshake metadata, packet-size sequence), `dns_extractor.py`, `dns_feature_builder.py`, `session_builder.py`. Inference: `netsentinel/models/` (ONNX models for DDoS, C2, DGA/tunnelling, DNS exfiltration and encrypted-traffic applications, plus the port-scan decision tree) and `netsentinel/detectors/` (5 rule detectors). Alert output: `pipeline/alert_manager.py` (schema v1), REST `/api/...`, WebSocket `/ws`, signed receipts (`netsentinel/integrity/`). |
| Documentation of models, features and the training/validation approach | Section 5 below; `README.md`; per-model metrics in `models/*/…_metrics.json`, `models/exfil/exfil_meta.json`; evaluations in `model_comparisons/`; alert fields in [`ALERT_SCHEMA.md`](ALERT_SCHEMA.md). |
| A dashboard of live or replayed detections with severity and confidence | The console at `http://localhost:8000/console/` (plain HTML/JS, no build step, no CDN): Overview (PS coverage, throughput, latency, constraints), Alerts (live table with severity, confidence and its kind, latency, flow ID; detail pane with the full alert record, evidence and integrity checks), Hosts, Models (with the figures), Inspector–Sentry (Tier 2 numbers, charts and a live run of the cascade), Integrity, Ingest (replay, live capture, simulator, benchmark). |

---

## 2. Constraints

### (a) Read-only ingest

Packets are only ever read: from capture files, or from an interface on a
SPAN port / tap through Scapy's `sniff(store=False)`. There is no transmit
path anywhere in the sensor, no active probing, and detection needs no
internet connection (the models ship in `models/`). The simulator is a third,
clearly labelled source of synthetic events.

### (b) No payload decryption — TLS/QUIC metadata only

* **TLS over TCP:** JA3, JA3S, JA4, SNI, ALPN, offered/negotiated versions and
  cipher counts are read from the ClientHello and ServerHello, which TLS sends
  in the clear before any key exists (`netsentinel/extractor/tls_parse.py`).
  Application data is never read. JA4 is checked against the worked example
  in the JA4 specification and JA3 against the Salesforce reference
  implementation (`tests/test_tls_fingerprints.py`).
* **QUIC:** the ClientHello sits inside Initial packets that are protected with
  keys anyone can derive from the packet header and a salt published in
  RFC 9001 §5.2 — which is how Wireshark, Zeek and the JA4 tools read them,
  and how the Tier 2 track already does (`tier2/AUDIT.md`). Reading them still
  means running a decryption, so in the live pipeline it is **off by default**
  (`QUIC_INITIAL_PARSE`, environment variable
  `NETSENTINEL_QUIC_INITIAL_PARSE=1` to enable). When enabled it opens only a
  flow's first client Initial packets (at most four datagrams) and keeps only
  ClientHello metadata (`netsentinel/extractor/quic_initial.py`, checked
  against RFC 9001 Appendix A key vectors and real aioquic Initials). With it
  off, QUIC flows are analysed on sizes and timing like any other UDP flow.
* The Overview shows the switch's state and how many hellos were read.

### (c) Streaming with bounded latency

Every event is analysed as it arrives; nothing waits for a batch except the
windowed detectors, whose windows are part of their definition:

| Stage | Bound |
|---|---|
| A TCP flow reaches the detectors | at FIN/RST, after 120 s idle, or after 300 s active (`FLOW_IDLE_TIMEOUT`, `FLOW_ACTIVE_TIMEOUT`) |
| An unanswered probe (single packet) | after 5 s (`PROBE_FLOW_TIMEOUT_S`); live idle sweep every 5 s |
| DDoS rate / entropy window | 10 s |
| Port-scan window | 60 s of wire time or 1,000 flows, whichever comes first (closed by a timer in live mode even if traffic stops) |
| DNS behaviour window | 5 min |
| C2 combined score | needs ≥ 20 check-ins over ≥ 30 min — a beacon cannot be called periodic sooner |
| Analyzer time per event | measured continuously: p50/p95/p99 per event type and per detector (Overview → Latency, `GET /api/metrics`) |
| Ingest-to-alert time | carried by every alert whose ingest time is known (`latency_ms.ingest_to_alert`) |

Measured in the development container on the synthetic 100,000-packet
capture (benchmark below, `model_comparisons/ps26145_benchmark_synthetic.json`):
analyzer time per flow event p50 0.09 ms, p95 0.19 ms; per DNS query p50
0.04 ms, p95 0.07 ms (DNS name-model results are cached per name). The
heaviest single step is closing a port-scan window, which happens every 60 s
of wire time or every 1,000 flows, whichever comes first; alerts from that
window wait for it to close.

On the team's real captures (three 200 MB files, table below) the analyzer
took p50 0.08–0.14 ms and p95 1.9–2.5 ms per flow event, and p95 0.25–1.9 ms
per DNS query (`model_comparisons/ps26145_benchmark_real.json`). The p95 is
higher than on the synthetic capture because the application classifier
(about 1.5–1.8 ms a flow) runs on up to 50 flows a second and these captures
have fewer flows in total.

### (d) Stated and demonstrated throughput

`scripts/benchmark_throughput.py` (or **Run benchmark** on the Ingest tab /
Overview) replays a capture through the same streaming path live capture
uses — packet parsing, flow/DNS/TLS extraction and every detector — as fast
as one Python process can, with its own analyzer so nothing is added to the
running sensor, and reports what it sustained. Run from the console, it
shares the sensor's Python process, so stop the simulator or live capture
first for a clean figure. Throughput while running is also measured
continuously over 10 s windows (Overview → Throughput).

| Where | Input | Packets/s | Mbps | Flows/s | Real-time factor |
|---|---|---|---|---|---|
| Development container: one Python process, 2 vCPUs (Intel Xeon @ 2.80 GHz) | synthetic, 100,006 packets, 69.1 MB, 7,827 flows | 22,439 | 124.1 | 1,756 | 4.6× |
| Linux VM on the team's laptop: one Python process, 2 vCPUs (AMD Ryzen 5 5600H) | team capture, 24 Sep: 121,722 packets, 196.0 MB, 836 flows | 35,972 | 463.3 | 247 | 163× |
| same | team capture, 25 Sep: 47,215 packets, 198.4 MB, 939 flows | 24,274 | 816.0 | 483 | 654× |
| same | team capture, 26 Sep: 270,309 packets, 191.1 MB, 2,350 flows | 41,807 | 236.4 | 364 | 464× |

Sources: `model_comparisons/ps26145_benchmark_synthetic.json` and
`model_comparisons/ps26145_benchmark_real.json`, both with the final code;
repeated runs on the laptop VM varied by about 10%. The team's captures come
from one laptop, and two of the three have average packet sizes above the
1,514-byte Ethernet maximum (1,610 and 4,202 bytes): segments coalesced by
the network card, so their Mbps is higher than wire-size packets would give.
Packets/s and flows/s are the figures to compare. They also hold few flows;
the synthetic mix is the flow-heavy case, and its DNS names repeat a lot,
which favours the name cache. What one process sustains here, roughly
24,000–42,000 packets/s, is below a busy gigabit link; such a link needs
several sensor processes on split traffic, which is not implemented. State
the figure measured on the deployment hardware.

What the benchmark does not include: CICFlowMeter's batch pass (pcap mode
only, not part of live mode), and more than one process — the sensor is a
single process; scaling out by running several sensors on hashed slices of
the traffic is possible in principle but not implemented.

Two engineering changes made this possible and are covered by tests:
a struct-level pcap/pcapng reader (`netsentinel/extractor/fastpath.py`) that
produces field-for-field the same events as Scapy (checked by
`tests/test_tls_fingerprints.py::test_fast_reader_matches_scapy`), and a
per-name cache for the two DNS name models (they are pure functions of the
name). The telemetry-only encrypted-application classifier (about 1.5–1.8 ms
per flow; its ONNX export takes one flow at a time)
is capped at 50 classifications per second so it cannot become the ceiling of
the detectors that raise alerts.

### (e) Standardized alert schema

Every alert, from every detector, is built in one schema,
`netsentinel.alert/v1`: timestamp and event time/window, flow identifier with
Community ID, threat class, subtype and PS category, confidence and what kind
of number it is, severity, detector, evidence, ATT&CK mapping and latency.
See [`ALERT_SCHEMA.md`](ALERT_SCHEMA.md) and
[`alert_schema_v1.json`](alert_schema_v1.json). Alerts are checked as they are
built (`schema_violations`, shown on the Overview) and validated against the
JSON Schema in the tests.

---

## 3. Threat families

### (a) DDoS — SYN floods, UDP reflection/amplification, spoofed traffic, rate and entropy of source IPs

| | |
|---|---|
| Model | XGBoost, 59 flow features, trained on CIC-DDoS2019 (345,096 train / 86,275 test flows; F1 0.9997, ROC-AUC 0.999999 on that test split — `models/Ddos_detection/ddos_metrics.json`). Runs on CICFlowMeter flows (pcap mode) and simulator flows. |
| Rule | Per-destination 10 s window (`netsentinel/detectors/ddos_volume.py`): flow, packet and byte rate; source-IP entropy in bits and normalised; SYN-only and UDP share; top destination port; top UDP source port and the amplifier service it belongs to (NTP, DNS, SSDP, CLDAP, Memcached, …); handshake completion. Evaluated once the window holds ≥ 200 flows; fires on ≥ 100 new flows/s with a flood shape from ≥ 10 distinct sources (distributed), and ≥ 5× the destination's own baseline once one exists. |
| Subtype | `SYN flood`, `UDP reflection/amplification (<service>)`, `UDP flood`, `TCP flood`, with `(spoofed sources likely)` when ≥ 100 distinct sources, ≥ 90% of flows from a source new to the window and ≤ 5% completed handshakes. The binary model has no subtype of its own; the family comes from the window. The 18-class CIC-DDoS2019 model's label is attached as a hint only (macro F1 0.55). |
| Guards | A model alert needs ≥ 20 flows toward the destination in the window (a lone SYN probe and a lone flood packet look the same to a per-flow model); a window shaped like a scan (at most three sources, no port taking half the flows, no flood shape) is left to the scan detector; one alert per destination and family per 30 s; scan alerts from a flood's own sources are not raised separately. |
| Measured | No rule alert on 40.5 hours of the team's traffic (section 4). Before the ≥ 10-sources condition was added it raised one: a single client sending 205 DNS queries to its resolver within a second (`model_comparisons/ps26145_fixes_found_on_real_traffic.json`). |
| Not claimed | The rule's thresholds are starting points, not tuned on real attacks. Live mode relies on the rule: the XGBoost model is not run on the sensor's own flow features, which drift from the CICFlowMeter features it was trained on (`PIPELINE_TEST_PART3.md` §5). |

### (b) C2 beaconing

| | |
|---|---|
| Primary | Combined periodicity score, run live on every flow (`netsentinel/detectors/beacon_score.py`): 0.30 timing regularity + 0.20 FFT periodicity + 0.20 size regularity + 0.15 destination rarity + 0.15 persistence, per (source, destination) per 6-hour window, ≥ 20 check-ins over ≥ 30 min, known periodic services dropped, alert at 0.80. Same formula, weights and threshold as the offline evaluation; a test checks the live code gives identical numbers. |
| Evaluation of the score | On 97 captured hours over 8 days with one labelled beacon (`model_comparisons/c2_beacon_score_eval.json`): the beacon scored 0.824 and was caught at 0.80; 48 of 357 other sessions also scored ≥ 0.80 — 11.9 per 24 hours of capture, an upper bound because that traffic is unlabelled and treated as benign; they came from 12 distinct services. The beacon ranked 4th of 15 sessions in its own 6-hour window, and 42 sessions across all days scored at or above it, so the score narrows the list rather than singling the beacon out. |
| Evidence model | BiLSTM + FFT (CTU-13 / CIC-IDS2017, F1 0.998 on its test split — `models/c2_beacon_detector/c2_metrics.json`). On the real beacon's window it gave a probability of about 1.0 to all nine pairs it could score and, with its shipped gates, did not fire on the beacon but did fire on one benign pair (`model_comparisons/c2_compare.json`). Its verdict is therefore attached to combined-score alerts as evidence and does not decide (`C2_BILSTM_ALERTS = False`). |
| Live, on the team's traffic | 69 alerts in 40.5 hours (40.9 per 24 h; 8 source addresses, 29 destinations — section 4), about 3.4 times the offline rate. A likely reason is that live scoring alerts during the window, when rarity and persistence are computed on the part seen so far, while the offline run scored whole windows; the traffic also differs (24–27 Sep here, 18–25 Sep offline). |
| Not claimed | One labelled beacon is one data point; live scoring can alert before the 6-hour window closes because rarity and persistence use what has been seen so far. |

### (c) DGA and DNS tunnelling — entropy, n-grams, query length, record-type anomalies

| | |
|---|---|
| Model | Character-level CNN-BiLSTM, three classes (benign / DGA / DNS tunnel), macro F1 0.979 on its validation split (`models/dga_dna_tunneling_detection/dga_metrics.json`). Reads each name character by character, so it learns n-gram structure, length and character mix; an entropy gate (> 3 bits/char) and a known-service allowlist sit in front of its alerts. The training notebook (`dgatrain.ipynb`) takes benign names from the Tranco top-1M list and DGA names from DGArchive/Kaggle sets, and generates the DNS-tunnel class synthetically (random 10–60-character labels), so the tunnel part of that F1 is easy by construction. |
| Rules | `netsentinel/detectors/dns_behaviour.py`, per host over 5 minutes: **NXDOMAIN burst** (≥ 25 replies seen, ≥ 20 of them NXDOMAIN and ≥ 50%, across ≥ 10 base domains → `DGA`); **record-type anomaly** (≥ 30 queries to one base domain, ≥ 20 distinct names, ≥ 50% TXT/NULL/CNAME/MX/SRV/ANY/private → `DNS Tunnel`); **subdomain fan-out** (≥ 50 distinct names with leftmost labels averaging ≥ 20 characters → `DNS Tunnel`). |
| Extraction change | Every query type is now kept (the extractor used to drop everything but A/AAAA/CNAME/MX/TXT/SRV, which discarded exactly the NULL/ANY/private types tunnels use), and DNS replies are passed on (rcode, answer count, size). |
| Measured | On 40.5 hours of the team's traffic (51,918 queries): the three rules raised no alert; the name model raised 98 DGA and 17 tunnel-like alerts (5 and 3 source addresses), each at most once per source and base domain per 10 minutes (`DNS_MODEL_ALERT_REPEAT_S`; it was 60 s, which gave an alert a minute for a name queried every minute). |
| Not claimed | DNS-based reputation lookups by some security products look like fan-out; allow them per site (`DNS_BEHAVIOUR["allow_bases"]`). The NXDOMAIN rule needs to see replies. |

### (d) Malware in encrypted sessions — JA3/JA3S/JA4, packet-size and timing sequences

| | |
|---|---|
| Extraction | JA3/JA3S/JA4 from the cleartext hello, reassembled across TCP segments and TLS records; the first 20 payload packets' sizes, directions and times (`splt`) for every flow. |
| Rule | `netsentinel/detectors/tls_sessions.py`, per client → server → JA4 over 6 hours, from the 8th session: 0.30 fingerprint rarity on this sensor + 0.20 session-start regularity + 0.15 bytes-per-session regularity + 0.15 repeated packet-size sequence + 0.20 ClientHello anomalies (no SNI, no ALPN, nothing newer than TLS 1.1, ≤ 6 cipher suites, TLS on a non-TLS port). Alert at 0.70. An exact JA3/JA3S/JA4 match on the operator's blocklist (`netsentinel/intel/tls_fingerprint_blocklist.json`) alerts on the first session. |
| Measured | 21,138 ClientHellos parsed from 40.5 hours of the team's traffic; no alert (section 4). The five public malware-sandbox captures in the team's `PCAPS/` folder (about 8 minutes, 5 ClientHellos in total) are far too short to reach the 8-session minimum, and raised no TLS alert (`model_comparisons/ps26145_sandbox_pcaps_eval.json`). |
| Not claimed | This detector has not been measured on labelled malware traffic long enough for it to work, so it is a triage signal. The blocklist ships empty; nothing in it was invented. Rare, regular, legitimate clients (a custom updater, a monitoring agent) will also score high; the evidence shows the fingerprint, the hello flags and the size sequence so an analyst can tell. |

### (e) Reconnaissance and port scans — fan-out across ports or hosts

| | |
|---|---|
| Model | Network-event decision tree (SPSD, after Ring et al. 2018) over per-source 60 s windows, trained on CIDDS-001 (`netsentinel/models/weights/portscan_spsd_decisiontree.pkl`). 99.0% of the scans in the CIDDS-001 validation set (17,843 of 18,023 — `PORT_SCAN_COMPLETE.md`); that is the model on its dataset, not a NetSentinel detection rate. |
| What the tree decides on | Printed from the shipped tree: two or more contacts in a window to internal addresses that `network_info.json` does not list (NEIP), one or more contacts to a port it does not list as open on a listed host (NETCP), or 52 or more distinct targets (RWA). It reads each flow as a one-way record, like the NetFlow it was trained on — replies are not used, so every distinct target counts toward RWA — which is why it works on a one-way view as well as a two-way one. Four more leaves that can call a scan rest on 11 of its 12,911 training events (zero RWA: 4; three or four ICMP errors: 1; succession of exactly 2,334 windows: 2, at probability 0.5; succession of 2,980 windows or more: 4). ICMP is not parsed and succession is now capped at 2,333, so of these only the zero-RWA leaf can still fire. |
| Backstops | ≥ 100 distinct destination ports from one source in a window (vertical), and new: ≥ 32 hosts on the same port (host sweep). Ports a normal client fans out on toward the internet (DNS, web, NTP, DoT, mDNS) only count internal targets. |
| Inputs left out | Flows to multicast, limited-broadcast and unspecified addresses (service discovery is never answered by the group address), and a client's traffic to internet addresses on the ports above (a browsing burst can reach 52 servers in a minute). Both were found on the team's traffic; section 4. |
| Extraction change | Single-packet flows (unanswered SYNs) are now emitted as probe records after 5 s instead of being dropped, and live capture feeds the scan window (it used to reach only the pcap path). TCP teardown packets after a FIN no longer open a phantom one-packet flow per connection. Succession advances once per source and window even when a busy window reaches the tree in several batches. |
| Measured before this update | Through the real analyzer (`model_comparisons/README.md` §4): on 4 hours of the team's own capture (6,187 flows, 149 sources, no scans run, so every flag is a false-alarm upper bound) the tree raised 66 alerts from 4 sources and the fan-out rule alone raised none (`ps_spsd_benign.json`, `ps_rule_benign.json`); on 5 simulated scanners the tree caught 5 and the fan-out rule 2 (`ps_spsd_scans.json`, `ps_rule_scans.json` — the scans come from the project's own simulator, so this is a relative comparison only). |
| Live, on the team's traffic | 32 alerts in 40.5 hours, from 2 source addresses, every one decided by NEIP ≥ 2: contacts to internal addresses that the shipped `network_info.json` does not list, because it describes a demo network, not the team's (`model_comparisons/ps26145_live_path_eval.json`). 88,826 flows to internet addresses on web, DNS, NTP, DoT and mDNS ports and 6,258 multicast/broadcast flows were left out of the window. |
| Not claimed | NEIP and NETCP are only as good as `network_info.json`: describe the site's subnets, hosts and open ports there, or empty `known_hosts` and `known_open_ports`, which switches both indicators off (the loader's degraded mode) and leaves RWA and the backstops. Outbound scans of internet hosts on web, DNS or NTP ports are not seen by the tree after the exemption. ICMP is not parsed, so ping sweeps are not seen. The tree's own adapter looks for CICFlowMeter's CSV column names for reply packets and TCP flags, which the sensor's records do not use, so those fields reach it as zero; that matches its one-way training data for replies but not for flags, which matter to it only through RWA (RST is not among its splits). |

### (f) Data exfiltration — asymmetric flow volume, out/in byte ratio

| | |
|---|---|
| Rule | `netsentinel/detectors/exfil_ratio.py`: bytes sent and received per internal host → external destination over 15 minutes, on connections the internal host opened; alert at ≥ 5 MB out and ≥ 10× what came back. Flows seen in one direction only are skipped, not scored (a one-way view would make every ratio infinite). |
| Model | VAE over 24 lexical features of DNS names, trained on CIC-Bell-DNS-EXF-2021 (ROC-AUC 0.78, PR-AUC 0.83, best F1 0.89 — `models/exfil/exfil_meta.json`) — exfiltration over DNS. |
| Honesty fix | DNS-tunnel alerts used to carry an invented byte ratio (subdomain length × 50 bytes out, 512 bytes in) when no byte counts existed. Byte counts now appear only when measured — from the simulator, or from the DNS behaviour tracker's query and reply sizes (labelled as such). |
| Measured | On 40.5 hours of the team's traffic: the byte-ratio rule raised 4 alerts (2 source addresses, 4 destinations); the VAE raised 560 (332 per 24 h, from 6 source addresses; at least 456 of them at INFO severity), the largest source of alerts on this traffic (section 4). |
| Not claimed | Backups, cloud sync, video uploads and large pushes are legitimate asymmetric uploads; the alert names the destination and port so a known service can be allowed. |

---

## 4. Alert volume on the team's own traffic

All 83 capture files the team's sensor recorded from 24 to 27 September
2026 were replayed through the live-mode path — the sensor's own extractor
and every detector, as live capture runs them (CICFlowMeter, and so the
DDoS XGBoost model, not run) — with `model_comparisons/ps26145_live_path_eval.py`
and the final code. The traffic is unlabelled, so every count is an upper
bound on false alarms on this network, not a false-positive rate. Result:
`model_comparisons/ps26145_live_path_eval.json`.

40.5 captured hours: 11.3 million packets, 11.0 GB, 101,874 flows, 8,856
single-packet probe records, 51,918 DNS queries, 21,138 TLS ClientHellos.
Replaying all of it took about 5 minutes. It ran in four parts — 24
September, 25 September in two halves, and 26–27 September — and detector
state starts fresh in each.

| Detector | Alerts | Per 24 h | Source addresses |
|---|---|---|---|
| DNS exfiltration VAE (model) | 560 | 332.1 | 6 |
| DGA name model — machine-generated | 98 | 58.1 | 5 |
| C2 combined periodicity score (rule) | 69 | 40.9 | 8 |
| Port-scan tree (all on NEIP against the demo `network_info.json`, see 3(e)) | 32 | 19.0 | 2 |
| DGA name model — tunnel-like | 17 | 10.1 | 3 |
| Byte-ratio exfiltration (rule) | 4 | 2.4 | 2 |
| DDoS rate/entropy (rule) | 0 | 0 | — |
| DNS behaviour: NXDOMAIN, record type, fan-out (rules) | 0 | 0 | — |
| Encrypted-session profile (rule) | 0 | 0 | — |
| **All** | **780** | **462.5** | |

By severity: 554 INFO, 70 MEDIUM, 57 HIGH, 99 CRITICAL. The confidence
cut-offs are the ones the sensor already had — any detector's confidence
above 0.95 makes an alert CRITICAL, which is where the port-scan tree's
probability-1.0 alerts land — and uncertain DNS-name detections go to INFO;
that INFO rule no longer depends on the invented byte ratio (3(f)).

Six defects surfaced in this replay (one in the synthetic benchmark
capture) and were fixed before the run above; the before/after counts are
in `model_comparisons/ps26145_fixes_found_on_real_traffic.json`, each with
a test:

* multicast and broadcast flows counted as port scans (1,057 scan alerts in
  the first 15 hours before, 3 after);
* a flagged DNS name raising a model alert every minute (the exfiltration
  VAE's alerts in the same 15 hours went from 383 to 159 with a 10-minute
  repeat window);
* one client's burst of DNS lookups called a UDP flood (1 alert before, 0
  after);
* a browsing burst read as a host sweep (port-scan alerts over the 40.5
  hours went from 38 to 32; the 4 host sweeps are gone);
* any host active long enough becoming a "scanner" through the tree's
  succession splits (flagged from its 2,980th active window on; not visible
  in parts of at most 15 hours, shown by the test);
* one busy window evaluated several times (in the synthetic capture 241
  port-scan alerts before, 197 after; unchanged on the team's traffic).

The five malware-sandbox captures (`model_comparisons/ps26145_sandbox_pcaps_eval.json`)
raised 4 exfiltration-VAE and 3 DGA alerts; at about 8 minutes in total they
are too short for the session-level detectors (C2, TLS sessions).

---

## 5. Models, features and training / validation

| Detector | Kind | Input | Trained / validated on | Reported metric (source) |
|---|---|---|---|---|
| DDoS classifier | XGBoost (ONNX) | 59 CICFlowMeter flow features | CIC-DDoS2019, 80/20 split | F1 0.9997, ROC-AUC 0.999999 binary; 18-class macro F1 0.55 (`models/Ddos_detection/ddos_metrics.json`) |
| C2 sequence model | BiLSTM + FFT (ONNX) | 100 flows × (gap, packet size, bytes, direction) + 5 FFT features | CTU-13 beacons, CIC-IDS2017 and CTU-13 normal, 9,750 synthetic | F1 0.998, ROC-AUC 0.9998 (`models/c2_beacon_detector/c2_metrics.json`) — see (b) for its behaviour on real traffic |
| DGA / tunnel names | CNN-BiLSTM (ONNX) | domain characters (first 128) | Tranco top-1M (benign), DGArchive/Kaggle (DGA), synthetic tunnel names; 3 classes | macro F1 0.979 (`models/dga_dna_tunneling_detection/dga_metrics.json`) — tunnel class synthetic, see (c) |
| DNS exfiltration | VAE (ONNX) | 24 lexical features of the name | CIC-Bell-DNS-EXF-2021 | ROC-AUC 0.78, PR-AUC 0.83, best F1 0.89 (`models/exfil/exfil_meta.json`) |
| Port scan | Decision tree (SPSD) | 6 network-event features per source per 60 s | CIDDS-001 | 99.0% of validation scans (`PORT_SCAN_COMPLETE.md`) |
| Encrypted-traffic apps | FT-Transformer (ONNX) | 29 ISCX-style flow features | ISCX VPN-nonVPN, 14 classes | accuracy 0.881, macro F1 0.857 (`models/encrypted_traffic_transformer/ett_metrics.json`) — telemetry, no alerts |
| C2 combined score | Rule | check-in times and bytes per host pair | none (weights fixed a priori) | one labelled beacon on the team's capture, see (b); alert volume in section 4 |
| DDoS rate / entropy | Rule | per-destination window | none | detection: synthetic scenarios only; alert volume in section 4 |
| DNS behaviour | Rule | per-host query/reply window | none | detection: synthetic scenarios only; alert volume in section 4 |
| Encrypted sessions | Rule | JA3/JA4, session sizes/times | none | detection: synthetic scenarios only; alert volume in section 4 |
| Exfiltration by volume | Rule | per host-pair bytes | none | detection: synthetic scenarios only; alert volume in section 4 |

Validation metrics are the models' results on held-out parts of their own
public datasets. They are not detection rates on a NetSentinel deployment;
that needs labelled traffic from the site, which the project does not have.

---

## 6. Demonstrating it

```bash
pip install -r requirements.txt
python run.py                               # http://localhost:8000/console/
pytest tests/                               # includes tests/test_ps26145.py, tests/test_tls_fingerprints.py
python scripts/benchmark_throughput.py --synthetic 100000
python scripts/benchmark_throughput.py --pcap <capture.pcap>
```

1. **Overview** — the six families, throughput, latency, constraints.
2. **Ingest → Simulator → Mixed (all six)** — synthetic scenarios for every
   family: spoofed SYN flood and NTP reflection, a 36-minute beacon (back-dated,
   so it is scored at once), DGA names, an NXDOMAIN burst, a TXT tunnel, a rare
   TLS client, a vertical scan, a host sweep, DNS exfiltration and a 7.5 MB
   upload. Internal hosts use private ranges; every external or attacker
   address comes from the RFC 5737 documentation ranges.
3. Click a family tile → its alerts → open one: the alert record (schema v1),
   the evidence panel, and **Verify claims** / **Replay inference** — every
   detector's alerts now carry a signed receipt and replay to the same
   decision.
4. **Ingest → Replay a capture** — a real `.pcap`/`.pcapng`; the Overview shows
   the rate it is processed at.
5. **Ingest → Throughput benchmark** — the figure for constraint (d), with the
   machine it was measured on.
6. **Inspector–Sentry → Run the cascade** — Tier 2 end to end on a synthetic
   organisation (about 30 s on CPU; needs PyTorch), beside its real-data
   numbers re-derived from `tier2/*.json`. Not part of the live pipeline.

Figures for this document: `docs/figures/` (drawn by
`scripts/make_ps_figures.py` from the result files) and the README's Figures
section.

---

## 7. Limits, stated

* Rule detectors are heuristics with a priori thresholds; apart from the C2
  score's one labelled beacon, none is evaluated on labelled real attacks.
* The encrypted-session detector has not seen malware traffic long enough to
  reach its 8-session minimum.
* On the team's own traffic the pre-existing DNS models raise most alerts:
  the exfiltration VAE 332 and the DGA model 68 per 24 hours (section 4).
* The live C2 score alerts about 3.4 times as often per day as the offline
  whole-window evaluation did (section 3(b)).
* The port-scan tree's NEIP and NETCP indicators need the site described in
  `netsentinel/netinfo/network_info.json`; the shipped file describes a demo
  network, and all 32 port-scan alerts on the team's traffic came from it.
* The pipeline is one Python process; throughput figures are per sensor process.
* In live mode DDoS detection is the rate/entropy rule (the model reads
  CICFlowMeter features, which only exist in pcap mode).
* ICMP is not parsed; ping sweeps are not seen.
* Where the tap sees one direction only, the byte-ratio detector and the
  NXDOMAIN rule have nothing to work with and say so rather than guess.
* Tier 2 (Inspector–Sentry, `tier2/`) is verified standalone and not wired
  into this pipeline.
* The simulator is synthetic; alerts it produces show that the code paths
  work, not how well real attacks are caught.
