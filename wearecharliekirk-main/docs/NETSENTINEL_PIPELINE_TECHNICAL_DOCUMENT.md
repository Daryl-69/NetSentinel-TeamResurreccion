# NetSentinel — Technical Pipeline Documentation

_Prepared for technical review by cybersecurity professionals and evaluation panels._

---

## 1. System Overview

NetSentinel is a passive, machine learning-based Network Intrusion Detection System (NIDS). It ingests raw network traffic — either from PCAP files or live capture from a span port — extracts behavioral features from each packet and flow, and routes them through six specialised detection models. Alerts are delivered in real time to a browser-based dashboard via WebSocket.

The system is designed around three architectural principles:

1. **Passive observation.** NetSentinel operates on a copy of network traffic (mirror port or TAP). It does not sit inline, does not modify packets, and cannot cause network disruption. Its role is detection and alerting — response decisions remain with the analyst.

2. **Offline operation.** All six models run locally via ONNX Runtime on standard hardware. There are no cloud dependencies, no API calls, and no telemetry. This makes the system suitable for deployment in air-gapped environments — government networks, defence installations, and SCADA/ICS infrastructure where cloud-based security tools cannot be used.

3. **Metadata-only analysis.** NetSentinel never inspects packet payloads. It operates on headers, flow statistics, DNS query strings, and timing metadata. This allows detection on encrypted traffic (TLS 1.3) without requiring decryption, and respects data privacy by design.

All models are exported to the ONNX format (Open Neural Network Exchange), providing a consistent inference interface across architectures (XGBoost, BiLSTM, Transformer).

---

## 2. Detection Models

Each model addresses a distinct threat class. The following sections describe, for each model, what it detects, what features it uses, how the detection decision is made, and what its current limitations are.

---

### 2.1 DDoS Detection

| | |
|---|---|
| **Architecture** | XGBoost gradient-boosted tree (binary classifier) |
| **Training data** | CIC-DDoS2019, Canadian Institute for Cybersecurity |
| **Input** | 59 network flow features extracted by CICFlowMeter |
| **Decision threshold** | 98% model confidence, with heuristic rate guard |
| **MITRE ATT&CK** | T1498 (Network Denial of Service), T1499 (Endpoint DoS) |

#### What it detects

Distributed Denial of Service attacks — both volumetric (SYN floods, UDP floods, DNS/NTP/LDAP amplification) and application-layer (Slowloris, HTTP floods). The training data contains over 50 million flows across 13 attack subtypes.

#### How detection works

Each network flow (a bidirectional conversation identified by its 5-tuple) is summarised into 59 statistical features by CICFlowMeter. These features capture:

- **Traffic volume:** Total forward/backward packets, flow bytes per second, flow packets per second. DDoS traffic produces extreme packet rates and asymmetric byte ratios — reflection attacks, for instance, generate massive inbound responses from small outbound queries.
- **Timing characteristics:** Inter-arrival time statistics (mean, standard deviation, minimum, maximum) for both directions. Automated flood tools produce sub-millisecond, highly regular intervals, while normal traffic is bursty and variable.
- **Protocol indicators:** TCP flag counts (SYN, ACK, FIN, RST, PSH, URG). A SYN flood consists almost entirely of SYN packets. A UDP amplification attack has no TCP flags at all.
- **Packet size distributions:** Forward and backward packet length statistics. SYN floods produce uniformly small packets (40–60 bytes); amplification attacks show the signature pattern of small requests and large responses.

The model outputs a probability that the flow is an attack. To reduce false positives in production, we require:

1. The model confidence must exceed **98%** — this is deliberately conservative, trading slight detection delay for significantly fewer false alerts.
2. A **heuristic rate guard** checks that the flow actually exhibits high traffic rates (`Flow Packets/s > 100` or `Flow Bytes/s > 50,000`). This prevents false positives on slow flows that happen to resemble DDoS in their feature ratios.
3. An **all-zero guard** rejects flows with no valid feature data (degenerate flows from incomplete captures).

Additionally, the analyser tracks source IP diversity per destination. A large number of distinct source IPs targeting a single destination is consistent with botnet-driven DDoS and provides supplementary evidence for the alert.

#### Validation

The model achieves 99.97% F1-score on the CIC-DDoS2019 held-out test set. We validated the full pipeline (PCAP → CICFlowMeter → model) on the CIC-IDS-2017 Friday dataset, where it produced detections at 0.998+ confidence with zero extraction errors across 6,690 flows.

---

### 2.2 DGA Detection

| | |
|---|---|
| **Architecture** | Character-level CNN + Bidirectional LSTM (3-class classifier) |
| **Training data** | DGArchive 2024 (474K domains, 137 malware families) + Tranco Top-1M (legitimate) + 50K synthetic tunnel domains |
| **Input** | Domain name string, encoded character-by-character into a 128-element integer vector |
| **Output** | Three-class softmax: Benign, DGA, or DNS Tunnel |
| **MITRE ATT&CK** | T1568.002 (Dynamic Resolution: Domain Generation Algorithms) |

#### Threat context

Domain Generation Algorithms are used by malware families — including Conficker, CryptoLocker, Necurs, Ramnit, and Emotet — to dynamically create command-and-control domains. Rather than hardcoding a C2 server address (which defenders can sinkhole or block), the malware generates hundreds or thousands of pseudo-random domains each day and queries them until it finds the one the attacker has registered. This makes takedown efforts substantially more difficult, since the domain changes daily.

Typical DGA output: `xk4jf9a2m3b7c.biz`, `q8w3r5t7p.net`, `m2b7c9d4.xyz`.

#### How detection works

1. **Character encoding.** The domain string is lowercased and converted to a sequence of integers: each letter, digit, hyphen, and period maps to a fixed index (vocabulary size 40). Unknown characters are mapped to an "unknown" token. The sequence is padded or truncated to 128 characters.

2. **Convolutional feature extraction.** The 1D CNN layers process the character sequence with learned filters of varying widths (bigrams, trigrams). These filters learn to recognise local character patterns — DGA domains contain high-entropy character sequences (`xk4j`, `q8w3`) that are absent from natural language domain names, which tend to use recognisable word fragments (`google`, `stack`, `cloud`).

3. **Sequential modelling.** The Bidirectional LSTM processes the full character sequence in both directions. It captures domain-wide structural properties that the CNN cannot: DGA domains lack meaningful word boundaries, have uniform character frequency distributions (no vowel-consonant alternation), and often use TLDs (`.biz`, `.xyz`) that are disproportionately associated with algorithmically generated names.

4. **Classification.** The output layer produces softmax probabilities across three classes: Benign, DGA, and DNS Tunnel (a related but distinct threat where domain strings carry encoded tunnel payloads).

#### Training methodology

A critical detail: the model is evaluated using **family-wise holdout validation**. Twenty-seven entire DGA families are reserved for validation — the model has never seen any domain from these families during training. This prevents a common form of data leakage where a random train/test split places near-identical domains from the same malware family in both sets, artificially inflating accuracy.

With family-wise split, the model achieves **0.9787 macro-F1** — this is the honest, generalisation-tested metric. Earlier versions using random splits reported near-perfect accuracy, which was unreliable.

For reference, established systems such as Cisco Umbrella, Endgame (now Elastic), and FANCI report comparable accuracy in the 0.97–0.99 range. The practical distinction is that NetSentinel performs this classification locally, without forwarding DNS queries to an external resolver.

---

### 2.3 Data Exfiltration via DNS Tunneling

| | |
|---|---|
| **Architecture** | Variational Autoencoder (unsupervised anomaly detection) |
| **Training data** | CIC-Bell-DNS-EXF-2021, University of New Brunswick |
| **Input** | 24 DNS lexical features computed from the queried domain name |
| **Decision boundary** | Reconstruction error (MSE) exceeding 0.70 |
| **MITRE ATT&CK** | T1048 (Exfiltration Over Alternative Protocol), T1071.004 (DNS) |

#### Threat context

DNS tunneling is a data exfiltration technique in which an attacker encodes stolen data into DNS queries. Since DNS traffic on port 53 is rarely blocked by firewalls, it provides a reliable covert channel even in heavily restricted networks. Established tools for this technique include dnscat2, iodine, dns2tcp, and the DNS beacon mode in Cobalt Strike.

In practice, the stolen data is encoded into the subdomain field of the query:

```
5d2301340f59af309420872c7ac913512997f5ed.evil-c2.com   (hex-encoded payload)
GQ42VDZpBA.www.ggy666.tk                                (base64-encoded payload)
```

Each query can carry approximately 200 bytes. Over thousands of queries, entire databases can be extracted without triggering traditional security controls.

#### How detection works

The model uses an anomaly detection approach rather than supervised classification.

**Feature extraction.** For each DNS query, 24 lexical features are computed from the domain string alone (no network context required):

- **Entropy measures:** Shannon entropy and bigram entropy of the subdomain characters, normalised entropy. Tunnel domains have near-maximum entropy because encoded data produces uniformly distributed character sequences. Legitimate domains have lower entropy due to natural language structure.
- **Character composition:** Ratios of digits, hex characters (0–9, a–f), lowercase letters, special characters, and vowels. Hex-encoded tunnels produce 100% hex characters; base64 produces high digit and lowercase ratios. Legitimate domains have substantially higher vowel ratios (English words).
- **Length measures:** Subdomain length, log-length, longest label, label averages. Tunnel subdomains are typically 40–60+ characters per label to maximise data throughput. Normal subdomains are typically under 20 characters.
- **Structural measures:** Unique character count and ratio, maximum character repeat length, FQDN count, subdomain count.

**Anomaly scoring.** The Variational Autoencoder is trained on benign DNS traffic from the CIC-Bell dataset. It learns to compress and reconstruct normal DNS query feature vectors. During inference:

1. The 24 features are scaled using a RobustScaler fitted on the training distribution.
2. The encoder compresses the input into a low-dimensional latent representation.
3. The decoder reconstructs the original input from the latent space.
4. The reconstruction error (mean squared error between input and output) serves as the anomaly score.

Normal queries are well-represented in the VAE's learned distribution, producing low reconstruction error. Tunnel queries fall outside this distribution and cannot be accurately reconstructed, producing high error.

**Empirical separation.** The gap between normal and tunnel traffic is substantial:
- Normal DNS: MSE 0.18–0.42 (e.g., `domain.lan` = 0.18, `atmospherica.ru` = 0.29, `82bank.co.jp` = 0.42)
- Tunnel DNS: MSE 0.99–140 (e.g., dns2tcp = 0.99, iodine = 1.44, dnscat2 = 61–140)

The threshold of 0.70 sits comfortably between these distributions. The analyser additionally requires that either the reconstruction error exceeds 1.4 (indicating strong anomaly), or the domain exhibits moderate tunneling indicators (entropy > 4.0 with subdomain length > 20), before issuing an alert.

#### Validation

Tested against the DNS-Tunnel-Datasets collection, which includes PCAPs from:
- dnscat2 (TXT, CNAME, and MX record modes)
- iodine (A, CNAME, MX, NULL, SRV, TXT records)
- dns2tcp
- DNS-Shell
- Cobalt Strike DNS C2
- tcp-over-dns
- ozymandns

**Result: 100% true positive rate across all tools and record types, with 3.3% false positive rate** on normal traffic. The false positives are legitimate but structurally unusual domains such as `11111.sugarbabysoaps.com` and `api.aws.parking.godaddy.com`.

The original model had a false positive rate of approximately 97.7% due to a scikit-learn version mismatch in the scaler (pickled with version 1.6.1, loaded with 1.3.2). This was resolved by re-exporting the scaler with the correct version and tuning the threshold from 0.15 to 0.70 based on empirical analysis.

---

### 2.4 C2 Beacon Detection

| | |
|---|---|
| **Architecture** | Bidirectional LSTM with FFT spectral features |
| **Input** | Time-series of 100 consecutive flows between a source-destination pair, plus 5 FFT-derived periodicity features |
| **Activation requirement** | Minimum 100 flows between the same (src_ip, dst_ip) pair |
| **MITRE ATT&CK** | T1071 (Application Layer Protocol), T1573 (Encrypted Channel) |

#### Threat context

After initial compromise, implants (Cobalt Strike, Meterpreter, Sliver, Brute Ratel) maintain communication with their Command & Control infrastructure through periodic "check-ins" or beacons. The implant contacts the C2 server at regular intervals — for example, every 60 seconds — to request tasking and deliver collected data.

Even with jitter (randomising the interval by ±10–20%), this communication exhibits a detectable periodicity that normal human-driven traffic does not. Human browsing is inherently bursty and irregular; beacon traffic is quasi-periodic.

#### How detection works

The model uses two complementary approaches in a dual-path architecture:

**Temporal path (BiLSTM).** One hundred consecutive flows between the same source and destination are assembled into a time-series with four features per timestep: inter-arrival time (IAT), packet size, byte count, and direction. The Bidirectional LSTM processes this sequence forwards and backwards, learning to recognise the temporal regularity characteristic of beaconing — consistent IAT spacing, uniform packet sizes, and alternating request-response patterns.

**Spectral path (FFT).** The inter-arrival times are transformed using the Fast Fourier Transform to produce five spectral features:

1. **FFT score** — normalised magnitude of the dominant frequency. A high value indicates strong periodicity.
2. **Dominant frequency** — the actual beacon frequency (e.g., 0.0167 Hz corresponds to a 60-second interval).
3. **Harmonic ratio** — ratio of the second harmonic to the fundamental. Clean, regular beacons produce strong harmonics.
4. **Spectral entropy** — entropy of the power spectrum. Low values indicate energy concentrated at a single frequency (periodic); high values indicate broadband noise (random or human-driven).
5. **Peak prominence** — the extent to which the dominant frequency stands out from the spectral noise floor.

**Decision logic.** The BiLSTM's beacon probability is combined with the FFT features through the following conditions:

- **Low-jitter beacon:** Model probability > 90% AND coefficient of variation (IAT std/mean) < 0.05 AND the traffic does not match a known benign periodic pattern.
- **FFT-confirmed beacon:** Model probability > 90% AND FFT score > 0.15 AND spectral entropy < 0.85 AND peak prominence > 3.0.

**Benign periodic traffic exclusions.** Several categories of legitimate periodic traffic are excluded to prevent false positives:
- NTP synchronisation (port 123, approximately 64-second intervals)
- TCP keepalive messages (ports 22, 443, 3389, 5900 with 25–35 second intervals)
- DNS cache refresh (port 53, approximately 300-second intervals)
- Load balancer health probes (port 443, short sessions with 10–60 second intervals)

#### Current status

The architecture is well-designed and the FFT feature engineering is sound. However, the model has not yet been validated against real botnet PCAPs. Validation against the CTU-13 dataset (particularly Scenario 1, which contains Neris botnet traffic with clearly identifiable beaconing patterns) would provide the necessary empirical confirmation. The 100-flow activation threshold requires sustained network captures rather than brief packet snapshots.

---

### 2.5 Encrypted Traffic Classification

| | |
|---|---|
| **Architecture** | Feature Tokenizer Transformer (FT-Transformer) |
| **Training data** | Consolidated traffic dataset (VPN vs non-VPN, 14 application classes) |
| **Input** | 29 flow-level metadata features (no payload inspection) |
| **Performance** | 88% accuracy across 14 traffic classes |
| **MITRE ATT&CK** | T1573 (Encrypted Channel), T1572 (Protocol Tunneling) |

#### What this model does

It classifies encrypted network flows into 14 application categories — chat, streaming, file transfer, browsing, email, VoIP, and P2P — based solely on flow metadata. It further distinguishes whether each class is VPN-tunneled or direct (e.g., "VPN-Streaming" vs "Streaming").

The FT-Transformer tokenises each numerical feature independently, creating learned embeddings for each feature value, then applies multi-head self-attention to capture cross-feature interactions. VPN tunneling creates subtle correlations: slightly larger packet sizes (tunnel overhead), more uniform packet size distributions (encapsulation standardises framing), and altered timing patterns.

#### Practical limitation

Identifying traffic as "VPN" is not, in itself, a threat finding. Corporate employees, privacy-conscious users, and remote workers routinely use VPNs. The model's operational value is in **encrypted traffic visibility** — helping network operators understand what applications are running inside encrypted tunnels, without breaking encryption. In a SOC context, it helps answer the question "what constitutes the encrypted traffic we cannot inspect?" rather than providing a direct threat signal.

---

### 2.6 Port Scan Detection

| | |
|---|---|
| **Architecture** | XGBoost binary classifier |
| **Training data** | UNSW-NB15, University of New South Wales |
| **Input** | 40 UNSW-format features (mapped from CICFlowMeter output) |
| **MITRE ATT&CK** | T1046 (Network Service Discovery) |

#### What port scanning is

Port scanning is the reconnaissance phase of an attack — an adversary probes a target system to identify which services are running and accessible. Common techniques include Nmap SYN scans, which send SYN packets to thousands of ports and interpret the responses.

#### Current status

The model performs well on UNSW-NB15 test data, but the feature mapping between CICFlowMeter output and UNSW-NB15 format introduces approximations that degrade real-world performance. Several features are hardcoded rather than computed: TTL is set to 64 (Linux default), TCP round-trip time is set to 0.0, and connection tracking counters are approximated from session summaries.

As a result, the model does not reliably detect port scans from CIC-IDS-2017 PCAPs. The analyser compensates with a heuristic fan-out tracker (counting unique destination ports per source IP), but the ML model itself requires retraining on CIC-native features for production deployment.

---

## 3. The Extraction Pipeline

### Why a hybrid approach

CICFlowMeter is the standard tool for extracting flow-level statistical features — it produced the training data for most CIC-series datasets. However, it was designed for a single purpose (flow statistics) and does not support several capabilities that NetSentinel's models require:

| Requirement | CICFlowMeter | Custom extractor |
|---|---|---|
| Flow statistics for DDoS/PortScan models | Supported (and required, to avoid covariate shift) | Supported, but produces subtly different distributions |
| Individual DNS query strings for DGA classification | Not supported | Supported (Scapy DNS layer parsing) |
| 24 DNS lexical features for exfiltration detection | Not supported | Supported |
| 100-flow time-series for C2 beacon detection | Not supported (produces single-flow summaries) | Supported (session builder tracks src-dst pairs) |
| Real-time packet-by-packet processing for live capture | Not supported (batch processing only) | Supported |

Four of the six models require features that CICFlowMeter cannot produce. The hybrid approach uses each tool where it is strongest.

### Architecture

**Phase 1 (CICFlowMeter):** The PCAP is processed by CICFlowMeter's Python API, which produces flow-level statistical features identical to those used in training. A name-mapping wrapper translates CICFlowMeter's Python API output format (snake_case: `flow_byts_s`) to the CIC CSV format expected by the models (`Flow Bytes/s`). Events from this phase are tagged `extractor="cicflowmeter"` and routed exclusively to the DDoS and Port Scan models.

**Phase 2 (Custom extractor):** The same PCAP is processed packet-by-packet through a streaming pipeline that produces:
- DNS events (parsed from port-53 traffic) → routed to the DGA and Exfiltration models
- Flow events (TCP/UDP flow summaries) → routed to the Encrypted Traffic model
- Session events (100-flow time-series per src-dst pair) → routed to the C2 Beacon model

The analyser routes each event to the appropriate model(s) based on its type and source tag. CICFlowMeter events are never sent to DNS-based models, and custom extractor events are never sent to CICFlowMeter-trained models.

### The covariate shift problem and its resolution

When models trained on CICFlowMeter-produced features receive features computed by a different implementation, the statistical distributions do not match — even when the features have the same names. This is known as covariate shift. In our case, 92% of features showed statistically significant distribution differences (Kolmogorov-Smirnov test, p < 0.05) when computed by the custom extractor versus CICFlowMeter.

The differences arose from implementation details: timeout thresholds, TCP flag counting methods, and averaging window calculations. The resolution was straightforward — use CICFlowMeter itself for models trained on CICFlowMeter data. This eliminated the distribution mismatch entirely.

---

## 4. Dashboard Visualisations

The frontend (React, Vite) connects to the backend via WebSocket and renders real-time threat data across several visualisation components.

### Alert Feed
A chronological stream of detected threats, colour-coded by severity, showing source and destination IPs, threat type, confidence score, and MITRE ATT&CK technique IDs. This serves the same function as an alert console in Splunk Enterprise Security or IBM QRadar — it is the primary triage interface.

### Threat Graph (3D Force-Directed)
A network topology visualisation where nodes represent IP addresses and edges represent detected threat connections. Edge colour indicates threat type; edge thickness indicates confidence. When the same internal host appears in multiple threat types — DGA queries, C2 beaconing, and DNS tunnel exfiltration — the attack chain becomes visually apparent. This is the primary value of running six models simultaneously: correlated multi-signal detection that individual tools cannot provide.

### FFT Spectrum
The frequency-domain representation of inter-arrival times for suspected C2 sessions. A sharp peak at a specific frequency provides visual confirmation of periodic beaconing — for example, a peak at 0.0167 Hz indicates a 60-second beacon interval. This serves as an explainability tool: rather than reporting that a neural network classified the session as malicious, the analyst can independently verify the periodicity in the frequency spectrum.

### Attack Timeline
Time-series plot showing when each threat type was detected over the capture duration. This reveals attack phases — reconnaissance activity (port scans) clustering early, followed by C2 establishment, then exfiltration. The temporal correlation transforms individual alerts into a coherent incident narrative aligned with the MITRE ATT&CK kill chain.

### MITRE ATT&CK Heatmap
A matrix mapping detected threats to MITRE ATT&CK tactics and techniques. Every alert carries a technique ID (T1498, T1568.002, T1048, etc.), enabling integration with existing SOC workflows and threat intelligence platforms that use the same classification framework.

### Traffic Charts
Real-time bandwidth utilisation, packet rate, and protocol distribution. These provide the baseline context that makes model-generated alerts actionable — a sudden increase in DNS query volume, for example, may indicate tunneling activity before individual queries have been processed by the VAE.

---

## 5. Comparison with Existing Tools

### Versus Wireshark
Wireshark is a packet analyser — it allows an expert to inspect individual packets and conversations in detail. NetSentinel is an automated detection system. They are complementary: NetSentinel identifies threats; Wireshark is used to investigate the specific packets flagged by those alerts.

### Versus Snort and Suricata
Signature-based intrusion detection systems match traffic against databases of known-bad patterns. They are effective against known threats and produce low false positive rates. However, they require continuous rule updates and cannot detect zero-day attacks, new DGA families, or previously unseen C2 frameworks. NetSentinel's behavioural models detect anomalous patterns regardless of whether the specific tool has been encountered before — a new DNS tunneling tool will still produce high-entropy DNS queries, and the VAE will flag them.

### Versus commercial platforms (Cisco Umbrella, CrowdStrike Falcon, Darktrace)
These are mature, well-resourced platforms with substantially larger engineering teams and training datasets. NetSentinel does not claim to exceed their per-model accuracy. The practical differences are:

1. **Deployment constraints.** Cloud-dependent platforms cannot operate in air-gapped networks. NetSentinel can.
2. **Auditability.** Every model, feature, and decision boundary is fully inspectable. Commercial platforms operate as closed systems.
3. **Data sovereignty.** No network traffic or telemetry data leaves the monitored network.
4. **Cost.** NetSentinel has no licensing fees, whereas commercial platforms typically range from $50K to $500K annually.

---

## 6. Strategic Positioning

### Value proposition

The individual detection models are not, in isolation, a novel contribution — DGA detection, DDoS classification, and anomaly-based exfiltration detection are established techniques. The contribution of this work is the integration: fusing six independent threat signals into correlated attack chains on a single passive sensor that operates entirely offline.

When a DGA query, a C2 beacon, and DNS tunnel exfiltration originate from the same internal host, that is not three separate alerts — it is a complete kill chain from initial compromise through command-and-control to data exfiltration. This multi-model correlation, presented through a unified real-time dashboard, is what makes the system operationally useful.

### Regarding the expert feedback on Legitimate Service Abuse

The cybersecurity professional who reviewed the project identified a meaningful gap: modern threats increasingly abuse legitimate services (Telegram bots for C2, cloud storage for exfiltration, Slack webhooks for command relay). Traditional network detection focuses on identifying malicious infrastructure, but when the infrastructure is `api.telegram.org`, simple domain blocking is not viable.

This is a valid and forward-looking direction. The reason we prioritised pipeline repairs before pursuing it is straightforward: the existing models were producing unreliable results due to covariate shift (92% of features misaligned), a scaler version mismatch causing 97.7% false positives on the exfiltration model, and data leakage inflating the DGA accuracy. Building additional detection capabilities on an unreliable foundation would have compounded the problem.

With the pipeline now validated — covariate shift eliminated, exfiltration model achieving 100% TPR at 3.3% FPR, DGA evaluation corrected to honest 0.9787 F1 — the infrastructure is ready to support additional models, including Legitimate Service Abuse detection, with confidence in the underlying data quality.

---

## 7. Summary of Validated Results

| Model | Evaluation dataset | Result | Method |
|---|---|---|---|
| DDoS | CIC-DDoS2019 (test set) / CIC-IDS-2017 (PCAP) | 99.97% F1 / 0.998+ confidence | XGBoost on CICFlowMeter features |
| DGA | DGArchive 2024, 137 families | 0.9787 macro-F1 (family-wise split) | CNN-BiLSTM, char-level |
| Exfiltration | DNS-Tunnel-Datasets (7 tools, multiple record types) | 100% TPR, 3.3% FPR | VAE reconstruction error, threshold 0.70 |
| Port scan | CIC-IDS-2017 Friday PCAP | Not reliably detecting (feature mapping issue) | Requires retraining on CIC-native features |
| C2 beacon | — | Not yet validated | Requires sustained botnet PCAP (CTU-13 recommended) |
| ETT | Consolidated VPN dataset | 88% accuracy, 14 classes | FT-Transformer |

---

## 8. Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, uvicorn |
| Inference | ONNX Runtime (CPU execution) |
| Packet processing | Scapy (dissection), CICFlowMeter (flow features) |
| Frontend | React 19, Vite, Tailwind CSS |
| Visualisation | Three.js (3D graph), Recharts (time-series and distributions) |
| Real-time communication | WebSocket (server to client) |
| Model distribution | HuggingFace Hub with local caching (offline-capable) |
