# Eraser.io prompts — NetSentinel Tier 2

Four paste-ready prompts for https://app.eraser.io (Diagram → AI / "Generate diagram").
Paste ONE prompt per diagram. Every figure below is the measured value from
`v2\lanl_novelty.json`, `v2\results.json` and `v2\shift_results.json` — regenerate those
files and update here rather than editing numbers by hand.

**Audience:** SIH judges and a working security engineer. The diagrams should survive being
questioned, not just look good.

---

## 1 — Full Inspector–Sentry architecture

> Create a technical system architecture diagram titled **"NetSentinel Tier 2 — Inspector–Sentry Cascade"**. Use a left-to-right flow with four labelled vertical swimlanes.
>
> **Lane 1 — "Passive Data Plane (no agent, no DPI, no inline device)"**
> Nodes: `Network TAP / SPAN port` → `Data Diode (unidirectional, egress-only visibility)` → `dumpcap ring buffer (headers only, snaplen 160 bytes, 1 file/hour)` → `Zeek 8.x`. Zeek fans out to three artefacts: `conn.log (volume + timing)`, `ssl.log (TLS SNI)`, `dns.log (query → A record)`. Add a note on this lane: "Read-only. No payload written to disk. Works behind a data diode where EDR agents cannot be installed."
>
> **Lane 2 — "Feature Construction"**
> `Service Category Resolver (deterministic regex taxonomy — NOT a model)` takes ssl.log + dns.log and emits one of 9 categories: Recon_API, Code_Repo_Paste, Messaging_API, Cloud_Storage, Browse, Sync, CI_CD, Internal, Unknown_External. Then `1-hour windowing (24 windows/day)` → `Edge tensor (Host × Day × 24 Windows × 9 Categories × 10 Features)`. Note: "Unknown_External is a deliberate outcome for ECH/DoH/raw-IP, not a failure — lost visibility is itself a signal."
>
> **Lane 3 — "Tier 2 models"**
> Two parallel boxes.
> **INSPECTOR (teacher, 205,546 params, GPU, commissioning + re-escalation only)** containing: `E-GraphSAGE edge aggregator (message = MLP[edge_features ‖ category_embedding ‖ hop-2 cohort])` → `hop-2 cohort context (other hosts on same category+window)` → `Transformer encoder, dim 96, 4 heads, 2 layers, norm_first` → `Denoising graph autoencoder (mask 25% of present edges, reconstruct all)`. Note: "Unsupervised. Never sees an attack label. Threshold = 99th percentile of commissioning reconstruction error."
> **SENTRY (student, 14,992 params, CPU, always-on)** containing: `Same edge aggregator, NO hop-2 cohort` → `GRU, dim 32, unidirectional` → `Linear projection head (distillation only)`. Note: "13.7× smaller. A router, not a detector."
>
> Draw a thick labelled arrow from Inspector to Sentry: **"Anomaly-weighted ENCODER distillation — L = E[(1 + λ·s_teacher)·‖project(f_student) − f_teacher‖²], λ = 4. Distil the eyes, never the verdict."**
>
> **Lane 4 — "Routing & escalation"**
> Three candidate router designs as a comparison group titled "Three routers, measured at equal escalation budget":
> `A — Distilled detector (regress teacher score)` marked **SELECTED**, `B — Encoder + per-host Mahalanobis (Ledoit-Wolf shrinkage, k=3, trim 0.05)` marked **REJECTED**, `C — Deferral head (predict "would the Inspector flag this?")` marked **candidate**.
> Then `Rank-based escalation budget selector (0.5% → 30%)` → `Escalate to Inspector` and → `MITRE ATT&CK mapping + alert manager` → `WebSocket → React dashboard`.
>
> Add a red-bordered "NOT YET BUILT" box listing: escalation loop, retention rule, adaptive sampler, rolling re-calibration.
>
> Add a footer note: "Prior art, stated explicitly: the Inspector is GraphIDS-shaped (arXiv:2509.16625). The cascade, the knowledge distillation and per-entity baselining are all established. Our contribution is the cross-service category-transition sequence semantics and the chain dataset."

---

## 2 — How the Inspector works + data pipeline + the dataset problem

> Create a detailed technical flow diagram titled **"How the Inspector Learns 'Normal' — and the Dataset Problem We Had to Solve"**. Three horizontal bands stacked top to bottom.
>
> **BAND 1 — "Our own capture (running now, 6 laptops, 12 days)"**
> Flow: `dumpcap ring buffer` → `snaplen 160 bytes (Ethernet + IP + TCP headers, TLS ClientHello SNI, DNS query name — payload discarded)` → `312-file ring @ ~131 MB, hourly rotation = 13 days retained` → `Windows Scheduled Task (SYSTEM, restarts at boot and on crash)` → `zeekify.sh (incremental, holds back the file still being written)` → `merged 12-day conn/ssl/dns per host` → `folder-name host namespacing (two people both on 192.168.1.5 stay two distinct hosts)`.
> Note: "~113 MB/hour per laptop. No payload on disk, so this is defensible to capture."
>
> **BAND 2 — "Feature extraction — 10 features per (host, category, 1-hour window)"**
> A table-style node listing all ten: `log_n_flows`, `log_bytes_up`, `log_bytes_down`, `egress_asymmetry (exfil signal)`, `iat_cv (classic beacon CoV — weak alone)`, `ks_uniform`, `ks_exponential`, `fft_prominence (automation)`, `distinct_endpoint_ratio (→1.0 = domain randomiser)`, `log_duration_mean`.
> Attach a highlighted callout box: **"THE JITTER-TRAP INVERSION — a beacon with random jitter produces UNIFORM inter-arrival times. Humans are log-normal and bursty. So low ks_uniform + low fft_prominence means automation. The evasion is itself the signature."**
> Second callout: "Training is a DENOISING AUTOENCODER: 25% of present edges are hidden from the encoder, the decoder must reproduce all of them. Reconstruction error = anomaly score. No attack labels are used, or needed."
>
> **BAND 3 — "Datasets evaluated — what each one could and could not test"**
> A comparison matrix with columns: Dataset | Real humans | Hostnames (SNI/DNS) | Multi-day per host | Attack labels | Verdict.
> Rows:
> - `Synthetic generator (synth.py, worlds A/B)` | yes-ish | yes | yes | yes | "Stand-in only. A detector evaluated on the generator that made its attacks learns the generator."
> - `Stratosphere Normal Captures` | yes | some | no | none | "UNREACHABLE — host firewalled from our network."
> - `WRCCDC 2018` — 1,021,950 conn records, 15,070 SNI names, 664 hosts | yes | **yes, 77.3% resolver hit rate, 13.9% LOTS-matched** | **no — 1 day only** | partial | "Proves the resolver works. Cannot baseline."
> - `LANL cyber1` — 612 hosts × 13 days, 749 real red-team events | yes | **NO — all IDs de-identified to C1, C2, U7** | **yes, 58 days** | **yes, real red team** | "Only real multi-day host data that exists. Zero egress traffic."
> - `IoT-23` — 23 captures, 213,852,924 labelled port-scan flows | devices only | **no ssl.log / dns.log** | no | yes | "Hosts are a smart lamp, an Echo and a doorlock. No cross-service chains exist to detect. Right dataset for the Tier-1 port-scan model only."
> - `Zenodo 19206234` | **no — LLM-agent generated** | yes | **no — 60 minutes max** | none | "Too short and synthetic."
>
> Below the matrix add a large conclusion box: **"THE STRUCTURAL GAP: a 124-dataset survey found none containing multi-stage or APT-style campaigns. LANL has labels and no egress. WRCCDC has egress and one day. IoT-23 has labels and no hostnames. Nobody publishes multi-day egress traffic with attack labels — because that means publishing where an organisation's staff browse. So we are capturing our own and injecting emulated LOTS chains with human-timed DevOps hard negatives."**

---

## 3 — Sentry: what it is, and the measured comparison

> Create a technical comparison diagram titled **"The Sentry — a Router, Not a Detector"**. Four sections.
>
> **SECTION A — "The economic problem"**
> Left: `Always-on GNN + Transformer on every host, every hour` labelled "GPU-bound. Cost scales with host count. Not deployable on CPU-only OT hardware."
> Right: `Cascade: cheap always-on router + expensive teacher on demand` labelled "CPU-only steady state. GPU touched only at commissioning and on escalation."
> Arrow between them: "The question is not 'can a small model detect?' It is 'can a small model decide what deserves a big model?'"
>
> **SECTION B — "Measured on real traffic — LANL cyber1, 612 hosts × 13 days, 3 seeds"**
> A results table:
> | Metric | Router A (distilled detector) | Router B (encoder + Mahalanobis) |
> | AUC vs the Inspector | **0.992 ± 0.003** | 0.634 ± 0.007 |
> | Recall of Inspector's flags @ 5% escalation budget | **96.9% ± 1.1** | 18.4% ± 4.6 |
> | Parameters | 14,992 | 14,992 |
> | Compression vs Inspector (205,546 params) | **13.7×** | 13.7× |
> Add: `kNN geometry overlap 0.433 ± 0.009 (MARGINAL)`, `Inspector flag rate on test 2.6% ± 0.2 against a 1.0% target`.
> Caption in bold: **"96.9% is AGREEMENT WITH THE TEACHER — an efficiency number, not a detection rate. Never present it as detection."**
>
> **SECTION C — "Why B was rejected, with the literature"**
> Three cited nodes:
> - `Knowledge-distillation transfer is asymmetric: global outliers 78%, isolation-based 88%, neighbourhood 76%, but LOCAL outliers only 20% (MDPI MAKE 8(3):60)` → "so a student cannot inherit local-anomaly judgement — distil the encoder, not the decision."
> - `Confidence-based cascade deferral is provably suboptimal under distribution shift, specialist downstream models and label noise (Jitkrittum et al., NeurIPS 2023, arXiv:2307.02764)` → "all three describe an IDS. So router C predicts 'would the teacher flag this', not 'am I unsure'."
> - `Mahalanobis distance in high dimensions fails on near-OOD (ICCS 2022)` → "consistent with B's 0.634 and its 7× seed variance."
>
> **SECTION D — "Against what industry deploys today"**
> Comparison rows, each with why it fails on this threat:
> - `Signature IDS — Snort / Suricata` → "Kill chains ride GitHub, Telegram and Google Drive over TLS 1.3. There is no signature for a legitimate domain."
> - `EDR agents` → "Cannot be installed on OT/SCADA controllers, IoT, BYOD, or anything behind a data diode. NetSentinel is complementary, not a replacement."
> - `NetFlow/UEBA baselining` → "Per-user volume baselines. Does not model a sequence of service-category transitions."
> - `Always-on graph NIDS` → "Accurate but GPU-resident; the cascade is what makes it affordable."
> Bottom banner: **"Our only genuine novelty: cross-service category-transition sequence semantics. A 91-study systematic review found no prior work doing sequence-based, multi-service, graph-level detection across legitimate platforms."**

---

## 4 — The one you didn't ask for, and should show

This is what separates a student project from an engineering result, and judges reward it.

> Create a diagram titled **"How We Validate — and the Confound That Killed Our Own Headline Number"**. A vertical decision flow.
>
> Start: `Global AUC vs the red team = 0.745 ± 0.002, bootstrap 95% CI [0.699, 0.786]` styled as an attractive result.
> Decision node: **`Is this detection, or is it something else?`**
> Branch into the check: `WITHIN-HOST AUC — score each attacked host's attack windows against ITS OWN other windows, removing the between-host axis entirely`.
> Result node, red: **`0.557 ± 0.013 over 77 attacked hosts, 106 positives — CHANCE`**.
> Explanation node: `Live-window density: attacked hosts 0.811 vs everyone else 0.530. Red-team targets are the BUSIEST machines. The model was ranking WHICH host is unusual, not WHEN it was attacked.`
> Second explanation: `Novelty features (new_peer_ratio, new_service_flag) were added to fix this and did not: mean new_peer_ratio 0.021, because credential-based lateral movement uses access the host already has.`
> Structural caveat node: `Of 749 red-team events, 119 destination computers are modelled hosts but only 1 source is. So this measures VICTIM-side detection (clean negative). SOURCE-side — the outbound behaviour we actually model — is untested, not disproven.`
> Conclusion box: **"A tight confidence interval on a confounded metric is still confounded. We built this check ourselves, ran it across 3 seeds, and it argued against us. LANL cannot test the cross-service hypothesis because LANL has no egress. The 12-day capture plus injected chains is not a fallback — it is the only way this class of hypothesis can be tested."**
>
> Add a side panel titled "Evaluation protocol (arXiv:2608.01454)": `strictly monotonic temporal train → validate → test split`, `every threshold calibrated on validation only, never on test`, `multi-seed, mean ± σ reported`, `rank-based budget selection (quantile thresholds collapse under score ties)`.
>
> Add a second side panel titled "Calibration decay — measured three times": `world A→B cross-org: 6.26% flag rate`, `world A's own later period: 6.82%`, `LANL real traffic: 2.6% ± 0.2`, `all against a 1.0% target`. Caption: "The threshold decays from the day it is set. Every deployment needs its own calibration window plus rolling re-calibration. That is the next thing we are building."

---

## Speaking notes — the two sentences that matter

**When a judge asks how good it is:**
> "On 13 days of real enterprise traffic the Sentry recovers 96.9% ± 1.1 of everything the Inspector would flag, at 13.7× fewer parameters, on CPU. That's an efficiency result — agreement with the teacher, not a detection rate."

**When a judge asks whether it detects attacks:**
> "Against the real red team in that dataset, the Inspector is at chance within-host — 0.557 ± 0.013. We built the confound check that found it. LANL is an all-internal network with no egress, so it could never test our actual hypothesis; that's why we're capturing 12 days of our own traffic with injected LOTS chains."

Do not soften either one. The second answer is the one that makes a professional take the first one seriously.
