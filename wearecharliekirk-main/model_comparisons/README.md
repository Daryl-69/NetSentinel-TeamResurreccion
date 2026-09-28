# Model comparisons — did we pick the right models?

*25 September 2026. Every model in a comparison saw the same training rows and
was scored on the same test rows. All scores are reported, including the ones
where an alternative beat our model.*

| Detector | Our model | Tested against | Data | Verdict |
|---|---|---|---|---|
| DDoS | XGBoost | LightGBM, Random Forest, small neural net (MLP), logistic regression | CIC-DDoS2019, 431,371 flows (same data as the shipped model) | Tie on the standard split; on an unseen day ours keeps false alarms at 0.10% (LightGBM 0.09%), while the MLP catches more attacks at 3x the false alarms |
| DGA | CNN-BiLSTM | plain LSTM, character n-gram logistic regression, Random Forest / XGBoost on 7 name features | Public 25-family DGA dataset, 5-fold family-wise CV | Character models beat name features by ~20 F1 points; a simple n-gram model matched our CNN-BiLSTM |
| DNS exfiltration | VAE (reconstruction) | VAE latent distance, Mahalanobis, Isolation Forest, fusion | CIC-Bell-DNS-EXF-2021 | VAE best (ROC-AUC 0.78 vs 0.52–0.74) |
| Port scan | SPSD (+ fan-out backstop) | UPSD sequential test, fan-out rule alone | Simulated scans + 4 h of our own real traffic | SPSD catches the most scans; it also raises the most false alarms after UPSD |
| C2 beacon | Combined periodicity score (prototype; the live analyzer still runs BiLSTM + FFT) | BiLSTM + FFT (shipped), FFT alone, timing-regularity rule, autocorrelation | The same 11.4 h of our own traffic with one labelled Telegram-API beacon; combined score also on all 97 h (18–25 Sep) | The combined score caught the beacon, the BiLSTM missed it; cost: more alerts (7 vs 2 in the same 11.4 h; 48 in 97 h, from 12 ordinary periodic services). No timing method separates the beacon from normal periodic traffic. Bounded, not solved |
| Sentry router | distilled Sentry | encoder + per-host Mahalanobis router | LANL cyber1 | 0.992 vs 0.634 agreement with the Inspector (tie on synthetic data) |
| Encrypted traffic | FT-Transformer | — | — | **Not run**: the ISCX VPN-nonVPN data is not on this machine and the download sites are blocked from the analysis environment |

---

## 1. DDoS — `ddos_compare.py`, `ddos_compare_results.json`

Data: CIC-DDoS2019, dhoogla cleaned parquet release, 431,371 flows, the shipped
model's 59 features, binary attack vs benign. Seed 42.

**A. Random stratified 80/20 split** (345,096 / 86,275 — the protocol behind the shipped 99.97%)

| Model | F1 | Precision | Recall | False alarms on benign |
|---|---|---|---|---|
| **XGBoost (ours)** | **99.97%** | 99.98% | 99.96% | 0.06% |
| LightGBM | 99.97% | 99.98% | 99.96% | 0.06% |
| Random Forest | 99.96% | 99.98% | 99.94% | 0.07% |
| MLP | 99.90% | 99.95% | 99.85% | 0.18% |
| Logistic regression | 99.71% | 99.79% | 99.62% | 0.72% |

**B. Train on the "training day" files (125,170 flows), test on the "testing day" files (306,201)** — a different day with a different attack mix

| Model | F1 | Precision | Recall | False alarms on benign |
|---|---|---|---|---|
| **XGBoost (ours)** | 98.60% | 99.98% | 97.25% | 0.10% |
| LightGBM | 98.59% | 99.98% | 97.24% | 0.09% |
| Random Forest | 98.34% | 99.97% | 96.76% | 0.14% |
| Logistic regression | 98.89% | 99.90% | 97.89% | 0.47% |
| **MLP** | **99.60%** | 99.94% | **99.26%** | 0.31% |

Reading: on the standard split every tree model ties. On an unseen day the MLP
catches ~2 points more attacks at ~3x the false-alarm rate. XGBoost is a
defensible choice for a SOC that is short of analyst time; the MLP result says
an ensemble is worth trying. Latencies in the JSON were measured on a shared
2-core machine with Python per-row calls and are not comparable to the ONNX
0.031 ms figure — do not quote them.

## 2. DGA — `dga_compare.py`, `dga_compare_results.json`

Data: Cucchiarelli et al., *Expert Systems with Applications* 170 (2021) —
25 DGA families from 360 Netlab (13,500 domains each) + Alexa benign.
Public, so anyone can re-run it. **This is not DGArchive**, the data the shipped
model was trained on.

Protocol: 5-fold family-wise cross-validation. Each fold holds out 5 whole DGA
families (never seen in training) plus 20% of benign domains. Same 120,000
training domains (60k per class) for every model; test = 4,000 per held-out
family + 20,000 held-out benign. Neural models: 2 epochs, max length 64 (CPU budget).

| Model | F1 (mean ± sd) | Recall on unseen families | False alarms on benign |
|---|---|---|---|
| char n-gram logistic regression | 81.3 ± 7.2% | 72.7% | 5.1% |
| **CNN-BiLSTM (our architecture, retrained here)** | 78.6 ± 9.0% | 68.4% | 4.1% |
| plain LSTM | 78.3 ± 8.4% | 69.3% | 6.4% |
| XGBoost on 7 name features | 58.2 ± 14.0% | 46.4% | 9.2% |
| Random Forest on 7 name features | 57.2 ± 13.3% | 47.9% | 15.6% |
| *shipped model, NOT retrained (trained on DGArchive)* | *81.8 ± 7.7%* | *72.7%* | *4.1%* |

Reading: learning from the characters beats hand-made name statistics by
~20 F1 points. A simple n-gram model matched (slightly beat) our CNN-BiLSTM
under the same small training budget — we cannot claim the deep model is best.
The shipped model's row is not a fair "unseen family" result: DGArchive contains
most of these families. It does show the shipped model holds ~82% F1 on an
independent dataset it was never trained on, versus 97.9% on its own test split.
Hardest fold (nymaim, ramdo, simda, matsnu, symmi — pronounceable and
dictionary-style DGAs): every model fell to 45–69% F1.

## 3. DNS exfiltration — existing result, `models/exfil/exfil_meta.json`

CIC-Bell-DNS-EXF-2021, ROC-AUC per scorer: VAE reconstruction **0.781**, VAE
latent distance 0.740, input-space Mahalanobis 0.724, fusion of all 0.646,
Isolation Forest 0.521. The shipped model uses the VAE reconstruction score only.

## 4. Port scan — `ps_pipeline.py`, `ps_*.json`

Run through the real analyzer (`FlowAnalyzer` + `flush_portscan_buffer`), swapping
only the decision method.

| Decision method | Simulated scanners caught (5) | Real benign sources flagged (149 sources, 4 h) |
|---|---|---|
| **SPSD model + fan-out backstop (deployed)** | **5 / 5** | 4 (66 alerts) |
| UPSD sequential test + backstop | 2 / 5 | 6 (45 alerts) |
| Fan-out rule only (≥100 ports per window) | 2 / 5 | 0 |

Caveats: the scans come from our own simulator (circular — relative comparison
only). No scans were run during the real 4 h window, so every flag there is a
false alarm upper bound. CIDDS-001, the SPSD validation set, is not on this
machine, so the 99.03% figure was not re-measured.

## 5. C2 beacon — `c2cmp.py`, `c2_beacon_score.py`, `c2_same_window.py`, `c2_fft_recheck.py`

One labelled beacon: our own harness sent 231 Telegram-API check-ins
(60 s ± 5%) on 20 Sep, 19:12–23:11 UTC (`beacon_truth.jsonl`). Everything else in
the captures is our own unlabelled traffic, treated as benign, so every
false-alarm count below is an upper bound.

### 5a. The shipped model on the 4-hour beacon window — `c2cmp.py`, `c2_compare.json`

347 host pairs in the window; 9 had the ≥100 flows the shipped model needs.

| Method | Beacon's rank |
|---|---|
| BiLSTM + FFT probability (shipped) | tied first — **all 9 sessions scored above 0.9999**, so no separation |
| Shipped model's gated decision | **missed the beacon**, flagged 1 benign session (SSDP, port 1900) |
| FFT periodicity score alone | 1st of 9 (5.76 vs next 5.40) — **does not hold up, see the re-check** |
| Timing-regularity rule (low CV) | 3rd of 9 · 5th of 30 sessions with ≥20 connections |
| Autocorrelation rule | 4th of 9 · 9th of 30 |

**Re-check of the FFT result** — `c2_fft_recheck.py`, `c2_fft_recheck.json`. The
beacon's session had 378 flows and was scored in 12
overlapping 100-flow windows; `c2cmp.py` kept each session's best window. Ranked
by its median window instead, the beacon is 3rd of 9 (4.01). 39% of its flow
gaps were under 5 s (several flows per check-in), and that structure, not the
60-second rhythm, is what the FFT of the gaps picks up.

**Out-of-sample false-alarm check** — `fft_benign.py`, `fft_benign.json`: the same FFT
score on 7.4 h of benign traffic from a different day (22 Sep, 16:18–23:39 local,
986 host pairs, 13 with ≥100 flows):

| FFT prominence threshold | Benign sessions at or above it | After dropping known periodic services (DNS, NTP, SSDP, mDNS/LLMNR) |
|---|---|---|
| 3.0 (the shipped model's own gate) | 12 of 13 | 6 |
| 5.0 | 4 | 2 |
| 5.5 | 1 (HTTPS, 5.56) | 1 |
| 5.76 (the beacon's best window) | 0 | 0 |

The shipped model also fired on 1 benign session that day.

### 5b. Combined beacon score (v2 prototype) on every capture — `pcapng_conns.py`, `c2_beacon_score.py`, `c2_beacon_score_eval.json`

All 146 capture files (2026-09-18 to 2026-09-25 UTC, 97 captured hours) were
reduced on the capture machine to connection records (start time, endpoints,
ports, bytes; no payload). A session is one source → destination pair in one
6-hour UTC window with at least 20 check-ins spanning 30 minutes (connections
starting < 5 s apart count as one check-in). DNS, NTP, SSDP, mDNS, LLMNR, NetBIOS,
DHCP and multicast / link-local traffic are dropped first. 359 sessions qualified.

Score = 0.30 × timing regularity + 0.20 × FFT periodicity + 0.20 × size regularity
+ 0.15 × destination rarity + 0.15 × persistence. **The weights and the 0.80 alert
threshold were fixed before any session was scored and were not tuned afterwards.**

| | Combined score | FFT alone | Timing regularity alone |
|---|---|---|---|
| Beacon's rank in its own 6-hour window | 4th of 15 | 4th of 15 | 4th of 15 |
| Benign sessions scoring at or above the beacon (all 97 h) | **42** | 104 | 66 |

At the pre-set threshold of 0.80:

- The real beacon **was flagged**, narrowly (score 0.824; its IPv4 fallback session scored 0.642).
- **48 benign session alerts** in 97 h of capture (11.9 per 24 h). They came from **12 services**
  (destination network + port) on 19 host pairs: periodic HTTPS on port 443 (32 alerts) and port 5684,
  the registered port for CoAP, an IoT protocol (16). 3 of the 12 services were on our own LAN.
- New alerting services kept appearing: 2, 3, 1, 1, 0, 2, 3 per capture day. The beacon's destination
  network had not alerted before the beacon started.
- The margin is thin: at 0.85 the beacon is missed (23 benign alerts); at 0.75 it is caught with 65.

Simulated variants of the real beacon (its real check-in sizes, re-timed or thinned; **simulated, not captured**):

| Variant | Score | Flagged at 0.80 |
|---|---|---|
| ±20% jitter | 0.815 | yes |
| ±50% jitter | 0.793 | no |
| 20% of check-ins dropped | 0.834 | yes |
| one check-in every ~5 min | 0.813 | yes |
| one check-in every ~15 min | not scored (only 16 check-ins in the window; the rule needs 20) | no |

### 5c. Head-to-head on the same hours — `c2_same_window.py`, `c2_same_window.json`

Both detectors on exactly the hours the shipped model was tested on. The combined
score's weights, filters and 0.80 threshold are unchanged; it is scored over each
whole period instead of 6-hour blocks (so the beacon's score differs slightly from 5b).

| Same hours | Combined score | Shipped BiLSTM + FFT |
|---|---|---|
| 20 Sep beacon window, 4.0 h | beacon **caught** (0.849, 3rd of 12 sessions); 5 benign alerts (port 443 ×4, 5684) | beacon **missed**; 1 benign alert (SSDP, port 1900) |
| 22 Sep, 7.4 h, no beacon | 2 benign alerts (port 5684, 443) | 1 benign alert (port 1900, SSDP) |
| **Total, 11.4 h** | **beacon caught, 7 benign alerts** | **beacon missed, 2 benign alerts** |

The shipped model can only score sessions with ≥100 flows (9 and 13 here); the
combined score scores sessions with ≥20 check-ins (12 and 20).

### What the C2 tests show

1. The combined score beats either single timing signal across days (42 benign sessions above the
   beacon vs 66 and 104), and unlike the shipped model it flags the real beacon (same 11.4 h: caught with 7 benign alerts, vs missed with 2).
2. It does **not** separate the beacon from legitimate periodic traffic. In the beacon's own
   window, three benign sessions scored at or above it under each method (under the combined
   score: one on port 5684 and two HTTPS).
   A regular rhythm is not, by itself, malicious.
3. The FFT term adds little. The FFT of the gaps looks for a pattern *in* the gaps, and a clean
   beacon's gaps have none: a simulated, perfectly regular 60-second beacon (±5% random jitter)
   gets a prominence of only 3.2 (median of 200 runs); the real beacon got 2.68 against a benign median of 2.26.
4. Beacons slower than about one check-in every 15 minutes need longer windows.

Status: **bounded, not solved.** One labelled beacon. The combined score is a prototype run
offline; it is **not** wired into the live analyzer. Next steps: remember reviewed periodic
services per site (the 48 alerts came from 12 services), record more labelled beacons with the harness
at other intervals and jitters, and use longer windows for slow beacons.

## 6. Sentry router — existing result, `tier2/INSPECTOR_SENTRY_SPEC.md` §9.5

LANL cyber1, 3 seeds: distilled Sentry agreement with the Inspector
**0.992 ± 0.003**; encoder + per-host Mahalanobis router 0.634 ± 0.007. On
synthetic data (8 seeds) the three router designs are statistically tied.

## 7. Encrypted traffic — not run

The FT-Transformer was trained on ISCX VPN-nonVPN (`consolidated_traffic_data.csv`).
That file is not on this machine, and unb.ca / Kaggle / Hugging Face are blocked
from the analysis environment. Put the ISCX VPN-nonVPN CSVs in
`D:\1_sih26\dataset\` and the comparison (Random Forest, XGBoost/LightGBM, MLP,
logistic regression vs FT-Transformer) can be run the same way.
