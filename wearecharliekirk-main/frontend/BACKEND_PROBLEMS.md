# NetSentinel — Backend Problems & Remediation Plan

> Status doc for the detection backend (FastAPI + WebSocket + ONNX Runtime).
> Written to be handed to a reviewer: it states what is broken, *why it is
> broken*, how to prove it, and the order to fix it in. Nothing here is
> aspirational — every item is a known gap in the current build.

**Scope.** This covers the Python detection service only. The dashboard
(`src/`) is complete and consumes the alert schema described in §5 through
`ws://localhost:8000/ws` with an automatic mock fallback.

**Hard constraint.** None of these fixes can be executed inside the Figma
Make workspace — there is no Python runtime, no `onnxruntime`, no packet
captures, and no model artifacts here. Everything below is validated by
running the backend repo (`run.py`) on a host with the trained models and a
`.pcap` / live tap.

---

## 0. TL;DR — priority order

| # | Problem | Severity | Blocks demo? | Effort |
|---|---------|----------|--------------|--------|
| 1 | Train/inference **covariate shift** (CICFlowMeter CSV vs. live Scapy extractor) | 🔴 Critical | Yes (silent FP/FN) | High |
| 2 | Only **4 of 6 threat classes** wired at runtime (Port Scan + Exfil trained, not loaded) | 🔴 Critical | Yes | Medium |
| 3 | **C2 FFT** computed on mean-removed IATs → perfect beacon yields ~zero spectrum | 🟠 High | Partially | Low |
| 4 | **CV-gate false-positive regression** on benign periodic traffic (NTP, keep-alives) | 🟠 High | No | Low |
| 5 | Alert schema missing **5-tuple flow id + SHAP evidence** the frontend now expects | 🟡 Medium | No | Low |
| 6 | Test suite proves *load/run*, not *live accuracy* (real-flow tests skipped) | 🟡 Medium | No | Medium |

Do them in this order. #1 and #2 are the two that decide whether the
system detects anything real; #3–#6 are correctness and credibility.

---

## 1. Train/inference covariate shift  🔴

**The problem.** Every model was trained on public Kaggle datasets whose
features were produced by **CICFlowMeter**. At inference time features come
from our **own Scapy-based flow extractor**. These two produce numerically
different values for nominally-identical features:

- Flow timeout / active-idle splitting differs (CICFlowMeter's 120s/5s vs.
  ours) → the *same* packets become a different number of flows with
  different durations, packet counts, and rates.
- IAT, `flow_bytes/s`, `fwd/bwd` accounting, and header-length handling are
  each defined slightly differently.
- Feature *order* and units (µs vs. ms) must match the training frame
  exactly or the model reads garbage silently.

The result is **covariate shift**: `P(features)` at inference ≠ `P(features)`
at training. The model does not error — it just quietly loses accuracy, and
neither high confidence nor the passing unit tests reveal it. This is the
single biggest credibility risk in the project.

**How to prove it (the validation experiment — do this first).**
1. Take one labelled `.pcap` you trust (e.g. a CIC dataset capture).
2. Run it through **CICFlowMeter** → `ref.csv`.
3. Run the *same pcap* through our extractor → `ours.csv`.
4. Align on flow key (5-tuple + start time) and compare feature
   distributions: per-feature KS statistic, mean/std deltas, and a
   scatter of `ours` vs. `ref` for the top features by model importance.
5. Score both frames with the ONNX model and compare the confusion
   matrices. The delta between them *is* the covariate-shift penalty.

**How to fix (in order of preference).**
- **Best:** retrain on features produced by *our own extractor* so train and
  inference share one code path. Requires re-labelling flows, but removes
  the shift entirely.
- **Cheaper:** make the extractor bit-compatible with CICFlowMeter
  (match timeouts, IAT definition, units, feature order). Verify with the
  KS test above until distributions overlap.
- **Stopgap:** fit a per-feature scaler/quantile-mapper from `ours → ref`
  and apply it before inference. Documents the gap honestly rather than
  hiding it.

**Acceptance.** Confusion matrices from step 5 agree within a stated
tolerance (e.g. ≤2% F1 drop per class) on the held-out pcap.

---

## 2. Only 4 of 6 threat classes wired  🔴

**The problem.** The runtime registry loads four models:

| Wired | Model | Class |
|-------|-------|-------|
| ✅ | DDoS XGBoost | DDoS |
| ✅ | DGA CNN-BiLSTM | DGA / DNS-tunnel |
| ✅ | C2 BiLSTM+FFT | C2 beaconing |
| ✅ | ETT FT-Transformer | Encrypted malware |
| ❌ | **Port Scan XGBoost (bot 5)** | Recon / port scan |
| ❌ | **Exfil VAE (bot 6)** | Data exfiltration |

Bots 5 and 6 are **trained and the artifacts exist**, but there is no
wrapper, no config entry, and no registry registration, so the service
detects only four of the six mandated classes. The problem statement
requires all six. **Do not upload bots 5/6 to Hugging Face before wiring
and testing them** — wire first, prove they run on real flows, then publish.

**Wiring checklist (per model).**
1. Add a `config` entry (feature list, input shape, threshold, class name,
   MITRE mapping).
2. Write a `models/port_scan.py` / `models/exfiltration.py` wrapper matching
   the existing wrapper interface (`predict(features) -> (label, conf, evidence)`).
3. Register in `models/registry.py`.
4. **Exfil VAE specifically:** the anomaly score is reconstruction error vs.
   a threshold, not a softmax. The joblib **scaler must be loaded with a
   matching scikit-learn version** or it will unpickle wrong/silently skew —
   pin the version and assert on load. Decide the threshold from the
   training reconstruction-error distribution (e.g. 4σ), not a guess.
5. Emit the class-specific evidence the frontend already renders:
   - Port scan → `fan_out: {target_ip, ports[], window}`
   - Exfil → `byte_ratio: {outbound, inbound}`

**Acceptance.** A crafted port-scan pcap and an exfil pcap each produce a
correctly-classed alert end-to-end over the WebSocket.

---

## 3. C2 FFT computed on mean-removed IATs  🟠

**The problem.** The C2 detector removes the mean from the inter-arrival-time
series before the FFT. A *perfect* beacon has near-constant IATs — once you
subtract the mean, the signal is ~all zeros, so the spectrum is flat and the
dominant-frequency feature the model keys on collapses. The cleanest beacon
(the most obviously malicious case) is the one this pipeline is weakest on.

**Fix.** Do not mean-center before the FFT, or window/detrend in a way that
preserves the periodic component. Compute the periodogram on the raw IAT
series, take the dominant non-DC bin, and derive spectral entropy from the
normalized power spectrum. Validate against a synthetic 60s ±5% beacon: the
dominant frequency should land at ~1/60 Hz with low spectral entropy.

**Acceptance.** Synthetic constant-interval beacon scores *higher*, not
lower, than a jittered one.

---

## 4. CV-gate false-positive regression  🟠

**The problem.** The coefficient-of-variation gate meant to catch periodic
C2 also fires on **benign periodic traffic** — NTP sync, TCP keep-alives,
heartbeats, polling. These are legitimately regular, so a naive "low CV of
IAT ⇒ beacon" rule flags them. This inflates the false-positive rate on
exactly the quiet-network traffic a SOC sees most.

**Fix.** The gate needs a benign-periodic allowlist / secondary features:
destination reputation, port (123/NTP, etc.), payload-size regularity,
jitter profile, and duration. A real beacon is regular *and* long-lived
*and* to an unusual destination — require the conjunction, not CV alone.
Re-tune the threshold against a benign capture that *contains* NTP/keep-alive
so the regression is measured, not assumed away.

**Acceptance.** Benign periodic capture produces zero C2 alerts; synthetic
beacon still detected.

---

## 5. Alert schema: add 5-tuple flow id + SHAP evidence  🟡

**The problem.** The frontend (now complete) renders the NTRO alert schema
`{ timestamp, flow id (5-tuple), threat class, confidence, supporting
evidence }`. The backend currently emits source/dest IP but not the full
**5-tuple flow id** (`src_ip:src_port → dst_ip:dst_port · protocol`), and
its `evidence` dict is hand-written strings rather than model-grounded
attributions.

**Fix.** In `alert_manager.py`:
- Add `flow` to every alert: `{src_ip, src_port, dst_ip, dst_port, protocol}`.
- For tree models (DDoS, Port Scan XGBoost) attach top-k **SHAP** feature
  contributions so "supporting evidence" is the model's actual reasoning,
  not a template.
- Keep emitting the class-specific evidence objects from §2 (`fan_out`,
  `byte_ratio`, `iat[]`, `class_probs[]`, `ja4`) — the dashboard already has
  panels for each of these.

The frontend `parseBackendAlert()` in `src/data/useThreatFeed.ts` already
maps ISO→epoch, 0–1→%, UPPERCASE→lowercase severity, and nested
`mitre`/`geo`; extend it in lockstep as fields are added.

**Acceptance.** A live alert deserializes into the `Alert` interface in
`src/types/alert.ts` with `flow` populated and no missing-field fallbacks.

---

## 6. Test suite proves load/run, not live accuracy  🟡

**The problem.** The ~37 passing tests confirm models *load*, *run*, and
*catch obvious synthetic cases*. They do **not** measure live performance —
the real-flow / pcap-replay tests were skipped. Two internal reports
disagree; treat `HONEST_TEST_REPORT.md` as the credible baseline and
`COMPLETE_TESTING_JOURNEY_REPORT.md` as over-generous / partly synthetic.

The headline metrics (DDoS 99.3% F1, DGA 93.6%, C2 93.5%, ETT 88%) are
**dataset test-split numbers**, not live-capture numbers, and until §1 is
resolved they overstate real accuracy.

**Fix.**
- Un-skip and run the pcap-replay tests against labelled captures per class.
- Report a confusion matrix *per class from real flows*, separate from the
  training-split numbers.
- Add a false-positive test on a purely-benign capture (ties into §4).

**Acceptance.** A `LIVE_RESULTS.md` with per-class precision/recall from
pcap replay through the *actual* extractor → ONNX path, plus a stated FP rate
on benign traffic.

---

## Recommended sequence

1. **§1 covariate-shift validation experiment** — until you know the size of
   the gap, every other metric is suspect.
2. **§2 wire bots 5 & 6** — you are not detecting two mandated classes.
3. **§6 run the skipped real-flow tests** — get honest per-class numbers.
4. **§3 fix the C2 FFT** — it's ~20 lines and fixes the strongest-signal case.
5. **§4 fix the CV-gate FP regression** — measured against benign periodic.
6. **§5 schema: 5-tuple + SHAP** — finish the frontend contract.

Only after 1–3 pass should bots 5/6 be published to Hugging Face.
