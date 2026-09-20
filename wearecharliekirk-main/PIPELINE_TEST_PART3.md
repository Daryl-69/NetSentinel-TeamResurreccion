# Full-pipeline test, Part 3 — the accuracy question

*20 September 2026. Both Part 2 blockers are fixed. Every figure below was
re-measured today against the **same 200 MB capture Part 2 used**
(`ns_00001_20260918083538.pcap`, 2,113 flow events), so the before/after is
like for like. The capture was processed on the machine that holds it; it was
never copied anywhere.*

## The one-line answer

The two blockers are fixed and verified on real traffic. But the headline is
the thing that is still **not** claimed:

> **Not claimed: accuracy, recall, or a false-positive rate.** Those need
> labelled data, and this capture has none. Everything measured here is
> **behaviour, not accuracy.**

Section 2 explains why that is a statement about the evidence and not modesty.

---

## 1. The two Part 2 fixes landed

### 1.1 Exfiltration VAE — was saturated and anonymous, now graded and attributed

Part 2 found 30 exfiltration alerts that were all CRITICAL, all at confidence
exactly `1.000`, and all with `destination_ip = None`. The confidence was
computed as `min(mse / threshold, 1.0)`, and whenever `mse > threshold` that
ratio is by definition greater than 1 — so it clamped to `1.000` every time.
The score was binary while presenting itself as a confidence.

```python
# netsentinel/models/exfiltration.py:94-95
excess = (mse - self.threshold) / self.threshold
conf   = 1.0 - math.exp(-excess)
```

Separately, `dst_ip` was computed in the DNS extractor's `process_packet` but
never passed into `_handle_query`, so it never reached the alert.

Measured on the real capture, before and after:

| Exfiltration alerts | Part 2 | Now |
|---|---|---|
| confidence values | `1.000` on all 30 | **14 distinct values, 0.712 – 1.000** |
| `dest_ip` populated | 0 / 30 | **27 / 27** |
| severity | 30 × CRITICAL | graded — most INFO, 2 CRITICAL, 2 HIGH |

### 1.2 "VPN Traffic" is telemetry, not an alert

The encrypted-traffic transformer is a 14-class classifier. "VPN Traffic" is one
of its **class labels** — a description of what a flow is, not a claim that
anything is wrong — and it was being surfaced as an alert, accounting for 103 of
144 alerts. It is now recorded as classification telemetry behind a config flag
(`ETT_ALERT_ON_VPN = False`, `netsentinel/config.py:128`, gated at
`netsentinel/pipeline/analyzer.py:352`). Nothing was deleted; it moved from the
alert stream to the telemetry stream.

### 1.3 Net effect on the identical capture

| | Part 2 | Now |
|---|---|---|
| flow events | 2,113 | 2,113 |
| **total alerts** | **144** | **34**  (1.61% of events) |
| — VPN Traffic | 103 | **0** (now telemetry) |
| — all other classes | 41 | 34 |
| **CRITICAL** | **30** | **2** |
| CRITICAL + HIGH (actionable) | 30 | **4** |
| models loaded | 6/6 | 6/6 in 1.47 s |

Of the 110-alert reduction, 103 is the VPN reclassification — plain arithmetic,
not a model improvement. The remaining change (41 → 34, and the collapse of
CRITICAL from 30 to 2) follows the exfil regrade. Post-fix class mix is
Data Exfiltration 26, DGA 7, DNS Tunnel 1; severity is 29 INFO, 2 CRITICAL,
2 HIGH, 1 MEDIUM.

**~4 actionable alerts per host per half-hour** is a load a human can read.
That is the operational claim, and it is the only one this section supports.

---

## 2. Why there is still no accuracy, recall, or FP-rate number

The evaluation splits into two halves. They are **not** equally trustworthy, and
collapsing them into one "accuracy" figure would be the dishonest move.

### 2.1 Half 1 — recall on simulator attacks: **circular, upper bound only**

`python scripts/evaluate_detection.py --n 500`

| attack class | n | detected | rate | what actually fired |
|---|---:|---:|---:|---|
| ddos | 500 | 218 | 43.6% | DDoS 218 |
| dga | 500 | 386 | 77.2% | DGA 386 |
| c2 | 500 | 64 | 12.8% | C2 Beacon 64 |
| port_scan | **5 sources** | **5** | **100.0%** | Port Scan 5 (+ DDoS 449) |
| exfil | 500 | 419 | 83.8% | Data Exfiltration 413, DNS Tunnel 6 |

Simulator benign traffic: **0 alerts on 500 normal flows and 0 on 500 normal DNS
queries.**

Two things about this table, both of which matter more than the percentages:

**The generator is unseeded, so these move run to run.** Across five
consecutive runs: ddos 43.6–50.4%, dga 74.6–79.6%, c2 12.0–13.8%, exfil
82.0–84.6%. Quote a range or quote nothing; a single decimal here is noise.

**`port_scan` is measured per *source*, not per flow** — note the `n` of 5.
Port scan is an aggregate detector: it emits one alert per scanning host per
time window, so 500 scan flows from 5 attacking hosts *should* produce exactly
5 alerts. Scoring it per-flow called complete detection "1%". The harness now
measures whether each scanning source was caught (`evaluate_detection.py`,
`AGGREGATE`). The DDoS 449 alongside it is the DDoS model also firing on the
same short high-rate flows — see §4.3.

**These are not accuracy figures, and must not be quoted as any.** The attack
traffic comes from `netsentinel/simulator/traffic_gen.py`, written by the same
people as the detectors. Measuring recall on it asks *"does the detector fire on
the thing we built it to fire on?"* — not *"does it catch real attacks?"* A real
attacker does not sample from our generator. Every number in that table is an
**upper bound** and a wiring smoke test.

They are still worth running, because a smoke test catches wiring faults — which
is exactly what the `port_scan` row is (§4.3).

### 2.2 Half 2 — false positives on real traffic: measured, still an upper bound

Real packets off a real link, scored by the real pipeline. Not circular, and the
useful half.

| | measured |
|---|---|
| flow events | 2,113 |
| alerts | 34 (1.61% of events) |
| by class | Data Exfiltration 26, DGA 7, DNS Tunnel 1 |
| by severity | INFO 29, CRITICAL 2, HIGH 2, MEDIUM 1 |
| CRITICAL + HIGH | 4 |

**The assumption that stops this being a false-positive rate:** the capture has
**no ground-truth labels**. Nobody has verified it contains no real intrusion,
and nobody has verified that anything it *does* contain was caught. So these 34
alerts are *"alerts raised on ordinary traffic"* — an **upper bound** on the
false-positive count, not a measured false-positive rate. If even one of the 34
is a true positive, the FP count is lower; if the capture contains an intrusion
nothing flagged, there is a false negative that this measurement cannot see.

A false-positive *rate* requires a denominator of confirmed-benign flows. This
capture does not provide one.

---

## 3. So, stated plainly

**What can be said, because it was measured:**

- The full path runs on real traffic with **zero analyzer errors**; 6/6 models
  load in 1.47 s from the vendored `models/` directory with no network.
- On a real 200 MB single-host capture: **34 alerts from 2,113 flow events,
  4 of them actionable.**
- Exfiltration confidences are **graded (0.712–1.000, 14 distinct)** and every
  exfil alert **names a destination**.
- Benign simulator traffic raises **0 alerts in 1,000 events**.
- Wiring for DDoS, DGA, C2, exfiltration **and port scan** is exercised end to
  end. Port scan now flags **5/5 scanning sources** having previously flagged
  none, and adds **no false positives** on the real capture (§4.3).
- `pytest tests/` runs clean with no flags: **62 passed, 11 skipped, 0 errors**
  (§4.4).
- The integrity layer's inclusion proofs, append-only consistency proofs and
  signed ledger all verify — **42 / 42** regression tests, including exhaustive
  consistency over every `(old_size, new_size)` pair up to 33 and rejection of
  rewritten history.

**What cannot be said, and is not said anywhere in this project:**

- ❌ "NetSentinel is *X*% accurate."
- ❌ "*X*% recall" / "*X*% detection rate" as a product claim.
- ❌ "*X*% false-positive rate."
- ❌ Any per-class number from §2.1 quoted without the word *circular* attached.

> **Still not claimed: accuracy, recall, or a false-positive rate. Those need
> labelled data and this capture has none. Everything above is behaviour, not
> accuracy.**

---

## 4. Defects this pass surfaced

Recorded because a test pass that finds nothing usually means the test was weak.

### 4.1 Simulator events carried no timestamp — **fixed**

Generated events omitted `timestamp`, so `event.get("timestamp", 0)` returned
`0`, and the analyzer's `if now - last_alert_time > 60.0` dedup treated every
alert as a duplicate of an event from 1970. **Every DNS-family alert was
silently suppressed** — the first run of this evaluation reported dga 0.0% and
exfil 0.0% and both were harness artifacts, not detector failures. Fixed with a
`_stamp()` helper applied across the generators
(`netsentinel/simulator/traffic_gen.py:21,33`). This is why §2.1 shows 77.8% and
82.0% rather than zeros.

### 4.2 sklearn version skew silently disabled port-scan loading — **shimmed**

`requirements.txt` pins `scikit-learn==1.3.2`; the runtime has 1.7.2. Estimators
unpickled from the older version lack `monotonic_cst`, raising `AttributeError`
at load and disabling the detector without a hard failure. A compatibility shim
backfills the attribute (`netsentinel/models/portscan_detector.py:104-106`). The
pin should still be enforced at startup or the model re-serialised.

### 4.3 Port scan detected nothing in the integrated pipeline — **FIXED**

Port scan went from **0% to 100% of scanning sources detected (5/5)**, with
**no new false positives on the real capture** (still 34 alerts, unchanged).

**First, a correction to this document.** An earlier draft of this section
blamed *routing precedence* — it claimed the DDoS model ran first and that an
`if alert is None` guard short-circuited the port-scan buffer. **That was
wrong.** Reading the code, the port-scan block is *not* behind that guard; only
the encrypted-traffic block is. The real causes were four separate defects,
none of them precedence, and none of them in the model:

**(a) The aggregation buffer discarded flow identity.** `analyzer.py` buffered
`event["features"]` alone, but `Flow.from_cic_record()` reads `Src IP`,
`Dst IP`, `Dst Port` and `Timestamp` — which live at the *event* level, not
inside `features`. Every buffered record therefore came back with `src_ip` as
the literal string `"None"` and `dst_port` `0`, collapsing all 500 flows into
one fake source with a single port. Fan-out was permanently 1, so no scan could
ever fire, regardless of model quality. The buffer now carries identity
alongside features (via `setdefault`, so genuine CICFlowMeter records that
already have those columns are never overwritten).

**(b) Alerts were built but arrived unclassified.** `_alert_to_dict()` emitted
`"threat_type"`, while `AlertManager.create_alert()` reads `"threat"` — the
contract every other wrapper follows (`ddos.py`, `dga.py`, `c2_beacon.py` all
emit `"threat"`). Port-scan alerts fell through to the `"Unknown"` default, so
they carried `threat_class: Unknown`, a default MEDIUM severity and an Unknown
MITRE mapping instead of **T1046**. Fixed by emitting the contract key.

**(c) The SPSD model's confidence was not a probability.** This is the
serious one. `predict_proba()` was returning **raw leaf counts** — literally
`[0., 15.]` — instead of `[0., 1.]`. A `DecisionTreeClassifier` pickled under
the pinned scikit-learn 1.3.2 stores raw class counts in `tree_.value`, and
scikit-learn ≥1.4 (runtime here is 1.7.2) returns that array straight out of
`predict_proba` without normalising. Two things broke silently:

- confidence became an arbitrary sample count, and AlertManager's
  `confidence > 0.95 → CRITICAL` rule then escalated **every** SPSD port-scan
  alert to CRITICAL regardless of real certainty;
- the fire test `proba >= 0.5` degraded into *"this leaf saw ≥ 1 scan
  sample"*, far more permissive than P(scan) ≥ 0.5 — a latent false-positive
  source on real traffic.

The `monotonic_cst` shim (§4.2) let the model load and hid all of it. The fix
normalises by the row sum, which is correct under both layouts: an
already-normalised row sums to 1.0 and is unchanged. Confidence now reads 1.0
on a pure leaf instead of 15.0.

**(d) The harness measured the wrong thing** — per-flow recall on an
aggregate detector. See §2.1.

Two notes that remain open, neither blocking:

- **DDoS also fires on scan flows** (449 of 500). The simulated scan flows
  carry high packet rates, so the DDoS model legitimately trips on them. The
  aggregator comments intend port scan to be the more specific diagnosis; the
  override currently only applies within a flush cycle. Worth tightening, but
  it is a labelling-precision issue, not a miss.
- **Severity is computed twice** — once by the port-scan detector (which knows
  the fan-out) and again by `create_alert` from confidence alone. They can
  disagree (detector said HIGH, alert says CRITICAL). Now that confidence is a
  real probability the disagreement is at least meaningful.

And the standing caveat: **the 99.03% in `PORT_SCAN_COMPLETE.md` is still a
statement about the SPSD model on a CIDDS-001 validation set, not a
NetSentinel detection rate.** The 100% above is source-level recall on
*self-generated* scan traffic — circular, like everything else in §2.1.

### 4.4 `pytest tests/` aborted the entire run — **FIXED**

```
before:  pytest tests/   ->  INTERNALERROR, collection aborts, 0 tests run
after:   pytest tests/   ->  62 passed, 11 skipped, 0 errors, 0 failures
```

No flags, no `PYTHONPATH`. Three problems, all fixed by one new
`tests/conftest.py` rather than by rewriting the offending modules:

- **`tests/test_advanced.py` is a live-API script, not a test.** It executes at
  import and calls `sys.exit(1)` when nothing is listening on `localhost:8000`.
  pytest imports every `test_*.py` during collection, so that `sys.exit` killed
  the whole run before a single test executed. Flagged back in Part 1. It is
  now excluded via `collect_ignore` and stays runnable as
  `python tests/test_advanced.py` against a live server.
- **`test_live_pcap(pcap_path)`** declared an argument pytest read as a fixture
  request that did not exist, erroring at setup every run. There is now a
  `pcap_path` fixture fed by a new `--pcap` option; without it the test *skips*
  (the 11th skip) instead of erroring. It became a proper opt-in integration
  test: `pytest tests/ --pcap=/path/to/capture.pcap`.
- **The repo root had to be on `sys.path` manually**, so `python tests/x.py`
  failed with `ModuleNotFoundError: No module named 'netsentinel'` unless the
  caller set `PYTHONPATH`. The conftest now inserts it.

**A test that could not fail.** Fixing the warnings surfaced this:
`tests/test_model_loading` called `registry.load_all_models()` and
`registry.get_model(...)` — **neither method exists** on `ModelRegistry` (the
real API is `load_all()` plus per-model attributes). Every run raised
`AttributeError`, hit a bare `except Exception`, printed the error and did
`return False` — and **pytest counts a returned value as a pass**. So it
reported PASSED on every run while asserting nothing and in fact failing, and
it was inflating the headline count. Rewritten to assert against the real API;
it now genuinely passes because all 6 models do load. `PytestReturnNotNone`
warnings: 0.

The two remaining warnings are third-party (scapy FFDH deprecation, and a
scikit-learn `InconsistentVersionWarning` for a `RobustScaler` — see §4.5).

### 4.5 The scikit-learn pin is still not enforced — **OPEN**

`requirements.txt` pins `scikit-learn==1.3.2`; the runtime is **1.7.2**. This
version skew has now produced **two** distinct defects, one of which
(§4.3c) silently corrupted a model's output for an unknown length of time
while every test stayed green:

| symptom | status |
|---|---|
| `monotonic_cst` missing on unpickled trees → detector disabled at load | shimmed (§4.2) |
| `predict_proba` returns raw leaf counts, not probabilities | fixed (§4.3c) |
| `RobustScaler` unpickled across versions | **unaudited** |

The `RobustScaler` warning is the same class of risk. Its attributes are plain
arrays so it is *probably* fine, but "probably" is doing real work in that
sentence and nobody has checked what it scales or whether those values moved.

The durable fix is one of: enforce the pin at startup and fail hard, or
re-serialise every `.pkl` under the version actually deployed. Shimming
symptoms one at a time does not scale — the two defects above were each
invisible until something downstream looked obviously wrong, and a scaler
quietly producing shifted values would not look obviously wrong at all.

---

## 5. What a publishable number would actually require

A recall or accuracy figure worth putting in a submission needs traffic that is
**real** and **labelled** — neither of which the current evidence has. The
concrete path:

1. **Obtain a labelled intrusion capture** with per-flow ground truth —
   CIC-IDS2017, CTU-13, or UNSW-NB15 are the standard choices.
2. **Map its labels onto our threat classes**, and be explicit about classes
   that do not map cleanly rather than quietly dropping them.
3. **Run the pipeline unchanged** and compute per-class precision, recall and
   F1, plus a genuine false-positive rate against the labelled-benign subset.
4. **Report the operating point**, because recall and FP rate trade off against
   each other and a single number without a threshold is meaningless.
5. **Report the covariate shift too** — the extractor's features drift against
   CICFlowMeter, so a number from a dataset built with CICFlowMeter does not
   transfer to this extractor without that caveat.

None of this was done here: those datasets were not reachable from the
environments this test ran in. Until step 5 is complete, the correct phrasing in
every document, slide and demo is **"behaviour verified on real traffic"** —
never *"X% accurate."*

---

## 6. Reproducing this

```bash
# Half 1 — circular recall + benign FP (no capture needed)
python scripts/evaluate_detection.py --n 500

# Half 2 — the real-traffic half, point it at your own capture
python scripts/evaluate_detection.py --n 500 --pcap /path/to/capture.pcap
```

```bash
# Test suite — no flags, no PYTHONPATH needed any more
pytest tests/

# Opt-in live pipeline test against a real capture
pytest tests/ --pcap=/path/to/capture.pcap
```

`scripts/evaluate_detection.py` prints the circularity warning alongside its own
output by design, so the numbers cannot be copied out of a terminal without the
caveat that qualifies them.

---

## Status after Part 3

| | |
|---|---|
| Part 2 blocker: exfil saturation + missing destination | **fixed, verified on real traffic** |
| Part 2 blocker: alert volume | **fixed** — 144 → 34, CRITICAL 30 → 2 |
| Backend test suite | **`pytest tests/` runs clean** — 62 passed, 11 skipped, 0 errors (§4.4) |
| Integrity (inclusion, append-only, signed ledger) | 42 / 42 passing |
| Port-scan detection in the integrated pipeline | **fixed** — 0% → 5/5 sources, 0 new FP (§4.3) |
| scikit-learn pin not enforced (2 defects so far) | **OPEN** (§4.5) |
| Accuracy / recall / FP rate | **not measured, not claimed — needs labelled data** |
