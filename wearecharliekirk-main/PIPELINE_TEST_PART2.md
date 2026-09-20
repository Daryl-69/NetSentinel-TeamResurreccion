# Full-pipeline test, Part 2 — with the models loaded

*20 September 2026. The models are now public and vendored into `<repo>/models/`,
so everything that was blocked in Part 1 has been run. Same real input: a
**200 MB / 186,363-packet capture of ordinary traffic from one host**, spanning
**32.5 minutes**. Every number below is measured.*

## What changed since Part 1

| Part 1 | Now |
|---|---|
| 6 models unobtainable (proxy blocked HuggingFace) | **6/6 load in 1.5 s** from `<repo>/models/` |
| Detection half untestable | **Full path exercised end to end on real traffic** |
| 7 failed / 7 passed / 14 skipped | **60 passed / 0 failed / 10 skipped** |

`get_model_path()` now resolves `$NETSENTINEL_MODELS_DIR` → `<repo>/models/` →
legacy paths → HuggingFace, so an air-gapped site never needs the network.

## 1. End to end, on real traffic

```
pcap → extractor → 6 models → analyzer → alert manager
```

| | measured |
|---|---|
| models loaded | 6/6 in 1.5 s |
| flow events | 2,113 |
| alerts raised | **144** |
| analyzer errors | **0** |
| wall clock | 39.7 s for 32.5 min of traffic → **49× real time** |
| byte rate | ~5.0 MB/s (~40 Mbps) |
| peak RSS | 244 MB |

The pipeline runs clean: no crashes, no unhandled exceptions, six models
resolving and scoring on genuine packets. That part works.

## 2. The finding that matters — alert volume

**144 alerts from one host in 32.5 minutes = ~266 alerts per host per hour.**

| class | count | share | severity |
|---|---|---|---|
| VPN Traffic | 103 | 71.5% | LOW |
| **Data Exfiltration** | **30** | 20.8% | **CRITICAL** |
| DGA | 8 | 5.6% | — |
| DNS Tunnel | 3 | 2.1% | — |

This was one laptop doing ordinary things for half an hour. As an illustration
only — assuming this host is representative, which is an assumption — a
100-host site would see on the order of **26,000 alerts/hour, ~5,500 of them
CRITICAL**. No SOC absorbs that.

This is the single thing standing between the current build and an industrial
deployment. It is not a model-accuracy problem so much as an operating-point and
alert-hygiene problem.

## 3. The exfiltration alerts need attention before any demo

All 30 share a signature that should not appear on ordinary traffic:

```
conf=1.000  src=10.36.16.146  dst=None  sev=CRITICAL
mitre={'tactic':'Exfiltration','technique':'T1048',
       'name':'Exfiltration Over Alternative Protocol'}
```

Three things stand out, stated as observation and inference, not as a verdict:

1. **Confidence is exactly 1.000 on every one of them.** A VAE
   reconstruction-error score pinned at the top of its range across 30
   consecutive alerts indicates the score is saturating — a normalisation or
   threshold issue — rather than 30 independent maximally-confident findings.
2. **`destination_ip` is `None`.** An exfiltration alert that cannot say where
   the data went is not actionable, whatever its confidence.
3. **Thirty genuine exfiltration events in 32 minutes on a personal machine is
   not a plausible reading.** I have no ground-truth labels for this capture, so
   I am not calling each one a false positive — but the aggregate is not
   credible, and the two points above explain why.

This is consistent with the previously documented exfil-VAE false-positive
concern, and sharper than that framing: the alerts are CRITICAL, saturated, and
missing their destination field.

**Before the demo:** either recalibrate the exfil threshold against a benign
baseline, or gate the exfil model behind a volume precondition, or downgrade it
to informational. Any of the three is defensible; shipping 30 CRITICALs per
half-hour per host is not.

## 4. "VPN Traffic" is 72% of alert volume and probably is not an alert

The encrypted-traffic transformer is a **14-class classifier**. "VPN Traffic" is
one of its class labels — a description of what a flow is, not a claim that
anything is wrong. It is currently surfaced as an alert (LOW), and it accounts
for **103 of 144 alerts**.

Reclassifying it as telemetry rather than an alert removes ~72% of the volume at
zero detection cost. That is the cheapest available fix.

## 5. Test suite

**60 passed, 0 failed, 10 skipped.** Two failures found and fixed during this
pass, both stale tests rather than defects:

- `test_port_scan_model_loads` asserted the **40-column UNSW-NB15** schema. The
  shipped model is the **69-feature CIC** XGBoost
  (`port_scan_cic_xgboost.onnx` + `port_scan_cic_features.json`). The test was
  left behind by the CIC migration and was checking a model that is no longer
  wired in. Updated to 69, and its `skipif` — which referenced a path that never
  existed and was always truthy — now checks the real file.
- `test_benign_traffic_not_detected` compared against lowercase `'benign'` while
  the detector emits `'Benign'`. Pure case mismatch; the behaviour was correct
  (benign traffic, 0.25% confidence, correctly not flagged). Now compared
  case-insensitively.

## 6. One correction to Part 1, and one defensive fix

**Correction.** Part 1 said `config.py` "prints the error and continues rather
than failing hard." **That was wrong.** `from netsentinel import config` exits 1
and `import netsentinel.main` exits 1 — it raises and refuses to start, which is
correct behaviour. Part 1 has been amended.

**Near-miss, worth recording.** My first end-to-end harness threw 186
`AttributeError`s inside `analyze_flow`. `process_pcap()` yields `None` every
1000 packets as a cooperative-yield signal (`pcap_reader.py:191`), and
`analyze_flow` calls `.get()` on it. I nearly reported this as a live pipeline
bug — but **`routes.py:339` already guards it** (`if event is None: continue`).
The shipped path is correct; my harness was not.

A one-line guard was still added to `analyze_flow`, because the contract
shouldn't depend on every caller remembering, and because a `None` also inflated
`flows_processed` before the guard.

## 7. Where this leaves "industrial grade"

**Works:** the full path runs on real traffic with zero errors; models load fast
and cheap; 49× real time on a single core with 244 MB resident; the integrity
layer's inclusion proofs, append-only consistency proofs and signed ledger all
verify (fixed earlier today); the test suite is green.

**Blocks deployment:** alert volume. ~266 alerts/host/hour on ordinary traffic,
72% of it a classifier label surfaced as an alert, and 30 saturated CRITICAL
exfil alerts per half-hour with no destination.

**Order I would fix them:**

1. Stop emitting "VPN Traffic" as an alert — removes ~72% of volume immediately.
2. Recalibrate or gate the exfil VAE against a benign baseline; populate
   `destination_ip`.
3. Re-measure alert rate on the same capture; target something a human can read.
4. Then, and only then, quote an alert rate publicly.

**Still not measured, so still not claimed:** detection accuracy, recall, or
false-positive *rate* in the strict sense. Those need labelled data — this
capture has none. Everything above is behaviour on real traffic, not accuracy.
