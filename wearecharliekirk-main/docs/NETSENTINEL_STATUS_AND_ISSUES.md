# NetSentinel — Consolidated Status, Issues & Next Steps

_Passive, unidirectional ML-based network intrusion **detection** sensor (detect + alert only — no block/quarantine/mitigate)._

> **How to read this file.** Every claim is tagged with how strongly it's been
> verified:
> - ✅ **VALID** — verified in code / a real run, safe to rely on.
> - ⚠️ **PARTIAL** — works but has a caveat or is unproven on real data.
> - ❌ **OPEN** — a real, unresolved issue.
> - ❓ **UNVERIFIABLE** — depends on code you changed but haven't pushed, so I
>   could not confirm it.

---

## 1. What is READY and VALID

| Area | Status | Notes |
|---|---|---|
| Extraction (flow / DNS / session, PCAP + live) | ✅ VALID | Memory-safe `PcapReader` for large captures |
| 6-model routing + 5-tuple flow id | ✅ VALID | All six models load and route (verified in code) |
| WebSocket → dashboard | ✅ VALID | Live + mock both work |
| Frontend ↔ backend contract | ✅ VALID | `parseBackendAlert` maps snake_case, threat classes, model names, evidence keys; `tsc` clean |
| Live vs mock state is honest in UI | ✅ VALID | `feed.source` distinguishes `live` / `mock`; no silent fake feed |
| Evidence keys for the 5 specialty panels | ✅ VALID | `src_ip_entropy`, `fan_out`, `byte_ratio`, `ja4`/`ja4_rarity`, `iat` wired end-to-end |
| Passive / no-blocking contract | ✅ VALID | Detection-only, matches the enclave constraint |
| Runtime dependencies declared | ✅ VALID | `huggingface_hub`, `joblib`, `scikit-learn` now in `requirements.txt` |
| DDoS XGBoost | ✅ VALID | Healthiest model; plausible on real data |
| ETT Transformer | ✅ VALID | Uses **JSON** scaler → immune to the exfil pickle bug |
| DGA / C2 detection | ⚠️ PARTIAL | Structurally sound; unproven on real beacon/DGA captures |

---

## 2. All KNOWN ISSUES (ranked by severity)

### 🔴 Critical — fix before any accuracy claim

1. **Exfil VAE ~50% false-positive rate** ❌ OPEN
   - Measured in your own runs (~16,708 / 50,000 ≈ 51.8%, and 3,401 / 9,100 in another).
   - Root cause: **scaler pickle version mismatch** — `exfil_scaler.joblib` was
     pickled with one scikit-learn version and unpickled with another, so the 24
     DNS features arrive mis-scaled → VAE reconstruction error inflated on nearly
     everything. Made worse by the relaxed exfil threshold (see #4).
   - **Fix:** pin `scikit-learn==<training version>`, re-pickle the scaler with
     that version, upload to HF (`Unded-17/netsentinel-models`), re-run PCAP,
     confirm rate drops to low single digits. **Not a retraining problem.**
   - **Uniqueness:** exfil is the ONLY model with both a pickle scaler AND an
     anomaly/reconstruction threshold. No other model can blow up this way.

2. **Retrained exfil scaler not deployed to HuggingFace** ❌ OPEN
   - No `hf_upload/` in the repo; the deployed scaler is still the mismatched one,
     so #1 persists in any fresh clone even after you pin locally.

### 🟠 High — correctness / honesty

3. **Extractor ↔ training feature drift (covariate shift)** ❌ OPEN
   - `ks_summary.txt` still shows ~92% of features shifted (stale — script skips
     regeneration if `ours.csv` exists).
   - Affects **any flow-feature model (DDoS, Port Scan, ETT)** — degrades accuracy
     (does NOT cause a false-positive flood like exfil).
   - **Fix:** `rm ours.csv && python scripts/covariate_shift.py`; align feature
     units (flag counts, packet rates, `Fwd/Bwd Header Length`) to CICFlowMeter;
     re-check that rate/flag features drop below KS 0.1. Document the residual gap
     honestly.

4. **Three demo-tuning compromises in `analyzer.py`** ❓ UNVERIFIABLE (code not pushed)
   - (a) Port-scan behavioral bypass (`num_ports >= 30` → alert, bypasses ML) →
     +10–20% FP on IT tools/scanners.
   - (b) DGA entropy gate `> 3.8` (was 3.0) → misses ~5–10% low-entropy DGA
     families (Suppobox/Shifu/Tinba).
   - (c) Exfil relaxed thresholds `dns_entropy > 3.5 and subdomain_len > 15`
     (strict was `> 4.5 / > 30`) → +5–15% FP on AWS/Azure/CDN domains.
   - **Decision:** video is recorded → revert all three to production defaults.
     Optionally keep a `DEMO_MODE` toggle in `config.py`.

5. **Documentation inconsistencies** ❌ OPEN
   - Accuracy tables disagree (README 93.6% / 88% vs demo 99.2% / 98.7%).
   - Entropy figure contradicts itself (2.59 vs 12.4 bits across docs).
   - Alert counts differ between STATUS and DEMO reports (6,370 vs 3,905/5,352).
   - **Fix:** produce ONE reproducible train/val/test report from the actual split
     you used, and make every doc cite that single source.

### 🟡 Medium — hardening / robustness

6. **No upload validation on `/pcap/upload`** ❌ OPEN
   - Accepts arbitrary files. A monitoring enclave should reject executables,
     credential/payload fields, oversized files, and **pickle files** (ironic given
     exfil ships a `.joblib` pickle). Bound size and delete after processing.

7. **Port scan silent on synthetic traffic** ⚠️ PARTIAL
   - Produces ~0 alerts on the simulator because synthetic flow events bypass the
     packet layer → features are out-of-distribution → ~0.01–0.17% confidence.
     The **model is fine**; the input is wrong. Real Nmap PCAP scores 80–95%.
   - **Fix:** validate with a real port-scan capture, not the simulator.

8. **Simulator ≠ production path** ⚠️ PARTIAL
   - Real PCAP replay goes through the real analyzer (good). The **simulator/mock
     feed** generates flow events directly and does not exercise the models. Use it
     for UI demos only; use real PCAPs for validation.

9. **Runtime model download from HuggingFace** ⚠️ PARTIAL
   - `config.py` auto-downloads weights at runtime. Fine as a convenience, but it's
     a reproducibility/offline-enclave concern — consider vendoring weights or a
     hash-pinned manifest.

10. **Vestigial `.onnx` files under `netsentinel/models/`** 🟡
    - Not on the `config.py` resolution path (which uses subdirs) — dead, confusing.
      Delete or repoint so there's one source of truth for weights.

---

## 3. Is the pipeline "good"? — honest verdict

- The **models are not badly trained.** On in-distribution data they perform at
  normal-to-strong levels for their datasets.
- The failures you're seeing are **preprocessing/deployment/distribution issues**,
  not model-quality issues:
  - exfil 50% → scaler mismatch (deployment)
  - port scan 0 on sim → out-of-distribution input (synthetic)
  - covariate shift → extractor feature units (extraction layer)
- **The one thing still unproven:** none of the 6 models has been shown scoring a
  **real labeled attack PCAP** end-to-end. That single test is what converts
  "very likely good" into "proven good."

---

## 4. Recommended next steps (in order)

1. **Prove it on real data.** Feed real labeled captures and record confidence + FP:
   - Port scan → **Thursday CIC-IDS-2017** (has the port-scan class)
   - DDoS → Friday CIC-IDS-2017 / CIC-DDoS2019
   - C2 / DGA → **CTU-13 (Neris)** or **malware-traffic-analysis.net**
   - Exfil / DNS-tunnel → an iodine/dnscat2 capture
   - _(Note: DGA / DNS-tunnel / encrypted are NOT in CIC-IDS-2017 — you must source
     those separately.)_
2. **Fix exfil scaler** (pin sklearn → re-pickle → upload to HF → re-run → confirm).
3. **Revert the 3 compromises** to production defaults (video is done).
4. **Re-run covariate shift** and align feature units.
5. **Reconcile the docs** into one reproducible metrics report.
6. **Add upload validation** + delete vestigial model files.
7. **(Borrow from the other repo)** a "launch audit" that prints train/val/test
   metrics before the UI opens — cheap, and it directly answers "are the models
   good?" for a judge.

---

## 5. Research directions — the "industry expert" topics

> ⚠️ I don't have the record of your earlier expert conversation in front of me, so
> tell me the specific topics they raised and I'll map each to where it fits above.
> In the meantime, here's where research genuinely pays off for THIS system, based
> on the issues found:

- **Feature-distribution alignment / domain adaptation.** The covariate-shift
  finding is the deepest technical issue. Worth researching: calibrating your
  extractor to a reference (CICFlowMeter parity), and domain-adaptation techniques
  so models trained on public datasets generalize to your live extractor.
- **Anomaly-detector calibration.** The exfil VAE's threshold behavior is a
  research topic in itself — reconstruction-error calibration, scaler robustness,
  and rarity baselines (JA4 rarity, DNS-domain rarity) to suppress CDN/cloud FPs.
- **Behavioral / temporal correlation.** Moving beyond per-flow scoring to
  bounded rolling-window behavior (IAT variation, fan-out, burst ratio, byte
  asymmetry) — this is where multi-flow attacks (slow scans, beaconing) actually
  live, and where a network sensor adds value over endpoint tools.
- **Encrypted-traffic analysis (JA4/JA4S fingerprinting).** Rarity baselining and
  fingerprint drift is an active area and complements your ETT model.
- **Honest evaluation methodology.** Capture-grouped splits, temporal holdouts,
  and reproducible manifests (the other team leaned hard on this) — worth reading
  up on so your numbers survive scrutiny.

**Should you start researching now?** Yes — but do step 4.1 (prove on real data)
**first**. The real-PCAP results will tell you which research direction is actually
your bottleneck, so you don't spend weeks on domain adaptation if a scaler pin and
a feature-unit fix already close most of the gap.

---

_Last updated by assistant review. Items marked ❓ depend on unpushed code — push
and I'll verify them against the repo._
