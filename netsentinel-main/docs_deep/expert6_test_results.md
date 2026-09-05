# Expert 6: Data Exfiltration — Test Results

> **61/61 PASSED** | 0 Failed | 0 Skipped

---

## Model Overview

| Property | Value |
|---|---|
| Model | Expert 6: Data Exfiltration |
| Type | Unsupervised VAE (vae_recon) |
| Dataset | CIC-Bell-DNS-EXF-2021 |
| Features | 24 |
| Architecture | VAE encoder-decoder with reconstruction error scoring |

---

## Kaggle Training Metrics

| Metric | Score |
|---|---|
| **ROC-AUC** | 0.7801 |
| **PR-AUC** | 0.8330 |
| **Best F1** | 0.8906 |
| **Accuracy** | 0.8171 |

### Scorer Comparison (training selection set)

| Scorer | AUC |
|---|---|
| `vae_recon` | 0.7808 ← **selected** |
| `vae_latent` | 0.7405 |
| `inp_maha` | 0.7240 |
| `fusion` | 0.6464 |
| `iso` | 0.5205 |

---

## Test Results by Category

### T1–T4: Infrastructure Tests ✅

| Test | Result |
|---|---|
| Artifact integrity (7 files) | ✅ All present |
| Metadata schema (12 keys) | ✅ Valid |
| ONNX I/O shapes (24-dim) | ✅ Correct |
| Scaler + IsoForest pipeline | ✅ Functional |

---

### T5–T6: Easy Tests ✅

**Obvious Exfiltration** — all 8 patterns detected (mean score +5.4 vs benign +1.2)

**Obvious Benign** — 20 real-world domains clustered tightly (std=0.156)

| Domain | Score |
|---|---|
| `www.google.com` | +1.15 |
| `www.facebook.com` | +1.32 |
| `github.com` | +1.02 |
| `stackoverflow.com` | +1.45 |

---

### T7: Industrial CIC-Bell Replay Simulation ✅

> [!IMPORTANT]
> **100% True Positive Rate** on 50 synthetic exfil + 50 benign domains

| Metric | Value |
|---|---|
| TP | 50 |
| FP | 5 |
| TN | 45 |
| FN | 0 |
| **TPR** | **100.00%** |
| FPR | 10.00% |
| **Precision** | **90.91%** |
| **F1** | **0.9524** |

---

### T8: MITRE ATT&CK T1071.004 — DNS Tunneling Tools ✅

> [!TIP]
> **13/13 (100%) detection** across all 5 C2 frameworks

| Tool | Detected | Score Range |
|---|---|---|
| **iodine** | 3/3 (100%) | +6.52 – +6.53 |
| **dnscat2** | 3/3 (100%) | +4.63 – +5.21 |
| **dns2tcp** | 2/2 (100%) | +9.52 – +9.76 |
| **Cobalt Strike** | 3/3 (100%) | +2.15 – +3.49 |
| **Sliver C2** | 2/2 (100%) | +4.57 – +5.87 |

---

### T9: DGA-style Exfiltration ✅

| Metric | Value |
|---|---|
| Total DGA domains | 30 |
| Detected | 26/30 |
| **Detection Rate** | **87%** |

---

### T10: Low-and-Slow Exfiltration ✅

> [!NOTE]
> These are intentionally stealthy patterns that mimic CDN/API traffic with subtle encoded payloads

| Metric | Value |
|---|---|
| Total domains | 10 |
| Detected | 10/10 |
| **Detection Rate** | **100%** |

---

### T11: Edge Cases ✅

All 12 edge cases handled without crashes:

| Case | Score | Status |
|---|---|---|
| Empty string | +0.54 | ✅ |
| Single char | +0.39 | ✅ |
| Single dot | +0.13 | ✅ |
| Dots only | +0.19 | ✅ |
| Max length (253) | +15.14 | ✅ |
| All digits | +1.40 | ✅ |
| All uppercase | +1.85 | ✅ |
| Unicode/IDN | +1.86 | ✅ |
| Special chars | +1.58 | ✅ |
| IP-like | +0.71 | ✅ |
| localhost | +0.75 | ✅ |
| Very short (t.co) | +0.47 | ✅ |

---

### T12: Adversarial Evasion Resistance ✅

> [!IMPORTANT]
> **6/6 (100%) evasion attempts detected**

| Evasion Technique | Score | Status |
|---|---|---|
| Padding with real words + hex payload | +4.68 | DETECTED |
| Base64 payload under `google.com` | +2.22 | DETECTED |
| Payload mixed into banking subdomain | +4.24 | DETECTED |
| Punycode-disguised payload | +2.67 | DETECTED |
| Split payload across short labels | +2.64 | DETECTED |
| Legitimate-looking + subtle hex suffix | +4.17 | DETECTED |

---

### T13: Determinism ✅

3/3 identical results on repeated inference — zero drift.

---

### T14: Latency ✅

| Metric | Value |
|---|---|
| **Single P50** | **0.037 ms** |
| Single P95 | 0.082 ms |
| Single P99 | 0.411 ms |
| Batch-16 | 0.059 ms (0.004 ms/item) |
| Batch-64 | 0.119 ms (0.002 ms/item) |
| Batch-256 | 0.351 ms (0.001 ms/item) |

> [!TIP]
> At 0.037ms per inference, this model can process **~27,000 DNS queries/second** on a single CPU thread.

---

### T15: Batch Stress ✅

All batch sizes processed correctly: 1, 16, 128, 512, 1024

---

### T16: Synthetic Score Distribution ✅

| Metric | Value |
|---|---|
| Benign mean ± std | 1.47 ± 0.10 |
| Exfil mean ± std | 4.96 ± 1.77 |
| **Synthetic ROC-AUC** | **1.0000** |
| **Synthetic Best F1** | **1.0000** |
| Optimal threshold | 1.68 |

---

## Summary Statistics

| Category | Score |
|---|---|
| **Infrastructure** | 61/61 ✅ |
| **Industrial Sim F1** | 0.9524 |
| **MITRE DNS Tunnel** | 100% (13/13) |
| **DGA-Exfil** | 87% (26/30) |
| **Slow-Drip** | 100% (10/10) |
| **Adversarial Evasion Resist** | 100% (6/6) |
| **Synthetic AUC** | 1.0000 |
| **Latency (P50)** | 0.037 ms |
| **Throughput** | ~27K queries/sec |

> [!NOTE]
> Test file: [`test_expert6_exfil.py`](file:///d:/1_sih26/netsentinel/test_expert6_exfil.py)
