# NetSentinel Tier 2 — Audit

**Audit date:** 16 September 2026 · **revised 17 September 2026**
**Scope:** the Inspector–Sentry cascade (Tier 2) and its sensor path.
**Out of scope:** Tier 1 (the six ONNX experts), the frontend, the API layer.

**Two parts.**
**Part A** audits the sensor and its cryptographic handling: what is captured,
what is decrypted, what is retained, under what basis, and what the residual
risks are.
**Part B** audits every claim the project makes against the evidence file that
backs it, and registers the assumptions that are *not* evidence.

**Verification method.** Every figure in this document was re-derived from the
source `.json` produced by the named script, programmatically, on the audit
date. Every test suite was re-executed. Code behaviour claims were verified by
reading the cited line, not from documentation. Items that could not be
verified are marked **UNVERIFIED** with the reason, and are not presented as
passing.

**Verification result: 48 numeric claims re-derived, 0 mismatches. 7 test
suites re-run, 7 passing, 148 individual checks.** Six findings are raised in
§A8, of which two are Medium.

**The 17 September revision.** Re-running one script twice showed it did not
agree with itself. The cause — set iteration order making every synthetic result
irreproducible — is written up in full in **§B7**, together with what it changed
(little) and what it did not (nothing on real data). Three consequences run
through this revision: the confirmation threshold is swept and **G3 closes**
(§B2.9); wall-clock throughput is reported as an ordering and a range rather
than as constants (§B2.4); and a router *ranking* that three seeds had invented
is withdrawn at eight seeds (§B2.2, claim 14b). Two new gaps are opened, **G8**
and **G9**.

**Re-running this audit is one command:** `python verify_all.py`. It executes
every suite, re-derives every figure below from its source `.json`, checks that
no withdrawn claim has returned, and exits non-zero if anything fails.

---

# PART A — Sensor and cryptography

## A1. Data classification

| | |
|---|---|
| Data captured | Network packets on a mirrored egress link |
| Subjects | 6 laptops, team members, own equipment |
| Sensitivity | **Contains application payload.** See A6/F1 |
| Deployment model | Passive. Read-only TAP/SPAN behind a one-way data diode |
| Never performed | TLS interception · MITM · active scanning · endpoint agents · inline blocking |

The system is **detection-only**. It emits alerts; it takes no action on
traffic, and it is architecturally incapable of doing so — the diode makes the
return path physically absent.

## A2. What the sensor captures

`capture_service.ps1:146-152` — the exact `dumpcap` invocation:

```
-i <interface>
-w ns.pcap
-b duration:<3600>        rotate hourly
-b files:<312>            ring buffer, oldest overwritten
-b filesize:<131000>      KB
-s 0                      snaplen 0 = WHOLE PACKETS
```

`-s 0` is the material setting. It means **no per-packet truncation**: the full
frame, headers and payload, is written to disk.

**Why whole packets, evidenced.** `capture_probe.json`, 2 files, 173,682
packets:

| snaplen | ClientHellos captured whole |
|---|---|
| 160 | 0.0% |
| 512 | 16.7% |
| 1024 | 53.5% |
| 1500 | 53.5% |
| 2048 | 95.6% |
| 4096 | 100.0% |

QUIC is stricter: RFC 9000 requires a client Initial padded to ≥1,200 bytes.
At snaplen 512, **0 of 805** QUIC Initials were readable. Without the hostname,
every QUIC flow collapses into `Unknown_External` and the detector has no
service categories to work with.

The flatline between 1024 and 1500 is the ethernet MTU: **46.5% of ClientHellos
(159 of 342) span multiple TCP segments**, which no snaplen can fix — that is
TCP reassembly, performed by Zeek.

## A3. What the QUIC processing accesses — precise statement

This is the section most likely to be challenged, so it is stated at line
granularity. All references are `netsentinel_v2/quic.py`.

**A3.1 What is rejected before any cryptographic operation**

| packet class | line | disposition |
|---|---|---|
| Short-header packets (**all application data**) | `:167` `if not (first & 0x80): return None` | Rejected. Never decrypted, never parsed |
| Non-QUIC UDP (fixed bit clear) | `:169` | Rejected |
| Version negotiation | `:173` | Reported, not decrypted |
| Unsupported versions | `:176` | Reported by version number, **not guessed** |
| Long-header packets that are not Initial | `:184` | Reported as `not_initial` |

**Application data in QUIC travels in 1-RTT short-header packets. Those are
rejected at line 167, before a key is derived.**

**A3.2 What is decrypted**

Only **client Initial** packets. A QUIC Initial exists solely to carry the TLS
ClientHello; at that point in the connection no application data has been
exchanged.

The decryption is necessarily **whole-packet**: AES-GCM is an AEAD and cannot
be partially opened (`:214`). So the honest statement is *not* "we decrypt only
the SNI" — it is:

> The Initial packet is decrypted in full. The Initial packet contains only
> connection-setup handshake bytes. From those, only the server name and the
> presence of an Encrypted ClientHello extension are retained.

Server Initial packets fail to decrypt under client keys and are **reported as
failures, not inferred** (`:154-162` docstring, `:217` exception path).

**A3.3 What is retained**

`_parse_client_hello_sni` (`:116-152`) walks the ClientHello extension list and
reads exactly two extension types:

| extension | id | retained |
|---|---|---|
| `server_name` | `0x0000` | the hostname string |
| `encrypted_client_hello` | `0xFE0D` | a boolean: present / absent |

Every other extension is skipped by length (`:148 off += elen`). The function's
entire return value is `(sni, ech_present)`.

`parse_quic_initial` returns `{sni, ech, version, dcid, ok, reason}` — no
ciphersuites, no ALPN, no key shares, no certificates, no session tickets, and
no application bytes, because none exist in an Initial.

**A3.4 Side effects**

`netsentinel_v2/quic.py` performs **no file I/O, no network I/O, no subprocess
execution**. Verified by search: no `open(`, `socket`, `requests`, `urllib`,
`subprocess`, or `os.` calls anywhere in the module. It is a pure function over
a `bytes` object.

## A4. Basis for the QUIC handling

| | |
|---|---|
| Standard | RFC 9001 §5.2, *Using TLS to Secure QUIC* — **Initial Secrets** |
| Key material | `initial_salt = 38762cf7f55934b34d179ae6a4c80cadccbb7f0a`, **published in the RFC itself** |
| Second input | The client's Destination Connection ID, transmitted **in cleartext** in the packet header |
| Derivation | `HKDF-Extract(salt, DCID)` → `HKDF-Expand-Label` → key, iv, hp |

**Both inputs are public by design.** The QUIC specification makes Initial
packets readable by any on-path observer; header protection and Initial
encryption exist to prevent middlebox ossification, not to provide
confidentiality. RFC 9001 §5.2 states this explicitly.

This is therefore **not decryption of protected content, and not interception**.
It reads a handshake that the protocol publishes the keys for. It requires no
private key, no certificate, no compromise of any endpoint, and no interaction
with the connection.

**Functional equivalence.** For TLS-over-TCP the same hostname is available in
plaintext in the ClientHello and is read by Zeek without any cryptography. The
QUIC path exists to give equivalent visibility for a transport that wraps the
same field. It does not extend visibility beyond what TLS already gives.

**Where visibility legitimately ends.** Encrypted ClientHello (`0xFE0D`) hides
the SNI. The system records ECH presence (32 instances measured) and the flow
falls to `Unknown_External`. **There is no attempt to defeat ECH**, and that
loss of visibility is treated as a signal rather than a failure.

## A5. Verification evidence

`test_quic.py`, re-executed on the audit date: **16 of 16 checks pass.**

Six checks validate the key schedule against **RFC 9001 Appendix A.1's own
published test vectors** — the RFC supplies a worked example with a known DCID
(`8394c8f03e515708`) and the expected derived values:

```
ok  initial_salt is the published v1 salt
ok  initial_secret  = HKDF-Extract(salt, dcid)
ok  client_initial_secret
ok  client key (AES-128-GCM)
ok  client iv
ok  client header-protection key
```

Five validate variable-length integer decoding. **Five are negative controls**,
confirming the parser fails safe rather than fabricating:

```
ok  short-header packet is not treated as Initial
ok  empty payload returns None
ok  version 0 is reported as version negotiation
ok  unknown version is reported, not guessed
ok  a truncated Initial says so rather than returning a hostname
```

The last is material: a packet cut short by snaplen returns
`reason: "truncated_by_snaplen"`, **not** a partial or guessed hostname.

## A6. What is written to disk, and retention

| artefact | contents | retention |
|---|---|---|
| `D:\capture\ns_*.pcap` | **Raw frames including application payload** | Ring buffer: 312 files × ~131 MB ≈ **13 days**, then overwritten by dumpcap |
| Zeek logs | Connection metadata, TLS SNI, DNS queries | Derived; no payload |
| Edge tensor | Numeric features per (host, day, hour, category) | Derived; **no hostnames, no addresses** |
| `capture_probe.json` | Sensor diagnostics **plus the 25 most-contacted hostnames** | Indefinite — see **F2** |

**The edge tensor is the model's only input.** By the time data reaches the
Inspector or Sentry it is 10 floating-point numbers per (host, hour, service
category). No hostname, no IP address, no payload, and no packet survives into
the model layer. Both models are structurally incapable of accessing content.

`capture_service.ps1:157` emits a warning at every service start:
`"raw files now contain payload -- keep this directory local and private"`.

## A7. Third-party dependencies

| package | version audited | role | criticality |
|---|---|---|---|
| `cryptography` | 46.0.7 | HKDF, AES-ECB (header protection), AES-GCM (Initial) | **Sensor only.** Not used by either model |
| `torch` | 2.14.0 | Inspector, Sentry | Model layer |
| `numpy` | 2.4.4 | Tensors throughout | Core |
| `scipy` | 1.17.1 | Feature statistics | Feature layer |
| `scikit-learn` | 1.8.0 | Ledoit-Wolf shrinkage (router B only — rejected router) | Optional |
| `matplotlib` | 3.10.9 | Charts | Reporting only |

**`cryptography` is imported by exactly one file** (`netsentinel_v2/quic.py`,
lines 45–48) and that file is used by exactly two callers (`capture_probe.py`,
`test_quic.py`). Verified by repository-wide search. It has **no reachable path
into the Inspector, the Sentry, the lifecycle, or the alerting layer.**

An auditor removing `cryptography` entirely would lose QUIC hostname naming and
nothing else. The import is guarded (`capture_probe.py:245`) so the system
degrades rather than crashes.

No version pinning is declared in `requirements.txt` — see **F5**.

## A8. Findings

| # | Severity | Finding |
|---|---|---|
| **F1** | **Medium** | Raw captures contain full application payload |
| **F2** | **Medium** | Diagnostic output retains identifiable browsing data |
| **F3** | **Medium** | Subject notice/consent record not evidenced |
| **F4** | Low | Repository exclusion of capture artefacts unverified |
| **F5** | Low | Dependencies unpinned |
| **F6** | Info | Optional-import degradation is silent by class |

---

**F1 — Raw captures contain full application payload. (Medium)**

`-s 0` writes complete frames. Any unencrypted traffic on the monitored link is
recorded verbatim for up to 13 days.

*Justification for the setting:* documented and measured (§A2) — no smaller
snaplen yields QUIC hostnames, and the alternative is losing service naming on
the majority of encrypted traffic.

*Current controls:* a start-up warning; an instruction to keep the directory
local; a 13-day ring that overwrites automatically.

*Gap:* the controls are advisory. No filesystem ACL, no encryption at rest, and
no automated exclusion were verified.

*Recommended:* restrict `D:\capture` by ACL to the capture service account;
document that the pcap ring is the sensitive artefact and the Zeek/tensor
outputs are not; consider a payload-stripping post-process once Zeek has
extracted metadata, so the payload-bearing window is hours rather than days.

---

**F2 — Diagnostic output retains identifiable browsing data. (Medium)**

`capture_probe.py:421` writes `"top_named": allnames.most_common(25)` into
`capture_probe.json`.

*Evidence:* the current file contains, among others,
`daily-cloudcode-pa.googleapis.com` (77), `hnid-dra.platform.hihonorcloud.com`
(30), `catalog.gamepass.com` (12), `login.live.com` (8). These identify
individual services, devices and consumer accounts belonging to the six capture
subjects.

*Why it matters:* this is a small, portable, human-readable file that is
committed alongside code and quoted in documentation — a materially different
exposure profile to a 40 GB local ring buffer.

*Recommended:* either drop `top_named` from the JSON and keep it in stdout
only, or reduce it to registrable-domain granularity, or gate it behind an
explicit `--include-names` flag that is off by default.

---

**F3 — Subject notice/consent record not evidenced. (Medium)**

Six individuals' complete network traffic, payload included, is captured. No
notice, consent record, or data-handling agreement was located in the audited
material.

*Status:* **UNVERIFIED** — absence of evidence in the repository, not evidence
of absence. The subjects are the project team and may well have agreed
verbally.

*Recommended:* record it in writing, naming what is captured, retention, who
can access it, and how to request deletion. For a defence-sector submission the
absence of this record is a foreseeable question.

---

**F4 — Repository exclusion of capture artefacts unverified. (Low)**

`.gitignore` coverage of `*.pcap` and `capture_probe.json` could not be checked:
**the device was offline at audit time.** Given F1 and F2, both should be
excluded.

*Status:* **UNVERIFIED.** Re-check before submission.

---

**F5 — Dependencies unpinned. (Low)**

`requirements.txt` names packages without version constraints. `cryptography`
performs security-relevant operations; an unpinned install makes the verified
configuration unreproducible.

*Versions audited:* listed in §A7.

*Recommended:* pin with `==`, or at minimum `>=` a floor, for `cryptography`
and `torch`.

---

**F6 — Optional-import degradation is silent by class. (Info)**

`cryptography` is imported inside a `try` at `capture_probe.py:245` so the probe
runs without it. Correct behaviour, but it is a pattern in which a missing
dependency produces a **plausible-looking wrong answer** rather than an error.

*Current state:* the QUIC packet counter is independent of the decryptor, and
an unavailable decryptor prints a four-line banner plus a named failure reason.
Verified by reading the current code path.

*Recommended:* apply the same discipline to any future optional dependency —
count first, decode second, and make the unavailable path state itself.

## A9. What an auditor can re-run

```bash
python test_quic.py          # 16/16 vs RFC 9001 Appendix A.1 vectors
python capture_probe.py <file.pcap> ...   # sensor visibility, from the pcaps
grep -rn "from cryptography" --include=*.py .   # 4 lines, all in quic.py
grep -n "if not (first & 0x80)" netsentinel_v2/quic.py   # the rejection line
```

`capture_probe.py --limit N` sorts filenames alphabetically and takes the last
N. The capture ring has restarted its numbering, so old high-numbered files
sort after new low-numbered ones. **Name files explicitly** or the probe
reports a different era than intended.

---

# PART B — Claims versus evidence

## B1. Method and status definitions

| status | meaning |
|---|---|
| **VERIFIED** | Re-derived from the named `.json` on the audit date. Value matched |
| **VERIFIED (BOUNDED)** | Value confirmed, but only valid inside a stated condition |
| **ASSUMPTION** | A chosen parameter, not a measurement. Labelled as such in code |
| **UNVERIFIED** | Could not be checked in this audit. Reason given |
| **WITHDRAWN** | Must not be claimed. Superseding evidence named |

**What the `±` in every table is.** Every seeded figure in this project was
produced by `np.std(...)` — the **population** standard deviation across seeds,
not a confidence interval. At n = 3 that is 0.816 × the unbiased (sample)
standard deviation, and a genuine 95% interval is **2.48 × the sample sd**,
roughly three times the number printed. The convention is left unchanged so
that every table agrees with every script; `ci_report.py` re-derives the
intervals and `ci_report.json` records them. Two consequences worth carrying:
within-host AUC **0.557** has a 95% interval of **[0.517, 0.597]** — its lower
bound is 0.017 from chance — and the three synthetic router intervals
(**A [0.794, 0.873], B [0.778, 0.830], C [0.804, 0.873]**, 8 seeds) sit on top
of one another, which is why B2.2 reports no ranking.

## B2. Claims register

### B2.1 Detection performance

| # | Claim | Source | Status |
|---|---|---|---|
| 1 | Router A agreement with teacher, AUC **0.992 ± 0.003** | `lanl_novelty.json`, 3 seeds | **VERIFIED** |
| 2 | Router B AUC **0.634 ± 0.007** | `lanl_novelty.json` | **VERIFIED** |
| 3 | Inspector pooled AUC **0.745 ± 0.002** | `lanl_novelty.json` | **VERIFIED (BOUNDED)** — confounded; must carry claim 6 |
| 4 | Inspector within-host AUC **0.557 ± 0.013** | `lanl_novelty.json` | **VERIFIED** |
| 5 | Inspector flag rate **2.56%** | `lanl_novelty.json` | **VERIFIED** |
| 6 | Under per-host scoring, pooled falls **0.745 → 0.618 ± 0.021**; day-level **0.639 → 0.487**; within-host unmoved (**+0.003**) | `lanl_novelty_hn.json` | **VERIFIED** |
| 7 | Attacked hosts are busier: live-window density **0.811 vs 0.530** | `lanl_novelty.json` | **VERIFIED** |
| 8 | At 5% budget the router recovers **96.9%** of the Inspector's flags | `lanl_novelty.json` | **VERIFIED** |
| 9 | At 5% budget, attack recall is **35.6%** | `lanl_novelty.json` | **VERIFIED** |
| 10 | kNN geometry overlap@20 = **0.439** | `lanl_novelty.json` | **VERIFIED** |

**Audit note on claims 8 and 9.** These are different quantities and the
register records them separately by design. 96.9% is routing fidelity against
the teacher; 35.6% is recall against ground truth. Any statement of "96.9%
recall" without the qualifier "of the Inspector's flags" is a
**misrepresentation** of claim 8.

**Audit note on claim 3.** The pooled figure is verified as a computation and
is simultaneously known to be confounded (claims 6, 7). It is retained in the
register because it appears in prior material; it must not be presented as a
detection result without claim 6 attached.

### B2.2 Does the architecture earn its parameters?

| # | Claim | Source | Status |
|---|---|---|---|
| 11 | On LANL, the Inspector **does not separate** from a ~0-parameter per-host Mahalanobis: 36–40–1 paired over 77 hosts, mean diff −0.036, **sign test p = 0.731** | `lanl_p0b.json` | **VERIFIED** |
| 12 | bag-Mahalanobis within-host **0.578 ± 0.273**; Inspector (same checkpoint) **0.542 ± 0.310** | `lanl_p0b.json` | **VERIFIED** |
| 13 | On synthetic data containing the chain, powered at n=149: **70–79, p = 0.51**; mean +0.026, **median −0.006** | `paired_synth.json` | **VERIFIED** |
| 14 | No combination of the two beats both parents. Six methods span **0.542–0.578** | `lanl_ensemble.json` | **VERIFIED** |
| 14b | On synthetic data the three routers are **not separable at 8 seeds**: A 0.833 ± 0.044, C 0.839 ± 0.039, B 0.804 ± 0.029; paired Wilcoxon p = 0.74 / 0.20 / 0.15 | `results_8seed.json` | **VERIFIED** |

**Audit note.** Claims 11–14 are adverse to the project and are recorded at the
same standard as the favourable ones. Claim 13's mean-positive /
median-negative split supports the narrower statement that the Inspector's
advantage is *concentrated on a minority of hosts*; it does not support a
general accuracy claim.

**Audit note on claim 14b — a ranking that three seeds invented.** A 3-seed run
gave A 0.876, C 0.850, B 0.818 and was written into six documents as an ordered
result. At 8 seeds no pair separates and router A alone spans **0.735 to 0.885**
across seeds — its own spread is an order of magnitude larger than the gaps it
was ranked by. The ranking is withdrawn. **The recommendation to build A is not
withdrawn**, but its basis moves from the synthetic comparison to the LANL one,
where the gap is not marginal: 0.992 against 0.634 agreement and 35.6% against
3.3% attack recall at a 5% budget, plus A being the only candidate that needs
neither a second head nor a per-host covariance estimate.

A related correction: `diagnostics.verdict()` asserted that router B carried
"~7× the seed variance of the learned heads". That was true of one 3-seed run;
at 8 seeds B has the **lowest** spread of the three (0.029 vs 0.044 and 0.039).
The sentence has been removed from the function, which measures the kNN overlap
and nothing else and now says only what the overlap supports.

### B2.3 Ablations

| # | Claim | Source | Status |
|---|---|---|---|
| 15 | Model is **order-blind**: full 0.998, hours shuffled 0.998, **difference 0.000** | `ablation_order_hard.json` | **VERIFIED** |
| 16 | An order-free bag-of-categories scores **1.000** — better than the model | `ablation_order_hard.json` | **VERIFIED** |
| 17 | Losing reverse-direction features costs **0.002** AUC (0.998 → 0.996) | `ablation_order_hard.json` | **VERIFIED** |
| 18 | Markov-transitions-only collapses to **0.444** | `ablation_order_hard.json` | **VERIFIED** |
| 19 | Without hard negatives one trivial rule scores **1.000**; with them, **0.797** | `synth.py` construction | **VERIFIED** |

Claim 17 is the evidential basis for the diode proposition: unidirectional
visibility is nearly free.

### B2.4 Throughput, cost, capacity

| # | Claim | Source | Status |
|---|---|---|---|
| 20 | Ordering of the three stages: cohort ≫ Sentry ≫ Inspector, all on one CPU core | `escalate.json` | **VERIFIED** — the ordering, not the absolute rates. See B-note below |
| 21 | Sentry is **7.5–8.6×** faster | `escalate.json` | **VERIFIED (BOUNDED)** — **CPU-to-CPU only**, and the ratio itself moves with machine load. See both notes |
| 22 | Compression **13.7×** | `results.json` | **VERIFIED** — this is a **parameter ratio, not a speed claim** |
| 23 | A 5% *window* budget re-runs the Inspector on **~48% of host-days** (9.7×) | `escalate.json` | **VERIFIED (BOUNDED)** — synthetic, 200 hosts; 49.4% and 48.4% on two runs |
| 24 | Budgeting in host-days removes the scatter: **7.5% against a 10% budget** | `test_tiers.py` | **VERIFIED** |
| 25 | Confirmation precision at 3σ = **12.7%** | `escalate.json` | **VERIFIED** |
| 26 | Inspecting everything at 100k hosts with a 200M-param teacher ≈ **$150/yr** | `gpu_cost.py` | **ASSUMPTION-DEPENDENT** — see B3.1 |

**Audit note on claim 20 (B-note) — these are not stable numbers.** Two runs of
`escalate.py` on the same container returned **70,950** and **104,385**
Inspector windows/s, a 47% swing, and the Sentry:Inspector ratio moved **8.59 →
7.54** with it. `timeit` already takes best-of-3; best-of-3 does not remove
contention when every core is busy. Nothing about the models changed between
those runs. Consequently **no absolute throughput figure in this project should
be quoted as a property of the system**, and the ratio should be given as a
range. `escalate.py` now times a fixed 512×512 matmul alongside the models and
writes it to `escalate.json` as `machine_reference`, so a reader can tell a
quiet machine from a busy one; `verify_all.py` asserts the stage *ordering* and
a 5–12× band rather than an equality, because an equality here would fail for
reasons that have nothing to do with the code.

**Audit note on claim 21.** The measurement is valid and the inference commonly
drawn from it is not. The Inspector is a Transformer that parallelises across
all 24 windows; the Sentry is a **unidirectional GRU — 24 sequential dependent
steps that a GPU cannot parallelise.** The 8.6× therefore **does not transfer
to GPU** and may invert. Any GPU-context use of this figure is unsupported.
Flagged in `gpu_cost.py:36-49` and in the module's runtime banner.

### B2.5 Deployment architecture

| # | Claim | Source | Status |
|---|---|---|---|
| 27 | The Sentry is **causal** — hours 0..t equal the full day's slice at t, max drift **4×10⁻⁶** | `test_tiers.py` | **VERIFIED** |
| 28 | The Inspector is **not causal** — partial day moves output by **0.032** | `test_tiers.py` | **VERIFIED** |
| 29 | The Inspector requires cohort — blanking it moves output by **0.410** | `test_tiers.py` | **VERIFIED** |
| 30 | The Sentry takes no cohort input | `models.py:104` | **VERIFIED** by inspection |
| 31 | At `audit_rate = 1.0`, every host-day is inspected (equivalent to full inspection) | `test_tiers.py` | **VERIFIED** — 40/40 |
| 32 | Audit draws are independent of score | `test_tiers.py`, `tiers.py:229` | **VERIFIED** |
| 33 | Mixed-fleet Inspector load **10.8%** — 51.4% audit, 44.5% router, 4.0% churn | `deploy_c.json` | **VERIFIED (BOUNDED)** — see B3.4 |
| 34 | Sentry peak at hour **17** median vs Inspector's earliest hour 24 | `deploy_c.json` | **VERIFIED (BOUNDED)** — untrained models |

Claims 27–30 are the load-bearing evidence for the edge/central split. They are
properties of the model architectures, established numerically rather than
argued.

### B2.6 Transfer and stability

| # | Claim | Source | Status |
|---|---|---|---|
| 35 | Mechanism transfers: Inspector AUC **0.873** (world A) → **0.852** (world B) | `shift_results.json` | **VERIFIED (BOUNDED)** — synthetic worlds |
| 36 | Threshold does **not** transfer: ratio **1.14**; and gives 6.7% in world A's *own* test period | `shift_results.json` | **VERIFIED** |
| 37 | Unguarded rolling recalibration is poisonable; the guarded policy holds | `test_calibration.py` | **VERIFIED** — re-run, passes |

Claim 36 is the evidential basis for requiring per-deployment calibration.

### B2.7 Sensor

| # | Claim | Source | Status |
|---|---|---|---|
| 38 | **0%** truncation at snaplen 0, over 173,682 packets | `capture_probe.json` | **VERIFIED** |
| 39 | TLS hostname recovery **90.1%** (308/342) | `capture_probe.json` | **VERIFIED** |
| 40 | **46.5%** of ClientHellos span TCP segments (159/342) | `capture_probe.json` | **VERIFIED** |
| 41 | 0 of 805 QUIC Initials readable at snaplen 512 | `capture_probe.json` (prior run) | **VERIFIED** |
| 42 | 1,002 plaintext DNS queries, 65 distinct names, 0 DoH connections | `capture_probe.json` | **VERIFIED** |
| 43 | QUIC key schedule matches RFC 9001 Appendix A.1 | `test_quic.py` | **VERIFIED** — 16/16 |

### B2.8 Attribution

| # | Claim | Status |
|---|---|---|
| 44 | The Inspector architecture is **GraphIDS-shaped, arXiv:2509.16625 — prior art, not ours** | **VERIFIED** as disclosed in `models.py:1-11` |
| 45 | The cascade, knowledge distillation and per-entity baselining are **established prior art** | **VERIFIED** as disclosed |
| 46 | Only novelty claimed: cross-service category semantics + the chain dataset | **UNVERIFIED** — rests on a 91-study review not re-checked in this audit |

**Audit note on claim 46.** The novelty claim is the narrowest in the project
and is correctly scoped, but the literature review behind it was not
independently re-verified here. It should not be strengthened.

### B2.9 Confirmation threshold — G3, closed 17 September

`sweep_threshold.py`, 3 seeds × 200 hosts × 16 days, 5% **host-day** escalation
budget, pooled across seeds. Two difficulties, both synthetic.

| | stealth 0.9–1.0, hard negatives **on** | stealth 0.3–1.0, hard negatives **off** |
|---|---|---|
| attack host-days escalated | 34 of 221 | 27 of 221 |
| vs random routing | 3.08×, **p < 0.001** | 2.44×, **p < 0.001** |
| precision at 3σ (the shipped setting) | 17.7% | 20.3% |
| precision at best F1 | **40.3%** at 6σ | **45.8%** at 5σ |
| alerts per 1,000 host-days, 3σ → best | 40.0 → **16.0** | 27.7 → **12.3** |
| attack recall cost of that move | 15.4% → 14.0% | 12.2% → 12.2% |

A third run holds hard negatives on and moves stealth to 0.3–1.0: 25 of 221
escalated, 2.26× random, 14.0% precision at 3σ rising to 38.7% at 6σ.

**The finding.** The shipped 3σ cut is too loose at every difficulty tried, and
tightening it buys far more precision than it costs recall. `escalate.py` uses
the harder setting, so the left column is the one comparable to claim 25.

**What these three runs do NOT show.** They are not a stealth ablation. Per G9,
changing `stealth_range` also resamples most of the benign population, so the
differences *between* the columns cannot be attributed to stealth — and note
that the lower-stealth runs came out with *lower* recall, which is the opposite
of what a stealth effect would predict and is the clearest evidence that
something other than stealth is moving. Read them as three independent samples
that agree about the **shape**, which is the only claim being made.

**In the units of B3.2**, at 100,000 hosts, moving 3σ → 6σ takes the cascade
from 90.5 to 36.3 analysts and from **\$7.24M to \$2.90M** a year — a **\$4.34M**
saving — for **1.4 points** of attack recall. That is larger than every compute
figure in B3.1 combined, and it is a single scalar.

**What this is not.** It is not a detection claim, the precision figures are
synthetic, and the currency rests on the two SOC assumptions in B3.2. The
transferable result is the **shape**: precision rises steeply with the cut while
recall stays flat until 5–6σ, so a SOC should choose the loosest threshold whose
volume its analysts can actually absorb, not the max-F1 point.

**A correction this exposed.** `gpu_cost.triage_economics` took
`confirm_precision` alone and held alert volume fixed, so raising the threshold
appeared to improve precision at no cost. The threshold does two things — it
raises precision *and* cuts volume — and it also costs recall. The function now
takes `confirm_rate` and `attack_recall` from the same row of
`sweep_threshold.json`, so the trade is reported in both directions.

**Still open (G8).** Recall tops out at 12–15% in every run because the **5%
escalation budget**, not the threshold, is the binding constraint. No threshold
recovers an attack the router never escalated.

## B3. Assumptions register — parameters that are not evidence

These values are **chosen, not measured**. Every figure derived from them is an
estimate. All are labelled in code; this register consolidates them.

### B3.1 Cost model — `gpu_cost.py`

| parameter | value | line |
|---|---|---|
| GPU speed-up over one CPU core | **40×** | `:65` "ASSUMPTION, NOT MEASURED" |
| GPU cost | $1.80/hr | `:69` |
| vCPU cost | $0.021/hr | `:70` |
| Teacher-scaling model | throughput ∝ 1/params | `:134` "a planning estimate, not a measurement" |

**Consequence:** every currency figure in the cost model — including the $150
and the $135 saving — is an estimate resting on an unbenchmarked GPU multiplier.
The module prints a four-line warning banner before any output. **No GPU
benchmark has been performed.** This is the single largest unverified input in
the project's economic argument.

### B3.2 SOC model — `gpu_cost.py:239-241`

| parameter | value |
|---|---|
| Analyst loaded cost | $80,000/yr |
| Productive hours | 1,600/yr |
| Minutes per alert triage | 12 |

The derived figures (113 analysts, $9.05M, $7.9M wasted at 100k hosts) are
**illustrative**, not measured. The *structural* conclusion they support — that
analyst cost exceeds compute cost by orders of magnitude — is robust to wide
variation in all three, but the specific currency amounts are not evidence.

### B3.3 Policy thresholds — chosen, unvalidated

| source | parameters |
|---|---|
| `lifecycle.py:56` | Promotion gates: 240 live windows · 10 distinct days · weekend required · 200 reference samples · named-flow ratio 0.50 · drift 0.35σ · disagreement 0.20. Docstring: *"a starting setting, not a validated constant"* |
| `tiers.py` | Risk-tier audit rates: 100% / 20% / 5% / 2%. Chosen to span the range, not derived |
| `visibility.py` | Tolerance 0.15, absolute floor 0.25 |
| `escalate.py` | Confirmation threshold 3σ — **known too loose** (claim 25) |

### B3.4 Conditions bounding otherwise-verified figures

| figure | condition |
|---|---|
| All `deploy_c.json` values | **Untrained models.** The file states this. Demonstrates architecture behaviour — who can answer when, what crosses the boundary, what it costs — **not detection performance** |
| The window→host-day scatter (claim 23) | Measured on synthetic data, 200 hosts: 9.9× and 9.7× on two runs. Not confirmed on LANL |
| Throughput (claims 20, 21) | One CPU core, batched inference over pre-built tensors. Excludes Zeek feature extraction, which likely dominates in production. **Also load-dependent** — see the B-note in B2.4 |
| Every synthetic figure produced before 17 Sep 2026 | Generated under a hash-order defect (B7). Re-run after the fix; the pre-fix files are kept in `prefix_hashorder/` |
| ETTE values | `P(detect \| inspected)` is a **parameter**, not measured. Quoted at 0.5 for illustration |
| Shift results (claim 35) | Two *synthetic* worlds, not two real organisations |

## B4. Claims that must not be made

Each is superseded by evidence in this audit.

| must not be said | superseded by |
|---|---|
| "95% recall" / "96.9% recall" unqualified | Claims 8, 9 — different quantities |
| Any Tier 2 detection rate as a product claim | Claims 4, 11, 13 — near chance, ties a trivial baseline |
| "0.745" without the confound | Claims 6, 7 |
| "13.7× faster" | Claim 22 — parameter ratio, not speed |
| "8.6× faster" in a GPU context | Claim 21 audit note |
| "94.7% GPU reduction" | Claim 23 — budget granularity; and B3.1 |
| "We detect the sequence" | Claims 15, 16 — order contributes 0.000 |
| "55% of DNS hidden by DoH" | No denominator exists for hidden queries. `capture_probe.py:381-386` |
| State of the art / novel transformer / replaces EDR | Claims 44, 45 |
| "The Inspector architecture is ours" | Claim 44 |

## B5. Test coverage — re-executed on the audit date

| suite | checks | result | covers |
|---|---|---|---|
| `test_lanl_loader.py` | 53 | **PASS** | Loader correctness, direction resolution, fan-in, labelling |
| `test_contracts.py` | 32 | **PASS** | Feature contract, tensor shapes, model input widths, NaN guard |
| `test_lifecycle.py` | 19 | **PASS** | Visibility gate, state machine, promotion blockers |
| `test_tiers.py` | 17 | **PASS** | Causality, cohort dependence, the audit dial, provenance |
| `test_quic.py` | 16 | **PASS** | RFC 9001 vectors, negative controls |
| `test_calibration.py` | narrative | **PASS** | Poisoning resistance, audit-budget sweep |
| `test_determinism.py` | 11 | **PASS** | Same seed, same bytes, in a fresh process under four different `PYTHONHASHSEED` values (B7); plus a characterisation test pinning G9 |
| **total** | **148** | **7/7 suites passing** | |

**Not covered by any suite:** the trained router head in the deployment path
(`EdgeTier` accepts a scoring callable; the demo supplies a stand-in), the
Zeek→tensor loader against real captures, and end-to-end alerting.

## B6. Open gaps

| # | Gap | Effect | Closes when |
|---|---|---|---|
| G1 | No corpus can test the actual hypothesis | LANL substitutes a port-derived taxonomy and evaluates a proxy task; synthetic data partly teaches its own generator | The snaplen-0 own capture reaches a commissioning/test split |
| G2 | No GPU benchmark | Every currency figure is an estimate (B3.1) | Both models are timed on the target GPU |
| ~~G3~~ | ~~Confirmation threshold untuned~~ | — | **CLOSED 17 Sep** — swept at two difficulties, `sweep_threshold.json` and `sweep_threshold_easy.json`. See B2.9 |
| G8 | The escalation budget, not the threshold, caps recall | At a 5% host-day budget recall tops out at 11–15% on synthetic data whatever the threshold | The budget is swept the same way, on a corpus with real labels |
| G9 | Generator parameters cannot be varied in isolation | `synth.generate` threads one RNG through the population in host order and `_inject_lsa` draws a stealth-dependent count, so changing `stealth_range` also resamples the benign traffic of **34 of 56 benign hosts** (pinned by `test_determinism.py`). Runs at different settings are separate samples, **not an ablation** | Each component gets its own stream: `np.random.SeedSequence(seed).spawn(4)` for topology, benign traffic, habits and injection. Deferred — it changes every synthetic number again |
| G4 | Router head not wired into the deployment path | `deploy_c.json` measures architecture, not detection | A trained checkpoint exists for the own corpus |
| G5 | Policy thresholds unvalidated | B3.3 — presented as starting settings | Tuned against a corpus with real labels |
| G6 | Recall curve not re-measured at host-day granularity | Cost and recall claims describe different regimes | The curve is recomputed under `tiers.py` budgeting |
| G7 | Cohort scope at multi-site scale undecided | Global = data movement + cross-tenant exposure; per-site = distribution shift the visibility gate would flag | A deployment decision is recorded |

---

## B7. Evidence-integrity finding — synthetic results were not reproducible

**Found 17 September 2026. Fixed the same day. Severity: high for evidence,
nil for the product.**

### What was wrong

`categories.ROLE_PREPATH` mapped each host role to a **set** of service
categories. `synth._benign_window` iterates that collection and draws from the
random generator *inside* the loop, so iteration order determined the order in
which random numbers were consumed. Python randomises string hashing per
process, so set iteration order — and therefore the entire synthetic corpus —
changed on every run.

`synth.generate(seed=0)` returned byte-different data in every fresh process.
The seed argument did not control the data it was supposed to control.

### How it stayed hidden

Every property a test would normally check still held. Re-running in the *same*
process reproduced exactly, because one process has one hash seed. All six test
suites passed. The seed-to-seed `±` absorbed the extra variance without
anything looking anomalous, which is the part worth dwelling on: **the error
bars were not wrong, they were measuring something nobody named.**

It surfaced only because `sweep_threshold.py` was run twice with identical
arguments and returned different answers.

### Measured effect

| quantity | run 1 | run 2 | run 3 (after fix) |
|---|---|---|---|
| attack host-days escalated at a 5% budget | 16 | 21 | **34** |
| recall | 7.2% | 9.5% | **15.4%** |
| confirmation precision at 3σ | 8.8% | 12.0% | **17.7%** |
| verdict vs random routing | p = 0.090, **not significant** | p = 0.004 | **p < 0.001** |

The first run would have supported the sentence *"at maximum stealth the router
is indistinguishable from random."* That sentence was never published, and on
the fixed generator it is false.

**What did not move.** Re-running everything after the fix left the load-bearing
findings where they were:

| figure | before | after |
|---|---|---|
| order ablation A (full) | 0.998 | 0.998 |
| order ablation B (order blinded) | 0.998 | 0.998 |
| **A − B**, the basis for withdrawing "we detect the sequence" | 0.000 | **0.000** |
| order-free bag-of-categories | 1.000 | 1.000 |
| host-days inspected at a 5% window budget | 49.4% | 48.4% |
| confirmation precision, `escalate.py` | 12.67% | 12.68% |

**LANL and own-capture results are untouched.** `lanl_loader.py` and
`zeek_loader.py` import only `_edge_row` and `WINDOWS_PER_DAY` from `synth`;
neither touches `ROLE_PREPATH`. Every headline real-data figure — within-host
0.557, pooled 0.745, host-normalised 0.618, router agreement 0.992, the sign
test p = 0.731 — was produced from real data and is unaffected.

### Fix and guard

`ROLE_PREPATH` values are now tuples, with a comment saying why they must stay
that way. `test_determinism.py` runs the generator in subprocesses under four
different `PYTHONHASHSEED` values and compares digests; it was checked against a
deliberately reintroduced set and fails on it (4 of 9 checks). `verify_all.py`
greps for the set literal as well.

### What an auditor should take from this

Three things, none of them comfortable:

1. **A passing test suite did not catch it.** The class of bug — iterate an
   unordered collection, draw randomness inside the loop — is invisible to any
   check that runs in one process.
2. **The fix changed a conclusion.** Not a headline one, but a real one. Any
   synthetic figure quoted from before 17 Sep should be re-read from the
   current `.json`, not from an earlier document. The superseded files are kept
   under `prefix_hashorder/` rather than deleted.
3. **Wall-clock figures have the same disease in milder form** (B2.4 B-note).
   Both were found by running the same thing twice and comparing. That is now
   the standing rule: **a number that has been produced once has not been
   measured.**

---

## Audit conclusion

**Part A.** The cryptographic handling is narrow, correct, and correctly
justified. It reads one handshake field using key material the governing RFC
publishes; it rejects application-data packets before deriving a key; it fails
safe on truncation and on unknown versions; and it is verified against the
standard's own test vectors. The dependency is confined to a single file with
no path into the model layer. **The material risks are not cryptographic — they
are data-handling (F1, F2) and governance (F3).**

**Part B.** The claims register is unusually well-supported: 47 numeric
claims re-derived exactly, adverse results recorded at the same standard as
favourable ones, and ten superseded claims registered as prohibited. **The
principal weakness is not any individual claim but G1** — no available corpus
can test the system's central hypothesis, which is why the strongest detection
figures are simultaneously the least meaningful ones. **The principal
unverified input is G2**, on which the entire economic argument rests.

The documented separation between *routing fidelity* (96.9%) and *detection*
(35.6%), and the explicit recording of a null result against a zero-parameter
baseline, indicate a measurement discipline that an auditor can rely on.

**Part B7 qualifies that.** A defect that made every synthetic result
irreproducible survived six passing test suites and two prior audits of this
file, and was caught only by running one script twice. The discipline was real
but it was checking the wrong axis: values against their source files, never
source files against a second run. The correction — re-run everything, keep the
superseded files, add a determinism suite, and report wall-clock figures as
relationships rather than constants — is recorded in full because concealing it
would leave the register looking stronger than the evidence behind it.

---

*Prepared 16 September 2026; revised 17 September 2026 after the finding in
B7. All figures re-derived programmatically from source `.json`, and all
synthetic `.json` regenerated, on the revision date; all test suites
re-executed. Items marked UNVERIFIED were not checked and are not asserted.*

*Re-run the whole check with `python verify_all.py` — exit code 0 only if every
suite passes, every number still matches its source, and no retired claim has
returned.*
