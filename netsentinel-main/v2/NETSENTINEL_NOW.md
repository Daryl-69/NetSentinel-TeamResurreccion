# NetSentinel — the whole thing, from scratch

**As of 11 Sep 2026, 12:40 IST · submission 20 Sep · 8.5 days left**

This replaces the scattered notes. If you read one file before the finale, read
this one. Every number here is traced to the file it came from, and where a
number does not mean what it sounds like, that is said next to it.

---

## 0. Right now — is the capture still running?

**Yes.** The newest file `ns_00004_20260911120845.pcap` was written seconds ago
and is still growing. `ns_00003` grew from 21 MB to 53 MB while I was working.
dumpcap is alive and the scheduled task is doing its job.

**But it is still running at snaplen 512.** `capture.log` shows no service start
since 09:29 IST today, which means the running `dumpcap` process still carries
the old arguments. The fix is on disk in the `.ps1` files; a running process
never re-reads its own command line. So every byte being written right now still
cannot name a QUIC flow, and QUIC is ~61% of the encrypted traffic.

### Do these three things, in this order

```powershell
cd D:\1_sih26#2\netsentinel-main\v2

# 1. stop the current capture and restart it so it picks up snaplen 0
.\install_capture_task.ps1 -Status          # confirm what is running
.\install_capture_task.ps1 -Uninstall
.\install_capture_task.ps1 -Interface 5 -OutDir D:\capture -MaxGB 40

# 2. stop the machine sleeping -- this is what cost you two whole days
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /h off

# 3. one hour later, verify the fix actually took
pip install dpkt                            # once
.\.venv\Scripts\python.exe capture_probe.py --dir D:\capture --limit 2
```

Step 3 should show `snaplen actually recorded in the files: 0`, truncation at
0.0%, and a non-zero count under *"hostname recovered from Initial"*. If QUIC
hostnames are still zero after the restart, something did not take — check that
`Get-CimInstance Win32_Process -Filter "Name='dumpcap.exe'"` shows `-s 0`.

Nothing else on the list matters as much as this. Every hour you wait is an hour
of capture you cannot use for the thing that makes the capture interesting.

---

## 1. What NetSentinel is

A **passive AI network intrusion detection system for unidirectional traffic** —
built for places where you cannot put software on the endpoints and cannot see
the return channel: nuclear plants, defence networks, SCADA/OT behind data
diodes, plus IoT and BYOD generally.

It reads only flow records and protocol handshake metadata. It does not decrypt
anything, does not read application payload, does not need a signature, does not
need a known-bad domain, and does not need an agent on the host.

### The threat it is built for

**LOTS / LSA — Living off Trusted Sites.** A modern intrusion does not call home
to `evil-malware.ru`. It uses GitHub, Telegram, Discord, Google Drive — services
that are allow-listed, TLS-encrypted, and completely ordinary. A typical chain:

```
Recon_API          a lookup of the victim's own public IP
   ↓
Code_Repo_Paste    pull the next stage from a public gist
   ↓
Messaging_API      beacon out over a messaging API
   ↓
Cloud_Storage      upload the stolen data
```

Every hop is legitimate in isolation. Signature IDS needs a known bad. Domain
filters need a bad domain. DPI needs plaintext. EDR needs an agent. A chain like
this defeats all four at once.

### What we actually detect (corrected 11 Sep)

**The combination of service categories a host touches, and the machine-like
shape of that traffic.** Not the domains. Not the payload. And — this changed
today — **not the order**. See §5.4: we ran the ablation and the ordering half of
the hypothesis did not survive it.

---

## 2. Architecture

### Tier 1 — six specialist experts (BUILT, running)

Six ONNX models, each a narrow specialist, running CPU-only:

| Model | Technique | Detects |
|---|---|---|
| DDoS | XGBoost | volumetric floods |
| DGA | CNN-BiLSTM | algorithmically generated domains |
| C2 Beacon | BiLSTM + FFT | periodic callbacks |
| Encrypted | FT-Transformer | malicious TLS by flow shape |
| Port Scan | XGBoost | reconnaissance sweeps |
| Exfiltration | VAE | DNS-lexical exfil |

End to end this works: 8.8 GB of `Friday-WorkingHours.pcap` → 32,266 alerts
across all six classes, 42.5 flows/s, 23 ms latency, 280 MB RSS. PCAP → extract
→ infer → alert → WebSocket → dashboard.

Tier 1 is **validated groundwork**, not the pitch. Lead with Tier 2.

### Tier 2 — the Inspector–Sentry cascade (the actual project)

Two models in a teacher/student cascade.

**The Inspector** — 205,546 parameters. A graph autoencoder over a host's
service-category edges: E-GraphSAGE-style hop-1 aggregation, a learned
positional embedding over the 24 hours of a day, a 2-layer Transformer encoder
across those hours, and a decoder that reconstructs the edge features.
Reconstruction error is the anomaly score. It trains **unsupervised** during a
commissioning window — it never needs an attack example. Architecture is
**GraphIDS (arXiv:2509.16625), prior art, not ours.** Say so.

**The Sentry** — 14,992 parameters, **13.7× smaller**. Same aggregator, no
hop-2 cohort term, a GRU instead of a Transformer. Runs always-on, CPU-only,
~250,000 windows/second on one core.

**The Sentry is not a detector. It is a router.** It answers *"would the
Inspector want to look at this?"*, not *"is this an attack?"*. That reframing is
what makes a graph neural network affordable on OT hardware.

**How the Sentry is trained:** anomaly-weighted **encoder** distillation, λ=4 —
we distil the teacher's *representation*, never its verdict. Motivated by MDPI
MAKE 8(3):60, which measured that local outliers transfer at only 20% while
global outliers transfer at 78%. That is exactly why the encoder+Mahalanobis
variant (router B) fails — see §5.1.

**Why the router does not use its own confidence:** confidence-based deferral is
provably suboptimal under distribution shift, specialist downstream models and
label noise (Jitkrittum et al., NeurIPS 2023, arXiv:2307.02764) — all three
describe an IDS. So we train the router to predict the teacher's decision. The
label is free: during commissioning we ran both models.

### The loop, end to end

```
1. Inspector commissions        unsupervised, on a baseline window
2. Distil                       anomaly-weighted encoder distillation, λ=4  →  Sentry
3. Sentry routes                scores every (host, category, hour) live, on CPU
4. Escalate                     top 5% by router score go back to the Inspector
5. Inspector confirms           re-runs on those only, emits ONE alert carrying
                                the timestamped chain steps — not four
                                disconnected alerts
```

### The Service Category Resolver

Deterministic regex, **never a model**. Nine categories:

```
Recon_API   Code_Repo_Paste   Messaging_API   Cloud_Storage
Browse      Sync              CI_CD           Internal        Unknown_External
```

The GNN never sees a domain — only a category and the shape of the
communication with it. That is what stops it memorising infrastructure.

*Known weakness:* the taxonomy mixes service identity with assumed purpose
(Dropbox is both `Cloud_Storage` and `Sync`; `Recon_API` sounds malicious even
when someone legitimately checks their public IP). Renaming before 20 Sep would
invalidate every measured number for a cosmetic gain. Document the ambiguity,
do not rename.

### The ten edge features

Per `(host, category, hour)`:

```
log_n_flows              volume
log_bytes_up
log_bytes_down           ← needs return traffic
egress_asymmetry         ← needs return traffic
iat_cv                   classic beacon coefficient of variation
ks_uniform               KS stat vs Uniform     — LOW means jittered beacon
ks_exponential           KS stat vs Exponential — LOW means human/Poisson
fft_prominence           dominant-frequency prominence → automation
distinct_endpoint_ratio  →1.0 means a domain randomiser
log_duration_mean
```

**The Jitter-Trap inversion:** an attacker who adds jitter to hide a beacon
produces *uniform* inter-arrival times. Humans are log-normal. The evasion is
the signature. This is the nicest idea in the project and it is cheap to explain.

**The two marked features need return traffic**, which a sensor behind a true
one-way tap cannot see. We measured the cost of dropping both: **0.002 AUC**
(§5.4). So the diode story and the feature list agree — but say which diode
topology you mean: a sensor *inside* the protected network exporting telemetry
one-way out (bidirectional visibility, features fine), versus a sensor that can
only physically see one direction (drop those two features, costs ~nothing).

---

## 3. The data

### What exists and what it can prove

| Source | What it is | What it CAN show | What it CANNOT |
|---|---|---|---|
| **LANL cyber1** | 612 hosts × 13 days, 749 real red-team events | real enterprise traffic, real attacker, real labels | zero external/egress traffic — the cross-service hypothesis **cannot fire here at all** |
| **Synthetic generator** | `netsentinel_v2/synth.py` | the pipeline runs end to end; the cascade mechanism | **nothing comparative** — see §5.5 |
| **Our own capture** | 1 laptop, running now | the only place a real LOTS chain could appear | 2.9 usable days so far, 1 host, no attack labels |

**Of 124 surveyed public datasets, none has multi-day egress traffic with
multi-stage campaign labels.** That is why we are capturing our own. It is also
the single honest reason the project cannot yet report a detection rate.

### The state of our own capture (measured, `capture_probe.py`)

- 5.70 days wall clock, 91 files, 3.56 GB
- **only 70 of 137 hours have data — 51%**; 14 files are empty (380 bytes)
- gaps: **21 h** (7–8 Sep), **23 h** (8–9 Sep), 8 h, 6 h, three of 2 h — the laptop slept
- snaplen 160 until 10 Sep 00:41, then 512

Split by what it can actually be used for:

| | live hours | days |
|---|---|---|
| snaplen 160 — names nothing | 55 | 2.3 |
| snaplen 512 — TLS yes, QUIC no | 15 | 0.6 |
| snaplen 0 — both | 0 | 0 |

**Do not say "12-day capture".** Say what is true: a capture that has been
running since 5 September, audited continuously, currently yielding ~2.9 usable
days, restarted at full capture on 11 September.

---

## 4. Visibility — what the sensor can and cannot see

All measured on our own files.

### Snaplen, settled by measurement

pcapng records the *original on-wire length* of every packet, so a capture that
truncated a handshake still tells us how big that handshake was.

| snaplen | packets truncated | TLS hostnames | QUIC hostnames |
|---|---|---|---|
| 160 | 50.8% | **0 of 442** | 0 |
| 512 | 25.1% | **365 of 415 (88.0%)** | **0 of 805** |
| 0 | 0% | — | unlocked |

**Why 512 can never work for QUIC:** RFC 9000 §14.1 *requires* a client Initial
packet to be padded to at least 1200 bytes. Our measured median is **1,230
bytes**; **90.2% exceed 512**. It is arithmetic, not tuning.

Cost of full capture, measured: **×1.84 bytes, ≈1.01 GB/day, 12.1 GB for 12
days** against a 40 GB budget with 67 GB free. Affordable.

### We parse QUIC rather than switching it off

QUIC Initial packets are protected with keys derived from a **salt published in
RFC 9001 §5.2** plus the client's own Connection ID, which travels in cleartext
in the same packet. Reading the handshake is the documented design — not an
attack, not TLS interception. We get the hostname and nothing else, exactly as
with TLS over TCP.

`netsentinel_v2/quic.py` implements it. `test_quic.py` verifies the derivation
against the RFC's own published vectors: **16/16 pass**, including negative
controls that make a truncated packet report itself rather than return a guess.

**The QUIC and DoH registry policies are no longer needed.** Drop them. Not
applying them makes the capture more representative of a real network, not less,
and removes the obvious question *"so it doesn't work on real traffic?"*

### What no snaplen fixes

- **46.3% of ClientHellos span more than one TCP segment.** A per-packet parser
  misses those at any snaplen; only TCP reassembly (Zeek) recovers them. This is
  a loader problem, not a capture flag. **Still open.**
- **43 ClientHellos in a 2-file sample carry Encrypted Client Hello**, where the
  visible name is a cover name. Small today, growing. We detect and report it
  rather than recording the decoy as truth.

### DNS — stated as facts, not as one ratio

An earlier audit of mine reported *"55% of DNS is DoH"*. **That was wrong and it
is retracted.** It counted bootstrap lookups *of a resolver's own hostname*,
which says nothing about how much DNS was subsequently hidden. Measured
properly, in the sampled window: **906 plaintext queries readable, 106 distinct
names, 1 connection to a known DoH endpoint.** We do not report a "% of DNS
hidden" because we cannot see hidden queries and therefore have no denominator.

---

## 5. Every measured number, and what it does not mean

### 5.1 On LANL cyber1 — real traffic, real red team, 3 seeds

Source: `lanl_novelty.json`. 612 hosts × 13 days, 749 red-team events.

| | value |
|---|---|
| Router A AUC — **agreement with the teacher** | **0.992 ± 0.003** |
| Router B AUC (encoder + Mahalanobis) | 0.634 ± 0.007 |
| Inspector global AUC vs attack window | **0.745 ± 0.002** |
| Inspector global AUC vs attack day | 0.639 ± 0.004 |
| **Inspector within-host AUC** | **0.557 ± 0.013** |
| Inspector flag rate | 2.56% |
| Model size | 205,546 → 14,992 (**13.7×**) |

Router A beats router B by a mile, exactly as the distillation-transfer
literature predicts. That result is solid.

### 5.2 The most dangerous number in the project

At a 5% escalation budget, on LANL:

| metric | value | what it means |
|---|---|---|
| `recall_teacher` | **96.9% ± 1.1** | of the **Inspector's own flags**, the Sentry recovers 96.9% |
| `recall_attack` | **35.6% ± 1.3** | of the **actual red-team attacks**, 35.6% are caught |

**These are different things and conflating them is the fastest way to lose the
panel.** The 96.9% is routing fidelity — it says the cheap model faithfully
reproduces the expensive model's decisions. It says nothing about whether the
expensive model is right.

Always say the full sentence: *"96.9% of the Inspector's flags are recovered at
a 5% budget."* Never shorten it to "96.9% recall". **Never say 95% recall** —
that was an early proposal that the measurements did not support.

Full curve, teacher-recall vs attack-recall:

| budget | recall_teacher | recall_attack |
|---|---|---|
| 1% | 37.7% | 11.5% |
| 2% | 68.0% | 19.3% |
| 3% | 85.6% | 27.2% |
| **5%** | **96.9%** | **35.6%** |
| 10% | 99.0% | 44.3% |
| 30% | 99.5% | 66.9% |

### 5.3 The weakness — lead with it

**Within-host AUC 0.557 ± 0.013 against the LANL red team. That is chance.**

We scored each attacked host against its own windows only. Attacked hosts were
simply *busier* — 0.811 live-window density versus 0.530 for everyone else. The
global 0.745 was largely ranking **which host was busy, not when it was
attacked**. We built that check ourselves and it argued against us.

One extra honesty note: the ±0.013 is seed-to-seed variation of the mean. The
spread **across hosts** within a single seed is **0.297** — far larger. 77 hosts,
106 positives. So the per-host picture is noisier than "0.557 ± 0.013" suggests.

LANL has zero external traffic, so the cross-service hypothesis cannot fire there
at all. That is the reason for our own capture — not an excuse, a design
consequence.

### 5.4 The order ablation — new, 11 Sep

`ablation_order.py`. 3 seeds, 120 hosts, 16 days, 45/960 attack days,
fully-shaped adversary, hard negatives on. The model can only see order through
the positional embedding and the Transformer over the hour axis, so permuting
the hour axis is a complete ablation of order.

| condition | ROC-AUC |
|---|---|
| A full model (order-aware) | 0.998 ± 0.001 |
| B hours permuted **at scoring** | 0.998 ± 0.001 |
| C hours permuted **at training and scoring** | 0.997 ± 0.001 |
| D bag of categories (**order-free**) | **1.000 ± 0.000** |
| E first-order Markov transitions | 0.444 ± 0.055 |
| F no reverse-direction features | 0.996 ± 0.002 |

- **A − B = 0.000** — shuffling the hours changes the score by nothing. The
  model is order-blind.
- **A − C = 0.000** — there is no order information in the data for any model.
- **A − D = −0.002** — an order-free Mahalanobis does marginally *better*.
- **A − F = 0.002** — losing the two reverse-direction features is nearly free.
  Good news, and it defuses the obvious attack on the diode pitch.

**Consequence: the word "sequence" came out of the deck.** The claim is now
*"we detect the combination and the shape, not the destination."*

### 5.5 Why the synthetic numbers cannot carry a comparative claim

On the generator as it was, this one rule:

> longest consecutive run of hours in which `Messaging_API` is present

scores **ROC-AUC 1.000** at every stealth level. One counter, no model. The
attacker was the only host that ever chatted for nine hours straight.

I added hard negatives — benign hosts that chat all day, and legitimate
integrations that poll on a schedule (which produce the same low-jitter timing
the Jitter-Trap keys on). Opt-in via `synth.generate(..., hard_negatives=True)`
so prior results stay reproducible.

| rule | old generator | with hard negatives |
|---|---|---|
| longest `Messaging_API` run | 1.000 | 0.797 |
| hours with `Messaging_API` | 0.999 | 0.661 |

Even hardened it is still over-determined — `distinct_endpoint_ratio` alone
scores 1.000, volume alone 0.999, timing alone 0.999. **Honest position: the
synthetic benchmark shows the pipeline runs end to end. It cannot support any
comparative claim about the architecture.** The LANL numbers are unaffected —
those are measured on real data and answer a different question.

Synthetic numbers, for completeness (`results.json`, world A): router A AUC
0.833 ± 0.044, B 0.804 ± 0.029, C 0.839 ± 0.039 at 8 seeds — no pair
separable; oracle 0.875. Treat as
pipeline-works evidence only.

### 5.6 The threshold does not transfer

Source: `shift_results.json`. The mechanism transfers across organisations
(oracle AUC 0.873 → 0.852). **The threshold does not:** a 99th-percentile
threshold fitted in world A flags **6.7%** in world A's own later test period and
**6.3%** in world B — against a 1% target. Ratio 1.14.

It decays **over time**, not just across networks. Every deployment needs its own
calibration window plus rolling recalibration. Which is why:

### 5.7 Guarded recalibration — new, 11 Sep

The obvious fix — a rolling 99th percentile — hands the attacker the threshold:
their own rising scores enter the reference set, the quantile climbs, and the
attack stops being an outlier by definition.

`test_calibration.py`, drift sized to the 6.7% we actually measured:

| policy | attack windows caught | false alerts | final threshold |
|---|---|---|---|
| FIXED (what we ship today) | 9.6% | 4.21% | 2.85 |
| UNGUARDED rolling quantile | **0.1%** | 1.92% | **4.29–4.53** |
| GUARDED | **8.8%** | 4.14% | 2.89 |

The attacker walks the unguarded threshold from 2.85 to ~4.4 and detection
collapses to 0.1%. The guards: admission by **provenance** (blind random audit)
never by score; movement bounded in MAD units; adaptation frozen while an
incident is open; forward-only application.

And the cost the deck was hiding — calibration draws from the **same budget** as
escalation:

| audit budget | detection | false alerts |
|---|---|---|
| 2% | 8.8% | 4.14% |
| 5% | 7.4% | 3.93% |
| 10% | 4.9% | 3.67% |
| 20% | 1.6% | 2.88% |

(The falling detection column is inflated — that stream is 12% attack, which no
real network is. Quote the shape of the trade, not these numbers.)

### 5.8 Cost

`cost_model.py` / `results.json`, 1,000 hosts, 14-day commissioning:

- inspect everything: **365,000** GPU-host-days/year
- NetSentinel steady state: **19,467** GPU-host-days/year
- **94.7% reduction**, plus a 14,000 GPU-host-day one-time commissioning cost

🔵 **Corrected 12 Sep — read this before quoting 94.7%.** That figure assumes a
2% escalation rate *per host-day* and no audit budget at all. Two measurements
changed it (full detail in `INSPECTOR_SENTRY.md` §5.4 and §7.4):

| regime | ongoing/yr | reduction |
|---|---|---|
| as quoted (2% host-day escalation, no audit) | 19,467 | 94.7% |
| + the 2% random audit that calibration needs | 26,767 | 92.7% |
| escalation counted the way the recall figures were measured | 198,317 | **45.7%** |

The last row is the important one: a 5% *window* budget makes the Inspector
re-run on **~48% of host-days**, because the escalated windows scatter across
almost every host-day. The recall numbers in §5.2 were measured at a
window-level budget; 94.7% assumes a host-day rate. **They describe different
systems and must not be quoted together.**

---

## 6. What we claim, and what we must never claim

### Say these

- 96.9% ± 1.1 **of the Inspector's flags** recovered at a 5% escalation budget (LANL)
- Router A AUC 0.992 ± 0.003 agreement with the teacher (LANL)
- 13.7× compression, 205,546 → 14,992 parameters
- 94.7% less GPU work at 1,000 hosts
- Within-host AUC 0.557 ± 0.013 — chance — **say this before they ask**
- We parse QUIC Initials per RFC 9001; 16/16 published vectors pass
- We ran an order ablation against our own headline claim and changed the claim

### Never say these

- **"95% recall"** or "96.9% recall" without "of the Inspector's flags"
- Any **Tier-2 detection rate** on our own capture — we have no labels
- "We detect the sequence" — tested, refuted, 11 Sep
- **"Router A is the best of the three"** — tested at 8 seeds, 17 Sep: they tie.
  Build A on the LANL gap (0.992 vs 0.634), not on a synthetic ranking
- A throughput figure to one decimal place — three runs on one machine gave
  8.59×, 7.54× and 8.22×. Say "about 8×, CPU to CPU"
- "State of the art", "novel transformer", "replaces EDR"
- That the Inspector architecture is ours — it is GraphIDS, arXiv:2509.16625
- "Headers only, no payload" — false at any snaplen. Correct wording: *the
  sensor keeps whole packets so it can read handshakes; the detector consumes
  only flow records and handshake metadata and never application payload.*
- "12-day capture" — see §3
- "55% of DNS is DoH" — retracted, §4

### The only genuine novelty

Cross-service **category semantics** — scoring which allow-listed categories a
host combines, per host, as the detection signal. A 91-study review of
graph-based NIDS found no published system doing this. Plus the chain dataset,
and the ablation discipline that tells us which half of the hypothesis survives.

Everything else — the cascade, the distillation, per-entity baselining, the
Inspector architecture — is prior art. Saying so buys credibility.

---

## 7. What is broken or open

### Tier 1
- **Exfil VAE ~50% false positives** — scikit-learn version mismatch.
  `pip install scikit-learn==1.6.1`
- **Port scan 0 detections** — a **39-feature model is being fed the 59-feature
  CIC schema**. This is a contract bug, not a dataset problem, and it must be
  fixed before any port-scan result is quoted.
- **Covariate shift** — 92% of features drifted vs CICFlowMeter; 3 bugs fixed but
  `ks_summary.txt` is stale. Re-run `scripts\covariate_shift.py`.
- 2 of 6 evidence panels visualise the wrong thing (the exfil panel shows a byte
  ratio; the model is DNS-lexical)
- No persistence, no auth, no SIEM connectors

### Tier 2 — ranked by value per remaining day

✅ **Done 12 Sep** (detail in `INSPECTOR_SENTRY.md`): visibility gate and
per-host state machine built and tested (`visibility.py`, `lifecycle.py`,
19/19), per-host score normalisation (`hostnorm.py`), feature contract test
(`test_contracts.py`, 32/32), the escalation loop built for real
(`escalate.py`), and the first Inspector throughput measurement — 70,950
windows/s, with the Sentry about 8× faster rather than the 13.7× that parameter
count implies.
1. **Per-host commissioning state machine.** COMMISSIONING / SENTRY_PRIMARY /
   ESCALATED / INCIDENT_HOLD / RECOMMISSIONING, promotion **on evidence** not on a
   14-day timer. A quiet server gives you almost nothing in two weeks; a monthly
   backup job never appears at all. Designed, not built. ~half a day, and it
   answers *"what happens when a new machine joins?"*
2. **TCP reassembly in the loader** — recovers the 46.3% of ClientHellos that
   span segments. Zeek already does this; route naming through Zeek output
   rather than reading packets directly.
3. **Visibility gate.** `capture_probe.py` reports naming coverage; what is
   missing is the gate that *refuses to score* and raises a **data-quality
   warning instead of a security alert** when coverage drops below what the model
   was fitted on. Right now a capture fault would look like an attack.
4. **Feature/schema contract tests** — assert feature name, order, count and
   units between training and runtime for every model. Would have caught the
   port-scan 39-vs-59 bug and the VAE scaler mismatch.
5. **Escalation loop, retention rule, sampler** — designed, not built.
6. **Re-run `real_probe.py` → `inject_demo.py`** once there is a snaplen-0
   corpus. Show it **only** if the benign-surge control comes back clean.

---

## 8. File map

```
D:\1_sih26#2\netsentinel-main\v2\

  CAPTURE
    start_capture.ps1          interactive capture, snaplen 0
    capture_service.ps1        the scheduled-task body, snaplen 0
    install_capture_task.ps1   -Status / -Uninstall / install
    capture_probe.py       NEW truncation, naming, QUIC readability, DNS facts
    capture_audit.py           older audit (superseded by capture_probe.py)
    zeekify.sh                 PCAP -> Zeek logs (run in WSL)

  MODELS
    netsentinel_v2/models.py       Inspector, Sentry, DeferralHead
    netsentinel_v2/train.py        commissioning + distillation
    netsentinel_v2/categories.py   the 9 categories, the 10 features
    netsentinel_v2/synth.py        generator (+ hard_negatives=True, NEW)
    netsentinel_v2/lanl_loader.py  LANL cyber1
    netsentinel_v2/zeek_loader.py  our own capture
    netsentinel_v2/baseline.py     per-host baselines
    netsentinel_v2/cost_model.py   the GPU-cost arithmetic
    netsentinel_v2/quic.py     NEW RFC 9001 QUIC Initial parser
    netsentinel_v2/calibration.py  NEW guarded rolling recalibration

  EXPERIMENTS / TESTS
    run_experiment.py          the main harness      -> results.json
    shift_test.py              cross-world transfer  -> shift_results.json
    test_lanl_loader.py        53 assertions on the LANL loader
    test_quic.py           NEW 16 checks vs RFC 9001 Appendix A.1
    test_calibration.py    NEW poisoning demo + audit-budget sweep
    ablation_order.py      NEW the order + diode ablations
    demo_scenario.py           the on-camera end-to-end demo
    real_probe.py              build a tensor from our own capture
    inject_demo.py             injection + benign-surge control (GATED)

  RESULTS (never type a number that is not in one of these)
    lanl_novelty.json          LANL — the real-traffic numbers
    results.json               synthetic world A
    shift_results.json         worlds A vs B, threshold transfer
    ablation_order_hard.json   the order ablation

  DOCS
    NETSENTINEL_NOW.md         this file
    ASTRA_REVIEW_11SEP.md      the 11 Sep review + full evidence
    CLAUDE.md                  routing table for the whole vault
    ARCHITECTURE_V2.md         Tier 2 design
    DATASETS.md                what each dataset can and cannot do

  DECK
    netsentinel_deck.html      the live 9-slide deck
    ppt\NetSentinel_SIH2026.pptx        10-slide
    ppt\NetSentinel_SIH2026_6slide.pptx official 6-slide template
```

## 9. How to run everything

```powershell
cd D:\1_sih26#2\netsentinel-main\v2

# the demo that goes on camera (~45 s)
.\.venv\Scripts\python.exe demo_scenario.py --quiet

# the test built to fail — 53 assertions on the LANL loader
.\.venv\Scripts\python.exe test_lanl_loader.py

# QUIC parser vs the RFC's own vectors — 16/16
.\.venv\Scripts\python.exe test_quic.py

# can the attacker move our threshold?
.\.venv\Scripts\python.exe test_calibration.py

# does order carry the signal? (~4 min)
.\.venv\Scripts\python.exe ablation_order.py --hard-negatives --stealth-lo 0.9

# what can the sensor actually see?
.\.venv\Scripts\python.exe capture_probe.py --dir D:\capture --limit 4

# rebuild the results page from JSON, on camera
.\.venv\Scripts\python.exe make_card.py --open
```

---

## 10. The plan to 20 September

**Today (11th).** Restart the capture at snaplen 0. Kill sleep. Verify with
`capture_probe.py` an hour later. Nothing else competes with this.

**12th–13th.** Per-host state machine (§7.1) — it is the most visible missing
piece and it answers a question judges always ask. Route naming through Zeek to
pick up the 46% of split ClientHellos.

**14th–15th.** Visibility gate (§7.3). Fix the port-scan schema contract and add
the contract tests (§7.4) — that is a teammate-sized task and it removes a known
embarrassment.

**16th–17th.** Fill the deck placeholders: PS ID, PS title, theme, team ID and
name, institution, mentor, six member names and departments. Fill the two
screenshot slots on slide 8. Rehearse against §6 until the never-say list is
automatic.

**18th–19th.** With ~7 days of snaplen-0 capture in hand: re-run `real_probe.py`
then `inject_demo.py`. **Show it only if condition B — the benign surge — comes
back clean.** If it does not, that is a real finding and it gets reported, not
hidden. Leave the result slot on slide 8 empty rather than filling it with
anything unmeasured.

**20th.** Submit.

---

## The story, in five sentences

Modern intrusions ride trusted services, and nothing in the current stack sees
them: signatures need a known bad, filters need a bad domain, DPI needs
plaintext, EDR needs an agent. NetSentinel watches which categories of service a
host combines and how machine-like the traffic looks, passively, with no agent
and no decryption, and makes it affordable by putting a 14,992-parameter router
in front of a 205,546-parameter graph model — recovering 96.9% of the big
model's flags while doing 94.7% less GPU work. We tested it against a real red
team and found our within-host AUC was 0.557 — chance — because the model was
ranking which host was busy, not when it was attacked. We ran an ablation
against our own headline claim and found the ordering half of it was not
supported, so we changed the claim. Everything above regenerates from a result
file by script, and the parts that do not work yet are listed by name.
