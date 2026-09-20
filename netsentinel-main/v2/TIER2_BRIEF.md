# NetSentinel Tier 2 — the Inspector–Sentry cascade

**A complete brief for someone joining with no prior context.**
Current as of 12 September 2026. No history, no changelog — this describes the
system as it stands today and every number that has actually been measured.

Rule that governs this document and the project: **every number here comes from
a `.json` file produced by a script in this repo.** The provenance is stated for
each one. If a number is not in one of those files, it does not get said out
loud, written on a slide, or put in a paper.

---

## 1. What the system is trying to do

Detect an insider or a compromised account moving through cloud services, when
all you have is passive network traffic and no ability to install anything on
the endpoint.

The deployment target is a network behind a **data diode** — a one-way optical
link used in nuclear, defence and SCADA environments. Traffic goes out, nothing
comes back. That rules out EDR agents, active scanning, TLS interception and
any inline device. You get a mirror of egress packets and nothing else.

**The hypothesis.** A person doing something they should not tends to combine
*categories of service* in a way that machine does not usually combine them:
touch an internal recon API, then a code-paste site, then a messaging API. Any
one of those is unremarkable. The combination, on that host, is not.

This is different from most anomaly detection, which scores flow statistics
(bytes, timing, ports) or individual destinations. A 91-study review of
graph-based NIDS found no published system scoring cross-service category
combinations per host. **That is the only claimed novelty.** The cascade, the
knowledge distillation, and per-entity baselining are all established prior art.

**What is explicitly not claimed.** Not state of the art. Not a novel
transformer. Not a replacement for EDR — it is complementary, and its niche is
where EDR cannot go: IoT, OT, BYOD, air-gapped and diode-separated networks.
The Inspector's architecture is not ours; it is GraphIDS-shaped
(arXiv:2509.16625).

---

## 2. Why there are two models

The original reason was cost. That reason does not survive measurement: at
100,000 hosts with a teacher a thousand times larger than ours, inspecting
every host-hour for a year costs about $150 (`gpu_cost.py`). The two reasons
that do survive are structural, and both are asserted in `test_tiers.py`
rather than argued — the Sentry can answer every hour and the Inspector
cannot, and the Inspector needs other hosts' data while the Sentry does not.
See §8.0. The shape:

```
        every window, always                  a small selected fraction
   ┌──────────────────────────┐         ┌──────────────────────────────┐
   │  SENTRY   14,992 params  │  top-k  │  INSPECTOR   205,546 params  │
   │  GRU, CPU, always-on     ├────────►│  GNN + Transformer           │
   │  a ROUTER, not a detector│         │  the expensive teacher       │
   └──────────────────────────┘         └──────────────────────────────┘
              ▲                                        │
              └────────── distillation ────────────────┘
```

The Sentry's job is **not** to decide whether something is an attack. Its job is
to predict *whether the Inspector would find this interesting*, and to spend a
fixed escalation budget on the windows most likely to be worth the Inspector's
time. That distinction drives everything else in the design, and it comes from
Jitkrittum et al., NeurIPS 2023 (arXiv:2307.02764): a router that predicts its
own uncertainty is provably suboptimal compared to one that predicts the
expensive model's decision.

---

## 3. The data representation — shared by every input source

Everything reduces to one tensor:

```
edges[host, day, window, category, feature]      float32
mask [host, day, window, category]               1.0 if that edge exists
```

- **24 windows per day**, one hour each.
- **9 categories.** Which nine depends on the corpus (see §5).
- **10 features per (host, category, window):**

| # | feature | what it captures |
|---|---|---|
| 0 | `log_n_flows` | volume |
| 1 | `log_bytes_up` | outbound volume |
| 2 | `log_bytes_down` | inbound volume |
| 3 | `egress_asymmetry` | up/down ratio — the exfiltration signal |
| 4 | `iat_cv` | inter-arrival coefficient of variation — classic beaconing |
| 5 | `ks_uniform` | KS distance from uniform inter-arrivals |
| 6 | `ks_exponential` | KS distance from exponential inter-arrivals |
| 7 | `fft_prominence` | periodicity — automation |
| 8 | `distinct_endpoint_ratio` | →1.0 means a domain randomiser |
| 9 | `log_duration_mean` | session length |

**The jitter-trap inversion.** A beacon that adds random jitter to evade timing
detection produces near-constant inter-arrival times relative to a human's. Real
sessions are bursty and heavy-tailed; an automated check-in is not. **Measured on
real captured traffic against published C2 sleep profiles** (`bench_beacon.json`):
`iat_cv` separates them at **0.878 AUC** averaged over uniform, gaussian and
lognormal jitter, `ks_exponential` at 0.826, `ks_uniform` at 0.773 — and
`fft_prominence` at only **0.623**, close to chance. So the working claim is
*the coefficient of variation carries this, the distributional tests support it,
and the periodicity term contributes little.* The evasion is still the signature;
it is `iat_cv` that sees it, not the periodicity feature.

A live window is one where `mask.sum(-1) > 0` — the host did something that
hour. Empty windows are excluded from every metric.

---

## 4. The models, precisely

### 4.1 EdgeAggregator — shared by both models

```
hop-1 message = MLP([ edge_features(10) ‖ category_embedding(16) ‖ cohort ])
window vector = MLP([ mean(messages), max(messages), presence_mask ])
```

The **cohort** term is hop-2 context: what other hosts were doing in the same
category in the same window. The Inspector uses it; the Sentry does not.

One implementation detail that matters, because it was a real bug: the max-pool
must be guarded on the true edge *count*, not on the denominator. Guarding on
the denominator lets a `-1e9` sentinel escape into the encoder on empty windows.

### 4.2 Inspector — the teacher

| component | params | share |
|---|---|---|
| `seq` — 2-layer TransformerEncoder, dim 96, 4 heads, ffn 192 | 149,568 | 72.8% |
| `agg` — EdgeAggregator | 41,712 | 20.3% |
| `dec` — decoder | 11,818 | 5.7% |
| `pos` — positional embedding (24 windows) | 2,304 | 1.1% |
| `cat_emb` — category embedding | 144 | 0.1% |
| **total** | **205,546** | |

Trained as a **denoising autoencoder**: 25% of present edges are hidden from
the encoder, and the decoder must reconstruct all of them. Reconstruction error
is the anomaly score. **Completely unsupervised — it never sees an attack
label, in training or in threshold selection.** The threshold is the 99th
percentile of reconstruction error over the commissioning window.

Its unit of work is a **whole host-day**, not a window. This matters
operationally and is easy to get wrong — see §7.7 and §8.0.

### 4.3 Sentry — the student and router

EdgeAggregator (no cohort) → GRU dim 32, unidirectional → Linear 32→96
projection head. **14,992 parameters.**

### 4.4 The distillation

```
L = E[ (1 + λ · s_teacher) · ‖ project(f_student) − f_teacher ‖² ]     λ = 4
```

The Sentry is distilled on the teacher's **encoder representation**, weighted
toward high-anomaly windows — not on its binary verdict. Motivation: MDPI MAKE
8(3):60 measured that in ordinary distillation, *global* outlier structure
transfers at ~78% but *local* outlier structure transfers at only ~20%. Local
structure is exactly what an anomaly router needs, so it has to be weighted for
explicitly. Slogan: **distil the eyes, never the verdict.**

---

## 5. The datasets — what each one is and what each one can and cannot test

This is the section most likely to be misread, so it is explicit about which
numbers came from which corpus.

### 5.1 LANL cyber1 — the only real attack labels

"Comprehensive, Multi-Source Cyber-Security Events" (Kent, 2015). 58 days of a
real enterprise network, ~17,700 computers, with a **red-team ground truth
file** — 749 labelled authentication events. Available from
`https://csr.lanl.gov/data/cyber1/`. Files used: `flows.txt.gz` (the bulk) and
`redteam.txt.gz` (the labels).

**Configuration actually used:** `--max-hosts 500 --lanl-days 13`. That keeps
the 500 busiest hosts by client-side flow count and then force-includes 112
red-team computers that had client traffic but did not rank — evaluating attack
recall on a host set that excludes the attacked hosts would be worthless. Result:
**H = 612 hosts × 13 days.** Commissioning days 0–5, validation gap 6–7, test
days 8–12. 39,492 live test windows, 131 attack windows on 80 hosts, of which 77
hosts carrying 106 positives are scoreable for within-host AUC.

**What LANL can test:** attack recall against a real red team. Nothing else
available does this.

**What LANL cannot test — read this before quoting any LANL number:**

1. **No named services.** Every computer is de-identified to `C1065`. There are
   no SaaS destinations, so the actual LOTS taxonomy (`Recon_API`,
   `Code_Repo_Paste`, …) would collapse to ~100% `Internal`. The loader
   substitutes a **port-derived** nine-class internal taxonomy occupying the
   same tensor slots: Directory, FileShare, RemoteAccess, Mail, WebProxy,
   Database, Infra, Workstation, Unknown. Measured distribution: FileShare 29.0%,
   Infra 24.6%, Directory 17.2%, WebProxy 16.8%, Workstation 6.5%, Unknown 4.0%,
   Database 1.1%, RemoteAccess 0.6%, Mail 0.1%. **This is a different signal
   measuring a different thing.** LANL evaluates a proxy task.
2. **Two of the ten features are uncomputable.** cyber1 logs one byte count, not
   a directional pair, so `log_bytes_down` and `egress_asymmetry` cannot be
   built. Those two slots are repurposed on LANL only, carrying `new_peer_ratio`
   and `new_service_flag` instead. Without that substitution the within-host AUC
   was 0.526 ± 0.308 — chance. Volume and timing alone do not separate a
   credential-based hop from an administrator's Tuesday.
3. **Labels are auth events, not flows.** They name a source and a destination
   computer. The default `label_policy=both` marks both. Marking only the
   destination is intuitive and wrong for this system: what NetSentinel models is
   a host's *outbound* behaviour, so the row whose shape changes is the
   compromised **source**. Measured on this run: 1 of 4 red-team source computers
   and 119 of 301 destination computers were modelled hosts — most destinations
   are servers with no client-side traffic.

**Two loader details that are load-bearing.** LANL does not normalise flow
direction and anonymises ephemeral ports as `N#####`, so the service port is
taken as `min(numeric ports)` and the endpoint holding the ephemeral port is
treated as the client. A destination-port resolver gets the direction backwards
on the dataset's own example row. Separately, fan-in thresholds for
"is this a server" are measured from a first streaming pass (p90/p99 of the
distinct-source distribution), not hard-coded.

**Caching.** Two passes over `flows.txt.gz` are expensive and both are cached
(`lanl_profile.json`, `lanl_tensors_H612_D13_nov1_b6.npz`). With both caches
present, the raw file is not needed at all — only `redteam.txt` for the labels.
The cache key encodes hosts, days and the novelty flag, so `--max-hosts`,
`--lanl-days` and `--no-novelty` must match the run that wrote it.

### 5.2 The synthetic generator — `netsentinel_v2/synth.py`

Builds the same tensor with the full 9-category LOTS taxonomy, real egress
semantics, and injected LOTS-LSA chains. Its purpose is to test the mechanism
where the hypothesis can actually fire; it is **not** evidence of real-world
performance, because a detector evaluated on the generator that produced its
attacks is partly learning the generator.

`hard_negatives=True` is on by default and matters. Without it the data is
solvable by one trivial rule — "find the host with the longest unbroken
`Messaging_API` run" scores AUC **1.000**. With hard negatives (35% "chatty"
hosts with all-day messaging presence, 25% "poller" hosts with low-jitter
scheduled CI/CD and sync traffic) that same rule drops to **0.797**.

### 5.3 Our own capture — the only corpus with named egress

Six laptops, `dumpcap` ring buffer, hourly rotation, 312-file ring
(~40 GB, ~13 days retained), Windows scheduled task running as SYSTEM.

**Capture is currently at snaplen 0 (whole packets), since 12 Sep 12:03 IST.**
This is not a preference; it was forced by measurement. See §6.

This corpus is the only one that can test the actual cross-service hypothesis,
because it is the only one with resolvable external service names. **It does
not yet have enough post-fix days for a commissioning/test split.**

### 5.4 Evaluated and rejected

| dataset | why it was rejected |
|---|---|
| WRCCDC 2018 | 1,021,950 conn records, 15,070 SNI names, 664 hosts, 77.3% resolver hit rate — but **one day only**, so no host can be baselined |
| Stratosphere Normal Captures | host unreachable from our network |
| Unified Host and Network (2017) | has directional bytes, but **no red-team labels**. Labels or directionality; not both |

---

## 6. Capture — what the sensor can actually see

Measured by `capture_probe.py`, which reads the **original on-wire length** of
each packet, so its truncation figures survive truncation. Latest run, 2 files,
173,682 packets:

| | measured |
|---|---|
| snaplen recorded in files | 262,144 (dumpcap's "whole packet") |
| packets truncated | **0 (0.0%)** |
| TLS ClientHellos seen | 342 |
| hostname recovered | **308 (90.1%)** |
| median snaplen actually needed | 654 bytes |
| 95th percentile | 2,041 bytes |
| ClientHellos split across TCP segments | **159 (46.5%)** |
| Encrypted Client Hello present | 32 |
| plaintext DNS queries readable | 1,002 |
| distinct names queried | 65 |
| connections to known DoH endpoints | 0 |
| distinct named destinations | 55 |

**Why snaplen 0 and not something smaller.** At snaplen 512, **0 of 805 QUIC
Initial packets** were readable. RFC 9000 requires a client Initial to be padded
to at least 1,200 bytes; measured median was 1,230. Truncation at 512 therefore
loses the hostname on every QUIC connection, which is most Google and YouTube
traffic. Coverage measured on the current corpus: snaplen 160 captures 0.0% of
ClientHellos whole, 512 → 16.7%, 1024 → 53.5%, 1500 → 53.5%, 2048 → 95.6%.

**Note the flatline between 1024 and 1500.** That is the ethernet MTU. Once a
handshake exceeds one packet, a larger capture buffer cannot help, because the
data was never in one packet. **46.5% of ClientHellos need TCP reassembly**,
which is Zeek's job, not dumpcap's. The capture story is therefore two claims,
not one: whole packets fix *truncation*, Zeek reassembly handles *fragmentation*.

**QUIC hostname recovery is legitimate and worth being able to defend.** QUIC
Initial packets are encrypted with a key derived from a salt published in
RFC 9001 §5.2 plus the client's own cleartext Connection ID. Anyone can compute
it; that is the design. Only the SNI is extracted. No user payload is decrypted,
and this is not interception. The implementation in `netsentinel_v2/quic.py` is
verified against the RFC's own Appendix A.1 test vectors — 16 checks, all
matching exactly. It requires the `cryptography` package; without it QUIC
packets are counted but cannot be named.

**A retracted claim, stated so nobody reintroduces it.** An earlier "55% of DNS
is hidden by DoH" figure was wrong. It counted bootstrap lookups *of the
resolver's own hostname*. We cannot see hidden queries, so we have no
denominator for them, and we therefore do not report a percentage. We report
counts: 1,002 plaintext queries, 65 distinct names, 0 DoH connections.

---

## 7. Every measured result, with the corpus it came from

### 7.1 LANL cyber1 — 612 hosts × 13 days, 3 seeds
*Source: `lanl_novelty.json`, `lanl_novelty_hn.json`, `lanl_p0b.json`*

| metric | value |
|---|---|
| Router A AUC — agreement with the teacher | 0.992 ± 0.003 |
| Router B AUC | 0.634 ± 0.007 |
| Inspector pooled AUC vs attack, window-level | 0.745 ± 0.002 — **confounded, see below** |
| Inspector pooled AUC, day-level | 0.639 ± 0.004 |
| **Inspector within-host AUC** | **0.557 ± 0.013** |
| Inspector flag rate | 2.56% |
| kNN geometry overlap @20 | 0.439 |
| runtime, 3 seeds, CPU | 843 s |

**Escalation budget curve (router A, window-level, mean of 3 seeds):**

| budget | recall of *teacher's flags* | recall of *actual attacks* |
|---|---|---|
| 1% | 37.7% | 11.5% |
| 2% | 68.0% | 19.3% |
| 5% | **96.9%** | **35.6%** |
| 10% | 99.0% | 44.3% |

**These two columns are different quantities and conflating them is the single
most dangerous error available in this project.** 96.9% is how much of the
Inspector's *own output* the Sentry recovers — a routing-fidelity number. 35.6%
is how many real attacks were caught. Never say "96.9% recall" unqualified; say
"96.9% of the Inspector's flags." Never quote any Tier 2 detection rate as if it
were a product claim. The figure "95% recall" was once proposed and is withdrawn.

**The busy-host confound — the most important caveat in the project.** Attacked
hosts in LANL are simply *busier*: live-window density **0.811** versus **0.530**
for everyone else. So a pooled ranking can score well by ranking busyness rather
than compromise. Testing that directly by scoring each window against its own
host's commissioning distribution (`--host-normalise`):

| metric | baseline | per-host scored | delta |
|---|---|---|---|
| pooled window AUC | 0.745 ± 0.002 | **0.618 ± 0.021** | **−0.127** |
| pooled day-level AUC | 0.639 ± 0.004 | 0.487 ± 0.024 | −0.152 |
| within-host AUC | 0.557 ± 0.013 | 0.560 ± 0.015 | +0.003 |
| flag rate | 2.6% | 2.0% | −0.6 pts |

Within-host did not move, and that is expected rather than disappointing:
within-host AUC ranks each host's windows against that host's own windows, and a
per-host z-score is a strictly increasing transform inside each host, which
cannot change a ranking. The residual +0.003 comes from 32 of 612 hosts having
under 20 live commissioning windows and falling back to the pooled scale.

**The pooled collapse is the finding.** Most of the gap between 0.745 and 0.557
was cross-host busyness. The honest position: **0.557 is the confound-free
number and it is near chance; 0.745 must never be quoted without this
attached.** One alternative reading cannot be excluded by this experiment — if
attacked hosts are busier *because* they are compromised, per-host scoring
destroyed real signal rather than an artefact. Nothing here distinguishes those.

### 7.2 Is the graph model worth its parameters?
*Source: `lanl_p0b.json` (real), `paired_synth.json` (synthetic)*

The baseline is deliberately near-zero-parameter: per host, a median and a MAD
over that host's own commissioning windows; score = mean squared robust z over
the flattened (category × feature) bag. No graph, no attention, no embedding, no
cohort, no training, no order. Scored on exactly the rows the Inspector scored.

**On LANL:**

| | pooled AUC | within-host AUC |
|---|---|---|
| Inspector (205,546 params) | 0.741 | 0.542 ± 0.310 |
| bag Mahalanobis (~0 params) | 0.627 | 0.578 ± 0.273 |

Paired over the 77 hosts both cover: Inspector wins 36, bag wins 40, 1 tie,
mean difference −0.036, **exact two-sided sign test p = 0.731.**

**On synthetic data, which does contain the cross-service chain** — 700 hosts,
16 days, 3 seeds, 149 paired hosts (the test would detect an 87–62 split):

| | value |
|---|---|
| mean within-host AUC | Inspector 0.761 ± 0.010, bag 0.736 ± 0.009 (**+0.025**) |
| mean pooled AUC | Inspector 0.744 ± 0.013, bag 0.708 ± 0.007 (+0.036) |
| paired win rate | Inspector 70 / bag 79 |
| sign test | **p = 0.51** |
| median paired difference | **−0.006** |

**The honest reading.** The Inspector does not reliably beat a median-and-MAD,
on either corpus. But the *shape* is informative: mean positive, median
negative means it **wins large on a minority of hosts and loses small on the
majority.** Its value is concentrated, not general. This is a real finding and
it is the current open engineering question.

### 7.3 Router selection
*Source: `results.json` (synthetic), `lanl_novelty.json` (LANL)*

Three candidate routers, measured at equal escalation budget:

| router | synthetic AUC, 8 seeds | LANL AUC, 3 seeds |
|---|---|---|
| **A — distilled detector**, regresses the continuous teacher score | 0.833 ± 0.044 | **0.992 ± 0.003** |
| B — encoder + per-host Mahalanobis (KMeans k=3, Ledoit-Wolf shrinkage, 5% trim) | 0.804 ± 0.029 | **0.634 ± 0.007** |
| C — deferral head, BCE on "would the teacher flag this" | 0.839 ± 0.039 | not run |

**On synthetic data no pair is separable** (A vs C p = 0.74, A vs B p = 0.20,
B vs C p = 0.15, Wilcoxon, paired by seed). A 3-seed run had read as a clean
ranking — A 0.876, C 0.850, B 0.818 — and that was noise; A alone spans 0.735
to 0.885 across seeds. **Withdrawn.**

**Build A on the LANL evidence instead**, where the gap is not subtle: 0.992
against 0.634 agreement, and 35.6% against 3.3% attack recall at a 5% budget.
A is also the simplest — no second head, no per-host covariance. Router B's
decision lives in the student's embedding, and the student preserves the
teacher's geometry only partly: kNN overlap@20 is 0.35 synthetic, 0.44 LANL.
Report that overlap alongside any recall claim.

*Against our own case:* on **synthetic** data B's attack recall at a 5% budget
is 31.8% ± 6.4 to A's 15.0% ± 2.8 — it agrees with the teacher less and catches
the planted attacks more. On LANL that reverses (3.3% vs 35.6%), which is why A
is the recommendation, but the synthetic result is recorded rather than dropped.

Parameter counts: Inspector 205,546; Sentry 14,992; deferral head 2,369.

**Escalation budget curve on synthetic data** (router A, 8 seeds) — note how
much lower these are than the LANL curve, because the synthetic attacks are
stealthier by construction:

| budget | recall of teacher's flags | recall of attacks |
|---|---|---|
| 0.5% | 6.3% ± 0.5 | 1.8% |
| 1% | 11.3% ± 1.0 | 3.4% |
| 2% | 20.2% ± 2.0 | 6.4% |
| 5% | 35.7% ± 3.9 | 15.0% |
| 10% | 49.1% ± 5.0 | 26.0% |

### 7.4 Throughput
*Source: `escalate.json`, all three measured on the same single CPU core*

**Quote the ordering and the range, not a rate.** Three runs on the same 2-core
container, with nothing about the models changed between them:

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| Inspector | 70,950 | 104,385 | 93,700 |
| Sentry | 609,187 | 787,016 | 770,065 |
| hop-2 cohort | 1,869,524 | 2,918,707 | 3,153,056 |
| **Sentry : Inspector** | **8.59×** | **7.54×** | **8.22×** |

The spread is contention, not the models — best-of-3 timing does not remove it
when both cores are busy. `escalate.json` now records a timed 512×512 matmul as
`machine_reference` so two runs can be compared, and `verify_all.py` checks the
ordering and a 5–12× band instead of an exact rate.

**The Sentry is roughly 8× faster, not 13.7×.** 13.7 is the *parameter* ratio and
is not a speed claim — do not use it as one. The cohort computation is not the
bottleneck, which is worth knowing before anyone proposes optimising it.

### 7.5 The order ablation — a claim this killed
*Source: `ablation_order_hard.json`, 3 seeds, 120 hosts, 16 days, hard negatives on*

Permuting the hour axis is a *complete* ablation of order, because order enters
the model only through the positional embedding and the Transformer's attention.

| condition | AUC |
|---|---|
| A — full model | 0.998 ± 0.001 |
| B — hours shuffled at scoring time | 0.998 ± 0.001 |
| C — hours shuffled at train *and* score | 0.997 ± 0.001 |
| **D — bag of categories, order-free** | **1.000 ± 0.000** |
| E — Markov transitions only | 0.444 ± 0.055 |
| F — no reverse-direction features | 0.996 ± 0.002 |

**A − B = 0.000. The model is order-blind.** An order-free baseline (D) scores
*better* than the model. Therefore:

> 🔴 **"We detect the sequence" is withdrawn.** The correct claim is **"we detect
> the combination and the shape."**

Condition F is good news for the diode story: losing reverse-direction features
costs only 0.002 AUC, so the system genuinely survives unidirectional visibility.

Note also that 72.8% of the Inspector's parameters (149,568 of 205,546) are the
Transformer, plus 2,304 for the positional embedding — **74% of the model is the
part this ablation shows contributes nothing measurable.** That is the leading
open question in §10.

### 7.6 Cross-organisation transfer
*Source: `shift_results.json`, two synthetic worlds with different role mixes,
work hours, volumes and off-hours rates*

| | world A | world B |
|---|---|---|
| Inspector AUC | 0.873 ± 0.011 | 0.852 ± 0.008 |
| router AUC | 0.804 ± 0.040 | 0.825 ± 0.011 |
| attack recall @5% | 31.4% ± 7.5% | 37.2% ± 3.1% |
| flag rate | 6.7% | 6.3% |

**The mechanism transfers; the threshold does not.** A's 99th-percentile
threshold produces a 6.3% flag rate in world B — a 1.14× ratio. Note it also
produces 6.7% in world A's *own* test period, so the threshold decays over time,
not merely across networks. Every deployment needs its own calibration window
plus rolling recalibration.

### 7.7 The escalation loop, end to end
*Source: `escalate.json`, 200 hosts × 16 days, 5% window budget*

| | measured |
|---|---|
| windows escalated | 1,280 |
| host-days the Inspector had to re-run | **775 of 1,600 (48.4%)** |
| host-days confirmed at 3σ | 560 |
| confirmation precision | **12.7%** |

**The budget granularity finding.** The Inspector's unit of work is a host-day.
Selecting the worst 5% of *windows* scatters those windows across 48.4% of
host-days, so the Inspector runs on nearly half of them. **5% of windows is not
5% of Inspector load** — the ratio is 9.7×.

That directly corrects the cost claim. At 1,000 hosts:

| accounting | GPU host-days/year | reduction |
|---|---|---|
| inspect everything | 365,000 | — |
| the original claim (2%/host-day) | 19,467 | 94.7% |
| plus the audit budget | ~26,600 | 92.7% |
| **at the window budget the recall numbers actually use** | **~198,000** | **45.7%** |

**45.7% is the defensible number.** Still real, still worth having, and not what
was previously claimed. The recall curve has not yet been re-measured at
host-day granularity, so the cost claim and the recall claim currently describe
different systems — this is open work.

Confirmation precision of 12.7% also means the 3σ confirmation threshold is far
too loose. **Swept on 17 Sep — see §7.8.**

---

### 7.8 The confirmation threshold, swept — `sweep_threshold.json`

3 seeds × 200 hosts × 16 days, a 5% **host-day** escalation budget, pooled.
Synthetic, stealth 0.9–1.0, hard negatives on — the same setting `escalate.py`
uses.

| σ | precision | attack recall | alerts per 1,000 host-days |
|---|---|---|---|
| **3.0 — ships today** | **17.7%** | **15.4%** | **40.0** |
| 4.0 | 24.3% | 15.4% | 29.2 |
| 5.0 | 32.7% | 14.9% | 21.0 |
| **6.0 — best F1** | **40.3%** | **14.0%** | **16.0** |
| 8.0 | 50.0% | 12.7% | 11.7 |

Precision climbs steeply; recall is flat to about 5σ. So the operating point is
**not** max-F1 — F1 prices a missed attack and a wasted analyst-hour equally,
and no SOC does. Pick the loosest threshold your analysts can absorb.

At 100,000 hosts, on `gpu_cost.py`'s SOC assumptions, 3σ → 6σ is 90.5 → 36.3
analysts and **\$7.24M → \$2.90M a year**, for 1.4 points of recall.

**Two qualifications, both load-bearing.** Recall tops out near 15% because the
*budget*, not the threshold, is the binding constraint — no threshold recovers
an attack the router never escalated. And the routing does beat a coin: random
selection of 5% of host-days would catch 11.1 of 221 attack days, the router
caught 34 (**3.08×, p < 0.001**). That test now runs on every sweep, because a
recall figure at a fixed budget means nothing without it.

---

## 8. Operational machinery

### 8.1 Guarded rolling recalibration — `netsentinel_v2/calibration.py`

§7.6 shows the threshold must adapt. But naive adaptation is attackable: if the
system re-learns "normal" from whatever it sees, a patient attacker ramps up
slowly and drags the definition of normal along with them. `test_calibration.py`
demonstrates this happening.

Four guards:

1. **Admission by provenance, not by score.** Only windows drawn by the blind
   random audit can update the baseline. An attacker cannot volunteer training
   data by looking normal, because looking normal is not what gets you admitted.
2. **Bounded movement.** Any single update may move the threshold by at most a
   fixed number of MAD units.
3. **Freeze on incident.** While a host is under incident hold, its baseline does
   not adapt at all.
4. **Forward-only.** Recalibration never retroactively rescores history.

The audit sample is not free and must be counted in the budget alongside
escalations — that is the 94.7% → 92.7% step in §7.7.

### 8.2 The visibility gate — `netsentinel_v2/visibility.py`

A capture fault must not look like an attack. If the sensor stops naming flows,
everything lands in `Unknown_External`, the feature distribution shifts hard, and
the Inspector faithfully reports a large anomaly. It is right that something
changed and wrong about what.

The gate records the conditions a baseline was fitted under and returns one of
four actions: `score`, `warn_and_score`, `refuse` (which raises a **DATA_QUALITY**
ticket, not a security alert), or `recommission`.

**The case people get backwards:** a sensor *improvement* invalidates a baseline
just as thoroughly as a degradation. Moving from snaplen 512 to 0 moved a large
share of encrypted traffic out of `Unknown_External` into real categories. A
baseline fitted before that describes a different world; score the new corpus
against it and the entire estate flags on the day the capture got better. The
gate treats material improvement as a recommission trigger. Absolute floor:
named-flow ratio below 0.25 means the resolver is not working and nothing should
be scored.

### 8.0 The deployment split — `netsentinel_v2/tiers.py`

The cascade is deployed in two tiers, and the split is justified by two
structural properties of the models rather than by compute cost.

```
 EDGE — one site, local traffic only  |  CENTRAL — every host converges
 -------------------------------------+---------------------------------
 Sentry, 14,992 params, CPU           |  Inspector, 205,546 params, GPU
 scores EVERY HOUR                    |  consumes a WHOLE host-day
 needs no other host's data           |  needs the hop-2 cohort
 decides what crosses the boundary    |  returns the verdict
```

**The Sentry is causal; the Inspector is not.** The Sentry's aggregator is
per-window and its GRU is unidirectional, so the score at hour *t* depends only
on hours 0..*t*. `test_tiers.py` asserts this numerically: scoring a truncated
day equals the corresponding slice of scoring the whole day to within
1e-5. The Inspector is a Transformer with a 24-slot positional embedding, so
hour 3's representation depends on hour 20 — measured drift of 0.032 when given
a partial day. It cannot answer before the day closes, at any amount of compute.

**The Inspector needs other hosts; the Sentry does not.** The hop-2 cohort is
the mean of *other* hosts' edges in the same (day, window, category). Blanking
it moves the Inspector's output by 0.410. That data does not exist at a single
diode-separated site, which is why the Inspector is central. The Sentry never
asks for it.

**The audit rate is a per-host dial, and it contains full inspection.** A
router that misses something never escalates it. The measured miss rate against
the teacher at a 5% budget is **3.1%**, and the blind audit is the only thing
that finds the rest, so its rate sets the worst-case detection time:
`ETTE = 1 / (audit_rate × P(detect | inspected))`.

| tier | audit | budget | Inspector load | worst-case ETTE (P=0.5) |
|---|---|---|---|---|
| crown_jewel | 100% | 100% | 100% | every day |
| elevated | 20% | 10% | 33% | 10 days |
| standard | 5% | 5% | 13% | 40 days |
| bulk | 2% | 5% | 10% | 100 days |

At `audit_rate = 1.0` every host-day reaches the Inspector regardless of the
router — that is exactly "inspect everything", with the hourly Sentry score
kept on top. **The cascade contains full inspection rather than substituting
for it**, and because the dial is per host, a domain controller can run at 1.0
while ten thousand endpoints run at 0.02. A single global mode cannot express
that. What caps the dial is analyst capacity, not compute (§7.4, `gpu_cost.py`).

**Escalation packets carry history.** `EscalationPacket` crosses the boundary
with the closing day, the preceding days, the triggering hour, the visibility
flags, the host's lifecycle state, and the reason it crossed. Handing the
Inspector one isolated hour would remove the combination the hypothesis is
about.

**Load is reported by cause, because only part of it is a budget.** Measured on
a 200-host, 8-day mixed-tier fleet (`deploy_c.json`): 173 of 1,600 host-days
inspected (10.8%) — 51% audit-driven, 45% router-driven, 4% churn. Escalation
is budgeted, audit is chosen, churn is absorbed. Quoting one figure for
"Inspector load" hides which of the three is moving.

**Measured latency benefit**, same run: the Sentry raised its peak score at
hour 17 median (IQR 15–19), against an Inspector that could not have answered
before hour 24 — a median of 7 hours earlier. Note this is architecture
behaviour on untrained models, not a detection claim.

`test_tiers.py` — 17 checks, all passing.

### 8.3 Per-host lifecycle — `netsentinel_v2/lifecycle.py`

Five states: `COMMISSIONING`, `SENTRY_PRIMARY`, `ESCALATED`, `INCIDENT_HOLD`,
`RECOMMISSIONING`.

**Promotion is on evidence, not on a 14-day timer.** Two weeks on a developer's
laptop is plenty of evidence; two weeks on a server whose only interesting
behaviour is a monthly backup is none, and a timer promotes it anyway. Gates
(all starting settings, none validated — say so when presenting them):

- ≥ 240 live windows
- ≥ 10 distinct days
- a weekend must have been observed
- ≥ 200 reference samples, which is what calibration needs to fit
- named-flow ratio ≥ 0.50
- score drift ≤ 0.35σ
- Sentry-vs-Inspector disagreement ≤ 0.20
- no open incident, visibility not degraded

When a host is blocked, the system reports exactly which gates it failed.

**Two things that are commonly misunderstood:**

*The Sentry runs from day one*, in parallel with the Inspector, not after
commissioning. Commissioning is the only period that yields free labels for
"would the teacher have flagged this" — which is precisely the router's training
target. Waiting would discard the data the router needs.

*The Inspector never stops.* After promotion it still sees every escalation, the
blind random audit sample, and a host's full history on confirmation. It steps
back; it does not leave.

`INCIDENT_HOLD` is deliberately not terminal, and release is always explicit and
human. "Suspicious hosts stay on the Inspector forever" sounds safe and is not
survivable — false positives, legitimate change and deliberately noisy traffic
would consume the entire budget within weeks.

---

## 9. Repository map

```
netsentinel_v2/
  models.py         Inspector, Sentry, DeferralHead, EdgeAggregator, recon_error
  train.py          commissioning, distillation, router heads, budget_curve
  categories.py     the 9 LOTS categories, the 10 edge features
  synth.py          the generator; hard_negatives=True by default
  lanl_loader.py    cyber1 -> tensors; port taxonomy, novelty features, caching
  zeek_loader.py    Zeek logs -> tensors (our own capture)
  quic.py           RFC 9001 §5.2 QUIC Initial decryption (needs `cryptography`)
  baseline.py       HostBaseline — KMeans + Ledoit-Wolf Mahalanobis (router B)
  hostnorm.py       per-host robust z-scoring, within_host_auc
  calibration.py    guarded rolling recalibration
  visibility.py     the data-quality gate
  lifecycle.py      per-host state machine
  cost_model.py     GPU accounting, window->host-day conversion

experiments (each writes the .json beside it)
  run_experiment.py   synthetic, routers A/B/C        -> results.json
  train_real.py       LANL and Zeek runner            -> lanl_novelty*.json
  lanl_p0b.py         Inspector vs bag, paired, LANL  -> lanl_p0b.json
  paired_synth.py     the same test on synthetic      -> paired_synth.json
  confound_test.py    busy-host confound experiments  -> confound_test.json
  ablation_order.py   order + diode ablations         -> ablation_order_hard.json
  escalate.py         throughput + the escalation loop-> escalate.json
  shift_test.py       world A vs world B              -> shift_results.json
  capture_probe.py    what the sensor can see         -> capture_probe.json
  deploy_c.py         Option C on a mixed-risk fleet  -> deploy_c.json

tests
  test_quic.py        16 checks vs RFC 9001 Appendix A.1 vectors
  test_contracts.py   32 feature-contract checks
  test_lifecycle.py   19 visibility-gate + state-machine checks
  test_tiers.py       17 checks on the Option C split (causality, dial)
  test_calibration.py poisoning demo + audit-budget sweep
  test_lanl_loader.py 53 assertions on the LANL loader
```

**Commands.**

```bash
# LANL, with both caches present -- no flows.txt.gz needed, only redteam.txt
python train_real.py --lanl --data . --max-hosts 500 --lanl-days 13 \
       --seeds 3 --out lanl_novelty.json
python train_real.py --lanl --data . --max-hosts 500 --lanl-days 13 \
       --seeds 3 --host-normalise --out lanl_novelty_hn.json
python lanl_p0b.py   --data . --max-hosts 500 --lanl-days 13

# synthetic
python run_experiment.py --seeds 3 --hard-negatives
python paired_synth.py --hosts 700 --days 16 --seeds 3
python ablation_order.py --hard-negatives --stealth-lo 0.9 --stealth-hi 1.0

# the sensor
python capture_probe.py <specific .pcap files>   # NOT --limit; see below
```

`capture_probe.py --limit N` sorts filenames alphabetically and takes the last
N. The capture ring restarted its numbering, so old high-numbered files can sort
after new low-numbered ones and you will silently probe the wrong era. Name the
files explicitly.

---

## 10. Open work, in priority order

1. **Test whether the Transformer earns its place.** 74% of the Inspector is the
   Transformer plus positional embedding, and the order ablation says that path
   contributes 0.000 AUC. Build an "Inspector-lite" — EdgeAggregator + hop-2
   cohort + mean-pool, no Transformer, roughly 54,000 parameters — and run the
   §7.2 paired comparison against both the full Inspector and the bag baseline.
   If it matches, ship it: the honest story becomes "we ablated 74% of our own
   parameters away after measuring that they did nothing", which is stronger than
   the current position.
2. **Re-measure the recall curve at host-day granularity** so the cost claim and
   the recall claim describe the same system (§7.7).
3. ~~**Tune the confirmation threshold.**~~ **DONE 17 Sep**, §7.8. 3σ → 6σ takes
   confirmation precision 17.7% → 40.3% and alerts per 1,000 host-days 40.0 →
   16.0, for 1.4 points of attack recall — \$7.24M → \$2.90M a year at 100k
   hosts. **What replaces it:** sweep the *escalation budget*, which is now what
   caps recall.
4. **Send history with escalations** — the window, the preceding sequence, the
   graph neighbourhood, the visibility flags, and the reason. Handing the
   Inspector a single isolated window can remove the very thing it needs.
5. **Run the own-capture corpus** once there are ~5 days of snaplen-0 data. It is
   the only corpus that can test the actual cross-service hypothesis.
6. **Understand where the Inspector's concentrated advantage lives** (§7.2) — it
   wins large on a minority of hosts. Which hosts, and why?

---

## 11. Claims discipline

**Say these:**
- "The Sentry is a router, not a detector."
- "96.9% of the *Inspector's flags* are recovered at a 5% budget."
- "Within-host AUC 0.557 ± 0.013 on LANL. That is near chance, and it is our
  weakest number." — lead with this if asked what is weakest.
- "We detect the combination and the shape."
- "The Inspector is GraphIDS-shaped, arXiv:2509.16625. Ours is the cross-service
  category semantics and the chain dataset."
- "45.7% GPU reduction at the budget granularity our recall numbers use."
- "About 8× faster by measured throughput" — 7.5–8.6× over three runs.

**Never say these:**
- "95% recall", or "96.9% recall" without "of the Inspector's flags"
- any Tier 2 detection rate as a product claim
- "0.745" without the busy-host confound attached
- "13.7× faster" — that is the parameter ratio, not a speed measurement
- "94.7% GPU reduction" — superseded by 45.7%
- "we detect the sequence" — withdrawn by ablation
- "55% of DNS is hidden by DoH" — retracted, we have no denominator
- "router A beats C and B" on synthetic data — withdrawn at 8 seeds; they tie
- any single-decimal throughput figure — three runs on one machine spanned
  7.5–8.6×
- state of the art / novel transformer / replaces EDR / the Inspector
  architecture is ours

**The stance that makes all of this work:** every one of the retractions above
was found by us, testing our own claims, and written down before anyone asked.
A panel that catches a team hiding a weakness punishes it. A panel that watches
a team argue against itself and survive the argument does the opposite. The
0.557, the order ablation, the 45.7% and the paired tie are not damage — they
are the evidence that the rest of the numbers can be trusted.
