# The Inspector–Sentry Cascade — complete specification

**NetSentinel Tier 2, as it stands on 13 September 2026.**
Everything needed to understand, run, defend or extend the system, from zero.

**The rule this document is written under:** every number below comes from a
`.json` file produced by a script in this repository, and the file is named
next to the number. Nothing is estimated, rounded up, or carried over from an
earlier draft. If a figure is not in one of those files, it does not appear
here and must not appear on a slide.

---

## 1. The problem

Detect an insider — or a compromised account — moving through cloud services,
using nothing but passively captured network traffic, on a network where you
cannot install anything on the endpoint.

The deployment target is behind a **data diode**: a one-way optical link used
in nuclear, defence and SCADA environments. Traffic leaves, nothing returns.
That rules out EDR agents, active scanning, TLS interception, and any inline
device. What you get is a mirror of egress packets and nothing else.

**The hypothesis.** Someone doing something they shouldn't tends to combine
*categories of service* in a way a machine normally doesn't: an internal recon
API, then a code-paste site, then a messaging API. Each is unremarkable alone.
The combination, on that host, is not.

Most anomaly detection scores flow statistics or individual destinations. A
91-study review of graph-based NIDS found no published system scoring
cross-service category combinations per host. **That is the only novelty
claimed.** The cascade, the knowledge distillation and per-entity baselining
are all established prior art. The Inspector's architecture is GraphIDS-shaped
(arXiv:2509.16625) and is not ours.

---

## 2. Why there are two models

Not cost. That was the original reason and it does not survive measurement: at
100,000 hosts with a teacher a thousand times larger than ours, inspecting
every host-hour for a year costs about **$150** (`gpu_cost.py`). The two
reasons that do survive are structural properties of the models, and both are
asserted numerically in `test_tiers.py` rather than argued.

**1 — The Sentry is causal. The Inspector is not.**
The Sentry's aggregator is per-window and its GRU is unidirectional, so its
score at hour *t* depends only on hours 0..*t*. Measured: scoring a truncated
day equals the corresponding slice of scoring the whole day to within
**4 × 10⁻⁶**. It can answer every hour.
The Inspector is a Transformer with a 24-slot positional embedding, so hour 3's
representation depends on hour 20. Measured drift when handed a partial day:
**0.032**. It cannot answer before the day closes, at any amount of compute.

**2 — The Inspector needs other hosts. The Sentry does not.**
The hop-2 cohort term is the mean of *other* hosts' edges in the same
(day, window, category). Blanking it moves the Inspector's output by **0.410**.
That data does not exist at a single diode-separated site. The Sentry never
asks for it.

Those two facts place the models. They are not preferences.

---

## 3. Architecture

### 3.1 The whole pipeline

```
┌─────────────────────────── SENSOR (settled, measured) ───────────────────────┐
│                                                                              │
│  Network TAP / SPAN                                                          │
│         │                                                                    │
│         ▼                                                                    │
│  Data diode  ── one-way, egress only ──                                      │
│         │                                                                    │
│         ▼                                                                    │
│  dumpcap ring buffer   snaplen 0 (whole packets), 1 file/hour,               │
│         │              312-file ring ≈ 40 GB ≈ 13 days retained              │
│         ▼                                                                    │
│  Zeek 8.x  +  QUIC Initial decryption (RFC 9001 §5.2)                        │
│         │                                                                    │
│         ├──► conn.log   volume + timing                                      │
│         ├──► ssl.log    TLS SNI                                              │
│         ├──► dns.log    query → A record                                     │
│         └──► QUIC SNI   from the Initial packet                              │
│                          │                                                   │
│                          ▼                                                   │
│  Service category resolver  — deterministic regex taxonomy, NOT a model      │
│                          │                                                   │
│                          ▼                                                   │
│  1-hour windowing → edge tensor                                              │
│      edges[host, day, window, category, feature]   (H, D, 24, 9, 10)         │
│      mask [host, day, window, category]                                      │
└──────────────────────────────────────────────────────────────────────────────┘
                                     │
        ┌────────────────────────────┴─────────────────────────────┐
        │                                                          │
        ▼                                                          ▼
╔═══════════════════════════════╗   boundary   ╔═══════════════════════════════╗
║  EDGE TIER                    ║══════════════║  CENTRAL TIER                 ║
║  one site, local traffic only ║              ║  every host converges here    ║
╠═══════════════════════════════╣              ╠═══════════════════════════════╣
║                               ║              ║                               ║
║  SENTRY   14,992 params  CPU  ║              ║  INSPECTOR 205,546 params GPU ║
║  ┌─────────────────────────┐  ║              ║  ┌─────────────────────────┐  ║
║  │ EdgeAggregator          │  ║              ║  │ EdgeAggregator          │  ║
║  │   (NO cohort)           │  ║              ║  │   + hop-2 cohort        │  ║
║  │        ↓                │  ║              ║  │        ↓                │  ║
║  │ GRU 32, unidirectional  │  ║              ║  │ + positional emb (24)   │  ║
║  │        ↓                │  ║              ║  │        ↓                │  ║
║  │ Linear 32→96            │  ║              ║  │ Transformer ×2, dim 96  │  ║
║  │   (distillation head)   │  ║              ║  │   4 heads, ffn 192      │  ║
║  └─────────────────────────┘  ║              ║  │        ↓                │  ║
║             │                 ║              ║  │ decoder → recon error   │  ║
║   scores EVERY HOUR           ║              ║  └─────────────────────────┘  ║
║             │                 ║              ║   consumes a WHOLE host-day   ║
║             ├──► hourly score ║              ║             │                 ║
║             │    same-day     ║              ║             ▼                 ║
║             │    triage       ║              ║   verdict: confirm / release  ║
║             │                 ║              ║             │                 ║
║             ▼                 ║              ║             ▼                 ║
║   at day close, decide:       ║              ║   MITRE mapping → alert       ║
║     1. blind audit draw?      ║              ║                               ║
║     2. commissioning /        ║              ║                               ║
║        recommission /         ║              ║                               ║
║        incident state?        ║              ║                               ║
║     3. router score ≥ cut?    ║              ║                               ║
║             │                 ║              ║                               ║
║             ▼                 ║              ║                               ║
║   EscalationPacket ═══════════╬══════════════╬══► ingest                     ║
║     · the closing day         ║              ║                               ║
║     · preceding days          ║              ║                               ║
║     · triggering hour         ║              ║                               ║
║     · visibility flags        ║              ║                               ║
║     · lifecycle state         ║              ║                               ║
║     · reason it crossed       ║              ║                               ║
╚═══════════════════════════════╝              ╚═══════════════════════════════╝
                                                             │
                     ┌───────────────────────────────────────┘
                     │  anomaly-weighted ENCODER distillation, λ = 4
                     │  (runs during commissioning; teaches the Sentry)
                     ▼
              back to the SENTRY
```

### 3.2 The time axis — one host's life

```
 day 0                          promotion                        ongoing
   │                                │                                │
   ▼                                ▼                                ▼
   ├────── COMMISSIONING ───────────┼────── SENTRY_PRIMARY ──────────┤
   │                                │                                │
INSPECTOR                           │                                │
   ████████████████████████████     │    ▉      ▉       ▉      ▉     │
   every host-day                   │    escalations + blind audit   │
   │                                │    ── never fully idle ──      │
   │  teaches (this is the ONLY     │                                │
   │  source of router labels)      │      ▲ escalate  │ verdict     │
   ▼                                │      │           ▼             │
SENTRY                              │                                │
   ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄      │    ██████████████████████████  │
   running + learning               │    scores every hour, routes   │
                                    │                                │
                          PROMOTION GATE — evidence, not a timer:
                          ≥240 live windows · ≥10 distinct days
                          a weekend observed · ≥200 reference samples
                          named-flow ratio ≥0.50 · score drift ≤0.35σ
                          Sentry↔Inspector disagreement ≤0.20
                          no open incident · visibility not degraded
```

**Two things people get wrong.** The Sentry runs from **day one**, in parallel,
not after commissioning — commissioning is the only period that produces its
training labels ("would the teacher have flagged this"), so starting it later
throws the training set away. And the Inspector **never fully idles** — it
keeps a blind random audit sample forever, because otherwise nothing detects
the Sentry drifting away from it.

### 3.3 State machine

```
   ┌──────────────────┐  gates met   ┌──────────────────┐
   │  COMMISSIONING   │─────────────►│  SENTRY_PRIMARY  │
   └──────────────────┘              └────────┬─────────┘
                                       ▲      │  router score over cut
                                       │      ▼
                          resolved   ┌──────────────────┐
                          benign     │    ESCALATED     │
                          ───────────└────────┬─────────┘
                                              │ Inspector confirms
                                              ▼
   ┌──────────────────┐  gates met   ┌──────────────────┐
   │ RECOMMISSIONING  │◄─────────────│  INCIDENT_HOLD   │
   └────────┬─────────┘  EXPLICIT    └──────────────────┘
            │            human        baseline adaptation FROZEN
            │            release      (deliberately not terminal)
            └──► SENTRY_PRIMARY

   SENTRY_PRIMARY ──► RECOMMISSIONING  when the visibility gate says
                                        the baseline is stale
```

---

## 4. The data representation

Every input source reduces to one tensor.

```
edges[host, day, window, category, feature]   float32
mask [host, day, window, category]            1.0 where that edge exists
```

24 windows per day, one hour each. A **live** window is one where
`mask.sum(-1) > 0`; empty windows are excluded from every metric.

### 4.1 The nine categories

Which nine depends on the corpus.

| own capture / synthetic (LOTS taxonomy) | LANL cyber1 (port-derived) |
|---|---|
| `Recon_API` | `Directory` — Kerberos / LDAP / GC |
| `Code_Repo_Paste` | `FileShare` — SMB / NFS |
| `Messaging_API` | `RemoteAccess` — RDP / SSH / WinRM / VNC |
| `Cloud_Storage` | `Mail` — SMTP / IMAP / POP |
| `Browse` | `WebProxy` — HTTP(S) / proxy ports |
| `Sync` | `Database` — MSSQL / Oracle / MySQL / PG |
| `CI_CD` | `Infra` — DNS / NTP / SNMP / RPC / syslog |
| `Internal` | `Workstation` — peer-to-peer, low fan-in |
| `Unknown_External` | `Unknown` — numeric-but-unmapped |

`Unknown_External` is a deliberate outcome for ECH, DoH and raw-IP traffic, not
a failure. Lost visibility is itself a signal.

### 4.2 The ten features

| # | feature | what it captures |
|---|---|---|
| 0 | `log_n_flows` | volume |
| 1 | `log_bytes_up` | outbound volume |
| 2 | `log_bytes_down` | inbound volume |
| 3 | `egress_asymmetry` | up/down ratio — the exfiltration signal |
| 4 | `iat_cv` | inter-arrival coefficient of variation — beaconing |
| 5 | `ks_uniform` | KS distance from uniform inter-arrivals |
| 6 | `ks_exponential` | KS distance from exponential inter-arrivals |
| 7 | `fft_prominence` | periodicity — automation |
| 8 | `distinct_endpoint_ratio` | → 1.0 means a domain randomiser |
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

**On LANL only**, slots 2 and 3 are unusable: cyber1 logs one byte count, not a
directional pair. Those two slots instead carry `new_peer_ratio` and
`new_service_flag`. Without that substitution, LANL within-host AUC was
0.526 ± 0.308 — chance. Volume and timing alone cannot separate a
credential-based hop from an administrator's Tuesday.

---

## 5. Model specifications

### 5.1 EdgeAggregator — shared

```
hop-1 message = MLP([ edge_features(10) ‖ category_embedding(16) ‖ cohort(10)? ])
window vector = MLP([ mean_c(message), max_c(message), presence_mask(9) ])
```

The category embedding is what stops the model memorising infrastructure. The
cohort term is the sampled hop-2 neighbourhood — Inspector only.

One implementation detail that was a real bug: the max-pool must be guarded on
the **true edge count**, not the denominator. The denominator is clamped to ≥1
and so is never zero, which let a `-1e9` sentinel escape into the encoder on
every empty window and blew first-epoch loss to ~1e12.

### 5.2 Inspector — the teacher

| component | params | share |
|---|---|---|
| `seq` — TransformerEncoder ×2, dim 96, 4 heads, ffn 192, norm_first | 149,568 | 72.8% |
| `agg` — EdgeAggregator with cohort | 41,712 | 20.3% |
| `dec` — decoder | 11,818 | 5.7% |
| `pos` — positional embedding, 24 slots | 2,304 | 1.1% |
| `cat_emb` — category embedding | 144 | 0.1% |
| **total** | **205,546** | |

Trained as a **denoising autoencoder**: 25% of present edges are hidden from
the encoder; the decoder must reconstruct all of them. Reconstruction error is
the anomaly score. **Fully unsupervised — it never sees an attack label**, in
training or in threshold selection. Threshold = 99th percentile of
reconstruction error over the commissioning window.

Unit of work: a **whole host-day**, never a single window.

### 5.3 Sentry — the student and router

EdgeAggregator (no cohort) → GRU dim 32, unidirectional → Linear 32→96
projection head. **14,992 parameters.** Deferral head, when used: 2,369.

### 5.4 The distillation

```
L = E[ (1 + λ · s_teacher) · ‖ project(f_student) − f_teacher ‖² ]      λ = 4
```

The Sentry is distilled on the teacher's **encoder representation**, weighted
toward high-anomaly windows — never on its binary verdict. Motivation: MDPI
MAKE 8(3):60 measured that in ordinary distillation, *global* outlier structure
transfers at ~78% while *local* outlier structure transfers at only ~20%. Local
structure is exactly what an anomaly router needs, so it has to be weighted for
explicitly. **Distil the eyes, never the verdict.**

The router predicts *the teacher's decision*, not its own uncertainty.
Confidence-based deferral is provably suboptimal under distribution shift,
specialist downstream models and label noise — all three describe an IDS
(Jitkrittum et al., NeurIPS 2023, arXiv:2307.02764).

---

## 6. The audit dial — coverage of the router's blind spots

A router that misses something never escalates it, and the Inspector never gets
a chance. **Measured miss rate against the teacher at a 5% budget: 3.1%** — the
Sentry recovers 96.9% of the Inspector's flags, so roughly one in thirty-two
dies at the router.

The blind random audit is the only thing that finds the rest, so its rate sets
worst-case detection time:

```
ETTE = 1 / ( audit_rate × P(detect | inspected) )
```

Audit is drawn **before the score is consulted**, which is what makes audited
windows admissible to calibration by provenance rather than by score.

### 6.1 Risk tiers — the dial is per host

| tier | audit | escalation budget | Inspector load | worst-case ETTE (P=0.5) |
|---|---|---|---|---|
| `crown_jewel` | 100% | 100% | 100% | every day |
| `elevated` | 20% | 10% | 33% | 10 days |
| `standard` | 5% | 5% | 13% | 40 days |
| `bulk` | 2% | 5% | 10% | 100 days |

At `audit_rate = 1.0` every host-day reaches the Inspector regardless of the
router — that is exactly "inspect everything", with the hourly Sentry score
kept on top. **The cascade contains full inspection rather than substituting
for it.** A domain controller runs at 1.0 while ten thousand endpoints run at
0.02, in one deployment. A single global mode cannot express that.

What caps the dial is **analyst capacity, not compute** — every audited
host-day the Inspector flags becomes an alert someone must triage.

---

## 7. Operational machinery

### 7.1 Visibility gate — `netsentinel_v2/visibility.py`

A capture fault must not look like an attack. If the sensor stops naming flows,
everything lands in `Unknown_External`, the feature distribution shifts hard,
and the Inspector faithfully reports a large anomaly. It is right that
something changed and wrong about what.

Four outcomes: `score`, `warn_and_score`, `refuse` (raises a **DATA_QUALITY**
ticket, not a security alert), `recommission`. Absolute floor: named-flow ratio
below 0.25 means the resolver is not working.

**The case people get backwards:** a sensor *improvement* invalidates a
baseline exactly as thoroughly as a degradation. Moving snaplen 512 → 0 moved a
large share of encrypted traffic out of `Unknown_External` into real
categories; a baseline fitted before that describes a different world, and
scoring the new corpus against it flags the whole estate on the day the capture
got better. Material improvement is a recommission trigger.

### 7.2 Guarded rolling recalibration — `netsentinel_v2/calibration.py`

Thresholds decay, so they must adapt — but naive adaptation is attackable: a
patient attacker ramps slowly and drags "normal" along. Four guards:

1. **Admission by provenance, not score.** Only blind-audited windows update
   the baseline. An attacker cannot volunteer training data by looking normal,
   because looking normal is not what gets you admitted.
2. **Bounded movement.** Any update moves the threshold by at most a fixed
   number of MAD units.
3. **Freeze on incident.** A host under incident hold does not adapt at all.
4. **Forward-only.** Recalibration never retroactively rescores history.

### 7.3 Lifecycle — `netsentinel_v2/lifecycle.py`

Five states as diagrammed in §3.3. Promotion gates as listed there. Every
threshold is a **starting setting, not a validated constant** — say that when
presenting them. When a host is blocked the system names which gates it failed.

`INCIDENT_HOLD` is deliberately not terminal. "Suspicious hosts stay on the
Inspector forever" sounds safe and is not survivable — false positives,
legitimate change and deliberately noisy traffic would consume the whole budget
within weeks. Release is always explicit and human.

---

## 8. The datasets — what each one can and cannot test

### 8.1 LANL cyber1 — the only real attack labels

Kent (2015), "Comprehensive, Multi-Source Cyber-Security Events". 58 days of a
real enterprise network, ~17,700 computers, **749 labelled red-team
authentication events**. From `https://csr.lanl.gov/data/cyber1/`;
`flows.txt.gz` and `redteam.txt.gz`.

**Configuration used:** `--max-hosts 500 --lanl-days 13`. Keeps the 500 busiest
hosts by client-side flow count, then force-includes 112 red-team computers
that had client traffic but did not rank — evaluating attack recall on a host
set that excludes the attacked hosts would be worthless. Result **H = 612 hosts
× 13 days**; commissioning days 0–5, validation gap 6–7, test days 8–12;
**39,492 live test windows, 131 attack windows on 80 hosts**, of which 77 hosts
carrying 106 positives are scoreable for within-host AUC.

**What it cannot test.** Every computer is de-identified to `C1065`, so there
are no nameable SaaS destinations and the LOTS taxonomy would collapse to ~100%
`Internal`. The loader substitutes a port-derived taxonomy — measured
distribution FileShare 29.0%, Infra 24.6%, Directory 17.2%, WebProxy 16.8%,
Workstation 6.5%, Unknown 4.0%, Database 1.1%, RemoteAccess 0.6%, Mail 0.1%.
**LANL evaluates a proxy task**, not the cross-service hypothesis.

Two loader details that are load-bearing: LANL does not normalise flow
direction and anonymises ephemeral ports as `N#####`, so the service port is
taken as `min(numeric ports)` and the endpoint holding the ephemeral port is
treated as the client — a destination-port resolver gets the direction
backwards on the dataset's own example row. And fan-in thresholds for "is this
a server" are measured from a first streaming pass (p90/p99), not hard-coded.

Labels are auth events naming a source and destination computer;
`label_policy=both` marks both. Measured on this run: **1 of 4** red-team
source computers and **119 of 301** destinations were modelled hosts — most
destinations are servers with no client-side traffic.

**Caching.** Both expensive passes are cached (`lanl_profile.json`,
`lanl_tensors_H612_D13_nov1_b6.npz`). With both present the raw 12 GB file is
not needed at all — only `redteam.txt` for the labels. The cache key encodes
hosts, days and the novelty flag.

### 8.2 Synthetic generator — `netsentinel_v2/synth.py`

Full 9-category LOTS taxonomy, real egress semantics, injected LOTS-LSA chains.
Tests the mechanism where the hypothesis can fire. **Not** evidence of
real-world performance — a detector evaluated on the generator that produced
its attacks is partly learning the generator.

`hard_negatives=True` by default and it matters: without it, one trivial rule —
"the host with the longest unbroken `Messaging_API` run" — scores AUC **1.000**.
With hard negatives (35% "chatty" hosts, 25% "poller" hosts) it drops to
**0.797**.

### 8.3 Our own capture — the only corpus with named egress

Six laptops, dumpcap ring buffer, hourly rotation, Windows scheduled task as
SYSTEM. **snaplen 0 (whole packets) since 12 Sep 12:03 IST.** The only corpus
that can test the actual hypothesis. Does not yet have enough post-fix days for
a commissioning/test split.

### 8.4 Evaluated and rejected

| dataset | why |
|---|---|
| WRCCDC 2018 | 1,021,950 conn records, 15,070 SNI names, 664 hosts, 77.3% resolver hit rate — but **one day only**, so no host can be baselined |
| Stratosphere Normal Captures | host unreachable from our network |
| Unified Host and Network (2017) | has directional bytes, **no red-team labels**. Labels or directionality, not both |

---

## 9. Every measured number

### 9.1 Sensor — `capture_probe.json`

2 files, 173,682 packets.

| | measured |
|---|---|
| snaplen recorded in files | 262,144 (dumpcap "whole packet") |
| packets truncated | **0 (0.0%)** |
| TLS ClientHellos seen | 342 |
| hostname recovered | **308 (90.1%)** |
| median snaplen needed | 654 bytes |
| 95th percentile | 2,041 bytes |
| ClientHellos split across TCP segments | **159 (46.5%)** |
| Encrypted Client Hello present | 32 |
| plaintext DNS queries readable | 1,002 |
| distinct names queried | 65 |
| DoH endpoint connections | 0 |
| distinct named destinations | 55 |

**Snaplen coverage:** 160 → 0.0% of ClientHellos whole · 512 → 16.7% ·
1024 → 53.5% · **1500 → 53.5%** · 2048 → 95.6% · 4096 → 100%.

Note the flatline between 1024 and 1500 — that is the ethernet MTU. Once a
handshake exceeds one packet a bigger capture buffer cannot help. **46.5% need
TCP reassembly**, which is Zeek's job. Two claims, not one: whole packets fix
*truncation*, Zeek reassembly handles *fragmentation*.

**Why snaplen 0.** At 512, **0 of 805 QUIC Initial packets** were readable —
RFC 9000 requires a client Initial padded to ≥1,200 bytes, measured median
1,230. QUIC hostname recovery uses the salt published in RFC 9001 §5.2 plus the
client's own cleartext Connection ID; anyone can compute it, only the SNI is
extracted, no user payload is decrypted. Verified against the RFC's Appendix
A.1 vectors — **16 checks, all exact**. Requires the `cryptography` package.

**Retracted, so nobody reintroduces it:** an earlier "55% of DNS hidden by DoH"
figure counted bootstrap lookups *of the resolver's own hostname*. We cannot
see hidden queries, so we have no denominator. Report counts, never a
percentage.

### 9.2 LANL cyber1 — `lanl_novelty.json`, `lanl_novelty_hn.json`, 3 seeds

| metric | value |
|---|---|
| Router A AUC — agreement with the teacher | **0.992 ± 0.003** |
| Router B AUC | 0.634 ± 0.007 |
| Inspector pooled AUC, window-level | 0.745 ± 0.002 ⚠ **confounded** |
| Inspector pooled AUC, day-level | 0.639 ± 0.004 |
| **Inspector within-host AUC** | **0.557 ± 0.013** |
| Inspector flag rate | 2.56% |
| kNN geometry overlap @20 | 0.439 |
| runtime, 3 seeds, CPU | 843 s |

**Escalation budget curve** (router A, window-level, 3-seed mean):

| budget | recall of the *teacher's flags* | recall of *actual attacks* |
|---|---|---|
| 1% | 37.7% | 11.5% |
| 2% | 68.0% | 19.3% |
| 5% | **96.9%** | **35.6%** |
| 10% | 99.0% | 44.3% |

**These two columns are different quantities.** 96.9% is routing fidelity — how
much of the Inspector's own output the Sentry recovers. 35.6% is how many real
attacks were caught. Never say "96.9% recall" without "of the Inspector's
flags". Never quote a Tier 2 detection rate as a product claim. "95% recall"
was once proposed and is withdrawn.

### 9.3 The busy-host confound

Attacked hosts in LANL are simply *busier*: live-window density **0.811** vs
**0.530**. Scoring each window against its own host's commissioning
distribution (`--host-normalise`):

| metric | baseline | per-host scored | delta |
|---|---|---|---|
| pooled window AUC | 0.745 ± 0.002 | **0.618 ± 0.021** | **−0.127** |
| pooled day-level AUC | 0.639 ± 0.004 | 0.487 ± 0.024 | −0.152 |
| within-host AUC | 0.557 ± 0.013 | 0.560 ± 0.015 | +0.003 |
| flag rate | 2.6% | 2.0% | −0.6 pts |

Within-host did not move, and that is arithmetic rather than failure: it ranks
each host's windows against that host's own, and a per-host z-score is strictly
increasing inside each host, so it cannot change a ranking. The +0.003 residual
comes from 32 of 612 hosts having under 20 live commissioning windows and
falling back to the pooled scale.

**The pooled collapse is the finding.** Most of the gap between 0.745 and 0.557
was cross-host busyness. **0.557 is the confound-free number, it is near
chance, and 0.745 must never be quoted without this attached.** One alternative
reading cannot be excluded: if attacked hosts are busier *because* compromised,
per-host scoring destroyed real signal. Nothing here distinguishes those.

### 9.4 Is the graph model worth its parameters? — `lanl_p0b.json`, `paired_synth.json`, `lanl_ensemble.json`

The baseline: per host, a median and a MAD over that host's own commissioning
windows; score = mean squared robust z over the flattened (category × feature)
bag. No graph, no attention, no embedding, no cohort, no training, no order.
Scored on exactly the rows the Inspector scored.

**On LANL**, paired over the 77 hosts both cover:

| | pooled | within-host |
|---|---|---|
| Inspector (205,546 params) | 0.741 | 0.542 ± 0.310 |
| bag Mahalanobis (~0 params) | 0.627 | **0.578 ± 0.273** |

Inspector wins **36**, bag wins **40**, 1 tie, mean difference −0.036,
exact two-sided sign test **p = 0.731**.

**On synthetic data that does contain the chain** — 700 hosts, 16 days, 3
seeds, 149 paired hosts (the test would detect an 87–62 split):

| | value |
|---|---|
| mean within-host AUC | Inspector **0.761**, bag **0.736** (+0.025) |
| mean pooled AUC | Inspector 0.744, bag 0.708 (+0.036) |
| paired win rate | 70 / 79 |
| sign test | **p = 0.51** |
| median paired difference | **−0.006** |

Mean positive, median negative: **the Inspector wins large on a minority of
hosts and loses small on the majority.** Its value is concentrated, not general.

**Combining them does not help.** Six methods on LANL:

| scorer | within-host AUC |
|---|---|
| bag-Mahalanobis | 0.578 |
| ensemble min(z) | 0.569 |
| ensemble mean(z) | 0.568 |
| ensemble max(z) | 0.568 |
| ensemble mean(rank) | 0.557 |
| Inspector | 0.542 |

**All six between 0.54 and 0.58.** That is not "our model is bad" — it is *the
task is not solvable on this corpus by any method we can build*. Accuracy does
not discriminate.

### 9.5 Router selection — `results_8seed.json` (synthetic), `lanl_novelty.json` (LANL)

| router | synthetic AUC, 8 seeds | LANL AUC, 3 seeds |
|---|---|---|
| **A — distilled detector**, regresses the continuous teacher score | 0.833 ± 0.044 | **0.992 ± 0.003** |
| B — encoder + per-host Mahalanobis (KMeans k=3, Ledoit-Wolf, 5% trim) | 0.804 ± 0.029 | **0.634 ± 0.007** |
| C — deferral head, BCE on "would the teacher flag this" | 0.839 ± 0.039 | not run |

**On synthetic data the three routers are indistinguishable.** Paired by seed:
A vs C p = 0.74, A vs B p = 0.20, B vs C p = 0.15 (Wilcoxon, n = 8). An earlier
3-seed run read as a clean ranking — A 0.876, C 0.850, B 0.818 — and it was
noise: A alone spans 0.735 to 0.885 across seeds. **That ranking is withdrawn.**

**Build A anyway, on the LANL result rather than the synthetic one.** On real
data the gap is not subtle: **0.992 vs 0.634** agreement, and 35.6% vs 3.3%
attack recall at a 5% budget. A is also the simplest — no second head, no
per-host covariance to estimate — and B's decision lives in a geometry the
student only partly preserves (kNN overlap@20 0.35 synthetic, 0.44 LANL).
Report that overlap alongside any recall claim.

*A note against our own case:* on **synthetic** data B's attack recall at a 5%
budget is 31.8% ± 6.4 against A's 15.0% ± 2.8. B agrees with the teacher less
and catches the planted attacks more — it behaves like an independent detector
rather than a teacher-mimic. On LANL that reverses completely (3.3% vs 35.6%),
which is why A is the recommendation, but the synthetic result is recorded
rather than dropped.

**Synthetic budget curve** (router A, 8 seeds) — much lower than LANL because
the synthetic attacks are stealthier by construction:

| budget | teacher's flags | attacks |
|---|---|---|
| 0.5% | 6.3% ± 0.5 | 1.8% |
| 1% | 11.3% ± 1.0 | 3.6% |
| 2% | 20.2% ± 2.0 | 6.4% |
| 5% | 35.7% ± 3.9 | 15.0% |
| 10% | 49.1% ± 5.0 | 26.0% |

### 9.6 Throughput — `escalate.json`, all on the same single CPU core

**Quote the ordering and the range, never a rate.** Three runs of `escalate.py`
on the same 2-core container:

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| Inspector, windows/sec | 70,950 | 104,385 | 93,700 |
| Sentry, windows/sec | 609,187 | 787,016 | 770,065 |
| hop-2 cohort, windows/sec | 1,869,524 | 2,918,707 | 3,153,056 |
| **Sentry : Inspector** | **8.59×** | **7.54×** | **8.22×** |

Nothing about the models changed between those runs — only what else the
container was doing. `timeit` already takes best-of-3 and best-of-3 does not
remove contention when both cores are busy. So the absolute rates are a property
of the afternoon, not of the system, and even the ratio moves by 12%.
`escalate.json` now records a `machine_reference` (a timed 512×512 matmul: 296
GFLOPS, 2 threads, on run 3) so any two runs can be compared honestly, and
`verify_all.py` asserts the **ordering** and a 5–12× band rather than an equality.

**The Sentry is roughly 8× faster, not 13.7×.** 13.7 is the parameter ratio and
is not a speed claim. The cohort computation is not the bottleneck.

⚠ **Do not carry 8.6× onto a GPU slide.** It is CPU-to-CPU. The Inspector's
Transformer parallelises across all 24 windows; the Sentry's GRU is 24
sequential steps a GPU cannot parallelise. On GPU the gap shrinks and may
invert — which is precisely why the Sentry belongs on CPU. Present it as a
placement decision backed by a benchmark you have run.

### 9.7 Order ablation — `ablation_order_hard.json`, 3 seeds, 120 hosts, 16 days

Permuting the hour axis is a *complete* ablation of order, because order enters
the model only via the positional embedding and the Transformer's attention.

| condition | AUC |
|---|---|
| A — full model | 0.998 ± 0.001 |
| B — hours shuffled at scoring | 0.998 ± 0.001 |
| C — hours shuffled at train *and* score | 0.997 ± 0.001 |
| **D — bag of categories, order-free** | **1.000 ± 0.000** |
| E — Markov transitions only | 0.444 ± 0.055 |
| F — no reverse-direction features | 0.996 ± 0.002 |

**A − B = 0.000. The model is order-blind**, and an order-free baseline scores
*better*. Therefore **"we detect the sequence" is withdrawn**; the claim is
**"we detect the combination and the shape."**

F is good news for the diode story: losing reverse-direction features costs
0.002 AUC, so the system genuinely survives unidirectional visibility.

Note also that 149,568 + 2,304 = **74% of the Inspector is the part this
ablation shows contributes nothing measurable.**

### 9.8 Cross-organisation transfer — `shift_results.json`

Two synthetic worlds, different role mixes, work hours, volumes, off-hours rates.

| | world A | world B |
|---|---|---|
| Inspector AUC | 0.873 ± 0.011 | 0.852 ± 0.008 |
| router AUC | 0.804 ± 0.040 | 0.825 ± 0.011 |
| attack recall @5% | 31.4% ± 7.5% | 37.2% ± 3.1% |
| flag rate | 6.7% | 6.3% |

**The mechanism transfers; the threshold does not.** A's 99th-percentile
threshold produces 6.3% in world B — a 1.14× ratio — and 6.7% in world A's
*own* test period, so it decays over time, not merely across networks.

### 9.9 The escalation loop — `escalate.json`, 200 hosts × 16 days, 5% window budget

| | measured |
|---|---|
| windows escalated | 1,280 |
| host-days the Inspector re-ran on | **775 of 1,600 (48.4%)** |
| host-days confirmed at 3σ | 560 |
| confirmation precision | **12.7%** |

**Budget granularity.** The Inspector's unit is a host-day. The top 5% of
*windows* scatters across 48.4% of *host-days* — a **9.7×** multiplier (9.9×
 on an earlier run; see AUDIT B7). This is
why `tiers.py` budgets in host-days: `budget_cut` takes a quantile over
per-host-day peaks. Measured after the fix: **7.5% of host-days against a 10%
budget** — no scatter.

Confirmation precision of 12.7% means the 3σ threshold is far too loose. §9.13
sweeps it.

### 9.10 Option C on a mixed fleet — `deploy_c.json`, 200 hosts × 8 days

Tier mix: 2 crown_jewel, 11 elevated, 117 standard, 70 bulk.

**Detection latency.** Sentry raised its peak at **hour 17** (IQR 15–19)
against an Inspector that could not have answered before hour 24 — a median of
**7 hours earlier**.

**Inspector load, by cause** — 173 of 1,600 host-days (10.8%):

| reason | count | share |
|---|---|---|
| audit | 89 | 51.4% |
| router | 77 | 44.5% |
| commissioning | 7 | 4.0% |

Escalation is **budgeted**, audit is **chosen**, churn is **absorbed**. Quoting
one figure for "Inspector load" hides which of the three is moving.

**The dial, same fleet:**

| audit rate | host-days inspected | fraction | ETTE @ P=0.5 |
|---|---|---|---|
| 2% | 110 | 6.9% | 100 days |
| 5% | 158 | 9.9% | 40 days |
| 20% | 376 | 23.5% | 10 days |
| **100%** | **1,600** | **100%** | every day |

*(Untrained models — this demonstrates architecture behaviour, not detection
performance.)*

### 9.11 Cost — `gpu_cost.py`

At 100,000 hosts, inspecting **everything** for a year:

| teacher size | inspect-all $/yr | cascade $/yr | saved |
|---|---|---|---|
| 205,546 | $0 | $0 | $0 |
| 2,000,000 | $2 | $0 | $1 |
| 20,000,000 | $15 | $2 | $13 |
| 200,000,000 | $150 | $16 | $135 |

Scaling the fleet with a 200M-parameter teacher: 100k → $150/yr · 1M →
$1,502 · 10M → $15,017 · 100M → $150,170.

**Below roughly ten million hosts, do not lead with GPU cost.** The saving is
arithmetically real and economically irrelevant. At vendor-multi-tenant or
national-infrastructure scale it becomes a genuine six-figure line.

**Where the money actually is**, same 100,000 hosts:

```
alerts/day, inspect everything :      2,560
alerts/day, cascade            :      2,481      ← only 3.1% lower
analysts needed                :        113
analyst spend                  : $  9,054,336 /yr
wasted on false positives      : $  7,904,435 /yr   at 12.7% precision
```

**The cascade does not reduce alert volume, by design** — a faithful router
that recovers 96.9% of the teacher's flags necessarily passes 96.9% of the
alerts through. It saves *inspection*, not *triage*. Alert volume is controlled
by the **confirmation threshold**, and that single number is worth more than
every compute optimisation in the architecture combined. It is no longer
untuned: see §9.13.

### 9.12 Test coverage

| file | checks |
|---|---|
| `test_lanl_loader.py` | 53 |
| `test_contracts.py` | 32 feature-contract checks |
| `test_lifecycle.py` | 19 visibility-gate + state-machine |
| `test_tiers.py` | 17 Option C — causality, cohort, the dial |
| `test_quic.py` | 16 vs RFC 9001 Appendix A.1 vectors |
| `test_calibration.py` | poisoning demo + audit-budget sweep |
| `test_determinism.py` | 9 — same seed, same bytes, in a fresh process under four `PYTHONHASHSEED` values |

Run all of them, plus every documented number and every retired claim, with one
command: **`python verify_all.py`**. Exit code 0 only if everything passes.

---

### 9.13 The confirmation threshold, swept

`sweep_threshold.py`, 3 seeds × 200 hosts × 16 days, a 5% **host-day**
escalation budget, pooled across seeds. Synthetic, two difficulties.

| σ | precision | attack recall | alerts per 1,000 host-days |
|---|---|---|---|
| 2.0 | 14.5% | 15.4% | 48.8 |
| **3.0 — what ships today** | **17.7%** | **15.4%** | **40.0** |
| 4.0 | 24.3% | 15.4% | 29.2 |
| 5.0 | 32.7% | 14.9% | 21.0 |
| **6.0 — best F1** | **40.3%** | **14.0%** | **16.0** |
| 8.0 | 50.0% | 12.7% | 11.7 |

*(stealth 0.9–1.0, hard negatives on — the same setting `escalate.py` uses. At
the easier setting the shape is identical and the levels are higher: 20.3% →
45.8% precision, recall flat at 12.2%.)*

**Read the shape, not the levels.** Precision climbs steeply while recall sits
flat to about 5σ. So the operating point is not max-F1 — F1 prices a missed
attack and a wasted analyst-hour the same, and no SOC does. It is *the loosest
threshold whose alert volume your analysts can absorb.*

**What it is worth.** At 100,000 hosts, on the SOC assumptions in `gpu_cost.py`:

| | 3.0σ | 6.0σ |
|---|---|---|
| alerts/day | 1,985 | 796 |
| analysts | 90.5 | 36.3 |
| analyst spend | \$7.24M/yr | **\$2.90M/yr** |
| attack recall | 15.4% | 14.0% |

**\$4.34M a year for 1.4 points of recall** — one scalar, worth more than every
compute optimisation in this document combined.

**Two honest qualifications.**

1. **The budget, not the threshold, caps recall.** Recall tops out near 15%
   because the router escalates 5% of host-days, and no threshold recovers an
   attack that was never escalated. The next sweep is of the budget.
2. **The routing does beat a coin, and this is the test that says so:**
   escalating 5% of host-days at random would catch 11.1 of 221 attack days;
   the router caught 34 (**3.08×, p < 0.001**). That test is now computed and
   written into `sweep_threshold.json` on every run, because a recall figure at
   a fixed budget means nothing without it.

---

## 10. What changed

### Before

```
   ├─────── 14 DAYS ────────┤
   │                        │
   │   INSPECTOR only       │  ──►  handover  ──►   SENTRY only
   │   learns the network   │                      monitors
   │                        │                      │
   └────────────────────────┘                      └─► if it detects
                                                        something, send
                                                        back to Inspector
                                                        for a verdict
```

Justification: **GPU cost**. The Inspector is expensive, so run it once to
learn, then hand monitoring to something cheap.

### After

```
   ├─── COMMISSIONING ──────┤─────── SENTRY_PRIMARY ────────
   │  Inspector: all days   │  Inspector: escalations + audit, never idle
   │  Sentry:   in parallel │  Sentry:   hourly, at the EDGE
   │            LEARNING    │
   └── promotion on EVIDENCE┘
```

Justification: **latency and data locality**, both structural, both measured.

| | before | after | why |
|---|---|---|---|
| **Why two models** | GPU cost | Inspector can't answer before midnight; Inspector needs cross-host data, Sentry doesn't | Cost measured at $150/yr for 100k hosts with a 200M teacher — the premise was false |
| **When the Sentry starts** | after 14 days | **day one, in parallel** | Commissioning is the only source of the router's training labels ("would the teacher have flagged this"). Starting later throws the training set away |
| **Handover** | Inspector stops | **Inspector never stops** — escalations + permanent blind audit | Without the audit, nothing detects the Sentry drifting from the teacher; and the audit is the only cover for the router's measured 3.1% miss rate |
| **Promotion** | 14-day timer | **evidence gate** — 240 live windows, 10 distinct days, a weekend seen, 200 reference samples, drift ≤0.35σ, disagreement ≤0.20 | A timer promotes a quiet server that showed you nothing exactly as readily as a busy laptop that showed you everything |
| **Where each runs** | unspecified | **Sentry at the edge, Inspector central** | Sentry needs no hop-2 cohort (measured: blanking cohort moves the Inspector 0.410); it can sit at a diode-separated site where the Inspector structurally cannot |
| **Detection cadence** | daily | **hourly (Sentry) + daily (Inspector)** | Sentry is causal — proven to 4×10⁻⁶. Measured 7 hours earlier, median |
| **Escalation budget** | 5% of windows | **budgeted in host-days** | 5% of windows re-ran the Inspector on ~48% of host-days — a 9.7× scatter. Now 7.5% against a 10% budget |
| **Coverage of router misses** | not addressed | **per-host audit dial**, 2% → 100% | At 100% the cascade *is* full inspection, per host. A crown-jewel asset and a kiosk get different coverage in one deployment |
| **What crosses on escalation** | the flagged window | **the day + preceding days + trigger hour + visibility + state + reason** | Handing the Inspector one isolated hour removes the combination the hypothesis is about |
| **Threshold** | fixed after commissioning | **guarded rolling recalibration** | Threshold decays over time, not just across networks (6.7% flag rate in world A's own test period). Naive adaptation is poisonable |
| **Capture faults** | not distinguished | **visibility gate** — refuses to score, raises DATA_QUALITY | A sensor change, in either direction, shifts the feature distribution and the model faithfully reports an anomaly about the wrong thing |
| **"We detect the sequence"** | claimed | **withdrawn** — "combination and shape" | Permuting the hour axis changes AUC by 0.000 |
| **Cost claim** | 94.7% GPU reduction | **withdrawn** — lead with "no GPU needed at the edge tier" | 94.7% → 92.7% with audit → 45.7% at the real budget granularity → and the absolute figure is $150/yr |
| **Speed claim** | 13.7× | **8.6×**, measured, CPU-to-CPU only | 13.7 is the parameter ratio, not a speed measurement |

---

## 11. Open work, in priority order

1. **Run the own-capture corpus.** The only corpus that can test the actual
   cross-service hypothesis. Five days of snaplen-0 data ≈ 17 September. Run
   the same three tests already scripted: Inspector, bag baseline, paired sign
   test. Both outcomes are presentable.
2. ~~**Tune the confirmation threshold.**~~ **DONE 17 Sep** — `sweep_threshold.py`,
   §9.13. The 3σ cut ships too loose: 3σ → 6σ raises confirmation precision
   17.7% → 40.3% and cuts alerts per 1,000 host-days 40.0 → 16.0, for 1.4
   points of attack recall. At 100k hosts that is 90.5 → 36.3 analysts,
   $7.24M → $2.90M a year. **What replaces it:** the *escalation budget* is now
   the binding constraint on recall — no threshold recovers an attack the
   router never escalated — so sweep the budget the same way, on a corpus with
   real labels.
3. **Wire the trained router head into `EdgeTier`.** It takes a scoring
   callable; the demo passes a stand-in. One-line change once there is a
   checkpoint from the own corpus.
4. **Test whether the Transformer earns its place.** 74% of the Inspector is
   the Transformer plus positional embedding, and the order ablation says that
   path contributes 0.000. An "Inspector-lite" — aggregator + cohort +
   mean-pool, roughly 54,000 params — run through the §9.4 paired comparison.
5. **Decide the cohort's scope at multi-site scale.** Global cohort means
   shipping every site's tensor centrally — a data-movement and cross-tenant
   privacy problem. Per-site means each Inspector's cohort covers a different
   population than it trained on, which the visibility gate would correctly
   flag. Neither is fatal; both need a decision.
6. **Re-measure the recall curve at host-day granularity** so the cost claim
   and the recall claim describe the same system.
7. **Give the generator independent RNG streams.** `synth.generate` threads one
   generator through the population in host order and `_inject_lsa` draws a
   stealth-dependent count, so changing `stealth_range` also resamples the
   benign traffic of most hosts — 34 of 56 in the test that pins it. Until that
   is fixed, **varying a generator parameter and comparing the results is not an
   ablation**, and none of the cross-setting comparisons in §9.13 should be read
   as one. The fix is `np.random.SeedSequence(seed).spawn(4)` for topology,
   benign traffic, habits and injection. Deferred only because it changes every
   synthetic number again. `test_determinism.py` fails when someone does it, by
   design.

---

## 12. Claims discipline

**Say these**

- "The Sentry is a router, not a detector."
- "96.9% of the *Inspector's flags* are recovered at a 5% budget."
- "One command re-runs every test, re-derives every number in this document
  from its source file, and fails if a withdrawn claim has come back:
  `python verify_all.py`."
- "Within-host AUC 0.557 ± 0.013 on LANL. That is near chance, and it is our
  weakest number." — lead with this if asked what is weakest.
- "We detect the combination and the shape."
- "On synthetic data the three routers are tied at 8 seeds. We build A because
  of the LANL gap — 0.992 against 0.634 — not because of a synthetic ranking."
- "The Inspector is GraphIDS-shaped, arXiv:2509.16625. Ours is the
  cross-service category semantics and the chain dataset."
- "About 8× faster by measured throughput, CPU to CPU" — the range is
  7.5–8.6× over three runs; do not quote a decimal place.
- "The edge tier needs no GPU at all."
- "At 100% audit the cascade *is* full inspection — it contains it."

**Never say these**

- "95% recall", or "96.9% recall" without "of the Inspector's flags"
- any Tier 2 detection rate as a product claim
- "0.745" without the busy-host confound attached
- "13.7× faster" — parameter ratio, not a speed measurement
- "94.7% GPU reduction" — withdrawn
- "we detect the sequence" — withdrawn by ablation
- "55% of DNS is hidden by DoH" — retracted, no denominator
- "router A beats C and B" on synthetic data — withdrawn at 8 seeds; they tie
- any single-decimal throughput figure — three runs on one machine spanned
  7.5–8.6×
- state of the art / novel transformer / replaces EDR / the Inspector
  architecture is ours

**The stance that makes this work.** Every retraction above was found by us,
testing our own claims, and written down before anyone asked. A panel that
catches a team hiding a weakness punishes it; a panel that watches a team argue
against itself and survive does the opposite. The 0.557, the order ablation,
the paired tie and the $150 are not damage — they are the evidence that the
remaining numbers can be trusted.

---

## 13. Repository

```
netsentinel_v2/
  models.py         Inspector, Sentry, DeferralHead, EdgeAggregator, recon_error
  train.py          commissioning, distillation, router heads, budget_curve
  tiers.py          Option C — EdgeTier / CentralTier / RiskTier /
                      EscalationPacket / load_report
  lifecycle.py      per-host state machine, promotion gates
  visibility.py     the data-quality gate
  calibration.py    guarded rolling recalibration
  hostnorm.py       per-host robust z-scoring, within_host_auc
  categories.py     the 9 categories, the 10 edge features
  synth.py          the generator; hard_negatives=True by default
  lanl_loader.py    cyber1 → tensors; port taxonomy, novelty features, caching
  zeek_loader.py    Zeek logs → tensors (own capture)
  quic.py           RFC 9001 §5.2 QUIC Initial decryption
  baseline.py       HostBaseline — KMeans + Ledoit-Wolf Mahalanobis (router B)
  cost_model.py     host-day accounting, window→host-day conversion, ETTE
  gpu_cost.py       industrial cost model, SOC triage economics

experiments                                        → output
  run_experiment.py   synthetic, routers A/B/C      → results.json
  train_real.py       LANL and Zeek runner          → lanl_novelty*.json
  lanl_p0b.py         Inspector vs bag, paired      → lanl_p0b.json
  lanl_ensemble.py    can they be combined?         → lanl_ensemble.json
  paired_synth.py     the same test on synthetic    → paired_synth.json
  deploy_c.py         Option C on a mixed fleet     → deploy_c.json
  confound_test.py    busy-host confound            → confound_test.json
  ablation_order.py   order + diode ablations       → ablation_order_hard.json
  escalate.py         throughput + escalation loop  → escalate.json
  shift_test.py       world A vs world B            → shift_results.json
  capture_probe.py    what the sensor can see       → capture_probe.json

tests
  test_lanl_loader.py · test_contracts.py · test_lifecycle.py
  test_tiers.py · test_quic.py · test_calibration.py
```

### Commands

```bash
# LANL — with both caches present, no flows.txt.gz needed, only redteam.txt
python train_real.py --lanl --data . --max-hosts 500 --lanl-days 13 \
       --seeds 3 --out lanl_novelty.json
python train_real.py --lanl --data . --max-hosts 500 --lanl-days 13 \
       --seeds 3 --host-normalise --out lanl_novelty_hn.json
python lanl_p0b.py      --data . --max-hosts 500 --lanl-days 13
python lanl_ensemble.py --data . --max-hosts 500 --lanl-days 13

# synthetic
python run_experiment.py --seeds 3 --hard-negatives
python paired_synth.py   --hosts 700 --days 16 --seeds 3
python ablation_order.py --hard-negatives --stealth-lo 0.9 --stealth-hi 1.0

# Option C
python deploy_c.py --hosts 200 --days 8
python test_tiers.py

# the sensor — name files explicitly, NOT --limit
python capture_probe.py D:\capture\ns_000NN_<timestamp>.pcap ...
```

`capture_probe.py --limit N` sorts filenames alphabetically and takes the last
N. The capture ring restarted its numbering, so old high-numbered files sort
after new low-numbered ones and you will silently probe the wrong era.
