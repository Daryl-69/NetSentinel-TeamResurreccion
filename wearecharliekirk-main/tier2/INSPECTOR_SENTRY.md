# The Inspector–Sentry cascade — everything, with the changes marked

**Updated 12 Sep 2026.** This is the complete picture of Tier 2: what each model is, how
it trains, how they talk to each other, every measured number, and — marked
inline — **what changed and why**.

Change markers used throughout:

| marker | meaning |
|---|---|
| 🟢 **NEW** | did not exist before 11 Sep 2026 |
| 🔵 **CHANGED** | existed, and the value or wording is now different |
| 🔴 **WITHDRAWN** | we used to claim this; measurement killed it. Do not say it |
| ⚪ **UNCHANGED** | stated explicitly because people keep asking |

---

## 0. The change log, at a glance

If you read nothing else on this page:

| # | What | Status |
|---|---|---|
| 1 | "We detect the **sequence**" → "we detect the **combination and the shape**" | 🔴 WITHDRAWN — ablation, §7.1 |
| 2 | "96.9% recall" → "96.9% **of the Inspector's flags**" (attack recall is 35.6%) | 🔵 CHANGED — §6.2 |
| 3 | Guarded rolling recalibration | 🟢 NEW — `calibration.py`, §5 |
| 4 | Hard negatives in the generator | 🟢 NEW — `synth.py`, §7.2 |
| 5 | The order + diode ablations | 🟢 NEW — `ablation_order.py`, §7 |
| 6 | Reverse-direction features cost 0.002 AUC — diode story holds | 🟢 NEW — §7.3 |
| 7 | "Build router B" recommendation | 🔴 WITHDRAWN — A wins 0.992 vs 0.634 |
| 8 | "≥95% recall at a 5% budget" | 🔴 WITHDRAWN — never say it |
| 9 | The empty-window max-pool bug | 🔵 CHANGED — fixed, §2.1 |
| 10 | The Inspector architecture is ours | 🔴 WITHDRAWN — GraphIDS, arXiv:2509.16625 |
| 11 | Inspector = 205,546 params, Sentry = 14,992, 13.7× | ⚪ UNCHANGED |
| 12 | Within-host AUC 0.557 ± 0.013 — chance | ⚪ UNCHANGED, still the headline weakness |
| 13 | **94.7% GPU reduction** — only at a *host-day* budget | 🔵 **CHANGED** — 92.7% with audit, **45.7%** at the window budget the recall figures use. §5.4 |
| 14 | **5% of windows ≈ 48% of Inspector load** | 🟢 NEW — measured, §7.4. The budget was counted in the wrong unit |
| 15 | **Inspector throughput 71–104k win/s; Sentry 7.5–8.6× faster** | 🟢 NEW — never measured before, §3.2. The spread is machine load, not the models |
| 16 | **P0 on real LANL: pooled AUC 0.745 → 0.618** under per-host scoring | 🟢 **NEW, RUN 12 Sep** — within-host unmoved (+0.003, as predicted). The pooled headline was substantially a busy-host artefact. §6.4 |
| 17 | **P0b on real LANL: the Inspector TIES a ~0-parameter baseline** | 🟢 **NEW, RUN 12 Sep** — paired over 77 hosts, 36–40–1, sign test **p = 0.731**. §6.4 |
| 18 | Visibility gate (P2) | 🟢 NEW — `visibility.py`, §8.1 |
| 19 | Per-host state machine (P3) | 🟢 NEW — `lifecycle.py`, §8.2 |
| 20 | Feature contract test (P4) | 🟢 NEW — `test_contracts.py`, 32 checks |
| 21 | Router A regresses a **continuous** target | ⚪ UNCHANGED — it always did. §4.1 |

---

## 1. The idea in one paragraph

A graph neural network good enough to spot a kill chain riding trusted services
is too expensive to run on every host, every hour, forever — especially on
CPU-only OT hardware. So we run it **twice**: once per host during a
commissioning window to learn that host's own normal, and then again only on the
few host-days something cheap has flagged. The cheap thing is a 13.7×-smaller
model that is **not a detector** — it is a **router** that answers *"would the
Inspector want to look at this?"*. That single reframing is the project.

```
       COMMISSIONING                         STEADY STATE
       ─────────────                         ────────────
  Inspector (205,546 p, GPU)            Sentry (14,992 p, CPU, always on)
  learns each host's normal                        │
  unsupervised, no attack                          │ scores every
  examples needed                                  │ (host, category, hour)
         │                                         ▼
         │  anomaly-weighted                 top 5% by router score
         │  ENCODER distillation, λ=4              │
         ▼                                         ▼
      Sentry  ─────────────────────────────►  Inspector re-runs
                                              on those only
                                                   │
                                                   ▼
                                          ONE alert carrying the
                                          timestamped chain steps
```

---

## 2. The Inspector — the expensive teacher

**205,546 parameters.** ⚪ UNCHANGED. `netsentinel_v2/models.py`.

🔴 **WITHDRAWN:** we used to present this architecture as ours. It is
**GraphIDS-shaped — arXiv:2509.16625, prior art.** Say so out loud; it costs
nothing and buys credibility for the parts that *are* ours.

### 2.1 The edge aggregator (hop-1)

For every `(host, category, hour)` the model builds a message:

```
message(c) = MLP([ edge_features(c) , category_embedding(c) , cohort(c) ])
window     = MLP([ mean_c message , max_c message , presence_mask ])
```

Three things are doing real work here:

- **The category embedding** (9 categories → 16 dims) is what stops the model
  memorising infrastructure. The GNN never sees a domain.
- **The cohort term** is the sampled hop-2 neighbourhood — the mean edge
  features of *other* hosts touching the same category in the same hour. This is
  what an E-GraphSAGE-style model contributes over a flat per-host model.
- **The presence mask** is passed explicitly, so "this host touched nothing this
  hour" is a fact the model can use rather than an absence it has to infer.

🔵 **CHANGED — a bug worth knowing about.** The max-pool used a `-1e9` sentinel
to mask absent edges. On an **empty** window there is nothing to max over, and
the guard was written against a denominator that had been `clamp(min=1)`ed and so
was never zero. The sentinel escaped into the encoder on roughly half of all
windows and blew first-epoch loss to ~1e12. Fixed by guarding on the **true**
edge count:

```python
mx = (m.masked_fill(mk == 0, -1e9)).max(dim=2).values
mx = torch.where(cnt > 0, mx, torch.zeros_like(mx))   # cnt, not denom
```

Every number in this document is post-fix.

### 2.2 The sequence encoder

```
h    = aggregator(edges, mask, cohort) + positional_embedding[:24]
z    = TransformerEncoder(h)          # 2 layers, 4 heads, dim 96, ffn 192,
                                      # dropout 0.1, norm_first=True
recon = MLP([ z , category_embedding ])   # -> (B, 24, 9, 10)
```

**Order enters the model in exactly two places: the learned positional
embedding, and the Transformer's attention across the 24 hours.** That is why
permuting the hour axis is a *complete* ablation of order — remember this for
§7.1.

### 2.3 How it trains — unsupervised, no attack examples

A **denoising autoencoder over host-days**. Hide 25% of present edges from the
encoder, then ask the decoder to reconstruct *every* present edge:

```python
drop = (torch.rand_like(m) > 0.25).float() * m
_, pred = model(e * drop.unsqueeze(-1), drop, c * drop.unsqueeze(-1))
loss = (((pred - e) ** 2).mean(-1) * m).sum() / m.sum().clamp(min=1)
```

Defaults: 14 epochs, dim 96, batch 64, AdamW lr 2e-3, weight decay 1e-4, grad
clip 1.0.

**The anomaly score is the per-window reconstruction error over present edges.**
No labels anywhere. This is the property that matters commercially: it needs no
attack example, therefore no signature, no bad-domain list, no decryption and no
agent.

---

## 3. The Sentry — the cheap student

**14,992 parameters, 13.7× smaller.** ⚪ UNCHANGED. Measured at **609–787k
windows/second** on one CPU core — see §3.2, and note that parameter
compression (13.7×) and speed-up (≈8×) are different numbers.

```
aggregator  same message function, but use_cohort=False   (no hop-2)
sequence    GRU(32 → 32), unidirectional                  (not a Transformer)
project     Linear(32 → 96)                               (distillation head only)
```

Two deliberate amputations: **no cohort term** (hop-2 needs every other host's
features for that hour — expensive to assemble at wire speed) and **a GRU
instead of a Transformer** (no quadratic attention, streams naturally).

### 3.2 🟢 NEW — what the Inspector actually costs

We quoted the Sentry at ~250,000 windows/s and never measured the Inspector at
all, so "why the router?" had no number behind it. Measured on one CPU core,
best of three (`escalate.py`, 200 hosts × 16 days):

| stage | throughput |
|---|---|
| hop-2 cohort assembly | 1.9–3.2M win/s |
| Inspector forward | 71–104k win/s |
| Sentry forward | 609–787k win/s |
| **Sentry speed-up** | **7.5–8.6×** (three runs: 8.59, 7.54, 8.22) |

Two things worth saying out loud:

- The Sentry measures *faster* than the ~250,000 win/s we have been quoting.
  Use the measured figure and say which machine it came from.
- **The hop-2 cohort is not the bottleneck.** The intuition was that assembling
  every other host's features per hour would dominate; it runs at 1.87 M win/s,
  27× faster than the Inspector's own forward pass. The cost is the transformer,
  not the graph.

≈8× is a much more modest ratio than 13.7× compression suggests. Parameter
count is not runtime. Quote the range, 7.5–8.6× — three runs on one machine
spanned that much, so a single decimal place would be false precision.

### 3.1 The distillation — this is the bit people get wrong

We distil the **encoder**, never the verdict:

```
L = E[ (1 + λ · s_teacher) · ‖ project(f_student) − f_teacher ‖² ]     λ = 4
s_teacher = clip( teacher_error / quantile(teacher_error, 0.99), 0, 3 )
```

**Why weighted:** standard knowledge distillation minimises *mean* divergence,
which is exactly why rare signals wash out — and in an IDS the rare signal is
the entire product. Weighting by the teacher's own normalised anomaly score
forces student capacity onto the windows the teacher found hardest.

**Why the encoder and not the verdict:** MDPI MAKE 8(3):60 measured how anomaly
types survive distillation — global outliers **78%**, isolation **88%**,
neighbourhood **76%**, **local outliers only 20%**. A host-relative anomaly *is*
a local outlier. Distil the verdict and you throw away four-fifths of the thing
you care about. Distil the representation and the downstream head can still find
it.

Defaults: 16 epochs, dim 32, batch 64, lr 2e-3, λ=4.

---

## 4. Choosing the router — A, B or C

Three candidate ways to turn the student embedding into an escalation decision:

| | what it is | how it is trained |
|---|---|---|
| **A** distilled detector | regress the teacher's **normalised anomaly score** from the student embedding | MLP head, MSE |
| **B** encoder + Mahalanobis | per-host baseline on the student embedding: KMeans (k=3) + Ledoit-Wolf shrunk covariance, min Mahalanobis over components, trimmed 5% by teacher error | no head — pure distance |
| **C** deferral head | predict **"would the teacher flag this"** directly | MLP head + baseline distance, BCE |

### Measured — and this settles it

On **LANL cyber1**, 612 hosts × 13 days, 3 seeds (`lanl_novelty.json`):

| router | AUC (agreement with the teacher) |
|---|---|
| **A distilled detector** | **0.992 ± 0.003** |
| B encoder + Mahalanobis | **0.634 ± 0.007** |

On the synthetic world (`results.json`, treat as pipeline-works evidence only —
§7.2), 8 seeds: A 0.833 ± 0.044, C 0.839 ± 0.039, B 0.804 ± 0.029 — no pair
separable. C was only run on synth, not on LANL.

🔴 **WITHDRAWN.** An earlier document recommended **building router B**. That
recommendation is dead. B collapses exactly where the distillation-transfer
literature says it should: it relies on *local* geometry in the student space,
and local outliers are the 20% that does not survive distillation. **Build A, or
A+C.**

### 4.1 ⚪ UNCHANGED — the router already regresses a continuous target

Worth stating because it was raised as a risk: router A is trained with **MSE
on a real-valued target**, not BCE on a binary flag —
`train_head(Zc_s, Ec_err / thr_t, loss="mse")`. Router C is deliberately
binary, because a deferral head predicts a decision.

There was a real problem hiding underneath the question, though. The target
`err / thr_t` is divided by the commissioning threshold, and §5 recalibrates
that threshold as the system runs — so every recalibration silently rescales
the router's training target. Under `--host-normalise` the target becomes the
host-relative z, which is **threshold-free**, and the staleness disappears.
That flag is now wired into `run_experiment.py`.

### Why the router does not threshold its own confidence

"The Sentry escalates when it is unsure" is **confidence-based deferral**, which
is provably suboptimal under distribution shift, specialist downstream models,
and label noise — Jitkrittum et al., NeurIPS 2023, arXiv:2307.02764. All three
conditions describe an IDS exactly. So we never threshold the student's own
uncertainty. We train it to predict *the teacher's decision*, and during
commissioning that label is **free**, because we ran both models anyway.

---

## 5. 🟢 NEW — the escalation threshold, and how an attacker can move it

`netsentinel_v2/calibration.py` + `test_calibration.py`. This did not exist
before 11 Sep and it closes a hole we already had evidence for.

### The problem we already knew about

`shift_results.json`: the **mechanism** transfers across organisations (oracle
AUC 0.873 → 0.852) but the **threshold does not**. A 99th-percentile threshold
fitted in world A flags **6.7%** in world A's own *later* test period and
**6.3%** in world B — against a 1% target. It decays **over time**, not just
across networks.

### Why the obvious fix is dangerous

A rolling 99th percentile over recent scores hands the attacker the threshold:

```
attack begins → scores rise → the rolling quantile rises with them
→ the threshold moves above the attack → the attack reads as normal
→ alert rate returns to target and the system reports itself healthy
```

Measured, with drift sized to the 6.7% we actually observed:

| policy | attack windows caught | false alerts | final threshold |
|---|---|---|---|
| FIXED — what we ship today | 9.6% | 4.21% | 2.85 |
| UNGUARDED rolling quantile | **0.1%** | 1.92% | **4.29 – 4.53** |
| GUARDED | **8.8%** | 4.14% | 2.89 |

The attacker walks the unguarded threshold from 2.85 to ~4.4 and detection
collapses to 0.1%.

### The four guards

1. **Admission by provenance, never by score.** A window enters the reference set
   because it was reviewed-benign, or matured with no incident, or drawn by the
   **blind random auditor** — never because its score was low. Admitting
   low-scoring windows selects for the distribution that makes the threshold
   meaningless.
2. **Random audit fixes the sampling bias.** Once the Sentry routes only unusual
   traffic, the Inspector sees a biased sample; calibrating on it calibrates to
   already-suspicious traffic.
3. **Bounded movement, scale-aware.** At most 0.5 **MAD units** per update.
   "10% change" is meaningless when scores sit near zero; MAD units are not.
4. **Freeze on incident and on degraded capture.** A threshold must not drift
   during the event it exists to catch, nor adapt to a sensor fault.

Plus: **forward-only.** An update computed from data up to *t* applies to windows
after *t*. Never re-score history with a threshold derived from it.

### 🔵 CHANGED — the budget is not 5%, it is 5% *plus calibration*

| audit budget | detection | false alerts |
|---|---|---|
| 2% | 8.8% | 4.14% |
| 5% | 7.4% | 3.93% |
| 10% | 4.9% | 3.67% |
| 20% | 1.6% | 2.88% |

Every audited window is an Inspector run. **Calibration draws from the same
budget as escalation** — the old framing showed 5% for escalation and silently
implied calibration was free.

(The falling detection column is inflated: that stream is 12% attack, which no
real network is. Quote the *shape* of the trade, not these numbers.)

### 5.4 🔵 CHANGED — what the audit budget does to the cost claim

`cost_model.py` had no audit term at all, so the escalation budget looked like
the whole bill. It now takes one, and every rate is documented as **per
host-day**, because a host-day is the unit the Inspector consumes.

| regime | ongoing GPU-host-days/yr @ 1,000 hosts | reduction |
|---|---|---|
| as previously quoted (2% escalation, no audit) | 19,467 | **94.7%** |
| + the 2% random audit calibration needs | 26,767 | **92.7%** |
| escalation counted the way recall was measured (§7.4) | 198,317 | **45.7%** |

**94.7% and the recall figures are not from the same regime, and quoting them
side by side overstates the system.** Pick one and quote both numbers from it.

**Honest limit:** this bounds the *rate* at which a threshold can be walked. A
patient adversary who stays inside the eligible distribution can still shift a
baseline slowly. Nothing adaptive prevents that. Ours makes it slow, bounded,
logged and reversible — that is the claim, and it is the one to make.

---

## 6. Every measured number

### 6.1 On LANL cyber1 — real traffic, real red team, 3 seeds

`lanl_novelty.json` · 612 hosts × 13 days · 749 red-team events

| | value |
|---|---|
| Router A AUC — agreement with the teacher | 0.992 ± 0.003 |
| Router B AUC | 0.634 ± 0.007 |
| Inspector global AUC vs attack **window** | 0.745 ± 0.002 — ⚠️ **confounded, see §6.4**; 0.618 ± 0.021 when each host is scored against itself |
| Inspector global AUC vs attack **day** | 0.639 ± 0.004 — ⚠️ 0.487 ± 0.024 under per-host scoring |
| **Inspector within-host AUC** | **0.557 ± 0.013** (0.560 ± 0.015 with `--host-normalise`) |
| **Order-free bag Mahalanobis, same rows** | within-host **0.578 ± 0.273** — a **tie** with the Inspector, p = 0.731 (§6.4) |
| Inspector flag rate | 2.56% |
| Compression | 205,546 → 14,992 (13.7×) |
| GPU work at 1,000 hosts | 365,000 → 19,467 host-days/yr (**94.7%** less) — but read §5.4 first |
| Inspector throughput (measured, 1 CPU core) | 71–104k win/s over three runs |
| Sentry throughput (measured, same core) | 609–787k win/s (**7.5–8.6×**) |

### 6.2 🔵 CHANGED — the most dangerous number in the project

At a **5% escalation budget** on LANL:

| metric | value | what it actually means |
|---|---|---|
| `recall_teacher` | **96.9% ± 1.1** | of the **Inspector's own flags**, the Sentry recovers 96.9% |
| `recall_attack` | **35.6% ± 1.3** | of the **actual red-team attacks**, 35.6% are caught |

**These measure different things.** 96.9% is *routing fidelity* — the cheap model
faithfully reproduces the expensive model's decisions. It says **nothing** about
whether the expensive model is right.

Always say the whole sentence: *"96.9% of the Inspector's flags are recovered at
a 5% budget."* Never shorten it to "96.9% recall."

🔴 **WITHDRAWN: "≥95% recall."** That was an early proposal the measurements
never supported. If it is still in any file, it is wrong.

Full curve:

| budget | recall_teacher | recall_attack |
|---|---|---|
| 1% | 37.7% | 11.5% |
| 2% | 68.0% | 19.3% |
| 3% | 85.6% | 27.2% |
| **5%** | **96.9%** | **35.6%** |
| 10% | 99.0% | 44.3% |
| 30% | 99.5% | 66.9% |

### 6.3 🔵 CHANGED — the weakness, and lead with it

**Within-host AUC 0.557 ± 0.013. That is chance.**

We scored each attacked host against **its own windows only**. Attacked hosts
were simply *busier* — live-window density **0.811** versus **0.530** for
everyone else. The global 0.745 was largely ranking *which host was busy, not
when it was attacked*. We built that check ourselves and it argued against us.

🟢 **Confirmed 12 Sep, on LANL, not by argument.** Re-score every window
against its own host's commissioning distribution and the pooled AUC falls
**0.745 → 0.618**, day-level **0.639 → 0.487**, while within-host does not move
(+0.003). The busyness was doing most of the pooled work. §6.4.

One extra honesty note that is easy to miss: the **±0.013 is seed-to-seed
variation of the mean.** The spread **across hosts** inside a single seed is
**0.297** — far larger. 77 hosts, 106 positives. The per-host picture is much
noisier than "0.557 ± 0.013" makes it sound.

LANL has **zero external traffic**, so the cross-service hypothesis cannot fire
there at all. That is a design consequence, not an excuse — and it is the entire
reason for capturing our own egress data.

---

### 6.4 🟢 NEW — P0 and P0b, **run on the real LANL corpus**

**Status: RUN. 12 Sep.** An earlier draft of this section said the LANL corpus
was unreachable and reported synthetic stand-ins. That is no longer true. The
raw `flows.txt.gz` is still not needed — both expensive passes were already
cached (`lanl_profile.json`, `lanl_tensors_H612_D13_nov1_b6.npz`) and only
`redteam.txt` was missing. `lanl_loader.py` now checks for the flows file at
the point of use instead of up front, so a cached run needs no 12 GB download.

Configuration, so this is reproducible: `--max-hosts 500 --lanl-days 13`,
which force-includes 112 red-team computers and yields **H = 612**;
commissioning days 0–5, validation gap 6–7, test days 8–12; 39,492 live test
windows; 131 attack windows on 80 hosts; 77 hosts scoreable for within-host
AUC carrying 106 positives. Identical to the split behind `lanl_novelty.json`,
so every number below is like-for-like.

```
train_real.py --lanl --data . --max-hosts 500 --lanl-days 13 \
              --seeds 3 --host-normalise --out lanl_novelty_hn.json
lanl_p0b.py   --data . --max-hosts 500 --lanl-days 13
```

#### P0 — the prediction held, and it exposed something worse

The prediction in the previous draft was that per-host normalisation
**cannot** move within-host AUC, because within-host AUC ranks each host's
windows against that host's own windows and a per-host z-score is a strictly
increasing transform inside each host. A strictly increasing transform cannot
change a ranking, so it cannot change an AUC computed inside one.

On real LANL, 3 seeds:

| metric | baseline | `--host-normalise` | delta |
|---|---|---|---|
| **pooled window AUC** | 0.745 ± 0.002 | **0.618 ± 0.021** | **−0.127** |
| pooled day-level AUC | 0.639 ± 0.004 | 0.487 ± 0.024 | −0.152 |
| within-host AUC | 0.557 ± 0.013 | 0.560 ± 0.015 | +0.003 |
| router A within-host | 0.552 ± 0.019 | 0.565 ± 0.032 | +0.013 |
| flag rate | 2.6% | 2.0% | −0.6 pts |

Within-host moved **+0.003**, inside the ±0.013–0.015 seed noise. The residual
is not signal: 32 of 612 hosts had fewer than 20 live commissioning windows and
fell back to the pooled scale, and for those the transform is not per-host, so
it is not rank-preserving. The prediction held.

**The pooled number is the finding.** 0.745 → 0.618 when each host is scored
against itself. Day-level goes to 0.487, which is below chance.

🔴 **This is the strongest evidence yet that the 0.745 headline was
substantially a busy-host artefact.** Removing cross-host scale differences
removes most of the pooled advantage, and what is left (0.618) sits much closer
to the confound-free within-host figure (0.560). The honest reading:

> The gap between 0.745 pooled and 0.557 within-host was the confound. Force
> the model to rank each host against itself and the pooled number collapses
> toward the within-host number, which is where it belonged.

The alternative reading has to be stated too, because it cannot be ruled out
from this experiment alone: if attacked hosts are genuinely busier *because
they are compromised*, then per-host normalisation destroys real signal rather
than an artefact. Nothing here distinguishes those two. What can be said is
that 0.745 should never again be quoted as a clean detection number.

#### P0b — the Inspector versus a ~0-parameter baseline, on LANL, paired

The reviewer's exact ask: *"add either 'the Inspector beats an order-free
Mahalanobis on LANL within-host by X' or 'it does not, and here is why we keep
it'."* Here is the answer.

The baseline (`lanl_p0b.py`): per host, a median and a MAD over that host's own
commissioning windows; score = mean squared robust z over the flattened
(category × feature) bag. No graph, no attention, no embedding, no cohort, no
training, no order. Scored on exactly the rows the Inspector scored.

| | pooled AUC | within-host AUC |
|---|---|---|
| Inspector (205,546 params) | 0.741 | 0.542 ± 0.310 |
| bag Mahalanobis (~0 params) | 0.627 | **0.578 ± 0.273** |

A difference of means is not a result at that spread, so the comparison is
**paired over the 77 hosts both scorers cover**:

| | value |
|---|---|
| Inspector wins on | 36 hosts |
| bag wins on | 40 hosts |
| exact ties | 1 |
| mean difference (Inspector − bag) | **−0.036** |
| median difference | −0.021 |
| exact two-sided sign test | **p = 0.731** |

🔴 **The Inspector does not separate itself from a zero-parameter, order-free
baseline on within-host ranking on LANL.** It is not a loss either — p = 0.731
means the two are trading wins. It is a tie, measured, on real data.

The Inspector does keep a clear pooled advantage (0.741 vs 0.627). But §6.4's
P0 result is that the pooled metric is the confounded one, so that advantage
cannot be claimed as detection quality without the caveat attached.

#### What this means for the architecture — say this, not something softer

> On LANL, the graph model ties a per-host median-and-MAD on within-host
> ranking (p = 0.73, 77 hosts), and its pooled advantage largely disappears
> when each host is scored against itself (0.745 → 0.618). We keep the
> Inspector because LANL cannot test the hypothesis it was built for. The
> hypothesis is about combinations of *named external services* — a host that
> touches a recon API, then a paste site, then a messaging API. LANL is an
> all-internal enterprise network with every computer de-identified to `C1065`,
> so there are no nameable SaaS destinations at all. The loader substitutes a
> nine-class taxonomy derived from **ports** (Directory, FileShare,
> RemoteAccess, Mail, WebProxy, Database, Infra, Workstation, Unknown), which
> is a different signal measuring a different thing. The architecture is being
> judged on a proxy task. That is an argument for a better evaluation corpus,
> not a claim that the model works.

That last sentence is the honest position and it is defensible. What is not
defensible is quoting 0.745 without any of the above.

#### The earlier synthetic attempt, kept for provenance

Before the LANL run was possible we tried to reproduce the pathology
synthetically by thinning benign hosts until the density gap matched
(attacked 0.709 vs others 0.502, against LANL's 0.811 / 0.530). **It did not
reproduce** — the gap came out with the opposite sign (pooled 0.739 vs
within-host 0.766, −0.027, against LANL's +0.188). That is why the synthetic
result settled nothing and the real run had to happen. `confound_test.json`
retains those numbers.

---

## 7. 🟢 NEW — the ablations, and what they killed

`ablation_order.py`. 3 seeds, 120 hosts, 16 days, 45/960 attack days,
fully-shaped adversary, hard negatives on.

| condition | ROC-AUC |
|---|---|
| A full model (order-aware) | 0.998 ± 0.001 |
| B hours permuted **at scoring** | 0.998 ± 0.001 |
| C hours permuted **at training and scoring** | 0.997 ± 0.001 |
| D bag of categories (**order-free**) | **1.000 ± 0.000** |
| E first-order Markov transitions | 0.444 ± 0.055 |
| F no reverse-direction features | 0.996 ± 0.002 |

### 7.1 🔴 WITHDRAWN — "we detect the sequence"

Recall from §2.2 that order reaches the model through exactly two components.
Permuting the hour axis therefore ablates order **completely** while preserving
every feature, every category, the volume, the timing statistics and the mask.

- **A − B = 0.000.** Shuffling the hours changes the score by *nothing*. The
  trained model is order-blind.
- **A − C = 0.000.** There is no order information in the data for *any* model
  to use.
- **A − D = −0.002.** An order-free Mahalanobis on day-level aggregates does
  marginally **better** than the Transformer.

**The claim is now: "we detect the combination and the shape, not the
destination."** The cross-service part survives — *which* allow-listed categories
a host combines, plus how machine-like the traffic looks. The *ordering* part
does not.

This is a stronger position than it feels like. A judge can run this ablation in
one line of numpy. Being the people who already ran it, and who changed the claim
rather than the experiment, is worth more than the claim was.

### 7.2 🟢 NEW — why the old synthetic numbers could not have shown this

On the generator as it was, this single rule:

> longest consecutive run of hours in which `Messaging_API` is present

scores **ROC-AUC 1.000** at every stealth level. One counter. No model, no
features, no sequence. The attacker was the only host that ever chatted for nine
hours straight.

So I added the hard negatives: benign hosts that **chat all day**, and
legitimate integrations that **poll on a schedule** — the latter producing
low-jitter, near-uniform inter-arrival times, which is precisely the surface the
Jitter-Trap keys on. Opt-in via `synth.generate(..., hard_negatives=True)` so
every prior result stays reproducible.

| rule | old generator | with hard negatives |
|---|---|---|
| longest `Messaging_API` run | 1.000 | 0.797 |
| hours with `Messaging_API` | 0.999 | 0.661 |

Even hardened it is still over-determined: `distinct_endpoint_ratio` alone scores
1.000, volume alone 0.999, timing alone 0.999.

**Position to hold: the synthetic benchmark shows the pipeline runs end to end.
It cannot support any comparative claim about the architecture.** The LANL
numbers in §6.1 are unaffected — different data, different question.

### 7.3 🟢 NEW — good news: the diode story holds

Two of the ten features need return traffic: `log_bytes_down` and
`egress_asymmetry`. A sensor behind a genuine one-way tap cannot compute either.

**Dropping both costs 0.002 AUC** (A − F). Essentially free.

The obvious attack on a diode pitch is *"your features need the return
channel"*. We measured it; they do not. But be precise about which topology you
mean:

- sensor **inside** the protected network, exporting telemetry one-way out —
  bidirectional visibility, all ten features available; **or**
- sensor that can only physically see one direction — drop those two, cost
  ~nothing.

And say the rest honestly: missing reverse-direction data must be marked
**missing**, not recorded as zero traffic.

---

### 7.4 🟢 NEW — 5% of windows is not 5% of Inspector load

`escalate.py` built the loop for real, and building it exposed a unit error in
the budget.

The Inspector's unit of work is a **host-day** — the sequence encoder consumes
the whole 24-hour window, so there is no such thing as inspecting one hour. But
the budget was counted in **windows**. The top 5% of windows scatter across
almost every host-day in the set, so:

| budget granularity | host-days the Inspector sees | % of load | attack-day recall |
|---|---|---|---|
| top 5% of **windows** | 775 of 1,600 | **48%** | **87%** |
| top 5% of **host-days** | 80 of 1,600 | **5%** | **12%** |

**You can have 5% Inspector load or 87% recall. Not both.** The recall figures
in §6.2 were measured at a window-level budget; the 94.7% cost reduction
assumes a 2% host-day rate. They describe different systems.

`cost_model.windows_budget_to_host_day_load()` does the conversion with the
measured scatter, and §5.4 has the corrected cost table. Fixing this properly
means budgeting at host-day granularity and re-measuring the recall curve
there — that is the honest version and it is not yet run.

The loop itself works: Sentry scored 25,647 live windows, escalated 1,280, the
Inspector re-ran on 790 host-days rather than all 1,600, and emitted one alert
carrying a 4/4 in-order chain. Confirmation precision at a 3-robust-sigma
confirm threshold was **13%** (67 of 529 confirmed host-days were true attack
days) — that threshold needs tuning and is currently far too loose.

---

## 8. 🟢 NEW — the two pieces that were designed and are now built

### 8.1 The visibility gate — `netsentinel_v2/visibility.py`

A capture fault must not look like an attack. If the sensor stops naming flows,
everything lands in `Unknown_External`, the distribution shifts hard, and the
Inspector faithfully reports a large anomaly. It is right that something
changed and wrong about what.

The gate records the visibility conditions a baseline was fitted under and
returns one of four actions: `score`, `warn_and_score`, `refuse` (raise a
**DATA_QUALITY** ticket, not a security alert), or `recommission`.

The case that matters most is the one people get backwards: **the 11 Sep
snaplen change made the sensor BETTER and thereby invalidated every baseline
fitted before it.** Going 512 → 0 moved ~61% of encrypted flows out of
`Unknown_External` into real categories. A baseline fitted on the old corpus
describes a world where most traffic was unnameable; scored against the new
corpus, it flags the entire estate on the day the capture improved. The gate
treats a material *improvement* in naming coverage as a recommission trigger,
exactly like a degradation.

`test_lifecycle.py` exercises this on the five conditions we actually met,
including the snaplen-160 corpus and QUIC going dark mid-run. **19/19 pass.**

### 8.2 The per-host state machine — `netsentinel_v2/lifecycle.py`

COMMISSIONING / SENTRY_PRIMARY / ESCALATED / INCIDENT_HOLD / RECOMMISSIONING,
with promotion **on evidence, not on a 14-day timer**.

The test that makes the point: two hosts, both fourteen days in. A busy laptop
has 300 live windows and gets promoted. A quiet server has 60, and is held with
the reasons named — *live windows 60 < 240*, *reference samples 55 < 200
(calibration cannot fit)*. A timer would have promoted both. A host that has
never seen a weekend is held until the weekly cycle is observed.

`INCIDENT_HOLD` is deliberately not terminal — "suspicious hosts stay on the
Inspector forever" would consume the entire budget within weeks on false
positives alone. Release is explicit and routes to RECOMMISSIONING, which
resets the reference set. Visibility is tracked *separately* from state,
because a host can be on hold and have a degraded sensor at the same time and
those need different people.

Thresholds in `PromotionPolicy` are **starting settings, not tuned constants**.
Say that when presenting them.

### 8.3 What is still missing

1. **Send history with the escalation.** The hypothesis is about chains, so
   handing the Inspector only the single flagged window can remove the very
   thing it needs. An escalation should carry the window, the preceding
   sequence, the graph neighbourhood, the visibility flags, and the **reason**.
2. **Re-budget at host-day granularity and re-measure the recall curve there**
   (§7.4). Until that is done the cost claim and the recall claim describe
   different systems.
3. **Tune the confirmation threshold.** 3 robust sigma gave 13% precision on
   confirmed host-days — far too loose.
4. ~~**The LANL re-run** (§6.4).~~ 🟢 **DONE 12 Sep.** Both P0 and P0b now
   have real-corpus numbers, and both went against us — see §6.4. What is
   still open is the *consequence*: the pooled 0.745 has to come out of every
   slide and script, and the "why keep the GNN" answer has to become the
   evaluation-corpus argument rather than an accuracy argument.
5. **Tier 1 contract tests.** `test_contracts.py` covers the Tier 2 edge-feature
   path (32 checks). The port-scan 39-vs-59 mismatch and the exfil VAE scaler
   mismatch are the same class of bug and are still open.

---

## 9. The questions you will be asked, and the honest answer

**"How is this different from any other anomaly detector?"**
It scores which *categories of service* a host combines, per host, rather than
flow statistics or destinations. A 91-study review of graph-based NIDS found no
published system doing that. The cascade, the distillation and per-entity
baselining are all prior art.

**"Does the order of the chain matter?"**
We tested it. It does not — permuting the hours moves our AUC by 0.000, and an
order-free baseline matches us. We changed the claim. What carries the signal is
the combination of categories plus the machine-like shape of the traffic.

**"Does the graph model actually beat a simple baseline?"**
On LANL, no — and we checked whether that was LANL's fault. A per-host
median-and-MAD over the flattened feature bag (no graph, no attention, no
training, no order) ties the 205,546-parameter Inspector on within-host
ranking: paired over 77 attacked hosts, 36 wins to 40, sign test p = 0.73.
We then ran the same paired test on synthetic data that *does* contain the
cross-service chain, properly powered at 149 hosts: 70 to 79, p = 0.51. So the
"LANL is the wrong corpus" defence does not by itself explain the tie. What we
can say is narrower and true: the Inspector's **mean** within-host AUC is
+0.025 higher on structured data while its **median** paired difference is
slightly negative — it wins large on a minority of hosts and loses small on the
majority. Its value is concentrated, not general, and we are still measuring
where. See `paired_synth.json`.

**"Your headline number is 0.745. Is that real?"**
Partly, and we can tell you which part. Score every window against its own
host's baseline instead of a pooled one and it falls to 0.618, with the
day-level figure going to 0.487 — below chance. Attacked hosts in LANL are
busier than everyone else (live-window density 0.811 vs 0.530), and a large
share of that 0.745 was ranking busyness. The confound-free figure is the
within-host one, 0.557, and we lead with it.

**"What's your detection rate?"**
On the LANL red team, 35.6% of attacks at a 5% escalation budget, and a
within-host AUC of 0.557, which is chance — the model was ranking which host was
busy. We report the cascade result, which is measured and solid, and we do not
yet claim a detection rate on our own traffic because we have no labels for it.

**"So what's the 96.9%?"**
Routing fidelity: the Sentry recovers 96.9% of the **Inspector's own flags** at a
5% budget. It says the cheap model reproduces the expensive one. It does not say
the expensive one is right.

**"What if the attacker jitters the beacon?"**
Then the inter-arrival times become *uniform*, and human traffic is log-normal.
The evasion is the signature. That is the Jitter-Trap — and §7.2 is the honest
caveat: legitimate schedulers produce the same surface, which is why benign
pollers are now in the generator as hard negatives.

**"Why the GNN at all? Could a simpler model do this?"**
On synthetic data, a per-host Mahalanobis with essentially no parameters ties
with it — 0.727 vs 0.766 within-host AUC, and it is actually ahead on recall at
a fixed budget. So today we cannot claim the architecture wins on accuracy. We
keep the Inspector because it is the model that can use cross-service structure
once we have a corpus where that structure exists, and because the cascade is
built around a teacher whose representation the student can distil. The LANL
comparison would settle it and we have not been able to run it yet.

**"If the Inspector is only 205k parameters, why do you need a router at all?"**
Because parameter count is not runtime. Measured on one core across three runs:
Inspector 71–104k windows/s, Sentry 609–787k — 7.5–8.6×. And the Inspector's
unit of work is a whole
host-day, so at 1,000 hosts inspecting everything is 365,000 GPU-host-days a
year. The router is what turns that into tens of thousands.

**"What does the escalation actually cost?"**
More than the slide used to say. A 5% *window* budget makes the Inspector re-run
on ~48% of host-days, because the windows scatter. Budget at host-day
granularity and it is genuinely 5%, but recall drops from 87% to 12%. We
measured both and we quote whichever regime we are describing.

**"What would change your mind about the project?"**
The order ablation already did. Then the P0b baseline tied with our
architecture, and we wrote that down too.

---

## 10. Files

```
netsentinel_v2/models.py        Inspector, Sentry, DeferralHead, recon_error
netsentinel_v2/train.py         commissioning, distillation, heads, budget_curve
netsentinel_v2/baseline.py      HostBaseline — KMeans + Ledoit-Wolf Mahalanobis
netsentinel_v2/categories.py    9 categories, 10 edge features
netsentinel_v2/calibration.py   🟢 NEW guarded recalibration
netsentinel_v2/hostnorm.py      🟢 NEW per-host z-scoring + within_host_auc
netsentinel_v2/visibility.py    🟢 NEW the data-quality gate
netsentinel_v2/lifecycle.py     🟢 NEW per-host state machine
netsentinel_v2/cost_model.py    🔵 CHANGED audit term + window->host-day
netsentinel_v2/synth.py         🔵 CHANGED hard_negatives=True
run_experiment.py               🔵 CHANGED --host-normalise, --hard-negatives,
                                   reports within-host AUC  -> results.json
confound_test.py                🟢 NEW P0/P0b on SYNTH     -> confound_test.json
lanl_p0b.py                     🟢 NEW P0b on REAL LANL,   -> lanl_p0b.json
                                   paired per-host vs the Inspector
netsentinel_v2/lanl_loader.py   🔵 CHANGED flows.txt.gz is now only required
                                   when the cache that replaces it is absent
escalate.py                     🟢 NEW throughput + the loop -> escalate.json
test_contracts.py               🟢 NEW 32 feature-contract checks
test_lifecycle.py               🟢 NEW 19 gate + state-machine checks
shift_test.py                   world A vs B           -> shift_results.json
ablation_order.py               🟢 NEW order + diode   -> ablation_order_hard.json
test_calibration.py             🟢 NEW poisoning demo + audit-budget sweep
test_lanl_loader.py             53 assertions on the LANL loader
demo_scenario.py                🔵 CHANGED the on-camera claim wording
lanl_novelty.json               the real-traffic numbers — §6.1, §6.2
lanl_novelty_hn.json            🟢 NEW same, with --host-normalise — §6.4
lanl_p0b.json                   🟢 NEW the paired GNN-vs-baseline verdict — §6.4
```

Never type a number that is not in one of those `.json` files.
