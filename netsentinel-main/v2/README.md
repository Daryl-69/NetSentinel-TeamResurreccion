# NetSentinel V2 — Inspector–Sentry harness

Builds items **#1 and #2** of the V2_HARDENING build order — the Sentry that routes instead of
detects, and the chart that says whether it works — plus a **distribution-shift stress test** and
a **Zeek loader** so real traffic can replace the generator.

```bash
pip install torch numpy scipy scikit-learn matplotlib
python run_experiment.py --seeds 3 --hosts 300 --days 24    # ~2 min/seed, CPU
python shift_test.py     --seeds 3 --hosts 300 --days 24
python make_charts.py results.json
```

Kaggle: `netsentinel_v2_kaggle.ipynb` is self-contained (writes the package itself). **You do not
need a GPU** for the default run.

---

## ⚠️ Results changed on 2026-09-04 — a bug reversed the headline finding

`EdgeAggregator`'s max-pool guarded on `denom`, which is `.clamp(min=1.0)` and therefore never
zero. The `-1e9` masking sentinel escaped into the encoder on **every empty window (~52% of all
windows)**. First-epoch loss was **3.7 × 10¹²**. The model converged anyway, which is exactly why
nothing downstream looked wrong.

Because `-1e9` made empty-vs-populated windows trivially separable in embedding space, the
Mahalanobis router harvested that artifact as free discriminative signal, and **appeared to win**.
It does not.

| Router | buggy (withdrawn) | **corrected** |
|---|---|---|
| **A** distilled detector — *the original V2 design* | 0.805 | **0.876 ← best** |
| **B** encoder + Mahalanobis — *V2_HARDENING B1* | 0.845 | 0.818 ± 0.046 ← worst |
| **C** deferral head — *V2_HARDENING G5* | 0.791 | 0.850 |

**Build A, or A+C.** The V2_HARDENING B1 recommendation is withdrawn on this evidence.

---

## What it tests

Three routers at **equal escalation budget**. All three share the same distilled encoder; only the
judge differs, which is what makes the comparison fair.

| | Router | Provenance |
|---|---|---|
| **A** | distilled **detector** — student regresses the Inspector's anomaly score | the original V2 design |
| **B** | **encoder + Mahalanobis** — distil only the encoder, keep the per-host decision exact | V2_HARDENING B1 |
| **C** | **deferral head** — predict *"would the Inspector flag this?"* | V2_HARDENING G5 |

Plus the **G1 diagnostic**: does the student preserve the Inspector's *local* geometry? Measured as
kNN-neighbourhood overlap, not score correlation — score correlation stays high while local
structure quietly collapses.

## Results — 3 seeds, 300 hosts, 24 days, synthetic

```
Inspector AUC vs attack windows        0.875          <- the oracle is real
Router AUC vs Inspector decision
  A distilled detector                 0.876   <- best
  C deferral head                      0.850
  B encoder + Mahalanobis              0.818 ± 0.046
Compression                            205,546 -> 14,992 params  (13.7x)
kNN overlap@20                         0.346  -> MARGINAL
```

Recall of Inspector-flagged windows by escalation budget:

| budget | **A** | B | C |
|---|---|---|---|
| 1% | 11.2% | 11.4% | 10.7% |
| 5% | **37.1% ± 0.9** | 32.8% ± 6.9 | 38.3% ± 7.0 |
| 10% | 52.0% | 48.9% | 52.3% |
| lift @5% | 7.4× | 6.6× | 7.7× |

### Three findings

**1. The original design wins; the B1 "fix" does not.** Distilling the detector beats distilling
only the encoder and judging with Mahalanobis. The distillation-transfer argument predicted the
opposite; at this scale and dimensionality it does not hold.

**2. B's variance is 7× A's** (±6.9 vs ±0.9). That is the covariance-estimation instability flagged
as V2_HARDENING G3: ~4k commissioning windows for a 32-dim per-host covariance is too thin, even
with Ledoit–Wolf shrinkage. The instability is the tell, not the mean.

**3. The design target is still NOT met.** V2_HARDENING proposed *"≥95% recall at ≤5% budget."*
Measured: **37.1%** (A). Routing works — 7.4× better than random — but that headline was
aspirational. **Do not put ≥95% on a slide.**

### The claim this run supports

> *At a 5% escalation budget the Sentry recovers 37% of everything the Inspector would have
> flagged — 7.4× better than random routing — while being 13.7× smaller and running on CPU.
> Attack-recall figures are indicative-only until real capture replaces the generator.*

---

## Distribution-shift stress test (`shift_test.py`)

Answers the question a judge will ask: *your model learned normal from your own generator — what
happens on a network it has never seen?*

**World A** (dev-heavy software org) trains the encoder. **World B** (OT/plant-heavy: different
role mix, slower human rhythms, lower volumes, longer working day) is deployed to **cold** —
baselines re-fit on B's own commissioning window, but A's threshold and A's standardiser applied
unchanged, because that is the mistake a real deployment makes.

| metric | world A | world B | change |
|---|---|---|---|
| Inspector AUC vs attack | 0.881 | 0.852 | −3.3% |
| Router AUC | 0.804 | 0.825 | +2.7% |
| Recall @5% budget | 32.6% | 36.0% | +10.5% |
| kNN geometry overlap | 0.348 | 0.332 | −4.7% |
| **Flag rate (target 1.0%)** | **6.82%** | **6.26%** | — |

**The mechanism transfers. The calibration does not.** Detection quality barely moves across a
genuinely different organisation — that is a real, defensible answer. But a threshold set at world
A's 99th percentile flags 6.26% of world B, 6× the target.

And it flags **6.82% in world A's own test period**. So this is not a shift problem — it is a
**temporal** one: test-period reconstruction errors run systematically higher than
commissioning-period errors even in the same world. **The threshold decays from the day it is set.**

Architectural consequence: every deployment needs its own calibration window *and* rolling
re-calibration. The current design has no such knob. Add one.

---

## Real traffic (`netsentinel_v2/zeek_loader.py`)

Turns a directory of Zeek logs into the same `(host, day, window, category, feature)` tensor the
generator produces, so real data drops in without touching `models.py`, `baseline.py` or `train.py`.

```python
from netsentinel_v2 import zeek_loader as zl
real = zl.load_dir("path/to/zeek/logs")   # conn.log + ssl.log + dns.log
print(zl.summarise(real))
```

Uses `conn.log` for volume/timing, `ssl.log` SNI and `dns.log` queries for the Service Category
Resolver. No hostname (ECH/DoH/raw IP) → `Unknown_External`, deliberately: an unknown-category
transition is itself informative, and pretending otherwise hides how much visibility you lost.

Sources, and what each can and cannot do, are in **`DATASETS.md`**. Short version: no LOTS chain
corpus exists (a 2026 survey of 124 IDS datasets found none with multi-stage campaigns);
Stratosphere Normal Captures are real and free but hours-long and single-host, so they are good for
**encoder pretraining** and useless for multi-day per-host baselines.

---

## Honesty boundary

`synth.py` is a **stand-in, not a dataset**. A detector evaluated on the generator that made its
attacks learns the generator. Legitimate uses: exercising the harness, and the
**router-vs-Inspector agreement** experiment, which does not depend on the attacks being realistic
because the Inspector is the reference oracle.

The `RECALL OF ATTACK WINDOWS` block is **indicative only**. Unrealistic *benign* data is the more
damaging error, not unrealistic attacks.

What the generator does get right, because otherwise the experiment is meaningless: benign
behaviour is multimodal (workday/evening/weekend), and **DevOps hosts legitimately produce the same
Recon→Repo→Messaging→Cloud sequence as the attack**, with human timing. Those are the hard
negatives. Edge features are computed from real generated inter-arrival times, so the KS/FFT
automation features are genuine statistics.

## Evaluation protocol

Follows arXiv:2608.01454 — strictly monotonic **train → validate → test in time** (no random
splits), thresholds calibrated on **validation only**, **multi-seed** with mean ± σ. Rank-based
budget selection, not quantile thresholds, so score ties cannot silently report 100% recall.

## Layout

```
netsentinel_v2/
  categories.py   Service Category Resolver taxonomy + edge-feature schema
  synth.py        host-day generator; WORLDS A/B for the shift test
  models.py       Inspector (E-GraphSAGE + Transformer AE), Sentry, DeferralHead
  baseline.py     per-host baseline: Ledoit-Wolf (G3), k components (G4), trimmed
  diagnostics.py  G1 kNN-geometry go/no-go
  train.py        training loops + budget curve
  cost_model.py   GPU-host-day model and the corrected ETTE bound
  zeek_loader.py  real Zeek logs -> the same tensors
run_experiment.py   the router comparison
shift_test.py       the distribution-shift stress test
make_charts.py      the two charts
make_notebook.py    regenerates the Kaggle notebook from these sources
```

## Known gaps

- `Inspector` is a **reimplementation of GraphIDS** (arXiv:2509.16625), not our design. Cite it.
- No escalation loop, retention rule or sampling scheduler — the routers are **scorers**, not yet
  the architecture. `cost_model.py` computes their economics; the runtime does not run them.
- No rolling re-calibration, which the shift test says is required.
- Hop-2 cohort uses the full same-category population, not a sampled fanout.
