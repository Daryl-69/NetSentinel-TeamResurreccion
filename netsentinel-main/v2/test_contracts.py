#!/usr/bin/env python3
"""
test_contracts.py -- P4. Assert the feature contract between training and
runtime, for every producer of edge features.

Why this exists
---------------
Tier 1's port-scan model has been reporting zero detections for weeks. The
cause is not the dataset: a 39-feature model is being handed the 59-feature
CIC schema. Nothing raises. The array is the wrong width, numpy broadcasts or
truncates somewhere, and the model returns confident nonsense. The same class
of bug is why the exfil VAE's scaler mismatch went unnoticed.

A model silently accepting the wrong feature vector is the most expensive kind
of bug in this project, because every downstream number stays plausible. So:
assert the contract, in a test, on every path that produces features.

What a contract is here
-----------------------
  name    the feature's identity and its position in the vector
  order   position is load-bearing -- the tensor is indexed by it
  count   N_EDGE_FEATURES, and every producer must emit exactly that many
  units   the range a feature is defined over, so a KS statistic that comes
          back as 4.2 fails loudly instead of quietly poisoning a baseline

Run this before quoting any model output.
"""
from __future__ import annotations

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2.categories import (          # noqa: E402
    CATEGORIES, N_CATEGORIES, EDGE_FEATURES, N_EDGE_FEATURES, CAT_INDEX,
)
from netsentinel_v2 import synth                 # noqa: E402
from netsentinel_v2.models import Inspector, Sentry, EdgeAggregator  # noqa: E402

fails, n = [], 0


def check(name, cond, detail=""):
    global n
    n += 1
    if cond:
        print(f"  ok    {name}")
    else:
        fails.append(f"{name}  {detail}")
        print(f"  FAIL  {name}   {detail}")


# The contract. If you change a feature, you change it HERE first and the
# test tells you everything that has to follow.
CONTRACT = [
    # name,                    lo,    hi,    note
    ("log_n_flows",            0.0,   30.0,  "log1p of a count"),
    ("log_bytes_up",           0.0,   40.0,  "log1p of bytes"),
    ("log_bytes_down",         0.0,   40.0,  "log1p of bytes; NEEDS return traffic"),
    ("egress_asymmetry",      -1.0,    1.0,  "(up-down)/(up+down)"),
    ("iat_cv",                 0.0,   50.0,  "coefficient of variation, non-negative"),
    ("ks_uniform",             0.0,    1.0,  "KS statistic"),
    ("ks_exponential",         0.0,    1.0,  "KS statistic"),
    ("fft_prominence",         0.0,  100.0,  "non-negative"),
    ("distinct_endpoint_ratio", 0.0,   1.0,  "a ratio"),
    ("log_duration_mean",      0.0,   30.0,  "log1p of seconds"),
]

print("=" * 70)
print("  FEATURE CONTRACT -- training vs runtime")
print("=" * 70)

# ---- 1. the schema itself -------------------------------------------------
check("EDGE_FEATURES count matches N_EDGE_FEATURES",
      len(EDGE_FEATURES) == N_EDGE_FEATURES,
      f"{len(EDGE_FEATURES)} vs {N_EDGE_FEATURES}")
check("CATEGORIES count matches N_CATEGORIES",
      len(CATEGORIES) == N_CATEGORIES, f"{len(CATEGORIES)} vs {N_CATEGORIES}")
check("contract covers every declared feature",
      len(CONTRACT) == N_EDGE_FEATURES,
      f"contract {len(CONTRACT)} vs schema {N_EDGE_FEATURES}")
check("feature NAMES and ORDER match the contract exactly",
      [c[0] for c in CONTRACT] == list(EDGE_FEATURES),
      f"\n      schema:   {list(EDGE_FEATURES)}\n      contract: {[c[0] for c in CONTRACT]}")
check("CAT_INDEX is consistent with CATEGORIES order",
      all(CAT_INDEX[c] == i for i, c in enumerate(CATEGORIES)))
check("no duplicate feature names", len(set(EDGE_FEATURES)) == N_EDGE_FEATURES)
check("no duplicate category names", len(set(CATEGORIES)) == N_CATEGORIES)

# ---- 2. the producers -----------------------------------------------------
print()
d = synth.generate(n_hosts=12, n_days=3, seed=0, hard_negatives=True)
E, M = d["edges"], d["mask"]
check("synth emits (H, D, W, C, F) with the declared C and F",
      E.shape[3] == N_CATEGORIES and E.shape[4] == N_EDGE_FEATURES,
      f"got C={E.shape[3]} F={E.shape[4]}")
check("synth mask shape agrees with edge tensor",
      M.shape == E.shape[:4], f"{M.shape} vs {E.shape[:4]}")
check("mask is strictly binary", set(np.unique(M)).issubset({0.0, 1.0}))
check("no NaN or inf in emitted features", np.isfinite(E).all())

present = E[M > 0]
check("features are only populated where the mask says present",
      float(np.abs(E[M == 0]).max()) == 0.0,
      f"max |x| on masked-out edges = {float(np.abs(E[M == 0]).max()):.3e}")

# ---- 3. units, per feature ------------------------------------------------
print()
for i, (name, lo, hi, note) in enumerate(CONTRACT):
    col = present[:, i]
    if col.size == 0:
        check(f"units: {name}", False, "no present edges to check")
        continue
    mn, mx = float(col.min()), float(col.max())
    check(f"units: {name:<24} [{mn:8.3f}, {mx:8.3f}]  ({note})",
          mn >= lo - 1e-6 and mx <= hi + 1e-6,
          f"outside contract range [{lo}, {hi}]")

# ---- 4. the models' input widths -----------------------------------------
print()
agg = EdgeAggregator(dim=32, use_cohort=True)
expected_in = N_EDGE_FEATURES + 16 + N_EDGE_FEATURES
check("EdgeAggregator(with cohort) input width == F + 16 + F",
      agg.msg[0].in_features == expected_in,
      f"{agg.msg[0].in_features} vs {expected_in}")
agg2 = EdgeAggregator(dim=32, use_cohort=False)
check("EdgeAggregator(no cohort) input width == F + 16",
      agg2.msg[0].in_features == N_EDGE_FEATURES + 16,
      f"{agg2.msg[0].in_features} vs {N_EDGE_FEATURES + 16}")
check("EdgeAggregator output head consumes the presence mask (2*dim + C)",
      agg.out[0].in_features == 2 * 32 + N_CATEGORIES,
      f"{agg.out[0].in_features} vs {2*32 + N_CATEGORIES}")

insp = Inspector(dim=96)
check("Inspector decoder emits exactly N_EDGE_FEATURES",
      insp.dec[-1].out_features == N_EDGE_FEATURES,
      f"{insp.dec[-1].out_features} vs {N_EDGE_FEATURES}")
check("Inspector category embedding covers every category",
      insp.cat_emb.num_embeddings == N_CATEGORIES)
check("Inspector positional embedding covers a 24-hour day",
      insp.pos.shape[1] == 24, f"{insp.pos.shape[1]}")

sen = Sentry(dim=32, teacher_dim=96)
check("Sentry projects into the teacher's width",
      sen.project.out_features == 96, f"{sen.project.out_features}")

# ---- 5. a real forward pass, end to end -----------------------------------
print()
import torch                                                     # noqa: E402
B, W = 4, 24
e = torch.zeros(B, W, N_CATEGORIES, N_EDGE_FEATURES)
m = torch.zeros(B, W, N_CATEGORIES)
m[:, :, 0] = 1.0
z, pred = insp(e, m, torch.zeros_like(e))
check("Inspector forward returns (B,W,C,F)-shaped reconstruction",
      tuple(pred.shape) == (B, W, N_CATEGORIES, N_EDGE_FEATURES),
      f"{tuple(pred.shape)}")
zs, proj = sen(e, m)
check("Sentry projection is teacher-width so distillation can subtract them",
      proj.shape[-1] == z.shape[-1], f"{proj.shape[-1]} vs {z.shape[-1]}")

# an all-empty batch must not produce NaN -- this is the bug that once blew
# first-epoch loss to ~1e12 via the -1e9 max-pool sentinel
z0, pred0 = insp(e, torch.zeros_like(m), torch.zeros_like(e))
check("an ALL-EMPTY batch produces finite output (max-pool sentinel guard)",
      bool(torch.isfinite(pred0).all()) and bool(torch.isfinite(z0).all()))

print()
print("=" * 70)
if fails:
    print(f"  {len(fails)} of {n} checks FAILED")
    for f in fails:
        print("   -", f)
    sys.exit(1)
print(f"  all {n} checks passed")
print()
print("  This covers the Tier 2 edge-feature path. The Tier 1 port-scan model")
print("  (39 features) and the CIC extractor (59 features) need the same")
print("  treatment -- that mismatch is still open and is why port scan")
print("  reports zero detections.")
