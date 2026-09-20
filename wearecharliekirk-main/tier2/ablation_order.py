#!/usr/bin/env python3
"""
ablation_order.py -- does the ORDER of the kill chain carry the signal?

Why this exists
---------------
Slide 3 of our deck ends on the line "we detect the SEQUENCE, not the
destination." That is the whole claim of the project. It is also the claim we
have never tested. Everything we have measured so far -- 0.992 router AUC,
96.9% recall at a 5% budget, 13.7x compression -- is about how faithfully the
Sentry reproduces the Inspector. None of it says the Inspector is reading
order.

If we shuffle the hours of a day and the detector performs just as well, then
it is reading the SET of services a host touched, or the volume, and the word
"sequence" has to come out of the deck. A judge can ask for this experiment in
one sentence, and it takes one line of numpy to run, so we should be the ones
who ran it.

The model can only see order in two places: the learned positional embedding
`Inspector.pos`, and the TransformerEncoder over the window axis. So permuting
the window axis is a complete and honest ablation of order -- it preserves
every edge feature, every category, the volume, the timing statistics and the
mask, and destroys nothing but the arrangement in time.

Conditions
----------
  A  full              trained and scored normally.
  B  shuffled at score trained normally, hours permuted when scoring. Asks:
                       does this model's score depend on order AT ALL?
  C  shuffled at train trained and scored on permuted hours. Asks: is there
                       order information in the data that ANY model could use?
  D  bag of categories order-free by construction: aggregate the day into
                       mean/max/presence and score by Mahalanobis distance.
  E  Markov            first-order category-transition model. The cheapest
                       thing that uses order. If it matches the transformer,
                       we do not need the transformer.
  F  no reverse dir    drops log_bytes_down and egress_asymmetry, the two
                       features a sensor behind a true one-way tap cannot
                       compute. Not about order -- about whether our
                       deployment story and our feature list agree.

Read the result honestly. A > B means the model uses order. A > D and A > E
mean order-awareness beats order-free and cheap-order baselines. If those gaps
are small, say so in the deck and change the claim.

Usage:  python ablation_order.py [--seeds 3] [--hosts 120] [--days 16]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2 import synth, train as T                     # noqa: E402
from netsentinel_v2.categories import EDGE_FEATURES              # noqa: E402


def auc(y, s):
    """Rank-based ROC-AUC. No sklearn dependency, ties handled."""
    y = np.asarray(y).astype(bool)
    s = np.asarray(s, dtype=float)
    n1, n0 = y.sum(), (~y).sum()
    if n1 == 0 or n0 == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), float)
    ranks[order] = np.arange(1, len(s) + 1)
    # average ranks within ties
    su = np.unique(s)
    if len(su) < len(s):
        for v in su:
            m = s == v
            if m.sum() > 1:
                ranks[m] = ranks[m].mean()
    return float((ranks[y].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def permute_windows(E, M, Co, rng):
    """Independently permute the WINDOW axis of every row. Destroys order,
    preserves the exact multiset of windows, the mask and every feature."""
    E2, M2, Co2 = E.copy(), M.copy(), Co.copy()
    W = E.shape[1]
    for i in range(len(E)):
        p = rng.permutation(W)
        E2[i], M2[i], Co2[i] = E[i][p], M[i][p], Co[i][p]
    return E2, M2, Co2


def day_scores(err):
    """One score per host-day. An operator alerts on the worst hour."""
    return err.max(axis=1)


def mahalanobis_bag(tr, te):
    """Order-free baseline: diagonal Mahalanobis on day-level aggregates."""
    mu, sd = tr.mean(0), tr.std(0) + 1e-6
    return (((te - mu) / sd) ** 2).mean(1)


def bag_features(E, M):
    """Collapse the window axis. Whatever survives here is order-free."""
    pres = M.mean(axis=1)                             # (N,C) how often present
    mean = (E * M[..., None]).sum(1) / np.maximum(M.sum(1), 1)[..., None]
    mx = np.where(M[..., None] > 0, E, -1e9).max(1)
    mx = np.where(M.sum(1)[..., None] > 0, mx, 0.0)
    return np.concatenate([pres.reshape(len(E), -1),
                           mean.reshape(len(E), -1),
                           mx.reshape(len(E), -1)], axis=1)


def markov_scores(M_tr, M_te, n_cat):
    """First-order transition model over the dominant category per window."""
    def seq(M_):
        act = M_.sum(axis=2)                          # (N,W) edges per window
        dom = np.where(act > 0, M_.argmax(axis=2), n_cat)   # n_cat == 'idle'
        return dom
    s_tr, s_te = seq(M_tr), seq(M_te)
    K = n_cat + 1
    Tm = np.ones((K, K))                              # Laplace smoothing
    for r in s_tr:
        for a, b in zip(r[:-1], r[1:]):
            Tm[a, b] += 1
    Tm /= Tm.sum(1, keepdims=True)
    logT = np.log(Tm)
    out = np.empty(len(s_te))
    for i, r in enumerate(s_te):
        out[i] = -np.mean([logT[a, b] for a, b in zip(r[:-1], r[1:])])
    return out


def run_seed(seed, hosts, days, epochs, stealth=(0.0, 1.0), hard=False,
             verbose=True):
    rng = np.random.default_rng(1000 + seed)
    d = synth.generate(n_hosts=hosts, n_days=days, seed=seed,
                       stealth_range=stealth, hard_negatives=hard)
    E, M, A = d["edges"], d["mask"], d["is_attack_day"]
    H, D, W, C, F = E.shape
    Co = T.compute_cohort(E, M)

    split = days // 2                       # attackers activate at or after this
    def flat(x, lo, hi):
        return x[:, lo:hi].reshape(-1, *x.shape[2:])

    Etr, Mtr, Ctr = flat(E, 0, split), flat(M, 0, split), flat(Co, 0, split)
    Ete, Mte, Cte = flat(E, split, D), flat(M, split, D), flat(Co, split, D)
    y = A[:, split:].reshape(-1)

    Etr, mu, sd = T.standardise(Etr, Mtr)
    Ete, _, _ = T.standardise(Ete, Mte, mu, sd)
    Ctr, cmu, csd = T.standardise(Ctr, Mtr)
    Cte, _, _ = T.standardise(Cte, Mte, cmu, csd)

    res = {}

    # ---- A: the model as it exists ------------------------------------
    m = T.train_inspector(Etr, Mtr, Ctr, epochs=epochs, seed=seed)
    _, err = T.inspector_forward(m, Ete, Mte, Cte)
    res["A_full"] = auc(y, day_scores(err))

    # ---- B: same model, hours permuted at scoring time -----------------
    Ep, Mp, Cp = permute_windows(Ete, Mte, Cte, rng)
    _, errp = T.inspector_forward(m, Ep, Mp, Cp)
    res["B_shuffled_at_score"] = auc(y, day_scores(errp))

    # ---- C: trained on permuted hours too ------------------------------
    Etrp, Mtrp, Ctrp = permute_windows(Etr, Mtr, Ctr, rng)
    m2 = T.train_inspector(Etrp, Mtrp, Ctrp, epochs=epochs, seed=seed)
    _, err2 = T.inspector_forward(m2, Ep, Mp, Cp)
    res["C_shuffled_at_train"] = auc(y, day_scores(err2))

    # ---- D: order-free bag ---------------------------------------------
    res["D_bag_of_categories"] = auc(
        y, mahalanobis_bag(bag_features(Etr, Mtr), bag_features(Ete, Mte)))

    # ---- E: first-order Markov on category transitions ------------------
    res["E_markov_transitions"] = auc(y, markov_scores(Mtr, Mte, C))

    # ---- F: no reverse-direction features (true one-way sensor) ---------
    down = EDGE_FEATURES.index("log_bytes_down")
    asym = EDGE_FEATURES.index("egress_asymmetry")
    keep = np.ones(F, dtype=bool); keep[[down, asym]] = False
    Etr_d, Ete_d = Etr.copy(), Ete.copy()
    Etr_d[..., ~keep] = 0.0
    Ete_d[..., ~keep] = 0.0
    Ctr_d, Cte_d = Ctr.copy(), Cte.copy()
    Ctr_d[..., ~keep] = 0.0
    Cte_d[..., ~keep] = 0.0
    m3 = T.train_inspector(Etr_d, Mtr, Ctr_d, epochs=epochs, seed=seed)
    _, err3 = T.inspector_forward(m3, Ete_d, Mte, Cte_d)
    res["F_no_reverse_direction"] = auc(y, day_scores(err3))

    res["_n_test_days"] = int(len(y))
    res["_n_attack_days"] = int(y.sum())
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--hosts", type=int, default=120)
    ap.add_argument("--days", type=int, default=16)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--stealth-lo", type=float, default=0.0,
                    help="1.0 = fully shaped adversary. Raise this until the "
                         "task stops being saturated, or the ablation is "
                         "comparing perfect scores and means nothing.")
    ap.add_argument("--stealth-hi", type=float, default=1.0)
    ap.add_argument("--hard-negatives", action="store_true",
                    help="benign hosts that chat all day and poll on a "
                         "schedule. Without this the benchmark is solved by "
                         "one counter and the ablation is meaningless.")
    ap.add_argument("--out", default="ablation_order.json")
    a = ap.parse_args()

    T.set_device("cpu")
    runs = []
    for s in range(a.seeds):
        print(f"\n--- seed {s} ---", flush=True)
        runs.append(run_seed(s, a.hosts, a.days, a.epochs,
                             stealth=(a.stealth_lo, a.stealth_hi),
                             hard=a.hard_negatives))

    keys = [k for k in runs[0] if not k.startswith("_")]
    agg = {k: (float(np.mean([r[k] for r in runs])),
               float(np.std([r[k] for r in runs]))) for k in keys}

    print()
    print("=" * 72)
    print("  DOES ORDER CARRY THE SIGNAL?   ROC-AUC on held-out host-days")
    print(f"  {a.seeds} seeds, {a.hosts} hosts, {a.days} days, "
          f"{runs[0]['_n_attack_days']}/{runs[0]['_n_test_days']} attack days")
    print("=" * 72)
    label = {
        "A_full": "A  full model (order-aware)",
        "B_shuffled_at_score": "B  hours permuted at SCORE time",
        "C_shuffled_at_train": "C  hours permuted at TRAIN+SCORE",
        "D_bag_of_categories": "D  bag of categories (order-free)",
        "E_markov_transitions": "E  first-order Markov transitions",
        "F_no_reverse_direction": "F  no reverse-direction features",
    }
    for k in keys:
        m, s = agg[k]
        print(f"    {label[k]:<38} {m:.3f} +/- {s:.3f}")

    A, B = agg["A_full"][0], agg["B_shuffled_at_score"][0]
    Cc, Dd = agg["C_shuffled_at_train"][0], agg["D_bag_of_categories"][0]
    Ee, Ff = agg["E_markov_transitions"][0], agg["F_no_reverse_direction"][0]

    print()
    print("  READING:")
    print(f"    order sensitivity of the trained model   A - B = {A - B:+.3f}")
    print(f"    order information available in the data  A - C = {A - Cc:+.3f}")
    print(f"    benefit over an order-free baseline      A - D = {A - Dd:+.3f}")
    print(f"    benefit over cheap first-order order     A - E = {A - Ee:+.3f}")
    print(f"    cost of losing reverse direction         A - F = {A - Ff:+.3f}")
    print()
    if A - B < 0.02 and A - Cc < 0.02:
        print("    VERDICT: this model is close to order-blind on this data.")
        print("    The word 'sequence' is not earned by these numbers. Say")
        print("    'cross-service co-occurrence' until an experiment says")
        print("    otherwise, and put this table in the deck.")
    elif A - Dd < 0.02:
        print("    VERDICT: order matters to the model, but an order-free bag")
        print("    does just as well end-to-end. The sequence framing is not")
        print("    what is buying the detection. Report both.")
    else:
        print("    VERDICT: order-awareness is doing real work here. The claim")
        print("    survives THIS test -- on synthetic chains, which is the only")
        print("    place chains exist for us today. Say that out loud.")

    out = {"config": vars(a), "runs": runs,
           "mean_std": {k: list(v) for k, v in agg.items()}}
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  wrote {a.out}")


if __name__ == "__main__":
    main()
