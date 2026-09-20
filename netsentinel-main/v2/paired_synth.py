#!/usr/bin/env python3
"""
paired_synth.py -- the follow-up that lanl_p0b.py forces.

On the real LANL corpus the Inspector TIES a ~0-parameter, order-free per-host
Mahalanobis: paired over 77 attacked hosts, 36 wins to 40, one tie, sign test
p = 0.731 (lanl_p0b.json).

Our defence of the architecture is that LANL removes the thing the model exists
to use -- it is de-identified, has zero egress traffic, and resolves to three
categories with two of them carrying 100% of the edges. That defence is only
worth saying out loud if the Inspector DOES beat the baseline somewhere the
cross-service structure actually exists.

So: same paired test, same baseline, on the synthetic generator, which has all
nine categories, real egress, and the chain the model was designed around.

  * Inspector wins here  -> the LANL tie is an evaluation-corpus problem and we
                            can say so with a number behind it.
  * Inspector ties here  -> the architecture does not earn its parameters even
                            on data built to favour it, and we need to know
                            that before the 20th rather than during Q&A.

Both outcomes get written down. Run WITHOUT the busy-host confound imposed --
that was confound_test.py's job. This asks a different question: given clean,
structured data, is the graph worth 205,546 parameters?
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from math import comb

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2 import synth, train as T          # noqa: E402
from netsentinel_v2.hostnorm import within_host_auc, _auc  # noqa: E402
from confound_test import bag_mahalanobis_per_host    # noqa: E402


def per_host_auc(score, atk_win, ht, live_t, min_neg=5):
    """Per-host AUC keyed by host id, so two scorers can be paired."""
    out = {}
    for h in np.unique(ht):
        r = np.where(ht == h)[0]
        lv = live_t[r].reshape(-1)
        y = atk_win[r].reshape(-1)[lv].astype(bool)
        if y.sum() == 0 or (~y).sum() < min_neg:
            continue
        au = _auc(score[r].reshape(-1)[lv], y)
        if not np.isnan(au):
            out[int(h)] = float(au)
    return out


def sign_test(A, B):
    """Exact two-sided binomial sign test over the hosts both scorers cover."""
    common = sorted(set(A) & set(B))
    if not common:
        return None
    d = np.array([A[h] - B[h] for h in common])
    w, l = int((d > 0).sum()), int((d < 0).sum())
    n = w + l
    p = (min(1.0, 2.0 * sum(comb(n, i) for i in range(min(w, l) + 1)) / 2 ** n)
         if n else float("nan"))
    return dict(hosts=len(common), a_wins=w, b_wins=l, ties=int((d == 0).sum()),
                mean_diff=float(d.mean()), median_diff=float(np.median(d)),
                p=float(p))


def run_seed(seed, hosts, days, epochs):
    d = synth.generate(n_hosts=hosts, n_days=days, seed=seed,
                       stealth_range=(0.9, 1.0), hard_negatives=True)
    E, M, A = d["edges"], d["mask"], d["is_attack_day"]
    H, D, W = E.shape[0], E.shape[1], E.shape[2]

    Co = T.compute_cohort(E, M)
    split = days // 2
    hidx = np.repeat(np.arange(H)[:, None], D, axis=1)
    fl = lambda x, lo, hi: x[:, lo:hi].reshape(-1, *x.shape[2:])

    Ec, Mc, Cc = fl(E, 0, split), fl(M, 0, split), fl(Co, 0, split)
    Et, Mt, Ct = fl(E, split, D), fl(M, split, D), fl(Co, split, D)
    hc, ht = hidx[:, :split].reshape(-1), hidx[:, split:].reshape(-1)
    atk_day = A[:, split:].reshape(-1)

    Ec_s, mu, sd = T.standardise(Ec, Mc)
    Et_s, _, _ = T.standardise(Et, Mt, mu, sd)
    Cc_s, cmu, csd = T.standardise(Cc, Mc)
    Ct_s, _, _ = T.standardise(Ct, Mt, cmu, csd)

    insp = T.train_inspector(Ec_s, Mc, Cc_s, epochs=epochs, seed=seed)
    _, err_t = T.inspector_forward(insp, Et_s, Mt, Ct_s)

    live_t = (Mt.sum(-1) > 0)
    atk_win = np.repeat(atk_day[:, None], W, axis=1) & live_t
    bag = bag_mahalanobis_per_host(Ec_s, Mc, hc, Et_s, Mt, ht)

    lf = live_t.reshape(-1)
    y = atk_win.reshape(-1)[lf]

    ins_ph = per_host_auc(err_t, atk_win, ht, live_t)
    bag_ph = per_host_auc(bag, atk_win, ht, live_t)
    rep = sign_test(ins_ph, bag_ph)

    return dict(
        seed=seed,
        pooled_inspector=_auc(err_t.reshape(-1)[lf], y),
        pooled_bag=_auc(bag.reshape(-1)[lf], y),
        within_inspector=within_host_auc(err_t, atk_win, ht, live_t)[0],
        within_bag=within_host_auc(bag, atk_win, ht, live_t)[0],
        paired=rep,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=200)
    ap.add_argument("--days", type=int, default=16)
    ap.add_argument("--epochs", type=int, default=10)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--out", default="paired_synth.json")
    a = ap.parse_args()

    runs = [run_seed(s, a.hosts, a.days, a.epochs) for s in range(a.seeds)]
    g = lambda k: (float(np.mean([r[k] for r in runs])),
                   float(np.std([r[k] for r in runs])))

    print()
    print("=" * 72)
    print("  Inspector vs a ~0-parameter order-free baseline")
    print("  on SYNTHETIC data -- 9 categories, real egress, the chain present")
    print("=" * 72)
    print(f"  {a.hosts} hosts x {a.days} days, {a.seeds} seeds, "
          f"hard negatives ON, no busy-host confound imposed")
    print()
    for name, k in (("pooled  AUC", "pooled_"), ("within-host AUC", "within_")):
        im, isd = g(k + "inspector")
        bm, bsd = g(k + "bag")
        print(f"  {name:<18} Inspector {im:.3f} +/- {isd:.3f}    "
              f"bag {bm:.3f} +/- {bsd:.3f}    delta {im-bm:+.3f}")

    print()
    print("  PAIRED per host, per seed")
    ps, mds = [], []
    mdn = []
    for r in runs:
        p = r["paired"]
        if not p:
            continue
        ps.append(p["p"]); mds.append(p["mean_diff"]); mdn.append(p["median_diff"])
        print(f"    seed {r['seed']}:  {p['a_wins']:>3} Inspector / "
              f"{p['b_wins']:>3} bag / {p['ties']} tie   "
              f"n={p['hosts']:<4} mean diff {p['mean_diff']:+.3f}   "
              f"p = {p['p']:.4f}")

    sig = sum(1 for p in ps if p < 0.05)
    md = float(np.mean(mds)) if mds else float("nan")
    # The MEDIAN paired difference, recorded unconditionally. Mean-positive
    # with median-negative is the whole finding here -- the Inspector wins
    # large on a minority of hosts and loses small on the majority -- and an
    # earlier version of this file wrote the median only on one verdict branch,
    # so the documented figure had no source in the code that was shipped.
    mdmed = float(np.mean(mdn)) if mdn else float("nan")

    # ---- pool across seeds -------------------------------------------------
    # Per-seed n is small (attacked hosts are ~7% of the population), and a
    # per-seed sign test at n=15 CANNOT reach p<0.05 unless the split is close
    # to 14-1. Reporting "not significant" from an underpowered test as if it
    # were evidence of a tie is the exact error this file exists to avoid.
    W = sum(r["paired"]["a_wins"] for r in runs if r["paired"])
    L = sum(r["paired"]["b_wins"] for r in runs if r["paired"])
    N = W + L
    P = (min(1.0, 2.0 * sum(comb(N, i) for i in range(min(W, L) + 1)) / 2 ** N)
         if N else float("nan"))
    # smallest split at this N that WOULD reach p<0.05 -- the power check
    detectable = None
    for k in range(N // 2, -1, -1):
        if 2.0 * sum(comb(N, i) for i in range(k + 1)) / 2 ** N < 0.05:
            detectable = (N - k, k)
            break
    print(f"  POOLED  Inspector {W} / bag {L}   n = {N}   "
          f"sign-test p = {P:.4f}")
    if detectable:
        print(f"  power   at n={N} the test needs at least "
              f"{detectable[0]}-{detectable[1]} to reach p<0.05")
    else:
        print(f"  power   at n={N} NO split can reach p<0.05 -- the test "
              f"cannot answer the question. Raise --hosts or --seeds.")

    print()
    if detectable is None:
        verdict = (f"UNDERPOWERED: n={N} paired hosts cannot reach "
                   f"significance at any split. This run answers nothing; "
                   f"raise --hosts. Direction so far {md:+.3f}.")
    elif P < 0.05 and md > 0:
        verdict = ("the Inspector BEATS the order-free baseline where the "
                   "cross-service structure exists. The LANL tie is an "
                   "evaluation-corpus problem and we can say so with a number "
                   "behind it.")
    elif P < 0.05:
        verdict = ("the baseline BEATS the Inspector even on data built to "
                   "favour it. The architecture does not earn its parameters.")
    else:
        verdict = (f"NO DIFFERENCE DETECTED at n={N} (p={P:.3f}), though the "
                   f"means favour the Inspector by {md:+.3f}. This is not "
                   f"evidence of a tie -- it is absence of evidence either "
                   f"way. Quote it as 'we could not detect a difference', "
                   f"never as 'the Inspector wins'.")
    print(f"  pooled mean paired diff {md:+.4f}   "
          f"mean of per-seed medians {mdmed:+.4f}")
    print(f"  VERDICT: {verdict}")
    print()
    print("  Compare with LANL (lanl_p0b.json): 36/40/1, mean diff -0.036,")
    print("  p = 0.731 -- also no detectable difference, but there the means")
    print("  favour the BASELINE, not the Inspector.")

    with open(a.out, "w") as f:
        json.dump(dict(hosts=a.hosts, days=a.days, seeds=a.seeds,
                       epochs=a.epochs, hard_negatives=True,
                       confound_imposed=False, runs=runs,
                       seeds_significant=sig, mean_paired_diff=md,
                       pooled_inspector_wins=W, pooled_bag_wins=L,
                       median_paired_diff=mdmed,
                       pooled_n=N, pooled_sign_test_p=P,
                       min_detectable_split=detectable,
                       verdict=verdict), f, indent=2)
    print(f"  wrote {a.out}")


if __name__ == "__main__":
    main()
