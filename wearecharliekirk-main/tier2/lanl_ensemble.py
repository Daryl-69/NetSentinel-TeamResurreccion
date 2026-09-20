#!/usr/bin/env python3
"""
lanl_ensemble.py -- the experiment the P0b result points at.

lanl_p0b.json and paired_synth.json both found the same shape: the Inspector
and a ~0-parameter per-host Mahalanobis TIE on win rate, but the Inspector's
MEAN within-host AUC is higher while its MEDIAN paired difference is negative.
It wins large on a minority of hosts and loses small on the majority.

Two scorers that disagree host-by-host, each better on a different subset, is
the textbook case for combining rather than choosing. This tests whether the
combination beats both parents on the SAME rows, with the SAME paired test.

Why this can move within-host AUC at all, when per-host z-scoring provably
could not: within-host AUC is invariant to a monotone transform of ONE score.
A combination of two per-host-normalised scores is not monotone in either
parent, so it can and does reorder windows inside a host.

Combiners tested, all parameter-free -- no fitting, nothing to overfit:
    mean    average of the two per-host robust z-scores
    max     the more alarmed of the two (union of suspicions)
    min     agreement only (intersection; a precision play)
    rank    average of within-host percentile ranks, scale-free
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from math import comb

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2 import lanl_loader as ll            # noqa: E402
from lanl_p0b import (roc_auc, bag_mahalanobis,          # noqa: E402
                      per_host_auc, within_host_auc)


def host_z(score, live, min_live=20):
    """Per-host robust z. Fitted on that host's own live TEST windows -- the
    combination needs the two scales commensurable, and this is the cheapest
    way to get there without another fitting stage."""
    out = np.zeros_like(score, dtype=np.float64)
    for h in range(score.shape[0]):
        lv = live[h]
        x = score[h][lv] if lv.sum() >= min_live else score[h]
        if len(x) < 5:
            continue
        med = np.median(x)
        mad = np.median(np.abs(x - med)) * 1.4826 + 1e-9
        out[h] = (score[h] - med) / mad
    return out


def host_rank(score, live):
    """Within-host percentile rank. Scale-free, so it cannot be dominated by
    whichever parent happens to have the fatter tail."""
    out = np.zeros_like(score, dtype=np.float64)
    for h in range(score.shape[0]):
        s = score[h]
        order = np.argsort(s, kind="mergesort")
        r = np.empty(len(s), dtype=np.float64)
        r[order] = np.arange(1, len(s) + 1)
        out[h] = r / len(s)
    return out


def sign_test(A, B):
    common = sorted(set(A) & set(B))
    if not common:
        return None
    d = np.array([A[h][0] - B[h][0] for h in common])
    w, l = int((d > 0).sum()), int((d < 0).sum())
    n = w + l
    p = (min(1.0, 2.0 * sum(comb(n, i) for i in range(min(w, l) + 1)) / 2 ** n)
         if n else float("nan"))
    return dict(n=len(common), wins=w, losses=l, ties=int((d == 0).sum()),
                mean_diff=float(d.mean()), median_diff=float(np.median(d)),
                p=float(p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=".")
    ap.add_argument("--max-hosts", type=int, default=500)
    ap.add_argument("--lanl-days", type=int, default=13)
    ap.add_argument("--profile-cache", default="lanl_profile.json")
    ap.add_argument("--tensor-cache", default=".")
    ap.add_argument("--inspector-ckpt", default="pretrained_real.pt")
    ap.add_argument("--out", default="lanl_ensemble.json")
    a = ap.parse_args()

    d = ll.load_lanl(a.data, max_hosts=a.max_hosts, days=a.lanl_days,
                     cache=a.profile_cache, tensor_cache=a.tensor_cache,
                     label_policy="both", novelty=True, verbose=False)
    E, M = d["edges"], d["mask"]
    H, D, W = E.shape[0], E.shape[1], E.shape[2]
    c_end = max(1, D // 2)
    v_end = max(c_end + 1, int(D * 0.66)) if D > 2 else D
    Ec, Mc = E[:, :c_end], M[:, :c_end]
    Et, Mt = E[:, v_end:D], M[:, v_end:D]
    live = (Mt.sum(-1) > 0).reshape(H, -1)

    A_win = d.get("is_attack_window")
    if A_win is not None:
        atk = np.asarray(A_win)[:, v_end:D].reshape(H, -1).astype(bool)
    else:
        atk = np.repeat(np.asarray(d["is_attack_day"])[:, v_end:D][:, :, None],
                        W, axis=2).reshape(H, -1).astype(bool)
    atk = atk & live

    # ---- the two parents ---------------------------------------------------
    bag, _ = bag_mahalanobis(Ec, Mc, Et, Mt)

    import torch
    from netsentinel_v2 import train as T
    from netsentinel_v2.models import Inspector
    ck = torch.load(a.inspector_ckpt, map_location="cpu", weights_only=False)
    Co = T.compute_cohort(E, M)
    fl = lambda X, x, y: X[:, x:y].reshape(-1, *X.shape[2:])
    Et2, Mt2, Ct2 = fl(E, v_end, D), fl(M, v_end, D), fl(Co, v_end, D)
    Et2, *_ = T.standardise(Et2, Mt2, ck["mu"], ck["sd"])
    insp = Inspector(dim=96)
    insp.load_state_dict(ck["inspector"])
    _, err = T.inspector_forward(insp, Et2, Mt2, Ct2)
    ins = err.reshape(H, -1)

    # ---- commensurable views ----------------------------------------------
    iz, bz = host_z(ins, live), host_z(bag, live)
    ir, br = host_rank(ins, live), host_rank(bag, live)

    cands = {
        "Inspector":            ins,
        "bag-Mahalanobis":      bag,
        "ensemble mean(z)":     (iz + bz) / 2.0,
        "ensemble max(z)":      np.maximum(iz, bz),
        "ensemble min(z)":      np.minimum(iz, bz),
        "ensemble mean(rank)":  (ir + br) / 2.0,
    }

    print("=" * 74)
    print("  Combining the Inspector with the order-free baseline -- real LANL")
    print("=" * 74)
    print(f"  {H} hosts, test days {v_end}..{D-1}, "
          f"{int(live.sum()):,} live windows, {int(atk.sum())} attack windows")
    print()
    print(f"  {'scorer':<22}{'pooled':>9}{'within-host':>14}{'hosts':>7}")
    res, ph = {}, {}
    for name, s in cands.items():
        wm, ws, nh, npos = within_host_auc(s, atk, live)
        pl = roc_auc(s[live], atk[live])
        ph[name] = per_host_auc(s, atk, live)
        res[name] = dict(pooled=pl, within_mean=wm, within_std=ws,
                         n_hosts=nh, n_pos=npos)
        print(f"  {name:<22}{pl:>9.3f}{wm:>10.3f}+/-{ws:<5.3f}{nh:>5}")

    print()
    print("  PAIRED against each parent (exact sign test, same hosts)")
    best, best_p = None, None
    pairs = {}
    for name in cands:
        if name in ("Inspector", "bag-Mahalanobis"):
            continue
        vi = sign_test(ph[name], ph["Inspector"])
        vb = sign_test(ph[name], ph["bag-Mahalanobis"])
        pairs[name] = dict(vs_inspector=vi, vs_bag=vb)
        print(f"    {name}")
        print(f"      vs Inspector : {vi['wins']:>3}-{vi['losses']:<3} "
              f"mean {vi['mean_diff']:+.3f}  p={vi['p']:.4f}")
        print(f"      vs bag       : {vb['wins']:>3}-{vb['losses']:<3} "
              f"mean {vb['mean_diff']:+.3f}  p={vb['p']:.4f}")
        if vi["mean_diff"] > 0 and vb["mean_diff"] > 0:
            score = min(vi["p"], vb["p"])
            if best is None or res[name]["within_mean"] > res[best]["within_mean"]:
                best, best_p = name, score

    print()
    if best:
        r = res[best]
        base = max(res["Inspector"]["within_mean"], res["bag-Mahalanobis"]["within_mean"])
        print(f"  BEST COMBINATION: {best}")
        print(f"    within-host {r['within_mean']:.3f} vs best parent {base:.3f} "
              f"({r['within_mean'] - base:+.3f})")
        sig = (pairs[best]["vs_inspector"]["p"] < 0.05
               and pairs[best]["vs_bag"]["p"] < 0.05)
        print(f"    beats BOTH parents on the mean; "
              f"{'significant' if sig else 'NOT significant'} against both "
              f"(p {pairs[best]['vs_inspector']['p']:.3f} / "
              f"{pairs[best]['vs_bag']['p']:.3f})")
        if not sig:
            print("    -> report as 'the combination is at least as good as "
                  "either alone', not as a win.")
    else:
        print("  NO combination beats both parents on the mean. The two "
              "scorers are not complementary in the way the paired spread "
              "suggested. Report that; it is a real negative result.")

    out = dict(dataset="lanl_cyber1", hosts=H, test_days=D - v_end,
               live_windows=int(live.sum()), attack_windows=int(atk.sum()),
               scorers=res, paired=pairs, best=best)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  wrote {a.out}")


if __name__ == "__main__":
    main()
