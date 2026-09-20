#!/usr/bin/env python3
"""
confound_test.py -- P0 / P0b. Does per-host normalisation remove the
busy-host confound, and does the GNN beat a near-free order-free baseline?

Why this exists instead of a LANL re-run
----------------------------------------
The right experiment is to re-run `lanl_novelty` with per-host normalised
scores. The LANL cyber1 corpus is not reachable from this environment
(csr.lanl.gov is refused by the egress policy, and the copy that produced
lanl_novelty.json lives elsewhere). So this does the next most useful thing:
it REPRODUCES the confound in a setting where we control the ground truth,
then measures whether the fix removes it.

That is arguably the stronger validation of the mechanism, because here we
know by construction that the busy-host effect is present and exactly how big
it is. It is NOT a substitute for the LANL number. Run
`run_experiment.py --lanl <root> --host-normalise` to get that; the command is
in the doc and the code path is the same `HostScoreNormaliser` used here.

The confound, reproduced
------------------------
On LANL the red team went after busy machines: live-window density 0.811 on
attacked hosts versus 0.530 on everyone else. So here we thin the non-attacked
hosts' activity until the same gap exists. Nothing about the attack signal is
touched -- only how busy the two populations are. That is precisely the
structure that let a pooled AUC of 0.745 sit on top of a within-host AUC of
0.557.

What is measured, four ways
---------------------------
                        pooled (all host-days)   within-host (each vs itself)
  Inspector, raw error         inflated by busyness      the honest number
  Inspector, per-host z        should FALL               should RISE (P0)
  bag-of-categories Mahalanobis, per host  -- the ~0-parameter baseline (P0b)

A falling pooled AUC is the CORRECT outcome for the fix, not a regression:
the pooled number was inflated by the confound.

Usage:  python confound_test.py [--seeds 3] [--hosts 120] [--days 16]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2 import synth, train as T                       # noqa: E402
from netsentinel_v2.hostnorm import (                              # noqa: E402
    HostScoreNormaliser, within_host_auc, _auc,
)


def impose_busy_confound(M, E, attacked, rng, target_other=0.53):
    """Thin the NON-attacked hosts until their live-window density matches
    what LANL looked like. Attacked hosts are left completely untouched, so
    no attack signal is added or removed -- only the busyness gap appears."""
    M2, E2 = M.copy(), E.copy()
    H = M.shape[0]
    for h in range(H):
        if attacked[h]:
            continue
        live = M2[h].sum(-1) > 0                       # (D,W)
        idx = np.argwhere(live)
        if len(idx) == 0:
            continue
        cur = live.mean()
        if cur <= target_other:
            continue
        drop = int(len(idx) * (1.0 - target_other / cur))
        pick = rng.choice(len(idx), size=drop, replace=False)
        for d, w in idx[pick]:
            M2[h, d, w] = 0.0
            E2[h, d, w] = 0.0
    return M2, E2


def bag_mahalanobis_per_host(Ec, Mc, hc, Et, Mt, ht):
    """P0b: the ~0-parameter order-free baseline.

    Per host, fit a diagonal Gaussian to its commissioning windows in RAW
    feature space (category x feature, flattened) and score test windows by
    squared robust distance. No graph, no attention, no embedding, no
    training -- just a mean and a spread per host. If this matches the
    Inspector we have to justify the Inspector on something other than
    accuracy.
    """
    def flat(E, M):
        n = len(E)
        return np.concatenate([E.reshape(n, E.shape[1], -1),
                               M.reshape(n, M.shape[1], -1)], axis=-1)
    Fc, Ft = flat(Ec, Mc), flat(Et, Mt)
    live_c = (Mc.sum(-1) > 0)
    out = np.zeros(Ft.shape[:2], dtype=np.float64)
    for h in np.unique(ht):
        rc = np.where(hc == h)[0]
        rt = np.where(ht == h)[0]
        X = Fc[rc].reshape(-1, Fc.shape[-1])
        lv = live_c[rc].reshape(-1)
        if lv.sum() >= 20:
            X = X[lv]
        if len(X) < 5:
            continue
        med = np.median(X, axis=0)
        mad = np.median(np.abs(X - med), axis=0) * 1.4826 + 1e-6
        Z = (Ft[rt] - med) / mad
        out[rt] = (Z ** 2).mean(axis=-1)
    return out


def run_seed(seed, hosts, days, epochs):
    rng = np.random.default_rng(500 + seed)
    d = synth.generate(n_hosts=hosts, n_days=days, seed=seed,
                       stealth_range=(0.9, 1.0), hard_negatives=True)
    E, M, A = d["edges"], d["mask"], d["is_attack_day"]
    H, D, W, C, F = E.shape
    attacked = A.any(axis=1)

    M, E = impose_busy_confound(M, E, attacked, rng)
    dens_a = float((M[attacked].sum(-1) > 0).mean())
    dens_o = float((M[~attacked].sum(-1) > 0).mean())

    Co = T.compute_cohort(E, M)
    split = days // 2
    hidx = np.repeat(np.arange(H)[:, None], D, axis=1)

    def flat(x, lo, hi):
        return x[:, lo:hi].reshape(-1, *x.shape[2:])
    Ec, Mc, Cc = flat(E, 0, split), flat(M, 0, split), flat(Co, 0, split)
    Et, Mt, Ct = flat(E, split, D), flat(M, split, D), flat(Co, split, D)
    hc = hidx[:, :split].reshape(-1)
    ht = hidx[:, split:].reshape(-1)
    atk_day = A[:, split:].reshape(-1)

    Ec_s, mu, sd = T.standardise(Ec, Mc)
    Et_s, _, _ = T.standardise(Et, Mt, mu, sd)
    Cc_s, cmu, csd = T.standardise(Cc, Mc)
    Ct_s, _, _ = T.standardise(Ct, Mt, cmu, csd)

    insp = T.train_inspector(Ec_s, Mc, Cc_s, epochs=epochs, seed=seed)
    _, err_c = T.inspector_forward(insp, Ec_s, Mc, Cc_s)
    _, err_t = T.inspector_forward(insp, Et_s, Mt, Ct_s)

    live_c = (Mc.sum(-1) > 0)
    live_t = (Mt.sum(-1) > 0)
    atk_win = np.repeat(atk_day[:, None], W, axis=1) & live_t

    # ---- P0: fit the normaliser on COMMISSIONING only -------------------
    hn = HostScoreNormaliser(min_live=20).fit(err_c, hc, live_c)
    err_t_z = hn.transform(err_t, ht)

    # ---- P0b: the order-free, ~0-parameter baseline ---------------------
    bag = bag_mahalanobis_per_host(Ec_s, Mc, hc, Et_s, Mt, ht)

    lf = live_t.reshape(-1)
    y = atk_win.reshape(-1)[lf]
    hflat = np.repeat(ht[:, None], W, axis=1).reshape(-1)[lf]
    busy = np.asarray([float((M[h].sum(-1) > 0).mean()) for h in hflat])

    def pooled(s):
        return _auc(s.reshape(-1)[lf], y)

    def wh(s):
        return within_host_auc(s, atk_win, ht, live_t)

    def budget(s, b=0.05):
        """What a global top-k escalation cut actually selects.

        This is where the confound bites operationally. Within-host AUC is
        invariant to any per-host monotone rescaling -- it ranks a host
        against itself, so subtracting a per-host median and dividing by a
        positive per-host scale cannot change it. The POOLED top-k cut is a
        different story: with raw error the budget goes to whoever is busiest.
        """
        v = s.reshape(-1)[lf]
        k = max(1, int(round(b * len(v))))
        order = np.argsort(-v, kind="stable")[:k]
        sel = np.zeros(len(v), dtype=bool); sel[order] = True
        return {
            "recall_attack": float(y[sel].sum() / max(y.sum(), 1)),
            "precision": float(y[sel].mean()),
            "hosts_touched": int(len(np.unique(hflat[sel]))),
            "mean_busyness_of_selected": float(busy[sel].mean()),
        }

    r = {
        "density_attacked": dens_a, "density_other": dens_o,
        "pooled_raw": pooled(err_t),
        "pooled_z": pooled(err_t_z),
        "pooled_bag": pooled(bag),
        "n_fellback_hosts": hn.n_fellback,
        "mean_busyness_all": float(busy.mean()),
        "n_hosts_live": int(len(np.unique(hflat))),
    }
    for k, s in (("raw", err_t), ("z", err_t_z), ("bag", bag)):
        m, sd_, nh, npos = wh(s)
        r[f"within_{k}"] = m
        r[f"within_{k}_hostspread"] = sd_
        r[f"within_{k}_nhosts"] = nh
        r[f"within_{k}_npos"] = npos
        for bk, bv in budget(s).items():
            r[f"b5_{k}_{bk}"] = bv
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--hosts", type=int, default=120)
    ap.add_argument("--days", type=int, default=16)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--out", default="confound_test.json")
    a = ap.parse_args()

    T.set_device("cpu")
    runs = []
    for s in range(a.seeds):
        print(f"\n--- seed {s} ---", flush=True)
        runs.append(run_seed(s, a.hosts, a.days, a.epochs))

    def ms(k):
        v = [r[k] for r in runs if r[k] == r[k]]
        return (float(np.mean(v)), float(np.std(v))) if v else (float("nan"),) * 2

    print()
    print("=" * 74)
    print("  P0 / P0b -- the busy-host confound, reproduced and treated")
    print("=" * 74)
    da, _ = ms("density_attacked"); do, _ = ms("density_other")
    print(f"  live-window density   attacked {da:.3f}   others {do:.3f}   "
          f"(LANL: 0.811 / 0.530)")
    print(f"  hosts that fell back to the pooled scale: {runs[0]['n_fellback_hosts']}")
    print()
    print(f"  {'score':<34}{'pooled AUC':>14}{'within-host AUC':>19}")
    print("  " + "-" * 68)
    rows = [
        ("Inspector, RAW error", "pooled_raw", "within_raw"),
        ("Inspector, per-host z  (P0)", "pooled_z", "within_z"),
        ("bag-of-categories Mahalanobis (P0b)", "pooled_bag", "within_bag"),
    ]
    for label, pk, wk in rows:
        pm, ps = ms(pk); wm, wsd = ms(wk)
        print(f"  {label:<34}{pm:>8.3f} ±{ps:<4.3f}{wm:>12.3f} ±{wsd:<5.3f}")

    praw, _ = ms("pooled_raw"); pz, _ = ms("pooled_z")
    wraw, _ = ms("within_raw"); wz, _ = ms("within_z")
    wbag, _ = ms("within_bag")
    hs, _ = ms("within_raw_hostspread")
    print()
    print(f"  per-host spread within a seed (raw): ±{hs:.3f}   "
          f"hosts scored {runs[0]['within_raw_nhosts']}, "
          f"positives {runs[0]['within_raw_npos']}")

    print()
    print("  WHERE THE 5% ESCALATION BUDGET ACTUALLY GOES")
    print(f"  {'':<30}{'attack recall':>14}{'precision':>11}"
          f"{'hosts hit':>11}{'busyness':>10}")
    print("  " + "-" * 76)
    for label, k in (("Inspector, RAW error", "raw"),
                     ("Inspector, per-host z (P0)", "z"),
                     ("bag Mahalanobis (P0b)", "bag")):
        rc, _ = ms(f"b5_{k}_recall_attack")
        pr, _ = ms(f"b5_{k}_precision")
        ht_, _ = ms(f"b5_{k}_hosts_touched")
        bz, _ = ms(f"b5_{k}_mean_busyness_of_selected")
        print(f"  {label:<30}{rc*100:>12.1f}%{pr*100:>10.1f}%"
              f"{ht_:>11.1f}{bz:>10.3f}")
    ball, _ = ms("mean_busyness_all")
    nlive, _ = ms("n_hosts_live")
    print(f"  {'(population average)':<30}{'':>12} {'':>10}{nlive:>11.0f}{ball:>10.3f}")

    rraw, _ = ms("b5_raw_recall_attack")
    rz, _ = ms("b5_z_recall_attack")
    rbag, _ = ms("b5_bag_recall_attack")
    braw, _ = ms("b5_raw_mean_busyness_of_selected")
    bz2, _ = ms("b5_z_mean_busyness_of_selected")

    print()
    print("  READING")
    gap_here = praw - wraw
    gap_lanl = 0.745 - 0.557
    print(f"    DID WE REPRODUCE THE LANL CONFOUND?")
    print(f"      LANL: pooled 0.745, within-host 0.557  -> gap {gap_lanl:+.3f}")
    print(f"      here: pooled {praw:.3f}, within-host {wraw:.3f}  -> gap {gap_here:+.3f}")
    if gap_here < 0.05:
        print("      NO. Thinning benign hosts changed their density but did not")
        print("      create the pathology: within-host is not below pooled here.")
        print("      So this run CANNOT validate a fix for it. The LANL gap has")
        print("      a cause our generator does not contain, and P0 must be")
        print("      judged on the LANL re-run, not on this.")
    else:
        print("      YES -- the gap is present and a fix can be judged here.")
    print()
    print(f"    P0  within-host  raw {wraw:.3f} -> z {wz:.3f}   ({wz-wraw:+.3f})")
    print("        within-host AUC is INVARIANT to per-host rescaling by")
    print("        construction -- it ranks a host against itself, and z is a")
    print("        strictly increasing per-host transform. A +0.000 here is")
    print("        the arithmetic working, not the fix failing.")
    print(f"    P0  pooled       raw {praw:.3f} -> z {pz:.3f}   ({pz-praw:+.3f})"
          "   a FALL here is correct")
    print(f"    P0  recall@5%    raw {rraw*100:.1f}% -> z {rz*100:.1f}%   "
          f"({(rz-rraw)*100:+.1f} pts)   <-- where P0 actually pays")
    print(f"    P0  busyness of escalated windows {braw:.3f} -> {bz2:.3f} "
          f"(population {ball:.3f})")
    print(f"    P0b GNN vs bag, recall@5%  {rz*100:.1f}% vs {rbag*100:.1f}%   "
          f"({(rz-rbag)*100:+.1f} pts)")
    print()
    if rz - rraw > 0.02:
        print("    P0 VERDICT: per-host normalisation changes WHICH windows get")
        print("    escalated, and recovers more attacks at the same budget.")
        print("    Ship it, and re-run LANL to get the real delta.")
    elif abs(rz - rraw) <= 0.02:
        print("    P0 VERDICT: normalisation did not move attack recall at a")
        print("    fixed budget here. It still makes the escalation cut")
        print("    host-relative rather than busyness-driven, which is the")
        print("    right operational behaviour -- but do not claim a")
        print("    detection gain we did not measure.")
    else:
        print("    P0 VERDICT: normalisation HURT recall at fixed budget here.")
        print("    Report it and do not ship it without the LANL check.")
    print()
    agree_win = wz - wbag
    agree_rec = rz - rbag
    if agree_win > 0.02 and agree_rec > 0.02:
        print("    P0b VERDICT: the GNN beats the ~0-parameter baseline on BOTH")
        print("    metrics. That is the first real evidence for the")
        print("    architecture. Put it in §6.")
    elif agree_win > 0.02 > -agree_rec or agree_rec > 0.02 > -agree_win:
        print("    P0b VERDICT: SPLIT. The GNN is ahead on one metric and behind")
        print(f"    on the other (within-host {agree_win:+.3f}, "
              f"recall@5% {agree_rec*100:+.1f} pts), both inside the per-host")
        print("    spread. That is a tie, not a win. Do not claim the")
        print("    architecture wins until LANL says so.")
    elif abs(wz - wbag) <= 0.02:
        print("    P0b VERDICT: the GNN MATCHES a per-host Mahalanobis with no")
        print("    graph, no attention and no training. On this data the")
        print("    architecture is not paying for itself. Say so, and justify")
        print("    the Inspector as the model that CAN use cross-service")
        print("    structure once the snaplen-0 corpus exists -- not as the")
        print("    model that currently wins.")
    else:
        print("    P0b VERDICT: the baseline BEATS the GNN. Do not lead with the")
        print("    architecture. This must be in the deck before a judge finds it.")

    out = {"config": vars(a), "runs": runs,
           "mean_std": {k: list(ms(k)) for k in runs[0]}}
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  wrote {a.out}")


if __name__ == "__main__":
    main()
