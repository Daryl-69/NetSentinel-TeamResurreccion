#!/usr/bin/env python3
"""
sweep_threshold.py -- tune the Inspector's confirmation threshold.

WHY THIS IS THE LARGEST OPEN ITEM IN THE PROJECT.
escalate.py fixes the confirmation cut at 3.0 robust sigma and measures 12.7%
precision: roughly seven of every eight confirmations are false. Confirmations
become alerts, alerts become analyst-hours, and analyst time is the only
expensive resource in the whole system -- gpu_cost.py puts the waste at about
$7.9M a year at 100,000 hosts against $150 of compute. The threshold is a
single scalar. Nobody had swept it.

WHAT IT DOES.
Runs the real escalation path, then sweeps the confirmation cut and reports
precision, recall and the resulting analyst load at each point. The optimum is
NOT max-F1: a SOC has a fixed triage capacity, so the operating point is
"highest recall whose alert volume fits the analysts you have". Both views are
printed.

The cascade is unchanged. Only the post-Inspector cut moves.
"""
from __future__ import annotations

import argparse, json, os, sys

import numpy as np
import torch
from scipy import stats

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2 import synth, train as T                        # noqa: E402
from netsentinel_v2.hostnorm import HostScoreNormaliser             # noqa: E402


def run(seed, hosts, days, epochs, budget, stealth=(0.9, 1.0), hard_neg=True):
    d = synth.generate(n_hosts=hosts, n_days=days, seed=seed,
                       stealth_range=stealth, hard_negatives=hard_neg)
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
    Zc, err_c = T.inspector_forward(insp, Ec_s, Mc, Cc_s)
    thr_c = float(np.quantile(err_c, 0.99))

    sen = T.train_sentry(Ec_s, Mc, Zc, err_c, epochs=epochs + 2, seed=seed)
    Zt_s = T.sentry_forward(sen, Et_s, Mt)
    Zc_s = T.sentry_forward(sen, Ec_s, Mc)
    head = T.train_head(Zc_s, (err_c / (thr_c + 1e-9)).astype(np.float32),
                        epochs=epochs + 2, seed=seed)
    router = T.head_forward(head, Zt_s)

    # budget in HOST-DAYS (escalate.py showed window budgeting scatters 9.8x)
    hd = router.max(axis=1)
    k = max(1, int(round(budget * Et_s.shape[0])))
    rows = np.argsort(-hd, kind="stable")[:k]
    _, err_esc = T.inspector_forward(insp, Et_s[rows], Mt[rows], Ct_s[rows])

    hn = HostScoreNormaliser(min_live=20).fit(err_c, hc, (Mc.sum(-1) > 0))
    z = hn.transform(err_esc, ht[rows]).max(axis=1)
    return z, atk_day[rows], int(atk_day.sum()), Et_s.shape[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=200)
    ap.add_argument("--days", type=int, default=16)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--budget", type=float, default=0.05)
    ap.add_argument("--capacity", type=float, default=0.02,
                    help="alerts per host-day a SOC can actually triage")
    ap.add_argument("--stealth", nargs=2, type=float, default=[0.9, 1.0],
                    metavar=("LO", "HI"),
                    help="attacker stealth range; 0.9 1.0 is the hardest")
    ap.add_argument("--easy", action="store_true",
                    help="stealth 0.3-1.0, hard negatives off -- the setting "
                         "escalate.py and the 35.6%% recall figure use")
    ap.add_argument("--out", default="sweep_threshold.json")
    a = ap.parse_args()
    stealth = (0.3, 1.0) if a.easy else (a.stealth[0], a.stealth[1])
    hard_neg = not a.easy

    Z, Y, tot_atk, tot_hd = [], [], 0, 0
    for s in range(a.seeds):
        z, y, na, nhd = run(s, a.hosts, a.days, a.epochs, a.budget,
                            stealth, hard_neg)
        Z.append(z); Y.append(y); tot_atk += na; tot_hd += nhd
    z = np.concatenate(Z); y = np.concatenate(Y).astype(bool)

    print()
    print("=" * 74)
    print("  Confirmation threshold sweep")
    print("=" * 74)
    print(f"  {a.seeds} seeds, {a.hosts} hosts x {a.days} days, "
          f"{a.budget:.0%} host-day escalation budget")
    print(f"  stealth {stealth[0]:.1f}-{stealth[1]:.1f}, "
          f"hard negatives {'on' if hard_neg else 'off'}")
    print(f"  escalated host-days {len(z):,}  of which attack {int(y.sum()):,}"
          f"   total attack days {tot_atk:,}")

    # Does the ROUTER beat a coin? Escalating a `budget` fraction of host-days
    # at random would catch `budget * tot_atk` attack days in expectation. If
    # the observed count is not above that by more than chance, the routing
    # adds nothing at this difficulty and the sweep below is a sweep over
    # noise. This test must print before the table, not after it.
    frac = len(z) / max(tot_hd, 1)
    k_obs = int(y.sum())
    bt = stats.binomtest(k_obs, tot_atk, frac, alternative="greater")
    rlo, rhi = stats.binomtest(k_obs, tot_atk, frac).proportion_ci(0.95)
    verdict = ("BEATS random" if bt.pvalue < 0.05
               else "NOT distinguishable from random")
    print(f"  vs random routing: expected {frac * tot_atk:.1f} attack days, "
          f"got {k_obs}  ({k_obs / (frac * tot_atk):.2f}x, p={bt.pvalue:.3f})"
          f"  -> {verdict}")
    print(f"  recall 95% CI [{rlo:.1%}, {rhi:.1%}]   random = {frac:.1%}")
    print()
    print(f"  {'sigma':>7}{'confirmed':>11}{'precision':>11}{'recall':>9}"
          f"{'F1':>8}{'alerts/1k host-days':>21}")

    grid = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0, 8.0, 10.0]
    rows, best_f1, best_cap = [], None, None
    for t in grid:
        sel = z >= t
        n = int(sel.sum())
        if n == 0:
            continue
        prec = float(y[sel].mean())
        rec = float(y[sel].sum() / max(tot_atk, 1))
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        per1k = 1000.0 * n / max(tot_hd, 1)
        rows.append(dict(sigma=t, confirmed=n, precision=prec, recall=rec,
                         f1=f1, alerts_per_1k_host_days=per1k))
        mark = ""
        if best_f1 is None or f1 > best_f1["f1"]:
            best_f1 = rows[-1]
        if per1k <= a.capacity * 1000 and (best_cap is None or rec > best_cap["recall"]):
            best_cap = rows[-1]
        print(f"  {t:>7.1f}{n:>11,}{prec:>10.1%}{rec:>9.1%}{f1:>8.3f}"
              f"{per1k:>21.1f}{mark}")

    cur = next((r for r in rows if abs(r["sigma"] - 3.0) < 1e-9), None)
    print()
    if cur:
        print(f"  CURRENT setting, 3.0 sigma : precision {cur['precision']:.1%}"
              f"  recall {cur['recall']:.1%}  {cur['alerts_per_1k_host_days']:.1f} alerts/1k")
    print(f"  BEST F1      , {best_f1['sigma']:.1f} sigma : "
          f"precision {best_f1['precision']:.1%}  recall {best_f1['recall']:.1%}"
          f"  {best_f1['alerts_per_1k_host_days']:.1f} alerts/1k")
    if best_cap:
        print(f"  BEST within capacity ({a.capacity:.0%} of host-days), "
              f"{best_cap['sigma']:.1f} sigma : precision "
              f"{best_cap['precision']:.1%}  recall {best_cap['recall']:.1%}"
              f"  {best_cap['alerts_per_1k_host_days']:.1f} alerts/1k")
    else:
        print(f"  No threshold fits a {a.capacity:.0%} triage capacity. Either "
              f"raise capacity or tighten the escalation budget.")

    print()
    print("  Read this as an operating-point choice, not an optimum. F1 weights")
    print("  a missed attack and a wasted analyst-hour equally, and a SOC does")
    print("  not. Pick the highest recall whose volume your analysts can absorb.")
    print()
    print(f"  CAVEAT that must travel with these numbers: synthetic attacks,")
    print(f"  stealth {stealth[0]}-{stealth[1]}, hard negatives "
          f"{'on' if hard_neg else 'off'}. The SHAPE of the trade-off is the")
    print(f"  finding; the absolute precision will differ on real traffic.")
    if not bt.pvalue < 0.05:
        print()
        print("  AND READ THIS FIRST: at this difficulty the routing does not")
        print("  beat random selection at host-day granularity. Precision can")
        print("  still be bought with the threshold -- that part is real -- but")
        print("  do not present the recall as evidence the router works here.")

    json.dump(dict(seeds=a.seeds, hosts=a.hosts, days=a.days, budget=a.budget,
                   capacity=a.capacity, escalated=len(z),
                   attack_escalated=int(y.sum()), total_attack_days=tot_atk,
                   total_host_days=tot_hd, sweep=rows,
                   stealth=list(stealth), hard_negatives=hard_neg,
                   vs_random=dict(expected=float(frac * tot_atk), observed=k_obs,
                                  lift=float(k_obs / max(frac * tot_atk, 1e-9)),
                                  p_value=float(bt.pvalue),
                                  recall_ci=[float(rlo), float(rhi)],
                                  beats_random=bool(bt.pvalue < 0.05)),
                   current_3sigma=cur, best_f1=best_f1,
                   best_within_capacity=best_cap,
                   source=(f"synthetic, stealth {stealth[0]}-{stealth[1]}, "
                           f"hard negatives {'on' if hard_neg else 'off'}")),
              open(a.out, "w"), indent=2)
    print(f"\n  wrote {a.out}")


if __name__ == "__main__":
    main()
