#!/usr/bin/env python3
"""
deploy_c.py -- Option C running end to end on a mixed-risk fleet.

Shows the three things that justify the split, on data rather than in prose:

  1. DETECTION LATENCY. The Sentry emits a score every hour; the Inspector
     cannot answer before the day closes. Reported as the hour of first
     above-threshold Sentry score against the Inspector's midnight verdict.
  2. THE PER-HOST DIAL. A crown-jewel host at audit_rate 1.0 is running full
     inspection -- Option B -- inside the same architecture as a bulk endpoint
     at 0.02. One deployment, risk-tiered.
  3. LOAD, SPLIT BY CAUSE. Escalation is budgeted; audit is chosen; churn is
     absorbed. Reporting one number for "Inspector load" hides which of the
     three is actually moving.

Nothing here is a performance claim. The models are untrained -- what is being
demonstrated is the ARCHITECTURE's behaviour: who can answer when, what crosses
the boundary, and what it costs.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2 import synth, train as T                    # noqa: E402
from netsentinel_v2.models import Inspector, Sentry, recon_error  # noqa: E402
from netsentinel_v2.lifecycle import Lifecycle, State           # noqa: E402
from netsentinel_v2.tiers import (EdgeTier, CentralTier, TIERS,  # noqa: E402
                                  load_report)
from netsentinel_v2.cost_model import ette_days                 # noqa: E402


def build(hosts, days, seed):
    d = synth.generate(n_hosts=hosts, n_days=days, seed=seed,
                       hard_negatives=True)
    return d["edges"], d["mask"], d["is_attack_day"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=200)
    ap.add_argument("--days", type=int, default=8)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default="deploy_c.json")
    a = ap.parse_args()

    E, M, A = build(a.hosts, a.days, a.seed)
    H, D, W = E.shape[0], E.shape[1], E.shape[2]

    torch.manual_seed(a.seed)
    sentry, insp = Sentry(dim=32, teacher_dim=96).eval(), Inspector(dim=96).eval()

    def s_scores(e, m):
        with torch.no_grad():
            z = sentry.encode(torch.tensor(e, dtype=torch.float32),
                              torch.tensor(m, dtype=torch.float32))
        return z.abs().mean(-1).numpy()

    def inspect(e, m, c):
        with torch.no_grad():
            _, pred = insp(torch.tensor(e, dtype=torch.float32),
                           torch.tensor(m, dtype=torch.float32),
                           torch.tensor(c, dtype=torch.float32))
            return recon_error(pred, torch.tensor(e, dtype=torch.float32),
                               torch.tensor(m, dtype=torch.float32)).numpy()

    # ---- a realistic tier mix -------------------------------------------
    rng = np.random.default_rng(a.seed)
    assign, names = {}, ["crown_jewel", "elevated", "standard", "bulk"]
    weights = [0.01, 0.09, 0.55, 0.35]
    for h in range(H):
        assign[h] = TIERS[names[int(rng.choice(len(names), p=weights))]]

    lc = Lifecycle()
    for h in range(H):
        lc.get(h).state = State.SENTRY_PRIMARY
    lc.get(0).state = State.COMMISSIONING          # one host still commissioning

    edge = EdgeTier(s_scores, lifecycle=lc, tier_of=lambda h: assign[h],
                    seed=a.seed)
    central = CentralTier(inspect, T.compute_cohort, threshold=0.0)

    print("=" * 74)
    print("  Option C on a mixed-risk fleet")
    print("=" * 74)
    counts = {}
    for h in range(H):
        counts[assign[h].name] = counts.get(assign[h].name, 0) + 1
    print(f"  {H} hosts x {D} days = {H*D:,} host-days\n")
    print(f"  {'tier':<13}{'hosts':>7}{'audit':>8}{'budget':>8}"
          f"{'Inspector load':>16}{'worst-case ETTE':>18}")
    for nm in names:
        t_ = TIERS[nm]
        e50 = ette_days(t_.audit_rate, 0.5)["sampling_only_days"]
        lbl = "every day" if t_.audit_rate >= 1.0 else f"{e50:.0f} d"
        print(f"  {nm:<13}{counts.get(nm,0):>7}{t_.audit_rate:>8.0%}"
              f"{t_.escalation_budget:>8.0%}{t_.inspector_load():>15.0%}"
              f"{lbl:>18}")
    print("\n  ETTE = expected days for a router-invisible pattern to reach the")
    print("  Inspector by blind audit alone, at P(detect|inspected)=0.5.")

    # ---- run the fleet, day by day --------------------------------------
    all_packets, all_verdicts = [], []
    latency = []
    for day in range(D):
        peaks = np.array([s_scores(E[h, day][None], M[h, day][None])[0].max()
                          for h in range(H)])
        pkts = []
        for h in range(H):
            cut = edge.budget_cut(peaks, assign[h])
            hist_e = E[h, max(0, day - 2):day] if day else None
            hist_m = M[h, max(0, day - 2):day] if day else None
            # hourly path -- this is what the Inspector cannot do
            for hr in range(W):
                edge.score_hour(h, day, E[h, day], M[h, day], hr)
            p = edge.close_day(h, day, E[h, day], M[h, day], router_cut=cut,
                               history_edges=hist_e, history_mask=hist_m)
            if p:
                pkts.append(p)
        v = central.ingest(pkts, E[:, day], M[:, day])
        all_packets += pkts
        all_verdicts += v
        # latency: hour of the day's peak Sentry score vs the day closing
        for p in pkts:
            if p.trigger_window is not None:
                latency.append(p.trigger_window)

    print()
    print("  DETECTION LATENCY")
    lat = np.array(latency) if latency else np.array([0])
    print(f"    Sentry raised its peak at hour {np.median(lat):.0f} (median), "
          f"{np.percentile(lat,25):.0f}-{np.percentile(lat,75):.0f} IQR")
    print(f"    Inspector could not have answered before hour 24 on any of them")
    print(f"    hours saved, median: {24 - np.median(lat):.0f}")

    print()
    print("  INSPECTOR LOAD, BY CAUSE")
    rep = load_report(all_packets, H * D)
    print(f"    {rep['inspected']:,} of {rep['host_days']:,} host-days "
          f"({rep['fraction']:.1%})")
    for k, v_ in sorted(rep["by_reason"].items(), key=lambda x: -x[1]):
        print(f"      {k:<16}{v_:>7,}  {v_/rep['inspected']*100:>5.1f}%")
    print(f"    budget-controlled {rep['budget_controlled']:.0%} · "
          f"audit {rep['audit_driven']:.0%} · churn {rep['churn_driven']:.0%}")

    print()
    print("  THE DIAL -- same fleet, audit rate swept")
    print(f"    {'audit':>7}{'inspected':>12}{'fraction':>11}{'ETTE @P=0.5':>14}")
    sweep = {}
    for r in (0.02, 0.05, 0.20, 1.00):
        lc2 = Lifecycle()
        for h in range(H):
            lc2.get(h).state = State.SENTRY_PRIMARY
        tier = TIERS["standard"]
        forced = type(tier)(tier.name, r, tier.escalation_budget, tier.note)
        e2 = EdgeTier(s_scores, lifecycle=lc2, tier_of=lambda h, t=forced: t,
                      seed=a.seed)
        got = 0
        for day in range(D):
            pk = np.array([s_scores(E[h, day][None], M[h, day][None])[0].max()
                           for h in range(H)])
            cut = e2.budget_cut(pk, forced)
            for h in range(H):
                if e2.close_day(h, day, E[h, day], M[h, day], router_cut=cut):
                    got += 1
        e50 = ette_days(r, 0.5)["sampling_only_days"]
        lbl = "every day" if r >= 1.0 else f"{e50:.0f} d"
        print(f"    {r:>6.0%}{got:>12,}{got/(H*D):>10.1%}{lbl:>14}")
        sweep[str(r)] = dict(inspected=got, fraction=got / (H * D),
                             ette_days_p50=e50)
    print()
    print("    At audit 100% this is Option B -- every host-day inspected --")
    print("    with the hourly Sentry score kept on top. The cascade contains")
    print("    full inspection; it is not an alternative to it.")

    out = dict(hosts=H, days=D, host_days=H * D,
               tier_mix=counts, load=rep,
               latency_median_hour=float(np.median(lat)),
               latency_iqr=[float(np.percentile(lat, 25)),
                            float(np.percentile(lat, 75))],
               audit_sweep=sweep,
               note=("Untrained models. This demonstrates architecture "
                     "behaviour -- who can answer when, what crosses the "
                     "boundary, what it costs -- not detection performance."))
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  wrote {a.out}")


if __name__ == "__main__":
    main()
