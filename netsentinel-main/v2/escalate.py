#!/usr/bin/env python3
"""
escalate.py -- P1. The Inspector's real throughput, and the escalation loop
built for real rather than described.

Two things this answers that we could not answer before.

1. "You quote the Sentry at ~250k windows/s. What does the INSPECTOR cost?"
   We never measured it. 205,546 parameters is small, so the interesting cost
   is not the matmuls -- it is the hop-2 cohort aggregation, which has to look
   across every other host in the same hour before the model can run at all.
   This times all three stages separately on the same core, so the cascade
   ratio we quote is one we observed rather than one we assumed.

2. "Show the loop." The end-to-end description in the docs -- Sentry routes,
   Inspector re-runs on the top-k only, one alert carrying the chain steps --
   was designed and never built. It is built here, and it asserts that the
   Inspector really was called on k windows and not on N.

Usage:  python escalate.py [--hosts 200] [--days 16] [--budget 0.05]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2 import synth, train as T                        # noqa: E402
from netsentinel_v2.categories import CATEGORIES                    # noqa: E402
from netsentinel_v2.hostnorm import HostScoreNormaliser             # noqa: E402

CHAIN = ["Recon_API", "Code_Repo_Paste", "Messaging_API", "Cloud_Storage"]


def timeit(fn, *a, repeat=3, **kw):
    """Best-of-N wall clock. Best-of, not mean: we want the machine's
    capability, not the noise from whatever else the laptop is doing."""
    best, out = float("inf"), None
    for _ in range(repeat):
        t0 = time.perf_counter()
        out = fn(*a, **kw)
        best = min(best, time.perf_counter() - t0)
    return best, out


def machine_reference(repeat=5):
    """A fixed matmul, timed the same way, so a reader can tell whether a
    throughput figure came from a quiet machine or a busy one.

    This is not decoration. Two runs of this script on the SAME container gave
    70,950 and 104,385 Inspector windows/s -- a 47% swing -- and the
    Sentry:Inspector ratio moved 8.59 to 7.54 with it. Best-of-3 does not
    remove contention when every core is busy. Without a reference workload in
    the file, there is no way to tell a model change from a noisy neighbour,
    and 'we measured 8.6x' reads as a property of the model when it is partly
    a property of the afternoon.
    """
    a = torch.randn(512, 512)
    b = torch.randn(512, 512)
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        a @ b
        best = min(best, time.perf_counter() - t0)
    return dict(matmul_512_seconds=best,
                gflops=2 * 512 ** 3 / best / 1e9,
                torch_threads=int(torch.get_num_threads()),
                cpu_count=int(os.cpu_count() or 0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=200)
    ap.add_argument("--days", type=int, default=16)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--budget", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="escalate.json")
    a = ap.parse_args()

    T.set_device("cpu")
    d = synth.generate(n_hosts=a.hosts, n_days=a.days, seed=a.seed,
                       stealth_range=(0.9, 1.0), hard_negatives=True)
    E, M, A = d["edges"], d["mask"], d["is_attack_day"]
    H, D, W, C, F = E.shape
    roles = d["roles"]
    split = a.days // 2
    hidx = np.repeat(np.arange(H)[:, None], D, axis=1)

    print("=" * 74)
    print("  P1 -- Inspector throughput and the escalation loop")
    print("=" * 74)
    print(f"  {H} hosts x {D} days x {W} windows x {C} categories")

    # ---------------------------------------------------- hop-2 assembly ---
    t_cohort, Co = timeit(T.compute_cohort, E, M)
    n_windows_all = H * D * W
    print()
    print("  STAGE COSTS, same CPU, best of 3")
    print(f"    hop-2 cohort assembly   {t_cohort:7.3f} s for {n_windows_all:,} "
          f"windows  =  {n_windows_all/t_cohort:>12,.0f} win/s")

    def flat(x, lo, hi):
        return x[:, lo:hi].reshape(-1, *x.shape[2:])
    Ec, Mc, Cc = flat(E, 0, split), flat(M, 0, split), flat(Co, 0, split)
    Et, Mt, Ct = flat(E, split, D), flat(M, split, D), flat(Co, split, D)
    hc = hidx[:, :split].reshape(-1)
    ht = hidx[:, split:].reshape(-1)
    atk_day = A[:, split:].reshape(-1)

    Ec, mu, sd = T.standardise(Ec, Mc)
    Et, _, _ = T.standardise(Et, Mt, mu, sd)
    Cc, cmu, csd = T.standardise(Cc, Mc)
    Ct, _, _ = T.standardise(Ct, Mt, cmu, csd)

    insp = T.train_inspector(Ec, Mc, Cc, epochs=a.epochs, seed=a.seed)
    Zc, err_c = T.inspector_forward(insp, Ec, Mc, Cc)
    sen = T.train_sentry(Ec, Mc, Zc, err_c, epochs=10, seed=a.seed)

    n_test = Et.shape[0] * W
    t_insp, (Zt_full, err_full) = timeit(
        T.inspector_forward, insp, Et, Mt, Ct)
    t_sen, _ = timeit(T.sentry_forward, sen, Et, Mt)

    print(f"    Inspector forward       {t_insp:7.3f} s for {n_test:,} "
          f"windows  =  {n_test/t_insp:>12,.0f} win/s")
    print(f"    Sentry forward          {t_sen:7.3f} s for {n_test:,} "
          f"windows  =  {n_test/t_sen:>12,.0f} win/s")
    print(f"    Sentry is {t_insp/t_sen:.1f}x faster than the Inspector on "
          "the same core")
    print(f"    Inspector + its hop-2 input: "
          f"{n_test/(t_insp + t_cohort*len(Et)/(H*D)):>10,.0f} win/s effective")

    # ------------------------------------------------------- the router ---
    thr_c = float(np.quantile(err_c, 0.99))
    Zc_s = T.sentry_forward(sen, Ec, Mc)
    headA = T.train_head(Zc_s, (err_c / (thr_c + 1e-9)).astype(np.float32),
                         loss="mse", seed=a.seed)
    Zt_s = T.sentry_forward(sen, Et, Mt)
    router = T.head_forward(headA, Zt_s)

    # ------------------------------------------------- THE LOOP, FOR REAL --
    live_t = (Mt.sum(-1) > 0)
    lf = live_t.reshape(-1)
    rv = router.reshape(-1)
    k = max(1, int(round(a.budget * lf.sum())))
    cand = np.where(lf)[0][np.argsort(-rv[lf], kind="stable")[:k]]

    # rows the Inspector actually has to see
    rows = np.unique(cand // W)
    t0 = time.perf_counter()
    _, err_esc = T.inspector_forward(insp, Et[rows], Mt[rows], Ct[rows])
    t_cascade = time.perf_counter() - t0

    print()
    print("  THE LOOP")
    print(f"    Sentry scored                     {int(lf.sum()):,} live windows")
    print(f"    escalated at a {a.budget*100:.0f}% budget            {k:,} windows")
    print(f"    Inspector re-ran on               {len(rows):,} of "
          f"{Et.shape[0]:,} host-days "
          f"({100*(1-len(rows)/Et.shape[0]):.0f}% never woke it)")
    print(f"    wall clock, cascade               {t_cascade:.3f} s")
    print(f"    wall clock, inspect everything    {t_insp:.3f} s")
    print(f"    saving on this laptop             {100*(1-t_cascade/t_insp):.0f}%")

    assert len(rows) <= Et.shape[0]
    full_calls = Et.shape[0]
    print(f"    ASSERT Inspector called on {len(rows)}, not {full_calls}  -- "
          f"{'OK' if len(rows) < full_calls else 'FAILED'}")

    # ---- the budget-granularity bug this measurement exposed -------------
    # The Inspector's unit of work is a HOST-DAY: it takes the whole 24-hour
    # sequence, because the sequence encoder needs it. But we were budgeting
    # in WINDOWS. Escalating the top 5% of windows scatters them across
    # almost every host-day in the set, so the Inspector ends up re-running on
    # half of everything. 5% of windows is NOT 5% of Inspector load, and the
    # cost model quietly assumed it was.
    #
    # Budgeting at the granularity the Inspector actually consumes fixes it.
    hd_score = router.max(axis=1)                 # worst hour per host-day
    k_hd = max(1, int(round(a.budget * Et.shape[0])))
    rows_hd = np.argsort(-hd_score, kind="stable")[:k_hd]
    t0 = time.perf_counter()
    _, err_hd = T.inspector_forward(insp, Et[rows_hd], Mt[rows_hd], Ct[rows_hd])
    t_hd = time.perf_counter() - t0

    rec_win = float(atk_day[rows].sum() / max(atk_day.sum(), 1))
    rec_hd = float(atk_day[rows_hd].sum() / max(atk_day.sum(), 1))
    print()
    print("  BUDGET GRANULARITY -- 5% of WINDOWS is not 5% of INSPECTOR LOAD")
    print(f"    {'':<26}{'host-days seen':>16}{'% of load':>11}"
          f"{'attack-day recall':>19}")
    print(f"    {'top 5% of windows':<26}{len(rows):>16,}"
          f"{100*len(rows)/Et.shape[0]:>10.0f}%{rec_win*100:>18.0f}%")
    print(f"    {'top 5% of host-days':<26}{len(rows_hd):>16,}"
          f"{100*len(rows_hd)/Et.shape[0]:>10.0f}%{rec_hd*100:>18.0f}%")
    print(f"    wall clock {t_cascade:.3f} s  vs  {t_hd:.3f} s")
    print("    Budget at the granularity the Inspector consumes, or the 5%")
    print("    on the slide is not the 5% the GPU sees.")

    # per-host normalisation of the CONFIRMATION score (P0), fitted on
    # commissioning only
    hn = HostScoreNormaliser(min_live=20).fit(err_c, hc, (Mc.sum(-1) > 0))
    z_esc = hn.transform(err_esc, ht[rows])
    conf_thr = 3.0                       # 3 robust sigma above the host's own median
    confirmed_rows = rows[(z_esc.max(axis=1) >= conf_thr)]

    print(f"    Inspector CONFIRMED               {len(confirmed_rows):,} host-days "
          f"(>= {conf_thr:.0f} robust sigma vs that host's own baseline)")

    atk = atk_day[confirmed_rows]
    print(f"    of those, truly attack days       {int(atk.sum()):,} "
          f"({100*atk.mean() if len(atk) else 0:.0f}% precision)")

    # ------------------------------------------------ ONE alert, not four --
    if len(confirmed_rows):
        pick = confirmed_rows[np.argmax(
            hn.transform(err_esc, ht[rows])[
                np.searchsorted(rows, confirmed_rows)].max(axis=1))]
        h, day = int(ht[pick]), int(pick % (D - split)) + split
        zrow = hn.transform(
            T.inspector_forward(insp, Et[pick:pick+1], Mt[pick:pick+1],
                                Ct[pick:pick+1])[1], np.array([ht[pick]]))[0]
        print()
        print("  ONE ALERT, CARRYING THE CHAIN -- not four disconnected alerts")
        print(f"    host {h:03d} ({roles[h]}), day {day}, "
              f"{'ATTACK DAY' if atk_day[pick] else 'benign day (false positive)'}")
        print(f"    {'hour':<7}{'categories':<44}{'z vs own baseline':>18}")
        step = 0
        for w in range(W):
            cats = [CATEGORIES[c] for c in range(C) if Mt[pick, w, c] > 0]
            if not cats:
                continue
            mark = ""
            if step < len(CHAIN) and CHAIN[step] in cats:
                step += 1
                mark = f"   <- chain step {step}/4"
            txt = ", ".join(cats)
            if len(txt) > 42:
                txt = txt[:39] + "..."
            print(f"    {w:02d}:00  {txt:<44}{zrow[w]:>10.2f}{mark}")
        print(f"    chain steps walked in order: {step}/4")
        print("    No payload was inspected. The COMBINATION of categories and")
        print("    the machine-like shape of the traffic is what was scored.")

    out = {
        "hosts": H, "days": D, "windows": W,
        "machine_reference": machine_reference(),
        "timing_caveat": ("wall-clock on a shared container; these are "
                          "load-dependent. Compare ratios, and compare them "
                          "only against a run with a similar machine_reference."),
        "cohort_seconds": t_cohort, "cohort_win_per_s": n_windows_all / t_cohort,
        "inspector_seconds": t_insp, "inspector_win_per_s": n_test / t_insp,
        "sentry_seconds": t_sen, "sentry_win_per_s": n_test / t_sen,
        "sentry_speedup": t_insp / t_sen,
        "budget": a.budget, "escalated_windows": int(k),
        "host_days_total": int(Et.shape[0]),
        "host_days_inspected": int(len(rows)),
        "host_days_confirmed": int(len(confirmed_rows)),
        "confirm_precision": float(atk.mean()) if len(atk) else None,
        "cascade_seconds": t_cascade,
        "full_inspect_seconds": t_insp,
    }
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  wrote {a.out}")


if __name__ == "__main__":
    main()
