#!/usr/bin/env python3
"""
test_telegram.py -- does the Telegram-C2 bound actually hold?

The frontier in telegram_c2.py rests on two things that can each be wrong:

  1. Siegmund's ARL formula. It is an APPROXIMATION. If it disagrees with the
     real CUSUM detector, every day-count in the frontier is fiction. Test 1
     simulates the actual scalar detector and compares.

  2. NORMALITY. Siegmund assumes normal increments; real Messaging_API upload
     is lognormal -- right-skewed, heavy upper tail. A heavy right tail means
     MORE false alarms than the formula predicts, i.e. the true ARL0 is SHORTER
     than targeted. Test 2 measures that gap on the real (lognormal) stream so
     it is a stated number, not a surprise. This is the honest limit of the
     absolute day-counts; the SHAPE of the frontier does not depend on it.

Also checks the structural claims the bound makes: delay falls as footprint
rises, the floor is real, and per-window AUC collapses as the implant climbs.
Deterministic; exits non-zero on any failure.
"""
from __future__ import annotations

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import telegram_c2 as T                                    # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    print(("  ok    " if cond else "  FAIL  ") + name + ("" if cond else f"   {detail}"))
    PASS += bool(cond); FAIL += (not cond)


def mc_arl_normal(rng, k, h, shift, reps=20000, cap=6000):
    """Mean run length of the REAL cusum recursion on NORMAL increments,
    vectorised across reps. Validates Siegmund's formula on its own assumption."""
    s = np.zeros(reps)
    fired = np.zeros(reps, bool)
    t_of = np.full(reps, float(cap))
    for t in range(cap):
        z = rng.standard_normal(reps) + shift
        s = np.maximum(0.0, s + z - k)
        hit = (~fired) & (s > h)
        t_of[hit] = t
        fired |= hit
        if fired.all():
            break
    return float(t_of.mean())


def mc_arl_lognormal(rng, k, h, shift_sigma, reps=20000, cap=8000):
    """Same, but on the ACTUAL standardised lognormal upload stream the detector
    runs on. shift_sigma is the implant footprint in baseline-sigma units."""
    mu0, sigma0 = T.base_moments()
    s = np.zeros(reps)
    fired = np.zeros(reps, bool)
    t_of = np.full(reps, float(cap))
    for t in range(cap):
        x = rng.lognormal(T.BASE_MU_LOG, T.BASE_SIGMA_LOG, size=reps) + shift_sigma * sigma0
        z = (x - mu0) / sigma0
        s = np.maximum(0.0, s + z - k)
        hit = (~fired) & (s > h)
        t_of[hit] = t
        fired |= hit
        if fired.all():
            break
    return float(t_of.mean())


print("=" * 70)
print("  telegram_c2 -- the bound, tested")
print("=" * 70)

# 1. Siegmund vs the real detector, on NORMAL increments (its own assumption).
#    Siegmund is a SMALL-SHIFT approximation: tight for small net drift, looser
#    as (shift - k) grows. The frontier lives in the small-drift regime near the
#    floor, so that is where accuracy has to hold; large-shift delays are ~1 day
#    either way. Tolerances reflect that.
print("\n1. Siegmund ARL vs simulated CUSUM (normal increments)")
rng = np.random.default_rng(0)
for k, h, shift, tol in [(0.5, 4.0, 0.75, 0.15),   # small drift -> tight
                         (0.5, 4.0, 1.0, 0.18),
                         (0.5, 4.0, 1.5, 0.30)]:    # large drift -> loose, ~1d
    approx = T.arl(shift, k, h)
    sim = mc_arl_normal(rng, k, h, shift)
    rel = abs(approx - sim) / sim
    check(f"ARL1 k={k} h={h} shift={shift}: formula {approx:.1f} vs sim {sim:.1f}",
          rel < tol, f"rel err {rel:.0%} > {tol:.0%}")

approx0 = T.arl(0.0, 0.5, 3.0)
sim0 = mc_arl_normal(rng, 0.5, 3.0, 0.0, reps=20000, cap=20000)
check(f"ARL0 k=0.5 h=3.0: formula {approx0:.0f} vs sim {sim0:.0f}",
      abs(approx0 - sim0) / sim0 < 0.20, f"rel err {abs(approx0-sim0)/sim0:.0%}")

# 2. Why production does NOT use Siegmund: the lognormal skew breaks it, and the
#    empirical calibration fixes it. Both halves are asserted.
print("\n2. Lognormal skew breaks Siegmund; empirical calibration repairs it")
# 2a. a Siegmund-tuned h false-alarms far more often than promised on real skew
h_siegmund = T.arl.__self__ if False else None       # (no-op guard)
h_norm = 3.0
sieg_target = T.arl(0.0, 0.5, h_norm)                # what Siegmund promises
sim_skew, _ = T.arl_mc(rng, 0.5, h_norm, 0.0, reps=20000, cap=int(sieg_target * 3))
check(f"Siegmund-tuned h={h_norm} promises ARL0 {sieg_target:.0f} but skew gives "
      f"{sim_skew:.0f} (>=2x worse)",
      sim_skew < sieg_target / 2.0,
      f"skew ratio {sieg_target/max(sim_skew,1):.1f}x -- if ~1, there was no bug to fix")
# 2b. empirical calibration on the real stream actually hits its target
tgt = 1500.0
h_emp = T.calibrate_h(0.5, tgt, reps=6000)
sim_emp, _ = T.arl_mc(rng, 0.5, h_emp, 0.0, reps=20000, cap=int(tgt * 4))
check(f"empirical calibration hits ARL0 target {tgt:.0f}: measured {sim_emp:.0f}",
      abs(sim_emp - tgt) / tgt < 0.25, f"rel err {abs(sim_emp-tgt)/tgt:.0%}")

# 3. Structural claims of the bound.
print("\n3. The bound's structural claims")
fr = T.frontier(np.random.default_rng(1))
curve = fr["curve"]
days = [r["days_to_detect"] for r in curve]
check("delay strictly falls as footprint rises (conservation law)",
      all(a > b for a, b in zip(days, days[1:])),
      f"days: {[round(d,1) for d in days]}")
check("no footprint is literally undetectable (a zero-drift CUSUM still fires)",
      all(np.isfinite(r["days_to_detect"]) for r in curve),
      "if any row is inf the sub-k model regressed to the wrong hard-floor")
lost = [r for r in curve if r["lost_in_noise"]]
caught = [r for r in curve if not r["lost_in_noise"]]
check("the smallest footprints are LOST IN NOISE (delay within LOST_FACTOR of ARL0)",
      len(lost) >= 1 and all(l["footprint_sigma"] <= c["footprint_sigma"]
                             for l in lost for c in caught),
      f"lost footprints: {[l['footprint_sigma'] for l in lost]}")
check("every caught footprint is detected before a false alarm",
      all(c["days_to_detect"] < fr["arl0_measured_days"] for c in caught))
check(f"an operational floor exists ({fr['floor_kb_per_day']} KB/day)",
      fr["floor_kb_per_day"] is not None)

# lowering k must lower the floor -- the defender's knob works
fr_lo = T.frontier(np.random.default_rng(1), k=0.25)
check("lowering k lowers the bandwidth floor (the defender's knob works)",
      fr_lo["floor_kb_per_day"] is not None
      and fr_lo["floor_kb_per_day"] < fr["floor_kb_per_day"],
      f"k=0.25 floor {fr_lo['floor_kb_per_day']} vs k=0.5 floor {fr['floor_kb_per_day']}")

# 4. The evasion ladder: per-window detection collapses.
print("\n4. Per-window detection collapses up the evasion ladder")
lad = T.evasion_ladder(np.random.default_rng(2))
aucs = [r["per_window_auc_best"] for r in lad["rungs"]]
check("commodity rung is near-perfectly detectable per-window",
      aucs[0] > 0.95, f"rung0 AUC {aucs[0]:.3f}")
check("full-mimicry rung falls toward chance per-window",
      aucs[-1] < 0.75, f"full-mimicry AUC {aucs[-1]:.3f}")
check("per-window detectability is monotone non-increasing up the ladder",
      all(a >= b - 0.02 for a, b in zip(aucs, aucs[1:])),
      f"aucs: {[round(a,3) for a in aucs]}")
# the fully-mimicking rung: per-window is weak, but CUSUM still bounds it
full = lad["rungs"][-1]
check("full-mimicry rung is per-window-weak yet CUSUM-bounded in finite time",
      full["per_window_auc_best"] < 0.75 and np.isfinite(full["cusum_delay_days"]),
      f"auc {full['per_window_auc_best']:.3f}, delay {full['cusum_delay_days']:.1f}d")

# 5. Determinism -- same seed, same frontier (AUDIT.md B7 discipline).
print("\n5. Determinism")
a = T.frontier(np.random.default_rng(7))["curve"]
b = T.frontier(np.random.default_rng(7))["curve"]
check("frontier is deterministic (no RNG-order drift)",
      all(abs(x["days_to_detect"] - y["days_to_detect"]) < 1e-9 for x, y in zip(a, b)))

print()
print(f"  {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
