#!/usr/bin/env python3
"""
telegram_c2.py -- the "almost impossible" Telegram-C2 case, bounded rather
than "solved".

THE CASE. An implant uses api.telegram.org as its C2 channel on a host that
ALREADY uses Telegram. It matches the client's TLS stack, sleeps on the user's
schedule, randomises its long-poll timeout, and dribbles exfil UNDER the host's
own upload envelope. Same category (Messaging_API), same destination, human
timing. To a passive, one-directional, flow-level sensor with no payload, a
single window of that traffic is indistinguishable from the user's own Telegram.

DO NOT CLAIM WE DETECT IT IN A WINDOW. We do not, and this file proves the
per-window classifier collapses to chance as the implant climbs an evasion
ladder (see `evasion_ladder`). That collapse is real and it is reported.

WHAT WE CLAIM INSTEAD -- and what this file measures:

  1. Per-window detection is the wrong question. Perfect mimicry reproduces the
     SHAPE of the host's Telegram; it cannot reproduce the ABSENCE of the extra
     bytes it must send. A persistent mean shift, however small, accumulates.
     Page's CUSUM detects it (`cusum`, `detection_delay`).

  2. There is a CONSERVATION LAW, measured here, not asserted: the smaller the
     implant's per-window footprint, the longer CUSUM takes to catch it. There
     is no hard "invisible below X" cliff -- a zero-drift CUSUM still fires
     eventually. Instead there is an OPERATIONAL floor: the footprint whose
     detection delay sinks to within a factor (LOST_FACTOR) of the detector's
     own false-alarm interval. Below it the true alarm is no faster than a false
     one, so the channel is lost in noise. That floor is set by the DEFENDER's
     tuning (reference k, false-alarm target, baseline length), not by the
     attacker -- lower k or a longer baseline pushes it down, at the cost of
     delay or false alarms. The channel that is GUARANTEED invisible is the one
     whose bandwidth has been driven into that noise floor; driving the floor to
     zero needs an infinite baseline. (`frontier`.)

  3. Therefore the honest security property is a BOUND, not a detection:
     exfil bandwidth and time-to-detection trade off against each other on a
     curve the defender sets. "The undetectable channel is the one with no
     capacity." That statement is defensible; "we detect Telegram C2" is not.

ANCHORING. The benign per-active-window Messaging_API upload model is fitted to
netsentinel_v2.synth (median ~12.5 KB, p95 ~40 KB, 3 seeds). Our own 1.75h
capture contained ZERO Messaging_API windows, so there is no real anchor yet --
this is audit gap G1, stated wherever these numbers appear. The SHAPE of the
frontier is the finding; the absolute KB/day floor will move on real traffic.

Everything is deterministic given a seed (no set iteration in any RNG loop --
see AUDIT.md B7).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2.synth import _iat_stats, _human_iats, _beacon_iats  # noqa: E402

# --- benign baseline, anchored to synth Messaging_API (see module docstring) --
# lognormal(mu_log, sigma_log) in BYTES per active window.
#   median = exp(mu_log)        = 12,490   -> mu_log   = 9.4326
#   p95/median = exp(1.645*sig) = 3.24     -> sigma_log = 0.715
# gives mean 16,070 (synth 15,696) -- matched, not tuned.
BASE_MU_LOG = 9.4326
BASE_SIGMA_LOG = 0.715
ACTIVE_WINDOWS_PER_DAY = 3.9          # synth median presence 0.164 * 24


def baseline_upload(rng, n):
    """Benign per-active-window Messaging_API upload bytes."""
    return rng.lognormal(BASE_MU_LOG, BASE_SIGMA_LOG, size=n)


def base_moments():
    """(mean, std) of the benign upload in linear bytes."""
    m = np.exp(BASE_MU_LOG + BASE_SIGMA_LOG ** 2 / 2)
    v = (np.exp(BASE_SIGMA_LOG ** 2) - 1) * np.exp(2 * BASE_MU_LOG + BASE_SIGMA_LOG ** 2)
    return float(m), float(np.sqrt(v))


# --------------------------------------------------------------------------
# Page's CUSUM -- one-sided upper, on standardised per-active-window upload.
#
# The detector is Monte-Carlo'd on the ACTUAL lognormal upload stream, not on a
# normal-increment formula. That matters: the first version calibrated h with
# Siegmund's normal-increment ARL (Siegmund 1985) and test_telegram.py caught it
# false-alarming ~8x more often than promised, because real upload is right-
# skewed and the heavy upper tail trips a normal-tuned threshold. So Siegmund is
# kept ONLY as a cross-check in the test (it is accurate on genuinely normal
# increments); everything here runs against the real distribution.
#
# There is also no hard "floor below k" -- that was wrong. A zero-drift CUSUM
# still crosses h eventually, so a tiny footprint is not invisible; it simply
# sinks toward the false-alarm rate. The real floor is operational: the
# footprint whose detection delay reaches the false-alarm interval, i.e. where
# a false alarm arrives before the true one and the attacker is lost in noise.
# --------------------------------------------------------------------------
_OVERSHOOT = 1.166           # Siegmund's continuity correction rho (test only)


def cusum(x, mu0, sigma0, k, h):
    """The real detector. Return the index of the first alarm, or -1 if none."""
    z = (np.asarray(x, float) - mu0) / sigma0
    s = 0.0
    for i, zi in enumerate(z):
        s = max(0.0, s + zi - k)
        if s > h:
            return i
    return -1


def arl(delta_sigma, k, h):
    """Siegmund's ANALYTIC ARL for NORMAL increments -- cross-check only, used
    by test_telegram.py. Production uses arl_mc on the real lognormal stream."""
    b = h + _OVERSHOOT
    d = delta_sigma - k
    if abs(d) < 1e-9:
        return b * b
    return (np.exp(-2.0 * d * b) + 2.0 * d * b - 1.0) / (2.0 * d * d)


def arl_mc(rng, k, h, shift_sigma, reps=5000, cap=12000):
    """Mean run length of the real CUSUM on the standardised lognormal upload
    stream, with the implant footprint added as `shift_sigma` baseline-sigmas.
    Vectorised across `reps` chains; runs censored at `cap` count as `cap`
    (a right-censoring that only ever makes ARL look SHORTER, never longer)."""
    mu0, sigma0 = base_moments()
    s = np.zeros(reps)
    fired = np.zeros(reps, bool)
    t_of = np.full(reps, float(cap))
    for t in range(cap):
        x = rng.lognormal(BASE_MU_LOG, BASE_SIGMA_LOG, size=reps) + shift_sigma * sigma0
        z = (x - mu0) / sigma0
        s = np.maximum(0.0, s + z - k)
        hit = (~fired) & (s > h)
        t_of[hit] = t
        fired |= hit
        if fired.all():
            break
    return float(t_of.mean()), float(fired.mean())


_H_CACHE: dict = {}

# A footprint is "lost in noise" when its true-detection delay is not even this
# many times faster than a false alarm. 2x is an operating choice (like the
# F1-vs-capacity call elsewhere), not an optimum -- below it, detection is real
# but too slow to act on before the detector cries wolf on its own.
LOST_FACTOR = 2.0


def calibrate_h(k, target_arl0, reps=5000):
    """h whose in-control ARL on the REAL lognormal stream equals target_arl0
    (active windows). Bisection on the measured ARL0, cached by (k, target).

    Uses its OWN deterministic RNG derived from (k, target), NOT the caller's,
    so whether the result comes from cache or a fresh bisection never changes
    how much randomness the caller consumes -- otherwise a warm cache would
    silently shift every downstream draw (AUDIT.md B7 taught this the hard way).
    """
    key = (round(k, 4), round(target_arl0, 1))
    if key in _H_CACHE:
        return _H_CACHE[key]
    rng = np.random.default_rng(abs(hash(key)) % (2 ** 32))
    cap = int(max(6000, target_arl0 * 5))
    lo, hi = 0.5, 30.0
    for _ in range(16):
        mid = (lo + hi) / 2
        a0, _ = arl_mc(rng, k, mid, 0.0, reps=reps, cap=cap)
        if a0 < target_arl0:
            lo = mid
        else:
            hi = mid
    _H_CACHE[key] = hi
    return hi


def detection_delay(rng, k, h, delta_bytes, arl0=None, reps=5000):
    """(delay_windows, lost) for an implant adding `delta_bytes` per active
    window. `lost` is True when the delay is within LOST_FACTOR of the
    false-alarm interval arl0 -- the attacker is then indistinguishable from
    the detector's own noise, which is the honest floor, not a hard threshold."""
    mu0, sigma0 = base_moments()
    d_sigma = delta_bytes / sigma0
    cap = int(arl0 * 3) if arl0 else 8000
    delay, frac = arl_mc(rng, k, h, d_sigma, reps=reps, cap=cap)
    lost = (arl0 is not None) and (delay >= arl0 / LOST_FACTOR)
    return delay, lost


# --------------------------------------------------------------------------
# The capacity-delay frontier -- the theorem, measured.
# --------------------------------------------------------------------------
def frontier(rng, k=0.5, target_arl0_days=513.0, reps=5000):
    """Sweep the implant's per-window footprint; report bandwidth vs delay.

    Returns the calibrated detector, the operational floor (the footprint whose
    detection delay reaches the false-alarm interval), and a curve of
    (exfil KB/day, expected days-to-detection). All measured on the real
    lognormal stream, not on a normal-increment formula.
    """
    mu0, sigma0 = base_moments()
    arl0_windows = target_arl0_days * ACTIVE_WINDOWS_PER_DAY
    h = calibrate_h(k, arl0_windows, reps=reps)
    arl0_meas, _ = arl_mc(rng, k, h, 0.0, reps=reps, cap=int(arl0_windows * 4))

    rows, floor_kb = [], None
    for d_sigma in (0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0):
        delta = d_sigma * sigma0
        delay_win, lost = detection_delay(rng, k, h, delta, arl0=arl0_meas, reps=reps)
        kb_day = delta * ACTIVE_WINDOWS_PER_DAY / 1024.0
        days = delay_win / ACTIVE_WINDOWS_PER_DAY
        rows.append(dict(
            footprint_sigma=d_sigma,
            delta_bytes=float(delta),
            exfil_kb_per_day=float(kb_day),
            delay_active_windows=float(delay_win),
            days_to_detect=float(days),
            lost_in_noise=bool(lost),
        ))
        if not lost and floor_kb is None:
            floor_kb = kb_day        # smallest footprint still caught before a false alarm
    return dict(
        k=k, h=float(h), target_arl0_days=target_arl0_days,
        arl0_measured_windows=float(arl0_meas),
        arl0_measured_days=float(arl0_meas / ACTIVE_WINDOWS_PER_DAY),
        baseline_mean_bytes=mu0, baseline_std_bytes=sigma0,
        active_windows_per_day=ACTIVE_WINDOWS_PER_DAY,
        floor_kb_per_day=(None if floor_kb is None else float(floor_kb)),
        curve=rows,
    )


# --------------------------------------------------------------------------
# The evasion ladder -- per-window classifier AUC collapses; CUSUM does not.
# --------------------------------------------------------------------------
def _roc_auc(score, label):
    score = np.asarray(score, float); label = np.asarray(label, bool)
    n1, n0 = int(label.sum()), int((~label).sum())
    if n1 == 0 or n0 == 0:
        return float("nan")
    order = np.argsort(score, kind="mergesort")
    ranks = np.empty(len(score)); ranks[order] = np.arange(1, len(score) + 1)
    return float((ranks[label].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


# Each rung ADDS a constraint the implant satisfies. `poll_jitter` and
# `circadian`/`timeout_rand` shape the TIMING signal; `delta_sigma` is the
# volume footprint; `matched_tls` removes the fingerprint signal (modelled as
# whether a per-window TLS-mismatch flag is available).
LADDER = [
    ("0_commodity",    dict(delta_sigma=2.0, poll="fixed",    matched_tls=False, always_on=True)),
    ("1_jittered",     dict(delta_sigma=2.0, poll="uniform",  matched_tls=False, always_on=True)),
    ("2_matched_tls",  dict(delta_sigma=2.0, poll="uniform",  matched_tls=True,  always_on=True)),
    ("3_circadian",    dict(delta_sigma=1.0, poll="lognormal",matched_tls=True,  always_on=False)),
    ("4_full_mimicry", dict(delta_sigma=0.4, poll="lognormal",matched_tls=True,  always_on=False)),
]


def _window_features(rng, n, cfg, benign):
    """Per-active-window feature rows for an implant at one ladder rung.
    Returns (upload_z, timing_regularity, tls_mismatch) columns."""
    mu0, sigma0 = base_moments()
    up = baseline_upload(rng, n) + cfg["delta_sigma"] * sigma0
    up_z = (up - mu0) / sigma0
    # timing regularity: 1 - normalised iat_cv over the window's check-ins
    reg = np.empty(n)
    for i in range(n):
        if cfg["poll"] == "fixed":
            iats = _beacon_iats(rng, 12, 30.0, 0.0, shape="uniform")
        elif cfg["poll"] == "uniform":
            iats = _beacon_iats(rng, 12, 30.0, 0.5, shape="uniform")
        else:                                   # lognormal = human-mimicking
            iats = _human_iats(rng, 12, 30.0, sigma=1.1)
        cv = _iat_stats(iats)[0]
        reg[i] = 1.0 / (1.0 + cv)               # high = machine-regular
    tls = np.ones(n) if not cfg["matched_tls"] else np.zeros(n)
    return up_z, reg, tls


def evasion_ladder(rng, n=4000):
    """For each rung: the best per-window classifier AUC, and the CUSUM delay.

    The point is the CONTRAST: AUC falls toward 0.5 as the implant climbs;
    CUSUM delay stays finite until the footprint reaches the floor."""
    mu0, sigma0 = base_moments()
    # benign reference windows for the classifier
    bz = (baseline_upload(rng, n) - mu0) / sigma0
    breg = np.empty(n)
    for i in range(n):
        breg[i] = 1.0 / (1.0 + _iat_stats(_human_iats(rng, 12, 30.0, sigma=1.1))[0])
    btls = np.zeros(n)

    # a fixed CUSUM tuned once, reused across rungs
    k = 0.5
    arl0_windows = 513.0 * ACTIVE_WINDOWS_PER_DAY
    h = calibrate_h(k, arl0_windows)
    arl0_meas, _ = arl_mc(rng, k, h, 0.0, cap=int(arl0_windows * 4))

    out = []
    for name, cfg in LADDER:
        uz, reg, tls = _window_features(rng, n, cfg, None)
        # best single-window classifier: max over standardised signals
        # (upload deviation, timing regularity, tls mismatch)
        pos = np.vstack([uz, reg, tls]).T
        neg = np.vstack([bz, breg, btls]).T
        aucs = {}
        for j, fname in enumerate(("upload_z", "timing_reg", "tls_mismatch")):
            aucs[fname] = _roc_auc(np.r_[pos[:, j], neg[:, j]],
                                   np.r_[np.ones(n), np.zeros(n)])
        best = max(v for v in aucs.values() if not np.isnan(v))
        delay_win, lost = detection_delay(rng, k, h, cfg["delta_sigma"] * sigma0,
                                          arl0=arl0_meas)
        out.append(dict(
            rung=name,
            per_window_auc_best=float(best),
            per_window_auc=aucs,
            footprint_sigma=cfg["delta_sigma"],
            cusum_delay_days=float(delay_win / ACTIVE_WINDOWS_PER_DAY),
            cusum_lost_in_noise=bool(lost),
        ))
    return dict(k=k, h=float(h), arl0_days=float(arl0_meas / ACTIVE_WINDOWS_PER_DAY),
                rungs=out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="telegram_c2.json")
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)

    print("=" * 74)
    print("  Telegram-C2: the perfect-mimicry case, bounded not solved")
    print("=" * 74)
    mu0, sigma0 = base_moments()
    print(f"  benign active-window upload: mean {mu0:,.0f} B  std {sigma0:,.0f} B"
          f"   ({ACTIVE_WINDOWS_PER_DAY:.1f} active windows/day)")
    print(f"  ANCHOR: synth Messaging_API; real capture had 0 such windows (G1)")

    print("\n  EVASION LADDER -- per-window detection dies, accumulation does not")
    lad = evasion_ladder(rng)
    print(f"  false-alarm interval (ARL0) ~ {lad['arl0_days']:.0f} days")
    print(f"  {'rung':16s}{'footprint':>11}{'per-window AUC':>16}{'CUSUM detect':>16}")
    for r in lad["rungs"]:
        d = f"{r['cusum_delay_days']:.1f} d" + (" (lost)" if r["cusum_lost_in_noise"] else "")
        print(f"  {r['rung']:16s}{r['footprint_sigma']:>10.2f}σ"
              f"{r['per_window_auc_best']:>16.3f}{d:>16}")

    print("\n  CAPACITY-DELAY FRONTIER -- the theorem, measured on real skew")
    fr = frontier(rng)
    print(f"  CUSUM k={fr['k']}  h={fr['h']:.2f}   false alarm ~ once / "
          f"{fr['arl0_measured_days']:.0f} days (calibrated on lognormal)")
    fl = fr["floor_kb_per_day"]
    print(f"  operational floor ~ {fl:.0f} KB/day"
          if fl is not None else "  operational floor: none in range")
    print("  (smallest footprint still caught BEFORE a false alarm)")
    print(f"  {'exfil KB/day':>14}{'footprint':>11}{'days to detect':>16}{'':>9}")
    for r in fr["curve"]:
        tag = "  lost in noise" if r["lost_in_noise"] else ""
        print(f"  {r['exfil_kb_per_day']:>14.1f}{r['footprint_sigma']:>10.2f}σ"
              f"{r['days_to_detect']:>16.1f}{tag}")

    print("\n  READ IT AS A BOUND, NOT A DETECTION.")
    print("  - Per-window AUC falls toward chance under full mimicry. Reported.")
    print("  - Any footprint above the floor is caught; the delay is the")
    print("    attacker's, set by how little they dare send.")
    print(f"  - Below ~{fl:.0f} KB/day the true alarm arrives no sooner than a false"
          if fl is not None else "  - the floor sits below the smallest footprint swept")
    print("    one -- the channel is lost in the detector's own noise. Lower k or")
    print("    extend the baseline to push the floor down; nothing makes it zero.")
    print("  - The guaranteed-invisible channel is the one whose bandwidth has")
    print("    been driven into the noise floor. Zero-capacity = safe.")
    print("\n  CAVEATS (both stated, neither hidden):")
    print("  - baseline anchored to synth Messaging_API; real capture had 0 such")
    print("    windows (G1). The SHAPE of the frontier holds; the KB/day levels")
    print("    will move on real traffic.")
    print("  - assumes a STATIONARY baseline. A slow exfil ramp can hide inside")
    print("    real upward drift -- the drift the shift test already measured.")

    json.dump(dict(seed=a.seed, ladder=lad, frontier=fr,
                   baseline=dict(mean_bytes=mu0, std_bytes=sigma0,
                                 active_windows_per_day=ACTIVE_WINDOWS_PER_DAY,
                                 anchor="synth Messaging_API; real capture had 0 (G1)"),
                   claim=("bounded not solved: per-window AUC collapses under "
                          "mimicry; CUSUM converts exfil bandwidth into bounded "
                          "detection delay; guaranteed-invisible channel has "
                          "~zero capacity")),
              open(a.out, "w"), indent=2)
    print(f"\n  wrote {a.out}")


if __name__ == "__main__":
    main()
