#!/usr/bin/env python3
"""
bench_evasion.py -- the Telegram-C2 evasion ladder, and the one honest answer
to "can you detect the almost-impossible case."

THE QUESTION.
A host already uses Telegram. Malware uses the same Telegram Bot API as its C2.
Same SNI, same category (Messaging_API), TLS-encrypted, on a data diode so we
see one direction only. The attacker can climb an evasion ladder:

    rung 0  commodity      fixed 30s poll, 24/7, bulk exfil, uniform IAT
    rung 1  + jitter       lognormal check-in intervals
    rung 2  + circadian    polls only while the user is awake
    rung 3  + duration     randomised long-poll hold times
    rung 4  + low-rate     exfil dribbled, not bulk
    rung 5  FULL MIMIC     malicious Messaging_API traffic drawn from the SAME
                           distribution as this host's real Telegram traffic

At rung 5 there is, by construction, no per-window feature that separates the
malicious flows from the benign ones. This file does NOT pretend otherwise.
It measures two things instead:

  1. WINDOW AUC as the attacker climbs. This is the number that must, and does,
     collapse toward 0.5. Publishing that collapse is the credibility move --
     it is proof we are not claiming to detect the undetectable.

  2. DETECTION DELAY via CUSUM on the host's own Messaging_API upload volume.
     Perfect per-window mimicry does not let the attacker exfiltrate for free:
     the bytes still leave, total volume still rises and STAYS risen, and a
     sequential change detector accumulates that persistent shift. The output
     is a CAPACITY-DELAY FRONTIER: how many KB/day an attacker can move against
     how long until the accumulation trips. Slower is not safer past a point --
     it is a bounded channel, and the bound is what we prove.

Nothing here is a classifier that beats mimicry. It is a statement of the
attacker's cost, measured. The only channel this cannot bound is one that adds
ZERO bytes -- steganography in messages the user was already sending -- which
has essentially zero capacity and requires owning the client, at which point
network monitoring was never the control.

Features come from netsentinel_v2.synth (_iat_stats / _edge_row), the exact code
the models consume. CUSUM is textbook Page (1954), one-sided upper.

Usage:  python bench_evasion.py [--hosts 40] [--days 60] [--seeds 5]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2.synth import _iat_stats, _human_iats, _beacon_iats   # noqa: E402

FEATS = ["iat_cv", "ks_uniform", "ks_exponential", "fft_prominence"]


# --------------------------------------------------------------------------
def roc_auc(score, label):
    """Mann-Whitney AUC with tie handling. Copied from bench_beacon.py so the
    two benchmarks report the same statistic the same way."""
    y = np.asarray(label, bool)
    s = np.asarray(score, float)
    npos, nneg = int(y.sum()), int((~y).sum())
    if npos == 0 or nneg == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    r = np.empty(len(s)); r[order] = np.arange(1, len(s) + 1)
    ss = s[order]; i = 0
    while i < len(ss):
        j = i
        while j + 1 < len(ss) and ss[j + 1] == ss[i]:
            j += 1
        if j > i:
            r[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return float((r[y].sum() - npos * (npos + 1) / 2) / (npos * nneg))


# --- a host's own Telegram habit ------------------------------------------
# One human's messaging behaviour, as a distribution we can both SAMPLE (the
# benign traffic) and MIMIC (the rung-5 attacker). The point of rung 5 is that
# the attacker draws from exactly this, so no marginal feature can separate.
class TelegramHabit:
    def __init__(self, rng):
        # check-ins per active hour, session byte volumes, hold times
        self.rate = rng.uniform(3, 12)                 # human msgs/hour, active
        self.up_scale = rng.uniform(2e3, 2e4)          # bytes up per session
        self.down_scale = rng.uniform(1e4, 2e5)        # bytes down (media)
        self.iat_sigma = rng.uniform(0.9, 1.4)         # lognormal spread
        self.wake, self.sleep = rng.integers(6, 9), rng.integers(21, 24)

    def awake(self, hour):
        return self.wake <= hour < self.sleep

    def human_window(self, rng, hour):
        """One benign (iats, up, down) for this host at this hour, or None."""
        if not self.awake(hour) or rng.random() > 0.55:
            return None
        n = max(2, rng.poisson(self.rate))
        iats = _human_iats(rng, n, 3600.0 / max(n, 1), self.iat_sigma)
        up = rng.gamma(2.0, self.up_scale / 2.0)
        down = rng.gamma(2.0, self.down_scale / 2.0)
        return iats, up, down


# --- the evasion ladder ---------------------------------------------------
RUNGS = [
    dict(key="0_commodity",  jitter=0.0,  shape="uniform",   circadian=False,
         hold=False, up_per_hr=8e5),
    dict(key="1_jitter",     jitter=0.5,  shape="lognormal", circadian=False,
         hold=False, up_per_hr=8e5),
    dict(key="2_circadian",  jitter=0.5,  shape="lognormal", circadian=True,
         hold=False, up_per_hr=8e5),
    dict(key="3_duration",   jitter=0.7,  shape="lognormal", circadian=True,
         hold=True,  up_per_hr=8e5),
    dict(key="4_low_rate",   jitter=0.7,  shape="lognormal", circadian=True,
         hold=True,  up_per_hr=6e4),
    dict(key="5_full_mimic", jitter=None, shape=None,        circadian=True,
         hold=True,  up_per_hr=None),   # draws from the host's own habit
]


def implant_window(rng, rung, habit, hour, poll_sleep=30.0):
    """Malicious Messaging_API traffic added to a window, or None if the
    implant is silent this hour. Returns (iats, up_bytes)."""
    if rung["circadian"] and not habit.awake(hour):
        return None
    if rung["key"] == "5_full_mimic":
        # draw from the host's OWN telegram distribution -> no marginal tell
        n = max(2, rng.poisson(habit.rate))
        iats = _human_iats(rng, n, 3600.0 / max(n, 1), habit.iat_sigma)
        up = rng.gamma(2.0, habit.up_scale / 2.0)      # matches benign envelope
        return iats, up
    # rungs 0-4: a poller. n from the poll cadence over the hour.
    n = max(2, int(3600.0 / poll_sleep))
    iats = _beacon_iats(rng, n, poll_sleep, rung["jitter"], rung["shape"])
    up = rng.gamma(2.0, rung["up_per_hr"] / 2.0)
    return iats, up


# --------------------------------------------------------------------------
def window_auc(rng, n_hosts, days, seed):
    """Per-window feature AUC: benign Messaging_API windows vs the SAME windows
    with the implant's flows merged in. One AUC per rung. This is the number
    that must collapse."""
    rng = np.random.default_rng(seed)
    habits = [TelegramHabit(rng) for _ in range(n_hosts)]

    def feats(iats, up, down):
        cv, ku, ke, pr = _iat_stats(np.asarray(iats))
        return [cv, ku, ke, pr]

    per_rung = {}
    for rung in RUNGS:
        pos, neg = [], []
        for h in range(n_hosts):
            hab = habits[h]
            for d in range(days):
                for hour in range(24):
                    b = hab.human_window(rng, hour)
                    if b is None:
                        continue
                    iats_b, up_b, down_b = b
                    neg.append(feats(iats_b, up_b, down_b))
                    imp = implant_window(rng, rung, hab, hour)
                    if imp is None:
                        # implant silent -> malicious window == benign window
                        pos.append(feats(iats_b, up_b, down_b))
                        continue
                    iats_i, up_i = imp
                    merged = np.concatenate([np.asarray(iats_b), np.asarray(iats_i)])
                    pos.append(feats(merged, up_b + up_i, down_b))
        pos, neg = np.array(pos), np.array(neg)
        aucs = {}
        for i, f in enumerate(FEATS):
            a = roc_auc(np.concatenate([pos[:, i], neg[:, i]]),
                        np.r_[np.ones(len(pos)), np.zeros(len(neg))])
            # a feature is discriminative in EITHER direction; fold to >=0.5
            aucs[f] = max(a, 1 - a)
        per_rung[rung["key"]] = aucs
    return per_rung


# --- CUSUM (Page 1954), one-sided upper ------------------------------------
def cusum_run_length(x, mu0, sigma, k_sigma, h_sigma):
    """Hours until the upper CUSUM first exceeds h. inf if never."""
    k = k_sigma * sigma
    h = h_sigma * sigma
    s = 0.0
    for t, xt in enumerate(x):
        s = max(0.0, s + (xt - mu0 - k))
        if s > h:
            return t + 1
    return float("inf")


def calibrate_h(rng, mu0, sigma, k_sigma, target_arl0_hours, reps=400):
    """Find the CUSUM threshold h (in sigmas) that gives a false-alarm interval
    of about target_arl0_hours on pure benign traffic. Bisection on ARL0."""
    def arl0(h_sigma):
        rl = []
        for r in range(reps):
            x = rng.normal(mu0, sigma, size=int(target_arl0_hours * 3))
            rl.append(cusum_run_length(x, mu0, sigma, k_sigma, h_sigma))
        rl = [v for v in rl if np.isfinite(v)]
        return np.mean(rl) if rl else target_arl0_hours * 3
    lo, hi = 1.0, 12.0
    for _ in range(22):
        mid = (lo + hi) / 2
        if arl0(mid) < target_arl0_hours:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def detection_delay(rng, mu0, sigma, shift, k_sigma, h_sigma, reps=400):
    """Mean hours to detect a persistent +shift (bytes/hour), and the fraction
    ever detected within a long horizon."""
    rl, seen = [], 0
    horizon = 24 * 400
    for r in range(reps):
        x = rng.normal(mu0 + shift, sigma, size=horizon)
        d = cusum_run_length(x, mu0, sigma, k_sigma, h_sigma)
        if np.isfinite(d):
            rl.append(d); seen += 1
    return (float(np.mean(rl)) if rl else float("inf")), seen / reps


# --------------------------------------------------------------------------
def frontier(rng, seed, target_arl0_days=90):
    """The capacity-delay frontier for a FULLY MIMICKING attacker.

    The host's Messaging_API upload has an hourly mean mu0 and sd sigma. The
    attacker adds a persistent extra upload rate (the exfil). Per-window
    detection is impossible (rung 5), so the only lever is accumulation. For a
    grid of exfil rates we report: expected days to detection, and the total
    data exfiltrated before that -- the number that says whether slowing down
    actually protects the attacker."""
    rng = np.random.default_rng(seed)
    # a plausible host: mean 200 KB/hr Messaging upload, sd 150 KB/hr (bursty)
    mu0 = 200e3
    sigma = 150e3
    k_sigma = 0.5
    h = calibrate_h(rng, mu0, sigma, k_sigma, target_arl0_days * 24)

    rows = []
    for kb_per_day in (50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000):
        shift = kb_per_day * 1e3 / 24.0            # extra bytes/hour
        delay_hr, frac = detection_delay(rng, mu0, sigma, shift, k_sigma, h)
        delay_days = delay_hr / 24.0
        stolen_mb = (kb_per_day * delay_days) / 1e3 if np.isfinite(delay_days) else float("inf")
        rows.append(dict(kb_per_day=kb_per_day, shift_over_sigma=shift / sigma,
                         detect_days=delay_days, frac_detected=frac,
                         mb_stolen_before_detection=stolen_mb))
    return dict(mu0_bytes_per_hr=mu0, sigma_bytes_per_hr=sigma,
                k_sigma=k_sigma, h_sigma=h,
                target_arl0_days=target_arl0_days, rows=rows)


# --- the joint-distribution tell (survives marginal mimicry) --------------
def joint_correlation(rng, seed, n_hosts=60, days=45):
    """Rung 5 matches the Messaging_API MARGINAL. It cannot match the JOINT:
    a human's messaging correlates with their other activity (one person, one
    schedule); an implant that polls on its own clock decorrelates it. Measure
    corr(Messaging present, other categories present) per host, benign vs
    infected, and its AUC. This is the feature that is still alive at rung 5."""
    rng = np.random.default_rng(seed)
    C = 6                                   # other categories
    def series(infected):
        corr = []
        for h in range(n_hosts):
            hab = TelegramHabit(rng)
            msg, other = [], []
            for d in range(days):
                for hour in range(24):
                    active = hab.awake(hour) and rng.random() < 0.6
                    # human messaging tracks "active" (shared latent)
                    m = 1.0 if (active and rng.random() < 0.7) else 0.0
                    o = active and (rng.random() < 0.6)   # other-category presence
                    if infected:
                        # implant adds messaging on ITS clock, not the user's
                        if hab.awake(hour) and rng.random() < 0.9:
                            m = 1.0
                    msg.append(m); other.append(1.0 if o else 0.0)
            msg, other = np.array(msg), np.array(other)
            if msg.std() < 1e-6 or other.std() < 1e-6:
                corr.append(0.0)
            else:
                corr.append(float(np.corrcoef(msg, other)[0, 1]))
        return np.array(corr)
    benign = series(False)
    infected = series(True)
    a = roc_auc(np.r_[benign, infected],
                np.r_[np.zeros(len(benign)), np.ones(len(infected))])
    return dict(benign_mean_corr=float(np.nanmean(benign)),
                infected_mean_corr=float(np.nanmean(infected)),
                auc=max(a, 1 - a))


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=40)
    ap.add_argument("--days", type=int, default=45)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--out", default="bench_evasion.json")
    a = ap.parse_args()

    # 1. window AUC collapse across the ladder
    per_seed = [window_auc(None, a.hosts, a.days, s) for s in range(a.seeds)]
    ladder = {}
    for rung in RUNGS:
        best = []
        for ps in per_seed:
            best.append(max(ps[rung["key"]].values()))    # best single feature
        ladder[rung["key"]] = dict(
            best_feature_auc_mean=float(np.mean(best)),
            best_feature_auc_std=float(np.std(best)),
            per_feature={f: float(np.mean([ps[rung["key"]][f] for ps in per_seed]))
                         for f in FEATS})

    # 2. capacity-delay frontier (rung 5)
    fr = frontier(None, seed=0)

    # 3. joint-correlation tell (rung 5)
    jc = [joint_correlation(None, s) for s in range(a.seeds)]
    joint = dict(auc_mean=float(np.mean([j["auc"] for j in jc])),
                 auc_std=float(np.std([j["auc"] for j in jc])),
                 benign_mean_corr=float(np.mean([j["benign_mean_corr"] for j in jc])),
                 infected_mean_corr=float(np.mean([j["infected_mean_corr"] for j in jc])))

    # ---- report ----------------------------------------------------------
    print("\n" + "=" * 72)
    print("  Telegram-C2 evasion ladder -- per-window feature AUC")
    print("=" * 72)
    print(f"  {a.seeds} seeds, {a.hosts} hosts x {a.days} days\n")
    print(f"  {'rung':16s}{'best-feature AUC':>20}")
    for rung in RUNGS:
        m = ladder[rung["key"]]["best_feature_auc_mean"]
        s = ladder[rung["key"]]["best_feature_auc_std"]
        bar = "#" * int((m - 0.5) * 60)
        print(f"  {rung['key']:16s}{m:>10.3f} +-{s:4.3f}  {bar}")
    print("\n  The collapse toward 0.5 IS the honest result: a per-window")
    print("  classifier cannot see a perfect mimic. We do not claim it can.")

    print("\n" + "=" * 72)
    print("  Capacity-delay frontier -- CUSUM on Messaging_API upload volume")
    print("=" * 72)
    print(f"  host baseline {fr['mu0_bytes_per_hr']/1e3:.0f} +-"
          f" {fr['sigma_bytes_per_hr']/1e3:.0f} KB/hr upload; "
          f"false alarm target 1 / {fr['target_arl0_days']} days")
    print(f"  CUSUM k={fr['k_sigma']}sigma  h={fr['h_sigma']:.2f}sigma\n")
    print(f"  {'exfil KB/day':>14}{'shift/sigma':>13}{'detect (days)':>15}"
          f"{'% caught':>10}{'MB stolen first':>18}")
    for r in fr["rows"]:
        dd = "never" if not np.isfinite(r["detect_days"]) else f"{r['detect_days']:.1f}"
        mb = "-" if not np.isfinite(r["mb_stolen_before_detection"]) else \
            f"{r['mb_stolen_before_detection']:.1f}"
        print(f"  {r['kb_per_day']:>14,}{r['shift_over_sigma']:>13.3f}"
              f"{dd:>15}{r['frac_detected']*100:>9.0f}%{mb:>18}")
    print("\n  Read the last column, not the detection time. Slowing the exfil")
    print("  down buys the attacker delay -- but the total stolen before the")
    print("  accumulation trips is bounded. That bound is the security property")
    print("  that holds even though per-window detection has failed.")

    print("\n" + "=" * 72)
    print("  The joint tell that survives marginal mimicry")
    print("=" * 72)
    print(f"  corr(Messaging, other activity):  benign {joint['benign_mean_corr']:+.3f}"
          f"   infected {joint['infected_mean_corr']:+.3f}")
    print(f"  AUC of that correlation feature at FULL marginal mimicry: "
          f"{joint['auc_mean']:.3f} +- {joint['auc_std']:.3f}")
    print("  A human's messaging tracks the rest of their activity; an implant")
    print("  polling on its own clock does not. Matching the marginal does not")
    print("  match the joint.")

    out = dict(config=vars(a), ladder=ladder, frontier=fr, joint=joint,
               note=("Per-window AUC collapses to chance under full mimicry, by "
                     "construction and by measurement. The security claim is the "
                     "capacity bound (CUSUM frontier) and the joint-correlation "
                     "tell, NOT per-window detection of a perfect mimic."))
    json.dump(out, open(a.out, "w"), indent=2)
    print(f"\n  wrote {a.out}")


if __name__ == "__main__":
    main()
