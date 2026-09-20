#!/usr/bin/env python3
"""
bench_beacon.py -- does the jitter-trap inversion actually work on REAL traffic?

THE CLAIM, which appears in every document and on the deck:
    "A beacon that adds random jitter to evade timing detection produces
     UNIFORM inter-arrival times. Humans are log-normal and bursty. So low
     ks_uniform plus low fft_prominence indicates automation. The evasion is
     itself the signature."

WHY THE EXISTING EVIDENCE IS WORTHLESS:
    synth._beacon_iats is literally `rng.uniform(sleep*(1-j), sleep*(1+j))`.
    The feature ks_uniform measures distance from uniform. So the generator
    builds beacons uniform and the feature then detects uniformity. It is a
    tautology. It cannot fail, and it tells us nothing about real traffic.

WHAT THIS DOES INSTEAD:
    NEGATIVES  real inter-arrival times extracted from our own packet capture.
               Actual human browsing and actual machine background traffic. No
               model, no generator -- timestamps off the wire.
    POSITIVES  beacon schedules built from PUBLISHED C2 defaults, and crucially
               from THREE different jitter distributions, not just the uniform
               one the feature was designed against:
                 uniform      what synth assumes, what most C2 frameworks do
                 gaussian     an operator who wrote their own sleep loop
                 lognormal    a deliberately human-mimicking beacon

    If the feature only separates the uniform case, it detects a specific
    implementation choice rather than "automation", and the claim has to be
    narrowed. That is the question this file exists to answer.

Features come from synth._iat_stats -- the exact code the models consume, not a
reimplementation.
"""
from __future__ import annotations

import argparse, json, os, struct, sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture_probe as CP                          # noqa: E402
import pcap_to_tensor as P2T                        # noqa: E402
from netsentinel_v2.synth import _iat_stats         # noqa: E402

FEATS = ["iat_cv", "ks_uniform", "ks_exponential", "fft_prominence"]


# ---- POSITIVES: beacon schedules from documented C2 defaults --------------
# Sleep/jitter pairs as published in the frameworks' own documentation.
# Cobalt Strike's `sleep 60 37` means 60s with 37% jitter; Sliver's default is
# 60s/30s; Empire's agent delay defaults to 5s with 0.0 jitter and operators
# commonly raise it. These are configuration defaults, not measurements of any
# real intrusion.
C2_PROFILES = [
    ("cobaltstrike_60_37",  60.0, 0.37),
    ("cobaltstrike_300_20", 300.0, 0.20),
    ("sliver_60_50",        60.0, 0.50),
    ("empire_5_0",           5.0, 0.00),
    ("empire_60_30",        60.0, 0.30),
    ("slow_3600_10",      3600.0, 0.10),
]


def beacon_iats(rng, n, sleep, jitter, shape):
    """Three ways an implementer might add jitter to the same sleep."""
    if jitter <= 0:
        return np.full(n, sleep, dtype=float)
    if shape == "uniform":
        return rng.uniform(sleep * (1 - jitter), sleep * (1 + jitter), n)
    if shape == "gaussian":
        # same mean and a comparable spread, but a bell not a box
        return np.clip(rng.normal(sleep, sleep * jitter / 2.0, n), 1e-3, None)
    if shape == "lognormal":
        # a beacon deliberately imitating human burstiness
        sigma = max(jitter, 0.05)
        return rng.lognormal(np.log(sleep) - sigma ** 2 / 2, sigma, n)
    raise ValueError(shape)


# ---- NEGATIVES: real inter-arrivals off the wire --------------------------
def real_iats(paths, granularity="connection", idle_gap=60.0,
              min_len=8, verbose=True):
    """Real inter-arrival times off the wire, at a CHOSEN granularity.

    This distinction is the whole experiment and getting it wrong invalidates
    the result. A beacon's sleep interval is the time between CHECK-INS. Within
    one check-in the beacon still sends a burst of packets microseconds apart,
    exactly like any other connection. So:

      granularity="packet"      every packet timestamp in the flow. Real
                                traffic here is bursty, cv ~3.6.
      granularity="connection"  the START of each session, where a session ends
                                after `idle_gap` seconds of silence. This is
                                the series a beacon's sleep setting governs,
                                and the only one comparable to a C2 profile.

    Comparing packet-level real data against check-in-level beacons produces a
    perfect AUC that means nothing at all.
    """
    local = P2T.local_addresses(paths, verbose=False)
    flows = defaultdict(list)
    n_pk = 0
    for path in paths:
        for rec in P2T.read_with_ts(path):
            if rec[0] == "idb":
                continue
            _tag, ts, origlen, pkt = rec
            n_pk += 1
            p = CP.eth_ip(pkt)
            if not p:
                continue
            proto, s_ip, d_ip, l4off, _ = p
            if proto not in (6, 17) or len(pkt) < l4off + 4:
                continue
            sp, dp = struct.unpack("!HH", pkt[l4off:l4off + 4])
            s_loc, d_loc = s_ip in local, d_ip in local
            if s_loc == d_loc:
                continue
            key = (s_ip, d_ip, dp) if s_loc else (d_ip, s_ip, sp)
            flows[key].append(ts)

    out = []
    for k, ts in flows.items():
        ts = np.sort(np.asarray(ts))
        if granularity == "packet":
            series = ts
        else:
            gaps = np.diff(ts)
            starts = np.r_[ts[0], ts[1:][gaps > idle_gap]]
            series = starts
        if len(series) < min_len + 1:
            continue
        d = np.diff(series)
        d = d[d > 0]
        if len(d) >= min_len:
            out.append(d)
    if verbose:
        print(f"  read {n_pk:,} packets -> {len(flows):,} flows -> "
              f"{len(out):,} usable at {granularity} granularity "
              f"(>= {min_len} intervals)")
    return out


def roc_auc(score, label):
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


def boot_auc(pos, neg, reps=600, seed=0):
    """Percentile bootstrap over FLOWS. With ~24 real flows the point estimate
    is nearly meaningless on its own; the interval is the honest object."""
    rng = np.random.default_rng(seed)
    out = []
    for _ in range(reps):
        p = pos[rng.integers(0, len(pos), len(pos))]
        n = neg[rng.integers(0, len(neg), len(neg))]
        s = np.r_[p, n]
        y = np.r_[np.ones(len(p), bool), np.zeros(len(n), bool)]
        a = roc_auc(s, y)
        if not np.isnan(a):
            out.append(max(a, 1 - a))
    return (float(np.percentile(out, 2.5)), float(np.percentile(out, 97.5))) \
        if out else (float("nan"), float("nan"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--granularity", default="connection",
                    choices=["connection", "packet"])
    ap.add_argument("--idle-gap", type=float, default=60.0)
    ap.add_argument("--out", default="bench_beacon.json")
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)

    print("=" * 74)
    print("  Does the jitter-trap inversion hold on REAL traffic?")
    print("=" * 74)
    print(f"\n  NEGATIVES -- real inter-arrivals, {a.granularity} granularity")
    if a.granularity == "packet":
        print("  !! packet granularity is NOT comparable to a C2 sleep")
        print("  !! interval. Any separation here is an artefact.")
    neg = real_iats(a.pcaps, granularity=a.granularity, idle_gap=a.idle_gap)
    if len(neg) < 20:
        print("  too few real flows to test against. Need a bigger capture.")
        return 2
    neg_f = np.array([_iat_stats(d) for d in neg])
    lens = [len(d) for d in neg]

    print(f"\n  real flows: {len(neg)}   intervals per flow "
          f"median {int(np.median(lens))}, range {min(lens)}-{max(lens)}")
    print(f"  {'feature':<18}{'real median':>13}{'real p10':>11}{'real p90':>11}")
    for i, f in enumerate(FEATS):
        c = neg_f[:, i]
        print(f"  {f:<18}{np.median(c):>13.3f}{np.percentile(c,10):>11.3f}"
              f"{np.percentile(c,90):>11.3f}")

    # positives: match the real flows' length distribution so the comparison
    # is not confounded by sample size
    results = {}
    print()
    print("  SEPARATION, by jitter shape (AUC vs the same real negatives)")
    print(f"  {'shape':<12}{'iat_cv':>10}{'ks_uniform':>13}"
          f"{'ks_exp':>10}{'fft_prom':>11}{'best':>9}")
    for shape in ("uniform", "gaussian", "lognormal"):
        pos = []
        for name, sleep, jit in C2_PROFILES:
            for _ in range(max(1, len(neg) // len(C2_PROFILES))):
                n = int(rng.choice(lens))
                pos.append(beacon_iats(rng, n, sleep, jit, shape))
        pos_f = np.array([_iat_stats(d) for d in pos])
        y = np.r_[np.ones(len(pos_f), bool), np.zeros(len(neg_f), bool)]
        row, aucs = [], {}
        for i, f in enumerate(FEATS):
            s = np.r_[pos_f[:, i], neg_f[:, i]]
            au = roc_auc(s, y)
            # the claim is LOW ks_uniform / LOW fft means automation, so the
            # discriminating direction may be inverted -- report the usable one
            au = max(au, 1 - au)
            lo, hi = boot_auc(pos_f[:, i], neg_f[:, i], seed=i)
            aucs[f] = dict(auc=au, ci95=[lo, hi])
            row.append(au)
        best = max(row)
        print(f"  {shape:<12}{row[0]:>10.3f}{row[1]:>13.3f}"
              f"{row[2]:>10.3f}{row[3]:>11.3f}{best:>9.3f}")
        results[shape] = dict(n_pos=len(pos_f), aucs=aucs, best=best)
        bf = FEATS[int(np.argmax(row))]
        c = aucs[bf]["ci95"]
        print(f"  {'':<12}best feature: {bf}  95% CI [{c[0]:.3f}, {c[1]:.3f}]")

    print()
    u, g, l = (results[k]["best"] for k in ("uniform", "gaussian", "lognormal"))
    print("  FEATURE-BY-FEATURE, averaged over the three shapes:")
    for f in FEATS:
        m = float(np.mean([results[k]["aucs"][f]["auc"] for k in results]))
        print(f"    {f:<18}{m:.3f}")
    print()
    print(f"  uniform-jitter beacons   : best AUC {u:.3f}")
    print(f"  gaussian-jitter beacons  : best AUC {g:.3f}")
    print(f"  lognormal-jitter beacons : best AUC {l:.3f}")
    print()
    if u > 0.9 and l > 0.9:
        verdict = ("HOLDS. The timing features separate beacons from real "
                   "traffic regardless of how the jitter was drawn.")
    elif u > 0.9 and l < 0.75:
        verdict = ("NARROW. The features separate UNIFORM-jitter beacons well "
                   f"(AUC {u:.3f}) but a lognormal-jitter beacon, which is what "
                   f"a determined implementer would write, drops to {l:.3f}. "
                   "The claim detects a common implementation choice, not "
                   "automation in general. Say the narrower thing.")
    elif u < 0.75:
        verdict = ("FAILS. Even the uniform case does not separate on real "
                   "traffic. The synthetic result was an artefact of the "
                   "generator and the claim must be withdrawn.")
    else:
        verdict = (f"MIXED. uniform {u:.3f}, gaussian {g:.3f}, lognormal "
                   f"{l:.3f}. Report the per-shape table, not a single number.")
    print(f"  VERDICT: {verdict}")

    json.dump(dict(n_real_flows=len(neg), real_interval_median=int(np.median(lens)),
                   c2_profiles=[p[0] for p in C2_PROFILES], by_shape=results,
                   verdict=verdict, source="own capture, real packet timestamps"),
              open(a.out, "w"), indent=2)
    print(f"\n  wrote {a.out}")


if __name__ == "__main__":
    sys.exit(main() or 0)
