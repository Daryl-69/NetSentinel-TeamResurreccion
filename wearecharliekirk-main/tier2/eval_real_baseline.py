#!/usr/bin/env python3
"""How does the real-traffic Inspector behave on YOUR capture?

    python eval_real_baseline.py                          # tier2/data/baseline_corpus.sqlite
    python eval_real_baseline.py --corpus other.sqlite --train-frac 0.7

Splits the corpus IN TIME: the first --train-frac of its days commission the
Inspector/Sentry exactly as `inspector_live.py train` does; the remaining days
are replayed hour by hour exactly as `serve` scores live traffic (Sentry on
every active device -> top --budget to the Inspector -> flag if above its
99th-percentile threshold). It reports:

  * false-alarm rate on held-out BENIGN hours (the number that decides whether
    an operator keeps the thing switched on), by hour of day and by device;
  * detection of a planted living-off-trusted-services chain (Recon API ->
    paste site -> messaging API -> cloud upload, machine-regular timing)
    overlaid on randomly chosen held-out device-hours -- ground truth you
    control, since the capture has no attack labels;
  * data quality: days covered, device-days, share of traffic the resolver
    could not name (Unknown_External).

Writes the full result to real_baseline_eval.json. The planted chain is
synthetic by construction; the benign hours are entirely your traffic.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import numpy as np  # noqa: E402

import inspector_live as IL  # noqa: E402
from netsentinel_v2 import hostwindows as HW  # noqa: E402
from netsentinel_v2.categories import CAT_INDEX, CATEGORIES  # noqa: E402
from netsentinel_v2.synth import _edge_row  # noqa: E402

W = HW.WINDOWS_PER_DAY
CHAIN = [("Recon_API", 1.2e3, 900), ("Code_Repo_Paste", 2.5e3, 40_000),
         ("Messaging_API", 6e3, 3e3), ("Cloud_Storage", 2.5e7, 2e3)]


def chain_rows(host, lhour, rng):
    """One compromised hour: each chain step polled on a jittered timer."""
    out = []
    for cat, up, down in CHAIN:
        n = int(rng.integers(12, 40))
        sleep = float(rng.uniform(45, 120))
        iat = rng.uniform(sleep * 0.8, sleep * 1.2, n)
        out.append((host, lhour, CAT_INDEX[cat], n,
                    _edge_row(None, n, up * n / 20, down * n / 20, iat, 1.0 / n, 0.6)))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=IL.DEFAULT_BASELINE)
    ap.add_argument("--train-frac", type=float, default=0.7)
    ap.add_argument("--budget", type=float, default=0.05)
    ap.add_argument("--plant", type=int, default=200, help="planted chain hours")
    ap.add_argument("--epochs-teacher", type=int, default=8)
    ap.add_argument("--epochs-student", type=int, default=10)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default=os.path.join(HERE, "real_baseline_eval.json"))
    a = ap.parse_args()

    src = HW.CorpusStore(a.corpus, create=False)
    info = src.summary()
    rows = [r[:5] for r in src.rows(include_flagged=True)]
    days = sorted({r[1] // W for r in rows})
    if len(days) < 4:
        sys.exit(f"{a.corpus}: only {len(days)} day(s) -- need at least 4 to split train/test")
    split = days[int(len(days) * a.train_frac)]
    print(f"corpus {a.corpus}: {info['host_days']} device-days, {info['hosts']} devices, "
          f"{len(days)} days ({info['first_day']} .. {info['last_day']})")
    print(f"train on {sum(1 for d in days if d < split)} days, replay {sum(1 for d in days if d >= split)} held-out days")

    tmp = tempfile.mkdtemp()
    train = HW.CorpusStore(os.path.join(tmp, "train.sqlite"), tz_offset=src.tz)
    train.put([r for r in rows if r[1] // W < split])
    empty = HW.CorpusStore(os.path.join(tmp, "live.sqlite"), tz_offset=src.tz)
    t0 = time.time()
    b = IL.train_bundle(train, empty, a.epochs_teacher, a.epochs_student, live_days=None,
                        seed=a.seed, exclude_today=False, log=lambda t: print("  " + t))
    train_s = time.time() - t0
    thr = b["thr"]

    test = [r for r in rows if r[1] // W >= split]
    by_day = defaultdict(list)
    for r in test:
        by_day[r[1] // W].append(r)
    rng = np.random.default_rng(a.seed)

    # candidate device-hours to plant into: active held-out hours
    active = sorted({(r[0], r[1]) for r in test})
    plant = set()
    if active and a.plant:
        idx = rng.choice(len(active), size=min(a.plant, len(active)), replace=False)
        plant = {active[i] for i in idx}

    scored = escalated = flagged = 0
    by_hour = defaultdict(lambda: [0, 0])          # hour -> [device-hours, flags]
    by_dev = defaultdict(lambda: [0, 0])
    p_esc = p_flag = 0
    for day in sorted(by_day):
        drows = by_day[day]
        for w in range(W):
            lh = day * W + w
            upto = [r for r in drows if r[1] <= lh]
            live_hosts = sorted({r[0] for r in upto if r[1] == lh})
            if not live_hosts:
                continue
            hosts = sorted({r[0] for r in upto})
            k = max(1, int(round(a.budget * len(live_hosts))))
            # benign replay
            _s, esc, errs, _c, _a, _b = IL.score_hour(b, hosts, upto, w, k)
            f = [h for h, e in errs.items() if e >= thr]
            scored += len(live_hosts); escalated += len(esc); flagged += len(f)
            by_hour[w][0] += len(live_hosts); by_hour[w][1] += len(f)
            for h in live_hosts:
                by_dev[h][0] += 1
            for h in f:
                by_dev[h][1] += 1
            # planted chains in this hour, one device at a time
            for h in live_hosts:
                if (h, lh) not in plant:
                    continue
                mixed = upto + chain_rows(h, lh, rng)
                _s2, esc2, errs2, _c2, _a2, _b2 = IL.score_hour(b, hosts, mixed, w, k)
                p_esc += h in esc2
                p_flag += errs2.get(h, 0) >= thr

    n_plant = len(plant)
    unk = info["categories"].get("Unknown_External", 0) / max(info["windows"], 1)
    res = {
        "corpus": info,
        "split": {"train_days": sum(1 for d in days if d < split),
                  "test_days": sum(1 for d in days if d >= split),
                  "first_test_day": HW._day_str(split)},
        "model": {"threshold": thr, "train_seconds": round(train_s, 1), **b["meta"]},
        "benign_heldout": {
            "device_hours": scored, "escalated": escalated, "flagged": flagged,
            "false_alarm_rate": flagged / max(scored, 1),
            "flags_by_hour_of_day": {f"{w:02d}": v[1] for w, v in sorted(by_hour.items())},
            "device_hours_by_hour_of_day": {f"{w:02d}": v[0] for w, v in sorted(by_hour.items())},
            "by_device": {h: {"device_hours": v[0], "flagged": v[1]} for h, v in sorted(by_dev.items())},
        },
        "planted_chain": {"hours": n_plant, "escalated": p_esc, "flagged": p_flag,
                          "escalation_recall": p_esc / max(n_plant, 1),
                          "detection_recall": p_flag / max(n_plant, 1),
                          "note": "chain windows are synthetic overlays on real held-out hours"},
        "data_quality": {"unknown_external_window_share": round(unk, 4),
                         "windows_per_device_day": round(info["windows"] / max(info["host_days"], 1), 1)},
        "budget": a.budget,
    }
    with open(a.out, "w") as fh:
        json.dump(res, fh, indent=1, default=float)

    print("\n" + "=" * 66)
    print(f"  held-out benign device-hours : {scored:,}")
    print(f"  flagged (false alarms)       : {flagged:,}  = {100 * res['benign_heldout']['false_alarm_rate']:.2f}%"
          f"  (~{flagged / max(res['split']['test_days'], 1):.1f} per day)")
    print(f"  planted chain hours          : {n_plant}")
    print(f"  ...escalated by the Sentry   : {p_esc}  = {100 * res['planted_chain']['escalation_recall']:.1f}%")
    print(f"  ...flagged by the Inspector  : {p_flag}  = {100 * res['planted_chain']['detection_recall']:.1f}%")
    print(f"  Unknown_External window share: {100 * unk:.1f}%   (resolver could not name the service)")
    print("=" * 66)
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
