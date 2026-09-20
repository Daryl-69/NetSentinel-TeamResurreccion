#!/usr/bin/env python3
"""
ci_report.py -- what the "+/-" in every table actually is, and what a real
confidence interval would be.

WHY THIS EXISTS.
Every seeded figure in this project is written `mean +/- sd`, and every script
that produced one used `np.std(...)` -- the POPULATION standard deviation. At
n = 3 seeds that understates the sample standard deviation by sqrt(2/3), about
18%. Worse, a reader sees "+/-" and reads "confidence interval", which it is
not: with 3 seeds a 95% interval is 2.48 sample sd wide, roughly three times
the number printed.

Nothing here is a correction to a mean. The means are right and re-derived by
verify_all.py. This is a correction to how much certainty the +/- implies, and
it makes the project's own headline weakness -- within-host AUC 0.557 -- read
MORE honestly, not less: its 95% interval reaches down to 0.517, which is
chance.

Usage:  python ci_report.py
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)


def load(f):
    return json.load(open(f, encoding="utf-8"))


def series():
    """(label, source file, values-across-seeds). Every one read from a .json
    on disk -- nothing is typed in from a document."""
    out = []
    if os.path.exists("lanl_novelty.json"):
        R = load("lanl_novelty.json")["runs"]
        out += [
            ("within-host AUC, LANL", "lanl_novelty.json",
             [r["oracle"]["within_host_auc_mean"] for r in R]),
            ("pooled AUC, LANL", "lanl_novelty.json",
             [r["oracle"]["auc_vs_attack_window"] for r in R]),
            ("router A agreement", "lanl_novelty.json",
             [r["router_auc"]["A_distilled_detector"] for r in R]),
            ("router B agreement", "lanl_novelty.json",
             [r["router_auc"]["B_encoder_mahalanobis"] for r in R]),
        ]
    if os.path.exists("lanl_novelty_hn.json"):
        R = load("lanl_novelty_hn.json")["runs"]
        out += [("pooled AUC, host-normalised", "lanl_novelty_hn.json",
                 [r["oracle"]["auc_vs_attack_window"] for r in R])]
    if os.path.exists("paired_synth.json"):
        R = load("paired_synth.json")["runs"]
        out += [
            ("within-host, synthetic Inspector", "paired_synth.json",
             [r["within_inspector"] for r in R]),
            ("within-host, synthetic bag", "paired_synth.json",
             [r["within_bag"] for r in R]),
        ]
    # The 8-seed router comparison. Included because it is the clearest case
    # in the project of a "ranking" that three seeds invented: at eight seeds
    # the three intervals sit on top of each other.
    if os.path.exists("results_8seed.json"):
        R = load("results_8seed.json")["runs"]
        for k, nm in (("A_distilled_detector", "router A, synthetic"),
                      ("B_encoder_mahalanobis", "router B, synthetic"),
                      ("C_deferral_head", "router C, synthetic")):
            out += [(nm, "results_8seed.json",
                     [r["router_auc_vs_teacher"][k] for r in R])]
    return out


def main():
    rows = []
    for label, src, v in series():
        v = np.asarray(v, dtype=float)
        n = len(v)
        sd_pop = float(v.std())                 # what the documents print
        sd_smp = float(v.std(ddof=1))           # the unbiased estimate
        half = float(stats.t.ppf(0.975, n - 1) * sd_smp / np.sqrt(n))
        rows.append(dict(label=label, source=src, n=n, mean=float(v.mean()),
                         sd_population=sd_pop, sd_sample=sd_smp,
                         ci95_lo=float(v.mean() - half),
                         ci95_hi=float(v.mean() + half)))

    print("=" * 78)
    print("  What the +/- means, and what a 95% interval would be")
    print("=" * 78)
    print(f"  {'quantity':34s}{'mean':>7}{'+/- printed':>13}{'sample sd':>11}"
          f"{'95% CI':>18}")
    for r in rows:
        print(f"  {r['label']:34s}{r['mean']:>7.3f}{r['sd_population']:>13.3f}"
              f"{r['sd_sample']:>11.3f}   [{r['ci95_lo']:.3f}, {r['ci95_hi']:.3f}]")

    n = rows[0]["n"] if rows else 3
    fac = float(np.sqrt((n - 1) / n))
    mult = float(stats.t.ppf(0.975, n - 1) / np.sqrt(n))
    print()
    print(f"  At n = {n} seeds (the majority of rows; the router rows use 8):")
    print(f"    the printed +/- is the POPULATION sd -- {fac:.3f} x the sample sd")
    print(f"    a 95% interval is {mult:.2f} x the sample sd, not 1 x")
    print()
    print("  Read the consequences, not the table:")
    for r in rows:
        if r["ci95_lo"] < 0.60:
            print(f"    - {r['label']}: interval reaches down to "
                  f"{r['ci95_lo']:.3f}, {r['ci95_lo'] - 0.5:+.3f} from chance")
    for r in rows:
        if r["ci95_hi"] > 1.0:
            print(f"    - {r['label']}: the interval runs past 1.000, which an "
                  f"AUC cannot\n      reach. A symmetric t-interval ignores the "
                  f"bound; read it as [{r['ci95_lo']:.3f}, 1.000].")
    # overlap of the two synthetic arms -- the paired test already says p=0.46,
    # and the intervals should agree with it rather than contradict it.
    a = next((r for r in rows if r["label"].endswith("synthetic Inspector")), None)
    b = next((r for r in rows if r["label"].endswith("synthetic bag")), None)
    if a and b:
        ov = min(a["ci95_hi"], b["ci95_hi"]) - max(a["ci95_lo"], b["ci95_lo"])
        print(f"    - synthetic Inspector [{a['ci95_lo']:.3f}, {a['ci95_hi']:.3f}] and "
              f"bag [{b['ci95_lo']:.3f}, {b['ci95_hi']:.3f}]")
        # Read the p-value rather than typing it: an earlier version of this
        # line hard-coded 0.46, and by the time the file was re-run the true
        # value was 0.51. A narrative in code that does not measure what it
        # asserts will keep asserting it.
        pv = load("paired_synth.json").get("pooled_sign_test_p") \
            if os.path.exists("paired_synth.json") else None
        tail = f"(p = {pv:.2f})" if pv is not None else "(see paired_synth.json)"
        print(f"      overlap by {ov:.3f} AUC -- consistent with the sign test "
              f"{tail}, not a separate finding")

    print()
    print("  NOTHING HERE CHANGES A MEAN. The convention stays np.std() so that")
    print("  every table in every document agrees with every script. What must")
    print("  travel with those tables is this sentence: the +/- is a spread over")
    print("  3 seeds, not a confidence interval.")

    json.dump(dict(n_seeds=n, sd_convention="population (np.std, ddof=0)",
                   pop_over_sample=fac, ci95_multiplier_on_sample_sd=mult,
                   rows=rows),
              open("ci_report.json", "w"), indent=2)
    print("\n  wrote ci_report.json")


if __name__ == "__main__":
    sys.exit(main())
