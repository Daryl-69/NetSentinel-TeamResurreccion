#!/usr/bin/env python3
"""inject_demo.py -- detection on REAL captured traffic with an INJECTED chain.

    .\.venv\Scripts\python.exe inject_demo.py

WHAT IS REAL HERE AND WHAT IS NOT. Read this before you quote anything from it.

    REAL   the background traffic. Every byte count, flow count, inter-arrival
           time and duration in the untouched hours came off this machine's
           own NIC, parsed from D:\capture by real_probe.py. Nothing about the
           benign traffic is simulated.
    REAL   the model. The Inspector is commissioned on the early real hours,
           unsupervised, and its alert threshold is the 99th percentile of its
           own reconstruction error on those hours. Nothing is fitted to the
           attack.
    NOT    the adversary. There was no intrusion on this laptop. We inject a
           LOTS kill chain into the held-out hours and the exact injection is
           printed below, feature by feature, so anyone can check it.

Injecting a synthetic adversary into a real benign background is the standard
methodology when labelled egress data does not exist -- which, per DATASETS.md,
it does not. It is honest as long as it is stated. State it.

THE CONTROL IS THE POINT. We run three conditions through the same model:

    A  untouched real traffic          -> must stay quiet
    B  real traffic + a benign surge   -> must ALSO stay quiet (4x browsing)
    C  real traffic + the kill chain   -> should fire

A demo without B is worthless: any model can flag "something changed". B is
what separates "detects an attack" from "detects a difference".

>>> STATUS 2026-09-06: THIS SCRIPT DOES NOT PASS ITS OWN CONTROL YET.
>>> On the first 18 captured hours it flagged 5/5 benign-surge hours and 2/5
>>> untouched hours. It is detecting difference, not attack. The cause is the
>>> commissioning window: 11 hours where the design calls for 14 days, so the
>>> threshold and the standardisation are both fitted to almost nothing.
>>> DO NOT RUN THIS IN FRONT OF JUDGES until condition B comes back clean.
>>> Re-run it once the 12-day multi-host capture is in. If B still fires then,
>>> that is a real result about the model and it must be reported, not hidden.
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2.categories import CATEGORIES, CAT_INDEX, N_EDGE_FEATURES
from netsentinel_v2.synth import _edge_row
import netsentinel_v2.train as T

BAR = "=" * 76
RNG = np.random.default_rng(7)

# The chain, one step per hour, as it would appear in a real Monday afternoon.
# Every one of these services is legitimate and allow-listed.
CHAIN = [
    ("Recon_API",       "victim fingerprinting",   dict(n=4,   up=3.2e3,  down=9.5e3,  beacon=False)),
    ("Code_Repo_Paste", "stager pull from a gist", dict(n=6,   up=8.1e3,  down=2.4e5,  beacon=False)),
    ("Messaging_API",   "C2 poll (jittered)",      dict(n=61,  up=4.4e4,  down=3.1e4,  beacon=True)),
    ("Messaging_API",   "C2 poll (jittered)",      dict(n=58,  up=4.1e4,  down=2.9e4,  beacon=True)),
    ("Messaging_API",   "C2 poll (jittered)",      dict(n=64,  up=4.6e4,  down=3.3e4,  beacon=True)),
    ("Cloud_Storage",   "staged exfil upload",     dict(n=9,   up=1.9e7,  down=6.2e4,  beacon=False)),
]


def make_row(n, up, down, beacon):
    """Build one (host, category, hour) edge row the same way every other
    loader in this repo does -- through synth._edge_row, so the feature
    semantics cannot drift between the injected rows and the real ones."""
    if beacon:
        # A jittered beacon: 60s sleep, 30% jitter -> UNIFORM inter-arrivals.
        # This is the Jitter-Trap inversion. Uniform IATs are the signature.
        iats = RNG.uniform(60 * 0.7, 60 * 1.3, size=max(n - 1, 3))
        distinct = 0.05
        dur = 1.4
    else:
        iats = RNG.lognormal(mean=np.log(90.0), sigma=1.1, size=max(n - 1, 3))
        distinct = RNG.uniform(0.2, 0.6)
        dur = RNG.gamma(2, 4)
    return _edge_row(RNG, n, up, down, iats, distinct_ratio=distinct, dur_mean=dur)


def inject_chain(E, M, start_h, verbose=True):
    E, M = E.copy(), M.copy()
    rows = []
    for k, (cat, why, kw) in enumerate(CHAIN):
        w = start_h + k
        if w >= M.shape[2]:
            break
        ci = CAT_INDEX[cat]
        row = make_row(**kw)
        E[0, 0, w, ci] = row
        M[0, 0, w, ci] = 1.0
        rows.append((w, cat, why, kw, row))
    if verbose:
        print("\n  INJECTION SPEC -- this is the whole of what we added:")
        print(f"  {'hour':<6}{'category':<18}{'flows':>7}{'up':>12}{'down':>12}"
              f"{'iat_cv':>9}{'ks_unif':>9}")
        for w, cat, why, kw, row in rows:
            print(f"  {w:02d}:00 {cat:<18}{kw['n']:>7}{kw['up']:>12,.0f}"
                  f"{kw['down']:>12,.0f}{row[4]:>9.3f}{row[5]:>9.3f}"
                  f"   {why}")
        print("  Nothing else in the tensor is touched. No label is given to the model.")
    return E, M


def inject_benign_surge(E, M, start_h, factor=4.0):
    """CONTROL. Same hours, same magnitude of change, but it is ordinary
    browsing: existing categories, human log-normal timing, symmetric bytes.
    If this fires too, the model is detecting novelty, not a kill chain, and
    the demo has proved nothing."""
    E, M = E.copy(), M.copy()
    touched = []
    for k in range(len(CHAIN)):
        w = start_h + k
        if w >= M.shape[2]:
            break
        for cat in ("Browse", "Unknown_External", "Internal"):
            ci = CAT_INDEX[cat]
            if M[0, 0, w, ci] == 0:
                continue
            # recover the un-logged volumes, scale them, rebuild the row
            n = int(np.expm1(E[0, 0, w, ci, 0]) * factor)
            up = float(np.expm1(E[0, 0, w, ci, 1]) * factor)
            down = float(np.expm1(E[0, 0, w, ci, 2]) * factor)
            E[0, 0, w, ci] = make_row(max(n, 4), up, down, beacon=False)
            touched.append((w, cat, n))
    return E, M, touched


def score(insp, E, M, Co, mu, sd, lo, hi):
    flat = lambda X: X.reshape(-1, *X.shape[2:])
    Ef, Mf, Cf = flat(E)[:, lo:hi], flat(M)[:, lo:hi], flat(Co)[:, lo:hi]
    Ef, *_ = T.standardise(Ef, Mf, mu, sd)
    _, err = T.inspector_forward(insp, Ef, Mf, Cf)
    live = (Mf.sum(-1) > 0)
    return err[0], live[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tensor", default="real_capture.npz",
                    help="cached tensor written by real_probe.py")
    ap.add_argument("--epochs", type=int, default=14)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    if not os.path.exists(a.tensor):
        print(f"no {a.tensor}. Build it first:")
        print(r"   .\.venv\Scripts\python.exe real_probe.py --dir D:\capture --no-train")
        print(r"   (parses the pcaps once and writes real_capture.npz; a few minutes)")
        return 1

    d = np.load(a.tensor)
    E, M, n_h = d["E"], d["M"], int(d["n_h"])
    H, D, W, C, F = E.shape

    print(BAR)
    print("  NETSENTINEL  --  REAL CAPTURE, INJECTED CHAIN, WITH A CONTROL")
    print(BAR)
    print(f"  background   this machine's own traffic, {n_h} captured hours")
    print( "  adversary    injected by us, printed in full below")
    print( "  model        commissioned unsupervised on the early real hours")

    cut = int(n_h * 0.66)
    inj_at = cut
    print(f"\n  commissioning  hours 00-{cut-1}   (real, untouched)")
    print(f"  evaluation     hours {cut:02d}-{n_h-1}   (real, then modified)")

    live_all = (M.sum(-1) > 0)[0, 0]
    present = [c for i, c in enumerate(CATEGORIES) if (M[..., i] > 0).any()]
    print(f"  categories present in the real background: {', '.join(present)}")

    Co = T.compute_cohort(E, M)
    flat = lambda X: X.reshape(-1, *X.shape[2:])
    Ec, Mc, Cc = flat(E)[:, :cut], flat(M)[:, :cut], flat(Co)[:, :cut]
    Ec_s, mu, sd = T.standardise(Ec, Mc)

    print("\n  commissioning the Inspector on real traffic ...", flush=True)
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        insp = T.train_inspector(Ec_s, Mc, Cc, epochs=a.epochs, seed=a.seed)
    _, err_c = T.inspector_forward(insp, Ec_s, Mc, Cc)
    thr = float(np.quantile(err_c[0][(Mc.sum(-1) > 0)[0]], 0.99))
    print(f"  alert threshold = 99th pct of its own commissioning error = {thr:.4f}")

    # ---- three conditions, one model ------------------------------------
    errA, liveA = score(insp, E, M, Co, mu, sd, cut, n_h)

    Eb, Mb, touched = inject_benign_surge(E, M, inj_at)
    Cob = T.compute_cohort(Eb, Mb)
    errB, liveB = score(insp, Eb, Mb, Cob, mu, sd, cut, n_h)

    Ei, Mi = inject_chain(E, M, inj_at)
    Coi = T.compute_cohort(Ei, Mi)
    errC, liveC = score(insp, Ei, Mi, Coi, mu, sd, cut, n_h)

    print(f"\n  CONTROL: benign surge -- {len(touched)} existing category-hours "
          f"scaled 4x with human timing")

    print("\n" + BAR)
    print("  RECONSTRUCTION ERROR PER HOUR   (threshold %.4f)" % thr)
    print(BAR)
    print(f"  {'hour':<8}{'A untouched':>14}{'B benign 4x':>15}"
          f"{'C kill chain':>15}   what C added")
    hits = {"A": 0, "B": 0, "C": 0}
    nlive = 0
    for i in range(n_h - cut):
        w = cut + i
        if not liveA[i]:
            continue
        nlive += 1
        step = CHAIN[i][0] if i < len(CHAIN) else "-"
        mk = lambda e: ("%8.4f %s" % (e, "FLAG" if e >= thr else "    "))
        hits["A"] += errA[i] >= thr
        hits["B"] += errB[i] >= thr
        hits["C"] += errC[i] >= thr
        print(f"  {w:02d}:00 {mk(errA[i]):>16}{mk(errB[i]):>16}{mk(errC[i]):>16}"
              f"   {step}")

    print("\n" + BAR)
    print("  RESULT")
    print(BAR)
    for k, label in (("A", "untouched real traffic  "),
                     ("B", "real + 4x benign surge  "),
                     ("C", "real + injected chain   ")):
        n = int(hits[k])
        verdict = ("correctly quiet" if k in "AB" and n == 0 else
                   "DETECTED" if k == "C" and n else
                   "FALSE POSITIVE" if k in "AB" else "MISSED")
        print(f"  {label}  {n}/{nlive} hours flagged   {verdict}")

    ok = hits["A"] == 0 and hits["B"] == 0 and hits["C"] > 0
    print("\n  " + ("PASS -- fires on the chain, silent on the surge."
                    if ok else
                    "NOT A CLEAN PASS -- read the table above, do not spin it."))

    print("\n" + BAR)
    print("  SAY THIS, EXACTLY")
    print(BAR)
    print("  The background is real traffic captured on this machine.")
    print("  The adversary is injected by us and the injection is printed above.")
    print("  Condition B is the control: the same magnitude of change, benign.")
    print()
    print("  This is the EASY case -- the chain uses categories this host had")
    print("  never touched during commissioning. The HARD case is a compromised")
    print("  developer who already uses all four legitimately; that is what")
    print("  demo_scenario.py tests, and it is why that one has hard negatives.")
    print()
    print("  On real red-team data (LANL) our within-host AUC is 0.557 +/- 0.013.")
    print("  We do not claim a detection rate yet. We claim the cascade, measured.")
    print(BAR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
