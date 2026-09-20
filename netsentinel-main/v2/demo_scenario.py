#!/usr/bin/env python3
"""LIVE CASCADE DEMO -- the whole Inspector/Sentry loop, end to end, in ~1 minute.

    python demo_scenario.py

What it does, in order, printing as it goes:

    1. Builds a synthetic organisation -- developers, office staff, kiosks, OT
       panels, servers -- with realistic working hours and weekends. A few hosts
       are compromised and walk a LOTS kill chain:
           Recon_API -> Code_Repo_Paste -> Messaging_API (beacon) -> Cloud_Storage
       Crucially it ALSO generates DevOps hard negatives: legitimate developers
       walking the SAME four categories with human timing. Without those the
       experiment is trivially easy and the result is worthless.
    2. COMMISSIONING -- the Inspector learns "normal", unsupervised, never
       seeing an attack label. The alert threshold is the 99th percentile of its
       own commissioning reconstruction error.
    3. DISTILLATION -- the Sentry learns the Inspector's *encoder* (not its
       verdict), 205,546 -> 14,992 parameters.
    4. STEADY STATE -- the Sentry alone scores every window on CPU.
    5. ESCALATION -- the top 5% by Sentry score go BACK to the Inspector, which
       re-runs on only those host-days and returns the verdict.

>>> HONESTY: this is a SYNTHETIC environment. It demonstrates that the cascade
>>> mechanism works end to end and that escalation recovers the teacher's
>>> judgement at a fraction of the cost. The attack-recall figure it prints is
>>> INDICATIVE ONLY -- a detector evaluated on the generator that made its
>>> attacks partly learns the generator. The real-traffic numbers are in
>>> lanl_novelty.json, and the honest verdict there is within-host AUC
>>> 0.557 +/- 0.013. Never quote this script's recall as a real detection rate.
"""
from __future__ import annotations

try:
    import numpy, scipy, sklearn, torch          # noqa: F401
except ImportError as _e:                        # pragma: no cover
    import sys
    print("Missing dependency: %s" % _e.name)
    print(r"   .\.venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cpu")
    print(r"   .\.venv\Scripts\python.exe -m pip install numpy scipy scikit-learn")
    sys.exit(1)

import argparse, time
import numpy as np

from netsentinel_v2 import synth, train as T
from netsentinel_v2.categories import CATEGORIES
from run_experiment import roc_auc, count_params

BAR = "=" * 72
CHAIN = ["Recon_API", "Code_Repo_Paste", "Messaging_API", "Cloud_Storage"]


def head(n, total, title):
    print(f"\n[{n}/{total}] {title}", flush=True)
    print("      " + "-" * (len(title) + 2), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=150)
    ap.add_argument("--days", type=int, default=24)
    ap.add_argument("--budget", type=float, default=0.05)
    ap.add_argument("--epochs-teacher", type=int, default=14)
    ap.add_argument("--epochs-student", type=int, default=16)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--quiet", action="store_true", help="hide per-epoch loss")
    ap.add_argument("--fast", action="store_true",
                    help="~20s instead of ~45s: fewer hosts/epochs. Numbers "
                         "come out lower -- use it to rehearse, not to quote.")
    a = ap.parse_args()
    if a.fast:
        a.hosts, a.days, a.epochs_teacher, a.epochs_student = 60, 16, 8, 10
    t_all = time.time()

    print(BAR)
    print("  NETSENTINEL  --  LIVE INSPECTOR/SENTRY CASCADE")
    print("  synthetic environment  |  every stage runs for real, now")
    print(BAR)

    # ---------------------------------------------------------------- 1
    head(1, 5, "BUILD THE ORGANISATION")
    d = synth.generate(n_hosts=a.hosts, n_days=a.days, seed=a.seed)
    E, M, A = d["edges"], d["mask"], d["is_attack_day"]
    roles = d["roles"]
    H, D, W, C, F = E.shape
    comp = int(A.any(axis=1).sum())
    uniq, cnt = np.unique(roles, return_counts=True)
    print(f"      {H} hosts x {D} days x {W} one-hour windows")
    print("      roles      : " + ", ".join(f"{u} x{c}" for u, c in zip(uniq, cnt)))
    print(f"      compromised: {comp} host(s), activating AFTER commissioning")
    print(f"      kill chain : {' -> '.join(CHAIN)}")
    devs = int((roles == "developer").sum())
    print(f"      hard negatives: {devs} developer host(s) walk that SAME")
    print("                      category sequence legitimately, human-timed")

    c_end, v_start = D // 2, int(D * 0.66)
    print(f"      commissioning days 0-{c_end-1}   |   evaluated days {v_start}-{D-1}")

    Co = T.compute_cohort(E, M)
    flat = lambda X, x, y: X[:, x:y].reshape(-1, *X.shape[2:])
    Ec, Mc, Cc = flat(E, 0, c_end), flat(M, 0, c_end), flat(Co, 0, c_end)
    Et, Mt, Ct = flat(E, v_start, D), flat(M, v_start, D), flat(Co, v_start, D)
    hc = np.repeat(np.arange(H), c_end)
    ht = np.repeat(np.arange(H), D - v_start)
    Ec, mu, sd = T.standardise(Ec, Mc)
    Et, *_ = T.standardise(Et, Mt, mu, sd)

    # ---------------------------------------------------------------- 2
    head(2, 5, "COMMISSIONING  --  the Inspector learns 'normal'")
    print("      unsupervised denoising autoencoder; NO attack labels are used")
    t0 = time.time()
    import contextlib, io
    buf = io.StringIO()
    with (contextlib.redirect_stdout(buf) if a.quiet else contextlib.nullcontext()):
        insp = T.train_inspector(Ec, Mc, Cc, epochs=a.epochs_teacher, seed=a.seed)
    Zc, Ec_err = T.inspector_forward(insp, Ec, Mc, Cc)
    thr = float(np.quantile(Ec_err, 0.99))
    print(f"      trained on {Ec.shape[0]} host-days in {time.time()-t0:.0f}s")
    print(f"      alert threshold = 99th pct of its own error = {thr:.4f}")

    # ---------------------------------------------------------------- 3
    head(3, 5, "DISTILLATION  --  the Sentry learns the Inspector's EYES")
    t0 = time.time()
    buf = io.StringIO()
    with (contextlib.redirect_stdout(buf) if a.quiet else contextlib.nullcontext()):
        sen = T.train_sentry(Ec, Mc, Zc, Ec_err, epochs=a.epochs_student, seed=a.seed)
    Zc_s = T.sentry_forward(sen, Ec, Mc)
    headA = T.train_head(Zc_s, (Ec_err / (thr + 1e-9)).astype(np.float32),
                         loss="mse", seed=a.seed)
    pi, ps = count_params(insp), count_params(sen)
    print(f"      {pi:,} -> {ps:,} parameters  ({pi/ps:.1f}x smaller)  "
          f"in {time.time()-t0:.0f}s")
    print("      the ENCODER is distilled, never the verdict")

    # ---------------------------------------------------------------- 4
    head(4, 5, "STEADY STATE  --  Sentry alone, CPU, every window")
    t0 = time.time()
    Zt_s = T.sentry_forward(sen, Et, Mt)
    sA = T.head_forward(headA, Zt_s)
    t_sentry = time.time() - t0
    live = (Mt.sum(-1) > 0)
    lf = live.reshape(-1)
    n_live = int(lf.sum())
    print(f"      scored {n_live:,} live windows in {t_sentry:.2f}s "
          f"({n_live/max(t_sentry,1e-9):,.0f} windows/s)")

    # rank-based escalation
    order = np.argsort(-sA.reshape(-1)[lf])
    k = max(1, int(round(a.budget * n_live)))
    esc_flat = np.zeros(n_live, dtype=bool); esc_flat[order[:k]] = True
    esc = np.zeros(sA.shape, dtype=bool); esc.reshape(-1)[np.where(lf)[0]] = esc_flat
    esc_rows = np.where(esc.any(axis=1))[0]
    print(f"      escalation budget {a.budget*100:.0f}%  ->  {k:,} windows "
          f"on {len(esc_rows):,} host-days go BACK to the Inspector")

    # ---------------------------------------------------------------- 5
    head(5, 5, "ESCALATION  --  the Inspector re-runs, on those only")
    t0 = time.time()
    _, err_esc = T.inspector_forward(insp, Et[esc_rows], Mt[esc_rows], Ct[esc_rows])
    t_partial = time.time() - t0
    t0 = time.time()
    _, Et_err = T.inspector_forward(insp, Et, Mt, Ct)
    t_full = time.time() - t0
    flag = Et_err >= thr
    confirmed = int((err_esc[esc[esc_rows]] >= thr).sum())
    saved = (1 - len(esc_rows) / max(Et.shape[0], 1)) * 100
    print(f"      Inspector re-ran on {len(esc_rows):,}/{Et.shape[0]:,} host-days "
          f"({saved:.0f}% of them never woke it up)")
    print(f"      of the {k:,} escalated windows it CONFIRMED {confirmed:,} as anomalous")
    print(f"      wall clock here {t_partial:.2f}s vs {t_full:.2f}s for everything -- "
          "a weak saving")
    print("      because on this laptop BOTH models are small CPU tensors. The "
          "saving that")
    print("      matters is the host-day count above: in the field the Inspector "
          "is the GPU")
    print("      model and the Sentry is the only thing that has to keep up with "
          "the wire.")

    # ---------------------------------------------------------------- results
    atk = (np.repeat(A[:, v_start:D].reshape(-1)[:, None], W, 1) & live)
    n_atk = int(atk.reshape(-1)[lf].sum())
    caught = int((esc & atk).sum())
    rec_teacher = float(esc.reshape(-1)[lf][flag.reshape(-1)[lf]].mean()) if flag.any() else float("nan")
    auc_router = roc_auc(sA.reshape(-1)[lf], flag.reshape(-1)[lf])

    print("\n" + BAR)
    print("  RESULT")
    print(BAR)
    print(f"  Sentry agreement with the Inspector (AUC)   {auc_router:.3f}")
    print(f"  Inspector flags recovered at {a.budget*100:.0f}% budget       "
          f"{rec_teacher*100:5.1f}%")
    print(f"  Host-days the Inspector never had to see    "
          f"{(1-len(esc_rows)/max(Et.shape[0],1))*100:5.1f}%")
    print(f"  Model size                                  {pi:,} -> {ps:,}"
          f"  ({pi/ps:.1f}x)")
    if n_atk:
        print(f"  Attack windows present in the test period   {n_atk}")
        print(f"    reached the Inspector via escalation      {caught}"
              f"  ({caught/n_atk*100:.0f}%)   <-- INDICATIVE ONLY, synthetic")

    # -------------------------------------------------- chain reconstruction
    # Pick the host-day that best DEMONSTRATES the mechanism, not merely the
    # highest-scoring one. A compromised developer also generates his own
    # legitimate Cloud_Storage and Code_Repo traffic, so the first sighting of
    # each category is often out of order and the walkthrough reads as noise.
    # Rank by how far the canonical chain is walked IN ORDER; break ties on
    # score. Nothing here changes a metric -- it only chooses which row to show.
    def in_order_progress(row):
        step, first_hour = 0, {}
        for w in range(W):
            for c in range(C):
                if Mt[row, w, c] > 0 and CATEGORIES[c] == CHAIN[step]:
                    first_hour[CHAIN[step]] = w
                    step += 1
                    if step == len(CHAIN):
                        return step, first_hour
                    break
        return step, first_hour

    atk_rows = np.where(atk.any(axis=1) & esc.any(axis=1))[0]
    if len(atk_rows):
        prog = [in_order_progress(int(x))[0] for x in atk_rows]
        best = max(prog)
        cand = atk_rows[np.array(prog) == best]
        r = int(cand[int(np.argmax(sA[cand].max(axis=1)))])
        step_hour = in_order_progress(r)[1]
        h, dd = int(ht[r]), v_start + int(r % (D - v_start))
        print("\n" + BAR)
        print(f"  KILL-CHAIN RECONSTRUCTION  --  host {h:03d} ({roles[h]}), day {dd}")
        print(BAR)
        print("   hour   categories touched" + " " * 34 + "sentry   action")
        marks = {w: i for i, (cn, w) in enumerate(step_hour.items())}
        for w in range(W):
            cats = [CATEGORIES[c] for c in range(C) if Mt[r, w, c] > 0]
            if not cats:
                continue
            mark = ""
            if w in marks:
                mark = "  <-- chain step %d/4: %s" % (marks[w] + 1, CHAIN[marks[w]])
            act = "ESCALATED" if esc[r, w] else "         "
            txt = ", ".join(cats)
            if len(txt) > 50:
                txt = txt[:47] + "..."
            print(f"   {w:02d}:00  {txt:<52s}{sA[r,w]:6.2f}   {act}{mark}")
        walked = list(step_hour.keys())
        print(f"\n   canonical chain walked in order: {' -> '.join(walked)}"
              f"   ({best}/4 steps)")
        print("   Every one of those services is legitimate and allow-listed.")
        print("   No payload was inspected: the COMBINATION of categories and the")
        print("   machine-like shape of the traffic is what was scored.")
        print("   (We print the chain in order because it reads clearly. Do NOT")
        print("    claim the order is what the model used -- ablation_order.py")
        print("    shows permuting the hours changes the score by 0.000 AUC.)")

    print("\n" + BAR)
    print("  SYNTHETIC ENVIRONMENT -- the mechanism is real, the adversary is not.")
    print("  Real-traffic result: LANL cyber1, 612 hosts x 13 days, 3 seeds,")
    print("  within-host AUC 0.557 +/- 0.013 (chance). See lanl_novelty.json.")
    print(f"  total runtime {time.time()-t_all:.0f}s")
    print(BAR)


if __name__ == "__main__":
    main()
