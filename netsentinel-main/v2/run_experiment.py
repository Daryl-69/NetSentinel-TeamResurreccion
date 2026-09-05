#!/usr/bin/env python3
"""Run the full V2 experiment and emit results.json.

  python run_experiment.py --seeds 3 --hosts 300 --days 24
"""
from __future__ import annotations

# --- dependency guard -------------------------------------------------------
# A bare "ModuleNotFoundError: numpy" from a venv that was created but never
# populated is a confusing first thing to hit. Say what to run instead.
try:
    import numpy, scipy, sklearn, torch          # noqa: F401
except ImportError as _e:                        # pragma: no cover
    import sys
    print("Missing dependency: %s" % _e.name)
    print("")
    print("This virtualenv has no packages yet. Install them:")
    print("")
    print(r"   .\.venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cpu")
    print(r"   .\.venv\Scripts\python.exe -m pip install numpy scipy scikit-learn matplotlib")
    print("")
    print("(the CPU torch index keeps the download near 200MB instead of ~2.5GB)")
    sys.exit(1)
# ---------------------------------------------------------------------------

import argparse, json, time, sys
import numpy as np
import torch

from netsentinel_v2 import synth, train as T, cost_model
from netsentinel_v2.baseline import HostBaseline
from netsentinel_v2.diagnostics import geometry_report, verdict

BUDGETS = [0.005, 0.01, 0.02, 0.03, 0.05, 0.075, 0.10, 0.15, 0.20, 0.30]


def count_params(m):
    return sum(p.numel() for p in m.parameters())


def roc_auc(score, label):
    from sklearn.metrics import roc_auc_score
    label = np.asarray(label).astype(bool)
    if label.all() or not label.any():
        return float("nan")
    return float(roc_auc_score(label, np.asarray(score, dtype=np.float64)))


def run_seed(seed, hosts, days, epochs_t, epochs_s, stealth_range, verbose=True):
    t0 = time.time()
    d = synth.generate(n_hosts=hosts, n_days=days, seed=seed,
                       stealth_range=stealth_range)
    E, M, A = d["edges"], d["mask"], d["is_attack_day"]
    H, D, W, C, F = E.shape

    Co = T.compute_cohort(E, M)

    # ---- strictly monotonic temporal split (no random splits) -------------
    c_end, v_end = D // 2, int(D * 0.66)
    sl = lambda a, b: (slice(None), slice(a, b))
    flat = lambda X, a, b: X[:, a:b].reshape(-1, *X.shape[2:])
    hidx = lambda a, b: np.repeat(np.arange(H), b - a)

    Ec, Mc, Cc = flat(E, 0, c_end), flat(M, 0, c_end), flat(Co, 0, c_end)
    Ev, Mv, Cv = flat(E, c_end, v_end), flat(M, c_end, v_end), flat(Co, c_end, v_end)
    Et, Mt, Ct = flat(E, v_end, D), flat(M, v_end, D), flat(Co, v_end, D)
    hv, ht = hidx(c_end, v_end), hidx(v_end, D)
    hc = hidx(0, c_end)

    Ec, mu, sd = T.standardise(Ec, Mc)
    Ev, *_ = T.standardise(Ev, Mv, mu, sd)
    Et, *_ = T.standardise(Et, Mt, mu, sd)

    if verbose:
        print(f"[seed {seed}] commissioning {Ec.shape[0]} host-days | "
              f"val {Ev.shape[0]} | test {Et.shape[0]}", flush=True)

    # ---- Inspector --------------------------------------------------------
    insp = T.train_inspector(Ec, Mc, Cc, epochs=epochs_t, seed=seed)
    Zc_t, Ec_err = T.inspector_forward(insp, Ec, Mc, Cc)
    Zv_t, Ev_err = T.inspector_forward(insp, Ev, Mv, Cv)
    Zt_t, Et_err = T.inspector_forward(insp, Et, Mt, Ct)

    # Teacher's decision, calibrated on COMMISSIONING only.
    thr_t = float(np.quantile(Ec_err, 0.99))
    flag_v, flag_t = Ev_err >= thr_t, Et_err >= thr_t

    # ---- Sentry (encoder distillation only) -------------------------------
    sen = T.train_sentry(Ec, Mc, Zc_t, Ec_err, epochs=epochs_s, seed=seed)
    Zc_s = T.sentry_forward(sen, Ec, Mc)
    Zv_s = T.sentry_forward(sen, Ev, Mv)
    Zt_s = T.sentry_forward(sen, Et, Mt)

    # Windows with no traffic at all carry no decision and must not be scored;
    # including them inflates every recall number at high budget.
    live_t = (Mt.sum(-1) > 0)
    live_v = (Mv.sum(-1) > 0)

    # ---- per-host baselines in student space (G3/G4, trimmed) -------------
    # Fit on LIVE commissioning windows only. An empty window carries no
    # decision; including them puts a zero-variance spike in the baseline and
    # collapses the distance distribution into a mass of ties.
    live_c = (Mc.sum(-1) > 0)
    bl = {}
    for h in range(H):
        rows = np.where(hc == h)[0]
        Z = Zc_s[rows].reshape(-1, Zc_s.shape[-1])
        lv = live_c[rows].reshape(-1)
        err = Ec_err[rows].reshape(-1)
        if lv.sum() >= 20:
            Z, err = Z[lv], err[lv]
        bl[h] = HostBaseline(n_components=3, trim_frac=0.05).fit(Z, err)

    def maha(Z, hidx_):
        out = np.zeros(Z.shape[:2], dtype=np.float32)
        for h in np.unique(hidx_):
            r = np.where(hidx_ == h)[0]
            out[r] = bl[h].score(Z[r].reshape(-1, Z.shape[-1])).reshape(len(r), -1)
        return np.nan_to_num(out, nan=0.0, posinf=0.0, neginf=0.0)

    Mv_d, Mt_d = maha(Zv_s, hv), maha(Zt_s, ht)
    Mc_d = maha(Zc_s, hc)

    # ---- Router A: distilled DETECTOR (the original design) ---------------
    headA = T.train_head(Zc_s, (Ec_err / (thr_t + 1e-9)).astype(np.float32),
                         loss="mse", seed=seed)
    sA_t = T.head_forward(headA, Zt_s)

    # ---- Router B: encoder + Mahalanobis (V2_HARDENING B1) ----------------
    sB_t = Mt_d

    # ---- Router C: deferral head (V2_HARDENING G5) ------------------------
    # label is free: during commissioning we ran BOTH models.
    yC = (Ec_err >= thr_t).astype(np.float32)
    extra_c = np.stack([Mc_d, np.log1p(Mc_d), Mc.sum(-1)], -1).astype(np.float32)
    extra_t = np.stack([Mt_d, np.log1p(Mt_d), Mt.sum(-1)], -1).astype(np.float32)
    headC = T.train_head(Zc_s, yC, extra=extra_c, loss="bce", seed=seed)
    sC_t = T.head_forward(headC, Zt_s, extra_t)

    # ---- attack labels (indicative only -- synthetic) ---------------------
    atk_day = A[:, v_end:D].reshape(-1)
    atk_win = np.repeat(atk_day[:, None], W, axis=1) & live_t

    # ---- G1 diagnostic on LIVE windows only -------------------------------
    lf = live_t.reshape(-1)
    geo = geometry_report(Zt_t.reshape(-1, Zt_t.shape[-1])[lf],
                          Zt_s.reshape(-1, Zt_s.shape[-1])[lf],
                          Et_err.reshape(-1)[lf],
                          sA_t.reshape(-1)[lf])
    v_code, v_msg = verdict(geo)

    # ---- Is the ORACLE any good? If the Inspector cannot separate attacks,
    # every agreement number below is agreement with noise. Report it first.
    teach_auc = roc_auc(Et_err.reshape(-1)[lf], atk_win.reshape(-1)[lf])

    sel = lambda s: s.reshape(-1)[lf]
    curves = {
        "A_distilled_detector":  T.budget_curve(sel(sA_t), sel(flag_t), sel(atk_win), BUDGETS),
        "B_encoder_mahalanobis": T.budget_curve(sel(sB_t), sel(flag_t), sel(atk_win), BUDGETS),
        "C_deferral_head":       T.budget_curve(sel(sC_t), sel(flag_t), sel(atk_win), BUDGETS),
    }
    router_auc = {
        "A_distilled_detector":  roc_auc(sel(sA_t), sel(flag_t)),
        "B_encoder_mahalanobis": roc_auc(sel(sB_t), sel(flag_t)),
        "C_deferral_head":       roc_auc(sel(sC_t), sel(flag_t)),
    }

    res = dict(
        seed=seed, geometry=geo, verdict=[v_code, v_msg], curves=curves,
        router_auc_vs_teacher=router_auc,
        teacher_auc_vs_attack=teach_auc,
        params=dict(inspector=count_params(insp), sentry=count_params(sen),
                    deferral_head=count_params(headC),
                    compression=count_params(insp) / max(count_params(sen), 1)),
        teacher_flag_rate_test=float(sel(flag_t).mean()),
        attack_window_rate_test=float(sel(atk_win).mean()),
        live_window_frac=float(lf.mean()),
        runtime_s=time.time() - t0,
    )
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--hosts", type=int, default=300)
    ap.add_argument("--days", type=int, default=24)
    ap.add_argument("--epochs-teacher", type=int, default=14)
    ap.add_argument("--epochs-student", type=int, default=16)
    ap.add_argument("--stealth-max", type=float, default=1.0)
    ap.add_argument("--device", default="cpu", help="cpu | cuda")
    ap.add_argument("--out", default="results.json")
    a = ap.parse_args()
    T.set_device(a.device)

    runs = [run_seed(s, a.hosts, a.days, a.epochs_teacher, a.epochs_student,
                     (0.0, a.stealth_max)) for s in range(a.seeds)]

    # aggregate (multi-seed mean +/- std, per the benchmark protocol)
    agg = {}
    for router in runs[0]["curves"]:
        agg[router] = []
        for i, b in enumerate(BUDGETS):
            rt = [r["curves"][router][i]["recall_teacher"] for r in runs]
            ra = [r["curves"][router][i]["recall_attack"] for r in runs]
            agg[router].append(dict(
                budget=b,
                recall_teacher_mean=float(np.mean(rt)), recall_teacher_std=float(np.std(rt)),
                recall_attack_mean=float(np.nanmean(ra)), recall_attack_std=float(np.nanstd(ra))))

    cost, cost_txt = cost_model.summarise()
    geo_mean = {k: float(np.mean([r["geometry"][k] for r in runs]))
                for k in runs[0]["geometry"]}
    # verdict from the MEAN across seeds, not seed 0
    v_code, v_msg = verdict(geo_mean)

    # lift over random routing -- the number that says whether routing works
    best = max(agg, key=lambda r: agg[r][BUDGETS.index(0.05)]["recall_teacher_mean"])
    lift = {f"{b:.3f}": {r: (agg[r][i]["recall_teacher_mean"] / b) for r in agg}
            for i, b in enumerate(BUDGETS)}

    out = dict(runs=runs, aggregate=agg, budgets=BUDGETS,
               geometry_mean=geo_mean, verdict=[v_code, v_msg],
               lift_over_random=lift, best_router_at_5pct=best,
               oracle_auc=float(np.nanmean([r["teacher_auc_vs_attack"] for r in runs])),
               router_auc={k: float(np.nanmean([r["router_auc_vs_teacher"][k] for r in runs]))
                           for k in runs[0]["router_auc_vs_teacher"]},
               cost=cost, cost_text=cost_txt, params=runs[0]["params"])
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)

    # ---- console report ---------------------------------------------------
    print("\n" + "=" * 72)
    print("ORACLE QUALITY — can the Inspector separate attacks at all?")
    ta = [r["teacher_auc_vs_attack"] for r in runs]
    print(f"  Inspector AUC vs (synthetic) attack windows: "
          f"{np.nanmean(ta):.3f} ± {np.nanstd(ta):.3f}")
    if np.nanmean(ta) < 0.65:
        print("  !! WEAK ORACLE. Teacher-agreement numbers below are agreement")
        print("     with a detector that barely detects. Do not quote them.")
    print("\nROUTER AUC vs TEACHER DECISION")
    for r_ in runs[0]["router_auc_vs_teacher"]:
        vals = [r["router_auc_vs_teacher"][r_] for r in runs]
        print(f"  {r_:24s} {np.nanmean(vals):.3f} ± {np.nanstd(vals):.3f}")
    print("\nG1 GEOMETRY DIAGNOSTIC (go/no-go for the whole B1 fix)")
    for k, v in out["geometry_mean"].items():
        print(f"  {k:24s} {v:.4f}")
    print(f"  VERDICT: {out['verdict'][0]} — {out['verdict'][1]}")
    print("\nMODEL SIZE")
    p = out["params"]
    print(f"  Inspector {p['inspector']:,} params | Sentry {p['sentry']:,} | "
          f"compression {p['compression']:.1f}x")
    print("\nRECALL OF TEACHER-FLAGGED WINDOWS @ ESCALATION BUDGET (mean±std, n=%d seeds)"
          % a.seeds)
    hdr = "  budget | " + " | ".join(f"{r[:22]:>22s}" for r in agg)
    print(hdr); print("  " + "-" * (len(hdr) - 2))
    for i, b in enumerate(BUDGETS):
        row = f"  {b * 100:5.1f}% | "
        row += " | ".join(f"{agg[r][i]['recall_teacher_mean'] * 100:16.1f} ±{agg[r][i]['recall_teacher_std'] * 100:4.1f}"
                          for r in agg)
        print(row)
    print("\nRECALL OF (SYNTHETIC) ATTACK WINDOWS — INDICATIVE ONLY")
    for i, b in enumerate(BUDGETS):
        if b not in (0.01, 0.05, 0.10, 0.20):
            continue
        row = f"  {b * 100:5.1f}% | "
        row += " | ".join(f"{agg[r][i]['recall_attack_mean'] * 100:16.1f} ±{agg[r][i]['recall_attack_std'] * 100:4.1f}"
                          for r in agg)
        print(row)
    print("\nLIFT OVER RANDOM ROUTING (recall / budget) — best router: %s" % best)
    for i, b in enumerate(BUDGETS):
        if b in (0.01, 0.05, 0.10, 0.20):
            print(f"  {b*100:5.1f}% budget | " + " | ".join(
                f"{r.split('_')[0]}:{lift[f'{b:.3f}'][r]:5.1f}x" for r in agg))
    tgt = agg[best][BUDGETS.index(0.05)]["recall_teacher_mean"]
    print(f"\n  DESIGN TARGET CHECK: V2_HARDENING proposed '>=95% recall at <=5% budget'.")
    print(f"  Measured best at 5% budget: {tgt*100:.1f}%  ->  "
          f"{'MET' if tgt >= 0.95 else 'NOT MET'}. Do not quote the target as achieved.")
    print("\nCOST MODEL"); print(cost_txt)
    print("=" * 72)
    print(f"\nwrote {a.out}")


if __name__ == "__main__":
    main()
