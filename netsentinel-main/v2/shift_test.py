#!/usr/bin/env python3
"""Distribution-shift stress test: how brittle is the learned "normal"?

The question this answers is the one a judge will ask:

    "Your Inspector learned normal from your own generator. What happens when
     you point it at a network it has never seen?"

Setup — the honest analogue of a real deployment:

    WORLD A  dev-heavy software org      -> the Inspector and Sentry are TRAINED here
    WORLD B  OT/plant-heavy org          -> same mechanism, different organisation:
                                            different role mix, slower human rhythms,
                                            lower data volumes, longer working day

The encoder is trained ONCE on world A and never sees world B traffic during
training. In world B it is deployed cold: baselines are re-fit on B's own
commissioning window (which is what actually happens at a new customer), and
thresholds calibrated on A are applied unchanged, because that is the mistake
a real deployment makes.

Reported degradations:
  * Inspector AUC vs attack           A -> B     (does the oracle survive?)
  * Router AUC vs Inspector           A -> B     (does routing survive?)
  * Recall @5% escalation budget      A -> B
  * kNN geometry overlap              A -> B
  * Threshold transfer: the flag-rate world A's 99th-percentile threshold
    actually produces in world B. If that number is not ~1%, calibration does
    NOT transfer and every deployment needs its own calibration window.
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

import argparse, json, time
import numpy as np

from netsentinel_v2 import synth, train as T
from netsentinel_v2.baseline import HostBaseline
from netsentinel_v2.diagnostics import geometry_report
from run_experiment import roc_auc, count_params, BUDGETS


def prep(d):
    E, M = d["edges"], d["mask"]
    Co = T.compute_cohort(E, M)
    return E, M, Co, d["is_attack_day"]


def split(X, a, b):
    return X[:, a:b].reshape(-1, *X.shape[2:])


def run(seed, hosts, days, ep_t, ep_s):
    t0 = time.time()
    D = days
    c_end, v_end = D // 2, int(D * 0.66)

    A = synth.generate(n_hosts=hosts, n_days=days, seed=seed, world_cfg="A")
    B = synth.generate(n_hosts=hosts, n_days=days, seed=seed + 500, world_cfg="B")

    Ea, Ma, Coa, Aa = prep(A)
    Eb, Mb, Cob, Ab = prep(B)
    H = hosts

    # ---- world A: the training world ------------------------------------
    Ac, Mc, Cc = split(Ea, 0, c_end), split(Ma, 0, c_end), split(Coa, 0, c_end)
    At, Mt, Ct = split(Ea, v_end, D), split(Ma, v_end, D), split(Coa, v_end, D)
    Ac, mu, sd = T.standardise(Ac, Mc)
    At, *_ = T.standardise(At, Mt, mu, sd)

    # ---- world B: deployed cold. NOTE the standardiser is A's -----------
    # Re-deriving it on B would quietly hide part of the shift; a real
    # deployment ships the fitted preprocessing with the model.
    Bc, Nc, Dc = split(Eb, 0, c_end), split(Mb, 0, c_end), split(Cob, 0, c_end)
    Bt, Nt, Dt = split(Eb, v_end, D), split(Mb, v_end, D), split(Cob, v_end, D)
    Bc, *_ = T.standardise(Bc, Nc, mu, sd)
    Bt, *_ = T.standardise(Bt, Nt, mu, sd)

    hc = np.repeat(np.arange(H), c_end)
    ht = np.repeat(np.arange(H), D - v_end)

    print(f"[seed {seed}] training on world A ({Ac.shape[0]} host-days)", flush=True)
    insp = T.train_inspector(Ac, Mc, Cc, epochs=ep_t, seed=seed)
    Zc_t, Ec_err = T.inspector_forward(insp, Ac, Mc, Cc)
    Zat, Eat_err = T.inspector_forward(insp, At, Mt, Ct)
    Zbc, Ebc_err = T.inspector_forward(insp, Bc, Nc, Dc)
    Zbt, Ebt_err = T.inspector_forward(insp, Bt, Nt, Dt)

    thr = float(np.quantile(Ec_err, 0.99))          # calibrated on A only
    thr_b = float(np.quantile(Ebc_err, 0.99))       # what B's own calibration would be

    sen = T.train_sentry(Ac, Mc, Zc_t, Ec_err, epochs=ep_s, seed=seed)
    Zc_s = T.sentry_forward(sen, Ac, Mc)
    Zat_s = T.sentry_forward(sen, At, Mt)
    Zbc_s = T.sentry_forward(sen, Bc, Nc)
    Zbt_s = T.sentry_forward(sen, Bt, Nt)

    def baselines(Zs, mask_c, err, hidx):
        live = (mask_c.sum(-1) > 0)
        bl = {}
        for h in range(H):
            r = np.where(hidx == h)[0]
            Z = Zs[r].reshape(-1, Zs.shape[-1]); lv = live[r].reshape(-1)
            e = err[r].reshape(-1)
            if lv.sum() >= 20:
                Z, e = Z[lv], e[lv]
            bl[h] = HostBaseline(n_components=3, trim_frac=0.05).fit(Z, e)
        return bl

    def maha(bl, Z, hidx):
        out = np.zeros(Z.shape[:2], dtype=np.float32)
        for h in np.unique(hidx):
            r = np.where(hidx == h)[0]
            out[r] = bl[h].score(Z[r].reshape(-1, Z.shape[-1])).reshape(len(r), -1)
        return np.nan_to_num(out, nan=0., posinf=0., neginf=0.)

    bl_a = baselines(Zc_s, Mc, Ec_err, hc)
    bl_b = baselines(Zbc_s, Nc, Ebc_err, hc)   # re-fit on B — the deployment step

    res = {}
    for tag, (Zt_t, err, Zt_s, bl, mask, atk_day) in {
        "A": (Zat, Eat_err, Zat_s, bl_a, Mt, Aa),
        "B": (Zbt, Ebt_err, Zbt_s, bl_b, Nt, Ab),
    }.items():
        live = (mask.sum(-1) > 0); lf = live.reshape(-1)
        atk = (np.repeat(atk_day[:, v_end:D].reshape(-1)[:, None], mask.shape[1], 1) & live)
        flag = err >= thr                       # A's threshold, applied to both
        sB = maha(bl, Zt_s, ht)
        geo = geometry_report(Zt_t.reshape(-1, Zt_t.shape[-1])[lf],
                              Zt_s.reshape(-1, Zt_s.shape[-1])[lf],
                              err.reshape(-1)[lf], sB.reshape(-1)[lf])
        curve = T.budget_curve(sB.reshape(-1)[lf], flag.reshape(-1)[lf],
                               atk.reshape(-1)[lf], BUDGETS)
        res[tag] = dict(
            oracle_auc=roc_auc(err.reshape(-1)[lf], atk.reshape(-1)[lf]),
            router_auc=roc_auc(sB.reshape(-1)[lf], flag.reshape(-1)[lf]),
            recall_at_5=curve[BUDGETS.index(0.05)]["recall_teacher"],
            recall_attack_at_5=curve[BUDGETS.index(0.05)]["recall_attack"],
            knn=geo["knn_overlap@20"],
            flag_rate=float(flag.reshape(-1)[lf].mean()),
            attack_rate=float(atk.reshape(-1)[lf].mean()),
            curve=curve,
        )
    res["threshold_transfer"] = dict(
        thr_from_A=thr, thr_native_B=thr_b,
        ratio=thr_b / thr if thr else float("nan"),
        flag_rate_target=0.01,
        flag_rate_B_using_A_threshold=res["B"]["flag_rate"],
    )
    res["seed"] = seed
    res["runtime_s"] = time.time() - t0
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--hosts", type=int, default=300)
    ap.add_argument("--days", type=int, default=24)
    ap.add_argument("--epochs-teacher", type=int, default=12)
    ap.add_argument("--epochs-student", type=int, default=14)
    ap.add_argument("--device", default="cpu", help="cpu | cuda")
    ap.add_argument("--out", default="shift_results.json")
    a = ap.parse_args()
    T.set_device(a.device)

    runs = [run(s, a.hosts, a.days, a.epochs_teacher, a.epochs_student)
            for s in range(a.seeds)]
    agg = {}
    for w in ("A", "B"):
        agg[w] = {k: (float(np.nanmean([r[w][k] for r in runs])),
                      float(np.nanstd([r[w][k] for r in runs])))
                  for k in ("oracle_auc", "router_auc", "recall_at_5",
                            "recall_attack_at_5", "knn", "flag_rate")}
    tt = {k: float(np.nanmean([r["threshold_transfer"][k] for r in runs]))
          for k in ("ratio", "flag_rate_B_using_A_threshold")}
    out = dict(runs=runs, aggregate=agg, threshold_transfer=tt, budgets=BUDGETS,
               worlds={k: synth.WORLDS[k] for k in ("A", "B")})
    json.dump(out, open(a.out, "w"), indent=2)

    print("\n" + "=" * 74)
    print("DISTRIBUTION-SHIFT STRESS TEST — trained on world A, deployed cold to B")
    print("=" * 74)
    rows = [("Inspector AUC vs attack", "oracle_auc", 1),
            ("Router AUC vs Inspector", "router_auc", 1),
            ("Recall @5% budget", "recall_at_5", 100),
            ("Attack recall @5% (indicative)", "recall_attack_at_5", 100),
            ("kNN geometry overlap", "knn", 1),
            ("Flag rate (target 1.0%)", "flag_rate", 100)]
    print(f"  {'metric':34s} {'world A':>16s} {'world B':>16s}   change")
    print("  " + "-" * 72)
    for label, k, scale in rows:
        a_m, a_s = agg["A"][k]; b_m, b_s = agg["B"][k]
        d = (b_m - a_m) / a_m * 100 if a_m else float("nan")
        u = "%" if scale == 100 else ""
        print(f"  {label:34s} {a_m*scale:9.2f}{u} ±{a_s*scale:4.2f} "
              f"{b_m*scale:9.2f}{u} ±{b_s*scale:4.2f}   {d:+6.1f}%")
    print(f"\n  Threshold transfer: world B's native 99th-pct threshold is "
          f"{tt['ratio']:.2f}× world A's.")
    print(f"  Applying A's threshold in B flags "
          f"{tt['flag_rate_B_using_A_threshold']*100:.2f}% of windows "
          f"(target 1.00%).")
    print("=" * 74)
    print(f"\nwrote {a.out}")


if __name__ == "__main__":
    main()
