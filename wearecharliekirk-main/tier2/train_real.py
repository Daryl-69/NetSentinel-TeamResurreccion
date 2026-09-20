#!/usr/bin/env python3
"""Train the Inspector + Sentry on REAL Zeek logs instead of the generator.

    python train_real.py --data data --epochs-teacher 12 --epochs-student 14

There are no attack labels here, and none are needed: the Inspector is an
anomaly model that learns normal. What you get out is:

  * a REAL measurement of how much the Service Category Resolver can actually
    see (the category histogram) -- this is the honest headline
  * the escalation-budget curve, which needs no labels because the Inspector
    is the reference oracle
  * pretrained encoder weights, which are the transferable part

What you do NOT get is a detection rate. Nothing here can produce one, and any
number claiming otherwise from this script is wrong.
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

import argparse, glob, json, os, time
import numpy as np
import torch

from netsentinel_v2 import train as T, zeek_loader as zl, lanl_loader as ll
from netsentinel_v2.baseline import HostBaseline
from netsentinel_v2.categories import CATEGORIES, EDGE_FEATURES
from netsentinel_v2.diagnostics import geometry_report, verdict
from run_experiment import roc_auc, count_params, BUDGETS


def find_zeek_dirs(root):
    hits = set()
    for pat in ("**/conn.log", "**/conn.log.gz", "**/conn.log.labeled"):
        for p in glob.glob(os.path.join(root, pat), recursive=True):
            hits.add(os.path.dirname(p))
    return sorted(hits)


def merge(datasets):
    """Concatenate several captures along the host axis, padding days."""
    if len(datasets) == 1:
        return datasets[0]
    D = max(d["edges"].shape[1] for d in datasets)
    W, C, F = datasets[0]["edges"].shape[2:]
    E, M, names = [], [], []
    for d in datasets:
        e, m = d["edges"], d["mask"]
        pad = D - e.shape[1]
        if pad:
            e = np.pad(e, ((0, 0), (0, pad), (0, 0), (0, 0), (0, 0)))
            m = np.pad(m, ((0, 0), (0, pad), (0, 0), (0, 0)))
        E.append(e); M.append(m)
        names += [f"{os.path.basename(d['source'])}/{h}" for h in d["hostnames"]]
    E, M = np.concatenate(E), np.concatenate(M)
    return dict(edges=E, mask=M, hostnames=np.array(names),
                host_ids=np.arange(len(names)), source="merged")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data", help="folder containing Zeek logs")
    ap.add_argument("--epochs-teacher", type=int, default=12)
    ap.add_argument("--epochs-student", type=int, default=14)
    ap.add_argument("--device", default="cpu", help="cpu | cuda")
    ap.add_argument("--min-windows", type=int, default=1)
    ap.add_argument("--window", type=int, default=3600,
                    help="window length in seconds (default 3600). A short "
                         "capture yields one window per host at 3600s, which "
                         "is useless for baselines -- try 300.")
    ap.add_argument("--host-normalise", action="store_true",
                    help="P0: score each window against its own host's "
                         "commissioning distribution. Cannot change "
                         "within-host AUC (see INSPECTOR_SENTRY.md 6.4); "
                         "changes which windows a top-k cut escalates.")
    ap.add_argument("--out", default="real_results.json")
    ap.add_argument("--lanl", action="store_true",
                    help="load LANL cyber1 (flows.txt.gz + redteam.txt.gz) "
                         "from --data instead of Zeek logs. This is the only "
                         "path that produces a REAL attack-recall number.")
    ap.add_argument("--max-hosts", type=int, default=800,
                    help="[--lanl] busiest N client hosts to model")
    ap.add_argument("--lanl-days", type=int, default=58)
    ap.add_argument("--profile-rows", type=int, default=0,
                    help="[--lanl] rows to read in the fan-in profiling pass. "
                         "0 (default) = the whole file. Anything less and a "
                         "computer that first appears after the cut is unknown "
                         "to pass two and its flows are silently dropped -- "
                         "including red-team hosts.")
    ap.add_argument("--profile-cache", default="lanl_profile.json")
    ap.add_argument("--max-gb", type=float, default=6.0)
    ap.add_argument("--label-policy", default="both",
                    choices=("both", "src", "dst"),
                    help="[--lanl] which endpoint of a red-team auth event is "
                         "marked compromised. 'dst' is the intuitive choice "
                         "and the wrong one: we model OUTBOUND behaviour, so "
                         "the row that changes is the source. Re-run with each "
                         "before believing a low attack recall.")
    ap.add_argument("--no-novelty", action="store_true",
                    help="[--lanl] leave feature slots 2/3 (bytes_down, "
                         "egress_asymmetry) as the exact zeros cyber1 forces, "
                         "instead of filling them with new_peer_ratio and "
                         "new_service_flag. Use it to A/B the novelty features "
                         "against the run that scored chance without them.")
    ap.add_argument("--novelty-baseline-days", type=int, default=0,
                    help="[--lanl] days used to learn each host's peer/service "
                         "profile before it freezes. 0 (default) = days//2, "
                         "which is exactly the commissioning split, so the "
                         "profile ends where the training data ends.")
    ap.add_argument("--seeds", type=int, default=3,
                    help="repeat training with N seeds and report mean +/- std. "
                         "A single seed on ~100 positives is not a result.")
    ap.add_argument("--tensor-cache", default=".",
                    help="[--lanl] folder for the parsed-tensor cache; the "
                         "expensive pass runs once, then label-policy sweeps "
                         "are free. '' disables it.")
    a = ap.parse_args()
    T.set_device(a.device)
    t0 = time.time()

    if a.lanl:
        data = ll.load_lanl(a.data, max_hosts=a.max_hosts, days=a.lanl_days,
                            profile_rows=(a.profile_rows or None),
                            cache=a.profile_cache, max_gb=a.max_gb,
                            label_policy=a.label_policy,
                            novelty=(not a.no_novelty),
                            novelty_baseline_days=(a.novelty_baseline_days or None),
                            tensor_cache=(a.tensor_cache or None))
        dirs = [data["source"]]
    else:
        dirs = find_zeek_dirs(a.data)
        if not dirs:
            print(f"No conn.log found under '{a.data}'.")
            print("Run get_stratosphere.ps1 first, or point --data at a folder that")
            print("contains Zeek logs. If a capture ships only .pcap, convert it:")
            print("    zeek -r capture.pcap")
            print("For LANL cyber1 (flows.txt.gz + redteam.txt.gz) use --lanl.")
            return
        print(f"Found {len(dirs)} capture(s) with conn.log:")
        for d in dirs:
            print("   ", d)

        sets = []
        for d in dirs:
            try:
                sets.append(zl.load_dir(d, window_seconds=a.window,
                                        min_windows_per_host=a.min_windows))
            except Exception as e:
                print(f"  ! skipped {d}: {e}")
        if not sets:
            print("Nothing loaded."); return
        data = merge(sets)

    E, M = data["edges"], data["mask"]
    H, D, W, C, F = E.shape
    cats = list(data.get("categories", CATEGORIES))
    per_cat = M.sum(axis=(0, 1, 2))
    total = max(per_cat.sum(), 1)
    resolved = float("nan")

    print("\n" + "=" * 68)
    print("CATEGORY RESOLVER — what it actually resolved")
    print("=" * 68)
    for c, n in sorted(zip(cats, per_cat), key=lambda x: -x[1]):
        if n:
            print(f"  {c:18s} {int(n):>9,}  {n/total*100:5.1f}%")
    print(f"\n  hosts={H}  days={D}  live windows={int((M.sum(-1)>0).sum()):,}")
    fnames = list(data.get("feature_names", [])) or None
    if fnames and fnames != list(EDGE_FEATURES):
        print("  edge-feature schema on THIS dataset (differs from the generator):")
        for i, (nm, ok) in enumerate(zip(fnames, data.get("feature_available",
                                                          [True] * F))):
            mark = "" if ok else "   <-- unavailable, held at zero"
            star = " *" if nm != EDGE_FEATURES[i] else "  "
            print(f"    {i:2d}{star} {nm}{mark}")

    if a.lanl:
        # No external destinations exist on this network, so "resolver hit
        # rate" is not a meaningful question. The meaningful one is whether
        # the internal taxonomy actually splits the traffic or collapses it.
        used = int((per_cat > 0).sum())
        top = per_cat.max() / total
        print(f"  asset classes in use          : {used}/{len(cats)}")
        print(f"  largest single class          : {top*100:5.1f}% of edges")
        if used < 3 or top > 0.90:
            print("\n  >> The internal taxonomy has COLLAPSED: nearly everything")
            print("     landed in one class, so there is no category structure")
            print("     for the sequence hypothesis to work with. Fix the port")
            print("     map before reading anything into the numbers below.")
        na = [i for i, ok in enumerate(data.get("feature_available",
                                                [True] * F)) if not ok]
        if na:
            print(f"  !! edge features {na} are unavailable on this dataset and")
            print("     are held at exact zero (cyber1 logs one byte count, not")
            print("     a directional pair). Do not read exfil-asymmetry results.")
    else:
        # The right question is NOT "how much is Internal or Browse" -- both of
        # those are correct answers. Internal means east-west (a real category,
        # and the one that matters for the OT framing); Browse means the hostname
        # WAS resolved and simply is not a tracked service. The only genuine
        # failure is an external destination with no hostname at all.
        internal = per_cat[cats.index("Internal")]
        unres    = per_cat[cats.index("Unknown_External")]
        external = max(total - internal, 1)
        resolved = (external - unres) / external
        lots = sum(per_cat[cats.index(c)] for c in
                   ("Recon_API", "Code_Repo_Paste", "Messaging_API",
                    "Cloud_Storage", "CI_CD", "Sync"))
        print(f"  east-west (Internal)          : {internal/total*100:5.1f}% of all edges")
        print(f"  external destinations         : {int(external):,}")
        print(f"    resolved to a hostname      : {resolved*100:5.1f}%   <-- resolver hit rate")
        print(f"    no hostname (ECH/DoH/raw IP): {unres/external*100:5.1f}%")
        print(f"    matched a LOTS category     : {lots/external*100:5.1f}%")
        if resolved < 0.25:
            print("\n  >> The resolver is BLIND on this capture: most external")
            print("     destinations have no SNI or DNS name, so the cross-service")
            print("     SEQUENCE hypothesis cannot be tested here. Training still")
            print("     exercises volume+timing, but do not present any result from")
            print("     it as evidence for the category-transition idea.")
        elif lots / external < 0.02:
            print("\n  >> The resolver works, but almost nothing on this network uses")
            print("     the trusted services the LOTS taxonomy tracks. Good evidence")
            print("     the RESOLVER functions; not a test of the sequence idea.")

    if D < 3:
        print(f"\n  >> Only {D} day(s) of data. Per-host baselines need multiple")
        print("     days to see the workday/night structure they model. Treat")
        print("     the router numbers below as a plumbing check, not a result.")

    # ---------------- temporal split ---------------------------------------
    Co = T.compute_cohort(E, M)
    c_end = max(1, D // 2); v_end = max(c_end + 1, int(D * 0.66)) if D > 2 else D
    flat = lambda X, x, y: X[:, x:y].reshape(-1, *X.shape[2:])
    hidx = lambda x, y: np.repeat(np.arange(H), y - x)

    Ec, Mc, Cc = flat(E, 0, c_end), flat(M, 0, c_end), flat(Co, 0, c_end)
    Et, Mt, Ct = flat(E, v_end, D), flat(M, v_end, D), flat(Co, v_end, D)
    hc = hidx(0, c_end)
    if Et.shape[0] == 0:
        # Not enough days to hold anything out. Evaluate on the training split
        # and say so -- the host index must follow the data, not the range.
        Et, Mt, Ct, ht = Ec, Mc, Cc, hc
        t_lo, t_hi = 0, c_end          # the label slice must follow the data
        print("\n  >> Too few days for a held-out split; evaluating on TRAINING data.")
        print("     These numbers are a plumbing check only.")
    else:
        ht = hidx(v_end, D)
        t_lo, t_hi = v_end, D
    Ec, mu, sd = T.standardise(Ec, Mc)
    Et, *_ = T.standardise(Et, Mt, mu, sd)

    print(f"\ncommissioning host-days: {Ec.shape[0]}   test host-days: {Et.shape[0]}")

    live_c, live_t = (Mc.sum(-1) > 0), (Mt.sum(-1) > 0)
    lf = live_t.reshape(-1)

    # ---- ground truth is seed-independent; build it once, before training ---
    A_day0 = data.get("is_attack_day")
    A_win0 = data.get("is_attack_window")
    has_labels = A_day0 is not None and bool(np.asarray(A_day0).any())
    if A_day0 is None:
        atk_w = atk_d = np.zeros_like(live_t, dtype=bool)
    else:
        atk_d = np.repeat(np.asarray(A_day0)[:, t_lo:t_hi].reshape(-1, 1),
                          W, axis=1)
        atk_w = (np.asarray(A_win0)[:, t_lo:t_hi].reshape(-1, W)
                 if A_win0 is not None else atk_d)
    atk_w = (atk_w.astype(bool) & live_t)
    atk_d = (atk_d.astype(bool) & live_t)

    # ---------------- train (one seed) --------------------------------------
    def train_eval(seed):
      insp = T.train_inspector(Ec, Mc, Cc, epochs=a.epochs_teacher, seed=seed)
      Zc_t, Ec_err = T.inspector_forward(insp, Ec, Mc, Cc)
      Zt_t, Et_err = T.inspector_forward(insp, Et, Mt, Ct)

      # P0 (12 Sep): score each window against ITS OWN HOST's commissioning
      # distribution instead of the pooled one. Fitted on commissioning only.
      # NOTE what this can and cannot move -- see INSPECTOR_SENTRY.md 6.4.
      # Within-host AUC is INVARIANT to a per-host monotone rescale, so this
      # will NOT change within_host_auc_mean. It changes the pooled ranking
      # and therefore which windows a global top-k cut escalates.
      host_norm_info = {"enabled": bool(a.host_normalise), "hosts_fellback": 0}
      if a.host_normalise:
          from netsentinel_v2.hostnorm import HostScoreNormaliser
          _hn = HostScoreNormaliser(min_live=20).fit(Ec_err, hc, (Mc.sum(-1) > 0))
          Ec_err = _hn.transform(Ec_err, hc)
          Et_err = _hn.transform(Et_err, ht)
          host_norm_info["hosts_fellback"] = _hn.n_fellback

      thr = float(np.quantile(Ec_err, 0.99))
      flag = Et_err >= thr

      sen = T.train_sentry(Ec, Mc, Zc_t, Ec_err, epochs=a.epochs_student, seed=seed)
      Zc_s = T.sentry_forward(sen, Ec, Mc)
      Zt_s = T.sentry_forward(sen, Et, Mt)
      bl = {}
      for h in range(H):
          r = np.where(hc == h)[0]
          if len(r) == 0:
              continue
          Z = Zc_s[r].reshape(-1, Zc_s.shape[-1]); lv = live_c[r].reshape(-1)
          e = Ec_err[r].reshape(-1)
          if lv.sum() >= 20:
              Z, e = Z[lv], e[lv]
          if len(Z) >= 4:
              bl[h] = HostBaseline(n_components=3, trim_frac=0.05).fit(Z, e)

      def maha(Z, hi):
          out = np.zeros(Z.shape[:2], dtype=np.float32)
          for h in np.unique(hi):
              if h not in bl:
                  continue
              r = np.where(hi == h)[0]
              out[r] = bl[h].score(Z[r].reshape(-1, Z.shape[-1])).reshape(len(r), -1)
          return np.nan_to_num(out, nan=0., posinf=0., neginf=0.)

      Mt_d = maha(Zt_s, ht)
      headA = T.train_head(Zc_s, (Ec_err / (thr + 1e-9)).astype(np.float32),
                           loss="mse", seed=seed)
      sA = T.head_forward(headA, Zt_s)

      curves = {
          "A_distilled_detector":  T.budget_curve(sA.reshape(-1)[lf], flag.reshape(-1)[lf],
                                                  atk_w.reshape(-1)[lf], BUDGETS),
          "B_encoder_mahalanobis": T.budget_curve(Mt_d.reshape(-1)[lf], flag.reshape(-1)[lf],
                                                  atk_w.reshape(-1)[lf], BUDGETS),
      }
      curves_dayline = {
          "A_distilled_detector":  T.budget_curve(sA.reshape(-1)[lf], flag.reshape(-1)[lf],
                                                  atk_d.reshape(-1)[lf], BUDGETS),
      }
      aucs = {k: roc_auc(v.reshape(-1)[lf], flag.reshape(-1)[lf])
              for k, v in (("A_distilled_detector", sA),
                           ("B_encoder_mahalanobis", Mt_d))}
      oracle = dict(
          auc_vs_attack_window=roc_auc(Et_err.reshape(-1)[lf], atk_w.reshape(-1)[lf])
          if has_labels else float("nan"),
          auc_vs_attack_day=roc_auc(Et_err.reshape(-1)[lf], atk_d.reshape(-1)[lf])
          if has_labels else float("nan"),
      )
      if has_labels:
          lo, hi_ = boot_auc(Et_err.reshape(-1)[lf], atk_w.reshape(-1)[lf])
          oracle["auc_vs_attack_window_ci95"] = [lo, hi_]
          m, sd_, nh, npos = within_host_auc(Et_err, atk_w, ht)
          oracle.update(within_host_auc_mean=m, within_host_auc_std=sd_,
                        within_host_n_hosts=nh, within_host_n_positives=npos)
          # The router gets the same treatment as the teacher: a router that
          # only reproduces a between-host effect is not detecting either.
          mr, sr, nhr, _ = within_host_auc(sA, atk_w, ht)
          oracle.update(router_A_within_host_auc_mean=mr,
                        router_A_within_host_auc_std=sr,
                        router_A_within_host_n_hosts=nhr)
      oracle["host_normalise"] = host_norm_info
      geo = geometry_report(Zt_t.reshape(-1, Zt_t.shape[-1])[lf],
                            Zt_s.reshape(-1, Zt_s.shape[-1])[lf],
                            Et_err.reshape(-1)[lf], sA.reshape(-1)[lf])
      vc, vm = verdict(geo)
      return dict(seed=seed, flag_rate=float(flag.reshape(-1)[lf].mean()),
                  router_auc=aucs, curves=curves, curves_daylevel=curves_dayline,
                  oracle=oracle, geometry=geo, verdict=[vc, vm],
                  n_params=[count_params(insp), count_params(sen)],
                  _state=({"inspector": insp.state_dict(),
                           "sentry": sen.state_dict()} if seed == 0 else None))

    # ---- the confound check ------------------------------------------------
    # A global AUC vs attack answers "can the Inspector pick attack windows out
    # of the whole population?" -- and a model that merely ranks hosts by how
    # busy or how sparse they are will ace it whenever the attacked hosts differ
    # in that respect, while knowing nothing about the attack. Restricting to
    # each attacked host's OWN windows removes the between-host axis entirely.
    # If the within-host number collapses toward 0.5, the global one was
    # measuring WHICH host, not WHEN. Ask it before a reviewer does.
    def within_host_auc(score, label, hidx, min_neg=5):
        aucs, ns = [], []
        for h in np.unique(hidx):
            r = np.where(hidx == h)[0]
            lv = live_t[r].reshape(-1)
            s = score[r].reshape(-1)[lv]
            y = label[r].reshape(-1)[lv].astype(bool)
            if y.sum() == 0 or (~y).sum() < min_neg:
                continue
            au = roc_auc(s, y)
            if not np.isnan(au):
                aucs.append(au); ns.append(int(y.sum()))
        return (float(np.mean(aucs)) if aucs else float("nan"),
                float(np.std(aucs)) if aucs else float("nan"),
                len(aucs), int(sum(ns)))

    def boot_auc(score, label, reps=400, seed=0):
        """Percentile bootstrap. With ~100 positives the point estimate is
        nearly meaningless on its own; the interval is the honest object.
        Note what it does NOT cover: sampling noise only. A tight interval on
        a confounded metric is still a confounded metric."""
        y = np.asarray(label).astype(bool)
        if y.sum() < 2 or (~y).sum() < 2:
            return (float("nan"), float("nan"))
        rng = np.random.default_rng(seed)
        pos, neg = np.where(y)[0], np.where(~y)[0]
        sc = np.asarray(score, dtype=np.float64)
        out = []
        for _ in range(reps):
            i = np.concatenate([rng.choice(pos, len(pos), replace=True),
                                rng.choice(neg, len(neg), replace=True)])
            yy = np.zeros(len(i), dtype=bool); yy[:len(pos)] = True
            au = roc_auc(sc[i], yy)
            if not np.isnan(au):
                out.append(au)
        if not out:
            return (float("nan"), float("nan"))
        return (float(np.percentile(out, 2.5)), float(np.percentile(out, 97.5)))

    runs = []
    for sd_i in range(max(1, a.seeds)):
        print(f"\n--- seed {sd_i} " + "-" * 52, flush=True)
        runs.append(train_eval(sd_i))

    # ---------------- aggregate across seeds --------------------------------
    def agg(fn):
        v = []
        for r in runs:
            try:
                x = fn(r)
            except (KeyError, IndexError, TypeError):
                continue
            if x is None:
                continue
            x = float(x)
            if not np.isnan(x):
                v.append(x)
        if not v:
            return float("nan"), float("nan")
        return float(np.mean(v)), float(np.std(v))

    i5 = BUDGETS.index(0.05)
    multi = a.seeds > 1
    ms = lambda m, s: (f"{m:.3f} +/- {s:.3f}" if multi else f"{m:.3f}")
    mp = lambda m, s: (f"{m*100:5.1f}% +/- {s*100:.1f}" if multi
                       else f"{m*100:5.1f}%")

    # Counts are seed-independent: compute once, from the data itself.
    n_atk_w = int(atk_w.reshape(-1)[lf].sum())
    n_atk_d = int(atk_d.reshape(-1)[lf].sum())
    n_hosts_atk = int(np.unique(ht[atk_w.any(1)]).size) if has_labels else 0
    dens = live_t.mean(axis=1); atk_rows = atk_w.any(1)
    dens_atk = float(dens[atk_rows].mean()) if atk_rows.any() else float("nan")
    dens_oth = float(dens[~atk_rows].mean())

    print("\n" + "=" * 68)
    print("RESULT ON REAL TRAFFIC" +
          ("  (with REAL red-team ground truth)" if has_labels
           else "  (no attack labels - routing quality only)"))
    if a.lanl:
        print("  features : " + ("volume/timing + NOVELTY in slots 2,3"
                                 if not a.no_novelty else
                                 "volume/timing ONLY - slots 2,3 held at zero"))
    print(f"  seeds    : {a.seeds}" + ("" if multi else
          "   <-- one seed is not a result; use --seeds 3"))
    print("=" * 68)
    m, s = agg(lambda r: r["flag_rate"])
    print(f"  Inspector flag rate on test : {mp(m, s)}  (target  1.0%)")
    for k in ("A_distilled_detector", "B_encoder_mahalanobis"):
        m, s = agg(lambda r, k=k: r["router_auc"][k])
        print(f"  {k:24s} AUC vs Inspector {ms(m, s)}")
    for k in ("A_distilled_detector", "B_encoder_mahalanobis"):
        m, s = agg(lambda r, k=k: r["curves"][k][i5]["recall_teacher"])
        print(f"  {k:24s} recall @5% budget {mp(m, s)}")
    m, s = agg(lambda r: r["geometry"]["knn_overlap@20"])
    print(f"  kNN geometry overlap        : {ms(m, s)}  [{runs[0]['verdict'][0]}]")

    if has_labels:
        print("\n  --- against the red team (the only non-synthetic numbers) ---")
        print(f"  n = {n_atk_w} attack windows on {n_hosts_atk} distinct hosts,"
              f" out of {int(lf.sum()):,} live windows (day-level {n_atk_d})")
        gm, gs = agg(lambda r: r["oracle"]["auc_vs_attack_window"])
        dm, ds = agg(lambda r: r["oracle"]["auc_vs_attack_day"])
        print(f"  GLOBAL  Inspector AUC vs attack : {ms(gm, gs)} window-level, "
              f"{ms(dm, ds)} day-level")
        lo, _ = agg(lambda r: r["oracle"]["auc_vs_attack_window_ci95"][0])
        hi2, _ = agg(lambda r: r["oracle"]["auc_vs_attack_window_ci95"][1])
        print(f"          bootstrap 95% CI (seed-mean)  : [{lo:.3f}, {hi2:.3f}]")
        rm, rs = agg(lambda r: r["curves"]["A_distilled_detector"][i5]["recall_attack"])
        rdm, rds = agg(lambda r: r["curves_daylevel"]["A_distilled_detector"][i5]["recall_attack"])
        print(f"          router A recall @5% budget    : {mp(rm, rs)} window, "
              f"{mp(rdm, rds)} day")

        wm, ws = agg(lambda r: r["oracle"]["within_host_auc_mean"])
        am, asd = agg(lambda r: r["oracle"]["router_A_within_host_auc_mean"])
        wn = runs[0]["oracle"].get("within_host_n_hosts", 0)
        wp = runs[0]["oracle"].get("within_host_n_positives", 0)
        print(f"\n  WITHIN-HOST AUC - the confound check (each host vs itself)")
        print(f"          Inspector : {ms(wm, ws)}   over {wn} attacked hosts "
              f"({wp} positives)")
        print(f"          router A  : {ms(am, asd)}")
        print(f"          live-window density: attacked rows {dens_atk:.3f} "
              f"vs others {dens_oth:.3f}")
        gap = gm - (wm if not np.isnan(wm) else 0.5)
        if np.isnan(wm):
            print("    >> Not enough per-host data to run the check. The global")
            print("       AUC is UNVERIFIED - do not present it as detection.")
        elif wm < 0.60:
            print("    >> CHANCE. Scored against its own baseline, a host's")
            print("       attack windows are indistinguishable from its normal")
            print("       ones. Whatever the global AUC says, this is NOT")
            print("       detection. Report the within-host number.")
            if gap > 0.15:
                print("       The global figure is a BETWEEN-HOST effect: the")
                print("       model ranks WHICH host is unusual, not WHEN.")
        elif wm >= 0.70:
            print("    >> SURVIVES the check: the signal is temporal, inside a")
            print("       host's own behaviour. This is the number to defend.")
        else:
            print("    >> Weak but above chance. Needs more positives before it")
            print("       means anything; do not lead with it.")
        print("  labelling: see --label-policy. Positives are rare, so quote the")
        print("  COUNT and the CI, never a point estimate alone.")

    p_i, p_s = runs[0]["n_params"]
    print(f"\n  compression                 : {p_i:,} -> {p_s:,}  "
          f"({p_i/max(p_s,1):.1f}x)")

    torch.save({**(runs[0]["_state"] or {}), "mu": mu, "sd": sd},
               "pretrained_real.pt")
    for r in runs:
        r.pop("_state", None)
    json.dump(dict(source=dirs, dataset=("LANL cyber1" if a.lanl else "zeek"),
                   hosts=int(H), days=int(D), seeds=int(a.seeds),
                   novelty_features=(bool(a.lanl) and not a.no_novelty),
                   feature_names=list(data.get("feature_names", EDGE_FEATURES)),
                   feature_available=list(data.get("feature_available",
                                                   [True] * F)),
                   novelty_stats=data.get("novelty_stats"),
                   categories=cats,
                   category_counts={c: int(n) for c, n in zip(cats, per_cat)},
                   resolver_hit_rate=(None if a.lanl else float(resolved)),
                   has_attack_labels=bool(has_labels),
                   label_policy=data.get("label_policy"),
                   redteam_events=data.get("redteam_events"),
                   redteam_sources_modelled=data.get("redteam_sources_modelled"),
                   redteam_dests_modelled=data.get("redteam_dests_modelled"),
                   n_attack_windows=n_atk_w, n_attack_daylevel=n_atk_d,
                   n_attacked_hosts=n_hosts_atk, n_live_windows=int(lf.sum()),
                   live_density_attacked=dens_atk, live_density_other=dens_oth,
                   runs=runs, runtime_s=time.time() - t0),
              open(a.out, "w"), indent=2)
    print(f"  saved pretrained_real.pt and {a.out}   ({time.time()-t0:.0f}s total)")
    print("=" * 68)


if __name__ == "__main__":
    main()
