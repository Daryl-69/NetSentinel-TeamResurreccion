#!/usr/bin/env python3
"""
lanl_p0b.py -- P0b on the REAL LANL corpus, which is the one comparison the
reviewer said was missing:

    "After P0b, add either 'the Inspector beats an order-free Mahalanobis on
     LANL within-host by X' or 'it does not, and here is why we keep it'.
     Both are safe. Leaving the comparison unrun is the one gap."

We previously ran this on synthetic data only, and the synthetic run failed to
reproduce LANL's pathology (gap came out with the opposite sign), so it settled
nothing. This runs the baseline on the actual red-team labels.

The baseline is deliberately as close to zero-parameter as it can be while
still being a fair opponent:

  * per host, a median and a MAD over that host's own COMMISSIONING windows
  * score = mean squared robust z over the flattened (category x feature) bag
  * no graph, no attention, no embedding, no cohort, no training, no order

If this ties or beats the 205,546-parameter Inspector on within-host AUC, the
Inspector cannot be justified on within-host accuracy and we have to say so.

Reads the same tensor cache train_real.py uses, so it scores EXACTLY the rows
the Inspector scored -- same hosts, same day split, same live mask.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2 import lanl_loader as ll     # noqa: E402


def roc_auc(score, label):
    """Rank-based AUC. No sklearn dependency, ties handled by average rank."""
    y = np.asarray(label).astype(bool)
    s = np.asarray(score, dtype=np.float64)
    npos, nneg = int(y.sum()), int((~y).sum())
    if npos == 0 or nneg == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), dtype=np.float64)
    ranks[order] = np.arange(1, len(s) + 1, dtype=np.float64)
    # average ranks within ties
    s_sorted = s[order]
    i = 0
    while i < len(s_sorted):
        j = i
        while j + 1 < len(s_sorted) and s_sorted[j + 1] == s_sorted[i]:
            j += 1
        if j > i:
            ranks[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return float((ranks[y].sum() - npos * (npos + 1) / 2.0) / (npos * nneg))


def bag_mahalanobis(Ec, Mc, Et, Mt):
    """Per-host diagonal robust Gaussian over the flattened bag.

    Ec/Et: (hosts, days, windows, categories, features)
    Returns (hosts, days*windows) scores for the test split.
    """
    H = Ec.shape[0]
    def flat(E, M):
        # (H, D, W, C, F) -> (H, D*W, C*F + C)
        h, d, w, c, f = E.shape
        return np.concatenate([E.reshape(h, d * w, c * f),
                               M.reshape(h, d * w, c)], axis=-1)
    Fc, Ft = flat(Ec, Mc), flat(Et, Mt)
    live_c = (Mc.sum(-1) > 0).reshape(H, -1)
    out = np.zeros(Ft.shape[:2], dtype=np.float64)
    fellback = 0
    for h in range(H):
        X, lv = Fc[h], live_c[h]
        if lv.sum() >= 20:
            X = X[lv]
        elif len(X) >= 5:
            fellback += 1
        if len(X) < 5:
            continue
        med = np.median(X, axis=0)
        mad = np.median(np.abs(X - med), axis=0) * 1.4826 + 1e-6
        out[h] = (((Ft[h] - med) / mad) ** 2).mean(axis=-1)
    return out, fellback


def per_host_auc(score, label, live, min_neg=5):
    """Per-host AUC keyed by host index, so two scorers can be PAIRED on the
    identical host set. train_real.py returns only the mean; with a per-host
    spread near 0.27 a difference of means is not a result on its own."""
    out = {}
    for h in range(score.shape[0]):
        lv = live[h]
        y = label[h][lv].astype(bool)
        if y.sum() == 0 or (~y).sum() < min_neg:
            continue
        au = roc_auc(score[h][lv], y)
        if not np.isnan(au):
            out[h] = (au, int(y.sum()))
    return out


def within_host_auc(score, label, live, min_neg=5):
    """Mean per-host AUC. Identical definition to train_real.py so the numbers
    are directly comparable."""
    d = per_host_auc(score, label, live, min_neg)
    aucs = [v[0] for v in d.values()]
    ns = [v[1] for v in d.values()]
    return (float(np.mean(aucs)) if aucs else float("nan"),
            float(np.std(aucs)) if aucs else float("nan"),
            len(aucs), int(sum(ns)))


def paired_report(a_name, A, b_name, B):
    """Wilcoxon-style paired comparison over the hosts BOTH scorers cover.

    Reported because the unpaired means hide the thing that matters: whether
    one scorer is better on the same hosts, or whether the two are trading
    wins and the difference of means is noise. Exact sign test, no scipy.
    """
    common = sorted(set(A) & set(B))
    if not common:
        return None
    da = np.array([A[h][0] for h in common])
    db = np.array([B[h][0] for h in common])
    diff = da - db
    wins = int((diff > 0).sum())
    losses = int((diff < 0).sum())
    ties = int((diff == 0).sum())
    n = wins + losses
    # two-sided exact binomial sign test, p = 0.5
    if n:
        from math import comb
        k = min(wins, losses)
        p = min(1.0, 2.0 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))
    else:
        p = float("nan")
    return dict(hosts_compared=len(common), a=a_name, b=b_name,
                mean_a=float(da.mean()), mean_b=float(db.mean()),
                mean_diff=float(diff.mean()),
                median_diff=float(np.median(diff)),
                a_wins=wins, b_wins=losses, ties=ties, sign_test_p=float(p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=".")
    ap.add_argument("--max-hosts", type=int, default=500)
    ap.add_argument("--lanl-days", type=int, default=13)
    ap.add_argument("--profile-cache", default="lanl_profile.json")
    ap.add_argument("--tensor-cache", default=".")
    ap.add_argument("--label-policy", default="both")
    ap.add_argument("--inspector-ckpt", default="pretrained_real.pt",
                    help="pretrained_real.pt from train_real.py. If present, "
                         "the Inspector is scored on the SAME rows and the "
                         "two are compared per host, paired.")
    ap.add_argument("--out", default="lanl_p0b.json")
    a = ap.parse_args()

    d = ll.load_lanl(a.data, max_hosts=a.max_hosts, days=a.lanl_days,
                     cache=a.profile_cache, tensor_cache=a.tensor_cache,
                     label_policy=a.label_policy, novelty=True, verbose=True)

    E, M = d["edges"], d["mask"]
    H, D, W = E.shape[0], E.shape[1], E.shape[2]
    A_day = np.asarray(d["is_attack_day"])
    A_win = d.get("is_attack_window")
    A_win = np.asarray(A_win) if A_win is not None else None

    # EXACTLY train_real.py's split (see train_real.py:249). Not first-half /
    # second-half: there is a validation gap between commissioning and test,
    # and scoring the gap would compare against rows the Inspector never saw.
    c_end = max(1, D // 2)
    v_end = max(c_end + 1, int(D * 0.66)) if D > 2 else D
    t_lo, t_hi = v_end, D
    Ec, Mc = E[:, :c_end], M[:, :c_end]
    Et, Mt = E[:, t_lo:t_hi], M[:, t_lo:t_hi]
    live_t = (Mt.sum(-1) > 0).reshape(H, -1)

    if A_win is not None:
        atk = A_win[:, t_lo:t_hi].reshape(H, -1).astype(bool)
    else:
        atk = np.repeat(A_day[:, t_lo:t_hi][:, :, None], W, axis=2)
        atk = atk.reshape(H, -1).astype(bool)
    atk = atk & live_t

    print()
    print("=" * 72)
    print("  P0b -- order-free per-host Mahalanobis on REAL LANL")
    print("=" * 72)
    print(f"  hosts {H}  days {D}  commissioning 0..{c_end-1}  "
          f"validation gap {c_end}..{t_lo-1}  test {t_lo}..{D-1}")
    print(f"  live test windows {int(live_t.sum()):,}   "
          f"attack windows {int(atk.sum()):,} on "
          f"{int((atk.any(1)).sum())} host(s)")

    score, fellback = bag_mahalanobis(Ec, Mc, Et, Mt)
    if fellback:
        print(f"  ({fellback} host(s) had <20 live commissioning windows and "
              f"were fitted on all windows instead)")

    wm, ws, nh, npos = within_host_auc(score, atk, live_t)
    pooled = roc_auc(score[live_t], atk[live_t])
    bag_ph = per_host_auc(score, atk, live_t)

    print()
    print(f"  bag-Mahalanobis  pooled AUC      : {pooled:.3f}")
    print(f"  bag-Mahalanobis  within-host AUC : {wm:.3f} +/- {ws:.3f}  "
          f"over {nh} attacked host(s), {npos} positive window(s)")

    out = dict(dataset="lanl_cyber1", hosts=H, days=D,
               commissioning_days=c_end, test_days=D - t_lo,
               live_test_windows=int(live_t.sum()),
               attack_windows=int(atk.sum()),
               attacked_hosts=int(atk.any(1).sum()),
               hosts_fellback=fellback,
               bag_pooled_auc=pooled,
               bag_within_host_auc_mean=wm,
               bag_within_host_auc_std=ws,
               bag_within_host_n_hosts=nh,
               bag_within_host_n_positives=npos)

    # ---- the Inspector, scored on the SAME rows, compared PER HOST ---------
    if a.inspector_ckpt and os.path.exists(a.inspector_ckpt):
        import torch
        from netsentinel_v2 import train as T
        from netsentinel_v2.models import Inspector

        ck = torch.load(a.inspector_ckpt, map_location="cpu",
                        weights_only=False)
        Co = T.compute_cohort(E, M)
        fl = lambda X, x, y: X[:, x:y].reshape(-1, *X.shape[2:])
        Ec2, Mc2, Cc2 = fl(E, 0, c_end), fl(M, 0, c_end), fl(Co, 0, c_end)
        Et2, Mt2, Ct2 = fl(E, t_lo, D), fl(M, t_lo, D), fl(Co, t_lo, D)
        # reuse the checkpoint's standardisation, not a fresh fit
        if "mu" in ck and "sd" in ck:
            Et2, *_ = T.standardise(Et2, Mt2, ck["mu"], ck["sd"])
        else:
            Ec2, mu, sd = T.standardise(Ec2, Mc2)
            Et2, *_ = T.standardise(Et2, Mt2, mu, sd)
        insp = Inspector(dim=96)
        insp.load_state_dict(ck["inspector"])
        _, err = T.inspector_forward(insp, Et2, Mt2, Ct2)
        insp_score = err.reshape(H, -1)

        ins_ph = per_host_auc(insp_score, atk, live_t)
        im, is_, inh, inpos = within_host_auc(insp_score, atk, live_t)
        ipool = roc_auc(insp_score[live_t], atk[live_t])
        print(f"  Inspector        pooled AUC      : {ipool:.3f}")
        print(f"  Inspector        within-host AUC : {im:.3f} +/- {is_:.3f}  "
              f"over {inh} attacked host(s)")

        rep = paired_report("Inspector", ins_ph, "bag-Mahalanobis", bag_ph)
        if rep:
            print()
            print("  PAIRED, on the hosts both scorers cover "
                  f"(n = {rep['hosts_compared']})")
            print(f"    Inspector wins on   {rep['a_wins']} host(s)")
            print(f"    bag wins on         {rep['b_wins']} host(s)")
            print(f"    exact ties          {rep['ties']}")
            print(f"    mean difference     {rep['mean_diff']:+.3f} "
                  f"(Inspector minus bag)")
            print(f"    sign test p         {rep['sign_test_p']:.3f}")
            verdict = ("the Inspector does NOT separate itself from a "
                       "~0-parameter order-free baseline"
                       if rep["sign_test_p"] > 0.05 else
                       ("the Inspector genuinely beats the baseline"
                        if rep["mean_diff"] > 0 else
                        "the baseline genuinely BEATS the Inspector"))
            print(f"    -> {verdict} on within-host ranking.")
            out["paired"] = rep
            out["inspector_pooled_auc"] = ipool
            out["inspector_within_host_auc_mean"] = im
            out["inspector_within_host_auc_std"] = is_
            out["verdict"] = verdict
    else:
        print(f"  (no {a.inspector_ckpt}; run train_real.py first for the "
              f"paired comparison)")

    print()
    print("  Caveat that must travel with these numbers: with ~100 positive")
    print("  windows and a per-host AUC spread near 0.27, quote the counts,")
    print("  the spread and the paired test -- never a difference of means.")
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"  wrote {a.out}")


if __name__ == "__main__":
    main()
