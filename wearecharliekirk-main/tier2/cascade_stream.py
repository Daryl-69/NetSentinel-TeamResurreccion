#!/usr/bin/env python3
"""Inspector-Sentry cascade, streamed hour by hour for the live view.

    python cascade_stream.py [--hosts 60] [--days 16] [--tick 0.8]

Builds an organisation (developers, office staff, kiosks, OT panels,
servers, with working hours, weekends and developer look-alikes that walk
the same services as an intruder), commissions the Inspector on its normal
days, distils the Sentry from it, then plays the watched days forward one
hour per tick:

    every host's current hour  -> Sentry scores it (CPU, every window)
    top 5% of the hour         -> escalated to the Inspector
    Inspector reconstruction   -> flagged if above its own 99th percentile

Only hours up to "now" are visible to either model: later hours of the day
are masked out before each forward pass.

Commands on stdin, one per line:
    attack   -- a compromised host starts its kill chain from 08:00 next day
    reset    -- back to benign behaviour
    quit

Output on stdout: one JSON object per line (type: log | stage | ready | hour).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import threading
import time

import numpy as np

from netsentinel_v2 import synth, train as T
from netsentinel_v2.categories import CATEGORIES
from run_experiment import count_params

CHAIN = ["Recon_API", "Code_Repo_Paste", "Messaging_API", "Cloud_Storage"]
ROLE_TAG = {"developer": "dev", "office": "ofc", "kiosk": "ksk", "ot_hmi": "hmi", "ot": "ot", "server": "srv"}


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=60)
    ap.add_argument("--days", type=int, default=16)
    ap.add_argument("--tick", type=float, default=0.8, help="seconds per hour")
    ap.add_argument("--budget", type=float, default=0.05)
    ap.add_argument("--epochs-teacher", type=int, default=8)
    ap.add_argument("--epochs-student", type=int, default=10)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    emit({"type": "stage", "stage": "building", "text": "Building the organisation's traffic profile"})
    d = synth.generate(n_hosts=a.hosts, n_days=a.days, seed=a.seed, hard_negatives=True)
    E, M, A, roles = d["edges"], d["mask"], d["is_attack_day"], d["roles"]
    H, D, W, C, F = E.shape
    names = ["%s-%03d" % (ROLE_TAG.get(str(r), str(r)[:3].strip("_")), h) for h, r in enumerate(roles)]
    c_end, v_start = D // 2, int(D * 0.66)

    Co = T.compute_cohort(E, M)
    flat = lambda X, x, y: X[:, x:y].reshape(-1, *X.shape[2:])
    Ec, Mc, Cc = flat(E, 0, c_end), flat(M, 0, c_end), flat(Co, 0, c_end)
    Ec, mu, sd = T.standardise(Ec, Mc)
    Es_all, *_ = T.standardise(E.reshape(-1, W, C, F), M.reshape(-1, W, C), mu, sd)
    Es_all = Es_all.reshape(H, D, W, C, F)

    emit({"type": "stage", "stage": "commissioning",
          "text": "Commissioning: the Inspector learns each host's normal (%d host-days, no attack labels)" % Ec.shape[0]})
    t0 = time.time()
    with contextlib.redirect_stdout(io.StringIO()):
        insp = T.train_inspector(Ec, Mc, Cc, epochs=a.epochs_teacher, seed=a.seed)
    Zc, Ec_err = T.inspector_forward(insp, Ec, Mc, Cc)
    thr = float(np.quantile(Ec_err, 0.99))
    emit({"type": "log", "text": "Inspector commissioned in %.0fs; alert threshold = 99th percentile of its own error = %.4f"
          % (time.time() - t0, thr)})

    emit({"type": "stage", "stage": "distilling", "text": "Distillation: the Sentry learns the Inspector's encoder"})
    t0 = time.time()
    with contextlib.redirect_stdout(io.StringIO()):
        sen = T.train_sentry(Ec, Mc, Zc, Ec_err, epochs=a.epochs_student, seed=a.seed)
        Zc_s = T.sentry_forward(sen, Ec, Mc)
        head = T.train_head(Zc_s, (Ec_err / (thr + 1e-9)).astype(np.float32), loss="mse", seed=a.seed)
    pi, ps = count_params(insp), count_params(sen)
    emit({"type": "log", "text": "Sentry distilled in %.0fs: %s -> %s parameters (%.1fx smaller)"
          % (time.time() - t0, "{:,}".format(pi), "{:,}".format(ps), pi / ps)})

    # which day each host plays: benign days from the watched period; a
    # compromised host plays a benign day until "attack", then its attack day
    rng = np.random.default_rng(a.seed + 7)
    watched = list(range(v_start, D))
    compromised = [h for h in range(H) if A[h, v_start:].any()]
    target = compromised[0] if compromised else 0
    attack_day = int(v_start + np.argmax(A[target, v_start:])) if compromised else v_start

    def benign_day(h):
        ok = [dd for dd in range(c_end, D) if not A[h, dd]]
        return int(rng.choice(ok)) if ok else 0

    budget_k = max(1, int(round(a.budget * H)))
    emit({"type": "ready", "hosts": [{"id": h, "name": names[h], "role": str(roles[h])} for h in range(H)],
          "threshold": thr, "params": {"inspector": pi, "sentry": ps, "ratio": round(pi / ps, 1)},
          "budget": a.budget, "budget_windows": budget_k, "categories": CATEGORIES, "chain": CHAIN,
          "target": {"id": target, "name": names[target]}})

    cmd = {"attack": False, "pending": False, "reset": False, "quit": False}

    def reader():
        for line in sys.stdin:
            s = line.strip().lower()
            if s == "attack":
                cmd["pending"] = True
            elif s == "reset":
                cmd["reset"] = True
            elif s == "quit":
                cmd["quit"] = True
                break
    threading.Thread(target=reader, daemon=True).start()

    day_n, w = 0, 6
    rows = {h: benign_day(h) for h in range(H)}
    totals = {"scored": 0, "escalated": 0, "confirmed": 0, "hours": 0}
    while not cmd["quit"]:
        if cmd["reset"]:
            cmd.update(reset=False, attack=False)
            rows[target] = benign_day(target)
        if cmd["pending"]:
            cmd.update(pending=False, attack=True)
            day_n += 1
            w = 8
            rows = {h: benign_day(h) for h in range(H)}
            rows[target] = attack_day
            emit({"type": "log", "text": "new traffic on %s" % names[target]})
        t_start = time.time()
        idx = [(h, rows[h]) for h in range(H)]
        e = np.stack([Es_all[h, dd] for h, dd in idx]).copy()
        m = np.stack([M[h, dd] for h, dd in idx]).copy()
        c = np.stack([Co[h, dd] for h, dd in idx]).copy()
        e[:, w + 1:] = 0.0; m[:, w + 1:] = 0.0; c[:, w + 1:] = 0.0      # the future is not visible
        t1 = time.perf_counter()
        s_all = T.head_forward(head, T.sentry_forward(sen, e, m))          # (H, W)
        sentry_ms = (time.perf_counter() - t1) * 1000
        s_now = s_all[:, w]
        live = m[:, w].sum(-1) > 0
        order = [int(h) for h in np.argsort(-np.where(live, s_now, -1e9)) if live[h]][:budget_k]
        t1 = time.perf_counter()
        _, err = T.inspector_forward(insp, e[order], m[order], c[order]) if order else (None, np.zeros((0, W)))
        insp_ms = (time.perf_counter() - t1) * 1000
        verdicts = []
        for j, h in enumerate(order):
            er = float(err[j, w])
            cats = [CATEGORIES[k] for k in range(C) if m[h, w, k] > 0]
            verdicts.append({"host": h, "name": names[h], "score": round(float(s_now[h]), 4),
                             "error": round(er, 5), "flagged": er >= thr, "categories": cats})
        totals["scored"] += int(live.sum()); totals["escalated"] += len(order)
        totals["confirmed"] += sum(1 for v in verdicts if v["flagged"]); totals["hours"] += 1
        tcats = [CATEGORIES[k] for k in range(C) if m[target, w, k] > 0]
        emit({"type": "hour", "day": day_n, "hour": w, "clock": "%02d:00" % w,
              "sentry": [round(float(x), 4) if live[i] else None for i, x in enumerate(s_now)],
              "escalated": order, "verdicts": verdicts, "threshold": thr,
              "attack_active": cmd["attack"], "target": target, "target_categories": tcats,
              "totals": totals, "sentry_ms": round(sentry_ms, 2), "inspector_ms": round(insp_ms, 2),
              "live_hosts": int(live.sum())})
        w += 1
        if w >= W:
            w = 0; day_n += 1
            rows = {h: benign_day(h) for h in range(H)}
            if cmd["attack"]:
                rows[target] = attack_day
        time.sleep(max(0.0, a.tick - (time.time() - t_start)))


if __name__ == "__main__":
    main()
