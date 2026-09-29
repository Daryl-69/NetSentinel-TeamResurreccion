#!/usr/bin/env python3
"""Inspector-Sentry on REAL traffic: commission on the baseline capture, watch
the live network hour by hour, fold the live traffic into the corpus and
retrain itself.

    python inspector_live.py status
    python inspector_live.py import-zeek D:\\capture-zeek --baseline --tz +05:30
    python inspector_live.py train
    python inspector_live.py serve            # started by the sensor, see below

Corpora (tier2/netsentinel_v2/hostwindows.py):
    data/baseline_corpus.sqlite   the team's 20-day capture, hourly windows only
                                  (hosts pseudonymised) -- shipped with the repo
    state/live_corpus.sqlite      every completed hour of the devices THIS sensor
                                  watches; grows while it runs (gitignored)

serve reads JSON lines on stdin from the sensor (netsentinel/inspector.py):
    {"t": "hello", "own_ips": [...], "iface": "eth0"}
    {"t": "flows", "r": [[host, peer, name, ts, dur, up, down], ...]}
    {"t": "cmd", "c": "retrain" | "quit"}
and writes JSON lines on stdout in the same shape as cascade_stream.py
(stage | log | ready | hour), plus "status", so the Sentinel view can show it.

Every `--tick` seconds it scores the current hour of every active device:
    Sentry (every device, CPU)  ->  top `--budget` escalated  ->  Inspector
    reconstruction error vs its commissioned 99th percentile -> flagged
When an hour is over (plus `--grace` minutes for late connections) the hour's
windows are written to the live corpus -- windows the Inspector flagged are
marked and never used for training, so an intrusion in progress is not
learned as normal. Every `--retrain-hours` (and on "retrain") the models are
re-commissioned on baseline + live corpus and hot-swapped.
"""
from __future__ import annotations

import argparse
import contextlib
import glob
import io
import json
import os
import queue
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import numpy as np  # noqa: E402

from netsentinel_v2 import hostwindows as HW  # noqa: E402
from netsentinel_v2.categories import CATEGORIES, N_CATEGORIES, N_EDGE_FEATURES  # noqa: E402

DEFAULT_STATE = os.environ.get("NETSENTINEL_INSPECTOR_STATE", os.path.join(HERE, "state"))
DEFAULT_BASELINE = os.environ.get("NETSENTINEL_BASELINE_CORPUS",
                                  os.path.join(HERE, "data", "baseline_corpus.sqlite"))
W = HW.WINDOWS_PER_DAY
# A model trained on the baseline and committed with the repo (train --publish):
# a fresh install loads it until it has trained on its own traffic.
SHIPPED_MODELS = os.path.join(HERE, "data", "models")


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":"), default=float) + "\n")
    sys.stdout.flush()


def _quiet():
    return contextlib.redirect_stdout(io.StringIO())


# --------------------------------------------------------------------------
# corpora
# --------------------------------------------------------------------------
def open_corpora(state_dir: str, baseline_path: str):
    live = HW.CorpusStore(os.path.join(state_dir, "live_corpus.sqlite"))
    base = HW.CorpusStore(baseline_path, create=False) if os.path.exists(baseline_path) else None
    return base, live


def training_stores(base, live):
    out = []
    if base is not None:
        out.append((base, "base:"))
    out.append((live, "live:"))
    return out


# --------------------------------------------------------------------------
# models
# --------------------------------------------------------------------------
def train_bundle(base, live, epochs_teacher=8, epochs_student=10, live_days=60,
                 seed=0, log=print, exclude_today=True):
    """Commission the Inspector and distil the Sentry on baseline + live corpus."""
    import torch
    from netsentinel_v2 import train as T
    from run_experiment import count_params

    before = {}
    if exclude_today:
        before["live:"] = (HW.local_hour(time.time(), live.tz) // W) * W   # today is incomplete
    # baseline: every day of the capture; live: the most recent `live_days`
    Sb = HW.build_samples([(base, "base:")]) if base is not None else None
    Sl = HW.build_samples([(live, "live:")], max_days=live_days or None, before_lhour=before)
    S = _cat(Sb, Sl)
    if S is None or len(S["host_day"]) < 2:
        raise RuntimeError("not enough traffic to commission the Inspector yet "
                           "(import the baseline capture, or let the sensor run for a day)")
    E, M, Co = S["edges"], S["mask"], S["cohort"]
    n_base = sum(1 for h, _ in S["host_day"] if h.startswith("base:"))
    n_live = len(S["host_day"]) - n_base
    log(f"Commissioning: the Inspector learns each device's normal "
        f"({n_base} baseline + {n_live} live device-days, no attack labels)")
    t0 = time.time()
    Es, mu, sd = T.standardise(E, M)
    with _quiet():
        insp = T.train_inspector(Es, M, Co, epochs=epochs_teacher, seed=seed)
    Z, err = T.inspector_forward(insp, Es, M, Co)
    live_w = M.sum(-1) > 0
    thr = float(np.quantile(err[live_w], 0.99)) if live_w.any() else float(np.quantile(err, 0.99))
    log(f"Inspector commissioned in {time.time() - t0:.0f}s; alert threshold = 99th percentile "
        f"of its own error on real traffic = {thr:.4f}")
    t0 = time.time()
    with _quiet():
        sen = T.train_sentry(Es, M, Z, err, epochs=epochs_student, seed=seed)
        Zs = T.sentry_forward(sen, Es, M)
        head = T.train_head(Zs, (err / (thr + 1e-9)).astype(np.float32), loss="mse", seed=seed)
    pi, ps = count_params(insp), count_params(sen)
    log(f"Sentry distilled in {time.time() - t0:.0f}s: {pi:,} -> {ps:,} parameters ({pi / ps:.1f}x smaller)")
    return {
        "inspector": insp, "sentry": sen, "head": head, "mu": mu, "sd": sd, "thr": thr,
        "meta": {"trained_at": time.time(), "baseline_host_days": n_base, "live_host_days": n_live,
                 "params": {"inspector": pi, "sentry": ps, "ratio": round(pi / ps, 1)},
                 "live_windows_at_train": int(live.summary()["windows"])},
    }


def _cat(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return {k: (np.concatenate([a[k], b[k]]) if k != "host_day" else a[k] + b[k]) for k in a}


def save_bundle(b, state_dir, keep=5) -> str:
    import torch
    d = os.path.join(state_dir, "models")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "inspector-%s.pt" % time.strftime("%Y%m%d-%H%M%S"))
    torch.save({"inspector": b["inspector"].state_dict(), "sentry": b["sentry"].state_dict(),
                "head": b["head"].state_dict(), "head_din": b["head"].net[0].in_features,
                "mu": b["mu"], "sd": b["sd"], "thr": b["thr"], "meta": b["meta"]}, path)
    with open(os.path.join(d, "current.json"), "w") as f:
        json.dump({"path": os.path.basename(path), "meta": b["meta"], "thr": b["thr"]}, f, indent=1)
    for old in sorted(glob.glob(os.path.join(d, "inspector-*.pt")))[:-keep]:
        os.remove(old)
    return path


def publish_bundle(b, models_dir=SHIPPED_MODELS) -> str:
    """Write the model where git tracks it (tier2/data/models/)."""
    import torch
    os.makedirs(models_dir, exist_ok=True)
    path = os.path.join(models_dir, "inspector_baseline.pt")
    torch.save({"inspector": b["inspector"].state_dict(), "sentry": b["sentry"].state_dict(),
                "head": b["head"].state_dict(), "head_din": b["head"].net[0].in_features,
                "mu": b["mu"], "sd": b["sd"], "thr": b["thr"], "meta": b["meta"]}, path)
    with open(os.path.join(models_dir, "current.json"), "w") as f:
        json.dump({"path": os.path.basename(path), "meta": b["meta"], "thr": b["thr"]}, f, indent=1)
    return path


def load_bundle(state_dir, shipped_dir=SHIPPED_MODELS):
    """This machine's latest model (state/models), else the shipped one."""
    import torch
    from netsentinel_v2.models import Inspector, Sentry
    from netsentinel_v2 import train as T
    p = None
    for d in (os.path.join(state_dir, "models"), shipped_dir):
        cur = os.path.join(d, "current.json")
        if os.path.exists(cur):
            with open(cur) as f:
                cand = os.path.join(d, json.load(f)["path"])
            if os.path.exists(cand):
                p = cand
                break
    if p is None:
        return None
    ck = torch.load(p, map_location="cpu", weights_only=False)
    insp, sen = Inspector(dim=96), Sentry(dim=32, teacher_dim=96)
    insp.load_state_dict(ck["inspector"]); sen.load_state_dict(ck["sentry"])
    head = T.Head(ck["head_din"], 0); head.load_state_dict(ck["head"])
    for m in (insp, sen, head):
        m.eval()
    return {"inspector": insp, "sentry": sen, "head": head, "mu": ck["mu"], "sd": ck["sd"],
            "thr": float(ck["thr"]), "meta": dict(ck["meta"], source=os.path.relpath(p, HERE))}


def score_hour(bundle, hosts, rows, w_now, budget_k):
    """Score hour `w_now` of one local day for `hosts`.

    rows: [(host, lhour, cat, n, f)] for that day (hours <= w_now).
    Returns (sentry score per host or None, escalated host list, {host: error}).
    """
    from netsentinel_v2 import train as T
    H = len(hosts)
    hi = {h: i for i, h in enumerate(hosts)}
    E = np.zeros((H, 1, W, N_CATEGORIES, N_EDGE_FEATURES), np.float32)
    M = np.zeros((H, 1, W, N_CATEGORIES), np.float32)
    for h, lh, c, _n, f in rows:
        w = lh % W
        if h in hi and w <= w_now:
            E[hi[h], 0, w, c] = f
            M[hi[h], 0, w, c] = 1.0
    Co = HW.compute_cohort(E, M)[:, 0]
    E, M = E[:, 0], M[:, 0]
    Es, _, _ = T.standardise(E, M, bundle["mu"], bundle["sd"])
    live = M[:, w_now].sum(-1) > 0
    t1 = time.perf_counter()
    s_all = T.head_forward(bundle["head"], T.sentry_forward(bundle["sentry"], Es, M))
    sentry_ms = (time.perf_counter() - t1) * 1000
    s_now = s_all[:, w_now]
    order = [int(i) for i in np.argsort(-np.where(live, s_now, -1e9)) if live[i]][:budget_k]
    errs = {}
    t1 = time.perf_counter()
    if order:
        _, err = T.inspector_forward(bundle["inspector"], Es[order], M[order], Co[order])
        errs = {hosts[i]: float(err[j, w_now]) for j, i in enumerate(order)}
    insp_ms = (time.perf_counter() - t1) * 1000
    scores = [float(s_now[i]) if live[i] else None for i in range(H)]
    cats = {hosts[i]: [CATEGORIES[k] for k in range(N_CATEGORIES) if M[i, w_now, k] > 0] for i in range(H)}
    return scores, [hosts[i] for i in order], errs, cats, sentry_ms, insp_ms


# --------------------------------------------------------------------------
# serve
# --------------------------------------------------------------------------
class Service:
    def __init__(self, a):
        self.a = a
        self.base, self.live = open_corpora(a.state, a.baseline)
        self.agg = HW.WindowAggregator(self.live.tz)
        self.lock = threading.Lock()
        self.bundle = None
        self.training = False
        self.train_error = None
        self.own_ips: set = set()
        self.iface = None
        self.hosts: list[str] = []            # id -> host (only ever appended)
        self.meta_version = 0
        self.flows_in = 0
        self.totals = {"scored": 0, "escalated": 0, "confirmed": 0, "hours": 0}
        self.day0 = HW.local_hour(time.time(), self.live.tz) // W
        self.last_retrain_check = 0.0
        self.fail_windows = -1                # live corpus size at the last failed attempt
        self.q: queue.Queue = queue.Queue()

    # ---- host registry
    def _name(self, h):
        tag = "you" if h in self.own_ips else "lan"
        tail = h.rsplit(".", 1)[-1] if "." in h else h.replace(":", "")[-4:]
        return f"{tag}-{tail}"

    def _register(self, hs):
        new = [h for h in hs if h not in self.hosts]
        if new:
            self.hosts.extend(sorted(new))
            self._ready()

    def _ready(self):
        self.meta_version += 1
        b = self.bundle
        target = next((i for i, h in enumerate(self.hosts) if h in self.own_ips), 0 if self.hosts else None)
        emit({"type": "ready", "mode": "real", "version": self.meta_version,
              "hosts": [{"id": i, "name": self._name(h), "role": "you" if h in self.own_ips else "lan", "ip": h}
                        for i, h in enumerate(self.hosts)],
              "threshold": b["thr"] if b else None,
              "params": b["meta"]["params"] if b else None,
              "budget": self.a.budget, "categories": CATEGORIES, "chain": [],
              "target": ({"id": target, "name": self._name(self.hosts[target])} if target is not None else None)})

    # ---- training
    def _train(self, reason):
        if self.training:
            return
        self.training = True

        def run():
            try:
                emit({"type": "stage", "stage": "commissioning",
                      "text": f"Training ({reason}) on baseline + live corpus"})
                b = train_bundle(self.base, self.live, self.a.epochs_teacher, self.a.epochs_student,
                                 self.a.live_days, log=lambda t: emit({"type": "log", "text": t}))
                path = save_bundle(b, self.a.state)
                with self.lock:
                    self.bundle = b
                    self.train_error = None
                emit({"type": "log", "text": f"New Inspector/Sentry live ({os.path.basename(path)})"})
                emit({"type": "stage", "stage": "watching", "text": "Watching real traffic"})
                self._ready()
            except Exception as e:
                self.train_error = str(e)
                self.fail_windows = self.live.summary()["windows"]
                emit({"type": "log", "text": f"Training skipped: {e}"})
                if self.bundle is None:
                    emit({"type": "stage", "stage": "collecting",
                          "text": "Collecting traffic until there is enough to commission the Inspector"})
            finally:
                self.training = False
        threading.Thread(target=run, daemon=True, name="inspector-train").start()

    def _maybe_retrain(self):
        now = time.time()
        if now - self.last_retrain_check < 60:
            return
        self.last_retrain_check = now
        b = self.bundle
        if b is None:
            if not self.training and self.train_error is None:
                self._train("first commissioning")
            elif self.train_error and self.live.summary()["windows"] > self.fail_windows:
                self._train("retry with new live traffic")
            return
        age_h = (now - b["meta"]["trained_at"]) / 3600
        grown = self.live.summary()["windows"] - b["meta"].get("live_windows_at_train", 0)
        if age_h >= self.a.retrain_hours and grown > 0:
            self._train(f"scheduled, {grown} new live windows")

    # ---- traffic
    def _on_msg(self, m):
        t = m.get("t")
        if t == "flows":
            for r in m.get("r", []):
                try:
                    self.agg.add(HW.FlowRecord(str(r[0]), str(r[1]), r[2] or None, float(r[3]),
                                               float(r[4]), float(r[5]), float(r[6])))
                    self.flows_in += 1
                except (IndexError, TypeError, ValueError):
                    pass
        elif t == "hello":
            self.own_ips = set(m.get("own_ips") or [])
            self.iface = m.get("iface")
            if self.hosts:
                self._ready()
        elif t == "cmd":
            c = m.get("c")
            if c == "retrain":
                self._train("requested")
            elif c == "quit":
                raise SystemExit(0)

    def _day_rows(self, lday, upto_lhour, extra):
        rows = self.live.rows(lhour_from=lday * W, lhour_to=upto_lhour, include_flagged=True)
        return [r[:5] for r in rows] + list(extra)

    def _score(self, lhour, extra, final):
        b = self.bundle
        hosts_now = sorted({r[0] for r in extra})
        if not hosts_now:
            return
        self._register(hosts_now)
        if b is None:
            return
        lday, w = divmod(lhour, W)
        rows = self._day_rows(lday, lhour, extra)
        day_hosts = sorted({r[0] for r in rows})
        k = max(1, int(round(self.a.budget * len(hosts_now))))
        scores, esc, errs, cats, s_ms, i_ms = score_hour(b, day_hosts, rows, w, k)
        by_host = dict(zip(day_hosts, scores))
        flagged = [h for h, e in errs.items() if e >= b["thr"]]
        verdicts = [{"host": self.hosts.index(h), "name": self._name(h), "ip": h,
                     "score": round(by_host[h], 4), "error": round(errs[h], 5),
                     "flagged": errs[h] >= b["thr"], "categories": cats[h]} for h in esc]
        live_n = sum(1 for s in scores if s is not None)
        tot = dict(self.totals)
        tot["scored"] += live_n; tot["escalated"] += len(esc); tot["confirmed"] += len(flagged); tot["hours"] += 1
        if final:
            self.totals = tot
        target = next((i for i, h in enumerate(self.hosts) if h in self.own_ips), 0)
        th = self.hosts[target] if self.hosts else None
        lt = time.gmtime(lhour * 3600)
        emit({"type": "hour", "mode": "real", "final": final, "day": lday - self.day0, "hour": w,
              "clock": time.strftime("%H:00", lt) if final else
                       time.strftime("%H:%M", time.gmtime(time.time() + self.live.tz)),
              "date": time.strftime("%Y-%m-%d", lt),
              "sentry": [round(by_host[h], 4) if by_host.get(h) is not None else None for h in self.hosts],
              "escalated": [self.hosts.index(h) for h in esc], "verdicts": verdicts,
              "threshold": b["thr"], "attack_active": False, "target": target,
              "target_categories": cats.get(th, []), "totals": tot,
              "sentry_ms": round(s_ms, 2), "inspector_ms": round(i_ms, 2), "live_hosts": live_n})
        return flagged

    def tick(self):
        now = time.time()
        # close finished hours (grace for connections that end late)
        close_upto = HW.local_hour(now - self.a.grace * 60, self.live.tz)
        closed = self.agg.pop_before(close_upto)
        if closed:
            by_hour = {}
            for r in closed:
                by_hour.setdefault(r[1], []).append(r)
            for lh in sorted(by_hour):
                flagged = []
                with self.lock:
                    try:
                        flagged = self._score(lh, by_hour[lh], final=True) or []
                    except Exception as e:
                        emit({"type": "log", "text": f"scoring failed for hour {lh % W}:00: {e}"})
                self.live.put(by_hour[lh], flagged=[(h, lh) for h in flagged])
                emit({"type": "log", "text": "%s %02d:00 closed: %d device(s), %d window(s) added to the "
                      "live corpus%s" % (time.strftime("%Y-%m-%d", time.gmtime(lh * 3600)), lh % W,
                                         len({r[0] for r in by_hour[lh]}), len(by_hour[lh]),
                                         f", {len(flagged)} flagged (kept out of training)" if flagged else "")})
        # score the hour in progress
        cur = HW.local_hour(now, self.live.tz)
        rows = self.agg.rows_for_hour(cur)
        with self.lock:
            try:
                self._score(cur, rows, final=False)
            except Exception as e:
                emit({"type": "log", "text": f"scoring failed: {e}"})
        self._maybe_retrain()
        emit(self._status())

    def _status(self):
        b = self.bundle
        return {"type": "status", "flows_in": self.flows_in, "devices": len(self.hosts),
                "training": self.training, "train_error": self.train_error,
                "model": None if b is None else {**b["meta"], "threshold": b["thr"]},
                "baseline": self.base.summary() if self.base is not None else None,
                "live": self.live.summary(), "retrain_hours": self.a.retrain_hours,
                "iface": self.iface}

    def run(self):
        emit({"type": "stage", "stage": "building", "text": "Loading the Inspector for real traffic"})
        try:
            self.bundle = load_bundle(self.a.state)
        except Exception as e:
            emit({"type": "log", "text": f"Could not load the saved model ({e}); retraining"})
        if self.base is None:
            emit({"type": "log", "text": f"No baseline corpus at {self.a.baseline} -- training on live traffic only"})
        else:
            s = self.base.summary()
            emit({"type": "log", "text": f"Baseline corpus: {s['host_days']} device-days over "
                  f"{s['days_spanned']} days ({s['first_day']} .. {s['last_day']})"})
        if self.bundle is not None:
            m = self.bundle["meta"]
            emit({"type": "log", "text": "Loaded Inspector trained %s on %d baseline + %d live device-days"
                  % (time.strftime("%Y-%m-%d %H:%M", time.localtime(m["trained_at"])),
                     m["baseline_host_days"], m["live_host_days"])})
            emit({"type": "stage", "stage": "watching", "text": "Watching real traffic"})
        else:
            self._train("first commissioning")
        self._ready()

        def reader():
            for line in sys.stdin:
                line = line.strip()
                if line:
                    try:
                        self.q.put(json.loads(line))
                    except ValueError:
                        pass
            self.q.put({"t": "cmd", "c": "quit"})
        threading.Thread(target=reader, daemon=True).start()

        next_tick = time.time() + 1.0
        while True:
            try:
                m = self.q.get(timeout=max(0.05, next_tick - time.time()))
                self._on_msg(m)
            except queue.Empty:
                pass
            except SystemExit:
                break
            if time.time() >= next_tick:
                self.tick()
                next_tick = time.time() + self.a.tick
        # flush what we have so a restart does not lose the partial hour's context
        rest = self.agg.pop_before(HW.local_hour(time.time(), self.live.tz))
        if rest:
            self.live.put(rest)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--baseline", default=DEFAULT_BASELINE)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--tick", type=float, default=30.0, help="seconds between scoring passes")
    s.add_argument("--grace", type=float, default=7.0, help="minutes after an hour ends before it is closed")
    s.add_argument("--budget", type=float, default=0.05)
    s.add_argument("--retrain-hours", type=float, default=24.0)
    s.add_argument("--live-days", type=int, default=60, help="most recent live days used for training")
    s.add_argument("--epochs-teacher", type=int, default=8)
    s.add_argument("--epochs-student", type=int, default=10)

    t = sub.add_parser("train")
    t.add_argument("--live-days", type=int, default=60)
    t.add_argument("--epochs-teacher", type=int, default=8)
    t.add_argument("--epochs-student", type=int, default=10)
    t.add_argument("--publish", action="store_true",
                   help="also write tier2/data/models/inspector_baseline.pt (committed with the repo)")

    sub.add_parser("status")

    z = sub.add_parser("import-zeek", help="Zeek logs (zeekify.sh output) -> corpus")
    z.add_argument("root")
    z.add_argument("--baseline", dest="to_baseline", action="store_true",
                   help="write the shipped baseline corpus (hosts pseudonymised) instead of the live corpus")
    z.add_argument("--tz", default=None, help="capture site's UTC offset, e.g. +05:30 (default: this machine)")
    z.add_argument("--local-ip", action="append", default=[],
                   help="address of a monitored device that is not RFC1918/ULA (e.g. its global IPv6)")
    a = ap.parse_args()

    try:
        import torch
        torch.set_num_threads(max(1, (os.cpu_count() or 2) // 2))
    except ImportError:
        if a.cmd in ("serve", "train"):
            emit({"type": "log", "text": "Missing dependency: torch (pip install torch --index-url "
                  "https://download.pytorch.org/whl/cpu)"})
            sys.exit(2)

    if a.cmd == "serve":
        Service(a).run()
    elif a.cmd == "train":
        base, live = open_corpora(a.state, a.baseline)
        b = train_bundle(base, live, a.epochs_teacher, a.epochs_student, a.live_days, exclude_today=False)
        print("saved", save_bundle(b, a.state))
        if a.publish:
            print("published", publish_bundle(b), "-- commit tier2/data/ to ship it")
    elif a.cmd == "status":
        base, live = open_corpora(a.state, a.baseline)
        cur = os.path.join(a.state, "models", "current.json")
        print(json.dumps({"baseline": base.summary() if base else None, "live": live.summary(),
                          "model": json.load(open(cur)) if os.path.exists(cur) else None}, indent=1))
    elif a.cmd == "import-zeek":
        print(json.dumps(import_zeek(a.root, a.to_baseline, a.tz, a.local_ip, a.state, a.baseline), indent=1))


def import_zeek(root, to_baseline, tz, local_ips, state_dir=DEFAULT_STATE, baseline_path=DEFAULT_BASELINE):
    path = baseline_path if to_baseline else os.path.join(state_dir, "live_corpus.sqlite")
    store = HW.CorpusStore(path, tz_offset=HW.parse_tz(tz) if (tz or not os.path.exists(path)) else None)
    print(f"  importing {root} -> {path}  (tz offset {store.tz:+d}s)", flush=True)
    res = HW.ingest(HW.records_from_zeek(root, local_ips,
                                         progress=lambda i, n, d: print(f"    [{i}/{n}] {os.path.basename(d)}", flush=True)
                                         if i % 24 == 0 or i == n else None), store)
    if to_baseline:
        pseudonymise(store)
    res["corpus"] = store.summary()
    return res


def pseudonymise(store):
    """Shipped baseline: replace device addresses with dev-01, dev-02, ..."""
    hosts = [h for (h,) in store.db.execute("SELECT DISTINCT host FROM windows ORDER BY host")]
    real = [h for h in hosts if not h.startswith("dev-")]
    n0 = len(hosts) - len(real)
    store.rename_hosts({h: "dev-%02d" % (n0 + i + 1) for i, h in enumerate(real)})


if __name__ == "__main__":
    main()
