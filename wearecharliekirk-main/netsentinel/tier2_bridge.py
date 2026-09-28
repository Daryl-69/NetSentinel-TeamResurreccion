"""Tier 2 (Inspector–Sentry) as seen from the Tier 1 sensor.

Tier 2 lives in ``tier2/``: a behavioural track that reasons about how a
host's mix of services changes over days. It is verified standalone
(``python tier2/verify_all.py``) and NOT wired into the live analyzer: the
Inspector needs a commissioning window of days per site before it can score.

What this module gives the console:

* ``status()`` — whether the track is present, which Python would run it and
  whether that Python has PyTorch, the headline numbers re-derived from the
  track's own result files at request time (numpy only, no torch), and its
  charts.
* a runner for ``tier2/demo_scenario.py``: the whole cascade — commissioning,
  distillation, steady state, escalation — end to end on a synthetic
  organisation in about a minute on CPU, streamed line by line.

Nothing here changes a Tier 2 result. Every number carries its source file
and the documented value it is checked against.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

REPO = Path(__file__).resolve().parent.parent
TIER2 = REPO / "tier2"


# ----------------------------------------------------------------- python
def tier2_python() -> str:
    """The interpreter that runs Tier 2: $NETSENTINEL_TIER2_PYTHON, else a
    virtualenv inside tier2/, else the one in ../netsentinel-main/v2/ where
    the track was developed, else the sensor's own Python."""
    env = os.getenv("NETSENTINEL_TIER2_PYTHON")
    if env:
        return env
    exe = "Scripts/python.exe" if os.name == "nt" else "bin/python"
    for p in (TIER2 / ".venv" / exe, TIER2 / "venv" / exe,
              # the Tier 2 track was developed in ../netsentinel-main/v2,
              # whose virtualenv already has PyTorch on the team's machine
              REPO.parent / "netsentinel-main" / "v2" / ".venv" / exe):
        if p.exists():
            return str(p)
    return sys.executable


_TORCH: dict = {}


def torch_available(refresh: bool = False) -> dict:
    py = tier2_python()
    if not refresh and _TORCH.get("python") == py:
        return _TORCH
    ok, detail = False, ""
    try:
        r = subprocess.run([py, "-c", "import torch, numpy, scipy, sklearn; print(torch.__version__)"],
                           capture_output=True, text=True, timeout=90)
        ok = r.returncode == 0
        detail = (r.stdout or r.stderr).strip().splitlines()[-1][:200] if (r.stdout or r.stderr) else ""
    except Exception as e:                                   # pragma: no cover - environment
        detail = str(e)[:200]
    _TORCH.clear()
    _TORCH.update(python=py, ok=ok, detail=detail, checked_at=time.time())
    return _TORCH


# ---------------------------------------------------------------- numbers
def _load(name: str):
    try:
        with open(TIER2 / name, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _mean(xs):
    xs = list(xs)
    return sum(xs) / len(xs) if xs else float("nan")


def _sd(xs):
    xs = list(xs)
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return (sum((x - m) ** 2 for x in xs) / len(xs)) ** 0.5     # population sd, as tier2 prints it


def _row(label, value, display, source, note="", doc=None, tol=None, lo=None, hi=None):
    if doc is not None and tol is not None:
        status = "matches" if abs(value - doc) <= tol else "differs"
    elif lo is not None and hi is not None:
        status = "matches" if lo <= value <= hi else "differs"
    else:
        status = "reported"
    return {"label": label, "value": value, "display": display, "source": source, "note": note,
            "documented": doc if doc is not None else ([lo, hi] if lo is not None else None),
            "status": status}


def headline_numbers() -> list:
    """Groups of headline numbers, re-derived from tier2/*.json the way
    tier2/verify_all.py does, with the documented value each is checked
    against."""
    groups = []

    d = _load("lanl_novelty.json")
    if d:
        runs = d["runs"]

        def at5(lbl, key):
            return _mean([[b for b in r["curves"][lbl] if abs(b["budget"] - 0.05) < 1e-9][0][key] for r in runs])

        within = [r["oracle"]["within_host_auc_mean"] for r in runs]
        rows = [
            _row("Sentry agreement with the Inspector (router AUC)",
                 _mean(r["router_auc"]["A_distilled_detector"] for r in runs),
                 "%.3f" % _mean(r["router_auc"]["A_distilled_detector"] for r in runs),
                 "lanl_novelty.json", "how well the small model ranks host-windows the way the big one would",
                 doc=0.992, tol=0.0015),
            _row("Inspector flags recovered at a 5% escalation budget", at5("A_distilled_detector", "recall_teacher"),
                 "%.1f%%" % (100 * at5("A_distilled_detector", "recall_teacher")), "lanl_novelty.json",
                 "of what the Inspector would have flagged — not a detection rate", doc=0.969, tol=0.0015),
            _row("Attack windows reaching the Inspector at that budget", at5("A_distilled_detector", "recall_attack"),
                 "%.1f%%" % (100 * at5("A_distilled_detector", "recall_attack")), "lanl_novelty.json",
                 "red-team windows among the 5% escalated", doc=0.356, tol=0.0015),
            _row("Inspector AUC against attack windows, pooled",
                 _mean(r["oracle"]["auc_vs_attack_window"] for r in runs),
                 "%.3f" % _mean(r["oracle"]["auc_vs_attack_window"] for r in runs), "lanl_novelty.json",
                 "partly separates attacked hosts from others", doc=0.745, tol=0.0015),
            _row("Inspector AUC within a host (the weakest number)", _mean(within),
                 "%.3f ± %.3f" % (_mean(within), _sd(within)), "lanl_novelty.json",
                 "near chance: on real data it does not yet tell a host's attack hours from its normal ones",
                 doc=0.557, tol=0.0015),
        ]
        groups.append({"title": "Real traffic — LANL cyber1, %s hosts × %s days, %s seeds" % (
            d.get("hosts"), d.get("days"), d.get("seeds")), "kind": "real", "rows": rows})

    r8 = _load("results_8seed.json")
    if r8:
        ra = r8.get("router_auc", {})
        p = r8.get("params", {})
        cfg = r8.get("config", {})
        rows = [
            _row("Inspector AUC against attack windows", r8.get("oracle_auc", float("nan")),
                 "%.3f" % r8.get("oracle_auc", float("nan")), "results_8seed.json",
                 "indicative only: the generator made the attacks it is scored on", doc=0.875, tol=0.002),
            _row("Router AUC against the Inspector: A distilled / B Mahalanobis / C deferral",
                 ra.get("A_distilled_detector", float("nan")),
                 "%.3f / %.3f / %.3f" % (ra.get("A_distilled_detector", 0), ra.get("B_encoder_mahalanobis", 0),
                                         ra.get("C_deferral_head", 0)),
                 "results_8seed.json", "no pair is separable at 8 seeds", doc=0.833, tol=0.002),
            _row("Model size, Inspector → Sentry", p.get("compression", float("nan")),
                 "{:,} → {:,} parameters ({:.1f}×)".format(p.get("inspector", 0), p.get("sentry", 0),
                                                           p.get("compression", 0)),
                 "results_8seed.json", "a size ratio, not a speed-up", doc=13.7, tol=0.05),
        ]
        groups.append({"title": "Synthetic organisation — %s seeds, %s hosts × %s days" % (
            cfg.get("seeds"), cfg.get("hosts"), cfg.get("days")), "kind": "synthetic", "rows": rows})

    e = _load("escalate.json")
    if e:
        frac = e["host_days_inspected"] / e["host_days_total"]
        rows = [
            _row("Sentry vs Inspector scoring speed on CPU", e["sentry_speedup"], "%.1f×" % e["sentry_speedup"],
                 "escalate.json", "wall-clock on a shared machine; varies with load", lo=5.0, hi=12.0),
            _row("Host-days that woke the Inspector at a 5% budget", frac, "%.1f%%" % (100 * frac), "escalate.json",
                 "the rest were settled by the Sentry alone", doc=0.487, tol=0.02),
            _row("Escalated host-days the Inspector confirmed", e["confirm_precision"],
                 "%.1f%%" % (100 * e["confirm_precision"]), "escalate.json", "", doc=0.127, tol=0.01),
        ]
        groups.append({"title": "Cost of the cascade — synthetic, %s hosts × %s days" % (e.get("hosts"), e.get("days")),
                       "kind": "synthetic", "rows": rows})

    a = _load("ablation_order_hard.json")
    if a:
        m = a["mean_std"]
        rows = [
            _row("Hours in order / hours shuffled / bag of categories",
                 m["D_bag_of_categories"][0],
                 "%.3f / %.3f / %.3f" % (m["A_full"][0], m["B_shuffled_at_score"][0], m["D_bag_of_categories"][0]),
                 "ablation_order_hard.json",
                 "the order of the hours adds nothing: it reads the combination and shape of services, not a sequence",
                 doc=1.000, tol=0.0015),
            _row("Reverse direction removed (what a one-way link shows)", m["F_no_reverse_direction"][0],
                 "%.3f" % m["F_no_reverse_direction"][0], "ablation_order_hard.json",
                 "costs about 0.001 AUC against the full two-way view", doc=0.996, tol=0.0015),
        ]
        groups.append({"title": "What the model reads — synthetic, hard setting", "kind": "synthetic", "rows": rows})

    t = _load("telegram_c2.json")
    b = _load("bench_evasion.json")
    if t:
        fr, lad = t["frontier"], t["ladder"]["rungs"]
        rows = [
            _row("Per-window AUC: commodity implant → full mimicry", lad[-1]["per_window_auc_best"],
                 "%.2f → %.2f" % (lad[0]["per_window_auc_best"], lad[-1]["per_window_auc_best"]), "telegram_c2.json",
                 "a perfect mimic cannot be caught in one window, and this says so", lo=0.0, hi=0.75),
            _row("CUSUM floor: smallest exfiltration caught before a false alarm", fr["floor_kb_per_day"],
                 "%.1f KB/day (false alarm every %.0f days)" % (fr["floor_kb_per_day"], fr["arl0_measured_days"]),
                 "telegram_c2.json", "bigger footprints are caught sooner; below the floor, no faster than chance",
                 lo=0.0, hi=1e9),
        ]
        if b and "joint" in b:
            rows.append(_row("Cross-service correlation under marginal mimicry", b["joint"]["auc_mean"],
                             "AUC %.3f" % b["joint"]["auc_mean"], "bench_evasion.json",
                             "matching each service's volume does not match how they move together",
                             lo=0.95, hi=1.0))
        groups.append({"title": "Telegram C2 — bounded, not solved (synthetic)", "kind": "synthetic", "rows": rows})
    return groups


def figures() -> list:
    out = []
    for name, caption in (("chart_escalation_budget.png",
                           "Recall of Inspector-flagged windows against the escalation budget, three routers, "
                           "mean ± 1 sd over 3 seeds (synthetic)"),
                          ("chart_geometry_diagnostic.png",
                           "Does the Sentry keep the Inspector's local geometry? kNN overlap 0.38: marginal")):
        if (TIER2 / name).exists():
            out.append({"name": name, "url": "/api/figures/tier2/" + name, "caption": caption})
    return out


def status(check_torch: bool = True) -> dict:
    present = TIER2.is_dir() and (TIER2 / "demo_scenario.py").exists()
    return {
        "present": present,
        "path": "tier2/",
        "wired_into_live_pipeline": False,
        "why_not_wired": ("The Inspector learns each host's normal over a commissioning window of days on the "
                          "site's own traffic; the live analyzer has no such window yet. Tier 2 runs and is "
                          "verified on its own: python tier2/verify_all.py."),
        "python": tier2_python(),
        "torch": torch_available() if (present and check_torch) else None,
        "numbers": headline_numbers() if present else [],
        "figures": figures() if present else [],
        "demo": DEMO.snapshot(0),
    }


# ------------------------------------------------------------------ runner
_RESULT_PATTERNS = {
    "router_auc": r"Sentry agreement with the Inspector \(AUC\)\s+([0-9.]+)",
    "recovered_pct": r"Inspector flags recovered at \d+% budget\s+([0-9.]+)%",
    "never_woken_pct": r"Host-days the Inspector never had to see\s+([0-9.]+)%",
    "params": r"Model size\s+([\d,]+) -> ([\d,]+)\s+\(([0-9.]+)x\)",
    "attack_windows": r"Attack windows present in the test period\s+(\d+)",
    "attack_reached": r"reached the Inspector via escalation\s+(\d+)\s+\((\d+)%\)",
    "runtime_s": r"total runtime (\d+)s",
    "scored_windows": r"scored ([\d,]+) live windows in ([0-9.]+)s \(([\d,]+) windows/s\)",
}


def parse_demo(text: str) -> dict:
    out = {}
    for k, pat in _RESULT_PATTERNS.items():
        m = re.search(pat, text)
        if m:
            out[k] = [g.replace(",", "") for g in m.groups()] if len(m.groups()) > 1 else m.group(1)
    return out


class DemoRunner:
    """Runs tier2/demo_scenario.py in a subprocess and keeps its output."""

    def __init__(self):
        self.lock = threading.Lock()
        self.lines: list[str] = []
        self.status = "idle"            # idle | running | done | error
        self.error: Optional[str] = None
        self.started: Optional[float] = None
        self.finished: Optional[float] = None
        self.fast = False
        self.returncode: Optional[int] = None
        self._proc: Optional[subprocess.Popen] = None

    def snapshot(self, since: int = 0) -> dict:
        with self.lock:
            text = "\n".join(self.lines)
            return {"status": self.status, "error": self.error, "fast": self.fast,
                    "started": self.started, "finished": self.finished, "returncode": self.returncode,
                    "n_lines": len(self.lines), "lines": self.lines[since:] if since >= 0 else [],
                    "result": parse_demo(text) if self.status in ("done", "error") else {}}

    def start(self, fast: bool = True) -> dict:
        with self.lock:
            if self.status == "running":
                return {"error": "The cascade demo is already running"}
            if not (TIER2 / "demo_scenario.py").exists():
                return {"error": "tier2/demo_scenario.py not found"}
            self.lines, self.status, self.error = [], "running", None
            self.started, self.finished, self.returncode, self.fast = time.time(), None, None, bool(fast)
        threading.Thread(target=self._run, args=(fast,), daemon=True, name="tier2-demo").start()
        return {"status": "started", "fast": bool(fast), "python": tier2_python()}

    def _run(self, fast: bool):
        cmd = [tier2_python(), "-u", "demo_scenario.py", "--quiet"] + (["--fast"] if fast else [])
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        try:
            proc = subprocess.Popen(cmd, cwd=str(TIER2), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace", bufsize=1, env=env)
            self._proc = proc
            for line in proc.stdout:                                  # type: ignore[union-attr]
                with self.lock:
                    self.lines.append(line.rstrip("\n"))
                    if len(self.lines) > 3000:
                        del self.lines[:500]
            rc = proc.wait(timeout=900)
            with self.lock:
                self.returncode = rc
                self.status = "done" if rc == 0 else "error"
                if rc != 0:
                    tail = " ".join(self.lines[-3:])
                    self.error = ("PyTorch is not installed for %s. Install it (pip install torch --index-url "
                                  "https://download.pytorch.org/whl/cpu) or set NETSENTINEL_TIER2_PYTHON."
                                  % tier2_python()) if "Missing dependency" in tail else ("exit code %d" % rc)
        except Exception as e:                                          # pragma: no cover - environment
            with self.lock:
                self.status, self.error = "error", str(e)[:300]
        finally:
            with self.lock:
                self.finished = time.time()


DEMO = DemoRunner()


# ------------------------------------------------------------------ figures
FIGURE_DIRS = {
    "tier2": TIER2,
    "ddos": REPO / "models" / "Ddos_detection",
    "c2": REPO / "models" / "c2_beacon_detector",
    "dga": REPO / "models" / "dga_dna_tunneling_detection",
    "ett": REPO / "models" / "encrypted_traffic_transformer",
    "portscan": REPO / "models" / "portscan",
    "docs": REPO / "docs" / "figures",
}


def figure_path(group: str, name: str) -> Optional[Path]:
    """A PNG from one of the known figure folders, or None. Only bare file
    names ending in .png are served."""
    base = FIGURE_DIRS.get(group)
    if base is None or not re.fullmatch(r"[A-Za-z0-9_.\-]+\.png", name or ""):
        return None
    p = (base / name).resolve()
    try:
        p.relative_to(base.resolve())
    except ValueError:
        return None
    return p if p.is_file() else None


MODEL_FIGURES = [
    ("ddos", "binary_confusion_matrix.png", "DDoS XGBoost — binary confusion matrix (CIC-DDoS2019 test split)"),
    ("ddos", "multi_confusion_matrix.png", "DDoS — 18-class confusion matrix (macro F1 0.55: a hint only)"),
    ("ddos", "feature_importance.png", "DDoS XGBoost — feature importance"),
    ("ddos", "shap_summary.png", "DDoS XGBoost — SHAP summary"),
    ("c2", "c2_confusion_matrix.png", "C2 BiLSTM+FFT — confusion matrix (its own test split)"),
    ("c2", "c2_training_curves.png", "C2 BiLSTM+FFT — training curves"),
    ("dga", "dga_confusion_matrix.png", "DGA CNN-BiLSTM — confusion matrix (tunnel class synthetic)"),
    ("dga", "dga_training_curves.png", "DGA CNN-BiLSTM — training curves"),
    ("ett", "confusion_matrix.png", "Encrypted-traffic FT-Transformer — 14-class confusion matrix"),
    ("ett", "training_curves.png", "Encrypted-traffic FT-Transformer — training curves"),
    ("portscan", "portscan_evaluation.png",
     "Port scan — the legacy per-flow XGBoost on CIC-IDS2017 (kept as a score; the SPSD tree decides)"),
]


def docs_figures() -> list:
    """Charts made from this repository's own result files (docs/figures/index.json)."""
    try:
        with open(FIGURE_DIRS["docs"] / "index.json", encoding="utf-8") as fh:
            items = json.load(fh)
    except Exception:
        return []
    return [dict(it, url="/api/figures/docs/" + it["name"]) for it in items
            if figure_path("docs", it.get("name", "")) is not None]


def model_figures() -> list:
    return [{"group": g, "name": n, "caption": c, "url": "/api/figures/%s/%s" % (g, n)}
            for g, n, c in MODEL_FIGURES if figure_path(g, n) is not None]
