"""Pipeline metrics -- throughput and latency, measured while the sensor runs.

PS 26145 constraints (c) and (d) ask for streaming with bounded latency and a
stated, demonstrated throughput. This module is where those numbers come from:

* throughput: packets/s, Mbps, flows/s and events/s over a sliding window of
  one-second buckets (wall clock, so a capture replayed faster than real time
  shows the rate the sensor actually sustained);
* latency: per-event analyzer time, per-detector inference time, and
  ingest-to-alert time (extractor emitted the event -> alert created), each
  kept as a bounded ring of recent samples and reported as p50/p95/p99/max.

Everything here is measured, never estimated. Counters are updated from the
capture thread and the event loop, so a lock guards them; each update is a
few dictionary operations.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Optional

import numpy as np

_KINDS = ("packets", "bytes", "flows", "dns", "sessions", "events", "alerts")


class PipelineMetrics:
    def __init__(self, window_s: int = 10, history_s: int = 120, max_samples: int = 4096):
        self.window_s = int(window_s)
        self.history_s = int(history_s)
        self.max_samples = int(max_samples)
        self._lock = threading.Lock()
        self.reset()

    # ------------------------------------------------------------------ state
    def reset(self) -> None:
        with getattr(self, "_lock", threading.Lock()):
            self.started = time.time()
            self._buckets: dict[int, list] = {}
            self.totals = {k: 0 for k in _KINDS}
            self.totals["dropped"] = 0
            self.events_by_kind: dict[str, int] = {}
            self.alerts_by_class: dict[str, int] = {}
            self._lat: dict[str, deque] = {}
            self._peak = {"packets_per_s": 0.0, "mbps": 0.0, "flows_per_s": 0.0, "events_per_s": 0.0}
            self.source = "idle"
            self.source_detail = ""
            self.source_since = time.time()

    def set_source(self, kind: str, detail: str = "") -> None:
        with self._lock:
            if kind != self.source or detail != self.source_detail:
                self.source_since = time.time()
            self.source, self.source_detail = kind, detail

    # ---------------------------------------------------------------- updates
    def _bucket(self, now: float) -> list:
        sec = int(now)
        b = self._buckets.get(sec)
        if b is None:
            b = [0] * len(_KINDS)
            self._buckets[sec] = b
            if len(self._buckets) > self.history_s + 5:
                for old in sorted(self._buckets)[: len(self._buckets) - self.history_s - 5]:
                    del self._buckets[old]
        return b

    def packet(self, nbytes: int, n: int = 1) -> None:
        now = time.time()
        with self._lock:
            b = self._bucket(now)
            b[0] += n
            b[1] += nbytes
            self.totals["packets"] += n
            self.totals["bytes"] += nbytes

    def event(self, kind: str) -> None:
        now = time.time()
        with self._lock:
            b = self._bucket(now)
            b[5] += 1
            self.totals["events"] += 1
            self.events_by_kind[kind] = self.events_by_kind.get(kind, 0) + 1
            if kind == "flow":
                b[2] += 1
                self.totals["flows"] += 1
            elif kind in ("dns", "dns_response"):
                b[3] += 1
                self.totals["dns"] += 1
            elif kind == "session":
                b[4] += 1
                self.totals["sessions"] += 1

    def dropped(self, n: int = 1) -> None:
        """Events the live queue had no room for (back-pressure; should stay 0)."""
        with self._lock:
            self.totals["dropped"] += n

    def latency(self, name: str, ms: float) -> None:
        with self._lock:
            d = self._lat.get(name)
            if d is None:
                d = deque(maxlen=self.max_samples)
                self._lat[name] = d
            d.append(float(ms))

    def alert(self, threat_class: str, ingest_to_alert_ms: Optional[float]) -> None:
        now = time.time()
        with self._lock:
            b = self._bucket(now)
            b[6] += 1
            self.totals["alerts"] += 1
            self.alerts_by_class[threat_class] = self.alerts_by_class.get(threat_class, 0) + 1
        if ingest_to_alert_ms is not None:
            self.latency("ingest_to_alert", ingest_to_alert_ms)

    # --------------------------------------------------------------- reading
    @staticmethod
    def _pct(samples) -> dict:
        if not samples:
            return {"n": 0, "p50": None, "p95": None, "p99": None, "max": None}
        a = np.fromiter(samples, dtype=np.float64)
        p50, p95, p99 = np.percentile(a, [50, 95, 99])
        return {"n": int(a.size), "p50": round(float(p50), 3), "p95": round(float(p95), 3),
                "p99": round(float(p99), 3), "max": round(float(a.max()), 3)}

    def rates(self, now: Optional[float] = None) -> dict:
        """Rates over the last `window_s` complete seconds (wall clock)."""
        now = time.time() if now is None else now
        cur = int(now)
        with self._lock:
            span = min(self.window_s, max(1, cur - int(self.started)))
            sums = [0] * len(_KINDS)
            for sec in range(cur - span, cur):
                b = self._buckets.get(sec)
                if b:
                    for i, v in enumerate(b):
                        sums[i] += v
        r = {
            "window_s": span,
            "packets_per_s": sums[0] / span,
            "mbps": sums[1] * 8 / span / 1e6,
            "flows_per_s": sums[2] / span,
            "dns_per_s": sums[3] / span,
            "events_per_s": sums[5] / span,
            "alerts_per_s": sums[6] / span,
        }
        with self._lock:
            for k in self._peak:
                if r[k] > self._peak[k]:
                    self._peak[k] = r[k]
        return {k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items()}

    def series(self, now: Optional[float] = None, seconds: Optional[int] = None) -> list:
        """Per-second history: [epoch_s, packets, bytes, flows, events, alerts]."""
        now = time.time() if now is None else now
        cur = int(now)
        n = min(self.history_s, seconds or self.history_s)
        out = []
        with self._lock:
            for sec in range(cur - n, cur):
                b = self._buckets.get(sec) or [0] * len(_KINDS)
                out.append([sec, b[0], b[1], b[2], b[5], b[6]])
        return out

    def snapshot(self, with_series: bool = True) -> dict:
        now = time.time()
        rates = self.rates(now)
        with self._lock:
            lat = {name: self._pct(list(d)) for name, d in self._lat.items()}
            totals = dict(self.totals)
            by_kind = dict(self.events_by_kind)
            by_class = dict(self.alerts_by_class)
            peak = {k: round(v, 3) for k, v in self._peak.items()}
            source = {"kind": self.source, "detail": self.source_detail,
                      "since": self.source_since}
        detectors = {k[len("det."):]: v for k, v in lat.items() if k.startswith("det.")}
        per_event = {k[len("event."):]: v for k, v in lat.items() if k.startswith("event.")}
        snap = {
            "generated_at": now,
            "uptime_s": round(now - self.started, 1),
            "source": source,
            "throughput": rates,
            "peak_throughput": peak,
            "totals": totals,
            "events_by_kind": by_kind,
            "alerts_by_class": by_class,
            "latency_ms": {
                "event": per_event,
                "detector": detectors,
                "ingest_to_alert": lat.get("ingest_to_alert", self._pct([])),
            },
        }
        if with_series:
            snap["series"] = self.series(now)
        return snap


class Timer:
    """`with Timer(metrics, "det.ddos_xgb"): ...` records elapsed ms."""
    __slots__ = ("m", "name", "t0", "ms")

    def __init__(self, metrics: Optional[PipelineMetrics], name: str):
        self.m, self.name, self.ms = metrics, name, 0.0

    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.ms = (time.perf_counter() - self.t0) * 1000.0
        if self.m is not None:
            self.m.latency(self.name, self.ms)
        return False


# Process-wide instance used by the live sensor. The benchmark builds its own.
METRICS = PipelineMetrics()
