"""C2 beaconing -- the combined periodicity score, run live on every flow.

This is the scorer evaluated offline in model_comparisons/c2_beacon_score.py
(results: model_comparisons/c2_beacon_score_eval.json). The five terms, the
weights and the 0.80 alert threshold are the same; ``fft_prom``, ``mad_ratio``,
``merge`` and ``features`` below are line-for-line the offline functions, and
tests/test_ps26145_detectors.py checks that they give identical numbers.

Per (source, destination) pair in a 6-hour UTC window, from connection starts:
  T  timing regularity   1 - min(1, MAD(gap)/median(gap))
  F  FFT periodicity     min(1, peak_prominence/8)
  S  size regularity     1 - min(1, MAD(bytes)/median(bytes))
  R  destination rarity  1 / number of sources talking to that destination
  C  persistence         share of captured hours in the window with a check-in
  score = 0.30 T + 0.20 F + 0.20 S + 0.15 R + 0.15 C
Known periodic services (DNS, NTP, SSDP, mDNS, LLMNR, NetBIOS, DHCP) and
multicast / link-local / broadcast destinations are dropped. A pair needs at
least 20 check-ins (starts < 5 s apart merged) spanning at least 30 minutes.

Differences from the offline run, both forced by streaming: the pair is
scored as check-ins arrive (so an alert can come before the window closes),
and R and C use the sources and captured hours seen so far in the window.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Optional

import numpy as np

from netsentinel.detectors.base import RuleDetector, is_skip_destination


# ---- offline functions (model_comparisons/c2_beacon_score.py) -------------
def fft_prom(iats):
    iats = np.asarray(iats, dtype=np.float64)
    if len(iats) < 4: return 0.0
    m = np.abs(np.fft.rfft(iats))[1:]
    if len(m) == 0 or m.sum() == 0: return 0.0
    return float((m.max() - np.median(m)) / (np.std(m) + 1e-9))


def mad_ratio(x):
    x = np.asarray(x, dtype=np.float64); med = np.median(x)
    return 1.0 if med <= 0 else float(np.median(np.abs(x - med)) / med)


def merge(conns, gap=5.0):
    conns = sorted(conns); out = []
    for t, b in conns:
        if out and t - out[-1][0] < gap: out[-1][1] += b
        else: out.append([t, b])
    return out


def features(merged, n_src, cap_hours, weights):
    t = np.array([m[0] for m in merged]); b = np.array([m[1] for m in merged]); iat = np.diff(t)
    T = 1 - min(1.0, mad_ratio(iat)); P = fft_prom(iat); F = min(1.0, P / 8.0)
    S = 1 - min(1.0, mad_ratio(b)); R = 1.0 / max(n_src, 1)
    hrs = {int(x // 3600) for x in t}; C = min(1.0, len(hrs) / max(len(cap_hours), 1))
    score = weights["T"] * T + weights["F"] * F + weights["S"] * S + weights["R"] * R + weights["C"] * C
    return dict(T=T, F=F, P=P, S=S, R=R, C=C, score=score, n=len(merged), median_iat=float(np.median(iat)))
# ---------------------------------------------------------------------------


def ip_level_bytes(event: dict) -> int:
    """Forward bytes counted the way the offline extractor counted them
    (IP total length of every initiator packet)."""
    f = event.get("features") or {}
    l4 = float(f.get("Fwd Packets Length Total", 0) or 0)
    pk = float(f.get("Total Fwd Packets", 0) or 0)
    hdr = 40 if ":" in str(event.get("source_ip", "")) else 20
    return int(l4 + hdr * pk)


class BeaconScorer(RuleDetector):
    key = "c2_combined"
    name = "c2_combined_score"
    version = "2"
    confidence_kind = "weighted_score"

    def __init__(self, params: dict, max_pairs: int = 100000, max_conns_per_pair: int = 3000):
        super().__init__(params)
        self.win = int(params["window_s"])
        self.weights = dict(params["weights"])
        self.threshold = float(params["threshold"])
        self.min_checkins = int(params["min_checkins"])
        self.min_span = float(params["min_span_s"])
        self.gap = float(params["merge_gap_s"])
        self.known = set(int(p) for p in params["known_ports"])
        self.rescore_every = max(1, int(params.get("rescore_every", 5)))
        self.max_pairs = max_pairs
        self.max_conns = max_conns_per_pair
        self._cap_hours: dict[int, set] = defaultdict(set)
        self._conns: dict[tuple, list] = defaultdict(list)     # (w,src,dst) -> [[t, b, l4, pkts]]
        self._srcs: dict[tuple, set] = defaultdict(set)        # (w,dst) -> {src}
        self._ports: dict[tuple, Counter] = defaultdict(Counter)
        self._since: dict[tuple, int] = defaultdict(int)
        self._alerted: set = set()
        self._last: dict[tuple, dict] = {}                     # latest score per pair
        self._cur_w: Optional[int] = None

    # ------------------------------------------------------------------
    def observe(self, event: dict) -> Optional[dict]:
        ts = event.get("timestamp")
        src, dst = event.get("source_ip"), event.get("dest_ip")
        if ts is None or not src or not dst:
            return None
        ts = float(ts)
        w = int(ts // self.win)
        self._roll(w)
        self._cap_hours[w].add(int(ts // 3600))
        try:
            dport = int(event.get("dest_port") or 0)
        except (TypeError, ValueError):
            dport = 0
        if dport in self.known or is_skip_destination(dst):
            return None
        key = (w, src, dst)
        conns = self._conns.get(key)
        if conns is None:
            if len(self._conns) >= self.max_pairs:
                return None
            conns = self._conns[key]
        f = event.get("features") or {}
        conns.append([ts, ip_level_bytes(event),
                      float(f.get("Fwd Packets Length Total", 0) or 0),
                      float(f.get("Total Fwd Packets", 0) or 0)])
        if len(conns) > self.max_conns:
            del conns[: len(conns) - self.max_conns]
        self._srcs[(w, dst)].add(src)
        self._ports[key][dport] += 1
        self._since[key] += 1
        if len(conns) < self.min_checkins or self._since[key] < self.rescore_every:
            return None
        self._since[key] = 0
        self.runs += 1
        return self._score(key)

    def _roll(self, w: int) -> None:
        if self._cur_w is None or w > self._cur_w:
            self._cur_w = w
            keep = {w, w - 1}
            for k in [k for k in self._conns if k[0] not in keep]:
                self._conns.pop(k, None); self._ports.pop(k, None)
                self._since.pop(k, None); self._last.pop(k, None)
            for k in [k for k in self._srcs if k[0] not in keep]:
                self._srcs.pop(k, None)
            for k in [k for k in self._cap_hours if k not in keep]:
                self._cap_hours.pop(k, None)
            self._alerted = {k for k in self._alerted if k[0] in keep}

    def _score(self, key) -> Optional[dict]:
        w, src, dst = key
        raw = self._conns[key]
        merged = merge([(c[0], c[1]) for c in raw], self.gap)
        if len(merged) < self.min_checkins or merged[-1][0] - merged[0][0] < self.min_span:
            return None
        n_src = len(self._srcs[(w, dst)])
        cap = self._cap_hours[w]
        f = features(merged, n_src, cap, self.weights)
        self._last[key] = {"src": src, "dst": dst, "window": w, "score": f["score"], "n": f["n"],
                           "median_gap_s": f["median_iat"], "T": f["T"], "F": f["F"], "S": f["S"],
                           "R": f["R"], "C": f["C"]}
        if f["score"] < self.threshold or key in self._alerted:
            return None
        self._alerted.add(key)
        self.alerts += 1
        return self._result(key, merged, f, n_src, len(cap))

    def _result(self, key, merged, f, n_src, n_cap) -> dict:
        w, src, dst = key
        t = np.array([m[0] for m in merged])
        iat = np.diff(t)
        port, _ = self._ports[key].most_common(1)[0]
        cv = float(np.std(iat) / (np.mean(iat) + 1e-9)) if iat.size else None
        return {
            "threat": "C2 Beacon",
            "confidence": round(float(min(1.0, max(0.0, f["score"]))), 4),
            "model": "c2_combined_score_v2",
            "confidence_kind": self.confidence_kind,
            "subtype": "periodic check-ins",
            "score": round(f["score"], 4),
            "components": {k: round(float(f[k]), 4) for k in ("T", "F", "S", "R", "C")},
            "fft_prominence": round(float(f["P"]), 3),
            "weights": self.weights,
            "threshold": self.threshold,
            "checkins": int(f["n"]),
            "median_gap_s": round(float(f["median_iat"]), 3),
            "span_s": round(float(t[-1] - t[0]), 1),
            "sources_to_destination": n_src,
            "captured_hours_in_window": n_cap,
            "dst_port": int(port),
            "window_utc": {"start": w * self.win, "end": (w + 1) * self.win},
            # the console's check-in chart reads these two
            "iat": [round(float(x), 3) for x in iat[:24]],
            "beacon_interval": round(float(f["median_iat"]), 2),
            "coefficient_of_variation": round(cv, 4) if cv is not None else None,
            "_event_start": float(t[0]),
            "_event_end": float(t[-1]),
            "_replay_inputs": {"checkins": [[float(a), float(b)] for a, b in merged],
                               "n_src": int(n_src), "captured_hours": int(n_cap)},
        }

    # ------------------------------------------------------------------
    def model_series(self, src: str, dst: str, ts: float, n: int = 100) -> list:
        """Last n merged check-ins as the BiLSTM+FFT model's input series."""
        key = (int(ts // self.win), src, dst)
        raw = sorted(self._conns.get(key, []))
        groups = []
        for t, b, l4, pk in raw:
            if groups and t - groups[-1][0] < self.gap:
                g = groups[-1]; g[2] += l4; g[3] += pk
            else:
                groups.append([t, b, l4, pk])
        groups = groups[-n:]
        out = []
        for i, (t, b, l4, pk) in enumerate(groups):
            out.append({"iat": 0.0 if i == 0 else max(0.0, t - groups[i - 1][0]),
                        "packet_size": (l4 / pk) if pk else 0.0, "bytes": l4, "direction": 1})
        return out

    def top(self, n: int = 5) -> list:
        """Highest-scoring pairs right now (the console's watch list)."""
        rows = sorted(self._last.values(), key=lambda r: -r["score"])[:n]
        return [{k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()} for r in rows]

    def replay(self, inputs: dict) -> Optional[dict]:
        merged = [list(x) for x in inputs.get("checkins", [])]
        if len(merged) < 2:
            return None
        cap = set(range(int(inputs.get("captured_hours", 1))))
        f = features(merged, int(inputs.get("n_src", 1)), cap, self.weights)
        fired = f["score"] >= self.threshold
        return {"threat": "C2 Beacon" if fired else "Benign",
                "confidence": round(float(min(1.0, max(0.0, f["score"]))), 4)}
