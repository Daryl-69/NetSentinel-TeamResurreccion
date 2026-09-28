"""Exfiltration by volume -- the out/in byte ratio of outbound connections.

PS 26145 threat (f): "exfiltration (asymmetric flow volume, out/in byte
ratio)". For connections an internal host opens to an external address, the
bytes the host sent (forward) and received (backward) are summed per
(host, destination) over 15 minutes. An alert fires when the host has sent
at least 5 MB and at least 10x what it received.

Only connections the internal host initiated are counted, and only when the
sensor saw traffic in both directions: a one-way view (asymmetric routing, a
tap on one direction) would make every ratio infinite, so such flows are
skipped rather than scored.

Known false positives: backups, cloud-drive sync, video uploads and large
git pushes are all legitimate asymmetric uploads. The alert says which
destination and port, so an analyst can allow a known service.
"""
from __future__ import annotations

import math
from collections import Counter, deque
from typing import Optional

from netsentinel.detectors.base import RuleDetector, Cooldown, is_internal, is_external, clamp01


class ByteRatioExfilDetector(RuleDetector):
    key = "exfil_ratio"
    name = "exfil_byte_ratio"
    version = "1"
    confidence_kind = "rule_score"

    def __init__(self, params: dict, max_pairs: int = 50000):
        super().__init__(params)
        self.window = float(params["window_s"])
        self.cool = Cooldown(params["cooldown_s"])
        self.max_pairs = max_pairs
        self._p: dict[tuple, dict] = {}
        self.skipped_one_way = 0

    def observe(self, event: dict) -> Optional[dict]:
        src, dst, ts = event.get("source_ip"), event.get("dest_ip"), event.get("timestamp")
        if ts is None or not (is_internal(src) and is_external(dst)):
            return None
        f = event.get("features") or {}
        out_b = float(f.get("Fwd Packets Length Total", 0) or 0)
        in_b = float(f.get("Bwd Packets Length Total", 0) or 0)
        in_p = float(f.get("Total Backward Packets", 0) or 0)
        if in_p <= 0:
            self.skipped_one_way += 1
            return None
        ts = float(ts)
        end = float(event.get("last_seen") or ts)
        key = (src, dst)
        st = self._p.get(key)
        if st is None:
            if len(self._p) >= self.max_pairs:
                self._evict(ts)
                if len(self._p) >= self.max_pairs:
                    return None
            st = {"q": deque(), "out": 0.0, "in": 0.0, "ports": Counter()}
            self._p[key] = st
        try:
            dport = int(event.get("dest_port") or 0)
        except (TypeError, ValueError):
            dport = 0
        st["q"].append((ts, end, out_b, in_b, dport))
        st["out"] += out_b; st["in"] += in_b; st["ports"][dport] += 1
        cutoff = end - self.window
        while st["q"] and st["q"][0][1] < cutoff:
            _, _, o, i, p = st["q"].popleft()
            st["out"] -= o; st["in"] -= i; st["ports"][p] -= 1
            if st["ports"][p] <= 0: del st["ports"][p]
        self.runs += 1
        inputs = {"bytes_out": st["out"], "bytes_in": st["in"]}
        verdict = self.replay(inputs)
        if verdict["threat"] == "Benign":
            return None
        ok, held = self.cool.allow(key, end)
        if not ok:
            self.suppressed += 1
            return None
        self.alerts += 1
        q = st["q"]
        port, _ = st["ports"].most_common(1)[0]
        return {
            "threat": "Data Exfiltration",
            "confidence": verdict["confidence"],
            "model": "exfil_byte_ratio",
            "confidence_kind": self.confidence_kind,
            "subtype": "asymmetric upload (out/in byte ratio)",
            "anomaly_type": "asymmetric_upload",
            "byte_ratio": {"outbound": int(st["out"]), "inbound": int(st["in"])},
            "out_in_ratio": round(st["out"] / max(1.0, st["in"]), 2),
            "connections": len(q),
            "dst_port": int(port),
            "window_s": self.window,
            "min_out_bytes": self.params["min_out_bytes"],
            "min_ratio": self.params["min_ratio"],
            "alerts_suppressed_since_last": held,
            "_event_start": q[0][0],
            "_event_end": max(x[1] for x in q),
            "_replay_inputs": inputs,
        }

    def _evict(self, now: float) -> None:
        for k in [k for k, st in self._p.items() if not st["q"] or st["q"][-1][1] < now - self.window]:
            self._p.pop(k, None)

    def replay(self, inputs: dict) -> dict:
        p = self.params
        out_b, in_b = float(inputs["bytes_out"]), float(inputs["bytes_in"])
        ratio = out_b / max(1.0, in_b)
        if out_b < p["min_out_bytes"] or ratio < p["min_ratio"]:
            return {"threat": "Benign", "confidence": 0.0}
        conf = 0.6 + 0.2 * clamp01(math.log10(ratio / p["min_ratio"])) \
            + 0.2 * clamp01(math.log10(out_b / p["min_out_bytes"]))
        return {"threat": "Data Exfiltration", "confidence": round(conf, 4)}
