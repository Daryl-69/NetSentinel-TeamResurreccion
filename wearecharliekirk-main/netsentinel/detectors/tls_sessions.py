"""Malware in encrypted sessions -- TLS fingerprints, sizes and timing.

PS 26145 threat (d): "malware communication in encrypted sessions (JA3/JA3S/
JA4 fingerprints, packet-size and timing sequences)". Nothing is decrypted;
every input is TLS handshake metadata or packet sizes and times.

For each TLS client -> server -> JA4 combination the sensor keeps the
sessions of the last 6 hours and scores them once there are at least 8:

  rarity  R  how few of this sensor's TLS clients use this JA4 (1 = only
             this host); counted only after >= 5 distinct TLS clients have
             been seen, so the first hosts on a quiet sensor are not "rare"
  timing  T  1 - MAD/median of the gaps between session starts
  size    S  1 - MAD/median of the bytes per session
  shape   P  share of sessions whose first six packet sizes and directions
             are identical (the packet-size sequence)
  hello   H  ClientHello anomalies: no SNI, no ALPN, nothing newer than
             TLS 1.1 offered, <= 6 cipher suites, TLS on a non-TLS port
             (three or more of these = 1.0)
  score = 0.30 R + 0.20 T + 0.15 S + 0.15 P + 0.20 H    alert at >= 0.70

A fingerprint on the operator's blocklist (intel/tls_fingerprint_blocklist
.json: exact JA3, JA3S or JA4 values) alerts on the first session. The file
ships empty: no fingerprint lists were downloaded and no malware traffic was
used to tune any of this. The weights and threshold were fixed a priori and
this detector has not been measured on labelled malware traffic -- treat its
alerts as triage leads. Rare, regular, legitimate clients (a custom updater,
a monitoring agent) will score high too; the evidence shows which.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict, deque
from typing import Optional

import numpy as np

from netsentinel.detectors.base import RuleDetector, Cooldown, mad_ratio


def load_blocklist(path: Optional[str]) -> dict:
    empty = {"ja3": {}, "ja3s": {}, "ja4": {}}
    if not path or not os.path.exists(path):
        return empty
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return empty
    out = {}
    for k in empty:
        v = data.get(k) or {}
        if isinstance(v, list):
            v = {x: "listed" for x in v}
        out[k] = {str(a).lower(): str(b) for a, b in v.items() if not str(a).startswith("_")}
    return out


def _splt_signature(splt) -> Optional[tuple]:
    if not splt:
        return None
    return tuple(int(p[0]) for p in splt[:6])


class EncryptedSessionDetector(RuleDetector):
    key = "tls_sessions"
    name = "tls_session_profile"
    version = "1"
    confidence_kind = "weighted_score"

    def __init__(self, params: dict, blocklist_path: Optional[str] = None,
                 max_keys: int = 50000, max_clients: int = 100000):
        super().__init__(params)
        self.window = float(params["window_s"])
        self.weights = dict(params["weights"])
        self.blocklist_path = blocklist_path
        self.blocklist = load_blocklist(blocklist_path)
        self.cool = Cooldown(params["cooldown_s"])
        self.tls_ports = set(int(p) for p in params["tls_ports"])
        self.max_keys, self.max_clients = max_keys, max_clients
        self._clients: set = set()
        self._fp_clients: dict[str, set] = defaultdict(set)
        self._sess: dict[tuple, deque] = {}
        self._fp_counts: Counter = Counter()
        self.handshakes = 0

    def blocklist_size(self) -> int:
        return sum(len(v) for v in self.blocklist.values())

    def observe(self, event: dict) -> Optional[dict]:
        tls = event.get("tls") or {}
        ja4 = tls.get("ja4")
        client, server, ts = event.get("source_ip"), event.get("dest_ip"), event.get("timestamp")
        if not ja4 or not client or not server or ts is None:
            return None
        ts = float(ts)
        self.handshakes += 1
        if len(self._clients) < self.max_clients:
            self._clients.add(client)
        fpc = self._fp_clients[ja4]
        if len(fpc) < 1000:
            fpc.add(client)
        self._fp_counts[ja4] += 1
        f = event.get("features") or {}
        total = float(f.get("Fwd Packets Length Total", 0) or 0) + float(f.get("Bwd Packets Length Total", 0) or 0)
        key = (client, server, ja4)
        q = self._sess.get(key)
        if q is None:
            if len(self._sess) >= self.max_keys:
                return None
            q = self._sess[key] = deque()
        q.append((ts, total, _splt_signature(event.get("splt"))))
        while q and q[0][0] < ts - self.window:
            q.popleft()
        self.runs += 1
        try:
            dport = int(event.get("dest_port") or 0)
        except (TypeError, ValueError):
            dport = 0

        hit = None
        for kind, value in (("ja4", ja4), ("ja3", tls.get("ja3")), ("ja3s", tls.get("ja3s"))):
            if value and str(value).lower() in self.blocklist[kind]:
                hit = {"kind": kind, "value": value, "label": self.blocklist[kind][str(value).lower()]}
                break
        if hit is None and len(q) < self.params["min_sessions"]:
            return None
        inputs = self._inputs(q, tls, ja4, dport, hit)
        verdict = self.replay(inputs)
        if verdict["threat"] == "Benign":
            return None
        ok, held = self.cool.allow(key, ts)
        if not ok:
            self.suppressed += 1
            return None
        self.alerts += 1
        starts = sorted(x[0] for x in q)
        gaps = np.diff(starts)
        sigs = Counter(x[2] for x in q if x[2] is not None)
        modal = list(sigs.most_common(1)[0][0]) if sigs else None
        subtype = (f"blocklisted {hit['kind'].upper()} ({hit['label']})" if hit
                   else "rare TLS client with regular sessions")
        return {
            "threat": "Encrypted Malware",
            "confidence": verdict["confidence"],
            "model": "tls_session_profile",
            "confidence_kind": "rule_score" if hit else self.confidence_kind,
            "subtype": subtype,
            "ja3": tls.get("ja3"), "ja3s": tls.get("ja3s"), "ja4": ja4,
            "sni": tls.get("sni"), "alpn": tls.get("alpn"),
            "offered_version": tls.get("offered_version"),
            "negotiated_version": tls.get("negotiated_version"),
            "cipher_count": tls.get("cipher_count"), "transport": tls.get("transport"),
            "sessions": len(q),
            "clients_with_fingerprint": inputs["clients_with_fp"],
            "sensor_tls_clients": inputs["population"],
            "components": {k: round(inputs[k], 4) for k in ("R", "T", "S", "P", "H")},
            "weights": self.weights, "threshold": self.params["alert_score"],
            "hello_flags": inputs["hello_flags"],
            "median_interval_s": round(float(np.median(gaps)), 2) if gaps.size else None,
            "splt_signature": modal,
            "blocklist": hit,
            "dst_port": dport,
            "alerts_suppressed_since_last": held,
            "_event_start": starts[0], "_event_end": starts[-1],
            "_replay_inputs": inputs,
        }

    def _inputs(self, q, tls, ja4, dport, hit) -> dict:
        p = self.params
        population = len(self._clients)
        n_fp = len(self._fp_clients.get(ja4, ()))
        R = (1.0 - min(1.0, (n_fp - 1) / 4.0)) if population >= p["rarity_min_population"] else 0.0
        starts = sorted(x[0] for x in q)
        gaps = np.diff(starts)
        T = 1 - min(1.0, mad_ratio(gaps)) if gaps.size >= 3 else 0.0
        sizes = [x[1] for x in q]
        S = 1 - min(1.0, mad_ratio(sizes)) if len(sizes) >= 3 else 0.0
        sigs = [x[2] for x in q if x[2] is not None]
        P = (Counter(sigs).most_common(1)[0][1] / len(q)) if sigs else 0.0
        flags = []
        if not tls.get("sni"):
            flags.append("no SNI")
        if not tls.get("alpn"):
            flags.append("no ALPN")
        if tls.get("offered_version") in ("TLS 1.1", "TLS 1.0", "SSL 3.0"):
            flags.append("no TLS 1.2+ offered")
        if tls.get("cipher_count") is not None and int(tls["cipher_count"]) <= 6:
            flags.append("few cipher suites")
        if dport and dport not in self.tls_ports:
            flags.append(f"TLS on port {dport}")
        H = min(1.0, len(flags) / 3.0)
        return {"R": float(R), "T": float(T), "S": float(S), "P": float(P), "H": float(H),
                "hello_flags": flags, "clients_with_fp": n_fp, "population": population,
                "blocklisted": hit is not None}

    def replay(self, inputs: dict) -> dict:
        if inputs.get("blocklisted"):
            return {"threat": "Encrypted Malware", "confidence": 0.99}
        w = self.weights
        score = (w["rarity"] * inputs["R"] + w["timing"] * inputs["T"] + w["size"] * inputs["S"]
                 + w["shape"] * inputs["P"] + w["hello"] * inputs["H"])
        if score < self.params["alert_score"]:
            return {"threat": "Benign", "confidence": 0.0}
        return {"threat": "Encrypted Malware", "confidence": round(min(1.0, score), 4)}

    def top_fingerprints(self, n: int = 8) -> list:
        return [{"ja4": fp, "sessions": c, "clients": len(self._fp_clients.get(fp, ()))}
                for fp, c in self._fp_counts.most_common(n)]
