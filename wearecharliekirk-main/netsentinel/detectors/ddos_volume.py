"""DDoS -- per-destination rate, source-IP entropy and attack family.

PS 26145 threat (a): "DDoS (SYN floods, UDP reflection/amplification, spoofed
traffic) using rate and entropy of source IPs". For every destination this
keeps a sliding window (10 s of wire time) of the flows arriving at it and
maintains, incrementally:

  flow / packet / byte rate          how hard the destination is being hit
  source-IP entropy (bits, and       many sources, each seen about once, is
  normalised by log2 of the flows)   what randomised (spoofed) sources look like
  SYN-only share, UDP share          the shape of the flood
  top destination port share         a flood hits one service; a scan spreads
  top UDP source port and service    reflection arrives FROM the reflector's
                                     service port (NTP 123, DNS 53, ...)
  handshake completion share         spoofed SYNs never complete a handshake

Two things use it. (1) Every DDoS alert from the XGBoost model gets this
window attached as evidence and its attack family as the subtype (the model
itself only says DDoS / not DDoS). (2) A rule raises a DDoS alert on its own
when the rate and shape gates are met; this is what covers live capture,
where the XGBoost model is not run on the sensor's own flow features.

The rule needs at least min_sources (10) distinct sources in the window:
a distributed attack by definition, and it keeps one client's burst of
lookups to its resolver from reading as a UDP flood.

Family rules, in order:
  SYN flood                     SYN-only share >= 0.8 and one port dominates
  UDP reflection/amplification  UDP share >= 0.8 and a known amplifier source port dominates
  UDP flood                     UDP share >= 0.8
  TCP flood                     TCP and one destination port dominates
"Spoofed sources likely" is added when >= 100 distinct sources, >= 90% of
flows from a source not seen before in the window, and <= 5% handshakes.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from typing import Optional

from netsentinel.detectors.base import RuleDetector, is_bogon, shannon_bits, clamp01

AMPLIFIERS = {
    17: "QOTD", 19: "CharGen", 53: "DNS", 69: "TFTP", 111: "Portmap", 123: "NTP",
    137: "NetBIOS", 161: "SNMP", 389: "CLDAP", 520: "RIP", 623: "IPMI", 1434: "MSSQL",
    1900: "SSDP", 3283: "ARMS", 3702: "WS-Discovery", 5351: "NAT-PMP", 5683: "CoAP",
    10001: "Ubiquiti", 11211: "Memcached", 37810: "DVR",
}

_F = ("ts", "src", "proto", "sport", "dport", "pkts", "bytes", "syn_only", "handshake")
MIN_FLOWS_FOR_FAMILY = 20


def flow_family(event: dict) -> str | None:
    """Attack family from ONE flow, for a model alert raised before the
    destination's window holds enough flows to judge its shape."""
    r = _flow_record(event)
    if r is None:
        return None
    _, _, proto, sport, _, _, _, syn_only, _ = r
    if proto == 6 and syn_only:
        return "SYN flood"
    if proto == 17 and sport in AMPLIFIERS:
        return f"UDP reflection/amplification ({AMPLIFIERS[sport]})"
    if proto == 17:
        return "UDP flood"
    if proto == 6:
        return "TCP flood"
    return None


def _flow_record(event: dict) -> Optional[tuple]:
    ts = event.get("timestamp")
    dst = event.get("dest_ip")
    if ts is None or not dst:
        return None
    f = event.get("features") or {}
    try:
        proto = int(event.get("protocol", f.get("Protocol", 6)) or 6)
    except (TypeError, ValueError):
        proto = 6
    fwd_p = float(f.get("Total Fwd Packets", 0) or 0)
    bwd_p = float(f.get("Total Backward Packets", 0) or 0)
    fwd_b = float(f.get("Fwd Packets Length Total", 0) or 0)
    bwd_b = float(f.get("Bwd Packets Length Total", 0) or 0)
    syn = float(f.get("SYN Flag Count", 0) or 0) > 0
    ack = float(f.get("ACK Flag Count", 0) or 0) > 0
    syn_only = proto == 6 and syn and not ack
    handshake = proto == 6 and syn and ack and bwd_p > 0
    try:
        sport = int(event.get("source_port") or f.get("src_port") or 0)
        dport = int(event.get("dest_port") or f.get("dst_port") or 0)
    except (TypeError, ValueError):
        sport = dport = 0
    return (float(ts), event.get("source_ip") or "", proto, sport, dport,
            max(1.0, fwd_p + bwd_p), fwd_b + bwd_b, syn_only, handshake)


class _Window:
    __slots__ = ("q", "src", "dport", "usport", "n", "pkts", "bytes", "syn_only", "udp",
                 "tcp", "handshake", "bogon", "first_seen_src", "last_eval", "last_eval_n", "baseline")

    def __init__(self):
        self.q = deque()
        self.src = Counter(); self.dport = Counter(); self.usport = Counter()
        self.n = 0; self.pkts = 0.0; self.bytes = 0.0
        self.syn_only = 0; self.udp = 0; self.tcp = 0; self.handshake = 0; self.bogon = 0
        self.last_eval = -1e18
        self.last_eval_n = 0
        self.baseline = None

    def add(self, r, sign: int):
        ts, src, proto, sport, dport, pkts, byts, syn_only, hs = r
        self.n += sign; self.pkts += sign * pkts; self.bytes += sign * byts
        self.src[src] += sign
        if self.src[src] <= 0: del self.src[src]
        self.dport[dport] += sign
        if self.dport[dport] <= 0: del self.dport[dport]
        if proto == 17:
            self.udp += sign
            self.usport[sport] += sign
            if self.usport[sport] <= 0: del self.usport[sport]
        elif proto == 6:
            self.tcp += sign
        self.syn_only += sign * int(syn_only)
        self.handshake += sign * int(hs)
        self.bogon += sign * int(is_bogon(src))


class DDoSWindowTracker(RuleDetector):
    key = "ddos_rate_entropy"
    name = "ddos_rate_entropy"
    version = "2"
    confidence_kind = "rule_score"

    def __init__(self, params: dict, max_destinations: int = 20000):
        super().__init__(params)
        self.window = float(params["window_s"])
        self.max_dst = max_destinations
        self._w: dict[str, _Window] = {}

    def observe(self, event: dict) -> Optional[str]:
        r = _flow_record(event)
        if r is None:
            return None
        dst = event["dest_ip"]
        w = self._w.get(dst)
        if w is None:
            if len(self._w) >= self.max_dst:
                self._evict(r[0])
                if len(self._w) >= self.max_dst:
                    return None
            w = _Window()
            self._w[dst] = w
        w.q.append(r); w.add(r, +1)
        cutoff = r[0] - self.window
        while w.q and w.q[0][0] < cutoff:
            w.add(w.q.popleft(), -1)
        return dst

    def sources(self, dst: str, cap: int = 5000) -> set:
        """Sources currently in the destination's window (at most cap)."""
        w = self._w.get(dst)
        if w is None:
            return set()
        return set(k for k, _ in zip(w.src, range(cap)))

    def _evict(self, now: float) -> None:
        stale = [d for d, w in self._w.items() if not w.q or w.q[-1][0] < now - 3 * self.window]
        for d in stale[: max(1, len(stale))]:
            self._w.pop(d, None)

    # ------------------------------------------------------------------
    def summary(self, dst: str) -> Optional[dict]:
        w = self._w.get(dst)
        if w is None or w.n <= 0:
            return None
        p = self.params
        span = max(1.0, min(self.window, w.q[-1][0] - w.q[0][0])) if len(w.q) > 1 else 1.0
        n = w.n
        distinct = len(w.src)
        h = shannon_bits(w.src.values()) + 0.0
        top_dport, top_dport_n = w.dport.most_common(1)[0] if w.dport else (None, 0)
        top_sport, top_sport_n = w.usport.most_common(1)[0] if w.usport else (None, 0)
        syn_share = w.syn_only / n
        udp_share = w.udp / n
        dport_share = top_dport_n / n
        sport_share = (top_sport_n / w.udp) if w.udp else 0.0
        hs_share = w.handshake / max(1, w.tcp) if w.tcp else 0.0
        unique_share = distinct / n
        family, service = None, None
        if n < MIN_FLOWS_FOR_FAMILY:
            pass    # too few flows to call a shape; see flow_family()
        elif syn_share >= p["shape_share"] and dport_share >= p["port_concentration"]:
            family = "SYN flood"
        elif udp_share >= p["shape_share"] and top_sport in AMPLIFIERS and sport_share >= 0.6:
            service = AMPLIFIERS[top_sport]
            family = f"UDP reflection/amplification ({service})"
        elif udp_share >= p["shape_share"]:
            family = "UDP flood"
        elif w.tcp / n >= p["shape_share"] and dport_share >= max(p["port_concentration"], 0.8):
            family = "TCP flood"
        spoofed = (family in ("SYN flood", "UDP flood", "TCP flood")
                   and distinct >= p["spoof_min_sources"]
                   and unique_share >= p["spoof_unique_share"]
                   and hs_share <= p["spoof_max_handshake"])
        return {
            "destination": dst,
            "window_s": self.window,
            "window_span_s": round(span, 3),
            "flows_in_window": n,
            "flow_rate_per_s": round(n / span, 2),
            "packet_rate_per_s": round(w.pkts / span, 2),
            "byte_rate_bps": round(w.bytes * 8 / span, 1),
            "distinct_sources": distinct,
            "src_ip_entropy": round(h, 3),
            "src_ip_entropy_norm": round(h / math.log2(n), 3) if n > 1 else 0.0,
            "new_source_share": round(unique_share, 3),
            "syn_only_share": round(syn_share, 3),
            "udp_share": round(udp_share, 3),
            "handshake_share": round(hs_share, 3),
            "top_dst_port": top_dport,
            "top_dst_port_share": round(dport_share, 3),
            "top_udp_src_port": top_sport,
            "top_udp_src_port_share": round(sport_share, 3),
            "amplifier_service": service,
            "bogon_source_share": round(w.bogon / n, 3),
            "bytes_per_packet": round(w.bytes / w.pkts, 1) if w.pkts else 0.0,
            "family": family,
            "family_basis": "window" if n >= MIN_FLOWS_FOR_FAMILY else None,
            "looks_like_scan": bool(n >= MIN_FLOWS_FOR_FAMILY and family is None
                                    and dport_share < p["port_concentration"] and distinct <= 3),
            "top_sources": [[ip, c] for ip, c in w.src.most_common(5)],
            "spoofed_sources_likely": bool(spoofed),
            "baseline_flow_rate_per_s": round(w.baseline, 2) if w.baseline is not None else None,
            "_event_start": w.q[0][0],
            "_event_end": w.q[-1][0],
        }

    def evaluate(self, dst: str, ts: float) -> Optional[dict]:
        """Rate/shape rule for one destination; at most once per second of wire time."""
        w = self._w.get(dst)
        if w is None:
            return None
        # Evaluate at most once per second of wire time, or sooner when the
        # window has doubled since the last look (a burst inside one second).
        grown = w.n >= 2 * max(1, w.last_eval_n) and w.n - w.last_eval_n >= 50
        if abs(ts - w.last_eval) < 1.0 and not grown:
            return None
        w.last_eval, w.last_eval_n = ts, w.n
        self.runs += 1
        p = self.params
        # cheap gate before the full summary
        if w.n < p["min_flows_per_s"] * min(self.window, 2.0):
            return None
        s = self.summary(dst)
        if s is None:
            return None
        rate = s["flow_rate_per_s"]
        fired = self.decide(s)
        if not fired:
            # Only traffic without a flood shape feeds the baseline, so a
            # flood that stays under the absolute gate cannot teach the
            # destination that floods are normal.
            if s["family"] is None:
                a = p["baseline_alpha"]
                w.baseline = rate if w.baseline is None else (1 - a) * w.baseline + a * rate
            return None
        return self.result(s)

    def decide(self, s: dict) -> bool:
        p = self.params
        if s["family"] is None or s["flow_rate_per_s"] < p["min_flows_per_s"]:
            return False
        # Distributed means many sources. One client firing a burst of DNS
        # lookups at its resolver (seen on real traffic: 205 queries in a
        # second, one source) has a flood's rate and shape but is not a DDoS.
        if s.get("distinct_sources", p.get("min_sources", 1)) < p.get("min_sources", 1):
            return False
        base = s.get("baseline_flow_rate_per_s")
        if base and s["flow_rate_per_s"] < p["baseline_multiplier"] * base:
            return False
        return True

    def confidence(self, s: dict) -> float:
        p = self.params
        over = clamp01(math.log10(max(1.0, s["flow_rate_per_s"] / p["min_flows_per_s"])))
        shares = {"SYN flood": s["syn_only_share"], "TCP flood": s["top_dst_port_share"]}
        share = shares.get(s["family"].split(" (")[0] if s["family"] else "", s["udp_share"])
        shape = clamp01((share - p["shape_share"]) / (1 - p["shape_share"])) if share is not None else 0.0
        return round(0.6 + 0.2 * over + 0.2 * shape, 4)

    def result(self, s: dict) -> dict:
        self.alerts += 1
        ev = {k: v for k, v in s.items() if not k.startswith("_")}
        return {
            "threat": "DDoS",
            "confidence": self.confidence(s),
            "model": "ddos_rate_entropy",
            "confidence_kind": self.confidence_kind,
            "subtype": s["family"] + (" (spoofed sources likely)" if s["spoofed_sources_likely"] else ""),
            **ev,
            "_event_start": s["_event_start"],
            "_event_end": s["_event_end"],
            "_replay_inputs": {k: v for k, v in ev.items() if k in (
                "flow_rate_per_s", "family", "syn_only_share", "udp_share", "top_dst_port_share",
                "baseline_flow_rate_per_s", "spoofed_sources_likely", "distinct_sources")},
        }

    def replay(self, inputs: dict) -> Optional[dict]:
        s = dict(inputs)
        if not self.decide(s):
            return {"threat": "Benign", "confidence": 0.0}
        return {"threat": "DDoS", "confidence": self.confidence(s)}
