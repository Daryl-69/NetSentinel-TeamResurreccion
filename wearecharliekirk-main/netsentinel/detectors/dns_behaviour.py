"""DNS behaviour -- record-type mix, NXDOMAIN rate, subdomain fan-out, bytes.

PS 26145 threat (c) lists four signals for DGA and DNS tunnelling: entropy,
n-grams, query length and record-type anomalies. The character-level
CNN-BiLSTM and the VAE judge one name at a time (entropy, n-grams, length).
This tracker adds what only shows up across many queries from one host over
five minutes:

* NXDOMAIN burst -> "DGA": a DGA bot resolves many names that do not exist.
  Fires on >= 20 NXDOMAIN replies to one host, >= 50% of its replies, over
  >= 10 different base domains.
* Record-type anomaly -> "DNS Tunnel": >= 30 queries from one host to one
  base domain, >= 20 distinct names, and >= 50% of them TXT / NULL / CNAME /
  MX / SRV / ANY / private types (the types tunnel tools carry data in).
* Subdomain fan-out -> "DNS Tunnel": >= 50 distinct names under one base
  domain whose leftmost labels average >= 20 characters.

It also keeps the bytes each host sent in queries and received in replies
for each base domain, so DNS-tunnel alerts carry measured byte counts
instead of none (they are no longer invented; see analyzer.py).

Known false positives: DNS-based reputation lookups (some antivirus and
mail-filter products encode hashes as subdomains) look like fan-out; allow
them per site with DNS_BEHAVIOUR["allow_bases"].
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Optional

from netsentinel.detectors.base import RuleDetector, base_domain, Cooldown

QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 13: "HINFO", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY", 52: "TLSA",
    64: "SVCB", 65: "HTTPS", 99: "SPF", 255: "ANY", 257: "CAA",
}


def qtype_name(q) -> str:
    try:
        q = int(q)
    except (TypeError, ValueError):
        return str(q or "?")
    if 65280 <= q <= 65534:
        return "PRIVATE"
    return QTYPE_NAMES.get(q, f"TYPE{q}")


class _Host:
    __slots__ = ("q", "r", "qtypes", "nx", "responses", "queries", "nx_bases")

    def __init__(self):
        self.q = deque(); self.r = deque()
        self.qtypes = Counter(); self.nx = 0; self.responses = 0; self.queries = 0
        self.nx_bases = Counter()


class _Base:
    __slots__ = ("q", "names", "qtypes", "rare", "label_len", "bytes_out", "bytes_in", "nx", "n")

    def __init__(self):
        self.q = deque(); self.names = Counter(); self.qtypes = Counter()
        self.rare = 0; self.label_len = 0; self.bytes_out = 0; self.bytes_in = 0; self.nx = 0; self.n = 0


class DnsBehaviourTracker(RuleDetector):
    key = "dns_behaviour"
    name = "dns_behaviour_rules"
    version = "1"
    confidence_kind = "rule_score"

    def __init__(self, params: dict, allow_bases=None, max_hosts: int = 20000):
        super().__init__(params)
        self.window = float(params["window_s"])
        self.rare = set(params["rare_types"])
        self.allow = set(allow_bases or ()) | set(params.get("allow_bases", ()))
        self.cool = Cooldown(params["cooldown_s"])
        self.max_hosts = max_hosts
        self._h: dict[str, _Host] = {}
        self._b: dict[tuple, _Base] = {}

    # ------------------------------------------------------------ queries
    def observe_query(self, event: dict) -> list:
        host = event.get("source_ip")
        name = (event.get("domain") or "").lower().rstrip(".")
        ts = event.get("timestamp")
        if not host or not name or ts is None:
            return []
        ts = float(ts)
        qt = qtype_name(event.get("query_type", 1))
        qbytes = int(event.get("query_bytes") or 0)
        base = base_domain(name)
        h = self._host(host)
        if h is None:
            return []
        rec = (ts, base, name, qt, qbytes)
        h.q.append(rec); h.queries += 1; h.qtypes[qt] += 1
        b = self._b.get((host, base))
        if b is None:
            b = _Base(); self._b[(host, base)] = b
        b.q.append(rec); b.n += 1; b.names[name] += 1; b.qtypes[qt] += 1
        b.rare += int(qt in self.rare); b.bytes_out += qbytes
        b.label_len += len(name.split(".")[0])
        self._expire(host, ts)
        self.runs += 1
        out = []
        if base not in self.allow:
            for rule in (self._rule_record_type, self._rule_fanout):
                r = rule(host, base, b, ts)
                if r:
                    out.append(r)
        return out

    # ---------------------------------------------------------- responses
    def observe_response(self, event: dict) -> list:
        host = event.get("source_ip")          # the client the reply went to
        name = (event.get("domain") or "").lower().rstrip(".")
        ts = event.get("timestamp")
        if not host or ts is None:
            return []
        ts = float(ts)
        base = base_domain(name) if name else ""
        rcode = int(event.get("rcode") or 0)
        rbytes = int(event.get("response_bytes") or 0)
        h = self._host(host)
        if h is None:
            return []
        rec = (ts, base, rcode, rbytes, name)
        h.r.append(rec); h.responses += 1
        if rcode == 3:
            h.nx += 1; h.nx_bases[base] += 1
        b = self._b.get((host, base)) if base else None
        if b is not None:
            b.bytes_in += rbytes
            b.nx += int(rcode == 3)
        self._expire(host, ts)
        r = self._rule_nxdomain(host, h, ts)
        return [r] if r else []

    # --------------------------------------------------------------- rules
    def _rule_nxdomain(self, host, h: _Host, ts) -> Optional[dict]:
        p = self.params
        if h.nx < p["nx_min_responses"] or h.responses < p["nx_min_queries"]:
            return None
        rate = h.nx / max(1, h.responses)
        if rate < p["nx_min_rate"] or len(h.nx_bases) < p["nx_min_base_domains"]:
            return None
        ok, held = self.cool.allow((host, "nx"), ts)
        if not ok:
            self.suppressed += 1
            return None
        self.alerts += 1
        inputs = {"rule": "nxdomain_burst", "nxdomain_replies": h.nx, "replies": h.responses,
                  "nxdomain_rate": rate, "nxdomain_base_domains": len(h.nx_bases)}
        conf = self.replay(inputs)["confidence"]
        samples = [r[4] for r in list(h.r)[-50:] if r[2] == 3][-5:]
        ev = {
            "rule": "nxdomain_burst", "window_s": self.window,
            "nxdomain_replies": h.nx, "replies": h.responses, "queries": h.queries,
            "nxdomain_rate": round(rate, 3), "nxdomain_base_domains": len(h.nx_bases),
            "sample_nxdomain_names": samples, "qtype_mix": dict(h.qtypes.most_common(8)),
            "alerts_suppressed_since_last": held,
        }
        return self._result("DGA", "NXDOMAIN burst", conf, host, None, h.q[0][0] if h.q else ts, ts, ev, inputs)

    def _rule_record_type(self, host, base, b: _Base, ts) -> Optional[dict]:
        p = self.params
        if b.n < p["tunnel_min_queries"] or len(b.names) < p["tunnel_min_unique_names"]:
            return None
        share = b.rare / b.n
        if share < p["tunnel_rare_type_share"]:
            return None
        ok, held = self.cool.allow((host, "rtype", base), ts)
        if not ok:
            self.suppressed += 1
            return None
        self.alerts += 1
        inputs = {"rule": "record_type_anomaly", "queries": b.n, "unique_names": len(b.names),
                  "rare_type_share": share}
        conf = self.replay(inputs)["confidence"]
        ev = self._base_evidence("record_type_anomaly", base, b)
        ev["rare_type_share"] = round(share, 3)
        ev["alerts_suppressed_since_last"] = held
        rare = [t for t, _ in b.qtypes.most_common() if t in self.rare]
        return self._result("DNS Tunnel", "record-type anomaly (" + "/".join(rare[:3]) + ")", conf,
                            host, base, b.q[0][0], ts, ev, inputs)

    def _rule_fanout(self, host, base, b: _Base, ts) -> Optional[dict]:
        p = self.params
        uniq = len(b.names)
        if uniq < p["fanout_min_unique_names"]:
            return None
        mean_label = b.label_len / b.n
        if mean_label < p["fanout_min_mean_label_len"]:
            return None
        ok, held = self.cool.allow((host, "fanout", base), ts)
        if not ok:
            self.suppressed += 1
            return None
        self.alerts += 1
        inputs = {"rule": "subdomain_fanout", "unique_names": uniq, "mean_label_len": mean_label}
        conf = self.replay(inputs)["confidence"]
        ev = self._base_evidence("subdomain_fanout", base, b)
        ev["alerts_suppressed_since_last"] = held
        return self._result("DNS Tunnel", "subdomain fan-out", conf, host, base, b.q[0][0], ts, ev, inputs)

    # ------------------------------------------------------------- helpers
    def _base_evidence(self, rule, base, b: _Base) -> dict:
        return {
            "rule": rule, "window_s": self.window, "base_domain": base,
            "queries": b.n, "unique_names": len(b.names),
            "mean_label_len": round(b.label_len / max(1, b.n), 1),
            "qtype_mix": dict(b.qtypes.most_common(8)),
            "sample_names": [n for n, _ in b.names.most_common()][:3],
            "nxdomain_replies": b.nx,
            "byte_ratio": {"outbound": int(b.bytes_out), "inbound": int(b.bytes_in)},
        }

    def _result(self, threat, subtype, conf, host, base, t0, t1, ev, replay_inputs) -> dict:
        return {
            "threat": threat, "confidence": conf, "model": "dns_behaviour_rules",
            "confidence_kind": self.confidence_kind, "subtype": subtype,
            "domain": base or "", **ev,
            "_event_start": float(t0), "_event_end": float(t1),
            "_replay_inputs": dict(replay_inputs),
        }

    def bytes_for(self, host: str, name: str) -> Optional[tuple]:
        """(bytes out in queries, bytes in replies) for host -> base domain, this window."""
        b = self._b.get((host, base_domain(name or "")))
        # a ratio from one or two queries, or before any reply was seen,
        # says nothing; report bytes only once there is something to compare
        if b is None or b.n < 3 or b.bytes_out <= 0 or b.bytes_in <= 0:
            return None
        return int(b.bytes_out), int(b.bytes_in)

    def host_summary(self, host: str) -> Optional[dict]:
        h = self._h.get(host)
        if h is None:
            return None
        return {"window_s": self.window, "queries": h.queries, "replies": h.responses,
                "nxdomain_replies": h.nx,
                "nxdomain_rate": round(h.nx / h.responses, 3) if h.responses else None,
                "qtype_mix": dict(h.qtypes.most_common(8))}

    def _host(self, host) -> Optional[_Host]:
        h = self._h.get(host)
        if h is None:
            if len(self._h) >= self.max_hosts:
                return None
            h = _Host(); self._h[host] = h
        return h

    def _expire(self, host, ts):
        cutoff = ts - self.window
        h = self._h[host]
        while h.q and h.q[0][0] < cutoff:
            _, base, name, qt, qb = h.q.popleft()
            h.queries -= 1; h.qtypes[qt] -= 1
            if h.qtypes[qt] <= 0: del h.qtypes[qt]
            b = self._b.get((host, base))
            if b is not None and b.q and b.q[0][0] < cutoff:
                _, _, bname, bqt, bqb = b.q.popleft()
                b.n -= 1; b.names[bname] -= 1
                if b.names[bname] <= 0: del b.names[bname]
                b.qtypes[bqt] -= 1
                if b.qtypes[bqt] <= 0: del b.qtypes[bqt]
                b.rare -= int(bqt in self.rare); b.bytes_out -= bqb
                b.label_len -= len(bname.split(".")[0])
                if b.n <= 0:
                    self._b.pop((host, base), None)
        while h.r and h.r[0][0] < cutoff:
            _, base, rcode, rb, _n = h.r.popleft()
            h.responses -= 1
            if rcode == 3:
                h.nx -= 1; h.nx_bases[base] -= 1
                if h.nx_bases[base] <= 0: del h.nx_bases[base]
            b = self._b.get((host, base))
            if b is not None:
                b.bytes_in = max(0, b.bytes_in - rb)
                b.nx = max(0, b.nx - int(rcode == 3))
        if not h.q and not h.r:
            self._h.pop(host, None)

    def replay(self, inputs: dict) -> Optional[dict]:
        p = self.params
        rule = inputs.get("rule")
        if rule == "nxdomain_burst":
            ok = (inputs["nxdomain_replies"] >= p["nx_min_responses"] and inputs["replies"] >= p["nx_min_queries"]
                  and inputs["nxdomain_rate"] >= p["nx_min_rate"]
                  and inputs["nxdomain_base_domains"] >= p["nx_min_base_domains"])
            threat = "DGA"
            conf = 0.6 + 0.25 * min(1.0, (inputs["nxdomain_rate"] - p["nx_min_rate"]) / (1 - p["nx_min_rate"])) \
                + 0.15 * min(1.0, inputs["nxdomain_replies"] / (4 * p["nx_min_responses"]))
        elif rule == "record_type_anomaly":
            ok = (inputs["queries"] >= p["tunnel_min_queries"] and inputs["unique_names"] >= p["tunnel_min_unique_names"]
                  and inputs["rare_type_share"] >= p["tunnel_rare_type_share"])
            threat = "DNS Tunnel"
            conf = 0.6 + 0.25 * min(1.0, (inputs["rare_type_share"] - p["tunnel_rare_type_share"]) / (1 - p["tunnel_rare_type_share"])) \
                + 0.15 * min(1.0, inputs["unique_names"] / (5 * p["tunnel_min_unique_names"]))
        elif rule == "subdomain_fanout":
            ok = (inputs["unique_names"] >= p["fanout_min_unique_names"]
                  and inputs["mean_label_len"] >= p["fanout_min_mean_label_len"])
            threat = "DNS Tunnel"
            conf = 0.6 + 0.2 * min(1.0, (inputs["mean_label_len"] - p["fanout_min_mean_label_len"]) / 40.0) \
                + 0.2 * min(1.0, inputs["unique_names"] / (4 * p["fanout_min_unique_names"]))
        else:
            return None
        return {"threat": threat if ok else "Benign", "confidence": round(conf, 4) if ok else 0.0}
