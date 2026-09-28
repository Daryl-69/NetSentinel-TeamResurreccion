"""Replay captures through the live-mode pipeline and count what it raises.

Aggregate output only: alert counts per detector and subtype, how many
distinct sources and destinations were involved (counted through a salted
hash, never written out), totals and timing. No address, hostname or file
name is written to the output.

The captures are the team's own traffic. It is unlabelled, so every alert
counted here is an upper bound on false alarms, not a false-positive rate.

Captures are processed in the order given, through one analyzer, with the
sensor's own extractor (what live capture uses; CICFlowMeter is not run).
Long runs can be split into parts that each fit a time limit and merged:

    python model_comparisons/ps26145_live_path_eval.py run --salt S --out part1.json a.pcap b.pcap ...
    python model_comparisons/ps26145_live_path_eval.py run --salt S --out part2.json c.pcap ...
    python model_comparisons/ps26145_live_path_eval.py merge --out result.json part1.json part2.json

Detector state (C2 and TLS windows, baselines) starts fresh in each part.
"""
import argparse
import collections
import contextlib
import hashlib
import io
import json
import logging
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")
logging.disable(logging.WARNING)
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def _h(salt: str, ip) -> str:
    return hashlib.sha256((salt + "|" + str(ip)).encode()).hexdigest()[:16]


def run(files, salt, out_path):
    os.chdir(REPO)
    from netsentinel.models.registry import ModelRegistry
    from netsentinel.extractor.pcap_reader import PacketProcessor
    from netsentinel.pipeline.alert_manager import AlertManager
    from netsentinel.pipeline.analyzer import FlowAnalyzer
    from netsentinel.config import FLOW_IDLE_TIMEOUT, FLOW_ACTIVE_TIMEOUT, SESSION_MIN_FLOWS
    with contextlib.redirect_stdout(io.StringIO()):
        reg = ModelRegistry().load_all()
    an = FlowAnalyzer(reg, AlertManager(max_stored=500000), None)
    counts = collections.Counter()
    srcs, dsts = collections.defaultdict(set), collections.defaultdict(set)
    sev = collections.Counter()
    held = collections.Counter()
    ps_rules = collections.Counter()
    tot = collections.Counter()
    t0 = time.time()

    def take(a):
        k = "|".join([a["threat_class"], str(a.get("detector")), a.get("threat_subtype") or ""])
        counts[k] += 1
        sev[a.get("severity")] += 1
        if a.get("source_ip"):
            srcs[k].add(_h(salt, a["source_ip"]))
        if a.get("dest_ip"):
            dsts[k].add(_h(salt, a["dest_ip"]))
        held[k] += int((a.get("evidence") or {}).get("alerts_suppressed_since_last") or 0)
        if a["threat_class"] == "Port Scan":
            ps_rules[_scan_rule(a)] += 1

    for f in files:
        proc = PacketProcessor(idle_timeout=FLOW_IDLE_TIMEOUT, active_timeout=FLOW_ACTIVE_TIMEOUT,
                               session_min_flows=SESSION_MIN_FLOWS, use_cicflowmeter=False)
        for ev in proc.process_pcap(f):
            if ev is None:
                continue
            tot["events"] += 1
            if ev.get("type") == "flow" and ev.get("stub"):
                tot["probe_records"] += 1
            elif ev.get("type") == "flow":
                tot["flows"] += 1
            elif ev.get("type") == "dns":
                tot["dns_queries"] += 1
            for a in an.analyze(ev):
                take(a)
        st = proc.stats
        tot["files"] += 1
        tot["packets"] += st["packets_processed"]
        tot["bytes"] += st["bytes_processed"]
        tot["capture_span_s"] += st.get("capture_span_s") or 0
        tot["tls_client_hellos"] += st["flow_extractor"].get("tls_client_hellos", 0)
    for a in an.finish():
        take(a)
    part = {
        "totals": dict(tot),
        "elapsed_s": round(time.time() - t0, 1),
        "severity": dict(sev),
        "alerts": dict(counts),
        "sources": {k: sorted(v) for k, v in srcs.items()},
        "destinations": {k: sorted(v) for k, v in dsts.items()},
        "repeats_held": dict(held),
        "portscan_group_destination_flows_left_out": an.portscan_rule.skipped_group,
        "portscan_external_service_flows_left_out": getattr(an.portscan_rule, "skipped_external_service", 0),
        "portscan_decided_by": dict(ps_rules),
    }
    with open(out_path, "w") as fh:
        json.dump(part, fh)
    return part


def _scan_rule(a) -> str:
    """Which rule decided a port-scan alert (the tree's learned rules are
    neip >= 2, netcp >= 1 and rwa >= 52; the backstops are fixed thresholds)."""
    ev = a.get("evidence") or {}
    inner = ev.get("evidence") or {}
    reason = str(ev.get("reason") or "")
    if "neip=" in reason:
        if (inner.get("neip") or 0) >= 2:
            return "tree: neip >= 2 (unlisted internal hosts)"
        if (inner.get("netcp") or 0) >= 1:
            return "tree: netcp >= 1 (unlisted port on a listed host)"
        if (inner.get("rwa") or 0) >= 52:
            return "tree: rwa >= 52 (distinct targets, read as unanswered)"
        return "tree: other leaf"
    if "fan-out" in reason:
        return "backstop: >= 100 ports"
    if "host sweep" in reason:
        return "backstop: >= 32 hosts on one port"
    return "other"


def merge(parts, out_path, note, labels=None):
    tot, sev, counts, held = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
    srcs, dsts = collections.defaultdict(set), collections.defaultdict(set)
    skipped, skipped_ext, elapsed, hours = 0, 0, 0.0, []
    decided = collections.Counter()
    for p in parts:
        d = json.load(open(p))
        tot.update(d["totals"]); sev.update(d["severity"]); counts.update(d["alerts"]); held.update(d["repeats_held"])
        for k, v in d["sources"].items():
            srcs[k].update(v)
        for k, v in d["destinations"].items():
            dsts[k].update(v)
        skipped += d["portscan_group_destination_flows_left_out"]
        skipped_ext += d.get("portscan_external_service_flows_left_out", 0)
        decided.update(d.get("portscan_decided_by", {}))
        elapsed += d["elapsed_s"]
        hours.append(round(d["totals"].get("capture_span_s", 0) / 3600, 2))
    h = tot["capture_span_s"] / 3600 if tot["capture_span_s"] else 0
    per_day = h >= 1.0          # a rate per 24 h from minutes of capture means nothing
    rows = []
    for k, n in sorted(counts.items(), key=lambda x: -x[1]):
        cls, det, sub = k.split("|", 2)
        rows.append({"class": cls, "detector": det, "subtype": sub, "alerts": n,
                     "per_24h_of_capture": round(n / h * 24, 1) if per_day else None,
                     "distinct_sources": len(srcs[k]), "distinct_destinations": len(dsts[k]),
                     "repeats_held": held[k]})
    by_class = collections.Counter()
    for r in rows:
        by_class[r["class"]] += r["alerts"]
    res = {
        "what": note,
        "pipeline": "live-mode path: the sensor's own extractor and every detector; CICFlowMeter not run",
        "labels": labels or "none -- the team's own traffic; every alert is an upper bound on false alarms",
        "parts": len(parts),
        "captured_hours": round(h, 2),
        "captured_hours_per_part": hours,
        "state": "detector state (C2/TLS windows, baselines) starts fresh in each part",
        "totals": {k: tot[k] for k in ("files", "packets", "bytes", "flows", "probe_records",
                                       "dns_queries", "tls_client_hellos", "events")},
        "processing_s": round(elapsed, 1),
        "alerts_total": sum(counts.values()),
        "alerts_per_24h_of_capture": round(sum(counts.values()) / h * 24, 1) if per_day else None,
        "alerts_by_class": dict(by_class.most_common()),
        "severity": dict(sev),
        "by_detector": rows,
        "portscan_group_destination_flows_left_out": skipped,
        "portscan_external_service_flows_left_out": skipped_ext,
        "portscan_decided_by": dict(decided.most_common()),
    }
    with open(out_path, "w") as fh:
        json.dump(res, fh, indent=1)
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--salt", required=True, help="same value for every part of one evaluation; not saved")
    r.add_argument("--out", required=True)
    r.add_argument("files", nargs="+")
    m = sub.add_parser("merge")
    m.add_argument("--out", required=True)
    m.add_argument("--note", default="")
    m.add_argument("--labels", default=None, help="what is known about the traffic (default: unlabelled own traffic)")
    m.add_argument("parts", nargs="+")
    a = ap.parse_args()
    if a.cmd == "run":
        p = run(a.files, a.salt, a.out)
        print(json.dumps({"totals": p["totals"], "alerts": p["alerts"], "elapsed_s": p["elapsed_s"]}))
    else:
        res = merge(a.parts, a.out, a.note, a.labels)
        print(json.dumps({k: res[k] for k in ("captured_hours", "alerts_total", "alerts_per_24h_of_capture",
                                               "alerts_by_class", "severity")}, indent=1))


if __name__ == "__main__":
    main()
