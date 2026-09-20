#!/usr/bin/env python3
"""
evaluate_detection.py -- per-class detection rate and false-positive rate.

READ THIS BEFORE QUOTING ANY NUMBER THIS PRINTS.

There are two halves to this evaluation and they are NOT equally trustworthy.

  HALF 1 -- RECALL, on simulator-generated attacks.  CIRCULAR. Warn loudly.
      The attack traffic comes from netsentinel/simulator/traffic_gen.py, which
      was written by the same people as the detectors. Measuring recall on it
      asks "does the detector fire on the thing we built it to fire on", not
      "does it catch real attacks". It is an UPPER BOUND and nothing more.
      A real recall number needs labelled real intrusion captures
      (CIC-IDS2017, CTU-13, UNSW-NB15). Those are not available offline here.

  HALF 2 -- FALSE POSITIVES, on real captured traffic.  NOT circular. Useful.
      Real packets off a real link, scored by the real pipeline. The one
      assumption is that the capture contains no actual intrusion, which is
      unverified -- so read it as "alerts raised on ordinary traffic", and
      treat it as an upper bound on the true false-positive rate.

So: the FP half is evidence. The recall half is a smoke test that the wiring
works, and must never be presented as detection accuracy.

Usage:
    python scripts/evaluate_detection.py [--n 500] [--pcap path/to/real.pcap]
"""
from __future__ import annotations

import argparse
import collections
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from netsentinel.models.registry import ModelRegistry          # noqa: E402
from netsentinel.pipeline.alert_manager import AlertManager     # noqa: E402
from netsentinel.pipeline.analyzer import FlowAnalyzer          # noqa: E402
from netsentinel.simulator import traffic_gen as G              # noqa: E402

# attack class -> (generator, the threat_class we expect to see)
ATTACKS = [
    ("ddos",      G.generate_ddos_flow,      {"DDoS"}),
    ("dga",       G.generate_dga_dns,        {"DGA"}),
    ("c2",        G.generate_c2_session,     {"C2 Beacon"}),
    ("port_scan", G.generate_port_scan_flow, {"Port Scan"}),
    ("exfil",     G.generate_exfil_dns,      {"Data Exfiltration", "DNS Tunnel"}),
]
BENIGN = [("normal_flow", G.generate_normal_flow), ("normal_dns", G.generate_normal_dns)]


def fresh():
    reg = ModelRegistry()
    reg.load_all()
    return FlowAnalyzer(reg, AlertManager(max_stored=200000))


def run_events(an, events):
    """Feed events, return list of alerts (including flushed port-scan alerts)."""
    out = []
    for ev in events:
        if ev is None:
            continue
        a = an.analyze_flow(ev)
        if a:
            out.append(a)
    try:
        out.extend(an.flush_portscan_buffer() or [])
    except Exception:
        pass
    return out


def cls_of(a):
    return a.get("threat_class") or a.get("threat_type") or a.get("threat") or "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=500, help="samples per class")
    ap.add_argument("--pcap", default=None, help="real capture for the FP half")
    a = ap.parse_args()

    an = fresh()

    print("=" * 74)
    print("  HALF 1 -- RECALL on SIMULATOR attacks  [CIRCULAR: upper bound only]")
    print("=" * 74)
    print(f"  {'attack class':14s}{'n':>6}{'detected':>10}{'rate':>9}   what fired")
    recall = {}
    # Port scan is an AGGREGATE detector: it emits one alert per scanning
    # SOURCE per time window, not one per flow. Scoring it per-flow measures
    # the wrong thing entirely -- 500 scan flows from 5 hosts SHOULD produce
    # exactly 5 alerts, and a per-flow metric calls that 1% when it is in fact
    # complete detection. Rows marked [per-source] use source-level recall.
    AGGREGATE = {"port_scan"}
    for name, gen, expect in ATTACKS:
        events = [gen() for _ in range(a.n)]
        alerts = run_events(an, events)
        seen = collections.Counter(cls_of(x) for x in alerts)
        top = ", ".join(f"{k}:{v}" for k, v in seen.most_common(3)) or "-"
        if name in AGGREGATE:
            truth = {e.get("source_ip") for e in events if e.get("source_ip")}
            found = {x.get("source_ip") for x in alerts if cls_of(x) in expect}
            hit = len(truth & found)
            denom = max(len(truth), 1)
            recall[name] = hit / denom
            print(f"  {name:14s}{denom:>6}{hit:>10}{recall[name]:>8.1%}   {top}   [per-source]")
        else:
            hit = sum(1 for x in alerts if cls_of(x) in expect)
            recall[name] = hit / a.n if a.n else 0.0
            print(f"  {name:14s}{a.n:>6}{hit:>10}{recall[name]:>8.1%}   {top}")
    print("\n  ^ These are NOT accuracy figures. The generator and the detectors")
    print("    share authorship. Treat as a wiring smoke test.")

    print()
    print("=" * 74)
    print("  HALF 2 -- FALSE POSITIVES")
    print("=" * 74)

    an2 = fresh()
    print(f"  (a) simulator benign traffic, n={a.n} each  [also partly circular]")
    for name, gen in BENIGN:
        alerts = run_events(an2, [gen() for _ in range(a.n)])
        seen = collections.Counter(cls_of(x) for x in alerts)
        top = ", ".join(f"{k}:{v}" for k, v in seen.most_common(3)) or "-"
        print(f"      {name:12s} alerts {len(alerts):>5}  rate {len(alerts)/a.n:>7.2%}   {top}")

    if a.pcap and os.path.exists(a.pcap):
        from netsentinel.extractor import PacketProcessor
        an3 = fresh()
        pp = PacketProcessor()
        n_ev = 0
        alerts = []
        for ev in pp.process_pcap(a.pcap):
            if ev is None:
                continue
            n_ev += 1
            r = an3.analyze_flow(ev)
            if r:
                alerts.append(r)
        try:
            alerts.extend(an3.flush_portscan_buffer() or [])
        except Exception:
            pass
        sev = collections.Counter(x.get("severity") for x in alerts)
        seen = collections.Counter(cls_of(x) for x in alerts)
        print(f"\n  (b) REAL capture  [NOT circular -- this is the evidence]")
        print(f"      {os.path.basename(a.pcap)}")
        print(f"      flow events        {n_ev:,}")
        print(f"      alerts             {len(alerts):,}   ({len(alerts)/max(n_ev,1):.2%} of events)")
        print(f"      by class           {dict(seen)}")
        print(f"      by severity        {dict(sev)}")
        actionable = sum(v for k, v in sev.items() if k in ("CRITICAL", "HIGH"))
        print(f"      CRITICAL+HIGH      {actionable}")
        print("      Assumption: this capture contains no real intrusion (unverified),")
        print("      so read these as an UPPER bound on the false-positive rate.")
    else:
        print("\n  (b) no --pcap given; skipping the real-traffic half (the useful one)")

    print()
    print("=" * 74)
    print("  Honest summary")
    print("=" * 74)
    print("  - No accuracy/recall figure here is fit for publication: the attack")
    print("    traffic is self-generated. Say 'wiring verified', not 'X% recall'.")
    print("  - The real-capture alert counts ARE measured on real packets and are")
    print("    the number to quote when discussing analyst load.")
    print("  - A publishable recall figure needs labelled real intrusion data.")


if __name__ == "__main__":
    main()
