#!/usr/bin/env python3
"""
verify_beacon_detection.py -- did NetSentinel detect the labelled beacon?

Companion to beacon_harness.py. The harness produced real TLS check-ins to
api.telegram.org on a known interval and logged every one. This script replays
the capture through the REAL pipeline and answers, in order:

  1. Did the extractor produce enough flows to the beacon destination to reach
     the 100-flow session threshold? (If not, nothing else matters -- the C2
     model is never invoked. This was the exact failure on the malware
     sandbox captures.)
  2. Were session events actually emitted for that host pair?
  3. What did the C2 model say -- and if it did not fire, WHICH gate rejected
     it (probability, coefficient of variation, or the FFT conditions)?
  4. Did a C2 Beacon alert reach the alert manager?
  5. What else fired, i.e. false positives on the same capture.

IMPORTANT -- process the capture as ONE stream. Captures are usually split into
hourly files. The session builder accumulates flows per host pair across the
whole stream, so the files MUST be fed through a single PacketProcessor in
chronological order. Running each file separately resets the accumulator and
guarantees you never reach 100 flows. This script does it correctly; a naive
per-file loop does not.

    python verify_beacon_detection.py --pcap "D:/capture/ns_*.pcap" \
                                      --truth beacon_truth.jsonl

READ THE RESULT HONESTLY
------------------------
The beacon's timing was chosen by us, so a detection here proves the detector
works on real Telegram-shaped traffic -- NOT that it generalises to an
adversary who picks their own timing. It is a large step up from the simulator
(real network, real TLS, real destination, real jitter) but it is not an
external benchmark. For that, use a labelled third-party capture such as
CTU-13.
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import statistics
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from netsentinel.extractor import PacketProcessor            # noqa: E402
from netsentinel.models.registry import ModelRegistry        # noqa: E402
from netsentinel.pipeline.alert_manager import AlertManager   # noqa: E402
from netsentinel.pipeline.analyzer import FlowAnalyzer        # noqa: E402

SESSION_MIN_FLOWS = 100  # SessionBuilder default; see extractor/session_builder.py


def cls_of(a: dict) -> str:
    return a.get("threat_class") or a.get("threat_type") or a.get("threat") or "?"


def load_truth(path: str) -> dict:
    meta, recs = {}, []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            (meta.update(o) if o.get("_meta") else recs.append(o))
    dest_ips = {r["dest_ip"] for r in recs if r.get("dest_ip")}
    return {"meta": meta, "records": recs, "dest_ips": dest_ips,
            "src_ip": meta.get("src_ip"), "interval": meta.get("interval")}


def cv_of(flows: list) -> float:
    """Coefficient of variation of inter-arrival times -- the low-jitter gate."""
    iats = [f.get("iat", 0) for f in flows if f.get("iat", 0) > 0]
    if len(iats) < 2:
        return float("nan")
    m = statistics.fmean(iats)
    return (statistics.pstdev(iats) / m) if m else float("nan")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", required=True, help="pcap path or glob (quote the glob)")
    ap.add_argument("--truth", required=True, help="beacon_truth.jsonl from the harness")
    a = ap.parse_args()

    files = sorted(glob.glob(a.pcap)) if any(c in a.pcap for c in "*?[") else [a.pcap]
    files = [f for f in files if os.path.exists(f)]
    if not files:
        print(f"no capture files matched: {a.pcap}", file=sys.stderr)
        return 2

    truth = load_truth(a.truth)
    beacon_ips = truth["dest_ips"]
    n_checkins = len(truth["records"])
    ok_checkins = sum(1 for r in truth["records"] if r.get("ok"))

    print("=" * 72)
    print("  GROUND TRUTH")
    print("=" * 72)
    print(f"  host            {truth['meta'].get('host')}")
    print(f"  beacon dest IPs {sorted(beacon_ips) or '(none logged)'}")
    print(f"  source ip       {truth['src_ip']}")
    print(f"  interval        {truth['interval']}s")
    print(f"  check-ins       {n_checkins} logged ({ok_checkins} succeeded)")
    print(f"  capture files   {len(files)} (processed as ONE stream)")

    reg = ModelRegistry()
    reg.load_all()
    an = FlowAnalyzer(reg, AlertManager(max_stored=500000))
    pp = PacketProcessor()          # single instance: session state must persist

    types = collections.Counter()
    alerts, beacon_sessions = [], []
    flows_to_beacon = 0

    for path in files:
        for ev in pp.process_pcap(path):
            if ev is None:
                continue
            t = ev.get("type", "flow")
            types[t] += 1
            if t == "flow" and ev.get("dest_ip") in beacon_ips:
                flows_to_beacon += 1
            if t == "session":
                pair = {ev.get("dest_ip"), ev.get("source_ip")}
                if pair & beacon_ips:
                    beacon_sessions.append(ev)
            res = an.analyze_flow(ev)
            if res:
                alerts.append(res)
    try:
        alerts.extend(an.flush_portscan_buffer() or [])
    except Exception:
        pass

    print()
    print("=" * 72)
    print("  1. DID WE REACH THE SESSION THRESHOLD?")
    print("=" * 72)
    print(f"  events by type          {dict(types)}")
    print(f"  flow events to beacon   {flows_to_beacon}")
    print(f"  threshold needed        {SESSION_MIN_FLOWS}")
    if flows_to_beacon < SESSION_MIN_FLOWS:
        print(f"  --> NO. Only {flows_to_beacon} flows reached the beacon destination,")
        print(f"      so no session was built and the C2 model was NEVER INVOKED.")
        print(f"      This is the same structural failure seen on the malware")
        print(f"      sandbox captures. Either run the harness longer, or the")
        print(f"      extractor is collapsing the check-ins into fewer flows")
        print(f"      (connection reuse / flow timeout) -- check that next.")
    else:
        print(f"  --> YES. Threshold crossed.")

    print()
    print("=" * 72)
    print("  2-3. WHAT DID THE C2 MODEL SAY?")
    print("=" * 72)
    if not beacon_sessions:
        print("  no session events for the beacon pair -> model not invoked")
    for i, s in enumerate(beacon_sessions):
        flows = s.get("flows", [])
        r = reg.c2.predict(flows)
        cv = cv_of(flows)
        print(f"  session {i}: {len(flows)} flows")
        print(f"    is_beacon   {r['is_beacon']}")
        print(f"    probability {r['confidence']:.3f}   (gate: > 0.90)")
        print(f"    cv of IATs  {cv:.3f}   (low-jitter gate: < 0.05)")
        print(f"    period est  {r.get('periodicity_seconds', 0):.1f}s "
              f"(actual {truth['interval']}s)")
        if not r["is_beacon"]:
            why = []
            if r["confidence"] <= 0.90:
                why.append("probability below 0.90")
            if not (cv < 0.05):
                why.append(f"cv {cv:.3f} not < 0.05")
            why.append("FFT conditions not met (fft>0.15, entropy<0.85, prom>3.0)")
            print(f"    REJECTED BY: {'; '.join(why)}")

    print()
    print("=" * 72)
    print("  4-5. ALERTS")
    print("=" * 72)
    by_class = collections.Counter(cls_of(x) for x in alerts)
    c2_alerts = [x for x in alerts if cls_of(x) == "C2 Beacon"]
    print(f"  total alerts    {len(alerts)}")
    print(f"  by class        {dict(by_class)}")
    print(f"  by severity     {dict(collections.Counter(x.get('severity') for x in alerts))}")
    print()
    print(f"  C2 Beacon alerts: {len(c2_alerts)}")
    for x in c2_alerts:
        print(f"    src={x.get('source_ip')} dst={x.get('dest_ip')} "
              f"conf={x.get('confidence')} sev={x.get('severity')}")

    hit = any(x.get("dest_ip") in beacon_ips for x in c2_alerts)
    print()
    print("=" * 72)
    print("  VERDICT")
    print("=" * 72)
    if hit:
        print("  DETECTED -- a C2 Beacon alert fired on the labelled destination.")
        print("  Valid claim: 'detects real Telegram-shaped beaconing on live traffic'.")
        print("  NOT a claim about adversary-chosen timing -- we picked the interval.")
    else:
        print("  NOT DETECTED -- no C2 Beacon alert on the labelled destination.")
        print("  Sections 1-3 above say which stage stopped it. Report this as a")
        print("  measured negative; do not describe C2 detection as working on")
        print("  real traffic until it does.")
    other = sum(v for k, v in by_class.items() if k != "C2 Beacon")
    print(f"  Alerts on everything else: {other} "
          f"(false positives, unless the capture contains a real intrusion)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
