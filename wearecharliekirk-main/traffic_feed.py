#!/usr/bin/env python3
"""Drive a NetSentinel sensor with synthetic threat traffic.

    python traffic_feed.py                    # sensor on http://localhost:8000
    python traffic_feed.py --sensor http://localhost:8000 --speed 1

Generates synthetic flow and DNS events with netsentinel/simulator and posts
them to the sensor's /api/ingest endpoint, where the same analyzer that reads
captured traffic scores them. Runs one pass of about 35 seconds and prints
what it sends and what the sensor reports back. Every address is private
(inside) or from the RFC 5737 documentation ranges (outside); nothing here
touches a real network.

Segments (each maps to one PS 26145 threat family):
  1  recon        vertical port scan, then a sweep of one port across a subnet
  2  host chain   a workstation reaches recon / code / messaging / storage
                  services in turn (the Inspector-Sentry view watches this)
  3  beaconing    36 HTTPS check-ins, one a minute of wire time
  4  dns          TXT-tunnel names and an NXDOMAIN burst
  5  encrypted    a rare TLS client with a fixed session shape
  6  exfiltration a 7.5 MB upload to one external host, plus DNS-encoded data
  7  volumetric   spoofed SYN flood and NTP reflection
"""
import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsentinel.simulator import traffic_gen as G  # noqa: E402

if os.name == "nt":
    os.system("")                                      # enable ANSI colours on Windows

O = "\033[38;5;208m"; R = "\033[38;5;203m"; GR = "\033[38;5;114m"; C = "\033[38;5;81m"
W = "\033[97m"; D = "\033[38;5;244m"; B = "\033[1m"; X = "\033[0m"
_printed = {}


def _relabel(ev):
    ev = dict(ev)
    ev.pop("synthetic", None)
    dom = ev.get("domain")
    if isinstance(dom, str):
        ev["domain"] = dom.replace("tunnel-sim.net", "relay-cdn.example").replace("exfiltrate.top", "sync-cache.example")
    return ev


class Sensor:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.sent = 0
        self.by_class = {}

    def _post(self, path, body, timeout=25):
        data = json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode() or "{}")

    def feed(self, events):
        events = [_relabel(e) for e in events]
        try:
            r = self._post("/api/ingest", {"events": events})
        except (urllib.error.URLError, OSError) as e:
            print(f"{R}  sensor unreachable: {e}{X}")
            sys.exit(1)
        self.sent += len(events)
        for a in r.get("alerts", []):
            cls = a.get("threat_class")
            self.by_class[cls] = self.by_class.get(cls, 0) + 1
            key = (cls, a.get("threat_subtype"))
            if _printed.get(key, 0) < 2:
                _printed[key] = _printed.get(key, 0) + 1
                print(f"    {R}{B}<- flagged{X}  {W}{cls}{X}  {D}{a.get('threat_subtype') or ''}"
                      f"  ({a.get('detector')}, confidence {a.get('confidence')}){X}")
        return r


def clock():
    return time.strftime("%H:%M:%S", time.localtime())


def segment(n, title, tag):
    print(f"\n{O}{B}[{n}/7] {title}{X}  {D}{tag}{X}")


def line(text):
    print(f"    {C}-> {text}{X}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sensor", default="http://localhost:8000")
    ap.add_argument("--speed", type=float, default=1.0, help="2 = twice as fast")
    a = ap.parse_args()
    sp = max(0.2, a.speed)
    s = Sensor(a.sensor)
    random.seed()

    print(f"{O}{B}  NetSentinel  ·  synthetic threat feed{X}")
    print(f"  {D}sensor {a.sensor}   started {clock()}{X}")
    try:
        h = json.loads(urllib.request.urlopen(a.sensor.rstrip('/') + "/api/health", timeout=5).read())
        loaded = sum(1 for v in (h.get('models') or {}).get('models_loaded', {}).values() if v)
        print(f"  {GR}sensor online, {loaded} models loaded{X}\n")
    except Exception as e:
        print(f"  {R}sensor not reachable at {a.sensor}: {e}{X}")
        sys.exit(1)

    t0 = time.time()

    line = lambda text: print(f"    {C}-> {text}{X}")  # noqa: E731 (local shadow ok)
    print(f"{D}  laying down normal background traffic first...{X}")
    for _ in range(6):
        s.feed([G.generate_normal_flow() for _ in range(30)] + [G.generate_normal_dns() for _ in range(10)])
        time.sleep(0.4 / sp)

    segment(1, "Reconnaissance", "one source probing many ports, then many hosts")
    line("vertical scan: 110 ports on one host")
    s.feed(G.generate_port_scan_burst())
    time.sleep(1.5 / sp)
    line("sweep: port 445 across a /24")
    s.feed(G.generate_host_sweep(hosts=70))
    time.sleep(1.5 / sp)

    segment(2, "Living-off-trusted-services chain", "one workstation, four legitimate services in turn")
    watched = None
    try:
        r = s._post("/api/cascade/attack", {})
        watched = r.get("host")
    except Exception:
        pass
    if watched:
        line(f"workstation {W}{B}{watched}{X}{C} starts reaching services it never touches")
    else:
        line("a workstation starts reaching services it never touches")
    for step in ("recon API", "code / paste site", "messaging API (beacon)", "cloud storage (upload)"):
        line(f"  -> {step}")
        time.sleep(1.1 / sp)
    line("the Inspector-Sentry view is scoring this host hour by hour")
    time.sleep(1.0 / sp)

    segment(3, "Command-and-control beaconing", "36 check-ins, ~60 s apart (wire time)")
    line("HTTPS to one external host, machine-regular timing")
    s.feed(G.generate_c2_beacon())
    time.sleep(2.0 / sp)

    segment(4, "DNS abuse", "tunnelling and generated names")
    line("TXT tunnel: data in the subdomains")
    s.feed(G.generate_txt_tunnel())
    time.sleep(1.5 / sp)
    line("NXDOMAIN burst: generated domains that don't resolve")
    s.feed(G.generate_nxdomain_burst())
    for _ in range(8):
        s.feed([G.generate_dga_dns()])
        time.sleep(0.25 / sp)
    time.sleep(1.0 / sp)

    segment(5, "Encrypted session", "a rare client, no decryption")
    line("fixed-shape TLS sessions from an uncommon fingerprint")
    s.feed(G.generate_tls_implant())
    time.sleep(1.8 / sp)

    segment(6, "Data exfiltration", "asymmetric upload and DNS-encoded data")
    line("7.5 MB out to one external host, little back")
    s.feed(G.generate_exfil_upload())
    time.sleep(1.2 / sp)
    for _ in range(8):
        s.feed([G.generate_exfil_dns()])
        time.sleep(0.25 / sp)
    time.sleep(1.0 / sp)

    segment(7, "Volumetric flood", "many sources, one target")
    line("spoofed SYN flood")
    s.feed(G.generate_syn_flood_burst())
    time.sleep(1.5 / sp)
    line("NTP reflection / amplification")
    s.feed(G.generate_reflection_burst())
    time.sleep(1.5 / sp)

    dur = time.time() - t0
    print(f"\n{O}{B}  done in {dur:.0f}s{X}  {D}· {s.sent:,} events sent{X}")
    order = ["DDoS", "C2 Beacon", "DGA", "DNS Tunnel", "Encrypted Malware", "Port Scan", "Data Exfiltration"]
    for cls in order:
        if cls in s.by_class:
            print(f"    {GR}{B}{s.by_class[cls]:>4}{X}  {W}{cls}{X}")
    other = {k: v for k, v in s.by_class.items() if k not in order}
    for k, v in other.items():
        print(f"    {GR}{B}{v:>4}{X}  {W}{k}{X}")
    if not s.by_class:
        print(f"    {D}no alerts returned — is the sensor's analyzer running?{X}")


if __name__ == "__main__":
    main()
