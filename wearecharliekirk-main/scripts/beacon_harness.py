#!/usr/bin/env python3
"""
beacon_harness.py -- generate a REAL, benign Telegram-shaped beacon and label it.

WHY THIS EXISTS
---------------
NetSentinel's C2 detector has never been tested on real beacon traffic. The
malware sandbox captures we have are 25-200 seconds long with 5-19 flows; the
session builder needs 100 flows between one host pair before the C2 model is
invoked at all, so the detector was never even called. Worse, 3 of 4 Telegram
samples opened exactly ONE connection, so more capture time would not have
helped them.

This harness produces the thing we actually need: real TLS traffic to
api.telegram.org, on a known interval, with ground-truth labels, over a long
enough window to cross the 100-flow threshold.

WHAT IT IS, AND IS NOT
----------------------
This is an ordinary HTTPS client polling a public API endpoint once a minute.
There is no malware, no exploit, no payload, and no credential. It is the
network *shape* of Telegram-based C2 -- periodic short TLS sessions to
api.telegram.org -- which is all NetSentinel can see, because it never
decrypts. Run it on your own machine, on your own network.

No bot token is needed. An unauthenticated request returns a small error
response, but the DNS lookup, TCP connect, TLS handshake (SNI =
api.telegram.org) and small request/response all happen exactly as they would
for a real bot. Since the detector works on flow metadata and timing, not
content, that is sufficient -- and it keeps credentials out of this entirely.

ONE CONNECTION PER CHECK-IN
---------------------------
This is the point of the whole exercise, so it is deliberate: every check-in
opens a NEW TCP connection and closes it. Connection reuse (keep-alive) is what
made 3 of the 4 real samples invisible -- one long-lived socket is ONE flow no
matter how many beacons ride inside it. If you change this to a pooled
Session, the harness stops testing what it is meant to test.

USAGE
-----
Run this on the machine whose traffic is being captured, at the same time as
your capture service:

    python beacon_harness.py --interval 60 --duration 4h

Then verify with:

    python verify_beacon_detection.py --pcap "D:/capture/ns_*.pcap" \
                                      --truth beacon_truth.jsonl

Keep --interval at 30s or more. This is a public API; a slow poll is normal
client behaviour, a fast one is abuse.
"""
from __future__ import annotations

import argparse
import http.client
import json
import random
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

DEFAULT_HOST = "api.telegram.org"
# Unauthenticated on purpose -- see module docstring. Never put a real token here.
DEFAULT_PATH = "/bot0000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/getUpdates"


def parse_duration(s: str) -> float:
    """'4h' / '30m' / '90s' / '3600' -> seconds."""
    s = s.strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s and s[-1] in mult:
        return float(s[:-1]) * mult[s[-1]]
    return float(s)


def local_ip_for(host: str) -> str:
    """Source address the OS would use to reach `host` (no traffic sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 443))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def one_checkin(host: str, path: str, timeout: float) -> dict:
    """One beacon: fresh TCP connection, TLS, GET, read, close.

    Returns a ground-truth record. Never raises -- a failed check-in is still
    an event the capture will contain, so it is recorded with its error.
    """
    rec: dict = {
        "ts": time.time(),
        "iso": datetime.now(timezone.utc).isoformat(),
        "host": host,
    }
    conn = None
    t0 = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
        conn.connect()
        try:
            rec["dest_ip"] = conn.sock.getpeername()[0]
            rec["src_port"] = conn.sock.getsockname()[1]
        except Exception:
            pass
        # Connection: close -> server tears down after the response, so the
        # next check-in is unambiguously a new flow.
        conn.request("GET", path, headers={"Host": host, "Connection": "close",
                                           "User-Agent": "netsentinel-beacon-harness/1.0"})
        resp = conn.getresponse()
        body = resp.read()
        rec.update(status=resp.status, resp_bytes=len(body), ok=True)
    except Exception as exc:
        rec.update(ok=False, error=f"{type(exc).__name__}: {exc}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        rec["rtt_ms"] = round((time.monotonic() - t0) * 1000, 1)
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interval", type=float, default=60.0,
                    help="seconds between check-ins (default 60, minimum 30)")
    ap.add_argument("--jitter", type=float, default=0.05,
                    help="fractional jitter, e.g. 0.05 = +/-5%% (default 0.05)")
    ap.add_argument("--duration", default="4h",
                    help="how long to run: 4h / 30m / 90s (default 4h)")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--path", default=DEFAULT_PATH)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--out", default="beacon_truth.jsonl",
                    help="ground-truth log (default beacon_truth.jsonl)")
    a = ap.parse_args()

    if a.interval < 30:
        print("refusing --interval below 30s: this is a public API, poll politely.",
              file=sys.stderr)
        return 2

    total = parse_duration(a.duration)
    expected = int(total // a.interval)
    src = local_ip_for(a.host)

    # The 100-flow session threshold is the thing we are trying to cross.
    print("=" * 68)
    print("  NetSentinel beacon harness -- benign, labelled, real TLS")
    print("=" * 68)
    print(f"  target        : {a.host}   (unauthenticated, no token)")
    print(f"  source ip     : {src}")
    print(f"  interval      : {a.interval:.0f}s +/- {a.jitter*100:.0f}%")
    print(f"  duration      : {total/3600:.2f}h  -> ~{expected} check-ins")
    print(f"  ground truth  : {a.out}")
    if expected < 100:
        print()
        print(f"  !! WARNING: ~{expected} check-ins is BELOW the 100-flow session")
        print(f"     threshold, so the C2 model will not be invoked. For a")
        print(f"     {a.interval:.0f}s interval you need at least "
              f"{100*a.interval/3600:.1f}h. Increase --duration.")
    print("=" * 68)
    print("  Start your packet capture now. Ctrl-C to stop early.\n")

    start = time.monotonic()
    deadline = start + total
    n_ok = n_err = 0
    meta = {
        "_meta": True, "host": a.host, "src_ip": src, "interval": a.interval,
        "jitter": a.jitter, "duration_s": total,
        "started_iso": datetime.now(timezone.utc).isoformat(),
    }

    try:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(meta) + "\n")
            fh.flush()
            i = 0
            while time.monotonic() < deadline:
                rec = one_checkin(a.host, a.path, a.timeout)
                rec["seq"] = i
                fh.write(json.dumps(rec) + "\n")
                fh.flush()          # flush every line: a crash must not lose labels
                if rec.get("ok"):
                    n_ok += 1
                else:
                    n_err += 1
                i += 1
                dst = rec.get("dest_ip", "?")
                print(f"  [{i:4d}/{expected}] {rec['iso'][11:19]}  {dst:<16} "
                      f"status={rec.get('status','-')} {rec['rtt_ms']:.0f}ms"
                      f"{'' if rec.get('ok') else '  ERR ' + rec.get('error','')[:40]}")

                # schedule next relative to now, with jitter
                sleep = a.interval * (1.0 + random.uniform(-a.jitter, a.jitter))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(sleep, remaining))
    except KeyboardInterrupt:
        print("\n  stopped by user")

    elapsed = (time.monotonic() - start) / 3600
    print()
    print("=" * 68)
    print(f"  check-ins: {n_ok} ok, {n_err} failed, over {elapsed:.2f}h")
    print(f"  ground truth written to: {a.out}")
    if n_ok + n_err < 100:
        print(f"  NOTE: {n_ok+n_err} flows is below the 100-flow session threshold;")
        print("        the C2 model will not have been invoked. Run longer.")
    print("  Now stop the capture and run verify_beacon_detection.py")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
