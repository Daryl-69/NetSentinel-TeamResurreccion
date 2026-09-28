"""Throughput benchmark (PS 26145 constraint d).

Replays a capture through the full streaming pipeline (extraction + every
detector) as fast as one process can and prints what it sustained.

    python scripts/benchmark_throughput.py --synthetic 100000
    python scripts/benchmark_throughput.py --pcap D:\\capture\\ns_00016.pcap --json bench.json

Use a real capture for the figure you state; the synthetic capture is a
repeatable made-up mix (TLS, HTTP, DNS, UDP, a few scan probes).
Results describe the machine they ran on.
"""
import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.WARNING)

from netsentinel.bench import run_benchmark, synthetic_pcap, synthetic_path  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pcap", help="capture to replay (.pcap / .pcapng)")
    g.add_argument("--synthetic", type=int, metavar="N", help="generate (once) and replay N synthetic packets")
    ap.add_argument("--json", help="also write the result to this file")
    args = ap.parse_args()

    if args.pcap:
        path, kind = args.pcap, "pcap"
    else:
        path, kind = synthetic_path(args.synthetic), "synthetic"
        if not os.path.exists(path):
            print(f"generating {args.synthetic} synthetic packets -> {path}")
            synthetic_pcap(path, args.synthetic)

    res = run_benchmark(path, kind=kind,
                        progress=lambda p: print(f"  {p['packets']:>9,} packets  {p['elapsed_s']:>7.1f} s", end="\r"))
    print(" " * 60, end="\r")
    ev = res["latency_ms"]["event"]
    print(f"\n{res['kind']} capture {res['file']}: {res['packets']:,} packets, {res['bytes'] / 1e6:.1f} MB, "
          f"{res['flows']:,} flows, {res['events']:,} events, {res['alerts']} alerts")
    print(f"elapsed {res['elapsed_s']} s  ->  {res['packets_per_s']:,} packets/s, {res['mbps']} Mbps, "
          f"{res['flows_per_s']:,} flows/s, {res['events_per_s']:,} events/s")
    if res.get("realtime_factor"):
        print(f"capture spans {res['capture_span_s']} s of traffic: processed at {res['realtime_factor']}x real time")
    print(f"time split: read+extract {res['stage_s']['read_and_extract']} s, detect {res['stage_s']['detect']} s")
    for kind, v in sorted(ev.items()):
        print(f"  analyzer latency per {kind:13s} p50 {v['p50']} ms  p95 {v['p95']} ms  p99 {v['p99']} ms  (n={v['n']})")
    print(f"machine: {res['machine']['cpu']} ({res['machine']['logical_cpus']} logical CPUs, one Python process), "
          f"Python {res['machine']['python']}, {res['machine']['os']}; RSS {res['rss_mb']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(res, fh, indent=1)
        print(f"written {args.json}")


if __name__ == "__main__":
    main()
