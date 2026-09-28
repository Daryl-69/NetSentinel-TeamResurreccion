"""Throughput benchmark -- PS 26145 constraint (d): state and demonstrate
throughput (flows/s or Mbps sustained).

Runs a capture through the same streaming path live capture uses (packet ->
flow/DNS/TLS extraction -> every detector) as fast as one Python process
can, and reports what it sustained: packets/s, Mbps, flows/s, events/s,
the per-event analyzer latency distribution, and peak memory.

Two inputs:
  * a real capture (--pcap), which is what the stated figure should come from;
  * a synthetic capture (--synthetic N): N packets of made-up TLS, HTTP, DNS,
    UDP and scan traffic, generated once and cached, for a quick repeatable
    check on any machine. Its numbers describe that mix on that machine.

The benchmark uses its own analyzer and metrics, so it never adds alerts or
counts to the running sensor; it does compete with the sensor for the CPU.
CICFlowMeter's batch pass is not included (it is not part of live mode).

    python scripts/benchmark_throughput.py --synthetic 100000
    python scripts/benchmark_throughput.py --pcap D:\\capture\\ns_00016.pcap
"""
from __future__ import annotations

import os
import platform
import random
import ssl
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# synthetic capture
# ---------------------------------------------------------------------------
def _client_hello_bytes() -> bytes:
    """A real ClientHello from this machine's OpenSSL (no network used)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="bench.example.net")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def _server_hello_bytes() -> bytes:
    body = struct.pack("!H", 0x0303) + os.urandom(32) + b"\x00" + struct.pack("!H", 0xC02F) + b"\x00"
    ext = struct.pack("!HH", 0xFF01, 1) + b"\x00" + struct.pack("!HH", 0x000B, 2) + b"\x01\x00"
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def synthetic_pcap(path: str, n_packets: int = 100_000, seed: int = 7, wire_pps: float = 5000.0,
                   progress: Optional[Callable[[int], None]] = None) -> str:
    """Write a synthetic mixed-traffic capture of about n_packets packets."""
    from scapy.all import Ether, IP, TCP, UDP, Raw, PcapWriter
    from scapy.layers.dns import DNS, DNSQR, DNSRR

    rnd = random.Random(seed)
    ch, sh = _client_hello_bytes(), _server_hello_bytes()
    t0 = 1_758_000_000.0
    span = n_packets / wire_pps
    pkts = []   # (ts, scapy packet)

    def tcp_session(t, c, s, cport, sport, tls):
        seq_c, seq_s = rnd.randint(1, 2**31), rnd.randint(1, 2**31)
        out = []
        def add(dt, src, dst, sp, dp, flags, payload=b""):
            nonlocal t
            t += dt
            p = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, seq=0, ack=0)
            if payload:
                p = p / Raw(payload)
            out.append((t, p))
        add(0, c, s, cport, sport, "S")
        add(0.02, s, c, sport, cport, "SA")
        add(0.02, c, s, cport, sport, "A")
        if tls:
            add(0.001, c, s, cport, sport, "PA", ch)
            add(0.03, s, c, sport, cport, "PA", sh)
        else:
            add(0.001, c, s, cport, sport, "PA", b"GET / HTTP/1.1\r\nHost: bench.example.net\r\n\r\n")
        for _ in range(rnd.randint(3, 10)):
            add(rnd.uniform(0.001, 0.02), s, c, sport, cport, "A", os.urandom(1400))
        for _ in range(rnd.randint(1, 3)):
            add(rnd.uniform(0.001, 0.05), c, s, cport, sport, "PA", os.urandom(rnd.randint(80, 400)))
        add(0.01, c, s, cport, sport, "FA")
        add(0.01, s, c, sport, cport, "FA")
        add(0.005, c, s, cport, sport, "A")
        return out

    count = 0
    while count < n_packets:
        t = t0 + rnd.uniform(0, span)
        c = f"192.168.10.{rnd.randint(2, 250)}"
        s = f"{rnd.choice(['203.0.113', '198.51.100'])}.{rnd.randint(1, 254)}"
        r = rnd.random()
        if r < 0.55:
            batch = tcp_session(t, c, s, rnd.randint(49152, 65535), 443, True)
        elif r < 0.65:
            batch = tcp_session(t, c, s, rnd.randint(49152, 65535), 80, False)
        elif r < 0.85:
            name = rnd.choice(["www", "api", "cdn", "mail"]) + "." + rnd.choice(["example", "sample", "test"]) + ".net"
            q = Ether() / IP(src=c, dst="192.168.10.1") / UDP(sport=rnd.randint(1024, 65535), dport=53) / \
                DNS(id=rnd.randint(0, 65535), rd=1, qd=DNSQR(qname=name, qtype=rnd.choice([1, 28, 65])))
            a = Ether() / IP(src="192.168.10.1", dst=c) / UDP(sport=53, dport=q[UDP].sport) / \
                DNS(id=q[DNS].id, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata="203.0.113.9"))
            batch = [(t, q), (t + 0.01, a)]
        elif r < 0.95:
            cp = rnd.randint(49152, 65535)
            batch = []
            for i in range(10):
                if i % 2 == 0:
                    batch.append((t + i * 0.02, Ether() / IP(src=c, dst=s) / UDP(sport=cp, dport=3478) / Raw(os.urandom(1200))))
                else:
                    batch.append((t + i * 0.02, Ether() / IP(src=s, dst=c) / UDP(sport=3478, dport=cp) / Raw(os.urandom(1200))))
        else:
            batch = [(t, Ether() / IP(src=c, dst=f"10.20.0.{rnd.randint(1, 254)}") /
                      TCP(sport=rnd.randint(49152, 65535), dport=rnd.choice([22, 445, 3389]), flags="S"))]
        pkts.extend(batch)
        count += len(batch)
        if progress and count % 5000 < len(batch):
            progress(count)
    pkts.sort(key=lambda x: x[0])
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    w = PcapWriter(tmp, sync=False)
    for ts, p in pkts:
        p.time = ts
        w.write(p)
    w.close()
    os.replace(tmp, path)
    return path


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------
def _cpu_name() -> str:
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/cpuinfo") as fh:
                for line in fh:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def _rss_mb() -> Optional[float]:
    try:
        import psutil
        return round(psutil.Process().memory_info().rss / 1e6, 1)
    except Exception:
        try:
            import resource
            r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            return round(r / 1024.0, 1) if sys.platform != "darwin" else round(r / 1e6, 1)
        except Exception:
            return None


def run_benchmark(pcap_path: str, registry=None, progress: Optional[Callable[[dict], None]] = None,
                  kind: str = "pcap", stop: Optional[threading.Event] = None) -> dict:
    """Replay pcap_path through extraction + every detector as fast as possible."""
    from netsentinel.extractor.pcap_reader import PacketProcessor
    from netsentinel.pipeline.alert_manager import AlertManager
    from netsentinel.pipeline.analyzer import FlowAnalyzer
    from netsentinel.pipeline.metrics import PipelineMetrics
    from netsentinel.config import FLOW_IDLE_TIMEOUT, FLOW_ACTIVE_TIMEOUT, SESSION_MIN_FLOWS
    if registry is None:
        from netsentinel.models.registry import ModelRegistry
        registry = ModelRegistry().load_all()

    m = PipelineMetrics(window_s=10, history_s=600, max_samples=200_000)
    proc = PacketProcessor(idle_timeout=FLOW_IDLE_TIMEOUT, active_timeout=FLOW_ACTIVE_TIMEOUT,
                           session_min_flows=SESSION_MIN_FLOWS, use_cicflowmeter=False, metrics=m)
    an = FlowAnalyzer(registry, AlertManager(max_stored=100_000, metrics=m), None, metrics=m)
    rss0 = _rss_mb()
    events = alerts = flows = stubs = dns = 0
    analyze_s = 0.0
    t_start = time.perf_counter()
    last_report = t_start
    for ev in proc.process_pcap(pcap_path):
        if stop is not None and stop.is_set():
            break
        if ev is None:
            now = time.perf_counter()
            if progress and now - last_report > 0.5:
                last_report = now
                progress({"packets": proc._packet_count, "elapsed_s": round(now - t_start, 2)})
            continue
        events += 1
        et = ev.get("type")
        if et == "flow":
            if ev.get("stub"):
                stubs += 1
            else:
                flows += 1
        elif et in ("dns", "dns_response"):
            dns += 1
        a0 = time.perf_counter()
        alerts += len(an.analyze(ev))
        analyze_s += time.perf_counter() - a0
    a0 = time.perf_counter()
    alerts += len(an.finish())
    analyze_s += time.perf_counter() - a0
    elapsed = time.perf_counter() - t_start
    st = proc.stats
    packets, nbytes = st["packets_processed"], st["bytes_processed"]
    lat = m.snapshot(with_series=False)["latency_ms"]
    span = st.get("capture_span_s")
    return {
        "kind": kind,
        "file": os.path.basename(pcap_path),
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "packets": packets,
        "bytes": nbytes,
        "avg_packet_bytes": round(nbytes / packets, 1) if packets else None,
        "capture_span_s": span,
        "flows": flows,
        "probe_stubs": stubs,
        "dns_events": dns,
        "events": events,
        "alerts": alerts,
        "tls_client_hellos": st["flow_extractor"]["tls_client_hellos"],
        "elapsed_s": round(elapsed, 3),
        "packets_per_s": round(packets / elapsed, 1) if elapsed else None,
        "mbps": round(nbytes * 8 / elapsed / 1e6, 2) if elapsed else None,
        "flows_per_s": round(flows / elapsed, 1) if elapsed else None,
        "events_per_s": round(events / elapsed, 1) if elapsed else None,
        "realtime_factor": round(span / elapsed, 2) if (span and elapsed) else None,
        "stage_s": {"read_and_extract": round(elapsed - analyze_s, 3), "detect": round(analyze_s, 3)},
        "latency_ms": {"event": lat["event"], "detector": lat["detector"]},
        "rss_mb": {"before": rss0, "after": _rss_mb()},
        "machine": {"cpu": _cpu_name(), "logical_cpus": os.cpu_count(), "python": platform.python_version(),
                    "os": f"{platform.system()} {platform.release()}", "processes": 1},
        "reader": st.get("reader"),
        "notes": ("One Python process: packet parsing ("
                  + ("struct-level fast reader" if st.get("reader") == "fast" else "Scapy")
                  + "), flow/DNS/TLS extraction and every detector in line. "
                  "CICFlowMeter's batch pass is not included."),
    }


def synthetic_path(n_packets: int) -> str:
    from netsentinel.config import PCAP_UPLOAD_DIR
    return os.path.join(PCAP_UPLOAD_DIR, f"bench_synthetic_{int(n_packets)}.pcap")
