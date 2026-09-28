"""Traffic Generator — SYNTHETIC normal + attack events for demos and tests.

Everything here is made up and is labelled as such everywhere it appears
(the console shows "Simulator (synthetic)"). It exercises the same analyzer
code paths as real traffic; it is not evidence that a detector works on
real traffic.

Addresses: internal hosts are 192.168.1.x / 10.0.x.x; every external or
"attacker" address comes from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no real third party
ever appears in a simulated alert.

Scenarios (one per PS 26145 threat family, plus normal background):
  normal         browsing-like flows (TLS with common browser fingerprints) + DNS
  ddos           (a) XGBoost-shaped flood flows, SYN flood from spoofed sources,
                     NTP reflection bursts
  c2             (b) one host checking in every ~60 s for 36 minutes
  dga            (c) random-looking domains; nxdomain = NXDOMAIN burst;
                     dns_tunnel = TXT queries carrying hex data
  tls            (d) a rare TLS client (no SNI/ALPN, 4 ciphers) with
                     fixed-size sessions every 30 s
  port_scan      (e) vertical scan burst; sweep = one port across 70 hosts
  exfil          (f) DNS-tunnel names; exfil_flow = 7.5 MB upload, 120 KB back
  mixed          background with every scenario injected in turn
"""
import random
import time
import string
import itertools

from netsentinel.config import FAKE_GEO, TARGET

VICTIM = TARGET["ip"]
_ATTACKERS = [g["ip"] for g in FAKE_GEO.values()]
_EXTERNAL = ["203.0.113.%d" % i for i in range(10, 60)] + ["198.51.100.%d" % i for i in range(10, 60)]


def _stamp(event: dict) -> dict:
    """Attach wall-clock time (as wire time and as ingest time) if unset.

    The analyzer de-duplicates DNS alerts on the event timestamp; events
    without one arrived as now=0 and every DGA / exfiltration alert was
    suppressed (DGA detection went 0% -> 76.5% and exfil 0% -> 100% once the
    generators stamped their events, measured 20 Sep).
    """
    event.setdefault("timestamp", time.time())
    event.setdefault("ingest_wall", time.time())
    event.setdefault("synthetic", True)
    return event


def _internal():
    return f"192.168.1.{random.randint(2, 254)}"


# ============================================================
# TLS fingerprints for synthetic sessions (computed, not copied)
# ============================================================
def _fingerprints():
    from netsentinel.extractor import tls_parse as T
    browser = {"legacy_version": 0x0303,
               "ciphers": [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
                           0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
               "extensions": [0x0a0a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005,
                              0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x4469, 0x0015],
               "sni": "www.example.com", "sni_present": True, "groups": [0x001d, 0x0017, 0x0018],
               "point_formats": [0], "sig_algs": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
               "alpn": ["h2", "http/1.1"], "alpn_raw": [b"h2", b"http/1.1"],
               "supported_versions": [0x0304, 0x0303], "ech": False}
    browser2 = dict(browser, ciphers=[0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
                                      0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
                    extensions=[0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022,
                                0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0x001b])
    implant = {"legacy_version": 0x0303, "ciphers": [0xc02f, 0xc030, 0x009c, 0x002f],
               "extensions": [0x000a, 0x000b], "sni": None, "sni_present": False,
               "groups": [0x0017, 0x0018], "point_formats": [0], "sig_algs": [], "alpn": [],
               "alpn_raw": [], "supported_versions": [], "ech": False}
    out = {}
    for name, ch in (("browser", browser), ("browser2", browser2), ("implant", implant)):
        out[name] = T.client_summary(ch, "t")
    out["server"] = T.server_summary({"legacy_version": 0x0303, "cipher": 0x1301,
                                      "extensions": [0x002b, 0x0033], "selected_version": 0x0304,
                                      "alpn": "h2"})
    out["implant_server"] = T.server_summary({"legacy_version": 0x0303, "cipher": 0xc02f,
                                              "extensions": [0xff01, 0x000b], "selected_version": None,
                                              "alpn": None})
    return out


_FP = None


def _fp():
    global _FP
    if _FP is None:
        _FP = _fingerprints()
    return _FP


# ============================================================
# Normal Traffic Generators
# ============================================================

def _normal_features() -> dict:
    return {
        # DDoS model features (59 features — fill key ones, rest 0)
        "Protocol": random.choice([6, 17]),  # TCP or UDP
        "Flow Duration": random.uniform(1000000, 60000000),
        "Total Fwd Packets": random.randint(5, 50),
        "Total Backward Packets": random.randint(5, 50),
        "Fwd Packets Length Total": random.uniform(500, 5000),
        "Bwd Packets Length Total": random.uniform(500, 5000),
        "Fwd Packet Length Max": random.uniform(100, 500),
        "Fwd Packet Length Min": random.uniform(40, 60),
        "Fwd Packet Length Mean": random.uniform(100, 300),
        "Fwd Packet Length Std": random.uniform(10, 50),
        "Bwd Packet Length Max": random.uniform(100, 500),
        "Bwd Packet Length Min": random.uniform(40, 60),
        "Bwd Packet Length Mean": random.uniform(100, 300),
        "Bwd Packet Length Std": random.uniform(10, 50),
        "Flow Bytes/s": random.uniform(100, 5000),
        "Flow Packets/s": random.uniform(1, 20),
        "Flow IAT Mean": random.uniform(10000, 500000),
        "Flow IAT Std": random.uniform(5000, 200000),
        "Flow IAT Max": random.uniform(100000, 1000000),
        "Flow IAT Min": random.uniform(1000, 5000),
        "SYN Flag Count": 0,
        "ACK Flag Count": random.randint(10, 50),
        "PSH Flag Count": random.randint(0, 5),
        "RST Flag Count": 0,
        "URG Flag Count": 0,
        "Avg Fwd Segment Size": random.uniform(100, 800),
        "Init Fwd Win Bytes": random.randint(8000, 65535),
        "Idle Mean": random.uniform(0, 500000),
        "Idle Std": random.uniform(0, 100000),
        # ETT model features
        "duration": random.uniform(100000, 60000000),
        "total_fiat": random.uniform(100000, 60000000),
        "total_biat": random.uniform(100000, 60000000),
        "min_fiat": random.uniform(5, 5000),
        "min_biat": random.uniform(0, 5000),
        "max_fiat": random.uniform(50000, 5000000),
        "max_biat": random.uniform(50000, 5000000),
        "mean_fiat": random.uniform(1000, 500000),
        "mean_biat": random.uniform(1000, 500000),
        "flowPktsPerSecond": random.uniform(5, 500),
        "flowBytesPerSecond": random.uniform(1000, 500000),
        "min_flowiat": random.uniform(0, 1000),
        "max_flowiat": random.uniform(10000, 5000000),
        "mean_flowiat": random.uniform(1000, 500000),
        "std_flowiat": random.uniform(500, 200000),
        "min_active": random.uniform(0, 1000000),
        "mean_active": random.uniform(0, 5000000),
        "max_active": random.uniform(0, 10000000),
        "std_active": random.uniform(0, 2000000),
        "min_idle": random.uniform(0, 1000000),
        "mean_idle": random.uniform(0, 5000000),
        "max_idle": random.uniform(0, 10000000),
        "std_idle": random.uniform(0, 2000000),
        "fwd_bwd_ratio": random.uniform(0.5, 2.0),
        "iat_cv": random.uniform(0.5, 3.0),
        "iat_range_norm": random.uniform(1, 10),
        "active_idle_ratio": random.uniform(0.1, 5.0),
        "duration_log": random.uniform(10, 18),
        "bytes_per_packet": random.uniform(50, 1000),
    }


def generate_normal_flow() -> dict:
    """A single benign flow event (browsing-like). About half are TLS on 443
    with one of two common browser fingerprints shared by many hosts."""
    f = _normal_features()
    tls_flow = f["Protocol"] == 6 and random.random() < 0.6
    ev = {
        "type": "flow",
        "source_ip": _internal(),
        "dest_ip": random.choice(_EXTERNAL),
        "source_port": random.randint(49152, 65535),
        "dest_port": 443 if tls_flow else random.choice([80, 443, 8080, 53, 123, 5222]),
        "protocol": f["Protocol"],
        "features": f,
    }
    if tls_flow:
        fp = _fp()
        ev["tls"] = {**fp[random.choice(["browser", "browser", "browser2"])], **fp["server"]}
        ev["splt"] = [[random.randint(200, 700), 0.0], [-random.randint(1200, 1500), 20.0],
                      [random.randint(60, 300), 40.0], [-random.randint(200, 3000), 60.0]]
    return _stamp(ev)


def generate_normal_dns() -> dict:
    """A benign DNS query."""
    legit_domains = [
        "google.com", "facebook.com", "youtube.com", "amazon.com",
        "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
        "reddit.com", "netflix.com", "github.com", "stackoverflow.com",
        "microsoft.com", "apple.com", "cloudflare.com", "aws.amazon.com",
        "mail.google.com", "docs.google.com", "drive.google.com",
    ]
    return _stamp({
        "type": "dns",
        "domain": random.choice(legit_domains),
        "source_ip": _internal(),
        "dest_ip": "192.168.1.1",
        "query_type": random.choice([1, 1, 1, 28]),
        # synthetic byte counts (small queries, small responses)
        "total_fwd_bytes": random.randint(40, 120),
        "total_bwd_bytes": random.randint(100, 500),
    })


# ============================================================
# (a) DDoS
# ============================================================

def generate_ddos_flow() -> dict:
    """A flow shaped like the CIC-DDoS2019 SYN-flood flows the XGBoost model
    was trained on (short, tiny, SYN-only, very high rate)."""
    return _stamp({
        "type": "flow",
        "source_ip": random.choice(_ATTACKERS),
        "dest_ip": VICTIM,
        "source_port": random.randint(1024, 65535),
        "dest_port": 80,
        "protocol": 6,
        "features": {
            "Protocol": 6,  # TCP
            "Flow Duration": random.uniform(0, 1000),  # Very short
            "Total Fwd Packets": random.randint(1, 3),  # Minimal packets
            "Total Backward Packets": 0,  # No response (SYN flood)
            "Fwd Packets Length Total": random.uniform(40, 80),  # Tiny
            "Bwd Packets Length Total": 0,
            "Fwd Packet Length Max": 60,
            "Fwd Packet Length Min": 40,
            "Fwd Packet Length Mean": 50,
            "Fwd Packet Length Std": 5,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0,
            "Bwd Packet Length Std": 0,
            "Flow Bytes/s": random.uniform(5000000, 50000000),  # Very high
            "Flow Packets/s": random.uniform(50000, 500000),  # Very high
            "Flow IAT Mean": random.uniform(0, 10),  # Rapid-fire
            "Flow IAT Std": random.uniform(0, 5),
            "Flow IAT Max": random.uniform(0, 50),
            "Flow IAT Min": 0,
            "SYN Flag Count": random.randint(1, 5),  # SYN flood
            "ACK Flag Count": 0,  # No ACK
            "PSH Flag Count": 0,
            "RST Flag Count": 0,
            "URG Flag Count": 0,
            "Avg Fwd Segment Size": 50,
            "Init Fwd Win Bytes": random.randint(1024, 4096),
            "Idle Mean": 0,
            "Idle Std": 0,
            # ETT features (short attack flow)
            "duration": random.uniform(0, 1000),
            "total_fiat": random.uniform(0, 1000),
            "total_biat": 0,
            "min_fiat": 0,
            "min_biat": 0,
            "max_fiat": random.uniform(0, 100),
            "max_biat": 0,
            "mean_fiat": random.uniform(0, 50),
            "mean_biat": 0,
            "flowPktsPerSecond": random.uniform(50000, 500000),
            "flowBytesPerSecond": random.uniform(5000000, 50000000),
            "min_flowiat": 0,
            "max_flowiat": random.uniform(0, 50),
            "mean_flowiat": random.uniform(0, 10),
            "std_flowiat": random.uniform(0, 5),
            "min_active": 0, "mean_active": 0, "max_active": 0, "std_active": 0,
            "min_idle": 0, "mean_idle": 0, "max_idle": 0, "std_idle": 0,
            "fwd_bwd_ratio": 999.0,  # All outbound
            "iat_cv": 0.1,  # Very periodic
            "iat_range_norm": 0.5,
            "active_idle_ratio": 999.0,
            "duration_log": 2.0,
            "bytes_per_packet": 50,
        }
    })


def _probe_flow(src, dst, sport, dport, proto, ts, pkts=1, size=40, syn=True, rst=False, bwd_pkts=0, bwd_size=0):
    return {
        "type": "flow", "source_ip": src, "dest_ip": dst, "source_port": sport, "dest_port": dport,
        "protocol": proto, "timestamp": ts, "last_seen": ts + 0.001, "ingest_wall": time.time(),
        "synthetic": True,
        "features": {
            "Protocol": proto, "Flow Duration": 1000.0, "Total Fwd Packets": pkts,
            "Total Backward Packets": bwd_pkts, "Fwd Packets Length Total": size * pkts,
            "Bwd Packets Length Total": bwd_size, "Fwd Packet Length Max": size,
            "Fwd Packet Length Min": size, "Fwd Packet Length Mean": size,
            "SYN Flag Count": 1 if syn else 0, "ACK Flag Count": 0, "RST Flag Count": 1 if rst else 0,
            "Flow Packets/s": 2000.0, "Flow Bytes/s": 80000.0, "Avg Fwd Segment Size": size,
        },
    }


def generate_syn_flood_burst(n: int = 400) -> list:
    """SYN flood from randomised (spoofed-looking) sources: every flow from
    a new address, one SYN each, no handshake completed. The random sources
    are drawn from the documentation ranges too."""
    now = time.time()
    pool = [f"{net}.{h}" for net in ("192.0.2", "198.51.100", "203.0.113") for h in range(1, 255)]
    sources = random.sample(pool, min(n, len(pool)))
    return [_probe_flow(sources[i % len(sources)], VICTIM, random.randint(1024, 65535), 80, 6, now - 1.0 + i / n)
            for i in range(n)]


def generate_reflection_burst(n: int = 400, service_port: int = 123) -> list:
    """UDP reflection/amplification: replies FROM ~40 reflectors' service
    port (NTP by default) to the victim, large payloads."""
    now = time.time()
    reflectors = ["198.51.100.%d" % i for i in range(100, 140)]
    victim = "10.0.0.2"
    return [_probe_flow(random.choice(reflectors), victim, service_port, random.randint(1024, 65535), 17,
                        now - 1.0 + i / n, pkts=random.randint(1, 3), size=468, syn=False)
            for i in range(n)]


# ============================================================
# (b) C2 beaconing
# ============================================================
_beacon_seq = itertools.count(1)


def generate_c2_beacon(checkins: int = 36, interval: float = 60.0) -> list:
    """One host checking in with one server every ~60 s (+/-3% jitter) for
    36 minutes, as flow events. Timestamps are back-dated so the whole
    series is 'already observed' when the simulator emits it."""
    k = next(_beacon_seq)
    src = f"192.168.1.{70 + k % 20}"
    dst = f"203.0.113.{150 + k % 50}"
    now = time.time()
    # Keep the whole series inside one 6-hour UTC scoring window (the
    # combined score is computed per window): if the current window started
    # too recently, place the series at the end of the previous one.
    span = checkins * interval * 1.05
    w0 = (now // 21600) * 21600
    end = now if now - w0 > span + 60 else w0 - 60
    t = end - checkins * interval
    fp = _fp()
    out = []
    for i in range(checkins):
        t += interval * (1 + random.uniform(-0.03, 0.03))
        f = _normal_features()
        f.update({"Protocol": 6, "Total Fwd Packets": 7, "Total Backward Packets": 6,
                  "Fwd Packets Length Total": 880 + random.randint(-12, 12),
                  "Bwd Packets Length Total": 3900 + random.randint(-40, 40)})
        out.append({"type": "flow", "source_ip": src, "dest_ip": dst,
                    "source_port": random.randint(49152, 65535), "dest_port": 443, "protocol": 6,
                    "timestamp": t, "last_seen": t + 0.4, "ingest_wall": time.time(), "synthetic": True,
                    "features": f, "tls": {**fp["browser"], **fp["server"]},
                    "splt": [[517, 0.0], [-1400, 30.0], [80, 55.0], [-120, 80.0]]})
    return out


def generate_c2_session() -> dict:
    """A 100-flow C2 session for the BiLSTM+FFT model (its verdict is
    attached to combined-score alerts as evidence)."""
    beacon_interval = random.uniform(30, 120)  # seconds
    jitter = beacon_interval * 0.05  # 5% jitter
    flows = []
    for i in range(100):
        iat = beacon_interval + random.uniform(-jitter, jitter)
        flows.append({
            "iat": iat,
            "packet_size": random.randint(60, 200),  # Small C2 packets
            "bytes": random.randint(100, 500),
            "direction": 1 if i % 2 == 0 else 0,  # Alternating
        })
    return _stamp({
        "type": "session",
        "flows": flows,
        "source_ip": _internal(),
        "dest_ip": random.choice(_ATTACKERS),
    })


# ============================================================
# (c) DGA and DNS tunnelling
# ============================================================

def generate_dga_dns() -> dict:
    """A DGA-style DNS query (random-looking domain)."""
    length = random.randint(8, 20)
    chars = string.ascii_lowercase + string.digits
    random_domain = ''.join(random.choice(chars) for _ in range(length))
    tld = random.choice([".com", ".xyz", ".top", ".tk", ".net", ".info"])
    return _stamp({
        "type": "dns",
        "domain": random_domain + tld,
        "source_ip": f"192.168.1.{random.randint(150, 160)}",
        "dest_ip": "192.168.1.1",
        "query_type": 1,
    })


_WORDS = ["river", "candle", "stone", "maple", "orbit", "velvet", "harbor", "pixel", "amber", "falcon",
          "meadow", "copper", "lantern", "willow", "summit", "cobalt", "ember", "glacier", "prairie", "quartz"]


def generate_nxdomain_burst(n: int = 32) -> list:
    """A host resolving many names that do not exist (dictionary-word DGA):
    query + NXDOMAIN reply pairs over n different base domains."""
    host = f"192.168.1.{random.randint(90, 99)}"
    now = time.time()
    out = []
    for i in range(n):
        name = random.choice(_WORDS) + random.choice(_WORDS) + random.choice(_WORDS) + random.choice([".com", ".net", ".org"])
        t = now - n * 0.5 + i * 0.5
        out.append({"type": "dns", "domain": name, "source_ip": host, "dest_ip": "192.168.1.1",
                    "query_type": 1, "query_bytes": 20 + len(name), "timestamp": t,
                    "ingest_wall": time.time(), "synthetic": True, "lexical": True})
        out.append({"type": "dns_response", "domain": name, "source_ip": host, "dest_ip": "192.168.1.1",
                    "query_type": 1, "rcode": 3, "answers": 0, "response_bytes": 90 + len(name),
                    "timestamp": t + 0.02, "ingest_wall": time.time(), "synthetic": True})
    return out


def generate_txt_tunnel(n: int = 40) -> list:
    """TXT queries carrying hex-encoded data under one base domain."""
    host = f"192.168.1.{random.randint(120, 129)}"
    base = random.choice(["tunnel-sim.net", "dnsx-sim.org"])
    now = time.time()
    out = []
    for i in range(n):
        label = ''.join(random.choice('0123456789abcdef') for _ in range(random.randint(24, 40)))
        name = f"{label}.t.{base}"
        t = now - n * 0.3 + i * 0.3
        out.append({"type": "dns", "domain": name, "source_ip": host, "dest_ip": "192.168.1.1",
                    "query_type": 16, "query_bytes": 30 + len(name), "timestamp": t,
                    "ingest_wall": time.time(), "synthetic": True, "lexical": True})
        out.append({"type": "dns_response", "domain": name, "source_ip": host, "dest_ip": "192.168.1.1",
                    "query_type": 16, "rcode": 0, "answers": 1, "response_bytes": 160 + len(name),
                    "timestamp": t + 0.03, "ingest_wall": time.time(), "synthetic": True})
    return out


def generate_exfil_dns() -> dict:
    """A DNS-tunnelling exfiltration query: long hex subdomain labels."""
    data_len = random.randint(20, 50)
    hex_data = ''.join(random.choice('0123456789abcdef') for _ in range(data_len))
    chunk_size = random.randint(10, 20)
    chunks = [hex_data[i:i+chunk_size] for i in range(0, len(hex_data), chunk_size)]
    tunnel_domain = '.'.join(chunks) + '.' + random.choice([
        'evil-tunnel.com', 'data-exfil.net', 'c2-dns.xyz',
        'exfiltrate.top', 'tunnel-data.info',
    ])
    return _stamp({
        "type": "dns",
        "domain": tunnel_domain,
        "source_ip": _internal(),
        "dest_ip": "192.168.1.1",
        "query_type": 1,
        # synthetic byte counts for the byte-ratio evidence panel
        "total_fwd_bytes": random.randint(1000, 5000),
        "total_bwd_bytes": random.randint(50, 200),
    })


# ============================================================
# (d) Malware in encrypted sessions
# ============================================================
_implant_seq = itertools.count(1)


def generate_tls_implant(sessions: int = 12, interval: float = 30.0) -> list:
    """A rare TLS client (no SNI, no ALPN, 4 cipher suites, TLS 1.2 only)
    opening fixed-size sessions to one server every ~30 s."""
    k = next(_implant_seq)
    src = f"192.168.1.{40 + k % 10}"
    dst = f"198.51.100.{200 + k % 40}"
    fp = _fp()
    now = time.time()
    t = now - sessions * interval
    out = []
    for i in range(sessions):
        t += interval * (1 + random.uniform(-0.02, 0.02))
        f = _normal_features()
        f.update({"Protocol": 6, "Total Fwd Packets": 6, "Total Backward Packets": 5,
                  "Fwd Packets Length Total": 1450 + random.randint(-5, 5),
                  "Bwd Packets Length Total": 2210 + random.randint(-5, 5)})
        out.append({"type": "flow", "source_ip": src, "dest_ip": dst,
                    "source_port": random.randint(49152, 65535), "dest_port": 443, "protocol": 6,
                    "timestamp": t, "last_seen": t + 0.3, "ingest_wall": time.time(), "synthetic": True,
                    "features": f, "tls": {**fp["implant"], **fp["implant_server"]},
                    "splt": [[189, 0.0], [-1164, 22.0], [126, 41.0], [-51, 63.0], [512, 70.0], [-256, 95.0]]})
    return out


# ============================================================
# (e) Reconnaissance
# ============================================================

def generate_port_scan_flow() -> dict:
    """A port-scan flow event (SYN scan characteristics)."""
    attacker = random.choice(_ATTACKERS)
    target_port = random.randint(1, 65535)
    return _stamp({
        "type": "flow",
        "source_ip": attacker,
        "dest_ip": VICTIM,
        "source_port": random.randint(49152, 65535),
        "dest_port": target_port,
        "protocol": 6,
        "features": _scan_features(),
    })


def _scan_features() -> dict:
    return {
        "Protocol": 6,  # TCP
        "Flow Duration": random.uniform(0, 500),  # Very short
        "Total Fwd Packets": 1,  # SYN only
        "Total Backward Packets": random.choice([0, 1]),  # Maybe SYN-ACK
        "Fwd Packets Length Total": 40,
        "Bwd Packets Length Total": random.choice([0, 40]),
        "Fwd Packet Length Max": 40,
        "Fwd Packet Length Min": 40,
        "Fwd Packet Length Mean": 40,
        "Fwd Packet Length Std": 0,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0,
        "Bwd Packet Length Std": 0,
        "Flow Bytes/s": random.uniform(1000, 10000),
        "Flow Packets/s": random.uniform(50, 500),  # Moderate rate
        "Flow IAT Mean": random.uniform(0, 100),
        "Flow IAT Std": random.uniform(0, 50),
        "Flow IAT Max": random.uniform(0, 200),
        "Flow IAT Min": 0,
        "Fwd IAT Mean": 0,
        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,
        "SYN Flag Count": 1,  # SYN scan
        "ACK Flag Count": 0,
        "RST Flag Count": random.choice([0, 1]),  # Port closed → RST
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "Fwd PSH Flags": 0,
        "Fwd Header Length": 20,
        "Bwd Header Length": 0,
        "Bwd Packets/s": 0,
        "Packet Length Max": 40,
        "Packet Length Mean": 40,
        "Packet Length Std": 0,
        "Packet Length Variance": 0,
        "Down/Up Ratio": 0,
        "Avg Packet Size": 40,
        "Avg Fwd Segment Size": 40,
        "Avg Bwd Segment Size": 0,
        "Subflow Fwd Packets": 1,
        "Subflow Fwd Bytes": 40,
        "Subflow Bwd Packets": 0,
        "Subflow Bwd Bytes": 0,
        "Init Fwd Win Bytes": random.randint(1024, 4096),
        "Init Bwd Win Bytes": 0,
        "Fwd Act Data Packets": 0,
        "Fwd Seg Size Min": 40,
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0,
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
        # ETT features (minimal for scan)
        "duration": random.uniform(0, 500),
        "total_fiat": 0, "total_biat": 0,
        "min_fiat": 0, "min_biat": 0,
        "max_fiat": 0, "max_biat": 0,
        "mean_fiat": 0, "mean_biat": 0,
        "flowPktsPerSecond": random.uniform(50, 500),
        "flowBytesPerSecond": random.uniform(1000, 10000),
        "min_flowiat": 0, "max_flowiat": 0,
        "mean_flowiat": 0, "std_flowiat": 0,
        "min_active": 0, "mean_active": 0, "max_active": 0, "std_active": 0,
        "min_idle": 0, "mean_idle": 0, "max_idle": 0, "std_idle": 0,
        "fwd_bwd_ratio": 999.0,
        "iat_cv": 0.1,
        "iat_range_norm": 0.5,
        "active_idle_ratio": 999.0,
        "duration_log": 2.0,
        "bytes_per_packet": 40,
    }


def generate_port_scan_burst() -> list[dict]:
    """A vertical scan: one scanner, 110 ports on one server (the fan-out
    backstop fires at 100 distinct ports; the SPSD tree may fire earlier)."""
    attacker = random.choice(["192.0.2.66", "192.0.2.67", "198.51.100.66"])
    victim = "10.0.0.3"
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
    ports += random.sample(range(1024, 65535), 110 - len(ports))
    now = time.time()
    burst = []
    for i, target_port in enumerate(ports):
        burst.append({
            "type": "flow",
            "source_ip": attacker,
            "dest_ip": victim,
            "source_port": random.randint(49152, 65535),
            "dest_port": target_port,
            "protocol": 6,
            "timestamp": now - 2.0 + i * 0.015,
            "ingest_wall": time.time(),
            "synthetic": True,
            "features": _scan_features(),
        })
    return burst


def generate_host_sweep(hosts: int = 70, port: int = 445) -> list:
    """One internal host probing one port across a /24 (lateral-movement
    recon). Most targets do not answer; a few reset."""
    src = f"192.168.1.{random.randint(20, 29)}"
    now = time.time()
    return [_probe_flow(src, f"10.0.5.{i + 1}", random.randint(49152, 65535), port, 6,
                        now - 3.0 + i * 0.02, rst=random.random() < 0.2)
            for i in range(hosts)]


# ============================================================
# (f) Exfiltration by volume
# ============================================================

def generate_exfil_upload() -> list:
    """An internal host sending 7.5 MB to one external server while
    receiving about 120 KB back, over three connections."""
    src = f"192.168.1.{random.randint(30, 39)}"
    dst = random.choice(["203.0.113.200", "198.51.100.199"])
    now = time.time()
    out = []
    for i in range(3):
        f = _normal_features()
        f.update({"Protocol": 6, "Total Fwd Packets": 1800, "Total Backward Packets": 900,
                  "Fwd Packets Length Total": 2_500_000 + random.randint(-20000, 20000),
                  "Bwd Packets Length Total": 40_000 + random.randint(-2000, 2000)})
        t = now - 90 + i * 30
        out.append({"type": "flow", "source_ip": src, "dest_ip": dst,
                    "source_port": random.randint(49152, 65535), "dest_port": 443, "protocol": 6,
                    "timestamp": t, "last_seen": t + 25, "ingest_wall": time.time(), "synthetic": True,
                    "features": f})
    return out


# ============================================================
# Mode dispatch
# ============================================================
_SCENARIOS = {
    "ddos": lambda: generate_syn_flood_burst() if random.random() < 0.5 else generate_reflection_burst(),
    "c2": lambda: generate_c2_beacon() + [generate_c2_session()],
    "tls": generate_tls_implant,
    "sweep": generate_host_sweep,
    "port_scan": generate_port_scan_burst,
    "nxdomain": generate_nxdomain_burst,
    "dns_tunnel": generate_txt_tunnel,
    "exfil_flow": generate_exfil_upload,
}
_mixed_cycle = itertools.cycle(["ddos", "c2", "tls", "sweep", "nxdomain", "dns_tunnel", "exfil_flow", "port_scan"])
_tick = itertools.count()

SIM_MODES = ["normal", "mixed", "ddos", "c2", "dga", "dns_tunnel", "nxdomain", "tls",
             "port_scan", "sweep", "exfil", "exfil_flow"]


def generate_event(attack_mode: str = "normal"):
    """One simulator tick: an event dict, or a list of events for bursts.

    Burst scenarios fire once every 20 ticks in their own mode (and one of
    them every 30 ticks in mixed mode); the ticks in between are background.
    """
    n = next(_tick)
    if attack_mode == "normal":
        return generate_normal_flow() if random.random() < 0.8 else generate_normal_dns()
    if attack_mode in _SCENARIOS:
        if n % 20 == 0:
            return _SCENARIOS[attack_mode]()
        if attack_mode == "ddos" and random.random() < 0.5:
            return generate_ddos_flow()
        return generate_normal_flow() if random.random() < 0.8 else generate_normal_dns()
    if attack_mode == "dga":
        return generate_dga_dns() if random.random() < 0.7 else generate_normal_dns()
    if attack_mode == "exfil":
        return generate_exfil_dns() if random.random() < 0.7 else generate_normal_dns()
    if attack_mode == "mixed":
        if n % 30 == 0:
            return _SCENARIOS[next(_mixed_cycle)]()
        r = random.random()
        if r < 0.66:
            return generate_normal_flow()
        if r < 0.90:
            return generate_normal_dns()
        if r < 0.97:
            return generate_ddos_flow()
        if r < 0.985:
            return generate_dga_dns()
        return generate_exfil_dns()
    return generate_normal_flow()
