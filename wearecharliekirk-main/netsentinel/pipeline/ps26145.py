"""PS 26145 coverage and constraint status, computed from the running sensor.

The console's Overview tab renders this. Every "live" value is read from the
sensor at request time (metrics, counters, configuration); the static text
says how each requirement is met and where in the repository it lives.
"""
from __future__ import annotations

import netsentinel.config as config
from netsentinel.pipeline.alert_schema import SCHEMA_ID, ALERT_SCHEMA

THREATS = [
    {
        "id": "a", "title": "DDoS",
        "ps_text": "SYN floods, UDP reflection/amplification, spoofed traffic, using rate and entropy of source IPs",
        "classes": ["DDoS"],
        "detectors": [
            {"name": "XGBoost on 59 flow features (CIC-DDoS2019)", "kind": "model", "key": "ddos"},
            {"name": "Per-destination rate, source-IP entropy and attack family (10 s window)",
             "kind": "rule", "key": "ddos_rate_entropy"},
        ],
        "evidence": ["flow, packet and byte rate", "source-IP entropy (bits and normalised)",
                     "SYN-only and UDP share", "amplifier source port (NTP, DNS, SSDP, ...)",
                     "spoofed-sources flag"],
        "code": "netsentinel/detectors/ddos_volume.py, netsentinel/models/ddos.py",
    },
    {
        "id": "b", "title": "C2 beaconing",
        "ps_text": "periodic check-ins to command-and-control",
        "classes": ["C2 Beacon"],
        "detectors": [
            {"name": "Combined periodicity score: timing, FFT, size, rarity, persistence (primary)",
             "kind": "rule", "key": "c2_combined"},
            {"name": "BiLSTM + FFT sequence model (verdict attached as evidence)", "kind": "model", "key": "c2"},
        ],
        "evidence": ["score and its five terms", "check-ins, median gap, span", "gap series", "BiLSTM probability"],
        "code": "netsentinel/detectors/beacon_score.py, netsentinel/models/c2_beacon.py",
    },
    {
        "id": "c", "title": "DGA and DNS tunnelling",
        "ps_text": "entropy, n-gram, query length and record-type anomalies",
        "classes": ["DGA", "DNS Tunnel"],
        "detectors": [
            {"name": "Character CNN-BiLSTM on each name (DGA / tunnel / benign)", "kind": "model", "key": "dga"},
            {"name": "DNS behaviour: NXDOMAIN rate, record-type mix, subdomain fan-out (5 min)",
             "kind": "rule", "key": "dns_behaviour"},
        ],
        "evidence": ["name entropy and class probabilities", "query type", "NXDOMAIN rate",
                     "record-type mix per host and base domain", "unique names, label length", "query/reply bytes"],
        "code": "netsentinel/models/dga.py, netsentinel/detectors/dns_behaviour.py",
    },
    {
        "id": "d", "title": "Malware in encrypted sessions",
        "ps_text": "JA3/JA3S/JA4 fingerprints, packet-size and timing sequences",
        "classes": ["Encrypted Malware"],
        "detectors": [
            {"name": "JA3/JA3S/JA4 from the cleartext hello + session size/timing profile",
             "kind": "rule", "key": "tls_sessions"},
        ],
        "evidence": ["JA3, JA3S, JA4, SNI, ALPN, offered version", "fingerprint rarity on this sensor",
                     "session timing and size regularity", "packet-size sequence", "ClientHello anomalies",
                     "blocklist match (operator-supplied)"],
        "code": "netsentinel/extractor/tls_parse.py, netsentinel/detectors/tls_sessions.py",
    },
    {
        "id": "e", "title": "Reconnaissance and port scans",
        "ps_text": "fan-out across ports or hosts",
        "classes": ["Port Scan"],
        "detectors": [
            {"name": "Network-event decision tree (SPSD, CIDDS-001) per source per 60 s",
             "kind": "model", "key": "port_scan"},
            {"name": "Fan-out backstops: >= 100 ports on a host, >= 32 hosts on a port", "kind": "rule",
             "key": "port_scan"},
        ],
        "evidence": ["distinct ports and hosts", "sweep port and host count", "RST / no-reply / ICMP counts",
                     "non-existent host and closed-port hits", "succession across windows"],
        "code": "netsentinel/models/portscan_detector.py, netsentinel/pipeline/portscan_integration.py",
    },
    {
        "id": "f", "title": "Data exfiltration",
        "ps_text": "asymmetric flow volume, out/in byte ratio",
        "classes": ["Data Exfiltration"],
        "detectors": [
            {"name": "Out/in byte ratio of outbound connections (15 min)", "kind": "rule", "key": "exfil_ratio"},
            {"name": "VAE on 24 lexical features of DNS names (DNS tunnelling)", "kind": "model",
             "key": "exfiltration"},
        ],
        "evidence": ["bytes out and in, ratio", "connections and port", "reconstruction error", "measured DNS bytes"],
        "code": "netsentinel/detectors/exfil_ratio.py, netsentinel/models/exfiltration.py",
    },
]


def _loaded(registry, key: str) -> bool:
    if key in (getattr(registry, "rule_detectors", {}) or {}):
        return True
    return getattr(registry, key, None) is not None


def build_status(analyzer, alert_manager, metrics, packet_processor=None, benchmark=None) -> dict:
    snap = metrics.snapshot(with_series=False)
    counts = dict(alert_manager.threat_counts)
    registry = analyzer.registry
    threats = []
    for t in THREATS:
        dets = [dict(d, loaded=_loaded(registry, d["key"])) for d in t["detectors"]]
        threats.append({**t, "detectors": dets,
                        "alerts": sum(counts.get(c, 0) for c in t["classes"]),
                        "active": any(d["loaded"] for d in dets)})

    lat = snap["latency_ms"]
    ev = lat.get("event", {})
    flow_p95 = (ev.get("flow") or {}).get("p95")
    dns_p95 = (ev.get("dns") or {}).get("p95")
    i2a = lat.get("ingest_to_alert") or {}
    ext = packet_processor.stats if packet_processor is not None else {}
    fe = (ext or {}).get("flow_extractor") or {}
    schema_bad = getattr(alert_manager, "schema_violations", 0)

    constraints = [
        {
            "id": "a", "title": "Read-only ingest", "status": "met",
            "how": ("Packets are only read: from capture files, or from a SPAN/tap interface through "
                    "Scapy's sniff() with store=False. No code path in the sensor transmits on the "
                    "monitored network, and detection needs no internet connection."),
            "live": {"sources": ["pcap/pcapng replay", "live interface (receive only)", "synthetic simulator"],
                     "source_now": snap["source"]["kind"]},
        },
        {
            "id": "b", "title": "No payload decryption",
            "status": "met" if not config.QUIC_INITIAL_PARSE else "attention",
            "how": ("TLS: JA3/JA3S/JA4, SNI and ALPN come from the ClientHello/ServerHello, which are "
                    "sent in the clear before any key exists. Application data is never read. QUIC "
                    "ClientHellos sit inside Initial packets protected with publicly derivable keys "
                    "(RFC 9001); reading them is a decryption, so it is off unless "
                    "NETSENTINEL_QUIC_INITIAL_PARSE=1."),
            "live": {"tls_client_hellos": fe.get("tls_client_hellos"),
                     "tls_sessions_profiled": getattr(analyzer.tls_detector, "handshakes", 0),
                     "quic_initial_parse": bool(config.QUIC_INITIAL_PARSE),
                     "quic_client_hellos": fe.get("quic_client_hellos")},
        },
        {
            "id": "c", "title": "Streaming, bounded latency", "status": "met",
            "how": ("Every event is analysed as it arrives. A flow reaches the detectors when it ends "
                    f"(FIN/RST), after {config.FLOW_IDLE_TIMEOUT} s idle or {config.FLOW_ACTIVE_TIMEOUT} s "
                    f"active; an unanswered probe after {config.PROBE_FLOW_TIMEOUT_S} s. Windowed detectors "
                    "add their window: DDoS 10 s, port scan 60 s, DNS behaviour 5 min, and C2 needs at least "
                    "30 minutes of check-ins by definition."),
            "live": {"flow_event_p95_ms": flow_p95, "dns_event_p95_ms": dns_p95,
                     "ingest_to_alert_p95_ms": i2a.get("p95"), "ingest_to_alert_p99_ms": i2a.get("p99"),
                     "dropped_events": snap["totals"].get("dropped", 0)},
        },
        {
            "id": "d", "title": "Stated and demonstrated throughput",
            "status": "measured" if benchmark else "not measured yet",
            "how": ("Throughput now is measured continuously over 10 s windows. The benchmark replays a "
                    "capture through extraction and every detector as fast as one process can and "
                    "reports what it sustained (scripts/benchmark_throughput.py, or the Benchmark button)."),
            "live": {"now": snap["throughput"], "peak": snap["peak_throughput"]},
            "benchmark": _bench_summary(benchmark),
        },
        {
            "id": "e", "title": "Standardized alert schema",
            "status": "met" if not schema_bad else "attention",
            "how": (f"Every alert is built in one schema ({SCHEMA_ID}): timestamp and event time, flow "
                    "identifier with Community ID, threat class and PS category, confidence with its kind, "
                    "severity, evidence, ATT&CK mapping and latency. JSON Schema at /api/schema/alert and "
                    "docs/alert_schema_v1.json."),
            "live": {"alerts": alert_manager.total_count, "schema_violations": schema_bad,
                     "required_fields": ALERT_SCHEMA["required"]},
        },
    ]
    deliverables = [
        {"title": "Working prototype repository",
         "detail": "ingest (netsentinel/extractor), feature extraction, model inference and rule detectors "
                   "(netsentinel/models, netsentinel/detectors), alert output (pipeline/alert_manager.py, "
                   "REST /api and WebSocket /ws)"},
        {"title": "Documentation of models, features and training/validation",
         "detail": "docs/PS26145_COMPLIANCE.md, docs/ALERT_SCHEMA.md, README.md (with figures), docs/figures/, "
                   "models/*/ *_metrics.json and evaluation figures"},
        {"title": "Dashboard of live or replayed detections with severity and confidence",
         "detail": "this console (/console/): Overview, Alerts, Hosts, Models, Inspector–Sentry, Integrity, Ingest"},
    ]
    return {"schema": SCHEMA_ID, "threats": threats, "constraints": constraints,
            "deliverables": deliverables, "totals": snap["totals"]}


def _bench_summary(b):
    if not b:
        return None
    keys = ("kind", "file", "measured_at", "packets", "avg_packet_bytes", "elapsed_s", "packets_per_s",
            "mbps", "flows_per_s", "events_per_s", "realtime_factor", "machine")
    out = {k: b.get(k) for k in keys}
    ev = (b.get("latency_ms") or {}).get("event") or {}
    out["flow_event_p95_ms"] = (ev.get("flow") or {}).get("p95")
    return out
