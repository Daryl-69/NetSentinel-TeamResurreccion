"""
tests/test_portscan.py

Test suite for the network-event port-scan detection fix (plan §9).

Tests 1, 2, and 5 are fully synthetic and always run. Tests 3 and 4 replay
real PCAP fixtures (`tests/fixtures/portscan_real.pcap`,
`tests/fixtures/benign.pcap`) through the full extraction + detection path;
they are skipped automatically if those fixtures aren't present in this
checkout (they are large binary captures and are not committed here), but
they will run as soon as the fixtures are dropped into place, e.g. copied
from the existing NetSentinel test assets.

Definition of done (plan §9): tests 1-5 pass; portscan_real.pcap produces a
Port Scan alert at realistic confidence (not ~1%); benign.pcap produces
none.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsentinel.netinfo.network_info import NetworkInfo
from netsentinel.extractor.network_event_builder import Flow, NetworkEventBuilder
from netsentinel.models.portscan_detector import PortScanConfig, PortScanDetector

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REAL_SCAN_PCAP = FIXTURES_DIR / "portscan_real.pcap"
BENIGN_PCAP = FIXTURES_DIR / "benign.pcap"


# ----------------------------------------------------------------------
# Shared fixtures
# ----------------------------------------------------------------------
def make_network_info(
    internal_subnets=None,
    known_hosts=None,
    known_open_ports=None,
    time_window_seconds=60,
) -> NetworkInfo:
    return NetworkInfo(
        internal_subnets=internal_subnets or ["192.168.220.0/24"],
        known_hosts=set(known_hosts or ["192.168.220.100"]),
        known_open_ports=known_open_ports or {"192.168.220.100": [80, 443]},
        time_window_seconds=time_window_seconds,
    )


# ----------------------------------------------------------------------
# Test 1: feature builder matches the paper's Table 4 worked example
# ----------------------------------------------------------------------
def test_feature_builder_matches_paper_table4():
    ni = make_network_info()
    builder = NetworkEventBuilder(ni)

    src = "192.168.220.16"
    flows = [
        # icmp_error_count = 2 (ICMP-unreachable received by src)
        Flow("192.168.220.100", src, 0, 0, "ICMP", 10, icmp_type=3, icmp_code=3),
        Flow("192.168.220.101", src, 0, 0, "ICMP", 11, icmp_type=3, icmp_code=1),
        # rst_count = 2 distinct targets (SYN sent, RST back, not established)
        Flow(src, "203.0.113.10", 5000, 1234, "TCP", 12, syn_count=1, rst_count=1, bwd_packets=1),
        Flow(src, "203.0.113.11", 5001, 4321, "TCP", 13, syn_count=1, rst_count=1, bwd_packets=1),
        # rwa_count = 4 distinct targets, unidirectional, no reply
        Flow(src, "203.0.113.20", 5002, 80, "TCP", 14, syn_count=1, bwd_packets=0),
        Flow(src, "203.0.113.21", 5003, 81, "TCP", 15, syn_count=1, bwd_packets=0),
        Flow(src, "203.0.113.22", 5004, 82, "TCP", 16, syn_count=1, bwd_packets=0),
        Flow(src, "203.0.113.23", 5005, 83, "TCP", 17, syn_count=1, bwd_packets=0),
        # neip_count = 1 (internal, not a known host)
        Flow(src, "192.168.220.55", 5006, 445, "TCP", 18, syn_count=1, ack_count=1, bwd_packets=1),
        # netcp_count = 3 distinct (dst, port) on a known host, non-open ports
        Flow(src, "192.168.220.100", 5007, 22, "TCP", 19, syn_count=1, ack_count=1, bwd_packets=1),
        Flow(src, "192.168.220.100", 5008, 3389, "TCP", 20, syn_count=1, ack_count=1, bwd_packets=1),
        Flow(src, "192.168.220.100", 5009, 8080, "TCP", 21, syn_count=1, ack_count=1, bwd_packets=1),
    ]

    events = builder.build(flows)
    assert len(events) == 1
    ev = events[0]

    assert ev.src_ip == src
    assert ev.icmp_error_count == 2
    assert ev.rst_count == 2
    assert ev.rwa_count == 4
    assert ev.neip_count == 1
    assert ev.netcp_count == 3


# ----------------------------------------------------------------------
# Test 2: succession count increments across consecutive suspicious
# windows and resets on a clean window
# ----------------------------------------------------------------------
def test_succession_count_increments_and_resets():
    ni = make_network_info(known_open_ports={"192.168.220.100": [80]})
    builder = NetworkEventBuilder(ni)
    src = "192.168.220.16"

    flows = []
    # 3 consecutive suspicious windows: probe a non-open port each time.
    for i, window_start in enumerate((0, 60, 120)):
        ts = window_start + 5
        flows.append(
            Flow(src, "192.168.220.100", 6000 + i, 9999, "TCP", ts, syn_count=1, ack_count=1, bwd_packets=1)
        )
    # 4th window: clean traffic to the one known-open port -> resets.
    flows.append(
        Flow(src, "192.168.220.100", 6100, 80, "TCP", 185, syn_count=1, ack_count=1, bwd_packets=1)
    )

    events = builder.build(flows)
    events_by_window = {ev.window_start: ev for ev in events}

    assert events_by_window[0].succession_count == 1
    assert events_by_window[60].succession_count == 2
    assert events_by_window[120].succession_count == 3
    assert events_by_window[180].succession_count == 0


# ----------------------------------------------------------------------
# Test 3: integration - real scan PCAP
# ----------------------------------------------------------------------
@pytest.mark.skipif(
    not REAL_SCAN_PCAP.exists(),
    reason=f"fixture not present: {REAL_SCAN_PCAP}",
)
def test_real_scan_pcap_fires_high_confidence_alert():
    """Test with SPSD mode using correct CICIDS2017 network topology.
    
    This PCAP is from CICIDS2017 Friday PortScan scenario:
    - Attacker: 172.16.0.1
    - Target: 192.168.10.50 (Ubuntu web server)
    - Network: 192.168.10.0/24
    
    With correct network_info, neip/netcp features populate properly
    and SPSD should give 85-99% confidence (not just 50% fallback).
    """
    flows = _flows_from_pcap(REAL_SCAN_PCAP)
    
    # Debug: Print flow statistics
    print(f"\n=== PCAP Analysis ===")
    print(f"Total flows parsed: {len(flows)}")
    attacker_flows = [f for f in flows if f.src_ip == "172.16.0.1"]
    print(f"Flows from 172.16.0.1: {len(attacker_flows)}")
    if attacker_flows:
        dst_ports = set(f.dst_port for f in attacker_flows)
        print(f"Distinct dst ports: {len(dst_ports)}")
        
        # Check timestamp distribution - THIS IS THE KEY
        timestamps = sorted([f.timestamp for f in attacker_flows])
        print(f"\nTimestamp distribution:")
        print(f"  Min: {timestamps[0]:.2f}")
        print(f"  Max: {timestamps[-1]:.2f}")
        print(f"  Span: {timestamps[-1] - timestamps[0]:.1f} seconds ({(timestamps[-1] - timestamps[0])/60:.1f} minutes)")
        print(f"  Unique timestamps: {len(set(timestamps))}")
        
        # Show gaps between timestamps
        gaps = [timestamps[i+1] - timestamps[i] for i in range(min(10, len(timestamps)-1))]
        print(f"  First 10 timestamp gaps: {[f'{g:.1f}s' for g in gaps]}")
        
        # Count flows per 60s window
        from collections import Counter
        import math
        windows = Counter(math.floor(ts / 60) * 60 for ts in timestamps)
        print(f"\n  Flows per window (first 5):")
        for window_start, count in sorted(windows.items())[:5]:
            print(f"    Window {window_start}: {count} flows")
    
    # Use CICIDS2017-specific network topology
    ni = make_network_info(
        internal_subnets=["192.168.10.0/24"],
        known_hosts=[
            "192.168.10.3", "192.168.10.5", "192.168.10.8", "192.168.10.9",
            "192.168.10.12", "192.168.10.14", "192.168.10.15", "192.168.10.25",
            "192.168.10.50"
        ],
        known_open_ports={
            "192.168.10.3": [53, 389, 636, 88, 3268],  # AD/DNS server
            "192.168.10.5": [80, 443],                  # Web server
            "192.168.10.8": [22, 80, 443, 3306],       # Database server
            "192.168.10.9": [22, 445, 139, 3389],      # Windows server
            "192.168.10.12": [21, 22, 80],              # FTP/Web
            "192.168.10.14": [25, 110, 143, 587, 993, 995],  # Mail server
            "192.168.10.15": [22, 445, 139, 3389],     # Windows workstation
            "192.168.10.25": [53],                      # DNS
            "192.168.10.50": [21, 22, 80, 443, 8080],  # Target: Ubuntu web server
        },
    )
    
    # Use SPSD mode (trained model) not UPSD fallback
    detector = PortScanDetector(
        network_info=ni,
        cfg=PortScanConfig(
            mode="spsd",
            model_path="netsentinel/models/weights/portscan_spsd_decisiontree.pkl",
            fanout_threshold=100
        ),
    )
    
    alerts = detector.process(flows)

    assert alerts, "expected at least one Port Scan alert on portscan_real.pcap"
    scan_alert = next(a for a in alerts if a.src_ip == "172.16.0.1")
    assert scan_alert.dst_ip in ("192.168.10.50", "multiple")
    
    # Debug: Print actual results
    print(f"\n=== Port Scan Alert Details ===")
    print(f"Confidence: {scan_alert.confidence:.4f}")
    print(f"Evidence: {scan_alert.evidence}")
    print(f"Reason: {scan_alert.reason}")
    print(f"SPSD available: {detector.spsd.is_available if detector.spsd else 'N/A'}")
    
    # With correct network_info + SPSD, confidence should be high (not just 50%)
    assert scan_alert.confidence >= 0.75, \
        f"Expected high confidence with SPSD + correct network_info, got {scan_alert.confidence:.2f}. " \
        f"Evidence: {scan_alert.evidence}"


# ----------------------------------------------------------------------
# Test 4: integration - benign PCAP produces zero port-scan alerts
# ----------------------------------------------------------------------
@pytest.mark.skipif(
    not BENIGN_PCAP.exists(),
    reason=f"fixture not present: {BENIGN_PCAP}",
)
def test_benign_pcap_produces_no_alerts():
    flows = _flows_from_pcap(BENIGN_PCAP)
    ni = make_network_info(
        internal_subnets=["172.16.0.0/16", "192.168.10.0/24"],
        known_hosts=["192.168.10.50", "192.168.10.3"],
        known_open_ports={
            "192.168.10.50": [22, 139, 445, 3389],
            "192.168.10.3": [389, 3268, 88, 53],
        },
    )
    detector = PortScanDetector(network_info=ni, cfg=PortScanConfig(mode="upsd"))
    alerts = detector.process(flows)
    assert alerts == []


# ----------------------------------------------------------------------
# Test 5: cold start - empty network_info must not crash, and the
# fan-out backstop must still catch a high-volume scan.
# ----------------------------------------------------------------------
def test_cold_start_degrades_gracefully_and_fanout_backstop_fires():
    ni = NetworkInfo()  # no internal_subnets / known_hosts / known_open_ports
    assert ni.degraded is True

    detector = PortScanDetector(
        network_info=ni,
        cfg=PortScanConfig(mode="spsd", model_path="does/not/exist.pkl", fanout_threshold=10),
    )

    src = "172.16.0.1"
    dst = "192.168.10.50"
    flows = [
        Flow(src, dst, 40000 + p, p, "TCP", 1.0 + p * 0.01, syn_count=1, bwd_packets=0)
        for p in range(1, 16)  # 15 distinct ports >= fanout_threshold=10
    ]

    alerts = detector.process(flows)  # must not raise

    assert len(alerts) == 1
    assert "fan-out" in alerts[0].reason
    assert alerts[0].src_ip == src


# ----------------------------------------------------------------------
# PCAP helper (used only by tests 3 and 4)
# ----------------------------------------------------------------------
def _flows_from_pcap(pcap_path: Path):
    """Aggregate a PCAP into bidirectional Flow objects keyed by
    (src_ip, dst_ip, src_port, dst_port, protocol).

    This is a minimal stand-in for the project's real CICFlowMeter wrapper,
    sufficient to exercise NetworkEventBuilder/PortScanDetector end to end
    in tests. Production code should adapt actual CICFlowMeter output via
    ``Flow.from_cic_record`` instead of this helper.
    """
    scapy = pytest.importorskip("scapy.all")

    packets = scapy.rdpcap(str(pcap_path))
    agg: dict = {}

    for pkt in packets:
        if scapy.IP not in pkt:
            continue
        ip = pkt[scapy.IP]
        ts = float(pkt.time)

        if scapy.TCP in pkt:
            tcp = pkt[scapy.TCP]
            key = (ip.src, ip.dst, tcp.sport, tcp.dport, "TCP")
            rkey = (ip.dst, ip.src, tcp.dport, tcp.sport, "TCP")
            flags = tcp.flags
            syn = 1 if flags & 0x02 else 0
            ack = 1 if flags & 0x10 else 0
            rst = 1 if flags & 0x04 else 0
            fin = 1 if flags & 0x01 else 0

            if rkey in agg:
                agg[rkey]["bwd_packets"] += 1
                agg[rkey]["rst_count"] = max(agg[rkey]["rst_count"], rst)
                agg[rkey]["ack_count"] = max(agg[rkey]["ack_count"], ack)
                continue

            rec = agg.setdefault(
                key,
                {
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "src_port": tcp.sport,
                    "dst_port": tcp.dport,
                    "protocol": "TCP",
                    "timestamp": ts,
                    "fwd_packets": 0,
                    "bwd_packets": 0,
                    "syn_count": 0,
                    "ack_count": 0,
                    "rst_count": 0,
                    "fin_count": 0,
                },
            )
            rec["fwd_packets"] += 1
            rec["syn_count"] = max(rec["syn_count"], syn)
            rec["ack_count"] = max(rec["ack_count"], ack)
            rec["rst_count"] = max(rec["rst_count"], rst)
            rec["fin_count"] = max(rec["fin_count"], fin)

        elif scapy.UDP in pkt:
            udp = pkt[scapy.UDP]
            key = (ip.src, ip.dst, udp.sport, udp.dport, "UDP")
            rec = agg.setdefault(
                key,
                {
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                    "protocol": "UDP",
                    "timestamp": ts,
                    "fwd_packets": 0,
                    "bwd_packets": 0,
                    "syn_count": 0,
                    "ack_count": 0,
                    "rst_count": 0,
                    "fin_count": 0,
                },
            )
            rec["fwd_packets"] += 1

        elif scapy.ICMP in pkt:
            icmp = pkt[scapy.ICMP]
            key = (ip.src, ip.dst, 0, 0, "ICMP", len(agg))
            agg[key] = {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "src_port": 0,
                "dst_port": 0,
                "protocol": "ICMP",
                "timestamp": ts,
                "fwd_packets": 1,
                "bwd_packets": 0,
                "icmp_type": int(icmp.type),
                "icmp_code": int(icmp.code),
            }

    return [Flow.from_cic_record(_to_cic_keys(rec)) for rec in agg.values()]


def _to_cic_keys(rec: dict) -> dict:
    """Map our internal snake_case aggregation dict onto the key names
    ``Flow.from_cic_record`` understands."""
    return {
        "src_ip": rec["src_ip"],
        "dst_ip": rec["dst_ip"],
        "src_port": rec["src_port"],
        "dst_port": rec["dst_port"],
        "protocol": rec["protocol"],
        "timestamp": rec["timestamp"],
        "fwd_packets": rec.get("fwd_packets", 0),
        "bwd_packets": rec.get("bwd_packets", 0),
        "syn_count": rec.get("syn_count", 0),
        "ack_count": rec.get("ack_count", 0),
        "rst_count": rec.get("rst_count", 0),
        "fin_count": rec.get("fin_count", 0),
        "icmp_type": rec.get("icmp_type"),
        "icmp_code": rec.get("icmp_code"),
    }
