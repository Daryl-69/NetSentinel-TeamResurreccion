#!/usr/bin/env python3
"""
Test the fast scan PCAP with SPSD model
"""

import sys
sys.path.insert(0, '.')

from pathlib import Path
from netsentinel.models.portscan_detector import PortScanDetector, PortScanConfig
from netsentinel.netinfo.network_info import NetworkInfo
from netsentinel.extractor.network_event_builder import Flow
import pytest

def make_network_info(internal_subnets, known_hosts, known_open_ports):
    """Helper to create NetworkInfo"""
    return NetworkInfo(
        internal_subnets=internal_subnets,
        known_hosts=set(known_hosts),
        known_open_ports=known_open_ports,
        time_window_seconds=60
    )

def flows_from_pcap(pcap_path):
    """Convert PCAP to Flow objects"""
    scapy = pytest.importorskip("scapy.all")
    
    packets = scapy.rdpcap(str(pcap_path))
    agg = {}
    
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
            
            rec = agg.setdefault(key, {
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
            })
            rec["fwd_packets"] += 1
            rec["syn_count"] = max(rec["syn_count"], syn)
            rec["ack_count"] = max(rec["ack_count"], ack)
            rec["rst_count"] = max(rec["rst_count"], rst)
            rec["fin_count"] = max(rec["fin_count"], fin)
    
    flows = []
    for rec in agg.values():
        flow = Flow(
            src_ip=rec["src_ip"],
            dst_ip=rec["dst_ip"],
            src_port=rec["src_port"],
            dst_port=rec["dst_port"],
            protocol=rec["protocol"],
            timestamp=rec["timestamp"],
            fwd_packets=rec["fwd_packets"],
            bwd_packets=rec["bwd_packets"],
            syn_count=rec["syn_count"],
            ack_count=rec["ack_count"],
            rst_count=rec["rst_count"],
            fin_count=rec["fin_count"],
        )
        flows.append(flow)
    
    return flows

def test_fast_scan():
    """Test fast scan PCAP with SPSD model"""
    
    pcap_path = Path("tests/fixtures/fast_scan.pcap")
    
    if not pcap_path.exists():
        print(f"❌ PCAP not found: {pcap_path}")
        print("Run: python scripts/generate_fast_scan.py")
        return
    
    print("\n" + "=" * 70)
    print("Testing Fast Port Scan with SPSD Model")
    print("=" * 70)
    
    # Load flows
    print(f"\nLoading PCAP: {pcap_path}")
    flows = flows_from_pcap(pcap_path)
    print(f"Total flows parsed: {len(flows)}")
    
    # Filter to attacker
    attacker_flows = [f for f in flows if f.src_ip == "172.16.0.1"]
    print(f"Flows from attacker (172.16.0.1): {len(attacker_flows)}")
    
    # Scan statistics
    dst_ports = set(f.dst_port for f in attacker_flows)
    print(f"Distinct destination ports: {len(dst_ports)}")
    
    # Create network info
    ni = make_network_info(
        internal_subnets=["192.168.10.0/24"],
        known_hosts=["192.168.10.50"],
        known_open_ports={
            "192.168.10.50": [21, 22, 80, 443, 8080]
        },
    )
    
    # Create detector with SPSD model
    detector = PortScanDetector(
        network_info=ni,
        cfg=PortScanConfig(
            mode="spsd",
            model_path="netsentinel/models/weights/portscan_spsd_decisiontree.pkl",
            fanout_threshold=100
        ),
    )
    
    print(f"\nSPSD Model loaded: {detector.spsd.is_available if detector.spsd else False}")
    
    # Build network events
    print("\nBuilding network events...")
    events = detector.builder.build(flows)
    print(f"Total network events: {len(events)}")
    
    attacker_events = [e for e in events if e.src_ip == "172.16.0.1"]
    print(f"Events from attacker: {len(attacker_events)}")
    
    if attacker_events:
        print("\n" + "-" * 70)
        print("Network Event Features (First Event):")
        print("-" * 70)
        ev = attacker_events[0]
        print(f"  Window start: {ev.window_start}")
        print(f"  ICMP errors:  {ev.icmp_error_count}")
        print(f"  RST count:    {ev.rst_count}")
        print(f"  RWA count:    {ev.rwa_count}")
        print(f"  NEIP count:   {ev.neip_count}")
        print(f"  NETCP count:  {ev.netcp_count}")
        print(f"  Succession:   {ev.succession_count}")
        print(f"  Distinct ports: {ev.distinct_dst_ports}")
        print(f"  Distinct IPs:   {ev.distinct_dst_ips}")
    
    # Detect
    print("\n" + "=" * 70)
    print("Running Detection...")
    print("=" * 70)
    alerts = detector.process(flows)
    
    if not alerts:
        print("❌ No alerts generated!")
        return
    
    alert = next((a for a in alerts if a.src_ip == "172.16.0.1"), None)
    
    if not alert:
        print("❌ No alert for attacker 172.16.0.1")
        return
    
    print(f"\n✅ ALERT DETECTED!")
    print("-" * 70)
    print(f"Source IP:    {alert.src_ip}")
    print(f"Target IP:    {alert.dst_ip}")
    print(f"Confidence:   {alert.confidence:.4f} ({alert.confidence*100:.1f}%)")
    print(f"Scan type:    {alert.scan_type}")
    print(f"Reason:       {alert.reason}")
    print(f"\nEvidence:")
    for key, value in alert.evidence.items():
        print(f"  {key:20s}: {value}")
    
    print("\n" + "=" * 70)
    print("Analysis:")
    print("=" * 70)
    
    if alert.evidence.get('netcp', 0) > 900:
        print("✅ High NETCP count (closed ports) detected")
    else:
        print(f"⚠️  NETCP count lower than expected: {alert.evidence.get('netcp', 0)}")
    
    if alert.evidence.get('rst', 0) > 900:
        print("✅ High RST count (closed port responses) detected")
    else:
        print(f"⚠️  RST count lower than expected: {alert.evidence.get('rst', 0)}")
    
    if alert.evidence.get('succession', 0) > 0:
        print(f"✅ Succession counter incremented: {alert.evidence.get('succession', 0)}")
    else:
        print("⚠️  Succession counter did not increment")
    
    if alert.confidence >= 0.85:
        print(f"✅ High confidence ({alert.confidence:.1%}) - SPSD model working!")
    elif alert.confidence >= 0.5:
        print(f"⚠️  Medium confidence ({alert.confidence:.1%})")
    else:
        print(f"❌ Low confidence ({alert.confidence:.1%})")
    
    print("\n" + "=" * 70)
    if alert.confidence >= 0.75 and alert.evidence.get('netcp', 0) > 500:
        print("🎉 SUCCESS! SPSD model detected the fast scan with high confidence!")
        print("This showcases the trained ML model working on concentrated scans.")
    else:
        print("⚠️  Detection worked but confidence/features lower than expected.")
        print("This may indicate the fan-out backstop fired instead of SPSD.")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    try:
        test_fast_scan()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
