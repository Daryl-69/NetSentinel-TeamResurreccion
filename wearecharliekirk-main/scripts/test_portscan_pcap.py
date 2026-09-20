"""
Test Port Scan Detection Against Real PCAP Files
=================================================

This script tests the port scan XGBoost model against real-world
PCAP files, specifically looking for reconnaissance/scan patterns.

Usage:
    python test_portscan_pcap.py <pcap_file>
    
Example:
    python test_portscan_pcap.py Thursday-WorkingHours.pcap
"""

import sys
import os
from pathlib import Path
from collections import defaultdict, Counter
from netsentinel.extractor.cicflowmeter_wrapper import CICFlowMeterExtractor
from netsentinel.models.port_scan import PortScanDetector

def analyze_pcap_for_scans(pcap_path: str, max_packets: int = 50000):
    """
    Analyze a PCAP file for port scan patterns.
    
    Args:
        pcap_path: Path to PCAP file
        max_packets: Maximum packets to process (for large files)
    """
    
    if not os.path.exists(pcap_path):
        print(f"❌ PCAP file not found: {pcap_path}")
        return
    
    file_size_mb = os.path.getsize(pcap_path) / (1024 * 1024)
    print(f"\n{'='*70}")
    print(f"🔍 Port Scan Detection Test")
    print(f"{'='*70}")
    print(f"📁 File: {os.path.basename(pcap_path)}")
    print(f"📊 Size: {file_size_mb:.2f} MB")
    print(f"⚙️  Max packets: {max_packets:,}")
    print(f"{'='*70}\n")
    
    # Initialize extractor and detector
    print("[1/4] Loading CICFlowMeter extractor...")
    try:
        extractor = CICFlowMeterExtractor()
    except Exception as e:
        print(f"❌ Failed to load CICFlowMeter: {e}")
        print("💡 Install with: pip install cicflowmeter")
        return
    
    print("[2/4] Loading Port Scan XGBoost model...")
    try:
        detector = PortScanDetector()
    except Exception as e:
        print(f"❌ Failed to load Port Scan model: {e}")
        print("💡 Ensure port_scan_cic_xgboost.onnx exists in models/portscan/")
        return
    
    print(f"[3/4] Extracting flows from PCAP (max {max_packets:,} packets)...")
    try:
        events = extractor.extract_from_pcap(pcap_path, max_packets=max_packets)
        print(f"✅ Extracted {len(events)} flows\n")
    except Exception as e:
        print(f"❌ Failed to extract flows: {e}")
        return
    
    if len(events) == 0:
        print("⚠️  No flows extracted from PCAP")
        return
    
    print("[4/4] Running port scan detection...")
    print(f"{'─'*70}\n")
    
    # Track scan patterns
    src_to_dst_ports = defaultdict(set)
    scan_alerts = []
    total_flows = 0
    
    for idx, event in enumerate(events):
        features = event.get("features", {})
        if not features:
            continue
        
        total_flows += 1
        src_ip = event.get("source_ip", "unknown")
        dst_port = event.get("dest_port", 0)
        
        # Track port fan-out
        if src_ip and dst_port:
            src_to_dst_ports[src_ip].add(dst_port)
        
        # Run ML detection
        try:
            result = detector.predict(features)
            
            if result.get("threat") == "Port Scan":
                conf = result.get("confidence", 0)
                num_ports = len(src_to_dst_ports[src_ip])
                
                scan_alerts.append({
                    "flow_idx": idx,
                    "source_ip": src_ip,
                    "dest_ip": event.get("dest_ip", "unknown"),
                    "dest_port": dst_port,
                    "confidence": conf,
                    "ports_scanned": num_ports,
                    "model": result.get("model", "port_scan_xgboost")
                })
        except Exception as e:
            # Silent fail for individual flows
            pass
    
    # Analysis Results
    print(f"{'='*70}")
    print(f"📊 Analysis Results")
    print(f"{'='*70}")
    print(f"Total flows analyzed: {total_flows:,}")
    print(f"Port scan alerts: {len(scan_alerts)}")
    print(f"Unique source IPs: {len(src_to_dst_ports)}")
    print(f"{'='*70}\n")
    
    # Find top scanners (by port fan-out)
    scanners = [(ip, len(ports)) for ip, ports in src_to_dst_ports.items() if len(ports) >= 5]
    scanners.sort(key=lambda x: x[1], reverse=True)
    
    if scanners:
        print(f"🎯 Top Port Scanners (by fan-out):")
        print(f"{'─'*70}")
        for rank, (ip, port_count) in enumerate(scanners[:10], 1):
            # Check if ML detected this IP
            ml_detected = any(a["source_ip"] == ip for a in scan_alerts)
            status = "✅ ML DETECTED" if ml_detected else "❌ ML MISSED"
            print(f"  {rank:2}. {ip:15} → {port_count:4} ports  {status}")
        print()
    
    if scan_alerts:
        print(f"🚨 ML Model Detections:")
        print(f"{'─'*70}")
        
        # Group by source IP
        by_src = defaultdict(list)
        for alert in scan_alerts:
            by_src[alert["source_ip"]].append(alert)
        
        for src_ip, alerts in sorted(by_src.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
            avg_conf = sum(a["confidence"] for a in alerts) / len(alerts)
            max_ports = max(a["ports_scanned"] for a in alerts)
            print(f"\n  Source: {src_ip}")
            print(f"  Flows flagged: {len(alerts)}")
            print(f"  Ports scanned: {max_ports}")
            print(f"  Avg confidence: {avg_conf:.3f}")
            print(f"  Sample ports: {sorted(src_to_dst_ports[src_ip])[:20]}")
    else:
        print("⚠️  No port scans detected by ML model")
        if scanners:
            print("\n💡 Possible reasons:")
            print("   - Model threshold too high")
            print("   - Features don't match training distribution")
            print("   - Scan pattern is stealthy (slow scan)")
    
    print(f"\n{'='*70}")
    print("✅ Analysis complete")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n📂 Available PCAP files in current directory:")
        pcaps = list(Path(".").glob("*.pcap"))
        if pcaps:
            for p in sorted(pcaps)[:10]:
                size_mb = p.stat().st_size / (1024 * 1024)
                print(f"  - {p.name:50} ({size_mb:>8.2f} MB)")
        else:
            print("  (no PCAP files found)")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Adjust max_packets based on file size
    file_size_mb = os.path.getsize(pcap_file) / (1024 * 1024)
    if file_size_mb > 1000:  # > 1GB
        max_packets = 20000
        print(f"⚠️  Large file detected ({file_size_mb:.0f} MB)")
        print(f"   Limiting to {max_packets:,} packets to avoid memory issues\n")
    elif file_size_mb > 100:  # > 100MB
        max_packets = 50000
    else:
        max_packets = 100000
    
    analyze_pcap_for_scans(pcap_file, max_packets=max_packets)
