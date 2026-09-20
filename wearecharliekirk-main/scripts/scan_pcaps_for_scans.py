"""
Quick PCAP Scanner - Identifies which PCAPs contain port scan patterns
======================================================================

Quickly analyzes all PCAP files to find which ones have port scan characteristics
without running full ML detection (faster for bulk analysis).

Usage:
    python scan_pcaps_for_scans.py
"""

import os
from pathlib import Path
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP
from scapy.utils import PcapReader


def quick_scan_analysis(pcap_path: str, max_packets: int = 5000) -> dict:
    """
    Quick heuristic analysis for port scan patterns.
    
    Returns:
        dict with scan indicators and confidence
    """
    src_to_dst_ports = defaultdict(set)
    src_to_dst_ips = defaultdict(set)
    syn_count = defaultdict(int)
    failed_connections = defaultdict(int)
    total_packets = 0
    
    try:
        print(f"  📦 Reading packets...", end=" ", flush=True)
        
        # Use PcapReader for memory efficiency
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                if total_packets >= max_packets:
                    break
                
                total_packets += 1
                
                if IP not in pkt:
                    continue
                
                src = pkt[IP].src
                dst = pkt[IP].dst
                
                # Track TCP patterns
                if TCP in pkt:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    flags = pkt[TCP].flags
                    
                    # Track port fan-out per source
                    src_to_dst_ports[src].add(dport)
                    src_to_dst_ips[src].add(dst)
                    
                    # Track SYN packets (scan indicators)
                    if flags & 0x02:  # SYN flag
                        syn_count[src] += 1
                        if not (flags & 0x10):  # No ACK (likely scan probe)
                            failed_connections[src] += 1
        
        print(f"✓ ({total_packets} packets)")
        
        # Analyze patterns
        scan_indicators = []
        scan_confidence = 0.0
        potential_scanners = []
        
        # Find sources with high port fan-out
        for src, ports in src_to_dst_ports.items():
            num_ports = len(ports)
            num_targets = len(src_to_dst_ips[src])
            syn_ratio = syn_count[src] / max(1, total_packets) * 100
            
            # Scoring heuristics
            score = 0
            reasons = []
            
            if num_ports >= 50:
                score += 100
                reasons.append(f"Very high fan-out ({num_ports} ports)")
            elif num_ports >= 20:
                score += 70
                reasons.append(f"High fan-out ({num_ports} ports)")
            elif num_ports >= 10:
                score += 40
                reasons.append(f"Moderate fan-out ({num_ports} ports)")
            
            if num_targets == 1 and num_ports >= 10:
                score += 30
                reasons.append("Vertical scan (1 target)")
            elif num_targets >= 10:
                score += 25
                reasons.append(f"Horizontal scan ({num_targets} targets)")
            
            if failed_connections[src] > num_ports * 0.5:
                score += 20
                reasons.append("Many failed connections")
            
            if score >= 40:
                potential_scanners.append({
                    "ip": src,
                    "ports": num_ports,
                    "targets": num_targets,
                    "syns": syn_count[src],
                    "score": score,
                    "reasons": reasons
                })
        
        # Overall file assessment
        if potential_scanners:
            potential_scanners.sort(key=lambda x: x["score"], reverse=True)
            scan_confidence = min(100, potential_scanners[0]["score"])
            scan_indicators = potential_scanners[0]["reasons"]
        
        return {
            "total_packets": total_packets,
            "contains_scans": scan_confidence >= 40,
            "confidence": scan_confidence,
            "indicators": scan_indicators,
            "scanners": potential_scanners[:3],  # Top 3
            "unique_sources": len(src_to_dst_ports)
        }
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return {
            "total_packets": 0,
            "contains_scans": False,
            "confidence": 0,
            "indicators": [f"Error: {str(e)}"],
            "scanners": [],
            "unique_sources": 0
        }


def scan_all_pcaps():
    """Scan all PCAP files in current directory."""
    print(f"\n{'='*80}")
    print(f"🔍 PCAP Port Scan Detection Survey")
    print(f"{'='*80}\n")
    
    # Find all PCAP files
    pcap_files = list(Path(".").glob("*.pcap"))
    pcap_files.extend(Path(".").glob("**/*.pcap"))
    
    # Deduplicate and sort by size (test smaller files first)
    pcap_files = list(set(pcap_files))
    pcap_files.sort(key=lambda p: p.stat().st_size)
    
    if not pcap_files:
        print("❌ No PCAP files found in current directory")
        return
    
    print(f"Found {len(pcap_files)} PCAP file(s)\n")
    
    results = []
    
    for idx, pcap in enumerate(pcap_files, 1):
        size_mb = pcap.stat().st_size / (1024 * 1024)
        
        print(f"[{idx}/{len(pcap_files)}] {pcap.name}")
        print(f"  📊 Size: {size_mb:.2f} MB")
        
        # Adjust sample size for large files
        if size_mb > 1000:
            max_packets = 3000
        elif size_mb > 100:
            max_packets = 5000
        else:
            max_packets = 10000
        
        result = quick_scan_analysis(str(pcap), max_packets)
        result["filename"] = pcap.name
        result["size_mb"] = size_mb
        results.append(result)
        
        # Print result
        if result["contains_scans"]:
            confidence_str = f"{result['confidence']:.0f}%"
            print(f"  ✅ LIKELY CONTAINS PORT SCANS (confidence: {confidence_str})")
            for indicator in result["indicators"][:3]:
                print(f"     • {indicator}")
            if result["scanners"]:
                top = result["scanners"][0]
                print(f"     • Top scanner: {top['ip']} → {top['ports']} ports")
        else:
            print(f"  ⚠️  No clear port scan patterns detected")
        
        print()
    
    # Summary
    print(f"{'='*80}")
    print(f"📊 Summary")
    print(f"{'='*80}\n")
    
    with_scans = [r for r in results if r["contains_scans"]]
    without_scans = [r for r in results if not r["contains_scans"]]
    
    if with_scans:
        print(f"✅ Files likely containing port scans ({len(with_scans)}):")
        print(f"{'─'*80}")
        for r in sorted(with_scans, key=lambda x: x["confidence"], reverse=True):
            print(f"  {r['filename']:50} ({r['confidence']:.0f}% confidence)")
        print()
    
    if without_scans:
        print(f"⚠️  Files without clear scan patterns ({len(without_scans)}):")
        print(f"{'─'*80}")
        for r in without_scans:
            print(f"  {r['filename']:50} (normal traffic or other attacks)")
        print()
    
    # Recommendations
    print(f"{'='*80}")
    print(f"💡 Recommendations")
    print(f"{'='*80}\n")
    
    if with_scans:
        top = sorted(with_scans, key=lambda x: x["confidence"], reverse=True)[0]
        print(f"Best file for testing: {top['filename']}")
        print(f"Test with: python test_portscan_pcap.py {top['filename']}\n")
    else:
        print("No clear port scan patterns found in any files.")
        print("Consider downloading CIC-IDS2017 Thursday or UNSW-NB15 reconnaissance PCAPs.")
        print("See PORT_SCAN_TEST_GUIDE.md for download links.\n")


if __name__ == "__main__":
    try:
        from scapy.all import rdpcap, IP, TCP  # noqa: F401
    except ImportError:
        print("❌ Scapy not installed")
        print("Install with: pip install scapy")
        exit(1)
    
    scan_all_pcaps()
