"""Test the REAL NetSentinel ML Pipeline

This script demonstrates the difference between:
  ❌ Test scripts (send_test_alert.py) → bypass pipeline, fake alerts
  ✅ Real pipeline → PCAP → extraction → ML models → alerts

Usage:
    python test_real_pipeline.py

What it does:
    1. Creates attack_traffic.pcap with 3 attack types
    2. Uploads PCAP to backend via /api/pcap/upload
    3. Backend processes: packets → flows → ML models → alerts
    4. Alerts broadcast to dashboard via WebSocket
    5. Reports results
"""
import os
import time
import requests
from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap, Raw

BACKEND_URL = "http://localhost:8000"
PCAP_FILE = "attack_traffic.pcap"


def create_attack_pcap():
    """Create a PCAP file with 3 realistic attack scenarios.
    
    Attack 1: DDoS SYN Flood (high pps, imbalanced SYN/ACK ratio)
    Attack 2: DGA Domain Query (suspicious domain name)
    Attack 3: Port Scan (many dest ports, single source)
    """
    from scapy.layers.l2 import Ether
    packets = []
    timestamp = time.time()
    
    print("\n[*] Generating attack traffic...")
    
    # ================================================================
    # Attack 1: DDoS SYN Flood (100 flows with FIN)
    # ================================================================
    print("  ├─ DDoS SYN Flood: 100 flows")
    attacker = "203.0.113.50"
    victim = "192.168.1.10"
    
    for i in range(100):
        # SYN
        syn = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src=attacker, dst=victim) / TCP(
            sport=10000 + i,
            dport=80,
            flags="S",
            seq=1000 + i * 100,
        )
        syn.time = timestamp + i * 0.01  # 10ms intervals = 100 pps
        packets.append(syn)
        
        # FIN to complete flow
        fin = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src=attacker, dst=victim) / TCP(
            sport=10000 + i,
            dport=80,
            flags="F",
            seq=1001 + i * 100,
        )
        fin.time = timestamp + i * 0.01 + 0.001
        packets.append(fin)
    
    # ================================================================
    # Attack 2: DGA Domain Queries (5 suspicious domains)
    # ================================================================
    print("  ├─ DGA Domains: 5 queries")
    dga_domains = [
        "xkqw8f3m2pqr.malware.net",
        "9fj2kd8s4lqp.evil.org",
        "m4lw4r3c2srv.cc",
        "r4nd0m8chars.biz",
        "qpwoei4k3mxz.info",
    ]
    
    dns_server = "8.8.8.8"
    bot = "192.168.1.200"
    
    for idx, domain in enumerate(dga_domains):
        pkt = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src=bot, dst=dns_server) / UDP(sport=50000 + idx, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain)
        )
        pkt.time = timestamp + 2.0 + idx * 0.5  # Spread over 2.5 seconds
        packets.append(pkt)
    
    # ================================================================
    # Attack 3: Port Scan (scan ports 1-50 with RST)
    # ================================================================
    print("  ├─ Port Scan: 50 flows")
    scanner = "198.51.100.75"
    target = "192.168.1.50"
    
    for port in range(1, 51):
        # SYN
        syn = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src=scanner, dst=target) / TCP(
            sport=55555,
            dport=port,
            flags="S",
            seq=2000 + port,
        )
        syn.time = timestamp + 5.0 + port * 0.02  # 20ms intervals
        packets.append(syn)
        
        # RST to complete flow
        rst = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src=scanner, dst=target) / TCP(
            sport=55555,
            dport=port,
            flags="R",
            seq=2001 + port,
        )
        rst.time = timestamp + 5.0 + port * 0.02 + 0.001
        packets.append(rst)
    
    # ================================================================
    # Add some benign traffic (complete 3-way handshake)
    # ================================================================
    print("  └─ Benign Traffic: 10 flows")
    normal_src = "192.168.1.100"
    normal_dst = "93.184.216.34"  # example.com IP
    
    for i in range(10):
        # SYN
        syn = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src=normal_src, dst=normal_dst) / TCP(
            sport=60000 + i, dport=80, flags="S", seq=5000 + i * 100
        )
        syn.time = timestamp + 10.0 + i * 0.5
        packets.append(syn)
        
        # SYN-ACK
        syn_ack = Ether(src="AA:BB:CC:DD:EE:FF", dst="00:11:22:33:44:55") / \
                  IP(src=normal_dst, dst=normal_src) / TCP(
            sport=80, dport=60000 + i, flags="SA", seq=6000 + i * 100, ack=5001 + i * 100
        )
        syn_ack.time = timestamp + 10.05 + i * 0.5
        packets.append(syn_ack)
        
        # ACK
        ack = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src=normal_src, dst=normal_dst) / TCP(
            sport=60000 + i, dport=80, flags="A", seq=5001 + i * 100, ack=6001 + i * 100
        )
        ack.time = timestamp + 10.1 + i * 0.5
        packets.append(ack)
        
        # FIN to close
        fin = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src=normal_src, dst=normal_dst) / TCP(
            sport=60000 + i, dport=80, flags="F", seq=5002 + i * 100, ack=6001 + i * 100
        )
        fin.time = timestamp + 10.2 + i * 0.5
        packets.append(fin)
    
    # Write PCAP with Ethernet linktype
    wrpcap(PCAP_FILE, packets, linktype=1)
    print(f"\n[✓] Created {PCAP_FILE} ({len(packets)} packets, {os.path.getsize(PCAP_FILE)} bytes)")
    return PCAP_FILE


def check_backend_health():
    """Verify backend is running and models are loaded."""
    print("\n[*] Checking backend health...")
    try:
        resp = requests.get(f"{BACKEND_URL}/api/health", timeout=5)
        resp.raise_for_status()
        health = resp.json()
        
        print(f"  ├─ Status: {health['status']}")
        print(f"  ├─ WebSocket clients: {health['websocket_clients']}")
        print(f"  └─ Models loaded:")
        
        for model_name, model_info in health["models"].items():
            status = "✓" if model_info["loaded"] else "✗"
            print(f"      {status} {model_name}")
        
        return True
    except requests.exceptions.ConnectionError:
        print("  ✗ Backend not running!")
        print("\n  Start backend with:")
        print("    python -m netsentinel.main\n")
        return False
    except Exception as e:
        print(f"  ✗ Health check failed: {e}")
        return False


def upload_pcap(pcap_path):
    """Upload PCAP to backend for processing."""
    print(f"\n[*] Uploading {pcap_path} to backend...")
    
    try:
        with open(pcap_path, "rb") as f:
            files = {"file": (os.path.basename(pcap_path), f, "application/vnd.tcpdump.pcap")}
            resp = requests.post(f"{BACKEND_URL}/api/pcap/upload", files=files, timeout=30)
            resp.raise_for_status()
            result = resp.json()
        
        print(f"  ├─ Upload status: {result['status']}")
        print(f"  ├─ Filename: {result['filename']}")
        print(f"  └─ Size: {result['size_bytes']} bytes")
        
        return True
    except Exception as e:
        print(f"  ✗ Upload failed: {e}")
        return False


def wait_for_processing(timeout=30):
    """Wait for backend to process PCAP and generate alerts."""
    print(f"\n[*] Waiting for ML pipeline to process PCAP (timeout: {timeout}s)...")
    print("    Pipeline: PCAP → FlowExtractor → 4 ML Models → AlertManager → WebSocket")
    
    start = time.time()
    initial_count = 0
    
    try:
        # Get initial alert count
        resp = requests.get(f"{BACKEND_URL}/api/alerts?limit=1000", timeout=5)
        resp.raise_for_status()
        initial_count = len(resp.json()["alerts"])
        print(f"    Initial alerts: {initial_count}")
    except:
        pass
    
    # Poll for new alerts
    while time.time() - start < timeout:
        try:
            resp = requests.get(f"{BACKEND_URL}/api/alerts?limit=1000", timeout=5)
            resp.raise_for_status()
            alerts = resp.json()["alerts"]
            
            if len(alerts) > initial_count:
                new_alerts = len(alerts) - initial_count
                print(f"\n  [✓] Pipeline generated {new_alerts} new alert(s)!")
                return alerts[:new_alerts]  # Return only new alerts
            
            print(".", end="", flush=True)
            time.sleep(1)
        except Exception as e:
            print(f"\n  ✗ Error polling alerts: {e}")
            return None
    
    print(f"\n  ✗ Timeout: No new alerts generated after {timeout}s")
    return None


def analyze_results(alerts):
    """Display detailed results from the pipeline."""
    if not alerts:
        print("\n[!] No alerts generated")
        print("\n  Possible reasons:")
        print("    1. PCAP had only benign traffic")
        print("    2. ML models didn't detect threats (confidence too low)")
        print("    3. Pipeline encountered an error (check backend logs)")
        return
    
    print(f"\n{'='*70}")
    print(f"  REAL PIPELINE TEST RESULTS")
    print(f"{'='*70}\n")
    
    # Group alerts by threat type
    by_type = {}
    for alert in alerts:
        threat_type = alert.get("threat_class", "unknown")
        by_type.setdefault(threat_type, []).append(alert)
    
    print(f"[✓] {len(alerts)} alert(s) generated via ML inference:\n")
    
    for threat_type, group in by_type.items():
        print(f"  {threat_type.upper()} ({len(group)} alert{'s' if len(group) > 1 else ''})")
        for alert in group[:3]:  # Show first 3 of each type
            print(f"    ├─ ID: {alert['id']}")
            print(f"    ├─ Severity: {alert['severity']}")
            print(f"    ├─ Confidence: {alert['confidence']*100:.1f}%")
            print(f"    ├─ Model: {alert['model_name']}")
            print(f"    ├─ Source IP: {alert['source_ip']}")
            print(f"    ├─ Dest IP: {alert['dest_ip']}")
            if alert.get("evidence"):
                print(f"    └─ Evidence: {list(alert['evidence'].keys())}")
            print()
    
    print(f"{'='*70}\n")
    
    # Verify vs expected attacks
    print("[*] Attack Detection Summary:")
    print(f"  ├─ Expected: DDoS SYN Flood, DGA Domains, Port Scan")
    print(f"  └─ Detected: {', '.join(by_type.keys())}")
    
    if "ddos" in by_type:
        print("      ✓ DDoS model activated")
    if "dga" in by_type:
        print("      ✓ DGA model activated")
    if "port_scan" in by_type or "discovery" in by_type:
        print("      ✓ Port scan detected")


def print_dashboard_instructions():
    """Print instructions for viewing results in dashboard."""
    print("\n" + "="*70)
    print("  VIEW RESULTS IN DASHBOARD")
    print("="*70 + "\n")
    print("  1. Open dashboard: http://localhost:8443")
    print("  2. Check top-right corner: Should show '🟢 Live'")
    print("  3. Watch for new alerts in the feed")
    print("  4. Critical Alert Panel appears for high-severity threats")
    print("  5. Model cards activate (XGBoost, CNN-BiLSTM, etc.)")
    print("  6. Charts spike when attacks detected")
    print("  7. MITRE heatmap updates with tactics/techniques")
    print("\n" + "="*70 + "\n")


def main():
    """Run complete pipeline test."""
    print("\n" + "="*70)
    print("  NetSentinel REAL ML Pipeline Test")
    print("  (Not a test script — actual packet processing)")
    print("="*70)
    
    # Step 1: Check backend
    if not check_backend_health():
        return 1
    
    # Step 2: Create attack PCAP
    pcap_path = create_attack_pcap()
    
    # Step 3: Upload PCAP
    if not upload_pcap(pcap_path):
        return 1
    
    # Step 4: Wait for processing
    alerts = wait_for_processing(timeout=30)
    
    # Step 5: Analyze results
    analyze_results(alerts)
    
    # Step 6: Dashboard instructions
    print_dashboard_instructions()
    
    print("[✓] Test complete!")
    print(f"\n  PCAP file saved: {pcap_path}")
    print("  You can upload it again anytime with:")
    print(f"    curl -F \"file=@{pcap_path}\" {BACKEND_URL}/api/pcap/upload\n")
    
    return 0


if __name__ == "__main__":
    exit(main())
