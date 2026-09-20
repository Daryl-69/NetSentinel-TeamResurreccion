"""Simple test - just upload PCAP and watch dashboard."""
import os
import requests
from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap

BACKEND_URL = "http://localhost:8000"
PCAP_FILE = "test_attacks.pcap"

def create_pcap():
    """Create a simple attack PCAP with COMPLETE flows."""
    from scapy.layers.l2 import Ether
    from scapy.all import wrpcap
    import time
    packets = []
    base_time = time.time()
    
    # DDoS SYN Flood (50 COMPLETE flows with FIN)
    print("[*] Creating DDoS SYN flood packets...")
    for i in range(50):
        # SYN
        syn = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src="203.0.113.50", dst="192.168.1.10") / \
              TCP(sport=10000+i, dport=80, flags="S", seq=1000+i*100)
        syn.time = base_time + i * 0.01
        packets.append(syn)
        
        # FIN to complete the flow
        fin = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src="203.0.113.50", dst="192.168.1.10") / \
              TCP(sport=10000+i, dport=80, flags="F", seq=1001+i*100)
        fin.time = base_time + i * 0.01 + 0.001
        packets.append(fin)
    
    # DGA Domain
    print("[*] Creating DGA domain query...")
    pkt = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
          IP(src="192.168.1.200", dst="8.8.8.8") / \
          UDP(sport=50000, dport=53) / \
          DNS(rd=1, qd=DNSQR(qname="xkqw8f3m2pqr.malware.net"))
    pkt.time = base_time + 2.0
    packets.append(pkt)
    
    # Port Scan (20 COMPLETE flows with RST)
    print("[*] Creating port scan...")
    for port in range(1, 21):
        # SYN
        syn = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src="198.51.100.75", dst="192.168.1.50") / \
              TCP(sport=55555, dport=port, flags="S", seq=2000+port)
        syn.time = base_time + 5.0 + port * 0.02
        packets.append(syn)
        
        # RST to complete the flow
        rst = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
              IP(src="198.51.100.75", dst="192.168.1.50") / \
              TCP(sport=55555, dport=port, flags="R", seq=2001+port)
        rst.time = base_time + 5.0 + port * 0.02 + 0.001
        packets.append(rst)
    
    # Write PCAP
    wrpcap(PCAP_FILE, packets, linktype=1)  # DLT_EN10MB
    print(f"[✓] Created {PCAP_FILE} ({len(packets)} packets)\n")

def upload_pcap():
    """Upload PCAP to backend."""
    print(f"[*] Uploading {PCAP_FILE}...")
    
    try:
        with open(PCAP_FILE, "rb") as f:
            files = {"file": (PCAP_FILE, f, "application/vnd.tcpdump.pcap")}
            resp = requests.post(f"{BACKEND_URL}/api/pcap/upload", files=files, timeout=30)
            resp.raise_for_status()
            print("[✓] PCAP uploaded successfully!\n")
            return True
    except Exception as e:
        print(f"[✗] Upload failed: {e}\n")
        return False

def main():
    print("\n" + "="*60)
    print("  Simple PCAP Upload Test")
    print("="*60 + "\n")
    
    # Check if backend is running
    try:
        resp = requests.get(f"{BACKEND_URL}/api/health", timeout=5)
        print("[✓] Backend is running\n")
    except:
        print("[✗] Backend not running!")
        print("    Start it with: python run.py\n")
        return
    
    # Create and upload PCAP
    create_pcap()
    
    if upload_pcap():
        print("="*60)
        print("  SUCCESS!")
        print("="*60)
        print("\n  Now watch your dashboard at http://localhost:8443")
        print("  - Top-right should show: 🟢 Live")
        print("  - Alerts should appear in the feed")
        print("  - Charts should update\n")
        print(f"  PCAP saved as: {PCAP_FILE}")
        print("  You can upload it again anytime with:")
        print(f"    curl -F \"file=@{PCAP_FILE}\" {BACKEND_URL}/api/pcap/upload\n")

if __name__ == "__main__":
    main()
