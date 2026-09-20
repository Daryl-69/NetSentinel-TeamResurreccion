#!/usr/bin/env python3
"""
Generate a fast port scan PCAP for testing SPSD model.

This simulates a concentrated port scan (1000 ports in ~30 seconds)
to showcase the trained ML model's behavioral features.

Usage:
    python scripts/generate_fast_scan.py
"""

from scapy.all import IP, TCP, wrpcap
import time
import os

def generate_fast_scan_pcap():
    """Generate synthetic fast port scan packets"""
    
    target = "192.168.10.50"  # Target IP (matches test topology)
    attacker = "172.16.0.1"   # Scanner IP
    ports = range(1, 1001)    # Scan ports 1-1000
    
    print("=" * 60)
    print("NetSentinel Fast Port Scan Generator")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Attacker: {attacker}")
    print(f"Ports: {len(ports)} (1-1000)")
    print(f"Expected duration: ~30 seconds")
    print()
    
    # Known open ports (will respond differently)
    open_ports = {21, 22, 80, 443, 8080}
    
    packets = []
    start_time = time.time()
    base_timestamp = 1499439229.0  # Arbitrary start time
    
    print("Generating packets...")
    
    for i, port in enumerate(ports, 1):
        timestamp = base_timestamp + (i * 0.03)  # 0.03s apart = ~30s total
        
        # SYN packet from attacker
        syn_pkt = IP(src=attacker, dst=target) / TCP(
            sport=40000 + port,
            dport=port,
            flags="S",
            seq=1000 + port
        )
        syn_pkt.time = timestamp
        packets.append(syn_pkt)
        
        # Response: SYN-ACK if open, RST if closed
        if port in open_ports:
            # SYN-ACK response (open port)
            synack_pkt = IP(src=target, dst=attacker) / TCP(
                sport=port,
                dport=40000 + port,
                flags="SA",
                seq=2000 + port,
                ack=1001 + port
            )
            synack_pkt.time = timestamp + 0.001
            packets.append(synack_pkt)
            
            # ACK from attacker
            ack_pkt = IP(src=attacker, dst=target) / TCP(
                sport=40000 + port,
                dport=port,
                flags="A",
                seq=1001 + port,
                ack=2001 + port
            )
            ack_pkt.time = timestamp + 0.002
            packets.append(ack_pkt)
            
            # RST to close connection
            rst_pkt = IP(src=attacker, dst=target) / TCP(
                sport=40000 + port,
                dport=port,
                flags="R",
                seq=1001 + port
            )
            rst_pkt.time = timestamp + 0.003
            packets.append(rst_pkt)
        else:
            # RST response (closed port)
            rst_pkt = IP(src=target, dst=attacker) / TCP(
                sport=port,
                dport=40000 + port,
                flags="R",
                seq=0,
                ack=1001 + port
            )
            rst_pkt.time = timestamp + 0.001
            packets.append(rst_pkt)
        
        if i % 100 == 0:
            print(f"  Generated {i}/{len(ports)} port probes...")
    
    generation_time = time.time() - start_time
    print(f"  Packet generation complete ({generation_time:.2f}s)")
    print()
    
    # Save to PCAP
    output_dir = "tests/fixtures"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "fast_scan.pcap")
    
    print(f"Saving PCAP to: {output_path}")
    wrpcap(output_path, packets)
    
    file_size = os.path.getsize(output_path)
    print(f"PCAP saved: {file_size:,} bytes ({file_size/1024:.1f} KB)")
    print()
    
    # Statistics
    print("=" * 60)
    print("Scan Characteristics:")
    print("=" * 60)
    print(f"Total packets: {len(packets)}")
    print(f"Scan duration: ~30 seconds")
    print(f"Scan rate: ~33 ports/second")
    print(f"Open ports: {len(open_ports)} ({', '.join(map(str, sorted(open_ports)))})")
    print(f"Closed ports: {len(ports) - len(open_ports)}")
    print()
    
    # Expected SPSD behavior
    print("Expected SPSD Model Behavior:")
    print("-" * 60)
    print("Per 60-second window:")
    print(f"  - All {len(ports)} ports in one window (concentrated scan)")
    print(f"  - netcp_count: ~{len(ports) - len(open_ports)} (closed ports probed)")
    print(f"  - rst_count: ~{len(ports) - len(open_ports)} (RST responses)")
    print(f"  - succession_count: 1 (first window with indicators)")
    print(f"  - Expected confidence: 85-95%")
    print()
    print("This PCAP will showcase the trained SPSD model!")
    print("=" * 60)

if __name__ == "__main__":
    try:
        generate_fast_scan_pcap()
        print("\n✅ Success! PCAP ready for testing.")
        print("\nNext steps:")
        print("  1. Run: pytest tests/test_portscan.py -v")
        print("  2. Or test directly with the fast_scan.pcap file")
    except ImportError as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure scapy is installed:")
        print("  pip install scapy")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
