import os
from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap
from netsentinel.extractor import PacketProcessor

def create_test_pcap(filename="test.pcap"):
    packets = []
    
    # 1. DNS Query for a DGA-like domain
    dns_pkt = IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname="xkqw8f3m.evil.com"))
    packets.append(dns_pkt)
    
    # 2. Short TCP Flow
    src = "192.168.1.100"
    dst = "10.0.0.1"
    sport = 54321
    dport = 80
    
    # SYN
    packets.append(IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=1000))
    # SYN-ACK
    packets.append(IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001))
    # ACK
    packets.append(IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001))
    # Data PSH-ACK
    packets.append(IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)/b"GET / HTTP/1.1\r\n\r\n")
    # FIN-ACK
    packets.append(IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="FA", seq=1019, ack=2001))
    
    wrpcap(filename, packets)
    print(f"Created {filename} with {len(packets)} packets")

def test_extractor(filename="test.pcap"):
    processor = PacketProcessor()
    
    print("\n--- Extracted Events ---")
    for event in processor.process_pcap(filename):
        print(f"\nEvent Type: {event['type']}")
        if event['type'] == 'dns':
            print(f"  Domain: {event['domain']}")
        elif event['type'] == 'flow':
            print(f"  Flow: {event['source_ip']}:{event['source_port']} -> {event['dest_ip']}:{event['dest_port']}")
            print(f"  Protocol: {event['protocol']}")
            # Check for some key features
            features = event['features']
            print(f"  Total Fwd Packets: {features.get('Total Fwd Packets')}")
            print(f"  Total Bwd Packets: {features.get('Total Backward Packets')}")
            print(f"  Fwd PSH Flags: {features.get('Fwd PSH Flags')}")
            print(f"  Total Features: {len(features)}")
        elif event['type'] == 'session':
            print(f"  Session: {event['source_ip']} -> {event['dest_ip']} (Flows: {event['flow_count']})")
            
    print("\n--- Stats ---")
    print(processor.stats)

if __name__ == "__main__":
    create_test_pcap()
    test_extractor()
