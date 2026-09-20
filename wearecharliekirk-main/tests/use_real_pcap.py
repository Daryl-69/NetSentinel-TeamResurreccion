"""Use a real PCAP file instead of creating one with Scapy."""
import requests

print("""
[!] Scapy PCAP creation has compatibility issues on Windows.

SOLUTION: Use a real PCAP file from a dataset instead.

Download options:
1. CIC-DDoS2019: https://www.unb.ca/cic/datasets/ddos-2019.html
2. CTU-13 Botnet: https://www.stratosphereips.org/datasets-ctu13
3. UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset

After downloading a .pcap file:
1. Copy it to this folder
2. Run: python upload_pcap.py your_file.pcap

OR use the traffic simulator (which works perfectly):
   python start_simulator.py
""")
