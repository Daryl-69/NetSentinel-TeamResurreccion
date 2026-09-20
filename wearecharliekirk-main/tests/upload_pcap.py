"""Upload any PCAP file to the backend."""
import sys
import requests

if len(sys.argv) < 2:
    print("Usage: python upload_pcap.py <pcap_file>")
    print("Example: python upload_pcap.py attack.pcap")
    sys.exit(1)

pcap_file = sys.argv[1]
backend_url = "http://localhost:8000"

print(f"[*] Uploading {pcap_file}...")

try:
    with open(pcap_file, "rb") as f:
        files = {"file": (pcap_file, f, "application/vnd.tcpdump.pcap")}
        resp = requests.post(f"{backend_url}/api/pcap/upload", files=files, timeout=30)
        resp.raise_for_status()
        print("[✓] PCAP uploaded successfully!")
        print("\n  Watch your dashboard at http://localhost:8443")
except FileNotFoundError:
    print(f"[✗] File not found: {pcap_file}")
except Exception as e:
    print(f"[✗] Upload failed: {e}")
