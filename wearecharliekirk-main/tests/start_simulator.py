"""Start the traffic simulator to generate live alerts."""
import requests

print("[*] Starting traffic simulator (mixed attacks)...")
try:
    resp = requests.post("http://localhost:8000/api/simulate/mixed")
    resp.raise_for_status()
    print("[✓] Simulator started!")
    print("\n  Watch your dashboard at http://localhost:8443")
    print("  Alerts should appear every few seconds")
    print("\n  To stop: python stop_simulator.py\n")
except Exception as e:
    print(f"[✗] Failed: {e}")
