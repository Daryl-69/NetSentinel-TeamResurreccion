"""Stop the traffic simulator."""
import requests

print("[*] Stopping simulator...")
try:
    resp = requests.post("http://localhost:8000/api/simulate/stop")
    resp.raise_for_status()
    print("[✓] Simulator stopped")
except Exception as e:
    print(f"[✗] Failed: {e}")
