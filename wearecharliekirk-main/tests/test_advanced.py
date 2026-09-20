"""NetSentinel — Advanced Stress & Validation Tests v2.

Tests:
  1. Individual model accuracy (does each model detect its attack type?)
  2. False positive rate (does normal traffic trigger alerts?)
  3. Throughput benchmark (how many flows/sec can the pipeline handle?)
  4. Alert schema validation
  5. Severity distribution
"""
import urllib.request
import json
import time
import sys

BASE = "http://localhost:8000"

def api_get(path):
    resp = urllib.request.urlopen(f"{BASE}{path}")
    return json.loads(resp.read())

def api_post(path):
    req = urllib.request.Request(f"{BASE}{path}", method="POST")
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())

def reset():
    """Stop simulation AND reset all counters."""
    api_post("/api/simulate/stop")
    api_post("/api/reset")
    time.sleep(0.3)


print("=" * 70)
print("  NETSENTINEL ADVANCED TEST SUITE v2")
print("=" * 70)

try:
    health = api_get("/api/health")
    models = health["models"]["models_loaded"]
    loaded = sum(1 for v in models.values() if v)
    print(f"\n[OK] Server online. {loaded}/4 models loaded.")
    for name, status in models.items():
        print(f"     [{'OK' if status else 'FAIL'}] {name}")
except Exception as e:
    print(f"[FAIL] Server not running: {e}")
    sys.exit(1)


# TEST 1: Individual Attack Detection
print("\n" + "-" * 70)
print("TEST 1: Individual Attack Type Detection")
print("-" * 70)

for attack, expected_threat in [("ddos", "DDoS"), ("dga", "DGA"), ("c2", "C2 Beacon")]:
    reset()
    api_post(f"/api/simulate/{attack}")
    time.sleep(3)
    api_post("/api/simulate/stop")
    time.sleep(0.2)

    stats = api_get("/api/stats")
    alerts_resp = api_get("/api/alerts?limit=100")
    processed = stats["flows_processed"]
    threats = stats["threat_distribution"]
    detected = threats.get(expected_threat, 0)

    if detected > 0:
        relevant = [a for a in alerts_resp["alerts"] if a["threat_class"] == expected_threat]
        max_conf = max(a["confidence"] for a in relevant) if relevant else 0
        print(f"  [{attack:5s}] PASS | {detected:3d} alerts | Max conf: {max_conf:.1%} | Flows: {processed}")
    else:
        print(f"  [{attack:5s}] FAIL | 0 detections / {processed} flows | Threats: {threats}")


# TEST 2: False Positive Rate
print("\n" + "-" * 70)
print("TEST 2: False Positive Rate (Normal Traffic Only)")
print("-" * 70)

reset()
api_post("/api/simulate/normal")
time.sleep(5)
api_post("/api/simulate/stop")
time.sleep(0.2)

stats = api_get("/api/stats")
processed = stats["flows_processed"]
false_alerts = stats["total_alerts"]
threats = stats["threat_distribution"]
fp_rate = (false_alerts / processed * 100) if processed > 0 else 0

if fp_rate < 15:
    verdict = "PASS"
elif fp_rate < 30:
    verdict = "WARN"
else:
    verdict = "FAIL"

print(f"  [{verdict}] {processed} normal flows, {false_alerts} false alerts ({fp_rate:.1f}% FP rate)")
if threats:
    print(f"         False threat types: {threats}")
else:
    print(f"         Zero false positives!")


# TEST 3: Throughput Benchmark
print("\n" + "-" * 70)
print("TEST 3: Throughput Benchmark (10 seconds mixed traffic)")
print("-" * 70)

reset()
api_post("/api/simulate/mixed")
time.sleep(10)
api_post("/api/simulate/stop")
time.sleep(0.2)

stats = api_get("/api/stats")
processed = stats["flows_processed"]
throughput = processed / 10.0
total_alerts = stats["total_alerts"]

print(f"  Flows processed: {processed}")
print(f"  Throughput: {throughput:.1f} flows/sec")
print(f"  Alerts: {total_alerts}")
print(f"  Threats: {stats['threat_distribution']}")
print(f"  [{'PASS' if throughput >= 5 else 'WARN'}] {throughput:.0f} flows/sec")


# TEST 4: Alert Schema Validation
print("\n" + "-" * 70)
print("TEST 4: Alert Schema Validation")
print("-" * 70)

alerts_resp = api_get("/api/alerts?limit=10")
alerts = alerts_resp["alerts"]
required = ["id", "timestamp", "source_ip", "dest_ip", "threat_class",
            "confidence", "severity", "model_name", "mitre", "geo"]

if not alerts:
    print("  [FAIL] No alerts to validate")
else:
    all_valid = True
    for i, alert in enumerate(alerts[:3]):
        missing = [f for f in required if f not in alert]
        if missing:
            print(f"  Alert {i}: FAIL — Missing: {missing}")
            all_valid = False
        else:
            sev = alert["severity"]
            conf = alert["confidence"]
            tc = alert["threat_class"]
            geo = alert.get("geo", {}).get("src_country", "??")
            print(f"  Alert {i}: PASS — [{sev:8s}] {tc:15s} conf={conf:.2%} src={geo}")
    if all_valid:
        print(f"  [PASS] All alerts have valid schema")


# TEST 5: Severity Distribution
print("\n" + "-" * 70)
print("TEST 5: Severity Distribution")
print("-" * 70)

alerts_resp = api_get("/api/alerts?limit=200")
alerts = alerts_resp["alerts"]

sev_counts = {}
for a in alerts:
    s = a["severity"]
    sev_counts[s] = sev_counts.get(s, 0) + 1

for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    count = sev_counts.get(sev, 0)
    bar = "#" * min(count, 40)
    print(f"  {sev:8s}: {count:3d} {bar}")

model_counts = {}
for a in alerts:
    m = a["model_name"]
    model_counts[m] = model_counts.get(m, 0) + 1

print(f"\n  Alerts by model:")
for model, count in sorted(model_counts.items(), key=lambda x: -x[1]):
    print(f"    {model:35s}: {count}")


# SUMMARY
print("\n" + "=" * 70)
print("  TEST SUITE COMPLETE")
print("=" * 70)
h = api_get("/api/health")
print(f"  Server: {h['status']} | Models: {loaded}/4")
print()
