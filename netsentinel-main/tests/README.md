# NetSentinel Test Suite

This directory contains test scripts for validating the NetSentinel detection pipeline and UI components.

---

## Quick Start

### Prerequisites
Before running tests, ensure both backend and frontend are running:

**Terminal 1 - Backend:**
```bash
cd ..
python run.py
```

**Terminal 2 - Frontend:**
```bash
cd ../frontend
npm run dev
```

**Terminal 3 - Run Tests:**
```bash
cd tests
python simple_test.py
```

---

## Test Scripts

### ✅ simple_test.py - **Quick Validation** (RECOMMENDED)

**Purpose:** End-to-end pipeline validation with minimal traffic.

**What it does:**
1. Creates synthetic PCAP with 71 packets:
   - 50 DDoS SYN flood packets
   - 1 DGA domain query
   - 20 port scan packets
2. Uploads PCAP to backend via HTTP POST
3. Backend processes packets → extracts flows → runs ML models → generates alerts
4. Dashboard receives alerts via WebSocket and displays them

**Usage:**
```bash
python simple_test.py
```

**Expected Output:**
```
✅ Backend is running
✅ Created test_attacks.pcap (71 packets)
✅ PCAP uploaded successfully!

SUCCESS!
Now watch your dashboard at http://localhost:8443
- Top-right should show: 🟢 Live
- Alerts should appear in the feed
- Charts should update
```

**Dashboard Expectations:**
- 1-3 alerts appear within 5 seconds
- 3D graph shows 2-4 nodes (attacker + victim IPs)
- Traffic chart shows packet spike
- MITRE heatmap lights up (Impact tactic)

**When to use:**
- Quick validation after code changes
- Verify backend → frontend integration
- Demo to judges/users (fast, reproducible)

---

### 🔥 start_simulator.py - **Traffic Generator** (FOR DEMOS)

**Purpose:** Continuous high-volume alert generation for demonstrations.

**What it does:**
1. Sends HTTP POST to `/api/simulate/mixed`
2. Backend generates synthetic flow events (bypasses packet extraction)
3. Events are tuned to trigger ML models (guaranteed alerts)
4. Runs continuously until stopped

**Usage:**
```bash
# Start simulator
python start_simulator.py

# Watch dashboard - alerts appear every 1-5 seconds

# Stop simulator (in another terminal)
python stop_simulator.py
```

**Expected Output:**
```
Simulator started! Alerts will appear continuously.
Press Ctrl+C or run stop_simulator.py to stop.
```

**Dashboard Expectations:**
- 10-20 alerts within 30 seconds
- 3D graph shows 6-10 nodes
- All charts continuously updating
- Multiple attack types (DDoS, DGA, Port Scan, Encrypted)

**When to use:**
- Live demonstrations (impressive visuals)
- Stress testing dashboard performance
- UI development (guaranteed data flow)

**Limitations:**
- Bypasses packet extraction (doesn't test full pipeline)
- Synthetic features (not from real network traffic)

---

### 📨 send_test_alert.py - **WebSocket Test**

**Purpose:** Validate WebSocket connectivity (frontend ↔ backend).

**What it does:**
1. Connects to WebSocket at `ws://localhost:8000/ws`
2. Sends fake alert JSON directly
3. Dashboard receives and displays alert

**Usage:**
```bash
python send_test_alert.py
```

**Expected Output:**
```
✅ Connected to ws://localhost:8000/ws
✅ Sent test alert
Check your dashboard!
```

**Dashboard Expectations:**
- Single DDoS alert appears immediately
- No PCAP processing (alert is fake)

**When to use:**
- Debug WebSocket issues
- Validate frontend schema parsing
- Test UI rendering without ML pipeline

---

### 🔬 test_real_pipeline.py - **Comprehensive Test**

**Purpose:** Large-scale validation with mixed traffic types.

**What it does:**
1. Creates large PCAP with 300+ packets:
   - 100 DDoS flows
   - 5 DGA domains
   - 50 port scans
   - 10 benign flows
2. Uploads to backend
3. Analyzes results (alert count, node count, MITRE mapping)

**Usage:**
```bash
python test_real_pipeline.py
```

**Expected Output:**
```
======================================================================
      NetSentinel REAL ML Pipeline Test
      (Not a test script — actual packet processing)
======================================================================

[*] Checking backend health...
├─ Status: online
├─ WebSocket clients: 1
└─ Models loaded: 4/4

[*] Creating comprehensive attack PCAP...
├─ DDoS flows: 100
├─ DGA queries: 5
├─ Port scans: 50
└─ Benign traffic: 10

[*] Uploading PCAP (15.2 KB)...
✅ Upload successful

[*] Waiting for processing (15s)...
[*] Analyzing results...

Results:
├─ Alerts generated: 8
├─ Critical: 3
├─ High: 4
├─ Medium: 1
└─ MITRE tactics: Impact, Discovery

✅ Test passed - alerts generated successfully
```

**Dashboard Expectations:**
- 5-10 alerts appear
- 4-8 nodes in graph
- Multiple severity levels

**When to use:**
- Comprehensive validation before release
- Test model discrimination (benign vs malicious)
- Verify multiple attack types

---

### 🐛 debug_pcap.py - **PCAP Debugging**

**Purpose:** Offline PCAP analysis without WebSocket/dashboard.

**What it does:**
1. Loads ML models directly
2. Processes PCAP file (reads from `uploads/test_attacks.pcap`)
3. Prints events and alerts to terminal
4. Shows why alerts were/weren't generated

**Usage:**
```bash
python debug_pcap.py
```

**Expected Output:**
```
[*] Loading models...
[OK] 4/4 models loaded in 0.21s
[*] Processing uploads/test_attacks.pcap...

Event 1: type=flow, src=203.0.113.50, dst=192.168.1.10
  Features: pps=500, syn_ack_ratio=0.95
  DDoS model: confidence=0.92 → ALERT

Event 2: type=dns, domain=xkqw8f3m2pqr.malware.net
  DGA model: confidence=0.78 → IGNORE (< 0.85)

[✓] Processed 71 events
[✓] Generated 1 alerts

[!] Some events didn't generate alerts:
1. Attack features didn't meet model thresholds
2. PCAP packets didn't form complete flows
3. Model confidence < 85%
```

**When to use:**
- Troubleshoot why PCAP isn't generating alerts
- Understand model decision-making
- Debug feature extraction issues

---

### 📤 upload_pcap.py - **Raw PCAP Upload**

**Purpose:** Upload custom PCAP files for analysis.

**What it does:**
1. Accepts PCAP filename as argument
2. Uploads to backend via HTTP POST
3. Backend processes and generates alerts

**Usage:**
```bash
python upload_pcap.py path/to/your.pcap
```

**When to use:**
- Test with real network captures (from Wireshark, tcpdump)
- Analyze historical attack PCAPs
- Validate against known malicious traffic

---

### 🧪 Other Test Scripts

**test_extractor.py**
- Unit test for flow extraction logic
- Validates 59 CIC-IDS2017 feature computation

**test_advanced.py**
- Advanced edge cases (encrypted traffic, fragmented packets)

**test_gating_integration.py**
- Tests confidence thresholding and heuristic gates

**use_real_pcap.py**
- Processes PCAP without backend (standalone mode)

---

## Test Comparison Matrix

| Script | Speed | Realism | Coverage | Use Case |
|:-------|:------|:--------|:---------|:---------|
| **simple_test.py** | ⚡ Fast (5s) | 🟡 Synthetic | 🟢 Full pipeline | Quick validation |
| **start_simulator.py** | ⚡ Continuous | ❌ Fake | 🟡 Partial (no extraction) | Demos |
| **send_test_alert.py** | ⚡ Instant | ❌ Fake | 🔴 UI only | WebSocket debug |
| **test_real_pipeline.py** | 🐌 Slow (30s) | 🟡 Synthetic | 🟢 Full pipeline | Comprehensive |
| **debug_pcap.py** | 🟡 Medium | 🟡 Depends | 🟢 Full pipeline | Troubleshooting |
| **upload_pcap.py** | 🟡 Depends | ✅ Real | 🟢 Full pipeline | Real traffic |

---

## Troubleshooting

### "Backend health check failed"
**Solution:** Ensure backend is running (`python run.py` in root directory)

### "PCAP uploaded but no alerts"
**Possible causes:**
1. Traffic is benign (correct behavior)
2. Attack features too subtle (increase intensity)
3. Confidence threshold too high (lower to 75% in `netsentinel/config.py`)
4. Flows incomplete (ensure TCP flows have FIN/RST flags)

**Debug:** Run `python debug_pcap.py` to see detailed processing

### "Dashboard shows 'Mock' instead of 'Live'"
**Solution:** 
1. Check WebSocket URL in `frontend/src/data/useThreatFeed.ts`
2. Should be `"ws://localhost:8000/ws"` not `""`
3. Restart frontend after changing

### "Graphs not updating"
**Solution:**
1. Check browser console for errors (F12)
2. Verify WebSocket connected (Network tab → WS)
3. Ensure alerts have `source_ip` and `dest_ip` fields

---

## Creating Custom Tests

### Example: Test Your Own PCAP

```python
import requests

# Upload your PCAP
with open("your_capture.pcap", "rb") as f:
    response = requests.post(
        "http://localhost:8000/api/pcap/upload",
        files={"file": f}
    )

print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")
```

### Example: Send Custom Alert

```python
import websocket
import json

ws = websocket.create_connection("ws://localhost:8000/ws")

alert = {
    "id": "custom-001",
    "threat_class": "custom_attack",
    "severity": "high",
    "confidence": 0.95,
    "source_ip": "1.2.3.4",
    "dest_ip": "192.168.1.100",
    "timestamp": 1735398123456,
    "mitre_tactic": "Execution",
    "mitre_technique": "T1059"
}

ws.send(json.dumps({"type": "alert", "data": alert}))
ws.close()
```

---

## Test Data Location

- **Generated PCAPs**: `tests/` directory (e.g., `test_attacks.pcap`)
- **Uploaded PCAPs**: `../uploads/` directory (auto-created by backend)
- **Logs**: Backend terminal output (no log files by default)

---

## Performance Benchmarks

**simple_test.py:**
- PCAP creation: ~0.5s
- Upload: ~0.1s
- Processing: ~2s
- Total: **~3 seconds**

**start_simulator.py:**
- Alert rate: ~10 alerts/sec
- CPU usage: ~5% (4-core system)
- Memory: ~50MB additional

**test_real_pipeline.py:**
- PCAP creation: ~2s
- Upload: ~0.2s
- Processing: ~10s
- Analysis: ~1s
- Total: **~15 seconds**

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: NetSentinel Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Start backend
        run: python run.py &
        
      - name: Wait for backend
        run: sleep 5
      
      - name: Run tests
        run: python tests/simple_test.py
```

---

## Contributing

When adding new tests:
1. Follow naming convention: `test_*.py` or `*_test.py`
2. Include docstring explaining purpose
3. Update this README with usage instructions
4. Ensure tests clean up after themselves (delete temp files)

---

## Support

For issues with tests:
1. Check backend logs (terminal running `python run.py`)
2. Check frontend console (F12 in browser)
3. Run `debug_pcap.py` for detailed analysis
4. Refer to `docs/COMPREHENSIVE_SYSTEM_REPORT.md` for architecture details
