# NetSentinel Dashboard — Quick Start Guide

## ✅ Phase 1 Integration Complete

The following changes have been applied:

1. **Frontend moved** to `netsentinel/frontend/`
2. **Live WebSocket enabled** in `src/data/useThreatFeed.ts` (line 24)
3. **Backend alert parser added** (`parseBackendAlert` function)
4. **Alert interface extended** with `sourceCoords` and `destCoords` for 3D graph

---

## 🚀 Local Testing (5 Minutes)

### Prerequisites

- **Python 3.11+** with backend dependencies installed
- **Node.js 18+** and npm
- **Windows:** Npcap installed (for live capture)

### Step 1: Start Backend

Open Terminal 1:

```bash
cd netsentinel
python run.py
```

Expected output:
```
  [~] Loading models...
  [OK] DDoS XGBoost loaded
  [OK] DGA CNN-BiLSTM loaded
  [OK] C2 BiLSTM+FFT loaded
  [OK] ETT Transformer loaded
  [~] Starting FastAPI server on http://0.0.0.0:8000
```

### Step 2: Install Frontend Dependencies

Open Terminal 2 (first time only):

```bash
cd netsentinel/frontend
npm install
```

Expected: ~30 seconds to install dependencies.

### Step 3: Start Frontend

In Terminal 2:

```bash
npm run dev
```

Expected output:
```
  VITE v8.0.5  ready in 342 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: http://192.168.1.x:5173/
```

### Step 4: Open Dashboard

Open browser: **http://localhost:5173**

Expected:
- ✅ Status: "● Connecting" → "● Monitoring" within 2 seconds
- ✅ Source indicator: "Mock" → "Live" (top-right corner)
- ⚠️ Alert feed will be empty (no traffic yet)

### Step 5: Generate Test Alerts

#### Option A: Upload PCAP (if you have one)

Open Terminal 3:

```bash
curl -F "file=@path/to/test.pcap" http://localhost:8000/api/pcap/upload
```

#### Option B: Use Traffic Simulator

Add this to your backend testing:

```python
# In run.py or a test script
from netsentinel.simulator.traffic_gen import TrafficGenerator
import asyncio

gen = TrafficGenerator()
async def test_alerts():
    # Generate DDoS attack
    flows = await gen.generate_ddos(count=100)
    # Process through pipeline...
    
asyncio.run(test_alerts())
```

#### Option C: Manual WebSocket Test

```bash
# Send a test alert directly (requires wscat: npm install -g wscat)
wscat -c ws://localhost:8000/ws

# Paste this JSON:
{
  "id": "test-001",
  "timestamp": "2026-08-28T12:34:56Z",
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.0.1",
  "threat_class": "DDoS",
  "threat_subtype": "SYN Flood",
  "confidence": 0.9937,
  "severity": "CRITICAL",
  "model_name": "DDoS XGBoost",
  "evidence": {
    "pps": 52450,
    "avg_pkt_size": 64,
    "syn_ack_ratio": 0.95
  },
  "mitre": {
    "tactic": "Impact",
    "technique": "T1498",
    "name": "Network Denial of Service"
  },
  "geo": {
    "src_country": "RU",
    "src_city": "Moscow",
    "src_lat": 55.75,
    "src_lon": 37.62,
    "dst_country": "IN",
    "dst_city": "New Delhi",
    "dst_lat": 28.61,
    "dst_lon": 77.21
  }
}
```

---

## ✅ Validation Checklist

After sending an alert, verify:

- [ ] **Critical Alert Panel** shows the threat (top-center, large)
- [ ] **Alert Feed** displays new row with severity dot + IP + confidence
- [ ] **3D Graph** renders nodes (may need to zoom/pan with mouse)
- [ ] **Charts** update (packet rate spike visible)
- [ ] **Model Cards** show active indicator (green pulsing dot on corresponding model)
- [ ] **MITRE Heatmap** cell intensity increases for the tactic

---

## 🔄 Switch Back to Mock Mode

If backend is not ready or you want to demo without it:

**Edit:** `frontend/src/data/useThreatFeed.ts` line 24:

```typescript
const WS_URL = "";  // Empty string = mock mode
```

Refresh browser → Dashboard plays 60-second demo loop.

---

## 🐛 Troubleshooting

### Problem: "WebSocket connection failed"

**Check:**
1. Backend running? (`python run.py` in Terminal 1)
2. Backend accessible? Open http://localhost:8000 in browser (should see FastAPI docs)
3. CORS issue? Check backend console for errors

**Fix:** Backend auto-falls back to mock mode after 4 seconds if WebSocket fails.

### Problem: "Status stuck on Connecting"

**Check browser console (F12 → Console tab):**
- Red error? Backend not running
- Yellow warning? Schema mismatch (check parseBackendAlert logs)

**Temporary fix:** Set `WS_URL = ""` to use mock mode.

### Problem: "Alerts appear but 3D graph is empty"

**Cause:** Backend alerts missing `geo` field.

**Fix:** Ensure backend's `alert_manager.py` includes geo coordinates:

```python
alert["geo"] = {
    "src_lat": 55.75,
    "src_lon": 37.62,
    "dst_lat": 28.61,
    "dst_lon": 77.21
}
```

**Temporary workaround:** Graph will show "No active threats" — alerts still display in feed.

### Problem: "Charts not updating"

**Check:** Browser console for errors in `TrafficCharts.tsx`.

**Cause:** Recharts may fail if data format is wrong.

**Fix:** Packet rate samples are generated automatically every 900ms — if charts are frozen, reload page.

### Problem: Three.js lag / graph stutters

**Fix:** Click **"2D View"** toggle in graph panel (top-right) → switches to SVG fallback.

---

## 📊 Demo Mode (No Backend Needed)

For presentations/screenshots:

1. Set `WS_URL = ""`
2. Refresh browser
3. Dashboard plays 60-second demo loop:
   - 0-5s: Normal traffic
   - 12s: DDoS attack (99.7% confidence)
   - 20s: C2 beacon (58.3s interval)
   - 30s: DGA domain (`xkqw8f3m.xyz`)
   - 45s: Port scan
   - 60s: Loop restarts

All panels populate with realistic data — no backend required.

---

## 🔗 API Endpoints (Backend)

If you want to test integration manually:

| Endpoint | Method | Purpose |
|:---|:---:|:---|
| `http://localhost:8000/` | GET | API docs (Swagger UI) |
| `ws://localhost:8000/ws` | WebSocket | Live alert stream |
| `http://localhost:8000/api/alerts` | GET | Recent alerts (REST) |
| `http://localhost:8000/api/pcap/upload` | POST | Upload PCAP file |
| `http://localhost:8000/api/stats` | GET | Pipeline statistics |

---

## 📝 Next Steps

Once basic integration works:

1. **Test with real PCAPs** (CIC-DDoS2019, CTU-13 samples)
2. **Add more evidence field mappings** in `parseBackendAlert()` (e.g., port scan targets)
3. **Test C2 beacon alerts** (verify `beaconInterval` displays correctly)
4. **Test DGA alerts** (verify domain name + entropy appear in indicators)
5. **Stress test** (100+ alerts, verify feed caps at 50, no lag)

---

## 📞 Support

If integration fails:

1. Check `FRONTEND_INTEGRATION_PLAN.md` Section 8 (Known Gaps)
2. Check browser console (F12) for errors
3. Check backend terminal for Python exceptions
4. Verify schema compatibility: compare backend alert JSON vs `parseBackendAlert()` expectations

The dashboard is designed to **gracefully degrade** — if live mode fails, it auto-switches to mock mode so you always have a working demo.
