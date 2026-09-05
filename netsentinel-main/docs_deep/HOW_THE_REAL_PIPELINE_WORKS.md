# How the REAL NetSentinel Pipeline Works

> **TL;DR:** You're right — the test scripts were just fake alerts. Here's how to use the ACTUAL ML pipeline with real network packets.

---

## 🔴 What You Just Tested (Fake)

```
Test Script → WebSocket → Dashboard
     ↑
  Bypasses the entire ML pipeline!
```

**Problem:** Those test scripts sent pre-made JSON alerts directly to the dashboard, skipping:
- ❌ Packet capture
- ❌ Flow extraction
- ❌ Feature engineering
- ❌ ML model inference
- ❌ All 4 neural networks

**You're right to be confused** — that's not how it should work in production.

---

## ✅ How It SHOULD Work (Real Pipeline)

```
Network Packets
    ↓
PCAP File OR Live Capture (Scapy)
    ↓
PacketProcessor (extractor/pcap_reader.py)
    ├─→ FlowExtractor (59 CIC features)
    ├─→ DNSExtractor (DGA detection)
    └─→ SessionBuilder (100-flow sequences for C2)
    ↓
Event Queue (flow/dns/session events)
    ↓
FlowAnalyzer (pipeline/analyzer.py)
    ├─→ DDoS XGBoost Model (ONNX)
    ├─→ DGA CNN-BiLSTM Model (ONNX)
    ├─→ C2 BiLSTM+FFT Model (ONNX)
    └─→ ETT Transformer Model (ONNX)
    ↓
AlertManager (creates structured alerts)
    ↓
WebSocketHub (broadcasts to dashboard)
    ↓
Dashboard (React frontend)
```

---

## 📦 Three Ways to Feed Real Packets

### Method 1: Upload a PCAP File (RECOMMENDED)

**Step 1:** Get a test PCAP with attacks
```bash
# Download sample attack PCAPs
# CIC-DDoS2019: https://www.unb.ca/cic/datasets/ddos-2019.html
# CTU-13 (C2 beacons): https://www.stratosphereips.org/datasets-ctu13
```

**Step 2:** Upload via API
```bash
curl -F "file=@path/to/attack.pcap" http://localhost:8000/api/pcap/upload
```

**What Happens:**
1. Backend saves PCAP to `uploads/` folder
2. `PacketProcessor` reads packets using Scapy
3. Extracts flows, DNS queries, sessions
4. Computes 59 CIC features per flow
5. Runs through all 4 ML models
6. If threat detected → creates alert
7. Broadcasts alert to dashboard via WebSocket
8. Dashboard updates in real-time

**Expected Dashboard Behavior:**
- Status: "Processing PCAP..."
- Alerts appear as threats are detected
- Charts spike when attacks found
- Model cards activate for corresponding detections

---

### Method 2: Live Network Capture (WINDOWS REQUIRES NPCAP)

**Prerequisites:**
- Windows: Install Npcap (WinPcap compatibility mode enabled)
- Run PowerShell/CMD as Administrator
- Know your network interface name

**Step 1:** Find your interface name
```powershell
# PowerShell
Get-NetAdapter | Select-Object Name, InterfaceDescription

# Common names:
# - "Ethernet" (wired)
# - "Wi-Fi" (wireless)
# - "Local Area Connection"
```

**Step 2:** Start live capture
```bash
# Replace "Ethernet" with your interface name
curl -X POST "http://localhost:8000/api/capture/start?interface=Ethernet"
```

**What Happens:**
1. Backend starts Scapy sniffing on specified interface
2. Every packet captured → processed in real-time
3. Flows assembled (bidirectional TCP/UDP tracking)
4. Features computed on-the-fly
5. ML models infer every flow
6. Alerts broadcast immediately when threats detected

**Expected Dashboard Behavior:**
- Status: "Live Capture (Ethernet)"
- Real-time alerts as threats occur on your network
- Packet rate chart shows actual network traffic
- If you browse YouTube/download files → "Benign" flow events (not alerted)
- If you run attack tools (nmap scan, hping3 flood) → alerts fire

**Stop Capture:**
```bash
curl -X POST http://localhost:8000/api/capture/stop
```

---

### Method 3: Traffic Simulator (FOR DEMO ONLY)

This generates **synthetic** labeled flows (not real packets, but goes through ML pipeline):

```bash
# Start generating mixed attack traffic
curl -X POST http://localhost:8000/api/simulate/mixed
```

**What Happens:**
1. `traffic_gen.py` creates fake flow metadata (not PCAPs)
2. Flows have attack characteristics (high pps, periodic intervals, suspicious domains)
3. Still goes through all 4 ML models
4. Alerts generated based on model predictions

**Use Case:** Demo when you don't have attack PCAPs or can't run live capture

**Stop Simulation:**
```bash
curl -X POST http://localhost:8000/api/simulate/stop
```

---

## 🧪 Testing the REAL Pipeline (Step-by-Step)

### Test 1: Upload a PCAP with Known Attack

**Download a test PCAP** (contains DDoS attack):
```bash
# Option A: Create synthetic PCAP with test script
python test_extractor.py
# This creates test.pcap with simulated SYN flood

# Option B: Download real dataset
# CIC-DDoS2019 has labeled attack PCAPs
```

**Upload it:**
```bash
curl -F "file=@test.pcap" http://localhost:8000/api/pcap/upload
```

**Watch the Backend Console:**
```
[*] Processing PCAP: test.pcap
[*] Extracted 150 flows
[*] Running DDoS detection...
[!] DDoS SYN Flood detected (confidence: 99.3%)
[*] Alert broadcast to 1 WebSocket client
```

**Watch the Dashboard:**
- Critical Alert Panel appears (DDoS threat)
- Alert feed populates
- Charts spike
- DDoS XGBoost card activates

---

### Test 2: Live Capture (If You Have Npcap)

**Start backend** (already running from earlier):
```
Backend: http://localhost:8000 ✓
```

**Start live capture:**
```bash
curl -X POST "http://localhost:8000/api/capture/start?interface=Ethernet"
```

**Generate attack traffic** (on another machine or VM):
```bash
# Option A: Port scan (triggers Discovery alerts)
nmap -sS 192.168.1.x

# Option B: SYN flood (triggers DDoS alerts)
hping3 -S --flood -p 80 192.168.1.x

# Option C: DNS tunneling (triggers DGA alerts)
# Use iodine or dnscat2 tools
```

**Watch Dashboard:**
- Alerts appear as attacks happen
- Real source IPs shown
- Real timestamps

**Stop capture when done:**
```bash
curl -X POST http://localhost:8000/api/capture/stop
```

---

## 🔍 Why the Dashboard "Doesn't Look Different"

You said: *"the entire figma conversation talked about so many frontend changes but I don't see much of a difference"*

**The Problem:** You're comparing to what exactly?

### If Comparing to Mock Mode:

**Mock Mode (60s demo loop):**
- Shows pre-scripted alerts (DDoS at 12s, C2 at 20s, DGA at 30s)
- Fixed confidence scores (99.7%, 93.2%, 91.8%)
- Fake IPs (192.168.1.x)
- Always same pattern

**Live Mode (what you tested):**
- Shows alerts sent via WebSocket
- Real confidence scores from models
- Real IPs from packets/PCAPs
- Dynamic, not scripted

**Visual Difference:**
- Top-right corner: "Mock" → "Live" badge
- Alert IDs: `mock-ddos-12000` → `test-ddos-001` or real UUIDs
- Timestamps: Relative to loop start → Real clock time

### If Comparing to OLD Frontend (Before Figma):

**You didn't have a frontend before!** The Figma conversation built:

1. ✅ **13 React components** (Header, CriticalAlertPanel, AlertFeed, 3D Graph, Charts, Heatmap, Model Cards, etc.)
2. ✅ **Monochrome aesthetic** ported from aethelats (glass cards, 3D cube, animations)
3. ✅ **WebSocket integration** (connects to backend, not just static)
4. ✅ **Schema adapter** (transforms Python backend → TypeScript frontend)
5. ✅ **MITRE ATT&CK heatmap** (14-tactic grid)
6. ✅ **3D threat graph** (WebGL with three.js, lazy-loaded)
7. ✅ **Real-time charts** (Recharts packet rate + severity timeline)
8. ✅ **Model status cards** (shows active models with accuracy rings)

**Before Figma:** You had only Python backend, no dashboard at all.

**After Figma:** Fully functional React dashboard.

---

## 📊 What You're Actually Seeing Now

Open **http://localhost:8443** and you should see:

### Live vs Mock Indicator
**Top-right corner:**
- `🟢 Live` = Connected to backend WebSocket, receiving real alerts
- `⚪ Mock` = WebSocket failed/timeout, showing 60s demo loop

### Current Data Source
**Since we sent test alerts via Python script:**
- Source: `Live` (WebSocket connected)
- Alerts: Test alerts we manually sent
- Not from real packet processing (yet)

---

## 🎯 Action Items for REAL Testing

### Step 1: Create Test PCAP
```bash
# Use the existing test script
python test_extractor.py
# This creates test.pcap with synthetic SYN flood
```

### Step 2: Upload PCAP
```bash
curl -F "file=@test.pcap" http://localhost:8000/api/pcap/upload
```

### Step 3: Watch Backend Logs
```bash
# In the terminal where backend is running, you should see:
# [*] Processing PCAP...
# [*] DDoS detected...
# [*] Alert broadcast
```

### Step 4: Watch Dashboard
**If backend detects a threat:**
- ✅ New alert appears in feed
- ✅ Critical panel updates (if high severity)
- ✅ Charts spike
- ✅ Model card activates

**If backend finds no threats:**
- Nothing appears in dashboard (benign traffic)

---

## 🐛 Common Issues

### Issue 1: "Nothing happens after PCAP upload"

**Diagnosis:**
```bash
# Check backend logs for errors
# Check PCAP is valid
# Check models loaded
curl http://localhost:8000/api/models
```

**Possible Causes:**
- PCAP has no attack traffic (all benign)
- PCAP is malformed
- Models not loaded properly

### Issue 2: "Live capture fails to start"

**Error:** `"Could not find interface 'Ethernet'"`

**Fix:**
```powershell
# Find correct interface name
Get-NetAdapter | Select-Object Name

# Use exact name in curl command
curl -X POST "http://localhost:8000/api/capture/start?interface=Wi-Fi"
```

**Error:** `"Permission denied"`

**Fix:** Run PowerShell as Administrator (Scapy needs elevated privileges)

**Error:** `"Npcap not found"`

**Fix:** Install Npcap from https://npcap.com/ (WinPcap compatibility mode enabled)

### Issue 3: "Dashboard still shows Mock mode"

**Cause:** WebSocket not connecting to backend

**Check:**
```bash
# Verify backend is running
curl http://localhost:8000/api/health

# Check WebSocket endpoint
# (should return Upgrade Required)
curl http://localhost:8000/ws
```

**Fix:** Restart both servers

---

## 📁 Key Files for Real Pipeline

| File | Purpose |
|:---|:---|
| `netsentinel/extractor/pcap_reader.py` | Reads PCAP, assembles flows |
| `netsentinel/extractor/flow_extractor.py` | Computes 59 CIC features |
| `netsentinel/pipeline/analyzer.py` | Routes events to models |
| `netsentinel/models/ddos.py` | DDoS XGBoost inference |
| `netsentinel/models/c2_beacon.py` | C2 BiLSTM+FFT inference |
| `netsentinel/models/dga.py` | DGA CNN-BiLSTM inference |
| `netsentinel/models/encrypted.py` | ETT Transformer inference |
| `netsentinel/api/routes.py` | PCAP upload & live capture endpoints |
| `netsentinel/api/websocket.py` | Broadcasts alerts to dashboard |

---

## 🎯 Summary

**What we tested earlier:** Fake alerts (test scripts) → good for verifying dashboard works

**What you need next:** Real packets → ML pipeline → alerts

**Three methods:**
1. **Upload PCAP** ← EASIEST (curl -F "file=@attack.pcap")
2. **Live capture** ← REQUIRES NPCAP + ADMIN
3. **Simulator** ← DEMO ONLY (synthetic flows)

**The dashboard IS working** — it's receiving alerts via WebSocket. Now you need to feed it REAL alerts from the ML pipeline, not test scripts.

---

## 🚀 Next Step: Upload a Real PCAP

**Try this now:**
```bash
# Create test PCAP
python test_extractor.py

# Upload it
curl -F "file=@test.pcap" http://localhost:8000/api/pcap/upload

# Watch backend terminal and dashboard
```

This will exercise the ENTIRE pipeline:
```
PCAP → Scapy → FlowExtractor → XGBoost → Alert → WebSocket → Dashboard
```

That's the real thing.
