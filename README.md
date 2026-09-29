# NetSentinel — AI-Powered Network Threat Detection System

**Team Resurreccion | SIH 2026 — Problem Statement SIH25126**

> *"See Everything. Touch Nothing. Trust the Chain."*

NetSentinel is an AI-powered **Network Detection & Response (NDR)** system built for **Smart India Hackathon 2026**. It tackles the challenge of detecting sophisticated cyber threats — DDoS, C2 beaconing, DGA domains, encrypted malware, port scans, and data exfiltration — in real time, using **only packet metadata and traffic volume**. No payloads are ever read or decrypted.

The system runs **six ONNX-deployed ML models** (XGBoost, BiLSTM, CNN, Transformer, VAE) as a FastAPI backend with WebSocket-powered dashboards, a two-tier **Inspector–Sentry** architecture for cost-efficient escalation (13.7× model compression, 7.1× lift over random routing), and full **MITRE ATT&CK mapping** for every alert. Models auto-download from HuggingFace and run on CPU — no GPU needed.



## ⚡ Quick Start — Download and Run

> **Prerequisites:** Python 3.10+ and Node.js 18+ installed. Internet for first run (models auto-download from HuggingFace).
>
> **Downloaded the ZIP instead of cloning?** Extract it and use `NetSentinel-TeamResurreccion-main` wherever the commands below say `NetSentinel-TeamResurreccion`. Everything else is the same (the model files inside the ZIP are Git LFS stubs, so the backends download the real models from HuggingFace on first run).
>
> **Want to monitor your real network in real time?** Do step 1, then follow [📡 Real-Time Detection on a Live Network](#-real-time-detection-on-a-live-network).

### 1️⃣ Backend + AI Pipeline (detects 6 threat families)

```bash
git clone https://github.com/Daryl-69/NetSentinel-TeamResurreccion.git
cd NetSentinel-TeamResurreccion/netsentinel-main

# Create virtual environment & install
python -m venv .venv          # Linux/Mac: python3 -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
# source .venv/bin/activate

pip install -r requirements.txt

# Start the server (models auto-download on first run)
python run.py

# ...or capture your real network traffic live (needs admin/root — see the live section below)
# sudo .venv/bin/python run.py --live        (Linux/Mac)
# python run.py --live                       (Windows, terminal "Run as Administrator")
```

✅ Server starts at **http://localhost:8000** — API docs at **http://localhost:8000/docs**

```bash
# Test it — trigger a DDoS attack simulation:
curl -X POST http://localhost:8000/api/simulate/mixed

# See the alerts:
curl http://localhost:8000/api/alerts
```

### 2️⃣ React Dashboard (real-time 3D threat visualization)

```bash
# In a NEW terminal:
cd NetSentinel-TeamResurreccion/netsentinel-main/frontend
npm install
npm run dev
```

✅ Dashboard opens at **http://localhost:5173** — connects to backend via WebSocket, shows live 3D threat graph, alert feed, MITRE heatmap, model confidence charts

### 3️⃣ Extended System + Inspector–Sentry Dashboard

```bash
# In a NEW terminal:
cd NetSentinel-TeamResurreccion/wearecharliekirk-main

python -m venv .venv          # Linux/Mac: python3 -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
# source .venv/bin/activate

pip install -r requirements.txt
python run.py                 # add --live (with sudo / as Administrator) to capture real traffic

# In ANOTHER terminal (activate the same .venv) — push synthetic threat traffic into the engine:
cd NetSentinel-TeamResurreccion/wearecharliekirk-main
python traffic_feed.py
```

✅ Open **http://localhost:8000/sentinel/** — Inspector–Sentry live ops dashboard  
✅ Open **http://localhost:8000/console/** — Operator console  
✅ Open **http://localhost:8000/docs** — Full API documentation

> **The Inspector–Sentry cascade (left half of `/sentinel/`) needs PyTorch**, which `requirements.txt` does not install. Without it the panel shows *"PyTorch is not available"*. Install it once into `tier2/.venv`, which the backend finds automatically (or point `NETSENTINEL_TIER2_PYTHON` at any Python that has torch):
> ```bash
> cd NetSentinel-TeamResurreccion/wearecharliekirk-main/tier2
> python -m venv .venv
> .venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu     # Windows: .venv\Scripts\pip ...
> .venv/bin/pip install -r requirements.txt
> ```
> Then restart `python run.py` and reload `/sentinel/`. Without live capture the panel runs a **synthetic demo organisation** (badge: SYNTHETIC DEMO). The Inspector trains on its own (about 10 s), the Sentry is distilled from it (205,546 → 14,992 parameters), and it then scores 60 hosts every hour. Running `python traffic_feed.py` starts a kill chain on one host (`dev-011`) in its "host chain" segment, and that host then gets escalated and flagged (or trigger it directly with `curl -X POST http://localhost:8000/api/cascade/attack`).
>
> **With `--live`, the same panel runs on your real devices** (badge: REAL TRAFFIC). It's commissioned on the team's baseline capture, then keeps learning from your own traffic. See [🧠 Inspector–Sentry on your real network](#-inspectorsentry-on-your-real-network).
>
> ⚠️ With the integrity layer enabled (the default), the extended backend **makes git commits** (`integrity: checkpoint #N`, updating `integrity/latest_sth.json`) in this checkout while it runs. Don't run it on a branch you plan to push as-is.

### 4️⃣ V2 Research Harness (Inspector–Sentry experiments)

```bash
cd NetSentinel-TeamResurreccion/netsentinel-main/v2

# Install PyTorch CPU (avoids pulling the 2.5GB CUDA build)
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt

# Run the full experiment (~2 min/seed, CPU only)
python run_experiment.py --seeds 3 --hosts 300 --days 24

# Distribution-shift stress test
python shift_test.py --seeds 3 --hosts 300 --days 24

# Generate result charts
python make_charts.py results.json
```

✅ Produces router comparison, escalation budget curves, and distribution-shift analysis

> **Note:** Steps 1 & 2 are the core demo (backend + dashboard). Step 3 is the extended version. Step 4 is the research harness. Each step is independent — you can run any combination.

---

## 📡 Real-Time Detection on a Live Network

Both backends can sniff live traffic from your network card and run the models on it in real time. The capture is **receive-only**: nothing is transmitted and no payload is decrypted.

### Requirements

| | |
|---|---|
| **Admin / root** | Raw packet capture needs it. Linux/macOS: `sudo`. Windows: open the terminal with **Run as Administrator**. |
| **Windows only: [Npcap](https://npcap.com/)** | Install it and tick *"Install Npcap in WinPcap API-compatible Mode"*. |
| **Linux (optional): `tcpdump`** | `sudo apt install tcpdump` lets the kernel filter packets (lower CPU). Without it NetSentinel filters in Python, which also works. |
| **Models** | Run `python run.py` once normally first (step 1) so the models are downloaded. Under `sudo`, the models you already downloaded are reused. |

### 1. See which interfaces you can capture on

```bash
cd NetSentinel-TeamResurreccion/netsentinel-main
python run.py --list-ifaces        # (inside the activated .venv)
```
```
   lo                       127.0.0.1
 * eth0                     192.168.1.23
 * = default (used when --iface is omitted)
```
You usually don't need this. The interface with your default route (the one you use for the internet) is picked automatically. Typical names: `eth0` / `wlan0` / `enp3s0` (Linux), `en0` (macOS Wi-Fi), `Wi-Fi` / `Ethernet` (Windows).

### 2. Start the backend with live capture

**Linux / macOS**
```bash
cd NetSentinel-TeamResurreccion/netsentinel-main
sudo .venv/bin/python run.py --live                  # default interface
sudo .venv/bin/python run.py --live --iface wlan0    # or name one
```
> Use the venv's Python with `sudo`. Plain `sudo python` runs the system Python, which doesn't have the dependencies.

**Windows** (PowerShell or Terminal opened **as Administrator**)
```powershell
cd NetSentinel-TeamResurreccion\netsentinel-main
.venv\Scripts\activate
python run.py --live
python run.py --live --iface "Wi-Fi"                 # or name one
```

You should see `[>] Live capture running on 'eth0'`. If capture can't start, the server still runs and prints the reason: wrong interface name (with the list of valid ones), not running as admin/root, or Npcap missing.

### 3. Watch it

- **Dashboard:** in a second terminal, `cd netsentinel-main/frontend && npm install && npm run dev`, then open **http://localhost:5173**. The header shows **LIVE** and alerts appear as they happen.
- **Terminal:**
  ```bash
  curl http://localhost:8000/api/extractor/stats   # packet / flow / DNS counters climbing
  curl http://localhost:8000/api/alerts            # alerts raised from your traffic
  ```
  > Windows PowerShell: type `curl.exe`, not `curl` (there `curl` is an alias for `Invoke-WebRequest`).

### 4. Give it something to detect (harmless)

```bash
nslookup xkqw8f3mzpq7v2hjrtz.com       # or: ping xkqw8f3mzpq7v2hjrtz.com
```
A random-looking domain lookup raises a **DGA** alert within a second or so, even though the domain doesn't exist. Normal browsing should raise no alerts. (If your browser or OS uses DNS-over-HTTPS, its lookups are encrypted and invisible to a metadata sensor. `nslookup` always uses plain DNS.)

### Start / stop capture without restarting

With the server already running as admin/root:
```bash
curl http://localhost:8000/api/capture/interfaces                           # list + default
curl -X POST "http://localhost:8000/api/capture/start?interface=eth0"       # omit ?interface= for the default
curl -X POST http://localhost:8000/api/capture/stop
```
You can also set the default interface with the `NETSENTINEL_IFACE` environment variable.

### Extended system (`wearecharliekirk-main`)

Same flags, same requirements:
```bash
cd NetSentinel-TeamResurreccion/wearecharliekirk-main
sudo .venv/bin/python run.py --live         # Windows (as Administrator): python run.py --live
```
Then open **http://localhost:8000/sentinel/** or **http://localhost:8000/console/**. The extended build also analyses IPv6 and uses rule-based volumetric, DNS-behaviour and beacon detectors alongside the models. On `/sentinel/`, live-capture detections appear in the *Live Detections* panel, and the Inspector–Sentry cascade panel switches to your real devices (next section).

### What "real time" means here

| Traffic | Reaches the detectors |
|---|---|
| DNS queries (DGA, DNS tunnel/exfil) | immediately |
| TCP connections (DDoS, port scan) | when the connection closes (FIN/RST) |
| UDP and long-lived connections | after 120 s idle or 300 s total (`FLOW_IDLE_TIMEOUT` / `FLOW_ACTIVE_TIMEOUT` in `netsentinel/config.py`) |
| C2 beaconing | once 100 flows between the same two hosts have been seen |

**Scope:** on a normal PC you see your own machine's traffic plus broadcasts. To watch a whole network, run NetSentinel on a machine connected to a switch mirror/SPAN port or a network tap. The interface is put in promiscuous mode.

### Known limits on real traffic

- `netsentinel-main` analyses **IPv4 only**. Use the extended build for IPv6.
- The DDoS XGBoost was trained on CICFlowMeter features and scores ordinary two-way traffic from the live extractor as DDoS (see `netsentinel-main/LIVE_RESULTS.md`). In `netsentinel-main`, live DDoS alerts therefore also require a flood shape: high rate and one-sided, with little or no reply traffic. The extended build uses its rate/source-entropy DDoS detector on live traffic instead.
- The exfiltration VAE (ROC-AUC 0.78) still flags some long telemetry/CDN hostnames, such as `*.data.microsoft.com`.
- The encrypted-traffic model classifies *applications* (including "VPN-*"). That is recorded as telemetry, not raised as an alert (`netsentinel-main`: set `NETSENTINEL_ETT_ALERTS=1` to alert on it again; extended: `ETT_ALERT_ON_VPN` in `config.py`).

---

## 🧠 Inspector–Sentry on your real network

When live capture runs (`wearecharliekirk-main`, `run.py --live`) and PyTorch is installed in `tier2/.venv` (step 3️⃣), the Inspector–Sentry cascade watches **your real devices**:

1. **Commissioned on the baseline:** the team's 20-day capture, imported once into `tier2/data/baseline_corpus.sqlite`.
2. **Watches live traffic:** every connection the sensor sees goes into a per-device, per-hour window (9 service categories × 10 statistics). Every 30 s the Sentry scores each device's current hour, the top 5 % (at least one device) go to the Inspector, and a device is **flagged** when the Inspector's reconstruction error passes its commissioned 99th-percentile threshold.
3. **Keeps your traffic:** each finished hour (after a 7-minute grace for late connections) is added to `tier2/state/live_corpus.sqlite`.
4. **Trains itself:** every 24 h it re-commissions on baseline + the last 60 days of your live corpus and hot-swaps the new models. **Hours the Inspector flagged are kept out of training**, so an intrusion in progress isn't learned as normal. The first retrain that uses your data happens after your first complete day.

### One-time: import the 20-day capture as the baseline

From `wearecharliekirk-main` with its `.venv` active. `--tz` is the UTC offset **where the capture was recorded**, so hour-of-day means local working hours:

```bash
# raw capture files (dumpcap .pcapng/.pcap, one folder or many files)
python -m netsentinel.inspector import D:\capture --baseline --tz +05:30

# ...or the Zeek logs zeekify.sh produced (one folder per hourly pcap)
python -m netsentinel.inspector import D:\capture-zeek --baseline --tz +05:30

python -m netsentinel.inspector status            # corpus size, days covered, current model
python -m netsentinel.inspector train --publish   # train on it and write tier2/data/models/ (ships with the repo)
cd tier2 && .venv\Scripts\python.exe eval_real_baseline.py   # optional: held-out false alarms + planted-chain detection
```

The corpus holds only hourly per-device statistics: no payloads, no domain names, no packet timestamps. Device addresses are replaced with `dev-01`, `dev-02`, … So it's small enough to **commit, and every install then starts from your baseline**:
```bash
git add wearecharliekirk-main/tier2/data/
git commit -m "Add 20-day baseline corpus and trained Inspector"
```
A fresh install loads the shipped model (`tier2/data/models/inspector_baseline.pt`) until it has retrained on its own traffic.

Devices are identified by the **private** (RFC1918 / IPv6 ULA) addresses in the capture. A laptop's *global* IPv6 address is detected automatically from pcaps. For Zeek logs, pass it with `--local-ip <address>` (repeatable). Importing without `--baseline` adds the capture to the *live* corpus instead, e.g. to seed a new site with its own past traffic.

### Run it

```bash
cd wearecharliekirk-main
sudo .venv/bin/python run.py --live        # Windows (Administrator): python run.py --live
```
You should see `[>] Tier 2 Inspector-Sentry watching real traffic on 'eth0'`. Open **http://localhost:8000/sentinel/**: the badge reads **REAL TRAFFIC · eth0**, each tile is one of your devices (`you-…` is this machine; hover for its IP), and flagged devices raise a banner with the categories they reached that hour.

```bash
curl http://localhost:8000/api/inspector/state            # devices, verdicts, corpus sizes, model
curl -X POST http://localhost:8000/api/inspector/retrain  # re-commission now instead of waiting 24 h
```
Set `NETSENTINEL_INSPECTOR=0` to keep Tier 2 off during live capture.

### Honest limits

- **Granularity is one device-hour.** The current hour is re-scored every 30 s, but the Inspector judges the shape of a device's hour, not single packets. Tier 1's detectors stay the per-flow layer.
- **A new network starts from someone else's normal.** Until the first retrain on your own complete day, your devices are judged against the baseline network, so expect extra flags on day one. The threshold is re-calibrated at every retrain.
- **Device = IP address.** A device whose address changes (DHCP) starts over as a new device.
- **Flag exclusion only protects flagged hours.** A slow drift that never crosses the threshold can still be learned as normal. That's the usual limit of self-training anomaly detectors.
- **Only tested on synthetic data so far:** this path was tested on a synthetic 20-day Zeek fixture, real pcaps and live traffic in a test container, not yet on the team's own 20-day capture.

---

## 🎯 What It Detects

| Threat Family | Model Architecture | MITRE ATT&CK |
|---|---|---|
| **DDoS Floods** | XGBoost (binary + multi-class) | T1498 — Network DoS |
| **C2 Beaconing** | BiLSTM + FFT periodicity analysis | T1071 — App Layer Protocol |
| **DGA / DNS Tunneling** | CNN-BiLSTM character-level | T1568 — Dynamic Resolution |
| **Encrypted Malware** | Transformer on TLS metadata | T1573 — Encrypted Channel |
| **Port Scanning** | XGBoost on flow features | T1046 — Network Service Scanning |
| **Data Exfiltration** | Variational Autoencoder (anomaly) | T1048 — Exfil Over Alt Protocol |

All models are in ONNX format and run on **CPU only** — no GPU required.

---

## 📁 Repository Structure

This repo contains **two main codebases** at different evolution stages, plus supporting materials:

```
NetSentinel-TeamResurreccion/
│
├── netsentinel-main/          # V1 core system (backend + frontend + v2 research)
│   ├── netsentinel/           # Python backend (FastAPI + 6 ONNX models)
│   │   ├── api/               # REST routes + WebSocket hub
│   │   ├── extractor/         # PCAP → flow features (scapy-based)
│   │   ├── models/            # 6 threat detectors (ONNX inference)
│   │   ├── pipeline/          # Flow analyzer + alert manager
│   │   └── simulator/         # Synthetic traffic generator
│   ├── frontend/              # React + Vite + Three.js dashboard
│   │   └── src/
│   │       ├── components/    # 15 UI components (3D threat graph, heatmaps, etc.)
│   │       ├── data/          # WebSocket hooks + mock data
│   │       └── types/         # TypeScript alert types
│   ├── v2/                    # V2 research harness (Inspector–Sentry architecture)
│   │   ├── netsentinel_v2/    # Tier 2 models (GraphSAGE Inspector, Sentry router)
│   │   ├── ppt/               # Presentation slides (.pptx)
│   │   └── ...                # Experiments, benchmarks, charts, configs
│   ├── tests/                 # 19 test files + fixtures
│   ├── scripts/               # Utility scripts (covariate shift, diagnostics)
│   ├── docs_deep/             # 17 architecture & design documents
│   ├── inspector centry/      # Inspector Sentry standalone dashboard (App.tsx)
│   ├── graphify-out/          # Dependency graph visualization
│   ├── run.py                 # Backend entry point
│   ├── requirements.txt       # Python dependencies
│   └── start_dashboard.cmd    # Windows quick-start script
│
├── wearecharliekirk-main/     # Extended version with PS 26145 compliance
│   ├── netsentinel/           # Enhanced backend (all V1 models + new modules)
│   │   ├── api/               # Extended routes (alerts schema, metrics, PS 26145)
│   │   ├── extractor/         # + fastpath, QUIC initial, TLS parse
│   │   ├── models/            # + port scan aggregation detector
│   │   ├── pipeline/          # + alert_schema, metrics, ps26145 compliance
│   │   ├── detectors/         # Rule-based detectors (beacon, ddos, dns, exfil, tls)
│   │   ├── integrity/         # Proof-carrying alerts (Ed25519 signing, DSSE)
│   │   ├── intel/             # TLS fingerprint blocklist (JA3)
│   │   ├── cascade_live.py    # Live Inspector–Sentry cascade
│   │   ├── tier2_bridge.py    # Tier 2 bridge module
│   │   └── bench.py           # Throughput benchmarking
│   ├── sentinel/              # Inspector–Sentry live dashboard (HTML/CSS/JS)
│   ├── console/               # Operator console (HTML/CSS/JS)
│   ├── tier2/                 # Tier 2 cascade streaming engine
│   ├── docs/                  # PS26145 compliance docs + performance figures
│   ├── model_comparisons/     # 20+ evaluation scripts & results
│   ├── tests/                 # Extended tests (PS26145, TLS fingerprints, tier2)
│   ├── scripts/               # Benchmarking + figure generation
│   ├── run.py                 # Backend entry point
│   ├── traffic_feed.py        # Threat traffic generator for demos
│   ├── beacon_truth.jsonl     # C2 beacon ground truth data
│   └── requirements.txt       # Python dependencies (+ PyNaCl, cryptography)
│
├── PCAPS/                     # Sample packet captures + reference PDFs
│   ├── *.pcap                 # 5 malware sandbox captures
│   ├── SE_Netflix_Introduction.pdf
│   └── STEADYSTRIDE_SIH25126 (1).pdf
│
└── README.md                  # This file
```

### What's What

| Folder | Purpose | Status |
|---|---|---|
| `netsentinel-main/netsentinel/` | Core V1 backend — 6 ONNX models, FastAPI, WebSocket | ✅ **Runnable** |
| `netsentinel-main/frontend/` | React dashboard with 3D threat graph, live alerts | ✅ **Runnable** |
| `netsentinel-main/v2/` | V2 research: Inspector–Sentry, experiments, Kaggle notebook | ✅ Runnable (standalone) |
| `wearecharliekirk-main/` | Extended V1 + PS 26145 compliance + sentinel dashboard | ✅ **Runnable** |
| `wearecharliekirk-main/sentinel/` | Inspector–Sentry live ops dashboard | ✅ Served by backend |
| `PCAPS/` | Sample captures for testing | Reference data |

---

## 🚀 Can You Download This and Run It?

**Honest answer: Yes — with caveats.**

### ✅ What works out of the box

| Component | How to run | What you get |
|---|---|---|
| **V1 Backend** (`netsentinel-main/`) | `python run.py` | FastAPI server on port 8000 with REST API + WebSocket |
| **React Dashboard** (`netsentinel-main/frontend/`) | `npm install && npm run dev` | Live threat dashboard on port 5173 |
| **Extended Backend** (`wearecharliekirk-main/`) | `python run.py` | Enhanced server with sentinel dashboard at `/sentinel/` |
| **Traffic Simulator** | POST to `/api/simulate/mixed` | Generates synthetic attacks through the pipeline |
| **PCAP Upload** | POST to `/api/pcap/upload` | Analyze real captures offline |
| **Live Capture** | `sudo .venv/bin/python run.py --live` | Real-time detection on your network card ([details](#-real-time-detection-on-a-live-network)) |
| **V2 Experiments** (`netsentinel-main/v2/`) | `python run_experiment.py` | Full Inspector–Sentry research harness |

### ⚠️ What requires setup

| Requirement | Why | How to fix |
|---|---|---|
| **ONNX Models (~50MB total)** | Models auto-download from HuggingFace on first run | Needs internet. Or download from [Unded-17/netsentinel-models](https://huggingface.co/Unded-17/netsentinel-models) manually |
| **Npcap** (Windows) | Required by scapy for live packet capture | Install [Npcap](https://npcap.com/) — only needed for live capture, not PCAP upload |
| **Admin / root** | Live capture needs raw socket access | `sudo .venv/bin/python run.py --live` (Linux/Mac) or an Administrator terminal (Windows). Not needed for simulation or PCAP upload |
| **Node.js 18+** | For the React frontend | `winget install OpenJS.NodeJS.LTS` |
| **Python 3.10+** | For the backend | `winget install Python.Python.3.12` |

### ❌ What doesn't run without extra work

| Component | Issue |
|---|---|
| **V2 models on real traffic** | Needs Zeek log data or LANL dataset (not included — too large) |
| **PPTX presentations** | View-only, not code |

---

## 🛠️ Quick Start (Full Setup)

### Option A: Just the Backend + Simulator (Easiest)

```bash
# 1. Clone
git clone https://github.com/Daryl-69/NetSentinel-TeamResurreccion.git
cd NetSentinel-TeamResurreccion/netsentinel-main

# 2. Create virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
# source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the backend (models auto-download from HuggingFace)
python run.py
```

The server starts on `http://localhost:8000`. Test it:
```bash
# Health check
curl http://localhost:8000/api/health

# Start attack simulation
curl -X POST http://localhost:8000/api/simulate/mixed

# View alerts
curl http://localhost:8000/api/alerts

# Interactive API docs
# Open http://localhost:8000/docs in browser
```

### Option B: Backend + React Dashboard

```bash
# Terminal 1: Start backend (see Option A above)
cd netsentinel-main
python run.py

# Terminal 2: Start frontend
cd netsentinel-main/frontend
npm install
npm run dev
```

Open `http://localhost:5173` — the dashboard connects to the backend via WebSocket and shows:
- 3D interactive threat graph (Three.js)
- Real-time alert feed with severity bands
- MITRE ATT&CK heatmap
- Per-model confidence charts
- Traffic volume & protocol breakdown
- Attack timeline

Then trigger an attack: `curl -X POST http://localhost:8000/api/simulate/ddos`

### Option C: Extended System with Inspector–Sentry Dashboard

```bash
# Terminal 1: Start the extended backend
cd wearecharliekirk-main
python -m venv .venv
.venv\Scripts\activate          # Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
python run.py

# Terminal 2: Start the threat traffic feed
cd wearecharliekirk-main
python traffic_feed.py
```

Open `http://localhost:8000/sentinel/` for the Inspector–Sentry live ops view (the cascade panel needs PyTorch in `tier2/.venv` — see step 3️⃣ of the Quick Start).
Open `http://localhost:8000/console/` for the operator console.
Open `http://localhost:8000/docs` for the API documentation.

### Option D: V2 Research Harness (Inspector–Sentry Experiments)

```bash
cd netsentinel-main/v2

# Install PyTorch CPU (don't pull the 2.5GB CUDA build)
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt

# Run the router comparison experiment (~2 min/seed on CPU)
python run_experiment.py --seeds 3 --hosts 300 --days 24

# Run the distribution-shift stress test
python shift_test.py --seeds 3 --hosts 300 --days 24

# Generate charts
python make_charts.py results.json
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     INGESTION LAYER                          │
│  Live Capture (scapy) ←→ PCAP Upload ←→ Synthetic Generator │
└──────────────┬──────────────────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────────────────┐
│                   EXTRACTION LAYER                           │
│  Packets → Flows → Sessions → Feature Vectors               │
│  (DNS queries, TLS metadata, flow stats, timing features)    │
│  No payload inspection — metadata and volume only            │
└──────────────┬──────────────────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────────────────┐
│                TIER 1: DETECTION MODELS                      │
│  ┌──────┐ ┌────────┐ ┌─────┐ ┌─────┐ ┌────────┐ ┌───────┐ │
│  │ DDoS │ │C2 Bcn  │ │ DGA │ │ ETT │ │PortScn │ │ Exfil │ │
│  │XGBst │ │BiLSTM  │ │CNN- │ │Trans│ │XGBoost │ │  VAE  │ │
│  │      │ │+FFT    │ │LSTM │ │formr│ │        │ │       │ │
│  └──┬───┘ └───┬────┘ └──┬──┘ └──┬──┘ └───┬────┘ └───┬───┘ │
└─────┼─────────┼─────────┼───────┼────────┼─────────┼───────┘
      └─────────┴─────────┴───────┴────────┴─────────┘
               ▼
┌─────────────────────────────────────────────────────────────┐
│              TIER 2: INSPECTOR–SENTRY (V2)                   │
│  Sentry (14,992 params, CPU) scores every host-hour          │
│  → Top 5% escalated to Inspector (205,546 params)            │
│  → E-GraphSAGE + Transformer Autoencoder                     │
│  → 13.7× compression, 7.1× lift over random routing         │
└──────────────┬──────────────────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────────────────┐
│                   ALERT PIPELINE                             │
│  Severity scoring → MITRE mapping → WebSocket broadcast      │
│  → React Dashboard / Sentinel Dashboard / REST API           │
└─────────────────────────────────────────────────────────────┘
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | System health, model status, pipeline stats |
| `GET` | `/api/alerts?limit=50` | Recent alerts |
| `GET` | `/api/stats` | Pipeline statistics |
| `GET` | `/api/models` | Loaded model details |
| `POST` | `/api/simulate/{type}` | Start simulation (`ddos`, `c2`, `dga`, `mixed`, `stop`) |
| `POST` | `/api/pcap/upload` | Upload .pcap/.pcapng for offline analysis |
| `POST` | `/api/pcap/process` | Process a local PCAP by filepath |
| `GET` | `/api/capture/interfaces` | Interfaces available for live capture + the default |
| `POST` | `/api/capture/start?interface=eth0` | Start live packet capture (omit `interface` for the default-route interface) |
| `POST` | `/api/capture/stop` | Stop live capture |
| `GET` | `/api/inspector/state` | *(extended)* Inspector–Sentry on real traffic: devices, hourly verdicts, corpora, model |
| `POST` | `/api/inspector/retrain` | *(extended)* Re-commission now on baseline + live corpus |
| `POST` | `/api/reset` | Reset stats and alerts |
| `WS` | `/ws` | Real-time alert + stats WebSocket |
| `GET` | `/docs` | Interactive Swagger API documentation |

---

## 🔬 V2 Research: Inspector–Sentry

The `v2/` directory contains a complete research harness for the **Inspector–Sentry** two-tier architecture:

- **Inspector**: E-GraphSAGE encoder + Transformer autoencoder (205,546 params). Learns per-host "normal" traffic profiles and flags anomalies via reconstruction error.
- **Sentry**: Distilled 14,992-parameter router that scores every host-hour on CPU. Only the top 5% are escalated to the Inspector.
- **Result**: At 5% escalation budget, recovers **36% ± 4** of everything the Inspector flags — **7.1× better than random routing**.

Key files:
| File | Purpose |
|---|---|
| `run_experiment.py` | Router comparison (A/B/C) across seeds |
| `shift_test.py` | Distribution-shift stress test (World A → B) |
| `train_real.py` | Train on real LANL dataset |
| `netsentinel_v2/models.py` | Inspector, Sentry, DeferralHead architectures |
| `netsentinel_v2/synth.py` | Host-day traffic generator with multimodal behavior |
| `netsentinel_v2/zeek_loader.py` | Load real Zeek logs into the harness |
| `netsentinel_v2_kaggle.ipynb` | Self-contained Kaggle notebook |

---

## 🔒 PS 26145 Compliance (`wearecharliekirk-main`)

The extended version adds compliance with the **PS 26145** security standard:

- **Read-only ingest** — no payload inspection, metadata only
- **Bounded latency** — sub-second detection pipeline
- **Structured alert schema** — consistent JSON format
- **Proof-carrying alerts** — Ed25519 signed with DSSE envelopes
- **Integrity chain** — tamper-evident alert ledger

See `wearecharliekirk-main/docs/PS26145_COMPLIANCE.md` for full details.

---

## 📊 PCAP Test Files

The `PCAPS/` folder contains 5 real malware sandbox captures for testing:
- CAPE Sandbox captures (C2, malware traffic)
- Zenbox capture
- Dr.Web vxCube capture

Upload any of these via the API:
```bash
curl -X POST -F "file=@PCAPS/091537851fa4eeac43238aadde430bb0e501aca0b46a713106b8b72f65fa0c0a_CAPE Sandbox.pcap" http://localhost:8000/api/pcap/upload
```

---

## 🧪 Testing

```bash
pip install pytest

# V1 unit tests (from netsentinel-main/)
cd netsentinel-main
python -m pytest tests/test_models.py tests/test_extractor.py tests/test_exfiltration.py tests/test_c2_fft_fix.py tests/test_gating_integration.py tests/test_port_scan.py -v

# V2 tests (from netsentinel-main/v2/)
cd netsentinel-main/v2
python -m pytest test_*.py -v

# Extended unit tests (from wearecharliekirk-main/)
cd wearecharliekirk-main
python -m pytest tests/test_ps26145.py tests/test_tls_fingerprints.py tests/test_tier2_bridge.py tests/test_integrity_merkle.py tests/test_extractor.py tests/test_models.py tests/test_port_scan.py tests/test_portscan.py tests/test_exfiltration.py tests/test_c2_fft_fix.py tests/test_gating_integration.py -v
```

> The other files in `tests/` (`test_advanced.py`, `test_live_system.py`, `test_real_pipeline.py`, `simple_test.py`, …) are scripts that talk to a **running** server (`python run.py` first) and some need `pip install requests`. `pytest tests/` on the whole folder stops at those.

---

## 📦 Models

Models are hosted on HuggingFace and **auto-download on first run**:

**Repository**: [Unded-17/netsentinel-models](https://huggingface.co/Unded-17/netsentinel-models)

| Model | Format | Size |
|---|---|---|
| DDoS XGBoost (binary + multi) | `.onnx` + feature names | ~1.5 MB |
| C2 Beacon BiLSTM + FFT | `.onnx` + scaler params | ~2 MB |
| DGA CNN-BiLSTM | `.onnx` | ~1 MB |
| Encrypted Traffic Transformer | `.onnx` + scaler + classes | ~3 MB |
| Port Scan XGBoost | `.onnx` + feature names | ~750 KB |
| Exfiltration VAE | `.onnx` + scaler + meta | ~500 KB |

Manual download (if no internet on target machine):
```bash
pip install huggingface_hub
huggingface-cli download Unded-17/netsentinel-models --local-dir ~/.cache/netsentinel/models
```

---

## ⚙️ Dependencies

### Backend (Python 3.10+)
```
fastapi >= 0.115.0       # Web framework
uvicorn[standard]        # ASGI server
scapy >= 2.5.0           # Packet parsing
onnxruntime >= 1.19.0    # ML inference (CPU)
numpy, pandas            # Data processing
huggingface_hub          # Model auto-download
scikit-learn             # Preprocessing
websockets               # Real-time communication
```

### Frontend (Node.js 18+)
```
react 19, react-dom 19   # UI framework
recharts                 # Charts
three.js                 # 3D threat graph
lucide-react             # Icons
vite 8                   # Build tool
tailwindcss 4            # Styling
typescript 5             # Type safety
```

### V2 Research (additional)
```
torch >= 2.4             # PyTorch (CPU index recommended)
scipy, matplotlib        # Analysis & charts
cryptography >= 42.0     # QUIC decryption
```

---

## 📄 Documentation Index

Detailed documentation is in `netsentinel-main/docs_deep/`:

| Document | What it covers |
|---|---|
| `ARCHITECTURE.md` | Complete system architecture |
| `ARCHITECTURE_V2.md` | V2 Inspector–Sentry design |
| `HOW_THE_REAL_PIPELINE_WORKS.md` | Extraction → detection flow |
| `LIVE_CAPTURE_GUIDE.md` | Setting up live capture |
| `VALIDATION_AND_STRATEGY.md` | Validation approach |
| `V2_HARDENING.md` | V2 hardening decisions |
| `FRONTEND_INTEGRATION_PLAN.md` | Frontend ↔ backend integration |
| `CRITIQUE.md` | Honest limitations |

---

## 📝 License

MIT License — see `netsentinel-main/LICENSE`

---

## 👥 Team Resurreccion

Built for **Smart India Hackathon 2026**

---

*Note: The V2 synthetic data generator is a stand-in, not a substitute for real network data. Claims about detection accuracy are validated on the synthetic generator and the LANL dataset. See `v2/README.md` § "Honesty boundary" for what the numbers do and do not prove.*
