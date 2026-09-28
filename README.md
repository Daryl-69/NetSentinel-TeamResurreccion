# NetSentinel — AI-Powered Network Threat Detection System

**Team Resurreccion | SIH 2026 — Problem Statement SIH25126**

> *"See Everything. Touch Nothing. Trust the Chain."*

NetSentinel is an AI-powered **Network Detection & Response (NDR)** system built for **Smart India Hackathon 2026**. It tackles the challenge of detecting sophisticated cyber threats — DDoS, C2 beaconing, DGA domains, encrypted malware, port scans, and data exfiltration — in real time, using **only packet metadata and traffic volume**. No payloads are ever read or decrypted.

The system runs **six ONNX-deployed ML models** (XGBoost, BiLSTM, CNN, Transformer, VAE) as a FastAPI backend with WebSocket-powered dashboards, a two-tier **Inspector–Sentry** architecture for cost-efficient escalation (13.7× model compression, 7.1× lift over random routing), and full **MITRE ATT&CK mapping** for every alert. Models auto-download from HuggingFace and run on CPU — no GPU needed.



## ⚡ Quick Start — Download and Run

> **Prerequisites:** Python 3.10+ and Node.js 18+ installed. Internet for first run (models auto-download from HuggingFace).

### 1️⃣ Backend + AI Pipeline (detects 6 threat families)

```bash
git clone https://github.com/Daryl-69/NetSentinel-TeamResurreccion.git
cd NetSentinel-TeamResurreccion/netsentinel-main

# Create virtual environment & install
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
# source .venv/bin/activate

pip install -r requirements.txt

# Start the server (models auto-download on first run)
python run.py
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

python -m venv .venv
# Windows:
.venv\Scripts\activate

pip install -r requirements.txt
python run.py

# In ANOTHER terminal — push threat traffic into the engine:
cd NetSentinel-TeamResurreccion/wearecharliekirk-main
python traffic_feed.py
```

✅ Open **http://localhost:8000/sentinel/** — Inspector–Sentry live ops dashboard  
✅ Open **http://localhost:8000/console/** — Operator console  
✅ Open **http://localhost:8000/docs** — Full API documentation

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
| **V2 Experiments** (`netsentinel-main/v2/`) | `python run_experiment.py` | Full Inspector–Sentry research harness |

### ⚠️ What requires setup

| Requirement | Why | How to fix |
|---|---|---|
| **ONNX Models (~50MB total)** | Models auto-download from HuggingFace on first run | Needs internet. Or download from [Unded-17/netsentinel-models](https://huggingface.co/Unded-17/netsentinel-models) manually |
| **Npcap / WinPcap** (Windows) | Required by scapy for live packet capture | Install [Npcap](https://npcap.com/) — only needed for live capture, not PCAP upload |
| **Admin privileges** | Live capture needs raw socket access | Not needed for simulation mode or PCAP upload |
| **Node.js 18+** | For the React frontend | `winget install OpenJS.NodeJS.LTS` |
| **Python 3.10+** | For the backend | `winget install Python.Python.3.12` |

### ❌ What doesn't run without extra work

| Component | Issue |
|---|---|
| **V2 models on real traffic** | Needs Zeek log data or LANL dataset (not included — too large) |
| **Live network capture** | Requires Npcap + admin + correct interface name in `config.py` |
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
.venv\Scripts\activate
pip install -r requirements.txt
python run.py

# Terminal 2: Start the threat traffic feed
cd wearecharliekirk-main
python traffic_feed.py
```

Open `http://localhost:8000/sentinel/` for the Inspector–Sentry live ops view.
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
| `POST` | `/api/capture/start` | Start live packet capture |
| `POST` | `/api/capture/stop` | Stop live capture |
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
# V1 tests (from netsentinel-main/)
cd netsentinel-main
python -m pytest tests/ -v

# V2 tests (from netsentinel-main/v2/)
cd netsentinel-main/v2
python -m pytest test_*.py -v

# Extended tests (from wearecharliekirk-main/)
cd wearecharliekirk-main
python -m pytest tests/ -v
```

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
