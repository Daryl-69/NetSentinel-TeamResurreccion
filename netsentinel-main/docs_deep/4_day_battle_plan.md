# ⚔️ NetSentinel — 4-Day Battle Plan (Aug 26-30)

## Context
- **Event**: SIH College Internal Round (shortlisting for Grand Finale)
- **Date**: August 30, 2026
- **Team**: 2 people + Claude as force multiplier
- **Starting point**: Plan only, zero code
- **Goal**: Working prototype that gets you shortlisted

---

> [!IMPORTANT]
> **College round ≠ Grand Finale.** You don't need 6 detectors, 10 dashboard panels, and IPFS. You need a **working demo** that proves you understand the problem deeply and have a credible prototype. Evaluators at this stage care about:
> 1. Do you understand the problem? (data diode, unidirectional traffic)
> 2. Does your prototype actually work? (live demo > slides)
> 3. Is the approach technically sound? (AI + blockchain integration)
> 4. Is this team capable of building the full solution at Grand Finale?

---

## 🎯 Scope for College Round (Ruthlessly Trimmed)

### ✅ BUILD THESE (MVP)
| Component | What | Why It's Essential |
|:---|:---|:---|
| **3 AI Detectors** | DDoS (XGBoost), DGA (CNN-Transformer), C2 Beaconing (LSTM+FFT) | 3 working detectors > 6 broken ones |
| **Meta-Classifier** | Simple MLP combining 3 detector outputs | Shows ensemble architecture |
| **Traffic Simulator** | Scapy-based generator for 3 attack types + benign | You NEED attack traffic for live demo |
| **Feature Pipeline** | DNS features + flow features + temporal features | Connects simulator → models |
| **FastAPI Backend** | REST + WebSocket server | Serves data to dashboard |
| **Dashboard (5 panels)** | Threat Stream, Alert Table, Threat Donut, XAI Panel, Blockchain Audit | Enough to impress, not enough to overwhelm |
| **Blockchain** | AlertRegistry.sol on Hardhat local chain + Python client | Ties to "Blockchain & Cybersecurity" theme |
| **XAI** | SHAP for XGBoost + basic feature importance for others | "Every alert is explainable" |
| **MITRE Mapper** | Static dictionary mapping: threat_class → MITRE technique | Simple but impactful |

### ❌ SKIP THESE (Grand Finale Stretch Goals)
| Component | Why Skip |
|:---|:---|
| Encrypted Malware Transformer | 4 hours training, complex JA4 pipeline — do at Grand Finale |
| Recon GNN (GraphSAGE) | ONNX export is unreliable, graph construction is complex |
| Exfil VAE | Least impressive to demo |
| Kafka / Flink | Overkill — Redis Streams or even in-memory queues are fine |
| IPFS | Just mention it in architecture slides |
| Docker / Docker Compose | Run directly, containerize at Grand Finale |
| Geo-Threat Map | Needs IP geolocation API, low ROI for effort |
| Knowledge Graph | Complex Cytoscape.js setup, skip for now |
| Polygon Amoy deployment | Local Hardhat chain is sufficient for demo |
| MITRE Heatmap | Static image in slides is enough |

---

## 👤 Role Split

| | **Person 1: "Backend Brain"** | **Person 2: "Frontend + Chain"** |
|:---|:---|:---|
| **Owns** | Python backend, AI models, feature pipeline, traffic simulator | React dashboard, blockchain, FastAPI integration, demo/presentation |
| **Primary tech** | Python, PyTorch, scikit-learn, FastAPI, Scapy | React, TypeScript, Solidity, Hardhat, ethers.js |
| **AI assist** | Use Claude for model code, feature engineering, SHAP integration | Use Claude for React components, smart contract, styling |

---

## 📅 Day-by-Day Schedule

### DAY 1 (Aug 26 — TODAY) — Foundation + Start Training
**Theme: "Set up everything, start cloud model training, build skeleton"**

#### Person 1 (Backend Brain)
| Time | Task | Deliverable |
|:---|:---|:---|
| Now → +2h | **Project setup**: Create repo structure, `requirements.txt`, virtual env. Scaffold `netsentinel/` Python package with empty modules | Working Python project that imports |
| +2h → +4h | **Traffic Simulator**: Build Scapy-based generator for DDoS (SYN flood, UDP amplification), DGA queries, C2 beacons (periodic connections) + benign traffic | `python -m netsentinel.simulator --attack ddos` generates traffic |
| +4h → +6h | **Feature Extractors**: Build `dns_features.py` (entropy, n-grams, query length, subdomain depth) and `flow_features.py` (pps, bps, syn_ack_ratio, fan_out) | Feature vectors from raw traffic |
| +6h → +8h | **Upload datasets to Kaggle**: CIC-IDS2017, CIC-DDoS2019. Start **DDoS XGBoost** notebook (should finish in 10-15 min). Start **DGA CNN-Transformer** notebook (3h run) | Kaggle notebooks running |
| +8h → +10h | **Temporal Features**: Build `temporal_features.py` (FFT periodicity, autocorrelation, IAT stats). Start **C2 LSTM+FFT** notebook on Kaggle T4 | Feature pipeline complete |
| +10h → +12h | **FastAPI skeleton**: Basic server with `/api/health`, `/api/alerts` GET, WebSocket `/ws` endpoint. Integrate feature pipeline | `uvicorn netsentinel.main:app` runs |

#### Person 2 (Frontend + Chain)
| Time | Task | Deliverable |
|:---|:---|:---|
| Now → +2h | **React project setup**: `npm create vite@latest dashboard -- --template react-ts`. Install D3.js, Recharts, socket.io-client. Set up dark theme CSS (colors, fonts, glassmorphism) | `npm run dev` shows dark themed shell |
| +2h → +5h | **Dashboard Layout**: Build Shell (sidebar + header + content area). Build **Live Threat Stream** panel (scrolling alert cards with severity colors). Use mock data for now | Sidebar + live feed rendering mock alerts |
| +5h → +8h | **Alert Table**: Sortable, filterable table with columns: timestamp, threat_class, severity, confidence, source_ip, dest_ip. Use mock data | Functional alert table |
| +8h → +10h | **Blockchain setup**: `npx hardhat init`. Write `AlertRegistry.sol` (with AccessControl). Write deploy script. Deploy to local Hardhat node | Contract deployed, `npx hardhat test` passes |
| +10h → +12h | **Threat Distribution donut**: D3.js animated donut chart showing threat type breakdown. Mock data | Animated donut chart rendering |

#### End of Day 1 Checkpoint ✅
- [ ] Python project runs, traffic simulator generates 3 attack types
- [ ] Feature extractors produce vectors from simulated traffic
- [ ] FastAPI server runs with basic endpoints
- [ ] DDoS model trained + ONNX exported (Kaggle)
- [ ] DGA + C2 models training on Kaggle (may finish overnight)
- [ ] React dashboard shows: sidebar, live feed, alert table, donut chart (mock data)
- [ ] Smart contract deployed on local Hardhat

---

### DAY 2 (Aug 27) — Models + Integration
**Theme: "Download trained models, wire everything together"**

#### Person 1 (Backend Brain)
| Time | Task | Deliverable |
|:---|:---|:---|
| Morning | **Download ONNX models** from Kaggle (DDoS done, check DGA + C2). If still training, check status and wait | ONNX files in `models/weights/` |
| +0h → +3h | **Inference wrappers**: Write `ddos_detector.py`, `dga_detector.py`, `c2_detector.py` — each loads ONNX, preprocesses input, returns score + class | `detector.predict(features) → {score, class}` |
| +3h → +5h | **Meta-Classifier**: Simple stacking — take 3 detector outputs, train a small MLP (can train locally on CPU in 5 min). Or even a simple weighted-average rule-based fusion | Final threat_class + confidence |
| +5h → +7h | **XAI Engine**: SHAP TreeExplainer for XGBoost, basic feature-importance for LSTM/CNN. Format as JSON: `{top_features: [{name, value, contribution}]}` | Every alert has explainability data |
| +7h → +9h | **MITRE Mapper**: Simple dict mapping. **Alert Manager**: Create full alert JSON with all fields (schema from the review) | Complete alert pipeline: traffic → features → model → XAI → MITRE → alert JSON |
| +9h → +12h | **Full pipeline integration**: Simulator → Features → Models → Meta-classifier → Alert → WebSocket push. Test end-to-end | `python -m netsentinel.demo` runs full pipeline |

#### Person 2 (Frontend + Chain)
| Time | Task | Deliverable |
|:---|:---|:---|
| Morning → +3h | **WebSocket integration**: Connect dashboard to backend WebSocket. Replace mock data with live data from `/ws`. Alerts appear in real-time in Live Threat Stream | Dashboard shows LIVE alerts from backend |
| +3h → +5h | **XAI Panel**: When user clicks an alert → show SHAP feature importance bar chart (horizontal bars, colored by positive/negative contribution) | Click alert → see "why the AI flagged this" |
| +5h → +7h | **Blockchain Audit Panel**: Table showing alerts with on-chain status: tx hash, block number, "✅ Verified" badge. Button to verify alert hash | Blockchain verification visible in UI |
| +7h → +9h | **Python Web3 client**: Write `chain_client.py` using web3.py — `anchor_alert(alert_json)` hashes alert, calls smart contract, returns tx_hash. Integrate with alert manager | Alerts auto-anchored to blockchain |
| +9h → +11h | **REST API integration**: Connect all remaining dashboard panels to real API endpoints: `/api/alerts`, `/api/stats` | All panels showing real data |
| +11h → +12h | **Polish**: Loading states, error handling, smooth transitions, responsive layout | Professional-looking dashboard |

#### End of Day 2 Checkpoint ✅
- [ ] All 3 models loaded and running inference
- [ ] Full pipeline: simulate attack → detect → explain → alert → blockchain
- [ ] Dashboard connected to live backend via WebSocket
- [ ] XAI panel shows SHAP explanations
- [ ] Blockchain panel shows anchored alerts with verification
- [ ] End-to-end demo works (even if rough)

---

### DAY 3 (Aug 28) — Polish + Edge Cases + Presentation
**Theme: "Make it bulletproof and beautiful"**

#### Person 1 (Backend Brain)
| Time | Task | Deliverable |
|:---|:---|:---|
| +0h → +3h | **Demo traffic dataset**: Create a curated 2-minute demo script that generates a realistic attack scenario: benign traffic → DDoS spike → C2 beacon appears → DGA domains detected. Time it perfectly for the demo | `python -m netsentinel.demo --scenario full_attack` |
| +3h → +5h | **Edge cases + robustness**: Test with edge cases — empty traffic, malformed packets, rapid bursts. Add error handling. Test model inference speed (should be <10ms per sample) | No crashes on weird input |
| +5h → +7h | **Throughput benchmark**: Run a simple benchmark — how many flows/sec can the pipeline process? Document the number | "We process X flows/sec on a laptop" |
| +7h → +9h | **API documentation**: Auto-generate FastAPI docs (Swagger UI at `/docs`). Clean up code, add docstrings | Clean, documented API |
| +9h → +12h | **Help Person 2 with presentation + demo rehearsal** | Smooth demo |

#### Person 2 (Frontend + Chain)
| Time | Task | Deliverable |
|:---|:---|:---|
| +0h → +3h | **Dashboard animations**: Pulse animation on new alerts, smooth count-up on stats, fade-in transitions, glassmorphism effects on cards | Dashboard looks premium |
| +3h → +5h | **Presentation slides**: 8-10 slides (problem → architecture → innovation → live demo → blockchain → metrics → impact → team) | PPT/Google Slides ready |
| +5h → +7h | **Architecture diagram**: Create a clean, visual architecture diagram for slides (use draw.io or Excalidraw). Create the "6 experts" visual | Visual aids ready |
| +7h → +9h | **Demo rehearsal**: Practice the 5-minute demo flow end-to-end. Time it. Identify failure points. Create backup plan (screenshots if live demo fails) | Rehearsed demo |
| +9h → +12h | **README + documentation**: Write a solid README.md with screenshots, setup instructions, architecture overview | Professional repo |

#### End of Day 3 Checkpoint ✅
- [ ] Curated demo scenario runs perfectly every time
- [ ] Dashboard looks stunning (dark theme, animations, glassmorphism)
- [ ] Presentation slides complete
- [ ] Architecture diagram clean and visual
- [ ] Demo rehearsed and timed
- [ ] README with screenshots

---

### DAY 4 (Aug 29) — Final Day Before Event
**Theme: "Rehearse, rehearse, rehearse. Fix only critical bugs."**

#### Both People Together
| Time | Task |
|:---|:---|
| Morning → +2h | **Full system test**: Start from scratch — clone repo, install deps, run backend, run dashboard, run demo. Fix any setup issues |
| +2h → +4h | **Code freeze 🔒**: Stop writing code. If something doesn't work, remove it rather than trying to fix it last minute |
| +4h → +6h | **Rehearse demo 3× minimum**: Time it. Practice the "wow moment" (live attack simulation). Practice answering 10 likely questions |
| +6h → +8h | **Prepare backup plan**: Take screenshots of dashboard at key moments. Record a video of the demo working. If live demo fails, play the video |
| +8h → +10h | **Polish presentation**: Refine slides based on rehearsal. Add speaker notes. Practice handoffs between both people |
| +10h → sleep | **Prepare logistics**: Charge laptops, test projector/HDMI, prepare 2 USB backups of entire project, test on second laptop if available |

---

## 🏗️ Simplified Tech Stack (For College Round)

| Layer | Grand Finale Plan | College Round Reality |
|:---|:---|:---|
| Streaming | Kafka + Flink | **In-memory Python queue** (or Redis if needed) |
| Models | 6 detectors + meta-classifier (ONNX) | **3 detectors + simple fusion** (ONNX) |
| Backend | FastAPI + complex pipeline | **FastAPI + simple pipeline** |
| Frontend | React + 10 panels + 5 libraries | **React + 5 panels + D3 + Recharts** |
| Blockchain | Polygon Amoy + IPFS + Pinata | **Hardhat local chain only** |
| Deployment | Docker Compose | **Direct execution** (`uvicorn` + `npm run dev`) |
| XAI | SHAP + Attention + LLM narratives | **SHAP for XGBoost + feature importance** |

---

## 📁 Simplified Repo Structure

```
netsentinel/
├── README.md
├── requirements.txt
├── .gitignore
│
├── netsentinel/                  # Python backend
│   ├── __init__.py
│   ├── main.py                  # FastAPI app entry point
│   ├── config.py
│   │
│   ├── simulator/               # Traffic generation
│   │   ├── __init__.py
│   │   ├── traffic_gen.py       # Scapy-based attack generator
│   │   └── scenarios.py         # Pre-built demo scenarios
│   │
│   ├── features/                # Feature extraction
│   │   ├── __init__.py
│   │   ├── dns_features.py
│   │   ├── flow_features.py
│   │   └── temporal_features.py
│   │
│   ├── models/                  # AI detectors
│   │   ├── __init__.py
│   │   ├── ddos_detector.py
│   │   ├── dga_detector.py
│   │   ├── c2_detector.py
│   │   ├── meta_classifier.py
│   │   └── weights/             # ONNX files go here
│   │
│   ├── intelligence/            # XAI + MITRE
│   │   ├── __init__.py
│   │   ├── xai_engine.py
│   │   ├── mitre_mapper.py
│   │   └── alert_manager.py
│   │
│   ├── blockchain/              # Web3 integration
│   │   ├── __init__.py
│   │   └── chain_client.py
│   │
│   └── api/                     # API layer
│       ├── __init__.py
│       ├── routes.py
│       └── websocket.py
│
├── blockchain/                  # Solidity contracts
│   ├── contracts/
│   │   └── AlertRegistry.sol
│   ├── scripts/
│   │   └── deploy.js
│   ├── test/
│   │   └── AlertRegistry.test.js
│   ├── hardhat.config.js
│   └── package.json
│
├── dashboard/                   # React frontend
│   ├── package.json
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── App.tsx
│       ├── main.tsx
│       ├── index.css
│       ├── components/
│       │   ├── Layout.tsx
│       │   ├── ThreatStream.tsx
│       │   ├── AlertTable.tsx
│       │   ├── ThreatDonut.tsx
│       │   ├── XAIPanel.tsx
│       │   └── BlockchainAudit.tsx
│       ├── hooks/
│       │   └── useWebSocket.ts
│       └── types/
│           └── alert.ts
│
├── notebooks/                   # Kaggle training notebooks
│   ├── 01_ddos_xgboost.ipynb
│   ├── 02_c2_beacon_lstm.ipynb
│   ├── 03_dga_cnn_transformer.ipynb
│   └── 04_meta_classifier.ipynb
│
└── docs/
    ├── architecture.png
    └── presentation.pptx
```

---

## 🎤 5-Minute Demo Script (College Round)

```
[0:00-0:30] HOOK
  "In 2019, the Kudankulam Nuclear Power Plant was hit by Dtrack malware.
   It took MONTHS to detect. What if we could detect it in SECONDS?"
  → Show NetSentinel logo + tagline

[0:30-1:00] PROBLEM
  "Critical infrastructure uses data diodes — one-way hardware.
   All existing IDS (Snort, Suricata) assume two-way traffic.
   There is NO AI-based IDS designed for unidirectional constraints."
  → Show data diode diagram

[1:00-2:00] SOLUTION — ARCHITECTURE
  "NetSentinel: 3 specialized AI detectors, not 1 generic model"
  → Show architecture diagram
  → Briefly explain: DDoS (XGBoost), DGA (CNN-Transformer), C2 (LSTM+FFT)
  → "Every alert is explainable, MITRE-mapped, and blockchain-verified"

[2:00-3:30] LIVE DEMO — THE WOW MOMENT
  → Switch to dashboard (already running)
  → "Let me launch a simulated attack campaign..."
  → Run: python -m netsentinel.demo --scenario full_attack
  → Dashboard lights up: DDoS alerts → C2 beacons → DGA domains
  → Click an alert → Show SHAP explanation
  → Show blockchain panel → "This alert is now tamper-proof on-chain"

[3:30-4:15] INNOVATION
  → "3 things make us different:"
  → "1. First IDS built for data diodes — read-only by design"
  → "2. AI explains WHY it flagged traffic — not a black box"
  → "3. Blockchain forensic chain — evidence that can't be tampered with"

[4:15-5:00] GRAND FINALE VISION
  → "For the Grand Finale, we'll add:"
  → "Encrypted malware detection WITHOUT decryption (Packet-Sequence Transformer)"
  → "Graph Neural Network for distributed scan detection"
  → "Decentralized threat intelligence sharing across enclaves"
  → "We process X flows/sec on a laptop. This scales to production."
```

---

## ⚡ What To Do RIGHT NOW

### Person 1 — Start immediately:
```bash
# 1. Create project
mkdir d:\1_sih26\netsentinel
cd d:\1_sih26\netsentinel
git init

# 2. Set up Python
python -m venv venv
venv\Scripts\activate
pip install fastapi uvicorn scapy numpy scipy scikit-learn xgboost onnxruntime shap web3 websockets

# 3. Start building traffic simulator
# → Ask Claude to help write the Scapy traffic generator
```

### Person 2 — Start immediately:
```bash
# 1. Create React dashboard
cd d:\1_sih26\netsentinel
npx -y create-vite@latest dashboard -- --template react-ts
cd dashboard
npm install d3 recharts socket.io-client

# 2. Set up Hardhat
cd d:\1_sih26\netsentinel
mkdir blockchain && cd blockchain
npx -y hardhat init
# → Choose "Create a JavaScript project"

# 3. Start building dark theme shell
# → Ask Claude to help with the cybersecurity dashboard layout
```

### Both — Start Kaggle notebooks:
1. Go to kaggle.com → New Notebook
2. Upload CIC-IDS2017 dataset
3. Ask Claude to generate the XGBoost DDoS training notebook
4. Run it (10 min on CPU) → Download ONNX

> [!TIP]
> **Use Claude aggressively.** Have Claude generate the boilerplate code for each component. Your job is to **integrate and test**, not write everything from scratch. Each component (traffic simulator, feature extractor, detector wrapper, React panel, smart contract) can be generated by Claude in minutes. You spend your time wiring them together and making the demo bulletproof.
