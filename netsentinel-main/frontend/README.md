# NetSentinel Dashboard 🛡️

AI-powered network threat detection dashboard built with React, TypeScript, and Vite.

Real-time visualization of threats detected by 6 machine learning models analyzing network traffic.

---

## 🎯 Features

- **Real-time Threat Visualization** - 3D network graph with geo-located threats
- **MITRE ATT&CK Heatmap** - Attack pattern analysis and mapping
- **Live Alert Feed** - Streaming threat alerts via WebSocket
- **Model Confidence Tracking** - Monitor 6 ML model performance in real-time
- **Attack Timeline** - Historical threat analysis
- **FFT Spectrum Analysis** - C2 beacon detection visualization
- **Traffic Analysis** - Network flow statistics and patterns

---

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ and npm
- [NetSentinel Backend](https://github.com/yourusername/netsentinel) running on `http://localhost:8000`

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

Dashboard opens on **`http://localhost:5173`**

### Build for Production

```bash
npm run build
```

Output in `dist/` directory.

---

## 🔌 Backend Connection

The dashboard connects to the NetSentinel backend via WebSocket and REST API:

- **WebSocket URL**: `ws://localhost:8000/ws` (real-time threat alerts)
- **REST API**: `http://localhost:8000/api` (simulations, uploads)

### Change Backend URL

Edit `src/data/useThreatFeed.ts`:

```typescript
const WS_URL = 'ws://your-backend-url/ws';
```

---

## 🎨 Dashboard Components

### Main Visualizations

- **3D Threat Graph** (`ThreatGraph.tsx`) - Interactive network topology with threat nodes
- **MITRE Heatmap** (`MitreHeatmap.tsx`) - ATT&CK technique frequency mapping
- **Alert Feed** (`AlertFeed.tsx`) - Real-time scrolling threat alerts
- **Confidence Bands** (`ConfidenceBands.tsx`) - Model performance monitoring
- **Traffic Charts** (`TrafficCharts.tsx`) - Network statistics and trends
- **FFT Spectrum** (`FFTSpectrum.tsx`) - Frequency domain analysis for beaconing

### Threat Detection Models

The dashboard displays alerts from 6 ML models:

1. **DDoS Binary XGBoost** - DDoS attack detection
2. **DGA LSTM** - Domain generation algorithm detection
3. **C2 Beacon Analyzer** - Command & control beacon detection
4. **VPN/Tunnel XGBoost** - Encrypted tunnel detection
5. **Port Scan XGBoost** - Port scanning detection
6. **Exfiltration VAE** - Data exfiltration detection

---

## 🧩 Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety and better DX
- **Vite** - Fast build tool and dev server
- **Three.js / React-Three-Fiber** - 3D visualizations
- **Recharts** - Charts and graphs
- **TailwindCSS** - Utility-first styling
- **Lucide React** - Icon library

---

## 📊 Data Flow

```
Backend (FastAPI + WebSocket)
    ↓
    → PCAP files / Live traffic
    → Feature extraction
    → 6 ML models
    → Threat detection
    ↓
WebSocket (ws://localhost:8000/ws)
    ↓
Frontend (This Dashboard)
    → useThreatFeed hook
    → Real-time alert updates
    → 3D graph, charts, MITRE map
    → User sees threats live
```

---

## 🧪 Testing

### 1. Start Backend

```bash
cd ../  # Go to backend folder
python run.py
```

Backend should be running on `http://localhost:8000`

### 2. Start Frontend

```bash
npm run dev
```

### 3. Generate Test Traffic

**Option A**: Use the HTML test page
- Open `../test_websocket.html` in browser
- Click "Run Mixed Simulation"

**Option B**: Use API directly
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/simulate/mixed" -Method POST
```

### 4. Watch Alerts

Alerts should appear in:
- Alert feed (right panel)
- 3D graph (threat nodes)
- MITRE heatmap (technique cells)
- Model confidence bands

---

## 🔍 Troubleshooting

### WebSocket Not Connecting

1. **Check backend is running**:
   ```bash
   curl http://localhost:8000/health
   ```

2. **Check browser console** (F12):
   - Should see: `WebSocket connected to ws://localhost:8000/ws`
   - If error, backend might not be running

3. **Verify WebSocket URL**:
   - Check `src/data/useThreatFeed.ts`
   - Default: `ws://localhost:8000/ws`

### No Alerts Appearing

1. **Generate test traffic**:
   ```powershell
   Invoke-RestMethod -Uri "http://localhost:8000/api/simulate/mixed" -Method POST
   ```

2. **Check backend logs** - should show alerts being generated

3. **Check model status** - run backend test:
   ```bash
   cd ../
   python test_models.py
   ```

### Dashboard Shows "Disconnected"

- Backend crashed or not running
- Restart backend: `python run.py`
- Refresh browser

---

## 📁 Project Structure

```
Share Figma conversation/
├── src/
│   ├── components/          # React components
│   │   ├── ThreatGraph.tsx       # 3D network visualization
│   │   ├── AlertFeed.tsx         # Live alert stream
│   │   ├── MitreHeatmap.tsx      # ATT&CK heatmap
│   │   ├── ConfidenceBands.tsx   # Model confidence
│   │   ├── TrafficCharts.tsx     # Network stats
│   │   └── FFTSpectrum.tsx       # C2 beacon analysis
│   ├── data/
│   │   ├── useThreatFeed.ts      # WebSocket hook
│   │   └── mockFeed.ts           # Test data
│   ├── types/
│   │   └── alert.ts              # TypeScript types
│   ├── App.tsx              # Main dashboard layout
│   ├── main.tsx             # Entry point
│   └── index.css            # Global styles
├── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
└── README.md
```

---

## 🔗 Related Projects

- **[NetSentinel Backend](https://github.com/yourusername/netsentinel)** - ML pipeline, models, and API
- **Original Problem List**: See `BACKEND_PROBLEMS.md` for issues that were resolved

---

## 🛠️ Development Notes

### Model Name Mapping

Backend sends internal model names, frontend displays user-friendly names:

```typescript
const MODEL_NAME_MAP = {
  'ddos_binary_xgboost': 'DDoS XGBoost',
  'dga_lstm': 'DGA LSTM',
  'c2_beacon': 'C2 Beacon',
  'vpn_tunnel_xgboost': 'VPN/Tunnel XGBoost',
  'port_scan_xgboost': 'Port Scan XGBoost',
  'exfil_vae': 'Exfiltration VAE'
};
```

### Alert Structure

WebSocket messages:

```json
{
  "type": "alert",
  "threat_type": "DDoS Attack",
  "model_name": "DDoS XGBoost",
  "severity": "high",
  "confidence": 0.95,
  "timestamp": "2026-08-29T10:30:45.123Z",
  "flow": {
    "src_ip": "192.168.1.100",
    "src_port": 54321,
    "dst_ip": "10.0.0.50",
    "dst_port": 80,
    "protocol": "TCP"
  },
  "evidence": {
    "mitre_tactic": "Impact",
    "mitre_technique": "T1498",
    "description": "High packet rate detected"
  }
}
```

---

## 📝 License

[Your License Here]

---

## 🤝 Contributing

This dashboard is part of the NetSentinel project. See main repo for contribution guidelines.

---

**Built with ❤️ for network security analysts and threat hunters**
