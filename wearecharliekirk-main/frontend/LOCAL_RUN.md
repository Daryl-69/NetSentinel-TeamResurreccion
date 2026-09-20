# Running the dashboard against the real NetSentinel backend

The dashboard ships in **mock mode** — it replays the scripted 60-second demo
from `README_COMPREHENSIVE.md`. This is intentional and it is also the only mode
that works **inside the Figma Make preview**, because that preview runs on a
remote proxy domain that has no network route to a server on your machine.

To feed **real / raw traffic** through your ONNX pipeline and watch it live, you
must run this dashboard **on the same host** as the backend. Here's how.

## 1. Start the backend

```bash
cd netsentinel
python run.py          # FastAPI + WebSocket on http://localhost:8000
```

Confirm it's up:

```bash
curl http://localhost:8000/api/health
```

## 2. Point the dashboard at the WebSocket

Open `src/data/useThreatFeed.ts` and set the switch near the top:

```ts
const WS_URL = "ws://localhost:8000/ws";
```

(Empty string keeps mock mode. When set, the hook connects on mount; if the
socket doesn't open within 4s it falls back to mock automatically, so the board
is never blank.)

## 3. Run the dashboard locally

```bash
# from this project root, on the SAME machine as the backend
pnpm install
pnpm dev                # Vite dev server, usually http://localhost:5173
```

Open the printed URL. The header badge flips from `mock` to `● live` once the
socket connects.

## 4. Send it traffic

Any of the backend's real input modes now drives the dashboard:

```bash
# scripted synthetic attack sequence
curl -X POST http://localhost:8000/api/simulate/mixed

# forensic replay of a raw capture (unclassified internet traffic)
curl -F "file=@capture.pcap" http://localhost:8000/api/pcap/upload

# live NIC capture (needs admin/root + Npcap on Windows)
curl -X POST http://localhost:8000/api/capture/start \
     -H "Content-Type: application/json" \
     -d '{"interface":"Ethernet"}'
```

As the pipeline classifies flows, each `Alert` broadcast on `/ws` appears in the
feed, drives the correlation graph / topology map, updates the MITRE heatmap,
lights the firing model's confidence band, and (for C2) renders the FFT peak.

## Alert shape contract

The dashboard's `Alert` type (`src/types/alert.ts`) mirrors
`alert_manager.py`. Each WebSocket frame should be JSON of that shape, e.g.:

```json
{
  "id": "al-1739...",
  "timestamp": 1739544000000,
  "threatType": "C2 Beacon",
  "severity": "high",
  "sourceIP": "10.0.0.22",
  "destIP": "185.220.101.4",
  "confidence": 94.1,
  "mitreTechnique": "App Layer Protocol",
  "mitreTactic": "Command & Control",
  "model": "C2 BiLSTM+FFT",
  "indicators": ["Dominant FFT freq 0.0172 Hz", "Beacon interval 58.3s"],
  "beaconInterval": 58.3
}
```

If your backend emits slightly different field names, map them in one place —
the `ingest()` call inside `useThreatFeed.ts` — and nothing else needs to change.

## Why not just call the API from the preview?

The Figma Make preview is served from `app-…figma.site`. Browser same-origin +
the sandbox network policy block it from reaching `localhost:8000` on your
machine. This is a hosting boundary, not a code problem — running the dashboard
locally (step 3) removes it entirely.
