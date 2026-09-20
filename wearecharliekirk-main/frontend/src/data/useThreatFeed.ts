import { useEffect, useRef, useState } from "react";
import type { Alert, FeedState, PacketSample, Severity } from "../types/alert";
import {
  DEMO_SCRIPT,
  MODELS,
  THREAT_TO_TACTIC,
  basePps,
  emptyMitre,
  makeBenign,
  phaseFor,
} from "./mockFeed";

/**
 * ── Live backend switch ───────────────────────────────────────────────
 * Set to your NetSentinel WebSocket to consume real alerts:
 *   const WS_URL = "ws://localhost:8000/ws";
 *
 * Empty string ("") = mock mode (the scripted 60-second demo). Note the
 * Figma Make preview sandbox cannot reach localhost, so live mode only
 * works when this app runs on the same host as `python run.py`
 * (see LOCAL_RUN.md). If the socket fails to open within 4s, we fall
 * back to mock automatically so the dashboard is never blank.
 * ──────────────────────────────────────────────────────────────────────
 */
const WS_URL = "ws://localhost:8000/ws";  // Live mode enabled

const LOOP_MS = 60_000;
const TICK_MS = 900;
const MAX_ALERTS = 50;
const MAX_SAMPLES = 60;

const zeroCounts = (): Record<Severity, number> => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
});

function initialState(): FeedState {
  return {
    alerts: [],
    packetRate: [],
    threatCounts: zeroCounts(),
    models: MODELS.map((m) => ({ ...m })),
    mitre: emptyMitre(),
    totalFlows: 0,
    flowsPerSec: 42.5,
    phase: phaseFor(0),
    status: "monitoring",
    source: "mock",
  };
}

/**
 * Transform backend alert schema → frontend Alert interface.
 * 
 * Backend schema (from alert_manager.py):
 *   - timestamp: ISO 8601 string
 *   - confidence: float 0-1
 *   - severity: UPPERCASE
 *   - threat_class: snake_case
 *   - mitre: nested object
 *   - evidence: dict
 *   - geo: nested object
 * 
 * Frontend schema (types/alert.ts):
 *   - timestamp: epoch ms
 *   - confidence: 0-100 percentage
 *   - severity: lowercase
 *   - threatType: camelCase
 *   - mitreTechnique/mitreTactic: flat
 *   - indicators: string array
 *   - sourceCoords/destCoords: [lat, lng] tuples
 */
// ── Backend → frontend vocabulary maps ────────────────────────────────
// The backend (alert_manager.py + model wrappers) emits its own strings:
// snake_case model ids, and threat classes like "VPN Traffic" /
// "Data Exfiltration". The frontend components filter on the ThreatType
// and ModelName unions, so we normalise here — otherwise the encrypted /
// exfil class panels, the MITRE heatmap, and the model cards stay dark
// even while alerts arrive.
const THREAT_CLASS_MAP: Record<string, Alert["threatType"]> = {
  DDoS: "DDoS",
  "C2 Beacon": "C2 Beacon",
  DGA: "DGA",
  "DNS Tunnel": "DGA",
  "VPN Traffic": "Encrypted",
  "Encrypted Malware": "Encrypted",
  "Port Scan": "Port Scan",
  "Data Exfiltration": "Exfiltration",
};

const MODEL_NAME_MAP: Record<string, Alert["model"]> = {
  ddos_binary_xgboost: "DDoS XGBoost",
  dga_cnn_bilstm_v2: "DGA CNN-BiLSTM",
  c2_beacon_bilstm: "C2 BiLSTM+FFT",
  encrypted_traffic_transformer: "ETT Transformer",
  port_scan_xgboost: "Port Scan XGBoost",
  exfil_vae: "Exfil VAE",
};

function parseBackendAlert(raw: any): Alert {
  // Transform evidence dict → human-readable indicators array
  const indicators: string[] = [];
  if (raw.evidence) {
    if (raw.evidence.pps) indicators.push(`${raw.evidence.pps.toLocaleString()} pps`);
    if (raw.evidence.avg_pkt_size) indicators.push(`Avg packet size: ${raw.evidence.avg_pkt_size} bytes`);
    if (raw.evidence.syn_ack_ratio !== undefined) indicators.push(`SYN/ACK ratio: ${raw.evidence.syn_ack_ratio.toFixed(2)}`);
    if (raw.evidence.beacon_interval) indicators.push(`Beacon interval: ${raw.evidence.beacon_interval}s`);
    if (raw.evidence.entropy) indicators.push(`Entropy: ${raw.evidence.entropy.toFixed(2)}`);
    if (raw.evidence.domain) indicators.push(`Domain: ${raw.evidence.domain}`);
    // Add more evidence field mappings as backend evolves
  }

  // Fallback indicators if evidence is empty
  if (indicators.length === 0) {
    indicators.push(`Detected by ${raw.model_name || "ML model"}`);
  }

  // Normalise the 5-tuple flow id (backend uses snake_case keys).
  const flow = raw.flow
    ? {
        srcIp: raw.flow.src_ip,
        srcPort: raw.flow.src_port ?? 0,
        dstIp: raw.flow.dst_ip,
        dstPort: raw.flow.dst_port ?? 0,
        protocol: (raw.flow.protocol ?? "TCP") as "TCP" | "UDP" | "ICMP",
      }
    : undefined;

  // DGA per-family probabilities → classProbs (all_probs may be an object
  // {label: p} or already a list of {label, p}).
  let classProbs: Alert["classProbs"];
  const ap = raw.evidence?.all_probs;
  if (Array.isArray(ap)) classProbs = ap;
  else if (ap && typeof ap === "object") classProbs = Object.entries(ap).map(([label, p]) => ({ label, p: Number(p) }));

  return {
    id: raw.id,
    timestamp: new Date(raw.timestamp).getTime(), // ISO → epoch ms
    threatType: THREAT_CLASS_MAP[raw.threat_class] ?? (raw.threat_class as Alert["threatType"]),
    severity: raw.severity.toLowerCase() as Severity,
    sourceIP: raw.source_ip,
    destIP: raw.dest_ip,
    domain: raw.evidence?.domain,
    confidence: Math.round(raw.confidence * 1000) / 10, // 0.9937 → 99.4
    flow,
    mitreTechnique: raw.mitre?.name ?? raw.mitre?.technique, // heatmap matches on technique name
    mitreTactic: raw.mitre?.tactic,
    model: MODEL_NAME_MAP[raw.model_name] ?? (raw.model_name as Alert["model"]),
    indicators,
    beaconInterval: raw.evidence?.beacon_interval ?? raw.evidence?.periodicity_seconds,
    classProbs,
    // Per-class evidence signals (backend evidence dict → typed fields).
    srcIpEntropy: raw.evidence?.src_ip_entropy,
    fanOut: raw.evidence?.fan_out
      ? {
          targetIp: raw.evidence.fan_out.target_ip,
          ports: raw.evidence.fan_out.ports ?? [],
          window: raw.evidence.fan_out.window ?? 0,
        }
      : undefined,
    byteRatio: raw.evidence?.byte_ratio
      ? { outbound: raw.evidence.byte_ratio.outbound, inbound: raw.evidence.byte_ratio.inbound }
      : undefined,
    ja4: raw.evidence?.ja4,
    ja4Rarity: raw.evidence?.ja4_rarity,
    iat: raw.evidence?.iat,
    // Transform geo object → coordinate tuples for 3D graph
    sourceCoords: raw.geo?.src_lat && raw.geo?.src_lon 
      ? [raw.geo.src_lat, raw.geo.src_lon] 
      : undefined,
    destCoords: raw.geo?.dst_lat && raw.geo?.dst_lon 
      ? [raw.geo.dst_lat, raw.geo.dst_lon] 
      : undefined,
  };
}

// Fold a single alert into feed state. Shared by mock + live paths so
// downstream aggregation is identical regardless of source.
function ingest(prev: FeedState, alert: Alert, source: FeedState["source"]): FeedState {
  const alerts = [alert, ...prev.alerts].slice(0, MAX_ALERTS);
  const threatCounts = { ...zeroCounts() };
  for (const a of alerts) threatCounts[a.severity] += 1;

  const models = prev.models.map((m) =>
    m.name === alert.model
      ? { ...m, active: true, lastConfidence: alert.confidence }
      : { ...m, active: false },
  );

  const mitre = prev.mitre.map((c) => ({ ...c }));
  const tactic = THREAT_TO_TACTIC[alert.threatType];
  if (tactic && alert.mitreTechnique) {
    const cell =
      mitre.find((c) => c.tactic === tactic && c.technique.startsWith(alert.mitreTechnique!.slice(0, 4))) ??
      mitre.find((c) => c.tactic === tactic);
    if (cell) cell.hits += 1;
  }

  const status: FeedState["status"] =
    alert.severity === "critical" ? "critical" : prev.status === "critical" ? "critical" : "monitoring";

  return { ...prev, alerts, threatCounts, models, mitre, status, source };
}

export function useThreatFeed(): FeedState {
  const [state, setState] = useState<FeedState>(initialState);
  const start = useRef(Date.now());
  const firedRef = useRef<Set<number>>(new Set());

  useEffect(() => {
    // Fetch historical alerts on mount
    fetch("http://localhost:8000/api/alerts")
      .then(res => res.json())
      .then(data => {
        if (data.alerts && Array.isArray(data.alerts)) {
          // Load first 50 historical alerts
          let newState = initialState();
          for (const rawAlert of data.alerts.slice(0, 50)) {
            const alert = parseBackendAlert(rawAlert);
            newState = ingest(newState, alert, "live");
          }
          setState(newState);
        }
      })
      .catch(err => console.warn("Failed to load historical alerts:", err));

    let ws: WebSocket | null = null;
    let mockIv: ReturnType<typeof setInterval> | null = null;
    let sampleIv: ReturnType<typeof setInterval> | null = null;
    let fallbackTimer: ReturnType<typeof setTimeout> | null = null;
    let live = false;

    // Chart samples run in BOTH modes so the packet-rate plot always moves.
    const startSampling = (isLive: boolean) => {
      sampleIv = setInterval(() => {
        const now = Date.now();
        const elapsed = (now - start.current) % LOOP_MS;
        setState((prev) => {
          const recent = prev.alerts.filter((a) => now - a.timestamp < 3000);
          const sample: PacketSample = {
            t: now,
            pps: isLive ? 800 + recent.length * 400 + Math.random() * 200 : basePps(elapsed),
            critical: recent.filter((a) => a.severity === "critical").length,
            high: recent.filter((a) => a.severity === "high").length,
            medium: recent.filter((a) => a.severity === "medium").length,
          };
          const packetRate = [...prev.packetRate, sample].slice(-MAX_SAMPLES);
          const flowsPerSec = +(40 + Math.random() * 6).toFixed(1);
          return {
            ...prev,
            packetRate,
            totalFlows: prev.totalFlows + Math.round(flowsPerSec * (TICK_MS / 1000)),
            flowsPerSec,
            phase: isLive ? "Live capture" : phaseFor(elapsed),
          };
        });
      }, TICK_MS);
    };

    const startMock = () => {
      if (live) return;
      setState((prev) => ({ ...prev, source: "mock" }));
      startSampling(false);
      mockIv = setInterval(() => {
        const now = Date.now();
        const elapsed = (now - start.current) % LOOP_MS;
        const loopIndex = Math.floor((now - start.current) / LOOP_MS);
        const phase = phaseFor(elapsed);
        const fired = firedRef.current;

        DEMO_SCRIPT.forEach((ev, i) => {
          const key = loopIndex * 100 + i;
          if (elapsed >= ev.atMs && elapsed < ev.atMs + TICK_MS && !fired.has(key)) {
            fired.add(key);
            setState((prev) => ({ ...ingest(prev, ev.make(), "mock"), phase }));
          }
        });
        if (fired.size > 400) firedRef.current = new Set();
        if (Math.random() < 0.5) {
          setState((prev) => ({ ...ingest(prev, makeBenign(), "mock"), phase }));
        }
      }, TICK_MS);
    };

    if (WS_URL) {
      setState((prev) => ({ ...prev, status: "connecting" }));
      try {
        ws = new WebSocket(WS_URL);
        fallbackTimer = setTimeout(() => {
          if (!live) startMock();
        }, 4000);
        ws.onopen = () => {
          live = true;
          if (fallbackTimer) clearTimeout(fallbackTimer);
          if (mockIv) clearInterval(mockIv);
          if (sampleIv) clearInterval(sampleIv);
          setState((prev) => ({ ...prev, source: "live", status: "monitoring" }));
          startSampling(true);
        };
        ws.onmessage = (e) => {
          try {
            const rawAlert = JSON.parse(e.data);
            // Handle backend message format: {"type": "alert", "data": {...}}
            const alertData = rawAlert.type === "alert" && rawAlert.data ? rawAlert.data : rawAlert;
            const alert = parseBackendAlert(alertData);
            setState((prev) => ingest(prev, alert, "live"));
          } catch (err) {
            console.warn("[WebSocket] Failed to parse alert:", err);
            /* ignore malformed frames */
          }
        };
        ws.onerror = () => {
          if (!live) startMock();
        };
        ws.onclose = () => {
          if (!live) startMock();
        };
      } catch {
        startMock();
      }
    } else {
      startMock();
    }

    return () => {
      ws?.close();
      if (mockIv) clearInterval(mockIv);
      if (sampleIv) clearInterval(sampleIv);
      if (fallbackTimer) clearTimeout(fallbackTimer);
    };
  }, []);

  return state;
}
