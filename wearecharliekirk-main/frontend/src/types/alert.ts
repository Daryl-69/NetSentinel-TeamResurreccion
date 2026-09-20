// Normalized to netsentinel/pipeline/alert_manager.py output.
// This is the single contract shared by the mock feed and, later,
// the real ws://localhost:8000/ws stream.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ThreatType =
  | "DDoS"
  | "C2 Beacon"
  | "DGA"
  | "Encrypted"
  | "Port Scan"
  | "Exfiltration"
  | "Benign";

export type ModelName =
  | "DDoS XGBoost"
  | "DGA CNN-BiLSTM"
  | "C2 BiLSTM+FFT"
  | "ETT Transformer"
  | "Port Scan XGBoost"
  | "Exfil VAE";

// The 5-tuple flow identifier mandated by the NTRO alert schema. A single
// flow id ties an alert to its evidence — one UID, one story (Corelight).
export interface FlowTuple {
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: "TCP" | "UDP" | "ICMP";
}

export interface Alert {
  id: string;
  timestamp: number; // epoch ms
  threatType: ThreatType;
  severity: Severity;
  sourceIP: string;
  destIP?: string;
  domain?: string;
  confidence: number; // 0–100
  flow?: FlowTuple; // 5-tuple flow id (NTRO schema)
  mitreTechnique?: string; // e.g. "T1498"
  mitreTactic?: string; // e.g. "Impact"
  model: ModelName;
  indicators: string[]; // supporting evidence (NTRO schema)
  beaconInterval?: number; // seconds, C2 only
  sourceCoords?: [number, number]; // [lat, lng] for 3D graph
  destCoords?: [number, number]; // [lat, lng] for 3D graph

  // ── Per-class evidence signals ─────────────────────────────────
  srcIpEntropy?: number; // DDoS — Shannon entropy (bits) of source-IP spread
  fanOut?: { targetIp: string; ports: number[]; window: number }; // Port Scan
  byteRatio?: { outbound: number; inbound: number }; // Exfiltration — bytes
  ja4?: string; // Encrypted — TLS client fingerprint
  ja4Rarity?: number; // Encrypted — 0–1, rarity of the fingerprint in baseline
  iat?: number[]; // C2 — inter-arrival times (seconds), for beacon clock
  classProbs?: { label: string; p: number }[]; // DGA — per-family probabilities
}

export interface PacketSample {
  t: number; // epoch ms
  pps: number; // packets / sec
  critical: number;
  high: number;
  medium: number;
}

export interface ModelStat {
  name: ModelName;
  short: string;
  accuracy: number; // %
  latency: number; // ms
  metricLabel: string; // "F1" | "Accuracy"
  active: boolean;
  threshold: number; // decision threshold (%)
  lastConfidence: number | null; // most recent alert confidence
}

export interface MitreCell {
  tactic: string;
  technique: string;
  id: string;
  hits: number;
}

export interface FeedState {
  alerts: Alert[];
  packetRate: PacketSample[];
  threatCounts: Record<Severity, number>;
  models: ModelStat[];
  mitre: MitreCell[];
  totalFlows: number;
  flowsPerSec: number;
  phase: string;
  status: "monitoring" | "critical" | "connecting";
  source: "mock" | "live";
}

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};
