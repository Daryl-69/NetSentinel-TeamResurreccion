import type { Alert, ModelStat, MitreCell, Severity, ThreatType } from "../types/alert";

// Real model metrics from README_COMPREHENSIVE.md §"AI Models".
// thresholds from README §"False Positive Scenarios" (95% DDoS conf,
// entropy/recall-tuned others). These are decision cut-offs, not accuracy.
export const MODELS: ModelStat[] = [
  { name: "DDoS XGBoost", short: "DDoS", accuracy: 99.3, latency: 4.3, metricLabel: "F1", active: false, threshold: 95, lastConfidence: null },
  { name: "DGA CNN-BiLSTM", short: "DGA", accuracy: 93.6, latency: 8.1, metricLabel: "ACC", active: false, threshold: 85, lastConfidence: null },
  { name: "C2 BiLSTM+FFT", short: "C2", accuracy: 93.5, latency: 6.7, metricLabel: "ACC", active: false, threshold: 90, lastConfidence: null },
  { name: "ETT Transformer", short: "ETT", accuracy: 88.0, latency: 12.4, metricLabel: "ACC", active: false, threshold: 75, lastConfidence: null },
  { name: "Port Scan XGBoost", short: "SCAN", accuracy: 96.4, latency: 3.9, metricLabel: "F1", active: false, threshold: 88, lastConfidence: null },
  { name: "Exfil VAE", short: "EXFIL", accuracy: 91.2, latency: 9.6, metricLabel: "AUC", active: false, threshold: 80, lastConfidence: null },
];

// Full MITRE ATT&CK tactic columns (enterprise), a handful mapped to
// techniques NetSentinel actually emits (alert_manager static map).
export const MITRE_TACTICS: { tactic: string; technique: string; id: string }[] = [
  { tactic: "Reconnaissance", technique: "Active Scanning", id: "T1595" },
  { tactic: "Initial Access", technique: "Exploit Public App", id: "T1190" },
  { tactic: "Execution", technique: "Command & Scripting", id: "T1059" },
  { tactic: "Persistence", technique: "Scheduled Task", id: "T1053" },
  { tactic: "Defense Evasion", technique: "Obfuscated Files", id: "T1027" },
  { tactic: "Discovery", technique: "Network Service Disc.", id: "T1046" },
  { tactic: "Command & Control", technique: "App Layer Protocol", id: "T1071" },
  { tactic: "Command & Control", technique: "Dynamic Resolution", id: "T1568" },
  { tactic: "Command & Control", technique: "Encrypted Channel", id: "T1573" },
  { tactic: "Exfiltration", technique: "Exfil Over C2", id: "T1041" },
  { tactic: "Impact", technique: "Network DoS", id: "T1498" },
  { tactic: "Impact", technique: "Endpoint DoS", id: "T1499" },
];

export function emptyMitre(): MitreCell[] {
  return MITRE_TACTICS.map((m) => ({ ...m, hits: 0 }));
}

const INTERNAL = ["10.0.0.14", "10.0.0.22", "10.0.1.7", "192.168.1.40", "10.0.0.9"];
const EXTERNAL = ["185.220.101.4", "45.153.160.132", "91.219.236.19", "104.244.72.115", "23.129.64.210"];
const DGA_DOMAINS = ["xkqw8f3m.xyz", "vb7zp2qk.info", "m9x4tzwq.top", "q1k8fjxn.club"];

let seq = 0;
const id = () => `al-${Date.now()}-${seq++}`;
const pick = <T,>(a: T[]) => a[Math.floor(Math.random() * a.length)];
const jit = (base: number, spread: number) => +(base + (Math.random() - 0.5) * spread).toFixed(1);
const port = () => 1024 + Math.floor(Math.random() * 64000);
const tuple = (
  srcIp: string,
  dstIp: string,
  dstPort: number,
  protocol: "TCP" | "UDP" | "ICMP" = "TCP",
): import("../types/alert").FlowTuple => ({ srcIp, srcPort: port(), dstIp, dstPort, protocol });

// A scripted event on the 60s demo timeline (README §"Demo Script").
export interface ScriptEvent {
  atMs: number;
  make: () => Alert;
}

function benign(): Alert {
  const src = pick(INTERNAL);
  const dst = pick(["142.250.72.14", "13.107.42.14", "151.101.1.140"]);
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "Benign",
    severity: "info",
    sourceIP: src,
    destIP: dst,
    flow: tuple(src, dst, 443),
    confidence: jit(62, 20),
    model: "ETT Transformer",
    indicators: ["Nominal flow rate", "Bidirectional handshake complete"],
  };
}

function ddos(): Alert {
  const src = pick(EXTERNAL);
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "DDoS",
    severity: "critical",
    sourceIP: src,
    destIP: "10.0.0.14",
    flow: tuple(src, "10.0.0.14", 80),
    confidence: jit(99.5, 0.6),
    mitreTechnique: "Network DoS",
    mitreTactic: "Impact",
    model: "DDoS XGBoost",
    // Volumetric floods spray spoofed sources → very high src-IP entropy.
    srcIpEntropy: jit(15.7, 0.6),
    indicators: [
      "SYN flood — 61.2K pps",
      "Packet size variance ≈ 0",
      "Handshake completion 0.4%",
      "Fwd/bwd ratio 240:1",
      "Source-IP entropy 15.7 bits (≈52K uniques)",
    ],
  };
}

function c2(): Alert {
  const dst = pick(EXTERNAL);
  const interval = jit(58.3, 1.4);
  // Near-constant inter-arrival times — the beacon clock.
  const iat = Array.from({ length: 12 }, () => +(interval + (Math.random() - 0.5) * 2.6).toFixed(1));
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "C2 Beacon",
    severity: "high",
    sourceIP: "10.0.0.22",
    destIP: dst,
    flow: tuple("10.0.0.22", dst, 8443),
    confidence: jit(94, 3),
    mitreTechnique: "App Layer Protocol",
    mitreTactic: "Command & Control",
    model: "C2 BiLSTM+FFT",
    beaconInterval: interval,
    iat,
    indicators: [
      "Dominant FFT freq 0.0172 Hz",
      `Beacon interval ${interval}s ± 5%`,
      "Spectral entropy 0.19",
      "Neris botnet signature",
    ],
  };
}

function dga(): Alert {
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "DGA",
    severity: "high",
    sourceIP: "10.0.1.7",
    destIP: "8.8.8.8",
    domain: pick(DGA_DOMAINS),
    flow: tuple("10.0.1.7", "8.8.8.8", 53, "UDP"),
    confidence: jit(93, 3),
    mitreTechnique: "Dynamic Resolution",
    mitreTactic: "Command & Control",
    model: "DGA CNN-BiLSTM",
    classProbs: [
      { label: "Cryptolocker", p: jit(0.71, 0.08) },
      { label: "Conficker", p: jit(0.14, 0.04) },
      { label: "Necurs", p: jit(0.08, 0.03) },
      { label: "Legit", p: jit(0.03, 0.02) },
    ],
    indicators: [
      "Shannon entropy 4.2",
      "Bigram score 0.02 (non-English)",
      "Consonant ratio 0.81",
      "Cryptolocker family",
    ],
  };
}

function portScan(): Alert {
  const src = pick(EXTERNAL);
  const dst = pick(INTERNAL);
  // One source sweeping a spread of destination ports — the fan-out signal.
  const common = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080];
  const ports = Array.from({ length: 64 }, (_, i) => (i < common.length ? common[i] : 1000 + i * 137));
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "Port Scan",
    severity: "medium",
    sourceIP: src,
    destIP: dst,
    flow: tuple(src, dst, common[0]),
    confidence: jit(90, 5),
    mitreTechnique: "Network Service Disc.",
    mitreTactic: "Discovery",
    model: "Port Scan XGBoost",
    fanOut: { targetIp: dst, ports, window: 8 },
    indicators: ["Vertical scan — 64 ports / 8s", "1 src → 64 dst ports", "No completed sessions"],
  };
}

function encrypted(): Alert {
  const src = pick(INTERNAL);
  const dst = pick(EXTERNAL);
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "Encrypted",
    severity: "medium",
    sourceIP: src,
    destIP: dst,
    flow: tuple(src, dst, 443),
    confidence: jit(84, 6),
    mitreTechnique: "Encrypted Channel",
    mitreTactic: "Command & Control",
    model: "ETT Transformer",
    ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
    ja4Rarity: jit(0.97, 0.02),
    indicators: [
      "JA4 fingerprint seen in 0.3% of baseline",
      "TLS 1.3 · non-standard cipher order",
      "Malware TLS client signature",
    ],
  };
}

function exfil(): Alert {
  const src = pick(INTERNAL);
  const dst = pick(EXTERNAL);
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "Exfiltration",
    severity: "critical",
    sourceIP: src,
    destIP: dst,
    flow: tuple(src, dst, 443),
    confidence: jit(88, 5),
    mitreTechnique: "Exfil Over C2",
    mitreTactic: "Exfiltration",
    model: "Exfil VAE",
    // Heavy outbound vs. trivial inbound — the exfil asymmetry.
    byteRatio: { outbound: Math.round(jit(48_200_000, 6_000_000)), inbound: Math.round(jit(180_000, 60_000)) },
    indicators: [
      "Outbound/inbound byte ratio 268:1",
      "48.2 MB uploaded in 40s burst",
      "VAE reconstruction error 4.7σ above baseline",
      "Sustained transfer to single external host",
    ],
  };
}

// The looping 60-second demo timeline.
export const DEMO_SCRIPT: ScriptEvent[] = [
  { atMs: 12_000, make: ddos },
  { atMs: 22_000, make: c2 },
  { atMs: 32_000, make: dga },
  { atMs: 40_000, make: encrypted },
  { atMs: 48_000, make: portScan },
  { atMs: 55_000, make: exfil },
];

export const PHASES: { atMs: number; label: string }[] = [
  { atMs: 0, label: "Baseline monitoring" },
  { atMs: 12_000, label: "Volumetric DDoS — SYN flood" },
  { atMs: 22_000, label: "C2 beacon correlation" },
  { atMs: 32_000, label: "DGA domain resolution" },
  { atMs: 40_000, label: "Encrypted tunnel analysis" },
  { atMs: 48_000, label: "Port scan fan-out" },
  { atMs: 55_000, label: "Data exfiltration burst" },
];

export function phaseFor(ms: number): string {
  let label = PHASES[0].label;
  for (const p of PHASES) if (ms >= p.atMs) label = p.label;
  return label;
}

export function makeBenign() {
  return benign();
}

// Base packets/sec envelope over the loop, spiking during DDoS.
export function basePps(ms: number): number {
  const s = ms / 1000;
  let pps = 900 + Math.sin(s / 3) * 180 + Math.random() * 120;
  if (s >= 12 && s < 20) pps += 42_000 * Math.min(1, (s - 12) / 1.5); // DDoS spike
  if (s >= 48 && s < 52) pps += 2_400; // port scan fan-out
  return Math.round(pps);
}

export const THREAT_TO_TACTIC: Record<ThreatType, string> = {
  DDoS: "Impact",
  "C2 Beacon": "Command & Control",
  DGA: "Command & Control",
  Encrypted: "Command & Control",
  "Port Scan": "Discovery",
  Exfiltration: "Exfiltration",
  Benign: "",
};

export const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
