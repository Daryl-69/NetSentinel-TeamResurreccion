import type { Alert } from "../types/alert";
import { SEVERITY_RANK } from "../types/alert";

export interface GraphNode {
  id: string;
  label: string;
  kind: "internal" | "external" | "domain";
  severity: Alert["severity"];
  val: number; // node size = alert volume
  hot: boolean; // part of the most recent alert
}
export interface GraphLink {
  source: string;
  target: string;
  severity: Alert["severity"];
  threat: string;
}
export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

const isInternal = (ip: string) => ip.startsWith("10.") || ip.startsWith("192.168.");

// Build an attacker→target correlation graph from the live alert window.
// This is the direct view of the pipeline's real output (flows + C2/DGA
// correlations) — no invented geo-IP required.
export function buildGraph(alerts: Alert[]): GraphData {
  const nodes = new Map<string, GraphNode>();
  const links: GraphLink[] = [];
  const hotId = alerts[0]?.id;

  const touch = (
    id: string,
    label: string,
    kind: GraphNode["kind"],
    sev: Alert["severity"],
    hot: boolean,
  ) => {
    const n = nodes.get(id);
    if (n) {
      n.val += 1;
      if (SEVERITY_RANK[sev] > SEVERITY_RANK[n.severity]) n.severity = sev;
      if (hot) n.hot = true;
    } else {
      nodes.set(id, { id, label, kind, severity: sev, val: 2, hot });
    }
  };

  for (const a of alerts) {
    if (a.threatType === "Benign") continue;
    const hot = a.id === hotId;
    const srcKind = isInternal(a.sourceIP) ? "internal" : "external";
    touch(a.sourceIP, a.sourceIP, srcKind, a.severity, hot);

    const targetId = a.domain ?? a.destIP;
    if (!targetId) continue;
    const tKind: GraphNode["kind"] = a.domain
      ? "domain"
      : isInternal(targetId)
        ? "internal"
        : "external";
    touch(targetId, targetId, tKind, a.severity, hot);
    links.push({ source: a.sourceIP, target: targetId, severity: a.severity, threat: a.threatType });
  }

  return { nodes: [...nodes.values()], links };
}
