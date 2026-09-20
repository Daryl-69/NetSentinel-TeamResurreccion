import { useMemo, useState } from "react";
import { Boxes } from "lucide-react";
import type { Alert } from "../types/alert";
import { buildGraph } from "../data/geo";
import type { GraphData } from "../data/geo";
import ForceGraph3DInner from "./ForceGraph3DInner";

// three.js is imported statically: the preview sandbox can't reliably
// resolve dynamically imported dep chunks, so we bundle it directly.

const HEX: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#facc15",
  low: "#22c55e",
  info: "#9ca3af",
};

type Mode = "3d" | "2d" | "map";

export default function ThreatGraph({ alerts }: { alerts: Alert[] }) {
  const [mode, setMode] = useState<Mode>("3d");
  const data = useMemo(() => buildGraph(alerts.slice(0, 40)), [alerts]);

  return (
    <section className="panel-base relative flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--bg-border)] z-10">
        <div className="flex items-center gap-2">
          <Boxes size={14} className="text-[var(--text-muted)]" />
          <h2 className="text-[13px] font-semibold">
            {mode === "map" ? "Network Topology" : "Attack Correlation Graph"}
          </h2>
          <span className="label-mono text-[9px] text-[var(--text-dim)]">
            {data.nodes.length} nodes · {data.links.length} edges
          </span>
        </div>
        <div className="flex gap-1.5">
          {(["3d", "2d", "map"] as Mode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`btn-ghost !py-1 !px-2.5 !text-[10px] label-mono ${mode === m ? "is-active" : ""}`}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      <div className="relative flex-1 min-h-[300px]">
        {data.nodes.length === 0 ? (
          <Empty />
        ) : mode === "3d" ? (
          <ForceGraph3DInner data={data} />
        ) : mode === "2d" ? (
          <Graph2D data={data} />
        ) : (
          <TopologyMap data={data} />
        )}
        {mode !== "map" && <Legend />}
      </div>
    </section>
  );
}

function Legend() {
  const items = [
    { c: "#ef4444", l: "critical" },
    { c: "#f97316", l: "high" },
    { c: "#facc15", l: "medium" },
    { c: "#ffffff", l: "domain" },
  ];
  return (
    <div className="absolute bottom-3 left-4 flex gap-3 z-10">
      {items.map((i) => (
        <span key={i.l} className="flex items-center gap-1.5 label-mono text-[8.5px]">
          <span className="h-2 w-2 rounded-full" style={{ background: i.c }} />
          {i.l}
        </span>
      ))}
    </div>
  );
}

function Empty() {
  return (
    <div className="absolute inset-0 flex items-center justify-center">
      <p className="label-mono text-[10px] text-[var(--text-dim)]">Awaiting correlated threats…</p>
    </div>
  );
}

const idOf = (v: unknown) => (typeof v === "string" ? v : (v as any).id);

// Lightweight SVG 2D fallback — no WebGL, radial layout.
function Graph2D({ data }: { data: GraphData }) {
  const layout = useMemo(() => {
    const n = data.nodes.length;
    const pos = new Map<string, { x: number; y: number }>();
    data.nodes.forEach((node, i) => {
      const angle = (i / Math.max(1, n)) * Math.PI * 2;
      const radius = node.kind === "domain" ? 34 : 42;
      pos.set(node.id, { x: 50 + Math.cos(angle) * radius, y: 50 + Math.sin(angle) * radius });
    });
    return pos;
  }, [data]);

  return (
    <svg viewBox="0 0 100 100" className="absolute inset-0 h-full w-full" preserveAspectRatio="xMidYMid meet">
      {data.links.map((l, i) => {
        const s = layout.get(idOf(l.source));
        const t = layout.get(idOf(l.target));
        if (!s || !t) return null;
        return (
          <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke={HEX[l.severity]} strokeWidth={l.severity === "critical" ? 0.5 : 0.25} strokeOpacity={0.45} />
        );
      })}
      {data.nodes.map((node) => {
        const p = layout.get(node.id);
        if (!p) return null;
        const color = node.kind === "domain" ? "#ffffff" : HEX[node.severity];
        const r = 1 + Math.min(3, node.val * 0.3);
        return (
          <circle key={node.id} cx={p.x} cy={p.y} r={r} fill={color} opacity={0.9}>
            {node.hot && <animate attributeName="r" values={`${r};${r + 1.2};${r}`} dur="1.6s" repeatCount="indefinite" />}
          </circle>
        );
      })}
    </svg>
  );
}

// Honest "map": a NETWORK topology, not a geographic one. NetSentinel sees
// internal subnet ↔ gateway ↔ external hosts — no real geo-IP — so this
// lays out by network position instead of inventing lat/long.
function TopologyMap({ data }: { data: GraphData }) {
  const layout = useMemo(() => {
    const pos = new Map<string, { x: number; y: number }>();
    const internal = data.nodes.filter((n) => n.kind === "internal");
    const external = data.nodes.filter((n) => n.kind === "external");
    const domains = data.nodes.filter((n) => n.kind === "domain");

    const spread = (arr: typeof data.nodes, x: number, pad = 14) => {
      arr.forEach((n, i) => {
        const y = arr.length === 1 ? 50 : pad + (i / (arr.length - 1)) * (100 - 2 * pad);
        pos.set(n.id, { x, y });
      });
    };
    spread(internal, 20);
    spread(external, 80);
    spread(domains, 92, 22);
    return pos;
  }, [data]);

  return (
    <svg viewBox="0 0 100 100" className="absolute inset-0 h-full w-full" preserveAspectRatio="xMidYMid meet">
      {/* zone guides */}
      <line x1="50" y1="6" x2="50" y2="94" stroke="rgba(255,255,255,0.08)" strokeDasharray="1 2" strokeWidth="0.3" />
      <text x="20" y="10" fill="#444" fontSize="3" fontFamily="JetBrains Mono, monospace" textAnchor="middle">
        INTERNAL
      </text>
      <text x="80" y="10" fill="#444" fontSize="3" fontFamily="JetBrains Mono, monospace" textAnchor="middle">
        EXTERNAL
      </text>
      {/* gateway */}
      <circle cx="50" cy="50" r="2.4" fill="none" stroke="#fff" strokeWidth="0.4" />
      <text x="50" y="45" fill="#888" fontSize="2.6" fontFamily="JetBrains Mono, monospace" textAnchor="middle">
        gateway
      </text>

      {data.links.map((l, i) => {
        const s = layout.get(idOf(l.source));
        const t = layout.get(idOf(l.target));
        if (!s || !t) return null;
        // route through the gateway to read as traversing the perimeter
        return (
          <path key={i} d={`M ${s.x} ${s.y} Q 50 50 ${t.x} ${t.y}`} fill="none" stroke={HEX[l.severity]} strokeWidth={l.severity === "critical" ? 0.5 : 0.25} strokeOpacity={0.4} />
        );
      })}
      {data.nodes.map((node) => {
        const p = layout.get(node.id);
        if (!p) return null;
        const color = node.kind === "domain" ? "#ffffff" : HEX[node.severity];
        const r = 1.2 + Math.min(2.6, node.val * 0.28);
        return (
          <g key={node.id}>
            <circle cx={p.x} cy={p.y} r={r} fill={color} opacity={0.92}>
              {node.hot && <animate attributeName="r" values={`${r};${r + 1};${r}`} dur="1.6s" repeatCount="indefinite" />}
            </circle>
            <text x={p.x} y={p.y - r - 1} fill="#666" fontSize="2.2" fontFamily="JetBrains Mono, monospace" textAnchor="middle">
              {node.label.length > 15 ? node.label.slice(0, 14) + "…" : node.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
