import { useMemo, useState } from "react";
import { ListFilter } from "lucide-react";
import type { Alert } from "../types/alert";
import { SEVERITY_COLOR, SEVERITY_RANK } from "../types/alert";
import { SeverityTag } from "./AlertFeed";

interface Props {
  alerts: Alert[];
  selectedId: string | null;
  onSelect: (a: Alert) => void;
}

type Filter = "risk" | "recent";

// Risk = severity band first, confidence second (Vectra Attack Signal
// Intelligence: rank by what the analyst should look at, not arrival order).
const riskScore = (a: Alert) => SEVERITY_RANK[a.severity] * 1000 + a.confidence;

export default function RiskStream({ alerts, selectedId, onSelect }: Props) {
  const [filter, setFilter] = useState<Filter>("risk");

  const rows = useMemo(() => {
    const threats = alerts.filter((a) => a.threatType !== "Benign");
    if (filter === "recent") return [...threats].sort((a, b) => b.timestamp - a.timestamp);
    return [...threats].sort((a, b) => riskScore(b) - riskScore(a) || b.timestamp - a.timestamp);
  }, [alerts, filter]);

  return (
    <section className="panel-base flex flex-col min-h-0 h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--bg-border)]">
        <div className="flex items-center gap-2">
          <ListFilter size={14} className="text-[var(--text-muted)]" />
          <h2 className="text-[13px] font-semibold">Triage Queue</h2>
          <span className="label-mono text-[9px] text-[var(--text-dim)]">{rows.length} open</span>
        </div>
        <div className="flex gap-1.5">
          {(["risk", "recent"] as Filter[]).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`btn-ghost !py-1 !px-2.5 !text-[10px] label-mono ${filter === f ? "is-active" : ""}`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-y-auto min-h-0 flex-1">
        {rows.length === 0 ? (
          <div className="px-4 py-10 text-center label-mono text-[10px] text-[var(--text-dim)]">
            No open threats — baseline nominal
          </div>
        ) : (
          <ul>
            {rows.map((a, i) => (
              <RiskRow key={a.id} alert={a} index={i} selected={a.id === selectedId} onSelect={onSelect} />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function RiskRow({
  alert,
  index,
  selected,
  onSelect,
}: {
  alert: Alert;
  index: number;
  selected: boolean;
  onSelect: (a: Alert) => void;
}) {
  const color = SEVERITY_COLOR[alert.severity];
  const time = new Date(alert.timestamp).toLocaleTimeString("en-GB", { hour12: false });
  const target = alert.domain ?? alert.destIP ?? "—";

  return (
    <li
      onClick={() => onSelect(alert)}
      className="animate-row group relative flex flex-col gap-1.5 px-4 py-3 border-b border-[var(--bg-border)] cursor-pointer transition-colors hover:bg-[var(--bg-surface-hover)]"
      style={{
        animationDelay: `${Math.min(index, 8) * 22}ms`,
        background: selected ? "var(--bg-surface-hover)" : undefined,
      }}
    >
      {selected && <span className="absolute inset-y-0 left-0 w-[2px]" style={{ background: color }} />}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="h-2 w-2 rounded-full shrink-0" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
          <span className="text-[12.5px] font-medium truncate">{alert.threatType}</span>
          <SeverityTag severity={alert.severity} />
        </div>
        <span className="mono text-[12px] tabular-nums shrink-0" style={{ color }}>
          {alert.confidence.toFixed(1)}%
        </span>
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className="mono text-[10px] text-[var(--text-muted)] truncate">
          {alert.sourceIP} → {target}
        </span>
        <span className="mono text-[9.5px] text-[var(--text-dim)] shrink-0">{time}</span>
      </div>
      {/* confidence bar — instant read on model certainty */}
      <div className="h-[2px] w-full rounded-full bg-[var(--bg-border)] overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${alert.confidence}%`, background: color }} />
      </div>
    </li>
  );
}
