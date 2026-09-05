import { useMemo, useState } from "react";
import type { Alert, Severity } from "../types/alert";
import { SEVERITY_COLOR } from "../types/alert";

interface Props {
  alerts: Alert[];
  onSelect: (a: Alert) => void;
}

type Filter = "all" | "threats" | "critical";

export default function AlertFeed({ alerts, onSelect }: Props) {
  const [filter, setFilter] = useState<Filter>("threats");

  const rows = useMemo(() => {
    if (filter === "all") return alerts;
    if (filter === "critical") return alerts.filter((a) => a.severity === "critical" || a.severity === "high");
    return alerts.filter((a) => a.threatType !== "Benign");
  }, [alerts, filter]);

  return (
    <section className="panel-base flex flex-col min-h-0">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--bg-border)]">
        <div className="flex items-center gap-2">
          <h2 className="text-[13px] font-semibold">Live Alert Feed</h2>
          <span className="label-mono text-[9px] text-[var(--text-dim)]">{rows.length} shown</span>
        </div>
        <div className="flex gap-1.5">
          {(["all", "threats", "critical"] as Filter[]).map((f) => (
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
            No alerts in view
          </div>
        ) : (
          <ul>
            {rows.map((a, i) => (
              <AlertRow key={a.id} alert={a} index={i} onSelect={onSelect} />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function AlertRow({ alert, index, onSelect }: { alert: Alert; index: number; onSelect: (a: Alert) => void }) {
  const color = SEVERITY_COLOR[alert.severity];
  const time = new Date(alert.timestamp).toLocaleTimeString("en-GB", { hour12: false });
  const target = alert.domain ?? alert.destIP ?? "—";

  return (
    <li
      onClick={() => onSelect(alert)}
      className="animate-row group grid grid-cols-[auto_64px_1fr_auto] items-center gap-3 px-4 py-2.5 border-b border-[var(--bg-border)] cursor-pointer hover:bg-[var(--bg-surface-hover)] transition-colors"
      style={{ animationDelay: `${Math.min(index, 8) * 22}ms` }}
    >
      <span
        className="h-2 w-2 rounded-full shrink-0"
        style={{ background: color, boxShadow: `0 0 8px ${color}` }}
      />
      <span className="mono text-[10.5px] text-[var(--text-dim)]">{time}</span>
      <span className="min-w-0 flex items-center gap-2">
        <SeverityTag severity={alert.severity} />
        <span className="text-[12px] font-medium truncate">{alert.threatType}</span>
        <span className="mono text-[10.5px] text-[var(--text-muted)] truncate hidden sm:inline">
          {alert.sourceIP} → {target}
        </span>
      </span>
      <span className="mono text-[11px] tabular-nums" style={{ color }}>
        {alert.confidence.toFixed(1)}%
      </span>
    </li>
  );
}

export function SeverityTag({ severity }: { severity: Severity }) {
  const color = SEVERITY_COLOR[severity];
  return (
    <span
      className="label-mono text-[8.5px] px-1.5 py-0.5 rounded border shrink-0"
      style={{ color, borderColor: color, background: `color-mix(in srgb, ${color} 12%, transparent)` }}
    >
      {severity}
    </span>
  );
}
