import { Gauge } from "lucide-react";
import type { ModelStat } from "../types/alert";

// Per-model horizontal band: fill = latest confidence, tick = decision
// threshold. Makes "why did this fire" legible — a bar past its tick is a
// firing detection; below it is suppressed.
export default function ConfidenceBands({ models }: { models: ModelStat[] }) {
  return (
    <section className="panel-base flex flex-col overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--bg-border)]">
        <Gauge size={14} className="text-[var(--text-muted)]" />
        <h2 className="text-[13px] font-semibold">Confidence vs Threshold</h2>
      </div>

      <div className="flex-1 flex flex-col justify-center gap-4 px-4 py-4">
        {models.map((m) => {
          const conf = m.lastConfidence;
          const firing = conf != null && conf >= m.threshold;
          const color = firing ? "var(--sev-high)" : "var(--text-muted)";
          return (
            <div key={m.name}>
              <div className="flex items-center justify-between mb-1.5">
                <span className="label-mono text-[9px] normal-case tracking-[0.04em]">{m.name}</span>
                <span className="mono text-[11px]" style={{ color: conf == null ? "var(--text-dim)" : color }}>
                  {conf == null ? "idle" : `${conf.toFixed(1)}%`}
                </span>
              </div>
              <div className="relative h-2 rounded-full bg-[var(--bg-inset)] border border-[var(--bg-border)] overflow-visible">
                <div
                  className="absolute inset-y-0 left-0 rounded-full transition-all duration-700"
                  style={{
                    width: `${conf ?? 0}%`,
                    background: color,
                    boxShadow: firing ? `0 0 8px ${color}` : "none",
                  }}
                />
                {/* threshold tick */}
                <div
                  className="absolute top-1/2 -translate-y-1/2 h-3.5 w-[2px] bg-[var(--text-main)]"
                  style={{ left: `${m.threshold}%` }}
                  title={`Threshold ${m.threshold}%`}
                />
              </div>
            </div>
          );
        })}
      </div>

      <div className="flex items-center gap-4 px-4 pb-3 pt-1 border-t border-[var(--bg-border)]">
        <span className="flex items-center gap-1.5 label-mono text-[8px]">
          <span className="h-2 w-3 rounded-sm" style={{ background: "var(--sev-high)" }} /> firing
        </span>
        <span className="flex items-center gap-1.5 label-mono text-[8px]">
          <span className="h-3 w-[2px] bg-[var(--text-main)]" /> threshold
        </span>
      </div>
    </section>
  );
}
