import { Cpu } from "lucide-react";
import type { ModelStat } from "../types/alert";

export default function ModelCards({ models }: { models: ModelStat[] }) {
  return (
    <section className="panel-base flex flex-col overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--bg-border)]">
        <Cpu size={14} className="text-[var(--text-muted)]" />
        <h2 className="text-[13px] font-semibold">Inference Models</h2>
        <span className="label-mono text-[9px] text-[var(--text-dim)]">ONNX Runtime</span>
      </div>
      <div className="grid grid-cols-2 gap-2 p-3 flex-1">
        {models.map((m) => (
          <ModelCard key={m.name} model={m} />
        ))}
      </div>
    </section>
  );
}

const CIRC = 2 * Math.PI * 15; // r=15

function ModelCard({ model }: { model: ModelStat }) {
  const offset = CIRC - (model.accuracy / 100) * CIRC;
  return (
    <div
      className="bento-box hover-lift p-3 flex flex-col gap-2"
      style={{ borderColor: model.active ? "var(--bg-border-hover)" : undefined }}
    >
      <div className="flex items-center justify-between">
        <div className="label-mono text-[8px] truncate">{model.short}</div>
        <span
          className={`h-1.5 w-1.5 rounded-full ${model.active ? "pulse-dot" : ""}`}
          style={{
            background: model.active ? "var(--sev-low)" : "var(--text-dim)",
            color: "var(--sev-low)",
          }}
        />
      </div>

      <div className="flex items-center gap-3">
        <svg width="38" height="38" viewBox="0 0 38 38" className="shrink-0 -rotate-90">
          <circle cx="19" cy="19" r="15" fill="none" stroke="var(--bg-border)" strokeWidth="3" />
          <circle
            cx="19"
            cy="19"
            r="15"
            fill="none"
            stroke="#fff"
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray={CIRC}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.9s var(--bezier-out)" }}
          />
        </svg>
        <div>
          <div className="mono text-[16px] font-bold leading-none tabular-nums">{model.accuracy}%</div>
          <div className="label-mono text-[7.5px] mt-1">{model.metricLabel}</div>
        </div>
      </div>

      <div className="flex items-center justify-between border-t border-[var(--bg-border)] pt-2">
        <span className="label-mono text-[7.5px]">Latency</span>
        <span className="mono text-[11px] tabular-nums">{model.latency}ms</span>
      </div>
    </div>
  );
}
