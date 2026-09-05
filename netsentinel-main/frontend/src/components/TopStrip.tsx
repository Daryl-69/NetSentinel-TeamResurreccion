import { Activity, Gauge, Layers, ShieldOff } from "lucide-react";
import type { FeedState, Severity } from "../types/alert";
import { SEVERITY_COLOR } from "../types/alert";

const DIST: Severity[] = ["critical", "high", "medium", "low"];

export default function TopStrip({ feed }: { feed: FeedState }) {
  // Inference latency = the detector that fired most recently, else pipeline mean.
  const active = feed.models.find((m) => m.active);
  const meanLatency = feed.models.reduce((s, m) => s + m.latency, 0) / feed.models.length;
  const latency = active ? active.latency : meanLatency;

  return (
    <div className="grid gap-4 lg:gap-5 lg:grid-cols-[repeat(3,minmax(0,1fr))_1.5fr]">
      <Metric
        icon={<Activity size={14} />}
        label="Flows / sec"
        value={feed.flowsPerSec.toFixed(1)}
        sub={`${feed.totalFlows.toLocaleString()} total`}
      />
      <Metric
        icon={<Gauge size={14} />}
        label="Inference latency"
        value={`${latency.toFixed(1)}`}
        unit="ms"
        sub={active ? active.name : "pipeline mean"}
      />
      <Metric
        icon={<Layers size={14} />}
        label="Detectors online"
        value={`${feed.models.length}`}
        sub="6 threat classes"
      />

      {/* severity distribution + passive-sensor callout */}
      <section className="panel-base flex items-center justify-between gap-4 px-4 py-3">
        <div className="flex flex-col gap-2 min-w-0">
          <span className="label-mono text-[8.5px]">Severity distribution</span>
          <div className="flex items-end gap-3">
            {DIST.map((s) => {
              const n = feed.threatCounts[s] ?? 0;
              return (
                <div key={s} className="flex flex-col items-center gap-1">
                  <span className="mono text-[17px] font-bold tabular-nums leading-none" style={{ color: SEVERITY_COLOR[s] }}>
                    {n}
                  </span>
                  <span className="label-mono text-[7px] text-[var(--text-dim)]">{s}</span>
                </div>
              );
            })}
          </div>
        </div>
        <div className="flex items-center gap-2 pl-4 border-l border-[var(--bg-border)] shrink-0 max-w-[180px]">
          <ShieldOff size={13} className="text-[var(--text-dim)] shrink-0" />
          <p className="text-[9px] leading-tight text-[var(--text-dim)]">
            Passive sensor — detection only, no automated response
          </p>
        </div>
      </section>
    </div>
  );
}

function Metric({
  icon,
  label,
  value,
  unit,
  sub,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  unit?: string;
  sub: string;
}) {
  return (
    <section className="panel-base px-4 py-3 flex flex-col gap-1.5">
      <div className="flex items-center gap-2 label-mono text-[8.5px]">
        <span className="text-[var(--text-muted)]">{icon}</span>
        {label}
      </div>
      <div className="mono text-[26px] font-bold leading-none tabular-nums">
        {value}
        {unit && <span className="text-[13px] text-[var(--text-muted)] ml-1">{unit}</span>}
      </div>
      <div className="label-mono text-[8px] text-[var(--text-dim)] truncate">{sub}</div>
    </section>
  );
}
