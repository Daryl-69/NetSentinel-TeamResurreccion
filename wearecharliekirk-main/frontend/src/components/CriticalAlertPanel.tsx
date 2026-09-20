import { AlertTriangle, ShieldCheck, Radio } from "lucide-react";
import type { Alert } from "../types/alert";
import { SEVERITY_COLOR } from "../types/alert";
import { SeverityTag } from "./AlertFeed";

interface Props {
  alert: Alert | null;
  onInspect: (a: Alert) => void;
}

export default function CriticalAlertPanel({ alert, onInspect }: Props) {
  if (!alert) {
    return (
      <section className="glass-card flex flex-col items-center justify-center gap-3 p-6">
        <ShieldCheck size={26} className="text-[var(--sev-low)]" />
        <p className="text-[13px] font-medium">All clear</p>
        <p className="label-mono text-[9.5px] text-[var(--text-dim)]">No active threats</p>
      </section>
    );
  }

  const color = SEVERITY_COLOR[alert.severity];
  const target = alert.domain ?? alert.destIP ?? "—";

  return (
    <section
      className="glass-card scan-container flex flex-col p-5 overflow-hidden"
      style={{ borderColor: `color-mix(in srgb, ${color} 45%, transparent)` }}
    >
      <div
        className="absolute inset-x-0 top-0 h-[2px]"
        style={{ background: `linear-gradient(90deg, transparent, ${color}, transparent)` }}
      />
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <AlertTriangle size={18} style={{ color }} className="pulse-dot" />
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-[15px] font-semibold">{alert.threatType}</h2>
              <SeverityTag severity={alert.severity} />
            </div>
            <p className="label-mono mt-1 text-[9px] text-[var(--text-dim)]">
              {alert.model} · {new Date(alert.timestamp).toLocaleTimeString("en-GB", { hour12: false })}
            </p>
          </div>
        </div>
        <div className="text-right animate-pop" key={alert.id}>
          <div className="mono text-[26px] font-bold leading-none tabular-nums" style={{ color }}>
            {alert.confidence.toFixed(1)}
            <span className="text-[13px]">%</span>
          </div>
          <div className="label-mono mt-1 text-[8.5px]">Confidence</div>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2">
        <Field label="Source" value={alert.sourceIP} />
        <Field label={alert.domain ? "Domain" : "Target"} value={target} />
        {alert.mitreTechnique && (
          <Field label="MITRE ATT&CK" value={`${alert.mitreTactic ?? ""} · ${alert.mitreTechnique}`} />
        )}
        {alert.beaconInterval && <Field label="Beacon interval" value={`${alert.beaconInterval}s`} />}
      </div>

      <div className="panel-inset mt-3 p-3">
        <div className="label-mono text-[8.5px] mb-2 flex items-center gap-1.5">
          <Radio size={10} /> Indicators
        </div>
        <ul className="space-y-1.5">
          {alert.indicators.map((ind, i) => (
            <li key={i} className="flex items-start gap-2 text-[11.5px] text-[var(--text-muted)]">
              <span className="mt-1.5 h-1 w-1 rounded-full shrink-0" style={{ background: color }} />
              <span className="mono">{ind}</span>
            </li>
          ))}
        </ul>
      </div>

      <button className="btn-premium mt-4 justify-center w-full" onClick={() => onInspect(alert)}>
        Inspect alert
      </button>
    </section>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="panel-inset px-3 py-2">
      <div className="label-mono text-[8px]">{label}</div>
      <div className="mono text-[12px] mt-0.5 truncate">{value}</div>
    </div>
  );
}
