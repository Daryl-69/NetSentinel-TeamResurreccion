import { X } from "lucide-react";
import type { Alert } from "../types/alert";
import { SEVERITY_COLOR } from "../types/alert";
import { SeverityTag } from "./AlertFeed";

export default function AlertDetailModal({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const color = SEVERITY_COLOR[alert.severity];
  const target = alert.domain ?? alert.destIP ?? "—";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)" }}
      onClick={onClose}
    >
      <div
        className="glass-card animate-neural w-full max-w-lg p-6 relative"
        style={{ borderColor: `color-mix(in srgb, ${color} 45%, transparent)` }}
        onClick={(e) => e.stopPropagation()}
      >
        <button
          className="absolute top-4 right-4 text-[var(--text-dim)] hover:text-[var(--text-main)] transition-colors"
          onClick={onClose}
        >
          <X size={18} />
        </button>

        <div className="flex items-center gap-2.5">
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: color, boxShadow: `0 0 10px ${color}` }} />
          <h2 className="text-[18px] font-semibold">{alert.threatType}</h2>
          <SeverityTag severity={alert.severity} />
        </div>
        <p className="label-mono text-[9px] mt-1.5 text-[var(--text-dim)]">
          {alert.model} · {new Date(alert.timestamp).toLocaleString("en-GB", { hour12: false })}
        </p>

        <div className="grid grid-cols-2 gap-2 mt-5">
          <Field label="Source IP" value={alert.sourceIP} />
          <Field label={alert.domain ? "Domain" : "Destination"} value={target} />
          <Field label="Confidence" value={`${alert.confidence.toFixed(1)}%`} accent={color} />
          {alert.mitreTechnique && <Field label="MITRE Technique" value={alert.mitreTechnique} />}
          {alert.mitreTactic && <Field label="Tactic" value={alert.mitreTactic} />}
          {alert.beaconInterval && <Field label="Beacon interval" value={`${alert.beaconInterval}s`} />}
        </div>

        <div className="panel-inset mt-4 p-4">
          <div className="label-mono text-[8.5px] mb-2.5">Detection indicators</div>
          <ul className="space-y-2">
            {alert.indicators.map((ind, i) => (
              <li key={i} className="flex items-start gap-2 text-[12px] text-[var(--text-muted)]">
                <span className="mt-1.5 h-1 w-1 rounded-full shrink-0" style={{ background: color }} />
                <span className="mono">{ind}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="panel-inset px-3 py-2.5">
      <div className="label-mono text-[8px]">{label}</div>
      <div className="mono text-[13px] mt-1 truncate" style={{ color: accent ?? "var(--text-main)" }}>
        {value}
      </div>
    </div>
  );
}
