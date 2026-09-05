import { FileSearch, Radio, ShieldOff } from "lucide-react";
import type { Alert } from "../types/alert";
import { SEVERITY_COLOR } from "../types/alert";
import { SeverityTag } from "./AlertFeed";

// The evidence panel is the NTRO alert schema made visible:
//   { timestamp, flow id (5-tuple), threat class, confidence, evidence }
export default function EvidencePanel({ alert }: { alert: Alert | null }) {
  if (!alert) {
    return (
      <section className="panel-base flex flex-col items-center justify-center gap-3 p-6 h-full text-center">
        <FileSearch size={24} className="text-[var(--text-dim)]" />
        <p className="text-[13px] font-medium">Select an alert</p>
        <p className="label-mono text-[9.5px] text-[var(--text-dim)]">
          Pick a row from the triage queue to inspect its evidence
        </p>
      </section>
    );
  }

  const color = SEVERITY_COLOR[alert.severity];
  const f = alert.flow;
  const flowId = f
    ? `${f.srcIp}:${f.srcPort} → ${f.dstIp}:${f.dstPort} · ${f.protocol}`
    : `${alert.sourceIP} → ${alert.domain ?? alert.destIP ?? "—"}`;

  return (
    <section
      className="panel-base scan-container flex flex-col min-h-0 h-full overflow-hidden"
      style={{ borderColor: `color-mix(in srgb, ${color} 40%, transparent)` }}
    >
      <div className="absolute inset-x-0 top-0 h-[2px]" style={{ background: `linear-gradient(90deg, transparent, ${color}, transparent)` }} />

      <div className="flex items-start justify-between gap-3 px-4 py-3.5 border-b border-[var(--bg-border)]">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="h-2.5 w-2.5 rounded-full shrink-0 pulse-dot" style={{ color, background: color }} />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-[15px] font-semibold truncate">{alert.threatType}</h2>
              <SeverityTag severity={alert.severity} />
            </div>
            <p className="label-mono mt-0.5 text-[8.5px] text-[var(--text-dim)]">{alert.model}</p>
          </div>
        </div>
        <div className="text-right animate-pop shrink-0" key={alert.id}>
          <div className="mono text-[22px] font-bold leading-none tabular-nums" style={{ color }}>
            {alert.confidence.toFixed(1)}
            <span className="text-[11px]">%</span>
          </div>
          <div className="label-mono mt-0.5 text-[8px]">confidence</div>
        </div>
      </div>

      <div className="overflow-y-auto min-h-0 flex-1 p-4 space-y-3">
        {/* NTRO schema block */}
        <Field label="Timestamp" value={new Date(alert.timestamp).toISOString().replace("T", " ").replace("Z", " UTC")} />
        <Field label="Flow ID · 5-tuple" value={flowId} accent />
        <div className="grid grid-cols-2 gap-2">
          <Field label="Threat class" value={alert.threatType} />
          <Field label="Detector" value={alert.model} />
        </div>
        {alert.mitreTechnique && (
          <Field label="MITRE ATT&CK" value={`${alert.mitreTactic ?? ""} · ${alert.mitreTechnique}`} />
        )}

        {/* Per-class evidence mini-visualisations */}
        {alert.iat && alert.iat.length > 0 && <BeaconClock iat={alert.iat} interval={alert.beaconInterval} color={color} />}
        {alert.classProbs && <ClassProbs probs={alert.classProbs} color={color} />}
        {alert.ja4 && <Ja4 fp={alert.ja4} rarity={alert.ja4Rarity} color={color} />}

        {/* Supporting evidence */}
        <div className="panel-inset p-3">
          <div className="label-mono text-[8.5px] mb-2 flex items-center gap-1.5">
            <Radio size={10} /> Supporting evidence
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

        {/* Passive-monitor callout — NetSentinel observes, it does not act. */}
        <div className="panel-inset p-3 flex items-start gap-2.5">
          <ShieldOff size={13} className="text-[var(--text-dim)] mt-0.5 shrink-0" />
          <p className="text-[10.5px] leading-relaxed text-[var(--text-dim)]">
            Passive detection sensor — no block, quarantine, or mitigation actions.
            NetSentinel monitors a unidirectional tap and raises evidence for the SOC to act on.
          </p>
        </div>
      </div>
    </section>
  );
}

function Field({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="panel-inset px-3 py-2">
      <div className="label-mono text-[8px]">{label}</div>
      <div className="mono text-[11.5px] mt-0.5 break-all" style={{ color: accent ? "var(--text-main)" : "var(--text-muted)" }}>
        {value}
      </div>
    </div>
  );
}

// C2 beacon clock — inter-arrival ticks. Near-uniform spacing = machine cadence.
function BeaconClock({ iat, interval, color }: { iat: number[]; interval?: number; color: string }) {
  const max = Math.max(...iat);
  return (
    <div className="panel-inset p-3">
      <div className="flex items-center justify-between mb-2">
        <div className="label-mono text-[8.5px]">Beacon clock · inter-arrival</div>
        {interval && <span className="mono text-[9px] text-[var(--text-muted)]">≈ {interval}s period</span>}
      </div>
      <div className="flex items-end gap-1 h-10">
        {iat.map((v, i) => (
          <div key={i} className="flex-1 rounded-t" style={{ height: `${(v / max) * 100}%`, background: color, opacity: 0.55 + 0.35 * (v / max) }} />
        ))}
      </div>
    </div>
  );
}

// DGA per-family probabilities — softmax over the classifier head.
function ClassProbs({ probs, color }: { probs: { label: string; p: number }[]; color: string }) {
  return (
    <div className="panel-inset p-3">
      <div className="label-mono text-[8.5px] mb-2">Family probability</div>
      <div className="space-y-1.5">
        {probs.map((c) => (
          <div key={c.label} className="flex items-center gap-2">
            <span className="mono text-[10px] w-20 shrink-0 truncate text-[var(--text-muted)]">{c.label}</span>
            <div className="flex-1 h-1.5 rounded-full bg-[var(--bg-border)] overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${c.p * 100}%`, background: color }} />
            </div>
            <span className="mono text-[9.5px] tabular-nums w-9 text-right text-[var(--text-dim)]">
              {(c.p * 100).toFixed(0)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Encrypted-malware JA4 fingerprint + rarity vs. baseline.
function Ja4({ fp, rarity, color }: { fp: string; rarity?: number; color: string }) {
  return (
    <div className="panel-inset p-3">
      <div className="flex items-center justify-between mb-1.5">
        <div className="label-mono text-[8.5px]">JA4 fingerprint</div>
        {rarity !== undefined && (
          <span className="mono text-[9px]" style={{ color }}>
            {(rarity * 100).toFixed(0)}% rare
          </span>
        )}
      </div>
      <div className="mono text-[10px] break-all text-[var(--text-muted)]">{fp}</div>
    </div>
  );
}
