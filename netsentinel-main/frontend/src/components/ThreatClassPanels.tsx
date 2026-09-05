import { useMemo } from "react";
import { Activity, Grid3x3, ArrowLeftRight } from "lucide-react";
import type { Alert, ThreatType } from "../types/alert";

// These three panels cover the threat classes whose evidence the previous
// dashboard never surfaced: volumetric DDoS (source-IP entropy), recon /
// port scan (src→port fan-out), and data exfiltration (byte-ratio asymmetry).

const latestOf = (alerts: Alert[], t: ThreatType) => alerts.find((a) => a.threatType === t) ?? null;

export default function ThreatClassPanels({ alerts }: { alerts: Alert[] }) {
  const ddos = useMemo(() => latestOf(alerts, "DDoS"), [alerts]);
  const scan = useMemo(() => latestOf(alerts, "Port Scan"), [alerts]);
  const exf = useMemo(() => latestOf(alerts, "Exfiltration"), [alerts]);

  return (
    <div className="grid gap-4 lg:gap-5 lg:grid-cols-3">
      <EntropyGauge alert={ddos} />
      <FanOutGrid alert={scan} />
      <ByteRatioChart alert={exf} />
    </div>
  );
}

function Shell({
  title,
  sub,
  icon,
  children,
}: {
  title: string;
  sub: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="panel-base flex flex-col min-h-[220px]">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--bg-border)]">
        <span className="text-[var(--text-muted)]">{icon}</span>
        <h2 className="text-[13px] font-semibold">{title}</h2>
        <span className="label-mono text-[8.5px] text-[var(--text-dim)] ml-auto">{sub}</span>
      </div>
      <div className="flex-1 p-4">{children}</div>
    </section>
  );
}

function Idle({ label }: { label: string }) {
  return (
    <div className="h-full flex items-center justify-center">
      <p className="label-mono text-[9.5px] text-[var(--text-dim)]">{label}</p>
    </div>
  );
}

// ── DDoS: source-IP entropy gauge ────────────────────────────────────────
// Volumetric floods spray spoofed sources; entropy climbs toward log2(uniques).
const ENTROPY_MAX = 18; // bits — ceiling for the gauge
const ENTROPY_THRESHOLD = 12; // above this, distribution reads as a flood

function EntropyGauge({ alert }: { alert: Alert | null }) {
  const v = alert?.srcIpEntropy;
  const sev = "var(--sev-critical)";
  const frac = v !== undefined ? Math.min(1, v / ENTROPY_MAX) : 0;
  // Semicircle gauge: 180° sweep.
  const R = 52;
  const circ = Math.PI * R; // half circumference
  const dash = circ * frac;

  return (
    <Shell title="Source-IP Entropy" sub="DDoS" icon={<Activity size={14} />}>
      {v === undefined ? (
        <Idle label="No volumetric activity" />
      ) : (
        <div className="flex flex-col items-center">
          <svg viewBox="0 0 120 70" className="w-full max-w-[200px]">
            <path d="M 8 62 A 52 52 0 0 1 112 62" fill="none" stroke="var(--bg-border)" strokeWidth="7" strokeLinecap="round" />
            <path
              d="M 8 62 A 52 52 0 0 1 112 62"
              fill="none"
              stroke={sev}
              strokeWidth="7"
              strokeLinecap="round"
              strokeDasharray={`${dash} ${circ}`}
            />
            {/* threshold tick */}
            <text x="60" y="40" textAnchor="middle" className="mono" fill="#fff" fontSize="17" fontWeight="700">
              {v.toFixed(1)}
            </text>
            <text x="60" y="55" textAnchor="middle" fill="#888" fontSize="6" fontFamily="JetBrains Mono, monospace">
              BITS · SRC-IP SPREAD
            </text>
          </svg>
          <div className="mt-2 flex items-center gap-2 label-mono text-[8.5px] text-[var(--text-dim)]">
            <span>threshold {ENTROPY_THRESHOLD} bits</span>
            <span style={{ color: v >= ENTROPY_THRESHOLD ? sev : "var(--text-dim)" }}>
              {v >= ENTROPY_THRESHOLD ? "· flood distribution" : "· nominal"}
            </span>
          </div>
        </div>
      )}
    </Shell>
  );
}

// ── Port Scan: src→port fan-out grid ─────────────────────────────────────
const WELL_KNOWN = new Set([21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080]);

function FanOutGrid({ alert }: { alert: Alert | null }) {
  const fan = alert?.fanOut;
  const sev = "var(--sev-medium)";
  const cells = useMemo(() => {
    if (!fan) return [];
    return fan.ports.slice(0, 64);
  }, [fan]);

  return (
    <Shell title="Port Fan-Out" sub="Recon" icon={<Grid3x3 size={14} />}>
      {!fan ? (
        <Idle label="No scanning activity" />
      ) : (
        <div className="flex flex-col h-full">
          <div className="flex items-baseline gap-2 mb-2">
            <span className="mono text-[20px] font-bold tabular-nums" style={{ color: sev }}>
              {fan.ports.length}
            </span>
            <span className="label-mono text-[8.5px] text-[var(--text-dim)]">ports / {fan.window}s → {fan.targetIp}</span>
          </div>
          <div className="grid grid-cols-8 gap-1 flex-1 content-start">
            {cells.map((p, i) => {
              const known = WELL_KNOWN.has(p);
              return (
                <div
                  key={i}
                  title={`port ${p}`}
                  className="aspect-square rounded-[3px]"
                  style={{
                    background: known ? sev : `color-mix(in srgb, ${sev} 30%, transparent)`,
                    animation: `barFill 0.4s var(--bezier-out) both`,
                    animationDelay: `${Math.min(i, 40) * 12}ms`,
                  }}
                />
              );
            })}
          </div>
          <p className="label-mono text-[8px] text-[var(--text-dim)] mt-2">
            filled = well-known service port · single source
          </p>
        </div>
      )}
    </Shell>
  );
}

// ── Exfiltration: outbound/inbound byte-ratio diverging chart ─────────────
function fmtBytes(b: number) {
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`;
  return `${b} B`;
}

function ByteRatioChart({ alert }: { alert: Alert | null }) {
  const br = alert?.byteRatio;
  const sev = "var(--sev-critical)";
  const inColor = "var(--sev-info)";

  if (!br) {
    return (
      <Shell title="Byte Ratio" sub="Exfiltration" icon={<ArrowLeftRight size={14} />}>
        <Idle label="No exfiltration activity" />
      </Shell>
    );
  }

  const total = br.outbound + br.inbound;
  const outFrac = br.outbound / total;
  const ratio = br.outbound / Math.max(1, br.inbound);

  return (
    <Shell title="Byte Ratio" sub="Exfiltration" icon={<ArrowLeftRight size={14} />}>
      <div className="flex flex-col h-full justify-center gap-4">
        <div className="flex items-baseline gap-2">
          <span className="mono text-[22px] font-bold tabular-nums" style={{ color: sev }}>
            {ratio >= 1 ? `${Math.round(ratio)}:1` : `1:${Math.round(1 / ratio)}`}
          </span>
          <span className="label-mono text-[8.5px] text-[var(--text-dim)]">outbound : inbound</span>
        </div>

        {/* diverging bar from center */}
        <div>
          <div className="flex justify-between label-mono text-[8px] mb-1">
            <span style={{ color: inColor }}>◄ inbound {fmtBytes(br.inbound)}</span>
            <span style={{ color: sev }}>outbound {fmtBytes(br.outbound)} ►</span>
          </div>
          <div className="relative h-4 rounded-full bg-[var(--bg-inset)] border border-[var(--bg-border)] overflow-hidden flex">
            <div className="h-full" style={{ width: `${(1 - outFrac) * 100}%`, background: inColor, opacity: 0.6 }} />
            <div className="h-full" style={{ width: `${outFrac * 100}%`, background: sev }} />
            <span className="absolute inset-y-0 left-1/2 w-px bg-[var(--bg-border-hover)]" />
          </div>
        </div>

        <p className="label-mono text-[8px] text-[var(--text-dim)]">
          heavy outbound asymmetry to a single external host — hallmark of staged exfiltration
        </p>
      </div>
    </Shell>
  );
}
