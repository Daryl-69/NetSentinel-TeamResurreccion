import { useMemo } from "react";
import { Area, AreaChart, ReferenceLine, ResponsiveContainer, XAxis, YAxis } from "recharts";
import { Radio } from "lucide-react";
import type { Alert } from "../types/alert";

// Visualizes the C2 detector's FFT branch: Inter-Arrival-Time periodicity
// in frequency space. A real beacon shows a sharp dominant peak; human
// browsing is flat/noisy. Derived from the active C2 alert's interval.
export default function FFTSpectrum({ alerts }: { alerts: Alert[] }) {
  const c2 = useMemo(() => alerts.find((a) => a.threatType === "C2 Beacon" && a.beaconInterval), [alerts]);
  const interval = c2?.beaconInterval ?? null;
  const domFreq = interval ? 1 / interval : null;

  const spectrum = useMemo(() => {
    const N = 60;
    const maxF = 0.05; // Hz (period ≥ 20s)
    return Array.from({ length: N }, (_, i) => {
      const f = (i / (N - 1)) * maxF;
      let mag = 0.06 + Math.random() * 0.05; // noise floor
      if (domFreq) {
        const peak = Math.exp(-(((f - domFreq) / 0.0016) ** 2)); // fundamental
        const harm = 0.35 * Math.exp(-(((f - domFreq * 2) / 0.0016) ** 2)); // 2nd harmonic
        mag = Math.max(mag, peak + harm);
      }
      return { f: +f.toFixed(4), mag: +mag.toFixed(3) };
    });
  }, [domFreq]);

  return (
    <section className="panel-base flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--bg-border)]">
        <div className="flex items-center gap-2">
          <Radio size={14} className="text-[var(--text-muted)]" />
          <h2 className="text-[13px] font-semibold">C2 Beacon Spectrum</h2>
          <span className="label-mono text-[9px] text-[var(--text-dim)]">FFT branch</span>
        </div>
        {interval && (
          <div className="text-right">
            <span className="mono text-[13px]" style={{ color: "var(--sev-high)" }}>
              {interval}s
            </span>
            <span className="label-mono text-[8px] ml-1">interval</span>
          </div>
        )}
      </div>

      <div className="flex-1 min-h-[120px] px-1 pt-2 relative">
        {!interval && (
          <div className="absolute inset-0 flex items-center justify-center z-10">
            <p className="label-mono text-[9px] text-[var(--text-dim)]">No periodicity detected — noise floor</p>
          </div>
        )}
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={spectrum} margin={{ top: 8, right: 10, bottom: 4, left: 0 }}>
            <defs>
              <linearGradient id="fftFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f97316" stopOpacity={interval ? 0.4 : 0.06} />
                <stop offset="100%" stopColor="#f97316" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="f" hide />
            <YAxis hide domain={[0, 1.2]} />
            {domFreq && (
              <ReferenceLine
                x={+domFreq.toFixed(4)}
                stroke="#f97316"
                strokeDasharray="3 3"
                label={{
                  value: `${domFreq.toFixed(4)} Hz`,
                  position: "top",
                  fill: "#f97316",
                  fontSize: 9,
                  fontFamily: "JetBrains Mono, monospace",
                }}
              />
            )}
            <Area
              type="monotone"
              dataKey="mag"
              stroke={interval ? "#f97316" : "#444"}
              strokeWidth={1.4}
              fill="url(#fftFill)"
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-3 gap-px bg-[var(--bg-border)] border-t border-[var(--bg-border)]">
        <Stat label="Dom. freq" value={domFreq ? `${domFreq.toFixed(4)}` : "—"} />
        <Stat label="Spectral H" value={interval ? "0.19" : "—"} />
        <Stat label="Peak prom." value={interval ? "0.88" : "—"} />
      </div>
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[var(--bg-surface)] px-3 py-2">
      <div className="label-mono text-[7.5px]">{label}</div>
      <div className="mono text-[11px] mt-0.5">{value}</div>
    </div>
  );
}
