import { useMemo } from "react";
import { Clock } from "lucide-react";
import type { Alert, ThreatType } from "../types/alert";
import { SEVERITY_COLOR } from "../types/alert";

const WINDOW_MS = 60_000;
const LANES: ThreatType[] = ["DDoS", "C2 Beacon", "DGA", "Encrypted", "Port Scan"];

// Rolling 60s swimlane — one lane per threat class, a marker per detection.
// This is the "story" view: it shows the attack sequence unfolding in time,
// which a scripted demo walks through end to end.
export default function AttackTimeline({ alerts }: { alerts: Alert[] }) {
  const now = Date.now();
  const events = useMemo(
    () =>
      alerts.filter(
        (a) => a.threatType !== "Benign" && now - a.timestamp < WINDOW_MS,
      ),
    [alerts, now],
  );

  return (
    <section className="panel-base flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--bg-border)]">
        <div className="flex items-center gap-2">
          <Clock size={14} className="text-[var(--text-muted)]" />
          <h2 className="text-[13px] font-semibold">Attack Timeline</h2>
          <span className="label-mono text-[9px] text-[var(--text-dim)]">rolling 60s</span>
        </div>
        <span className="label-mono text-[9px] text-[var(--text-dim)]">{events.length} events</span>
      </div>

      <div className="flex-1 flex flex-col justify-center gap-1.5 px-4 py-3">
        {LANES.map((lane) => {
          const laneEvents = events.filter((e) => e.threatType === lane);
          return (
            <div key={lane} className="grid grid-cols-[86px_1fr] items-center gap-3">
              <span className="label-mono text-[8.5px] normal-case tracking-[0.03em] truncate text-right">
                {lane}
              </span>
              <div className="relative h-6 rounded-md bg-[var(--bg-inset)] border border-[var(--bg-border)]">
                {laneEvents.map((e) => {
                  const x = ((WINDOW_MS - (now - e.timestamp)) / WINDOW_MS) * 100;
                  const color = SEVERITY_COLOR[e.severity];
                  return (
                    <div
                      key={e.id}
                      className="absolute top-1/2 -translate-y-1/2 -translate-x-1/2 h-3 w-3 rounded-full animate-pop"
                      style={{
                        left: `${x}%`,
                        background: color,
                        boxShadow: `0 0 8px ${color}`,
                      }}
                      title={`${e.threatType} · ${e.confidence.toFixed(1)}%`}
                    />
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-[86px_1fr] gap-3 px-4 pb-3">
        <span />
        <div className="flex justify-between label-mono text-[7.5px] text-[var(--text-dim)]">
          <span>-60s</span>
          <span>-40s</span>
          <span>-20s</span>
          <span>now</span>
        </div>
      </div>
    </section>
  );
}
