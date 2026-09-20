import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity } from "lucide-react";
import type { PacketSample } from "../types/alert";

export default function TrafficCharts({ data }: { data: PacketSample[] }) {
  const peak = Math.max(1000, ...data.map((d) => d.pps));
  const latest = data[data.length - 1]?.pps ?? 0;

  return (
    <section className="panel-base flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--bg-border)]">
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-[var(--text-muted)]" />
          <h2 className="text-[13px] font-semibold">Packet Rate</h2>
        </div>
        <div className="text-right">
          <span className="mono text-[13px] tabular-nums">{latest.toLocaleString()}</span>
          <span className="label-mono text-[8px] ml-1">pps</span>
        </div>
      </div>

      <div className="flex-1 min-h-[130px] px-1 pt-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 6, right: 8, bottom: 4, left: 0 }}>
            <defs>
              <linearGradient id="ppsFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#ffffff" stopOpacity={0.25} />
                <stop offset="100%" stopColor="#ffffff" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="t" hide />
            <YAxis hide domain={[0, peak * 1.1]} />
            <Tooltip
              cursor={{ stroke: "rgba(255,255,255,0.2)" }}
              contentStyle={{
                background: "#0a0a0a",
                border: "1px solid rgba(255,255,255,0.16)",
                borderRadius: 8,
                fontSize: 11,
                fontFamily: "JetBrains Mono, monospace",
              }}
              labelFormatter={() => ""}
              formatter={(v) => [`${Number(v).toLocaleString()} pps`, ""] as [string, string]}
            />
            <Area
              type="monotone"
              dataKey="pps"
              stroke="#ffffff"
              strokeWidth={1.4}
              fill="url(#ppsFill)"
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="px-4 pb-3 pt-1">
        <div className="label-mono text-[8px] mb-1.5">Threat activity (3s window)</div>
        <div className="h-[52px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 2, right: 8, bottom: 0, left: 0 }} stackOffset="none">
              <XAxis dataKey="t" hide />
              <YAxis hide />
              <Area type="step" dataKey="medium" stackId="s" stroke="#facc15" fill="#facc15" fillOpacity={0.35} strokeWidth={1} isAnimationActive={false} />
              <Area type="step" dataKey="high" stackId="s" stroke="#f97316" fill="#f97316" fillOpacity={0.4} strokeWidth={1} isAnimationActive={false} />
              <Area type="step" dataKey="critical" stackId="s" stroke="#ef4444" fill="#ef4444" fillOpacity={0.5} strokeWidth={1} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </section>
  );
}
