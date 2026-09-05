import { useEffect, useState } from "react";
import { Activity } from "lucide-react";
import ShieldCube from "./ShieldCube";
import type { FeedState } from "../types/alert";

interface Props {
  status: FeedState["status"];
  flowsPerSec: number;
  totalFlows: number;
  phase: string;
  source: FeedState["source"];
}

export default function Header({ status, flowsPerSec, totalFlows, phase, source }: Props) {
  const [clock, setClock] = useState("");
  useEffect(() => {
    const t = setInterval(
      () => setClock(new Date().toLocaleTimeString("en-GB", { hour12: false })),
      1000,
    );
    return () => clearInterval(t);
  }, []);

  const critical = status === "critical";
  const dotColor = critical ? "var(--sev-critical)" : "var(--sev-low)";
  const statusLabel = critical ? "Threat active" : "Monitoring";

  return (
    <header className="flex items-center justify-between gap-6 px-6 py-4 border-b border-[var(--bg-border)]">
      <div className="flex items-center gap-3">
        <ShieldCube />
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-[15px] font-semibold tracking-tight">NetSentinel</h1>
            <span className="label-mono text-[9px] px-1.5 py-0.5 border border-[var(--bg-border)] rounded">
              NIDS
            </span>
            <span
              className="label-mono text-[8px] px-1.5 py-0.5 rounded border"
              style={{
                color: source === "live" ? "var(--sev-low)" : "var(--text-dim)",
                borderColor: source === "live" ? "var(--sev-low)" : "var(--bg-border)",
              }}
              title={source === "live" ? "Connected to backend WebSocket" : "Simulated feed — see LOCAL_RUN.md to go live"}
            >
              {source === "live" ? "● live" : "mock"}
            </span>
          </div>
          <p className="label-mono mt-0.5 text-[9.5px] normal-case tracking-[0.04em] text-[var(--text-dim)]">
            {phase}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-5">
        <Metric label="Flows / sec" value={flowsPerSec.toFixed(1)} />
        <div className="hidden md:block h-8 w-px bg-[var(--bg-border)]" />
        <Metric label="Total flows" value={totalFlows.toLocaleString()} />
        <div className="hidden lg:block h-8 w-px bg-[var(--bg-border)]" />
        <div className="hidden lg:flex items-center gap-1.5 mono text-[13px] text-[var(--text-muted)]">
          <Activity size={13} className="text-[var(--text-dim)]" />
          {clock}
        </div>
        <div className="flex items-center gap-2 pl-1">
          <span
            className="pulse-dot inline-block h-2 w-2 rounded-full"
            style={{ background: dotColor, color: dotColor }}
          />
          <span
            className="label-mono text-[10px]"
            style={{ color: critical ? "var(--sev-critical)" : "var(--text-main)" }}
          >
            {statusLabel}
          </span>
        </div>
      </div>
    </header>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-right">
      <div className="mono text-[15px] font-semibold leading-none">{value}</div>
      <div className="label-mono mt-1 text-[9px]">{label}</div>
    </div>
  );
}
