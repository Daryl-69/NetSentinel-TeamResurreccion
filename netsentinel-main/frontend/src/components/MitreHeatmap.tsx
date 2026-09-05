import { useState } from "react";
import { Grid3x3 } from "lucide-react";
import type { MitreCell } from "../types/alert";

// Monochrome intensity ramp — white opacity encodes hit count, keeping
// the heatmap on-palette. A hit turns the cell "live" (border pulse).
export default function MitreHeatmap({ cells }: { cells: MitreCell[] }) {
  const [hover, setHover] = useState<MitreCell | null>(null);
  const max = Math.max(1, ...cells.map((c) => c.hits));

  return (
    <section className="panel-base flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--bg-border)]">
        <div className="flex items-center gap-2">
          <Grid3x3 size={14} className="text-[var(--text-muted)]" />
          <h2 className="text-[13px] font-semibold">MITRE ATT&CK</h2>
        </div>
        <span className="label-mono text-[9px] text-[var(--text-dim)]">
          {cells.filter((c) => c.hits > 0).length} active
        </span>
      </div>

      <div className="relative flex-1 p-3">
        <div className="grid grid-cols-3 gap-1.5">
          {cells.map((c) => {
            const intensity = c.hits === 0 ? 0 : 0.12 + (c.hits / max) * 0.5;
            const live = c.hits > 0;
            return (
              <div
                key={c.id}
                onMouseEnter={() => setHover(c)}
                onMouseLeave={() => setHover(null)}
                className="relative rounded-md border px-2 py-2 cursor-default transition-colors"
                style={{
                  background: `rgba(255,255,255,${intensity})`,
                  borderColor: live ? "var(--bg-border-hover)" : "var(--bg-border)",
                }}
              >
                <div className="label-mono text-[7.5px] leading-tight text-[var(--text-dim)] truncate">
                  {c.tactic}
                </div>
                <div className="mono text-[10px] mt-1 truncate" style={{ color: live ? "#fff" : "var(--text-dim)" }}>
                  {c.id}
                </div>
                {live && (
                  <span className="absolute top-1.5 right-1.5 mono text-[10px] font-semibold">{c.hits}</span>
                )}
              </div>
            );
          })}
        </div>

        {hover && (
          <div className="mt-3 panel-inset px-3 py-2 animate-neural">
            <div className="label-mono text-[8px]">{hover.tactic}</div>
            <div className="text-[12px] mt-0.5">{hover.technique}</div>
            <div className="mono text-[10px] text-[var(--text-muted)] mt-0.5">
              {hover.id} · {hover.hits} detection{hover.hits === 1 ? "" : "s"}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
