import { useMemo, useState } from "react";
import { useThreatFeed } from "./data/useThreatFeed";
import { SEVERITY_RANK } from "./types/alert";
import Header from "./components/Header";
import TopStrip from "./components/TopStrip";
import RiskStream from "./components/RiskStream";
import ThreatGraph from "./components/ThreatGraph";
import EvidencePanel from "./components/EvidencePanel";
import ThreatClassPanels from "./components/ThreatClassPanels";
import AttackTimeline from "./components/AttackTimeline";
import TrafficCharts from "./components/TrafficCharts";
import MitreHeatmap from "./components/MitreHeatmap";
import ModelCards from "./components/ModelCards";
import ConfidenceBands from "./components/ConfidenceBands";

export default function App() {
  const feed = useThreatFeed();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Highest-risk open threat: severity band first, then confidence, then recency.
  const critical = useMemo(() => {
    const threats = feed.alerts.filter((a) => a.threatType !== "Benign");
    if (threats.length === 0) return null;
    return [...threats].sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        b.confidence - a.confidence ||
        b.timestamp - a.timestamp,
    )[0];
  }, [feed.alerts]);

  // The evidence panel follows the analyst's selection, defaulting to the
  // top-risk alert so the workbench is never empty.
  const selected = useMemo(() => {
    const found = selectedId ? feed.alerts.find((a) => a.id === selectedId) : null;
    return found ?? critical;
  }, [selectedId, feed.alerts, critical]);

  return (
    <div className="relative min-h-full text-[var(--text-main)]">
      <div className="bg-criss-cross pointer-events-none fixed inset-0 -z-10" />

      <Header
        status={feed.status}
        flowsPerSec={feed.flowsPerSec}
        totalFlows={feed.totalFlows}
        phase={feed.phase}
        source={feed.source}
      />

      <main className="mx-auto max-w-[1700px] p-4 lg:p-6 grid gap-4 lg:gap-5">
        {/* Vital signs strip */}
        <div className="animate-entrance stagger-1">
          <TopStrip feed={feed} />
        </div>

        {/* Zone 1 · triage queue → Zone 2 · correlation graph → Zone 3 · evidence */}
        <div className="grid gap-4 lg:gap-5 lg:grid-cols-[0.9fr_1.35fr_1fr] h-[600px] lg:h-[700px]">
          <div className="animate-entrance stagger-2 flex min-h-0 h-full">
            <div className="flex-1 flex min-h-0 h-full">
              <RiskStream alerts={feed.alerts} selectedId={selected?.id ?? null} onSelect={(a) => setSelectedId(a.id)} />
            </div>
          </div>
          <div className="animate-entrance stagger-3 flex min-h-0 h-full">
            <div className="flex-1 flex min-h-0 h-full">
              <ThreatGraph alerts={feed.alerts} />
            </div>
          </div>
          <div className="animate-entrance stagger-4 flex min-h-0 h-full">
            <div className="flex-1 flex min-h-0 h-full">
              <EvidencePanel alert={selected} />
            </div>
          </div>
        </div>

        {/* Threat-class evidence: DDoS entropy · recon fan-out · exfil byte ratio */}
        <div className="animate-entrance stagger-5">
          <ThreatClassPanels alerts={feed.alerts} />
        </div>

        {/* Attack story: rolling swimlane */}
        <div className="animate-entrance stagger-6 min-h-[200px] flex">
          <div className="flex-1 flex">
            <AttackTimeline alerts={feed.alerts} />
          </div>
        </div>

        {/* Signals: traffic rate · model confidence bands */}
        <div className="grid gap-4 lg:gap-5 lg:grid-cols-2">
          <div className="animate-entrance stagger-7 min-h-[260px] flex">
            <div className="flex-1 flex">
              <TrafficCharts data={feed.packetRate} />
            </div>
          </div>
          <div className="animate-entrance stagger-7 min-h-[260px] flex">
            <div className="flex-1 flex">
              <ConfidenceBands models={feed.models} />
            </div>
          </div>
        </div>

        {/* Coverage: MITRE · detector fleet */}
        <div className="grid gap-4 lg:gap-5 lg:grid-cols-2">
          <div className="animate-entrance stagger-8 min-h-[280px] flex">
            <div className="flex-1 flex">
              <MitreHeatmap cells={feed.mitre} />
            </div>
          </div>
          <div className="animate-entrance stagger-8 min-h-[280px] flex">
            <div className="flex-1 flex">
              <ModelCards models={feed.models} />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
