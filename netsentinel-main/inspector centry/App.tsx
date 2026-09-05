import { useEffect, useMemo, useRef, useState } from "react";

/* ============================================================================
   NetSentinel — Expensive INSPECTOR → distilled cheap SENTRY
   During a tiered COMMISSIONING window the expensive inspector (E-GraphSAGE +
   Transformer) profiles ALL hosts. Hosts that pass are demoted to an always-on
   distilled SENTRY. The sentry re-escalates a host back to the inspector on
   (a) a detected anomaly, (b) a random sample, or (c) a behavioural change.
   Retention rule: if the inspector catches a threat DURING commissioning, that
   host is HELD on the inspector — it is never handed off to the sentry.
   GPU is paid up front during commissioning, then collapses to cheap
   steady-state with small escalation spikes.
   ========================================================================== */

const HOUR = 1;
const DAY = 24 * HOUR;
const SIM_END = 14 * DAY; // 336h

// dormant attacker: benign through commissioning, activates on day 9
const ACTIVATE = 9 * DAY; // 216h — recon begins
const ATTACK_ESC = ACTIVATE + 6; // sentry notices anomaly ~6h after activation
const EARLY_COMPROMISE = 36; // second threat, active during commissioning
const CHANGE_T = 7.5 * DAY; // benign behavioural-change host re-escalates here
const CHANGE_DUR = 8;

const GPU_INSPECTOR = 100; // expensive model, per host
const GPU_SENTRY = 6; // distilled model, per host

type Tier = { key: string; name: string; commHours: number; sampleInterval: number };
const TIERS: Tier[] = [
  { key: "basic", name: "Basic", commHours: 3 * DAY, sampleInterval: 18 },
  { key: "pro", name: "Pro", commHours: 5 * DAY, sampleInterval: 30 },
  { key: "ent", name: "Enterprise", commHours: 7 * DAY, sampleInterval: 44 },
];

type Category =
  | "Recon_API" | "Code_Repo_Paste" | "Messaging_API" | "Cloud_Storage"
  | "Browse" | "Sync" | "CI_CD";
type Phase = "recon" | "payload" | "c2" | "exfil" | "benign";
type Interaction = { id: string; hostId: string; cat: Category; t: number; domain: string; egressAsymmetry: number; pollingCoV: number; fftAutomationScore: number; phase: Phase };
type Host = { id: string; label: string; role: string; compromisedAt: number | null; events: Interaction[] };

// ---- rng -------------------------------------------------------------------
function mulberry32(seed: number) {
  return function () {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = (r: () => number, lo: number, hi: number) => lo + (hi - lo) * r();
const clamp = (x: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, x));

// ---- categories ------------------------------------------------------------
const CAT_ORDER: Category[] = ["Recon_API", "Code_Repo_Paste", "Messaging_API", "Cloud_Storage", "Browse", "Sync", "CI_CD"];
// calm, cool palette for service nodes — red/amber are reserved for threat signals only
const CAT_META: Record<Category, { color: string; sample: string }> = {
  Recon_API: { color: "#9d7bff", sample: "ip-api.com" },
  Code_Repo_Paste: { color: "#7aa2f7", sample: "raw.githubusercontent.com" },
  Messaging_API: { color: "#35e0d4", sample: "api.telegram.org" },
  Cloud_Storage: { color: "#5bc0be", sample: "drive.google.com" },
  Browse: { color: "#8a99ab", sample: "office.com" },
  Sync: { color: "#6f8296", sample: "onedrive.live.com" },
  CI_CD: { color: "#a6e22e", sample: "github.com/actions" },
};

// ---- scenario --------------------------------------------------------------
let _uid = 0;
const uid = () => `e${_uid++}`;

function benignStream(host: Omit<Host, "events">, seed: number, from: number, to: number): Interaction[] {
  const r = mulberry32(seed);
  const cats: Category[] = ["Browse", "Sync", "CI_CD", "Cloud_Storage"];
  const weights = host.role === "dev-laptop" ? [0.2, 0.15, 0.45, 0.2]
    : host.role === "app-server" ? [0.05, 0.7, 0.15, 0.1] : [0.55, 0.25, 0.05, 0.15];
  const pick = (): Category => { let x = r(); for (let i = 0; i < cats.length; i++) { if (x < weights[i]) return cats[i]; x -= weights[i]; } return cats[0]; };
  const out: Interaction[] = [];
  let t = from + rand(r, 1, 5);
  while (t < to) {
    const cat = pick();
    out.push({ id: uid(), hostId: host.id, cat, t: Math.round(t * 10) / 10, domain: CAT_META[cat].sample,
      egressAsymmetry: cat === "Sync" ? rand(r, 0.4, 0.6) : rand(r, 0.08, 0.32),
      pollingCoV: rand(r, 0.42, 0.95), fftAutomationScore: rand(r, 0.04, 0.34), phase: "benign" });
    t += rand(r, 3, 9);
  }
  return out;
}

function threatStream(host: Omit<Host, "events">, seed: number, at: number): Interaction[] {
  const out = benignStream(host, seed, 0, at); // benign until it activates
  const add = (cat: Category, t: number, domain: string, phase: Phase, o: Partial<Interaction> = {}) =>
    out.push({ id: uid(), hostId: host.id, cat, t, domain, egressAsymmetry: 0.5, pollingCoV: 0.05, fftAutomationScore: 0.92, phase, ...o });
  add("Recon_API", at, "ipify.org", "recon", { egressAsymmetry: 0.6, pollingCoV: 0.4, fftAutomationScore: 0.3 });
  add("Recon_API", at + 1, "ip-api.com", "recon", { egressAsymmetry: 0.58, pollingCoV: 0.42, fftAutomationScore: 0.32 });
  add("Code_Repo_Paste", at + 2, "raw.githubusercontent.com", "payload", { egressAsymmetry: 0.12 });
  add("Code_Repo_Paste", at + 3, "pastebin.com", "payload", { egressAsymmetry: 0.1 });
  for (let t = at + 4; t < SIM_END; t += 1) add("Messaging_API", t, "api.telegram.org", "c2", { egressAsymmetry: 0.52, pollingCoV: 0.04 });
  add("Cloud_Storage", at + 48, "drive.google.com", "exfil", { egressAsymmetry: 0.83 });
  add("Cloud_Storage", at + 52, "drive.google.com", "exfil", { egressAsymmetry: 0.85 });
  return out.sort((a, b) => a.t - b.t);
}

const HOST_DEFS: Omit<Host, "events">[] = [
  { id: "LT-8823", label: "LT-8823", role: "mktg-laptop", compromisedAt: ACTIVATE }, // dormant → activates in steady state
  { id: "WS-3382", label: "WS-3382", role: "hr-ws", compromisedAt: EARLY_COMPROMISE }, // already compromised during commissioning
  { id: "LT-2207", label: "LT-2207", role: "dev-laptop", compromisedAt: null },
  { id: "WS-1140", label: "WS-1140", role: "finance-ws", compromisedAt: null },
  { id: "SRV-APP-02", label: "SRV-APP-02", role: "app-server", compromisedAt: null },
  { id: "LT-5567", label: "LT-5567", role: "sales-laptop", compromisedAt: null },
  { id: "LT-9904", label: "LT-9904", role: "design-laptop", compromisedAt: null },
];
const HOSTS: Host[] = HOST_DEFS.map((h, i) => ({
  ...h,
  events: h.compromisedAt !== null ? threatStream(h, 700 + i * 91, h.compromisedAt) : benignStream(h, 1000 + i * 137, 0, SIM_END),
}));
const N = HOSTS.length;
const MAL = HOSTS.filter((h) => h.compromisedAt !== null).map((h) => ({ id: h.id, at: h.compromisedAt as number }));
const CHANGE_HOST = "LT-2207";

// ---- re-escalation windows (benign triggers only) --------------------------
type Reason = "anomaly" | "sample" | "change" | "held";
type Win = { hostId: string; start: number; end: number | null; reason: Extract<Reason, "sample" | "change"> };

function buildEscalations(tier: Tier): Win[] {
  const w: Win[] = [];
  w.push({ hostId: CHANGE_HOST, start: CHANGE_T, end: CHANGE_T + CHANGE_DUR, reason: "change" });
  const benign = HOSTS.filter((h) => h.compromisedAt === null && h.id !== CHANGE_HOST).map((h) => h.id);
  let idx = 0;
  for (let t = tier.commHours + tier.sampleInterval * 0.6; t < SIM_END - 5; t += tier.sampleInterval) {
    w.push({ hostId: benign[idx % benign.length], start: Math.round(t), end: Math.round(t) + 4, reason: "sample" });
    idx++;
  }
  return w;
}

// ---- error curve for a tracked threat --------------------------------------
function threatError(host: Host, simTime: number, anchor: number) {
  if (simTime < anchor) return 0.1;
  const beacons = host.events.filter((e) => e.phase === "c2" && e.t <= simTime).length;
  const exfil = host.events.some((e) => e.phase === "exfil" && e.t <= simTime);
  return clamp(0.16 + 0.5 * (1 - Math.exp(-beacons / 6)) + (exfil ? 0.42 : 0) + 0.015 * Math.sin(simTime / 6), 0, 0.98);
}
function alertTof(host: Host) {
  const c2 = host.events.filter((e) => e.phase === "c2");
  return c2.length >= 7 ? c2[6].t : null;
}

// ---- derived host state ----------------------------------------------------
type Status = "profiling" | "flagged" | "sentry-ok" | "re-escalated" | "held" | "alerting" | "critical";
type HostState = {
  host: Host; status: Status; layer: "inspector" | "sentry"; reason: Reason | null;
  error: number; exfilSeen: boolean; alertT: number | null; anchor: number | null; held: boolean;
};

function deriveHost(host: Host, simTime: number, tier: Tier, esc: Win[]): HostState {
  const commissioning = simTime < tier.commHours;
  const mal = host.compromisedAt;

  if (commissioning) {
    if (mal !== null && simTime >= mal) {
      // inspector catches it DURING commissioning — it will be held, never demoted
      return { host, status: "flagged", layer: "inspector", reason: "held", error: threatError(host, simTime, mal), exfilSeen: host.events.some((e) => e.phase === "exfil" && e.t <= simTime), alertT: alertTof(host), anchor: mal, held: true };
    }
    return { host, status: "profiling", layer: "inspector", reason: null, error: 0, exfilSeen: false, alertT: null, anchor: null, held: false };
  }

  // steady state
  if (mal !== null) {
    const error = threatError(host, simTime, mal);
    const exfilSeen = host.events.some((e) => e.phase === "exfil" && e.t <= simTime);
    const alertT = alertTof(host);
    const heldFromCommission = mal < tier.commHours;

    if (heldFromCommission) {
      // retention rule: stays on the inspector for the whole run
      let status: Status = "held";
      if (exfilSeen) status = "critical";
      else if (alertT !== null && simTime >= alertT) status = "alerting";
      return { host, status, layer: "inspector", reason: "held", error, exfilSeen, alertT, anchor: mal, held: true };
    }
    // dormant-then-active attacker: sentry must catch it after activation
    if (simTime >= mal + 6) {
      let status: Status = "re-escalated";
      if (exfilSeen) status = "critical";
      else if (alertT !== null && simTime >= alertT) status = "alerting";
      return { host, status, layer: "inspector", reason: "anomaly", error, exfilSeen, alertT, anchor: mal, held: false };
    }
    // activated but not yet detected — the honest latency window
    return { host, status: "sentry-ok", layer: "sentry", reason: null, error: 0.12, exfilSeen: false, alertT: null, anchor: null, held: false };
  }

  const aw = esc.find((x) => x.hostId === host.id && x.start <= simTime && (x.end === null || simTime < x.end));
  if (aw) {
    return { host, status: "re-escalated", layer: "inspector", reason: aw.reason, error: 0.11 + 0.03 * Math.sin(simTime / 5), exfilSeen: false, alertT: null, anchor: null, held: false };
  }
  return { host, status: "sentry-ok", layer: "sentry", reason: null, error: 0.1, exfilSeen: false, alertT: null, anchor: null, held: false };
}

// ---- GPU accounting --------------------------------------------------------
function loadAt(h: number, tier: Tier, esc: Win[]) {
  if (h < tier.commHours) return { inspector: N, sentry: 0 };
  let inspector = 0;
  for (const m of MAL) {
    if (m.at < tier.commHours) inspector++; // held from commissioning
    else if (h >= m.at + 6) inspector++; // re-escalated after activation
  }
  for (const w of esc) if (w.start <= h && (w.end === null || h < w.end)) inspector++;
  return { inspector, sentry: N - inspector };
}
const gpuAt = (h: number, tier: Tier, esc: Win[]) => { const l = loadAt(h, tier, esc); return l.inspector * GPU_INSPECTOR + l.sentry * GPU_SENTRY; };
const BASELINE = N * GPU_INSPECTOR;

// ---- formatting ------------------------------------------------------------
const pad = (n: number) => String(n).padStart(2, "0");
function dayClock(h: number) { const d = Math.floor(h / 24) + 1; return `Day ${d} · ${pad(Math.floor(h % 24))}:00`; }
const reasonLabel: Record<Reason, string> = { anomaly: "anomaly", sample: "sample", change: "drift", held: "held" };

/* ==========================================================================
   Component
   ========================================================================== */
export default function App() {
  const [simTime, setSimTime] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [tierKey, setTierKey] = useState("pro");
  const tier = TIERS.find((t) => t.key === tierKey)!;
  const esc = useMemo(() => buildEscalations(tier), [tier]);
  const raf = useRef<number | null>(null);

  useEffect(() => {
    if (!playing) return;
    let last = performance.now();
    const step = (now: number) => {
      const dt = (now - last) / 1000; last = now;
      setSimTime((t) => { const next = t + dt * speed * 9; if (next >= SIM_END) { setPlaying(false); return SIM_END; } return next; });
      raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => { if (raf.current) cancelAnimationFrame(raf.current); };
  }, [playing, speed]);

  const states = useMemo(() => HOSTS.map((h) => deriveHost(h, simTime, tier, esc)), [simTime, tier, esc]);
  const phase = simTime < tier.commHours ? "commissioning" : "steady";

  const onInspector = states.filter((s) => s.layer === "inspector");
  const onSentry = states.filter((s) => s.layer === "sentry");
  const held = states.filter((s) => s.held);
  const reesc = states.filter((s) => !s.held && (s.status === "re-escalated" || s.status === "alerting" || s.status === "critical"));
  const alerts = states.filter((s) => s.status === "alerting" || s.status === "critical");

  const load = loadAt(simTime, tier, esc);
  const gpuNow = load.inspector * GPU_INSPECTOR + load.sentry * GPU_SENTRY;
  const savedNow = Math.round((1 - gpuNow / BASELINE) * 100);
  const cumSaved = useMemo(() => {
    let s = 0; for (let h = 0; h <= simTime; h += 2) s += (BASELINE - gpuAt(h, tier, esc)) * 2; return Math.round(s);
  }, [simTime, tier, esc]);

  const reset = () => { setSimTime(0); setPlaying(true); };

  return (
    <div className="min-h-full w-full bg-ground text-ink font-sans">
      <div className="mx-auto max-w-[1400px] px-5 py-5 lg:px-8">
        <Header simTime={simTime} phase={phase} playing={playing} speed={speed} tier={tier}
          onToggle={() => (simTime >= SIM_END ? reset() : setPlaying((p) => !p))}
          onSpeed={setSpeed} onReset={reset} onTier={setTierKey}
          onScrub={(v) => { setSimTime(v); setPlaying(false); }} />

        <PhaseBar simTime={simTime} tier={tier} />

        <PipelineRail inspector={onInspector.length} sentry={onSentry.length} reesc={reesc.length}
          held={held.length} alerts={alerts.length} states={states} phase={phase}
          load={load} gpuNow={gpuNow} savedNow={savedNow} cumSaved={cumSaved} />

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[1.55fr_1fr]">
          <div className="flex flex-col gap-4">
            <NetworkGraph states={states} simTime={simTime} />
            <FleetTable states={states} />
          </div>
          <div className="flex flex-col gap-4">
            <Escalations states={states} simTime={simTime} />
            <AlertFeed simTime={simTime} tier={tier} esc={esc} />
          </div>
        </div>

        <footer className="mt-6 border-t border-line pt-3 text-[11px] leading-relaxed text-ink-faint font-mono">
          Inspector (tiered commissioning) → distilled Sentry (always-on) → re-escalate on {"{anomaly · sample · drift}"} → Inspector confirm → LLM verdict.
          Retention rule: a threat caught during commissioning is HELD on the inspector and never demoted to the sentry.
        </footer>
      </div>
    </div>
  );
}

/* ---- header --------------------------------------------------------------- */
function Header(props: {
  simTime: number; phase: string; playing: boolean; speed: number; tier: Tier;
  onToggle: () => void; onSpeed: (s: number) => void; onReset: () => void; onTier: (k: string) => void; onScrub: (v: number) => void;
}) {
  const { simTime, phase, playing, speed, tier, onToggle, onSpeed, onReset, onTier, onScrub } = props;
  return (
    <header className="flex flex-col gap-4 border-b border-line pb-4 lg:flex-row lg:items-end lg:justify-between">
      <div>
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full rounded-full bg-cyan opacity-60 [animation:ns-pulse_1.8s_ease-in-out_infinite]" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-cyan" />
          </span>
          <h1 className="font-mono text-lg font-extrabold tracking-tight">Net<span className="text-cyan">Sentinel</span></h1>
          <span className="rounded border border-line-bright px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest text-ink-dim">inspector → sentry</span>
        </div>
        <p className="mt-1.5 max-w-xl text-[13px] leading-relaxed text-ink-dim">
          The expensive <span className="text-ink">inspector</span> profiles every host during a tiered <span className="text-ink">commissioning</span> window;
          cleared hosts drop to an always-on distilled <span className="text-ink">sentry</span>. A threat caught during commissioning is held on the inspector, never demoted.
        </p>
      </div>

      <div className="flex flex-col items-start gap-2 lg:items-end">
        <div className="flex flex-wrap items-center gap-3 font-mono">
          <div className="overflow-hidden rounded-md border border-line-bright">
            {TIERS.map((t) => (
              <button key={t.key} onClick={() => onTier(t.key)}
                className={`px-2.5 py-1.5 text-[11px] font-semibold transition ${tier.key === t.key ? "bg-cyan text-[#04110f]" : "bg-panel text-ink-dim hover:text-ink"}`}>
                {t.name}
              </button>
            ))}
          </div>
          <div className="text-right">
            <div className="text-xl font-bold leading-none tabular-nums">{dayClock(simTime)}</div>
            <div className="mt-0.5 text-[11px] tabular-nums" style={{ color: phase === "commissioning" ? "var(--color-cyan)" : "var(--color-lime)" }}>
              {phase === "commissioning" ? "COMMISSIONING · inspector on all" : "STEADY · sentry on all"}
            </div>
          </div>
          <button onClick={onToggle} className="flex h-10 w-10 items-center justify-center rounded-md border border-line-bright bg-panel transition hover:border-cyan hover:text-cyan" aria-label={playing ? "Pause" : "Play"}>
            {simTime >= SIM_END ? <IconReset /> : playing ? <IconPause /> : <IconPlay />}
          </button>
          <div className="flex overflow-hidden rounded-md border border-line-bright">
            {[0.25, 1, 2, 4].map((s) => (
              <button key={s} onClick={() => onSpeed(s)} className={`px-2 py-1.5 text-[12px] font-semibold transition ${speed === s ? "bg-cyan text-[#04110f]" : "bg-panel text-ink-dim hover:text-ink"}`}>{s}×</button>
            ))}
          </div>
          <button onClick={onReset} className="flex h-10 w-10 items-center justify-center rounded-md border border-line-bright bg-panel text-ink-dim transition hover:border-ink hover:text-ink" aria-label="Reset"><IconReset /></button>
        </div>
        <input type="range" min={0} max={SIM_END} value={simTime} onChange={(e) => onScrub(Number(e.target.value))} className="ns-range w-full lg:w-[420px]" aria-label="Scrub timeline" />
      </div>
    </header>
  );
}

/* ---- phase timeline bar --------------------------------------------------- */
function PhaseBar({ simTime, tier }: { simTime: number; tier: Tier }) {
  const commPct = (tier.commHours / SIM_END) * 100;
  const nowPct = (simTime / SIM_END) * 100;
  return (
    <div className="mt-3">
      <div className="relative h-6 overflow-hidden rounded-md border border-line bg-panel">
        <div className="absolute inset-y-0 left-0 bg-cyan/15" style={{ width: `${commPct}%` }} />
        <div className="absolute inset-y-0 bg-lime/[0.06]" style={{ left: `${commPct}%`, right: 0 }} />
        <div className="absolute inset-y-0 w-px bg-line-bright" style={{ left: `${commPct}%` }} />
        {Array.from({ length: 13 }, (_, i) => i + 1).map((d) => (
          <div key={d} className="absolute inset-y-0 w-px bg-line/70" style={{ left: `${((d * DAY) / SIM_END) * 100}%` }} />
        ))}
        <span className="absolute top-1/2 -translate-y-1/2 pl-2 font-mono text-[10px] uppercase tracking-wider text-cyan">commissioning</span>
        <span className="absolute top-1/2 -translate-y-1/2 font-mono text-[10px] uppercase tracking-wider text-lime" style={{ left: `calc(${commPct}% + 8px)` }}>steady · sentry</span>
        <div className="absolute inset-y-0 z-10 w-0.5 bg-ink" style={{ left: `${nowPct}%` }} />
      </div>
    </div>
  );
}

/* ---- pipeline rail + GPU meter -------------------------------------------- */
function PipelineRail(props: {
  inspector: number; sentry: number; reesc: number; held: number; alerts: number; states: HostState[]; phase: string;
  load: { inspector: number; sentry: number }; gpuNow: number; savedNow: number; cumSaved: number;
}) {
  const { inspector, sentry, reesc, held, alerts, states, phase, load, gpuNow, savedNow, cumSaved } = props;
  const byReason = (r: Reason) => states.filter((s) => s.status === "re-escalated" && s.reason === r).length;
  const stages = [
    { k: "Inspector · expensive", v: inspector, sub: phase === "commissioning" ? "profiling all" : `${held} held`, color: "var(--color-cyan)" },
    { k: "Sentry · always-on", v: sentry, sub: "distilled", color: "var(--color-lime)" },
    { k: "Re-escalations", v: reesc, sub: `${byReason("anomaly")}a ${byReason("sample")}s ${byReason("change")}d`, color: "var(--color-amber)" },
    { k: "LLM verdict", v: alerts, sub: "alerts", color: "var(--color-rose)" },
  ];
  return (
    <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[1.55fr_1fr]">
      <div className="grid grid-cols-2 gap-2 rounded-lg border border-line bg-panel p-2 sm:grid-cols-4">
        {stages.map((s, i) => (
          <div key={s.k} className="relative flex items-center">
            <div className="flex-1 rounded-md bg-panel-2 px-3 py-2.5">
              <div className="font-mono text-[10px] uppercase tracking-wider text-ink-faint">{s.k}</div>
              <div className="mt-1 flex items-baseline gap-1.5">
                <span className="font-mono text-2xl font-bold tabular-nums" style={{ color: s.color }}>{s.v}</span>
                <span className="text-[11px] text-ink-dim">{s.sub}</span>
              </div>
            </div>
            {i < stages.length - 1 && <span className="mx-1 shrink-0 text-ink-faint" aria-hidden>→</span>}
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-line bg-panel p-3">
        <div className="flex items-center justify-between">
          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-faint">GPU load · vs. inspect-all baseline</span>
          <span className="font-mono text-sm font-bold" style={{ color: savedNow > 0 ? "var(--color-lime)" : "var(--color-ink-dim)" }}>−{savedNow}%</span>
        </div>
        <Bar label="inspect-all (inspector on all)" value={BASELINE} max={BASELINE} tone="rose" />
        <Bar label="NetSentinel (now)" value={gpuNow} max={BASELINE} tone="cyan" />
        <div className="mt-1.5 flex items-center justify-between font-mono text-[11px] text-ink-dim">
          <span>{gpuNow}/{BASELINE} units · {load.inspector}×inspector + {load.sentry}×sentry</span>
          <span className="text-lime">Σ {cumSaved.toLocaleString()} saved</span>
        </div>
      </div>
    </div>
  );
}

function Bar({ label, value, max, tone }: { label: string; value: number; max: number; tone: "rose" | "cyan" }) {
  const pct = Math.max(2, Math.round((value / max) * 100));
  return (
    <div className="mt-2">
      <div className="mb-0.5 flex justify-between font-mono text-[10px] text-ink-dim"><span>{label}</span><span className="tabular-nums">{value}u</span></div>
      <div className="h-2 overflow-hidden rounded-full bg-panel-2">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: tone === "rose" ? "var(--color-rose)" : "var(--color-cyan)" }} />
      </div>
    </div>
  );
}

/* ---- network graph -------------------------------------------------------- */
const VB_W = 660, VB_H = 470, HOST_X = 92, CAT_X = 556, TOP = 58, BOT = 40;
const statusColor: Record<Status, string> = {
  profiling: "var(--color-cyan)", "sentry-ok": "var(--color-lime)",
  "re-escalated": "var(--color-amber)", flagged: "var(--color-rose)", held: "var(--color-rose)",
  alerting: "var(--color-rose)", critical: "var(--color-rose)",
};
const PHASE_LABEL: Record<Phase, string> = { recon: "RECON", payload: "PASTE", c2: "C2 BEACON", exfil: "EXFIL", benign: "" };

// pre-path: the service categories each role's program is expected to reach.
// anything a host touches OUTSIDE this allow-list is an off-path deviation.
const ALLOWED_BASE: Category[] = ["Browse", "Sync", "CI_CD", "Cloud_Storage"];
const allowedFor = (role: string): Category[] => (role === "dev-laptop" ? [...ALLOWED_BASE, "Code_Repo_Paste"] : ALLOWED_BASE);
const OFFPATH = "var(--color-rose)";
const FLAWED_CAT: Category = "Messaging_API"; // the malicious C2 endpoint a detected host isolates onto
const DETECT_LAG = 6; // hours from compromise to detection

function bezier(x1: number, y1: number, x2: number, y2: number) {
  const mx = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
}
function bezierPoint(x1: number, y1: number, x2: number, y2: number, t: number) {
  const mx = (x1 + x2) / 2, u = 1 - t;
  const x = u * u * u * x1 + 3 * u * u * t * mx + 3 * u * t * t * mx + t * t * t * x2;
  const y = u * u * u * y1 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y2;
  return { x, y };
}

function NetworkGraph({ states, simTime }: { states: HostState[]; simTime: number }) {
  const hostY = (i: number) => TOP + i * ((VB_H - TOP - BOT) / (states.length - 1));
  const catY = (i: number) => TOP + i * ((VB_H - TOP - BOT) / (CAT_ORDER.length - 1));
  const catIndex = (c: Category) => CAT_ORDER.indexOf(c);

  // pre-path lanes: where each host is expected to go (its role's allow-list)
  const prePaths: { x1: number; y1: number; x2: number; y2: number }[] = [];
  states.forEach((s, hi) => {
    const hy = hostY(hi);
    for (const c of allowedFor(s.host.role)) prePaths.push({ x1: HOST_X, y1: hy, x2: CAT_X, y2: catY(catIndex(c)) });
  });

  type Pulse = { x1: number; y1: number; x2: number; y2: number; pos: number; color: string; off: boolean; phase: Phase };
  const pulses: Pulse[] = [];
  const deviations: { x1: number; y1: number; x2: number; y2: number }[] = []; // persistent off-path edges
  const catHit = new Array(CAT_ORDER.length).fill(0); // recency of a packet arriving at each category
  states.forEach((s, hi) => {
    const hy = hostY(hi); const allow = allowedFor(s.host.role); const seenOff = new Set<Category>();
    const detAt = s.host.compromisedAt !== null ? s.host.compromisedAt + DETECT_LAG : Infinity;
    const detected = simTime >= detAt; // once caught, the host isolates onto its flawed endpoint
    if (detected) deviations.push({ x1: HOST_X, y1: hy, x2: CAT_X, y2: catY(catIndex(FLAWED_CAT)) });
    for (const e of s.host.events) {
      if (e.t > simTime) break;
      // after detection it stops touching every other service and only talks to the flawed one
      if (detected && e.cat !== FLAWED_CAT) continue;
      const ci = catIndex(e.cat);
      const off = !allow.includes(e.cat); // deviates from its pre-path
      if (!detected && off && !seenOff.has(e.cat)) { seenOff.add(e.cat); deviations.push({ x1: HOST_X, y1: hy, x2: CAT_X, y2: catY(ci) }); }
      const age = simTime - e.t;
      if (age >= 0 && age <= 3) {
        const pos = age / 3;
        pulses.push({ x1: HOST_X, y1: hy, x2: CAT_X, y2: catY(ci), pos, color: off ? OFFPATH : CAT_META[e.cat].color, off, phase: e.phase });
        if (pos > 0.82) catHit[ci] = Math.max(catHit[ci], 1 - (pos - 0.82) / 0.18);
      }
    }
  });

  return (
    <div className="rounded-lg border border-line bg-panel p-3">
      <div className="mb-1 flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-wider text-ink-faint">Host ↔ service-category graph · live traffic</span>
        <div className="flex items-center gap-3 font-mono text-[10px] text-ink-dim">
          <span className="flex items-center gap-1"><svg width="14" height="6"><line x1="0" y1="3" x2="14" y2="3" stroke="var(--color-line-bright)" strokeWidth="1.4" strokeDasharray="2 2" /></svg>pre-path</span>
          <LegendDot color="var(--color-cyan)" label="on-path" />
          <LegendDot color="var(--color-rose)" label="off-path" />
        </div>
      </div>
      <svg viewBox={`0 0 ${VB_W} ${VB_H}`} className="h-[470px] w-full" preserveAspectRatio="xMidYMid meet">
        <defs>
          <filter id="ns-glow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="2.4" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* column headers */}
        <text x={HOST_X} y={26} fontSize={10} fontFamily="var(--font-mono)" textAnchor="middle" fill="var(--color-ink-faint)" letterSpacing="1.5">HOSTS</text>
        <text x={CAT_X} y={26} fontSize={10} fontFamily="var(--font-mono)" textAnchor="middle" fill="var(--color-ink-faint)" letterSpacing="1.5">SERVICE CATEGORIES</text>
        <text x={(HOST_X + CAT_X) / 2} y={26} fontSize={9} fontFamily="var(--font-mono)" textAnchor="middle" fill="var(--color-ink-faint)">→ requests →</text>

        {/* pre-path lanes: expected routes per host program */}
        {prePaths.map((p, i) => <path key={`pp${i}`} d={bezier(p.x1, p.y1, p.x2, p.y2)} fill="none" stroke="#3f5468" strokeWidth={1.2} strokeOpacity={0.55} strokeDasharray="4 4" />)}

        {/* deviations: persistent off-path edges */}
        {deviations.map((p, i) => <path key={`dv${i}`} d={bezier(p.x1, p.y1, p.x2, p.y2)} fill="none" stroke={OFFPATH} strokeWidth={1.6} strokeOpacity={0.5} strokeDasharray="5 4" className="[animation:ns-dash_1s_linear_infinite]" />)}

        {/* moving packets */}
        {pulses.map((p, i) => {
          const { x, y } = bezierPoint(p.x1, p.y1, p.x2, p.y2, p.pos);
          const fade = p.off ? 1 - p.pos * 0.3 : 0.8 - p.pos * 0.5;
          const r = p.off ? 4.2 : 2.3;
          const tag = p.off ? (PHASE_LABEL[p.phase] || "OFF-PATH") : "";
          return (
            <g key={`pu${i}`} opacity={fade}>
              <path d={bezier(p.x1, p.y1, p.x2, p.y2)} fill="none" stroke={p.color} strokeWidth={p.off ? 1.4 : 0.8} strokeOpacity={p.off ? 0.4 : 0.16} />
              <circle cx={x} cy={y} r={r} fill={p.color} filter={p.off ? "url(#ns-glow)" : undefined} />
              {p.off && p.pos < 0.62 && (
                <text x={x} y={y - 8} fontSize={8} fontWeight="600" fontFamily="var(--font-mono)" textAnchor="middle" fill={p.color} opacity={0.95}>{tag}</text>
              )}
            </g>
          );
        })}

        {/* category nodes */}
        {CAT_ORDER.map((c, i) => (
          <g key={c}>
            {catHit[i] > 0 && <circle cx={CAT_X} cy={catY(i)} r={5 + catHit[i] * 9} fill="none" stroke={CAT_META[c].color} strokeWidth={1.2} opacity={catHit[i] * 0.7} />}
            <circle cx={CAT_X} cy={catY(i)} r={5} fill="var(--color-panel-2)" stroke={CAT_META[c].color} strokeWidth={1.6} />
            <text x={CAT_X + 12} y={catY(i) + 3} fontSize={11} fontFamily="var(--font-mono)" fill="var(--color-ink-dim)">{c}</text>
          </g>
        ))}

        {/* host nodes */}
        {states.map((s, i) => {
          const col = statusColor[s.status];
          const halo = s.status === "re-escalated" || s.status === "alerting" || s.status === "critical" || s.status === "profiling" || s.status === "flagged" || s.status === "held";
          const solid = s.host.compromisedAt !== null;
          const chip = s.layer === "inspector" ? (s.held ? "HELD" : "INSP") : "SENTRY";
          const chipColor = s.layer === "sentry" ? "var(--color-lime)" : s.held ? "var(--color-rose)" : "var(--color-cyan)";
          return (
            <g key={s.host.id}>
              {s.held && <circle cx={HOST_X} cy={hostY(i)} r={13} fill="none" stroke="var(--color-rose)" strokeWidth={1} strokeDasharray="2 3" opacity={0.6} className="[animation:ns-dash_2s_linear_infinite]" />}
              {halo && <circle cx={HOST_X} cy={hostY(i)} r={9.5} fill="none" stroke={col} strokeWidth={1.2} opacity={0.45} className="[animation:ns-pulse_1.6s_ease-in-out_infinite]" />}
              <circle cx={HOST_X} cy={hostY(i)} r={5.5} fill={solid ? col : "var(--color-panel-2)"} stroke={col} strokeWidth={1.8} />
              <text x={HOST_X - 13} y={hostY(i) - 3} fontSize={11} fontFamily="var(--font-mono)" textAnchor="end" fill="var(--color-ink)">{s.host.label}</text>
              <text x={HOST_X - 13} y={hostY(i) + 8} fontSize={8.5} fontFamily="var(--font-mono)" textAnchor="end" fill="var(--color-ink-faint)">{s.host.role}</text>
              <text x={HOST_X + 12} y={hostY(i) + 3} fontSize={8} fontFamily="var(--font-mono)" fill={chipColor} letterSpacing="0.5">{chip}</text>
            </g>
          );
        })}
      </svg>
      <p className="mt-1 border-t border-line pt-2 font-mono text-[10px] leading-relaxed text-ink-faint">
        Faint dashed lanes are each host's <span className="text-ink-dim">pre-path</span> — the service categories its program is expected to reach. On-path requests travel quietly in category colour;
        any request <span className="text-rose">off the pre-path</span> is highlighted red. Once the deviation is <span className="text-rose">detected</span>, the host stops touching every other service and channels only into its malicious endpoint — a single red beam.
      </p>
    </div>
  );
}
function LegendDot({ color, label }: { color: string; label: string }) {
  return <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full" style={{ background: color }} />{label}</span>;
}

/* ---- fleet table ---------------------------------------------------------- */
function FleetTable({ states }: { states: HostState[] }) {
  const ordered = [...states].sort((a, b) => rank(b.status) - rank(a.status));
  return (
    <div className="rounded-lg border border-line bg-panel">
      <div className="border-b border-line px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-ink-faint">Fleet · current layer</div>
      <div className="divide-y divide-line/70">
        {ordered.map((s) => (
          <div key={s.host.id} className="grid grid-cols-[1.5fr_auto_auto] items-center gap-2 px-3 py-2">
            <div className="min-w-0"><span className="font-mono text-[13px]">{s.host.label}</span><span className="ml-2 text-[11px] text-ink-faint">{s.host.role}</span></div>
            <span className={`font-mono text-[10px] ${s.layer === "inspector" ? "text-cyan" : "text-lime"}`}>{s.layer === "inspector" ? (s.held ? "INSPECTOR ⛒" : "INSPECTOR") : "SENTRY"}</span>
            <StatusBadge status={s.status} reason={s.reason} />
          </div>
        ))}
      </div>
    </div>
  );
}
const rank = (s: Status) => ({ critical: 7, alerting: 6, held: 5, flagged: 5, "re-escalated": 4, profiling: 3, "sentry-ok": 2 }[s]);

function StatusBadge({ status, reason }: { status: Status; reason: Reason | null }) {
  const label = status === "re-escalated" ? `RE-ESC · ${reason ? reasonLabel[reason] : ""}`
    : status === "sentry-ok" ? "ON SENTRY"
    : status === "held" ? "HELD"
    : status.toUpperCase();
  const tone = status === "critical" || status === "alerting" || status === "flagged" || status === "held" ? "border-rose/50 bg-rose-dim text-rose"
    : status === "re-escalated" ? "border-amber/40 bg-amber/10 text-amber"
    : status === "profiling" ? "border-cyan/40 bg-cyan/10 text-cyan"
    : "border-lime/30 bg-lime/10 text-lime";
  return <span className={`whitespace-nowrap rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider ${tone}`}>{label}</span>;
}

/* ---- escalations panel ---------------------------------------------------- */
function Escalations({ states, simTime }: { states: HostState[]; simTime: number }) {
  const active = states.filter((s) => s.status === "re-escalated" || s.status === "alerting" || s.status === "critical" || s.status === "flagged" || s.status === "held");
  return (
    <div className="rounded-lg border border-line bg-panel">
      <div className="flex items-center justify-between border-b border-line px-3 py-2">
        <span className="font-mono text-[10px] uppercase tracking-wider text-ink-faint">On the inspector · re-escalated & held</span>
        <span className="font-mono text-[10px] text-ink-dim">{active.length}</span>
      </div>
      {active.length === 0 ? (
        <div className="px-3 py-8 text-center font-mono text-[12px] text-ink-faint">Fleet on the cheap sentry — nothing escalated.</div>
      ) : (
        <div className="flex flex-col gap-3 p-3">{active.map((s) => <EscCard key={s.host.id} s={s} simTime={simTime} />)}</div>
      )}
    </div>
  );
}

function EscCard({ s, simTime }: { s: HostState; simTime: number }) {
  const isThreat = s.anchor !== null;
  const anchor = s.anchor ?? Math.max(0, simTime - 10);
  const pts = useMemo(() => {
    const arr: { x: number; y: number }[] = []; const nSteps = 32;
    for (let i = 0; i <= nSteps; i++) {
      const t = anchor + ((simTime - anchor) * i) / nSteps;
      arr.push({ x: i / nSteps, y: isThreat ? threatError(s.host, t, anchor) : 0.1 + 0.02 * Math.sin(t / 4) });
    }
    return arr;
  }, [s.host, anchor, simTime, isThreat]);
  const spark = pts.map((p) => `${(p.x * 100).toFixed(1)},${(38 - p.y * 34).toFixed(1)}`).join(" ");
  const errColor = s.error >= 0.5 ? "var(--color-rose)" : isThreat ? "var(--color-amber)" : "var(--color-lime)";

  const subtitle = s.held ? "threat caught in commissioning → kept on inspector (never demoted)"
    : s.reason === "anomaly" ? "sentry flagged anomaly → inspector confirming"
    : s.reason === "sample" ? "random sample → inspector re-verifying"
    : "behavioural drift → inspector re-baselining";

  return (
    <div className="rounded-md border border-line-bright bg-panel-2 p-3 [animation:ns-rise_.3s_ease]">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2"><span className="font-mono text-[14px] font-bold">{s.host.label}</span><StatusBadge status={s.status} reason={s.reason} /></div>
          <div className="mt-0.5 font-mono text-[10px] text-ink-faint">{subtitle}</div>
        </div>
        <div className="font-mono text-[11px] tabular-nums" style={{ color: errColor }}>{s.error.toFixed(2)}</div>
      </div>
      <div className="mt-3">
        <div className="mb-1 flex items-center justify-between font-mono text-[10px] text-ink-dim"><span>reconstruction error</span><span>{isThreat ? "inspector" : "re-verify"}</span></div>
        <svg viewBox="0 0 100 40" preserveAspectRatio="none" className="h-12 w-full">
          <line x1="0" y1={38 - 0.5 * 34} x2="100" y2={38 - 0.5 * 34} stroke="var(--color-rose)" strokeWidth="0.4" strokeDasharray="2 2" opacity="0.6" />
          <polyline points={spark} fill="none" stroke={errColor} strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
        </svg>
      </div>
      <div className="mt-2 grid grid-cols-3 gap-2">
        <Feature label="Egress asym" value={s.exfilSeen ? "0.84" : isThreat ? "0.52" : "0.24"} hot={s.exfilSeen} />
        <Feature label="Polling CoV" value={isThreat ? "0.04" : "0.61"} hot={isThreat} />
        <Feature label="FFT autom." value={isThreat ? "0.92" : "0.19"} hot={isThreat} />
      </div>
      {(s.status === "alerting" || s.status === "critical") && (
        <div className="mt-3 rounded border border-rose/40 bg-rose-dim/60 p-2.5 [animation:ns-rise_.3s_ease]">
          <div className="mb-1 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-rose"><IconSpark /> LLM verdict</div>
          <p className="font-mono text-[11px] leading-relaxed">{verdict(s, simTime)}</p>
        </div>
      )}
      {s.reason === "sample" && <p className="mt-2 font-mono text-[10px] leading-relaxed text-lime">Poison check: unpredictable sample — an attacker can't time around it.</p>}
      {s.reason === "change" && <p className="mt-2 font-mono text-[10px] leading-relaxed text-lime">Drift: new legitimate service pattern — will re-baseline, not alert.</p>}
      {s.held && <p className="mt-2 font-mono text-[10px] leading-relaxed text-rose">Never handed to the sentry — the inspector monitors this host itself.</p>}
    </div>
  );
}

function verdict(s: HostState, simTime: number) {
  const hrs = ((simTime - (s.anchor ?? simTime)) / 24).toFixed(1);
  const conf = Math.min(99, Math.round(s.error * 100 + 2));
  const chain = s.held
    ? "compromised at commissioning → Recon(ip-api) → Paste(raw.githubusercontent) → beacon api.telegram.org (CoV 0.04)"
    : "dormant 9d → Recon(ip-api) → Paste(raw.githubusercontent) → beacon api.telegram.org (CoV 0.04)";
  if (s.status === "critical") return `${s.host.label}: ${chain}, now 4.3:1 egress to drive.google.com after ${hrs}d active. Active exfiltration (T1567); ${s.held ? "held on inspector since commissioning" : "certified host turned kill chain"}. Confidence ${conf}%.`;
  return `${s.host.label}: ${chain} for ${hrs}d. Automated beaconing (T1102); ${s.held ? "flagged during commissioning, never demoted" : "certified-then-activated"}. Confidence ${conf}%.`;
}

function Feature({ label, value, hot }: { label: string; value: string; hot?: boolean }) {
  return <div className="rounded bg-panel px-2 py-1.5"><div className="font-mono text-[9px] uppercase tracking-wide text-ink-faint">{label}</div><div className={`font-mono text-[13px] font-semibold tabular-nums ${hot ? "text-rose" : "text-ink"}`}>{value}</div></div>;
}

/* ---- alert feed ----------------------------------------------------------- */
type Row = { t: number; host: string; kind: string; text: string; tone: "lime" | "amber" | "rose" | "cyan" };
function AlertFeed({ simTime, tier, esc }: { simTime: number; tier: Tier; esc: Win[] }) {
  const rows: Row[] = [];
  // malicious hosts
  for (const m of MAL) {
    const host = HOSTS.find((h) => h.id === m.id)!;
    const heldFromCommission = m.at < tier.commHours;
    if (heldFromCommission) {
      rows.push({ t: m.at, host: m.id, kind: "THREAT IN COMMISSIONING", text: "Inspector caught anomalous chain during commissioning.", tone: "rose" });
      rows.push({ t: tier.commHours, host: m.id, kind: "HELD ON INSPECTOR", text: "Not cleared — never demoted to sentry; inspector keeps monitoring it.", tone: "rose" });
    } else {
      rows.push({ t: m.at + 6, host: m.id, kind: "RE-ESC · ANOMALY", text: "Sentry detected anomalous category transition — returned to inspector.", tone: "amber" });
    }
    const at = alertTof(host); if (at !== null && at >= (heldFromCommission ? 0 : m.at)) rows.push({ t: at, host: m.id, kind: "C2 BEACONING", text: "Inspector confirms automated beaconing to Messaging_API.", tone: "cyan" });
    for (const e of host.events.filter((e) => e.phase === "exfil")) rows.push({ t: e.t, host: m.id, kind: "EXFILTRATION", text: "High egress to Cloud_Storage — active kill chain (T1567).", tone: "rose" });
  }
  // cleared at commissioning end (only hosts NOT held)
  for (const h of HOSTS) {
    const heldFromCommission = h.compromisedAt !== null && h.compromisedAt < tier.commHours;
    if (!heldFromCommission) rows.push({ t: tier.commHours, host: h.label, kind: "CLEARED", text: "Passed commissioning — demoted to distilled sentry.", tone: "lime" });
  }
  // benign re-escalations
  for (const w of esc) {
    if (w.reason === "change") {
      rows.push({ t: w.start, host: w.hostId, kind: "RE-ESC · DRIFT", text: "Behavioural change (new service pattern) — inspector re-baselining.", tone: "amber" });
      if (w.end !== null) rows.push({ t: w.end, host: w.hostId, kind: "DRIFT-CLEARED", text: "Re-baselined as benign — returned to sentry.", tone: "lime" });
    } else {
      rows.push({ t: w.start, host: w.hostId, kind: "RE-ESC · SAMPLE", text: "Random re-verification (poison check) — unpredictable by design.", tone: "amber" });
      if (w.end !== null) rows.push({ t: w.end, host: w.hostId, kind: "SAMPLE-CLEARED", text: "Inspector confirms benign — returned to sentry.", tone: "lime" });
    }
  }
  const visible = rows.filter((r) => r.t <= simTime).sort((a, b) => b.t - a.t).slice(0, 40);
  const tone = (t: Row["tone"]) => t === "rose" ? "var(--color-rose)" : t === "cyan" ? "var(--color-cyan)" : t === "lime" ? "var(--color-lime)" : "var(--color-amber)";

  return (
    <div className="rounded-lg border border-line bg-panel">
      <div className="flex items-center justify-between border-b border-line px-3 py-2">
        <span className="font-mono text-[10px] uppercase tracking-wider text-ink-faint">Chain-level event feed</span>
        <span className="font-mono text-[10px] text-ink-dim">{visible.length}</span>
      </div>
      {visible.length === 0 ? (
        <div className="px-3 py-6 text-center font-mono text-[12px] text-ink-faint">Commissioning in progress — inspector profiling the fleet.</div>
      ) : (
        <div className="max-h-[340px] overflow-y-auto">
          {visible.map((r, i) => (
            <div key={i} className="flex gap-2.5 border-b border-line/60 px-3 py-2.5 last:border-0 [animation:ns-rise_.3s_ease]">
              <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: tone(r.tone) }} />
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[10px] tabular-nums text-ink-faint">{dayClock(r.t)}</span>
                  <span className="font-mono text-[10px] font-bold tracking-wider" style={{ color: tone(r.tone) }}>{r.kind}</span>
                  <span className="font-mono text-[10px] text-ink-dim">{r.host}</span>
                </div>
                <p className="mt-0.5 text-[12px] leading-snug text-ink-dim">{r.text}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---- icons ---------------------------------------------------------------- */
function IconPlay() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z" /></svg>; }
function IconPause() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 5h4v14H6zM14 5h4v14h-4z" /></svg>; }
function IconReset() { return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5" /></svg>; }
function IconSpark() { return <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l2.4 6.6L21 11l-6.6 2.4L12 20l-2.4-6.6L3 11l6.6-2.4z" /></svg>; }
