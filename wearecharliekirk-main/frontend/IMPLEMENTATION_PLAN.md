# NetSentinel Dashboard — Implementation Plan

> Fuses three inputs: **README_COMPREHENSIVE.md** (system architecture & data contracts),
> **DASHBOARD_DESIGN_RESEARCH.md** (UX strategy & component hierarchy), and the
> **aethelats** GitHub repo (visual language: monochrome black/white, glass/bento
> cards, SVG motion, three.js 3D graphs). Where the three conflict, the resolution
> and its rationale are stated explicitly below.

---

## 1. Committed decisions (no open questions)

The user asked to "figure what is optimal and do that." These are decided, not offered:

### Decision A — 3D visualization: **3D attack-correlation force-graph** (primary) with 2D fallback
- **What:** `react-force-graph-3d` rendering attacker IPs → target IPs/domains as an
  orbiting node-link graph. Node size = alert volume; link color = severity; the
  currently-active threat pulses.
- **Why this over a 3D globe:**
  - **Data-faithful (README):** the pipeline's real output is *flows and
    correlations* — source→dest, C2 beacon (src,dst) pairs, DGA domains. A
    correlation graph is a direct view of that; a globe needs invented geo-IP.
  - **Answers the research doc's critique:** the research doc rejects the 3D globe
    because "it conveys nothing / can't read labels." A force-graph of real
    attacker→target edges *does* convey structure, so it satisfies the user's
    explicit "3D graphs" request without inheriting the globe's weakness.
  - **Matches the repo:** aethelats already isolates three.js behind
    `React.lazy` + `Suspense` (`SkillKnowledgeGraph.jsx`). We reuse that exact
    pattern, so the aesthetic and the perf discipline both transfer.
- **Fallback:** a 2D toggle (`react-force-graph-2d`) for weak GPUs — the one piece
  of research-doc caution worth keeping for a live demo.

### Decision B — Scope: **full dashboard, all seven components**
Build every Priority-1→3 component from the research doc. The mock 60-second replay
(README demo script) drives all of them so the whole board is populated live.

### Decision C — Color: **monochrome base, chromatic severity only**
Pure-black canvas, white accent (aethelats tokens). Color appears *only* to encode
threat severity — this simultaneously honors the repo's monochrome identity and the
research doc's "save red for actual threats" principle.

### Decision D — Data layer: **swappable single hook**
`useThreatFeed()` is backed by a mock simulator now; swapping to the README's real
`ws://localhost:8000/ws` is a one-file change because the `Alert` type already
mirrors `alert_manager.py` output.

### Decision E — Stack adaptation: **port aethelats CSS into Tailwind v4**
The repo is Tailwind v3 (`@tailwind` directives + `tailwind.config.js` +
`tailwindcss-animate`). This project is Tailwind v4 (`@import 'tailwindcss'`, theme in
`index.css`, no config). The repo's design system is ~90% plain CSS custom classes +
`@keyframes` + CSS variables, which port verbatim into `src/index.css`. The few
`tailwindcss-animate` utilities are replaced by the repo's own `.animate-*` classes,
which we port anyway.

---

## 2. Architecture reconciliation

| Source | Governs | Applied as |
|---|---|---|
| README_COMPREHENSIVE.md | `Alert` shape, 4 models, MITRE map, WebSocket, 60s demo | data contracts + mock replay |
| DASHBOARD_DESIGN_RESEARCH.md | layout hierarchy, signal-over-noise, component priority | grid + build tiers |
| aethelats repo | monochrome tokens, glass/bento cards, SVG motion, three.js | ported `index.css` + motion vocabulary |

---

## 3. Design tokens (ported to `src/index.css`)

From aethelats `:root`, plus severity semantics layered on:

```
--bg-body:#020202  --bg-base:#000  --bg-surface:#0a0a0a  --bg-surface-hover:#121212
--text-main:#fff   --text-muted:#888  --text-dim:#444
--bg-border:rgba(255,255,255,.05)   --bg-border-hover:rgba(255,255,255,.15)
--bezier-smooth:cubic-bezier(.175,.885,.32,1.275)
/* only chromatic tokens */
--sev-critical:#ef4444  --sev-high:#f59e0b  --sev-medium:#eab308
--sev-low:#22c55e       --sev-info:#888
```

Ported utilities: `glass-card`, `glass-card-hover`, `bento-box`, `panel-base`,
`panel-inset`, `label-mono`, `btn-premium`, `hover-lift`, `hover-glow`, `nav-link`,
`scan-container`, `bg-criss-cross`, the 3D `.cube`, custom scrollbar.

Ported keyframes: `entranceY`, `entranceX`, `tableRowSlide`, `lineDrawIn`,
`nodePulse`, `nodeFloat`, `pulseGlow`, `scanLine`, `shimmer`, `counterPop`,
`barFill`, `ringDraw`, `panCrissCross`, `tabShine`, `neuralExpand`, stagger delays.

Font: Inter via Google Fonts CSS2 `@import` at top of `index.css` (per AGENTS.md).

---

## 4. Data layer

**`src/types/alert.ts`** — normalized to `alert_manager.py`:
```
Severity   = critical | high | medium | low | info
ThreatType = DDoS | C2 Beacon | DGA | Encrypted | Port Scan
Alert { id, timestamp, threatType, severity, sourceIP, destIP?, domain?,
        confidence(0-100), mitreTechnique?, model, indicators[],
        sourceCoords?, destCoords? }
```

- **`src/data/mockFeed.ts`** — replays README's exact 60s script:
  normal → DDoS SYN flood (T1498, 99.7%) → C2 beacon (58.3s interval) →
  DGA (`xkqw8f3m.xyz`, entropy 4.2) → port scan → normal. Emits alerts +
  packet-rate samples; real model metrics (99.3/4.3ms, 93.6/8.1ms, 93.5/6.7ms, 88/12.4ms).
- **`src/data/useThreatFeed.ts`** — returns `{alerts, packetRate[], threatCounts,
  models, mitreMatrix, status}`. **WebSocket swap point.**
- **`src/data/geo.ts`** — README `ipToGeo` private-IP→city map + graph node/link builder.

---

## 5. Layout (research-doc hierarchy, aethelats skin)

```
bg-criss-cross animated grid backdrop (fixed)
┌ HEADER — shield .cube · NetSentinel · ● Monitoring(pulseGlow) · mono clock ┐
├ TOP ────────────────────────┬──────────────────────────────────────────────┤
│  3D Attack-Correlation Graph │  CRITICAL ALERT PANEL                         │
│  (react-force-graph-3d,lazy) │  glass-card · severity border · scan sweep    │
├ MIDDLE ──────────────────────┴──────────────────────────────────────────────┤
│  LIVE ALERT FEED — glass rows, tableRowSlide, mono timestamps, top 50        │
├ BOTTOM ──────────┬───────────────┬───────────────┬───────────────────────────┤
│  Packet Rate     │ Threat Timeline│ MITRE Heatmap │ 4 Model Cards (cube+ring) │
└──────────────────┴───────────────┴───────────────┴───────────────────────────┘
```
Mount stagger via `stagger-1..8` + `entranceY`.

---

## 6. Components & build order

**Tier 1 — MVP core**
1. `index.css` tokens/keyframes + `App.tsx` grid shell + `bg-criss-cross`
2. `Header.tsx` — CSS 3D `.cube` shield mark, `pulseGlow` status dot, mono live clock
3. `data/useThreatFeed` + `mockFeed`
4. `AlertFeed.tsx` — glass rows, `tableRowSlide`, severity dot, mono time, confidence
5. `CriticalAlertPanel.tsx` — highest-severity active alert, severity border,
   `scan-container` sweep, indicators in `panel-inset`, `btn-premium`, `counterPop`

**Tier 2 — 3D + charts**
6. `ThreatGraph.tsx` — `react-force-graph-3d` (lazy/Suspense), attacker→target nodes,
   severity-colored links, active-threat pulse; 2D toggle fallback
7. `TrafficCharts.tsx` — Recharts packet-rate line + severity-stacked area, 60s window

**Tier 3 — differentiation**
8. `MitreHeatmap.tsx` — 14-tactic grid, monochrome white-opacity intensity ramp,
   `nodePulse` on live hits, hover tooltips
9. `ModelCards.tsx` — 4 `bento-box` cards, mini `.cube` + `ringDraw` accuracy ring,
   accuracy/latency in `label-mono`, `pulseGlow` when active

**Tier 4 — polish (if time)**
10. `AlertDetailModal.tsx` (`neuralExpand`), single filter (All/Critical/Last hour)

---

## 7. File tree
```
src/
  index.css                 # ported tokens + keyframes + Inter @import
  App.tsx                   # grid shell
  types/alert.ts
  data/useThreatFeed.ts     # ← WebSocket swap point
  data/mockFeed.ts  data/geo.ts
  components/
    Header.tsx  ShieldCube.tsx  CriticalAlertPanel.tsx  AlertFeed.tsx
    ThreatGraph.tsx  TrafficCharts.tsx  MitreHeatmap.tsx  ModelCards.tsx
    AlertDetailModal.tsx
```

## 8. Dependencies to add
`recharts`, `react-force-graph-3d`, `react-force-graph-2d`, `three`, `lucide-react`.
All three.js-backed code lazy-loaded so first paint stays light.

## 9. Performance discipline (from repo OPTIMIZATION_SUMMARY)
- three.js loads only when the graph mounts (`React.lazy` + `Suspense`)
- `will-change` + `translateZ(0)` on glass cards
- feed capped at 50 alerts, charts at 60-point window
- event listeners registered once (MagneticLensCursor lesson)
