# NetSentinel v2 — Critique, Integration, Fixes & Improvement Plan

_One document covering: (1) what the system now is, (2) the professional critique with
verification, (3) how the new v2 frontend (`jipper`) integrates with the existing
backend + 6 flow models + the GNN idea, (4) the fixes for every flaw, and (5) how to
improve all of it into a defensible SIH submission._

> Passive, unidirectional **detection** sensor. Detect + alert only — no block /
> quarantine / mitigate. EDR-**complementary**, agentless-first.

---

## 0. The system in one picture

```
                     ┌────────────────── v1: FLOW TIER (built, "validated groundwork") ──────────────────┐
   PCAP / live  ──▶  │  extraction → 6 ML models (DDoS·DGA·C2·ETT·PortScan·Exfil) → per-flow alerts      │
                     └───────────────────────────────────┬──────────────────────────────────────────────┘
                                                          │  flow stats + model outputs become EDGE FEATURES
                                                          ▼
   ┌──────────────────── v2: GRAPH / BEHAVIORAL TIER (the contribution) ─────────────────────────────────┐
   │  Service Category Resolver (domain → Cloud_Storage / Messaging_API / Recon_API / …)                  │
   │  → temporal graph (host nodes, category edges: egressAsymmetry, pollingCoV, fftAutomationScore)      │
   │  → E-GraphSAGE + masked-autoencoder (self-supervised; reconstruction error = anomaly)                │
   │                                                                                                       │
   │  DELIVERY PIPELINE (what the jipper frontend visualizes):                                             │
   │     Teacher/Inspector (expensive, tiered COMMISSIONING on ALL hosts)                                  │
   │        → distilled Student/Sentry (cheap, always-on)                                                  │
   │           → RE-ESCALATE on { anomaly | random sample | behavioural change } → Teacher confirm         │
   │              → LLM verdict (presentation layer over a deterministic decision)                         │
   │     Retention rule: a threat caught DURING commissioning is HELD on the Teacher, never demoted.       │
   └───────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Three tunable knobs (state honestly): **sampling rate** ↔ poison resistance/cost;
**re-enrollment cadence** ↔ drift resistance/cost; **student sensitivity** ↔
catch-rate vs. false-positives. The open research question is student sensitivity vs. cost.

---

## 1. Professional critique — verified

Verdicts cross-checked against the actual code/behaviour we've established.
✅ True · ⚠️ Directionally true / caveat · ❌ Not applicable as written.

### Part A — the v1 prototype (6 flow models)

| # | Claim | Verdict | Verification |
|---|---|---|---|
| A1 | Solved/commoditized space (~4.3/10 uniqueness) | ✅ | DDoS/DGA on CIC/CTU is done by every firewall vendor + hundreds of repos |
| A2 | Base-rate neglect: FP/analyst/shift is the real metric; 8.4% FP = thousands/day, unusable | ✅ **the killer** | Math is right — and you're living it: exfil is at ~50% FP right now |
| A3 | ETT separates VPN/non-VPN but not malicious vs legit VPN — the only useful split | ✅ | Matches the ETT limitation; headline capability has no security payoff |
| A4 | 42.5 flows/sec, 2–3 orders below enterprise line rate | ⚠️ | Number is from your own doc (unmeasured here); single-threaded Python+ONNX being far below line rate is certainly true |
| A5 | Synthetic-traffic validation is circular (learns the generator) | ✅ | Exactly the simulator problem — models score synthetic at 0.01–0.17% because features are out-of-distribution |
| A6 | Non-deployable ops gaps: in-memory alerts, no auth, no SIEM/SOAR, no IP reassembly | ✅ | Confirmed: `alert_manager` is in-memory (lost on restart), no auth |

### Part B — the v2 architecture (this is exactly what `jipper` implements)

| # | Claim | Verdict | Verification |
|---|---|---|---|
| B1 | Student/Sentry sensitivity is the whole ballgame; distillation loses rare-class recall — the recall you can't afford | ✅ **core risk** | The demo's own plan calls student sensitivity "the open research question." No evidence yet the student keeps the teacher's recall on quiet chains |
| B2 | No LSA dataset → can't prove the central claim; emulation ⇒ learns your generator | ✅ **biggest gap** | Doc confirms Mythic emulation is the plan; no real provenance-labelled corpus exists. Same trap as A5 |
| B3 | Category-transition signal may be weak; benign DevOps produces near-identical sequences | ✅ | `git pull → API → Slack → Drive` is a normal dev day; the merged doc itself flags this false-positive noise |
| B4 | Egress asymmetry / low CoV / FFT periodicity are known & cheaply evadable (jitter/pad) | ✅ | RITA/UEBA already use CoV beaconing; the merged doc admits timing "can be randomized" |
| B5 | Pricing tier = softer targets; attacker waits out the shorter window | ✅ | `jipper` TIERS set commissioning length by plan (Basic 3d / Pro 5d / Ent 7d) — this literally encodes the flaw |
| B6 | Activation→detection latency = dwell time = data already gone | ✅ | The demo shows a ~6h gap between attacker activation and detection — honest, but buyers measure dwell time |
| B7 | LLM verdict layer is non-deterministic, hallucination-prone, un-auditable | ✅ | Must be a presentation layer over a deterministic verdict, never the decision |
| B8 | Poisoning defense (random sampling) is probabilistic, not "poison-proof" | ✅ | Correct — state it as expected-time-to-detection, not immunity |

### Part C — the meta-flaw a panel WILL press

**Network-only, but LSA begins with host process injection (e.g. into `onedrive.exe`),
which EDR sees directly and cheaply.** ✅ **True and decisive.**
- Framed as "we replace EDR" → you lose (strictly worse on the host signal).
- Framed as "we cover what EDR **cannot reach**" → you win: agentless / unmanaged /
  BYOD / guest / IoT / OT where no endpoint agent can be installed. Real, unserved gap.

### Part D — additional flaws (all ✅, all hit v2)
- **DoH/DoT/ECH** hide the SNI/hostname the Service Category Resolver depends on — its
  input shrinks over time.
- **Cloud/CDN IP churn** makes IP→category mapping noisy and stale.
- **Privacy/DPDP 2023 / GDPR** — per-host behavioural profiling needs a lawful basis.
- **Undefined eval metric** — no precision/recall at a fixed alert budget, no PR/ROC, no cost matrix.
- **Cold-start** — a host compromised before/at enrollment has no benign baseline (attacker-in-the-baseline).
- **Single-tenant** — baselines don't transfer; every deployment is a fresh cold-start.

**Correction to an earlier note:** these Part B/C/D flaws DO fully apply here, because
`jipper` implements the elaborate Inspector/Sentry + tiers + LLM design (not the leaner
GNN-only subset).

---

## 2. Integration — new frontend (`jipper`) ↔ backend

### 2.1 What `jipper` is today
`src/App.tsx` is a **single-file, self-contained simulation** (seeded RNG, 14-day
timeline, dormant-attacker scenario). It renders the whole v2 story — tier selector,
Teacher→Student pipeline rail, GPU meter (expensive vs cheap + cumulative units saved),
host↔category graph, fleet table, re-escalation panel, alert feed. It has **no live data
layer** — everything is generated client-side. This is a **presentation prototype**, not
wired to the backend.

### 2.2 Target contract (make it live without changing the story)
Introduce the same swappable data-layer pattern used in the v1 dashboard
(`useThreatFeed`): a hook that connects to the backend and falls back to the built-in
simulation when offline. The backend must emit **host-window graph events**, not just
per-flow alerts:

```jsonc
// ws frame: type "graph_window"
{
  "type": "graph_window",
  "data": {
    "window_id": "w_2026...", "t_start": "...", "window_minutes": 5,
    "host": { "id": "LT-8823", "role": "dev-laptop", "layer": "student",   // teacher|student
              "status": "re-escalated", "reason": "anomaly" },              // anomaly|sample|change
    "edges": [
      { "cat": "Messaging_API", "domain": "api.telegram.org",
        "egress_asymmetry": 0.12, "polling_cov": 0.03, "fft_automation_score": 0.91,
        "flow_model": { "name": "c2_beacon_bilstm", "confidence": 0.88 } }   // ← v1 output as edge feature
    ],
    "recon_error": 0.74, "verdict": { "llm": "…", "deterministic_score": 0.81, "mitre": ["T1567"] }
  }
}
```

### 2.3 How v1 feeds v2 (the real combination)
The 6 flow models are **not replaced** — their outputs + flow stats become **edge
attributes** on the graph:
- C2 FFT periodicity → `fft_automation_score`, `polling_cov`
- Exfil byte accounting → `egress_asymmetry`
- Each per-flow model's `{name, confidence}` → an edge feature the GNN consumes
- Service Category Resolver maps the flow's domain/IP → node category

So v1 = "validated groundwork" that supplies rich edge features; v2 = the GNN + Teacher→Student
pipeline that scores the **sequence**. This is the honest, non-throwaway integration.

### 2.4 Frontend mapping (already present in `jipper`, just needs live binding)
| UI element | Backend field |
|---|---|
| Tier selector (Basic/Pro/Ent) | commissioning length + sampling rate (config) |
| Pipeline rail counts | count of hosts on teacher / student / re-escalations / LLM alerts |
| GPU meter (expensive vs cheap, units saved) | per-host layer × GPU_INSPECTOR(100)/GPU_SENTRY(6) |
| Graph node color + re-escalation halo | `host.status`, `host.layer` |
| Fleet table | `host.role/status/layer/reason` |
| Re-escalation panel | `reason`, `recon_error` sparkline, `edges[]` features |
| Alert feed | chain-level events + `verdict` |

---

## 3. Fixes — every flaw mapped to a concrete action

### v1 (do first — these gate any accuracy claim)
1. **Exfil ~50% FP** → pin `scikit-learn==<training version>`, re-pickle `exfil_scaler.joblib`,
   upload to HF, re-run PCAP, confirm rate drops to single digits. (Deployment bug, not training.)
2. **Circular/synthetic validation (A5)** → validate on **real** labelled PCAPs:
   Thursday CIC-IDS-2017 (port scan), CIC-DDoS2019 (DDoS), CTU-13/malware-traffic-analysis.net
   (C2/DGA), iodine/dnscat2 (exfil). Record confidence + FP per model.
3. **Covariate shift** → `rm ours.csv && python scripts/covariate_shift.py`; align feature
   units to CICFlowMeter; drop rate/flag KS below 0.1.
4. **Ops gaps (A6)** → add alert persistence (SQLite/Postgres), auth on the API, a SIEM/SOAR
   webhook, and upload validation (reject executables/pickles/oversized).
5. **Doc inconsistencies** → one reproducible train/val/test report; every doc cites it.

### v2 (design fixes — bake into the architecture now, cheap on paper)
6. **B1 student sensitivity** → treat as the stated open problem; measure **student recall vs.
   teacher recall on held rare chains** and publish the curve. Add "any student uncertainty →
   escalate" as a safety default.
7. **B2 dataset** → build the Mythic-emulated corpus BUT (a) label at the **chain** level,
   (b) hold out **tools/profiles** not just samples, (c) mix in real consented benign capture
   so the model can't shortcut on generator artifacts. State the limitation out loud.
8. **B3 DevOps false positives** → per-**role** baselines + hard-negative benign capture
   (git pull → CI → Slack → Drive) in training; report FP at a fixed alert budget.
9. **B4 evadable features** → don't rely on timing alone; combine with egress asymmetry +
   category-transition rarity; document evasion cost, don't claim robustness.
10. **B5 tier contradiction** → **scope commissioning/monitoring by data sensitivity, not pay
    grade.** Pricing may affect *cost*, never the coverage floor. (Change the `jipper` tier
    copy to reflect sensitivity tiers, not plan tiers.)
11. **B6 dwell time** → report expected activation→detection latency as a metric; position as
    EDR-complementary so host-side catches the injection immediately.
12. **B7 LLM** → LLM is presentation only; the alert decision is a deterministic score. Show
    both in the UI (`deterministic_score` drives severity; `llm` is the human-readable story).
13. **B8 poisoning** → state random-sampling as expected-time-to-detection with the sampling
    rate, not "poison-proof."
14. **C meta-flaw** → reframe all messaging as **EDR-complementary, agentless-first**.
15. **D resolver erosion** → plan for DoH/DoT/ECH: fall back to IP-reputation + JA4 + SNI-less
    category inference; keep taxonomy scrapers for CDN churn; document the shrinking-input risk.
16. **D privacy** → add a data-governance note (lawful basis, retention, anonymization).

---

## 4. How to improve — the winning framing

Follow the critique's Part E, in priority order:
1. **Lead with v2; demote the 6 models to "validated groundwork."** The distillation +
   retention-rule + unpredictable-sampling combination is the defensible novelty.
2. **Reframe as EDR-complementary, agentless-first.** Dodges the meta-flaw honestly and points
   at a real unserved market (BYOD/IoT/OT/guest/unmanaged).
3. **Prove ONE claim rigorously**, e.g. *"~90% inspection-GPU cost recovered vs. inspect-all,
   while retaining detection on the held scenarios"* — show the cost/coverage tradeoff with
   numbers (the `jipper` GPU meter is literally this story; back it with real measurements).
4. **State the open problems out loud** — student sensitivity + the missing LSA dataset.
5. **LLM as presentation over a deterministic verdict**, and say so.
6. **Fix the tier contradiction** — sensitivity, not pay grade.

### Sequencing (don't research in the wrong order)
1. Fix v1 exfil + prove the 6 models on **real** PCAPs → establishes the groundwork is real.
2. Wire `jipper` to a live `graph_window` feed (even replayed) → the demo stops being a pure sim.
3. Build the chain-level LSA dataset (Mythic + consented benign) → unlocks the only claim that matters.
4. Measure the cost/coverage curve and the student-vs-teacher recall curve → your two headline numbers.

---

## 5. Status snapshot

| Layer | State |
|---|---|
| v1 flow extraction + 6-model routing | ✅ built |
| v1 exfil scaler | ❌ FP ~50%, scaler pin + HF upload pending |
| v1 real-PCAP validation | ❌ unproven (only synthetic so far) |
| v1 ops (persistence/auth/SIEM/upload validation) | ❌ missing |
| v2 concept (GNN masked-AE, Service Category Resolver) | 📄 designed, not built |
| v2 pipeline demo (`jipper` Teacher→Student) | ✅ visualized, ❌ not wired to backend |
| LSA chain-level dataset | ❌ does not exist (the core blocker) |
| Framing (EDR-complement, one rigorous claim, honest limits) | ⚠️ needs adoption |

---

_Items depending on unpushed code are unverifiable here; push and they can be confirmed
against the repo._
