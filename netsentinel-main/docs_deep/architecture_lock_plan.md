# Plan: Lock the architecture (docs) + rework NetSentinel demo to the enroll→distill→re-escalate flow

## Context
Through several iterations the design converged from a "cheap-gate-first cascade" (which mapped to known triage IDS / UEBA and had a gate-as-single-point-of-failure) to a more defensible **expensive-teacher → distilled-cheap-student** architecture:

> Expensive teacher runs on **all** traffic during a **tiered enrollment window** (length = purchased plan). Hosts that pass are demoted to an always-on **distilled cheap student**. The student re-escalates a host back to the expensive model on **(a)** any detected anomaly, **(b)** random sampling (unpredictable, poison-resistant), or **(c)** a behavioural change. **Rolling re-enrollment** re-baselines over time; **threat-intel scrapers** keep the Service Category Resolver taxonomy current. The honest tradeoff is now three tunable knobs (sampling rate, re-enrollment cadence, student sensitivity), and the open research question is student sensitivity vs. cost (a knowledge-distillation problem).

Two deliverables, both requested:
- **(a) Docs:** capture this as the locked architecture + threat model in the merged notes.
- **(b) Demo:** rework `src/App.tsx` so the visualization tells *this* story (enrollment cost → cheap steady-state → the three re-escalation triggers, including a dormant-then-active attacker caught on activation), with the GPU meter reflecting enrollment vs. cheap steady-state cost.

## (a) Docs — `src/imports/pasted_text/cs-bpg-security-method-merged.md`
Append a new top-level section **"7. Architecture, Threat Model & Open Question"** containing:
- **Locked architecture** (the block-quote above, expanded into prose + a small ASCII flow: `Teacher (tiered enrollment) → distilled Student (always-on) → re-escalate on {anomaly | random sample | behavioural change} → Teacher confirm → LLM verdict`).
- **Prior art it builds on** (knowledge distillation / teacher-student; UEBA behavioural baselining; cascade/triage IDS) — stated plainly so novelty isn't over-claimed.
- **Why it resists the classic failures:** poisoning (sampled re-escalation + "any flaw returns to expensive"), window-wait bypass (random sampling can't be timed), drift (rolling re-enrollment for behavioural drift; scrapers for taxonomy drift — noted as two *distinct* drift types).
- **The three knobs** (sampling rate ↔ poison resistance/cost; re-enrollment cadence ↔ drift resistance/cost; student sensitivity ↔ catch-rate/false-positives/re-escalation frequency).
- **Residual risks kept honest:** student sensitivity is the system ceiling; activation→first-detectable-flaw latency; lower purchased tiers = softer targets; scope monitoring by data sensitivity, **not** pay grade.
- **Open research question:** how cheap can the distilled student get while staying sensitive enough that re-escalation fires on real attacks but not benign drift.

## (b) Demo — rewrite `src/App.tsx`
Reframe the simulation from a 6h window to a **14-day timeline** with two phases and the new pipeline. Keep the committed terminal/observability aesthetic and existing theme tokens in `src/index.css` (no CSS token changes needed; may add a couple of keyframes/util classes).

**Timeline & phases**
- Unit = hours; `SIM_END = 336` (14 days). Clock shows `Day N · HH:00` + a phase badge.
- **Tier selector** (Basic / Pro / Enterprise) sets enrollment length (e.g. 3 / 5 / 7 days) and sampling rate (e.g. 8% / 5% / 3%). Replaces the old speed-only control set (keep play/pause/speed/scrub).
- Phase = `enrollment` while `simTime < enrollDays`, else `steady`.

**Hosts / scenario**
- Same fleet shape (~7 hosts). The attacker (`LT-8823`) is **dormant during enrollment** (emits benign traffic → gets *certified*), then **activates a kill chain in steady state** (Recon→Paste→C2 beacon→Cloud exfil starting ~Day 9). It is caught by trigger (a) on its first post-activation flaw — demonstrating the poisoning fix + the activation→detection latency.
- One benign host demonstrates trigger (c): a **behavioural change** (role change / new SaaS category) mid-steady-state → re-escalated → **cleared after re-baseline** (transient, resolves — shows drift handling).
- Random benign hosts periodically demonstrate trigger (b): **sampled re-escalation** → return clean (shows poison resistance without an alert).

**Detection state model (derive per host at simTime)**
- Statuses: `profiling` (enrollment, on teacher) → `certified` (on cheap student) / `flagged`; in steady state: `student-ok`, `re-escalated` (temporarily on teacher: reason = anomaly | sample | change), `alerting`, `critical`.
- Reconstruction-error curve reused/adapted from current `errorAt`, but the attacker's error stays flat/benign during enrollment and climbs only after activation.
- Re-escalation events carry a `reason` so the UI and alert feed can label them.

**UI sections (evolve the existing components)**
- **Header:** clock with Day/phase, tier selector, play/pause, speed, scrub.
- **Pipeline rail (relabelled):** `Teacher · enrollment (N)` → `Student · always-on (N)` → `Re-escalations (N: anomaly/sample/change)` → `LLM alerts (N)`.
- **GPU meter (reworked, the core efficiency story):** instantaneous *expensive vs cheap* load — high plateau during enrollment (teacher on all), then drops to cheap steady-state with small re-escalation spikes; compare against an "always-expensive" baseline line; show **cumulative units saved**.
- **Network graph:** keep host↔service-category graph; color by new status; show a re-escalation halo when a host is temporarily back on the teacher.
- **Fleet table:** per-host phase/status + which layer it's currently on (Teacher/Student) + last re-escalation reason.
- **Sessions/escalations panel:** active re-escalations with reason, mini error sparkline, edge features, LLM verdict on alert/critical.
- **Alert feed:** chain-level events, now including CERTIFIED, RE-ESCALATED (reason), DRIFT-CLEARED, C2, EXFIL.

**Reuse from current file:** `mulberry32`/`rand`, `CAT_ORDER`/`CAT_META`, event-generation helpers, `errorAt` shape, `wallClock`/formatting (add a `dayClock`), `Ring`/`Bar`/`Feature`/`LegendDot`/icons, SVG graph layout math. Most structure stays; the phase/tier logic and status vocabulary are the new parts.

## Verification
- Dev server (already running on `$PORT`, hot reload) — open preview.
- Confirm: during enrollment the GPU meter sits near the always-expensive baseline and all hosts show `profiling`; at enrollment end benign hosts flip to `certified`/`student-ok` and GPU drops sharply.
- Confirm the dormant attacker is `certified` through enrollment, then on activation (~Day 9) trips trigger (a), re-escalates, and reaches `alerting`→`critical` — with a visible latency between activation and detection.
- Confirm a **sampled** re-escalation (b) returns clean, and a **behavioural-change** (c) host re-escalates then drift-clears.
- Confirm cumulative "units saved" vs always-expensive is materially positive by end of run.
- Confirm tier selector changes enrollment length + sampling rate and the meter/counts respond.
- No console errors (`figma logs` only if a failure is observed). Note: direct `tsc`/build Bash calls have been sandbox-denied previously; rely on hot-reload + careful review.
