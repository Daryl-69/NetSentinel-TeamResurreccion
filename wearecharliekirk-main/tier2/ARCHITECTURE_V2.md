# NetSentinel — Architecture (V2, as built and validated)

> The current, honest design of the Inspector–Sentry pipeline for detecting
> "Living off Trusted Sites" (LSA/LOTS) attacks, after critique, hardening, and a
> real experiment. This supersedes the original "distil the whole detector" design.
>
> Companion docs: [[CRITIQUE]], [[V2_HARDENING]], [[NetSentinel_ref]], [[cs-bpg-security-method-merged]].
>
> **Not to be confused with [[ARCHITECTURE]]** — that is the V1 deep doc for the six Tier-1
> models (50 KB, still accurate for what is shipped today). This note is Tier 2.
> Code and measured results: `netsentinel-main\v2\` (see its README and `results.json`).

---

## 0. One-paragraph summary

NetSentinel detects attacks that ride only **trusted services** (GitHub, Telegram, Google
Drive, Microsoft Graph…), where no single request is suspicious and the only signal is the
**cross-service category-transition sequence** a host follows over time. It uses two tiers: an
expensive **Inspector** (GPU) that deeply profiles hosts during a setup window and on re-checks,
and a cheap always-on **Sentry** (CPU) that watches every host continuously and decides who to
send back up to the Inspector. The key design correction: **do not shrink the whole detector into
the Sentry.** Shrink only its *summarizer* ("eyes") and make the cheap decision an exact
statistical test — because the "judge each host against its own baseline" part is the one thing
that does not survive model compression.

---

## 1. What it detects and why it's hard

Modern intrusions increasingly avoid custom malware infrastructure and instead **live off trusted
sites**: every hop of the kill chain uses a domain nobody can block.

| Stage | Trusted service abused | What it really is |
|---|---|---|
| Recon | `ip-api.com`, `ipify.org` | victim fingerprinting |
| Payload | `raw.githubusercontent.com`, `pastebin.com` | second-stage code pull |
| C2 | `api.telegram.org`, Graph/Teams, Discord | command & control |
| Exfil | `drive.google.com`, OneDrive, S3 | data theft (MITRE T1567) |

Each request alone is indistinguishable from normal business traffic. Domain allow-lists are
useless (these domains **must** be allowed); IOC/signature feeds are useless (there is no bad
domain to list). The signal is not *where* a host goes — it is the **order, timing, and
category-transition pattern** of who it talks to.

Real-world confirmation this is live: **HazyBeacon** (C2 over AWS Lambda URLs) and **TWINLOOT**
(entire C2 inside Microsoft SharePoint/Teams/Graph, no attacker-owned domain).

---

## 2. What is monitored (unchanged by the redesign)

The redesign changed *how the cheap tier decides*, **not what is watched**. Both tiers still see:

- **Network flow** — bytes up/down, egress asymmetry (upload ≫ download → exfil), duration.
- **Timing / automation** — inter-arrival times, polling regularity, jitter/FFT automation score.
- **Structure (graph)** — a host ↔ service-category graph built by the **Service Category
  Resolver** (domain/SNI/JA4 → semantic category: Recon, Repo, Messaging, Cloud, Browse, Sync…).
- **Sequence (kill chain)** — the cross-service category-transition pattern over a sliding window
  (Recon → Repo → C2 → Exfil).

All of this is fed **into the eyes** (see §3), which compress it into a short per-host,
per-window summary.

---

## 3. The two tiers, and the "eyes vs judgment" split

Every detector does two jobs: **eyes** (summarize raw traffic into a compact embedding) and
**judgment** (decide "is this weird for this host?"). The tiers differ on *both*:

| | Eyes (summarizer / encoder) | Judgment (the decision) |
|---|---|---|
| **Inspector** (big, GPU; setup + re-checks) | **big eyes** — E-GraphSAGE + masked-AE Transformer | big AI judgment (reconstruction error, LLM narrative) |
| **Sentry** (small, CPU; always-on, per host) | **small eyes** — a distilled copy of the big eyes (13.7× smaller) | **plain math** — distance from this host's saved baseline |

- "Eyes" ≠ "Inspector." Both tiers have eyes; the eyes are one component *inside* each tier.
- The **small eyes** are a shrunk copy of the **big eyes**.
- The **Sentry = small eyes + math judgment.** The **Inspector = big eyes + AI judgment.**

### Why split this way (the load-bearing insight)
Published distillation analysis: **global / manifold structure transfers well when compressed
(≈78–88%)**, but **local, per-host deviation detection transfers terribly (≈20%)**. The Sentry's
whole job is the local kind. So:

- **Distil only the eyes** (global structure — transfers well).
- **Never distil the judgment.** Replace it with an exact statistic computed on CPU from a
  baseline recorded during commissioning.

### The Sentry is a router, not a detector
Its only job is: *"should I bother the Inspector about this host?"* It is measured on **recall at
a fixed escalation budget**, not precision — the Inspector supplies precision on escalation.

---

## 4. The pipeline (lifecycle of a host)

```
                         ALL HOST TRAFFIC
                               │
              ┌────────────────┴─────────────────┐
        COMMISSIONING (tiered length)        STEADY STATE
              │                                    │
        ┌───────────┐                        ┌───────────┐
        │ INSPECTOR │ big eyes + AI          │  SENTRY   │ small eyes + math
        │ profiles  │ profiles EVERY host    │ always-on │ per host, per window
        │ everyone  │ + records baseline     │  (CPU)    │
        └─────┬─────┘   (μ_h, Σ_h) in        └─────┬─────┘
              │          SMALL-EYE space            │
     threat found here?                    deviation = distance(z_t ; μ_h, Σ_h)
       ├─ yes → HELD on Inspector (never demoted)   │
       └─ no  → CLEARED → demoted to Sentry ───────►│ > τ ?
                                                     │
                            ┌────────── re-escalate on ──────────┐
                            (a) anomaly  (b) random sample  (c) behavioural change
                                                     │
                                          back to INSPECTOR to confirm
                                                     │
                              ┌──────────────────────┴──────────────────┐
                        benign / drift                              malicious
                     re-baseline → Sentry              deterministic verdict → LLM prose → ALERT
```

**Retention rule:** anything the Inspector flags *during commissioning* is **HELD** on the
Inspector for life — never demoted to the Sentry. Closes the cascade blind spot.

**Baseline space caveat (correctness trap):** because the Sentry judges in **small-eye space**,
the baseline (μ_h, Σ_h) must be recorded in small-eye space — so the small eyes must run *during
commissioning too*, not only the Inspector.

---

## 5. What the experiment actually showed

> **Corrected 2026-09-04.** An earlier version of this section reported that router B won. That
> was an artifact of a bug in `EdgeAggregator`: the max-pool guarded on a clamped denominator, so
> the `-1e9` masking sentinel leaked into the encoder on every empty window (~52% of all windows),
> first-epoch loss 3.7e12. `-1e9` made empty-vs-populated windows trivially separable, and the
> Mahalanobis router harvested that as free signal. Fixed; re-run; **the finding reverses.**

A CPU-only harness trained the Inspector, distilled a Sentry 13.7x smaller, and raced three
routers at equal escalation budget under an honest protocol (temporal train→val→test split,
thresholds calibrated on validation only, 3 seeds ± σ, with DevOps hard-negative hosts that
legitimately produce the same Recon→Repo→Messaging→Cloud sequence).

| Router | Design | AUC vs Inspector | Recall @5% |
|---|---|---|---|
| **A** | distil the whole detector (original V2) | 0.833 ± 0.044 | 35.7% ± 3.9 |
| **C** | deferral head ("would the Inspector flag it?") | 0.839 ± 0.039 | 36.2% ± 5.5 |
| **B** | small eyes + Mahalanobis math | 0.804 ± 0.029 | 31.5% ± 5.7 |

*8 seeds. No pair is separable (A vs C p = 0.74, A vs B p = 0.20, B vs C p = 0.15,
Wilcoxon). The earlier 3-seed ranking — A 0.876, C 0.850, B 0.818 — was noise and is
withdrawn. A is still the build, on the LANL gap: 0.992 vs 0.634.*

Findings:
1. **The original design wins.** Distilling the detector beats distilling only the encoder. The
   distillation-transfer argument in §3 predicted the opposite; at this dimensionality it does not
   hold. **The §3 "never distil the judgment" rule is not supported by our own measurement** —
   keep the *reasoning* on record, but build A (or A+C).
2. **B's variance is 7x A's** (±6.9 vs ±0.9) — the covariance-estimation instability of §6.4:
   ~4k commissioning windows for a 32-dim per-host covariance is too thin even with Ledoit-Wolf.
3. **The "≥95% recall at ≤5% budget" target is NOT met.** Measured **35.7% ± 3.9** — still **7.1x
   better than random** routing. **Do not put ≥95% on a slide.**

Supporting: Inspector AUC 0.875 vs attack windows (the oracle is real, not noise). kNN geometry
overlap 0.346 ("marginal").

### 5b. Distribution-shift stress test

World A (dev-heavy org) trains the encoder; world B (OT/plant-heavy, slower rhythms, lower
volumes) is deployed to cold — baselines re-fit on B, but A's threshold and standardiser applied
unchanged.

| metric | world A | world B | change |
|---|---|---|---|
| Inspector AUC vs attack | 0.873 | 0.852 | −2.4% |
| Router AUC | 0.804 | 0.825 | +2.7% |
| Recall @5% | 32.6% | 36.0% | +10.5% |
| kNN overlap | 0.348 | 0.332 | −4.7% |
| **Flag rate (target 1.0%)** | **6.82%** | **6.26%** | — |

**The mechanism transfers; the calibration does not.** Detection quality barely moves across a
genuinely different organisation. But A's 99th-percentile threshold flags 6.26% in B — and
**6.82% in A's own test period**, so this is not a shift problem, it is a **temporal** one:
test-period reconstruction error runs higher than commissioning-period error even in the same
world. **The threshold decays from the day it is set.**

Consequence for the architecture: every deployment needs its own calibration window *and* rolling
re-calibration. §4 has no such knob. Add one.

### The claim you can defend
> "At a 5% escalation budget the Sentry recovers **37% of everything the Inspector would have
> flagged — 7.1x better than random routing — while being 13.7x smaller and running on CPU.**
> Detection quality holds across a different organisation; the alert threshold does not transfer
> and must be recalibrated per deployment and over time.
> Attack-recall numbers are indicative-only until real benign capture replaces the generator."

**Do not put ≥95% on a slide.**

## 6. Failure modes of the split design (know these before a judge does)

1. **Two gaps stack, not one.** Sentry differs from Inspector in *both* eyes (shrunk) and
   judgment (math vs AI); the losses multiply. Validate each leg separately.
2. **The small eyes are the whole system's ceiling.** If the shrunk summarizer squashes an
   attack window near normal, it never escalates and the Inspector's power is wasted. kNN
   overlap 0.377 is this ceiling showing up.
3. **"Which space is the baseline in?" trap.** Baseline must be in small-eye space; mixing big-
   and small-eye summaries silently breaks everything (see §4).
4. **Plain math assumes one "normal" per host.** Real hosts are multimodal (day/night,
   office/VPN) → single baseline floods false positives; multimodal baseline starves for data
   (covariance singular at d=64 with ~4k windows — needs Ledoit–Wolf shrinkage or diagonal).
5. **Baseline poisoning is easier with small eyes.** A slow attacker active during commissioning
   is summarized *as* normal, and compression blurs it in further. Mitigate with trimmed/robust
   (MCD) covariance + the retention rule + cohort baselining for cold-start.
6. **A small frozen model is an easier attack surface.** Adversary can shape traffic so its
   *summary* collides with normal (embedding collision) and never escalates — they only have to
   fool the cheap 24/7 layer.
7. **Drift hits the eyes silently.** Distilled once, the small eyes drift from what the big eyes
   would produce; catch-rate decays with no alarm. Re-distillation cadence is a hidden cost/knob.

---

## 7. Novelty — what is actually new (and what isn't)

External validation: a systematic review of **91 studies** on abuse of legitimate cloud/public
services as C2 found only 7 addressed detection at all, and **none** did sequence-based,
multi-service, or graph-based detection across multiple legitimate platforms — it explicitly
calls for exactly this. A judge can check it.

**Defensible as novel:**
- **Cross-service category-transition sequence semantics** (the Service Category Resolver +
  modelling transitions between semantic categories).
- **The provenance-labelled LSA chain dataset** (built by emulation — see §8).

**NOT novel — do not claim as invented:**
- The Inspector (E-GraphSAGE + masked-AE Transformer ≈ **GraphIDS**, NeurIPS 2025).
- Distilled lightweight IDS (many 2024–26 papers).
- Cascade-with-escalation / learning-to-defer (an ML subfield).
- Per-entity baseline + deviation (shipping in Sentinel UEBA, Exabeam).
- Mahalanobis on embeddings, jitter-as-signature, CoV beaconing (published / commercial).

---

## 8. Dataset plan (the corpus doesn't exist — build it, honestly)

No public benchmark labels cross-service LSA chains riding trusted domains. Approach:

- **Reuse real multi-stage data** (DARPA TC / OpTC) to validate the sequence hypothesis on
  *real red-team* traffic, not your own generator (kills the circularity objection).
- **Get the asymmetry right:** **benign = real** (consented lab/campus capture — `git pull`, CI,
  Slack, Drive sync, browsing), **malicious = emulated** (MITRE Caldera / Atomic Red Team +
  ~100-line custom agents over real Telegram/Graph/Drive APIs). **Fake benign makes every FP
  number meaningless** — this is the single highest-leverage data task.
- **Label by construction:** the orchestrator logs each action (timestamp, host, stage, ATT&CK
  technique); join against Zeek `conn.log`/`ssl.log` by (host, time-window).
- **Honest evaluation:** temporal splits, calibrate on validation only, multi-seed ± σ, report
  precision at a fixed alert budget (not accuracy).

---

## 9. Positioning — critical infrastructure first, LOTS second

- **Behind a data diode, EDR is absent** (no agent on a PLC/HMI/relay) and **bidirectional tools
  (Snort/Suricata/Zeek) are structurally disqualified** — your passive, unidirectional,
  metadata-only design is the *only* shape that fits.
- **OT hosts have near-deterministic comms**, so the "DevOps traffic looks identical" objection
  (B3) largely evaporates.
- **The seam to bridge:** behind a diode there is no Telegram/GitHub/Drive, so the LOTS threat
  model itself doesn't apply there. Resolve it by redefining **"service category" as internal
  asset class** (HMI, historian, engineering workstation, PLC): the *taxonomy* changes, the
  *mechanism* does not. Lead with OT; demo the trusted-sites story as the IT generalization.

---

## 10. Cost argument

With build B, **steady state uses zero GPU** — the always-on Sentry is a CPU encoder + a math
test. GPU is used **only during commissioning and re-escalation.**

```
GPU-host-days = H·D              (one-time commissioning)
              + H·(r + e)·365     (ongoing: sampling r + anomaly re-escalation e)
vs. inspect-all = H·365
```
Worked example (H=1000 hosts, D=14 d, r=1/30/day, e=0.02/day): inspect-all ≈ 365,000/yr;
NetSentinel one-time 14,000 + ongoing ≈ 19,400/yr → **≈95% steady-state reduction.**
VRAM is constant in host count (neighbor mini-batching bounds the graph). Distillation speedup:
cite the measured 26–181× range, not an invented number.

---

## 11. Honest limitations (say these first)

- **No real LSA chain corpus exists** — cost-recovery is proven against the Inspector-as-oracle
  (which proves agreement, *not* detection); always pair with DARPA-TC results.
- **37%, not 95%,** recall at a 5% budget on the current synthetic run.
- **The alert threshold does not transfer** — not across organisations and not across time. Needs
  a per-deployment calibration window and rolling re-calibration.
- **The small eyes cap the whole system;** their quality (kNN overlap) must be measured, not
  assumed.
- **Against an adversary who perfectly mimics human timing, the automation channel is lost** —
  but that forces a capped polling rate; price the evasion, don't claim to stop it.
- **On a managed endpoint, EDR wins** — NetSentinel is for the machines EDR cannot reach.

---

## 12. Build order for the finale (impact ÷ effort)

1. **Sentry-as-router — build A (distilled detector), optionally A+C.** *(Was "build B";
   corrected 2026-09-04 after the bug fix reversed the result.)*
2. **Recall-vs-escalation-budget chart** (the deliverable that wins the room).
2b. **Rolling re-calibration** — the shift test says the threshold decays; nothing implements it.
3. **GPU cost model + measured cost recovery on your own run.**
4. **Automation gate — IAT distribution-family test** (uniform IAT = jittered beacon).
5. **Deterministic verdict + LLM demoted to presentation-only** (+ replay bundle).
6. **Real consented benign capture.**

**Do not build:** E-GraphSAGE at enterprise scale, blockchain anchoring, SHAP, the
meta-classifier ensemble.

---

## Sources
- GraphIDS — arXiv:2509.16625 (NeurIPS 2025)
- E-GraphSAGE — arXiv:2103.16329
- *What Knowledge Transfers in Tabular Anomaly Detection? A Teacher–Student Distillation Analysis* — MDPI MAKE 8(3):60
- *When Does Confidence-Based Cascade Deferral Suffice?* — NeurIPS 2023
- *OOD Detection in High-Dimensional Data Using Mahalanobis Distance — Critical Analysis*
- *How Benchmarks and Evaluation Protocols Shape Conclusions in Provenance-Based IDS* — arXiv:2608.01454
- StageFinder — arXiv:2603.07560
- *Abuse of Cloud-Based and Public Legitimate Services as C2: A Systematic Literature Review* (91 studies)
- Varonis, *The Jitter-Trap: How Randomness Betrays the Evasive*
- DARPA OpTC usefulness — arXiv:2103.03080
- LOTS Project — https://lots-project.com/
