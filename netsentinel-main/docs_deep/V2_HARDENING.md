# V2 Hardening — Solving the Inspector–Sentry Critiques

> Companion to [[CRITIQUE]], [[NetSentinel_ref]], [[cs-bpg-security-method-merged]].
> Every critique item B1–B8, C, D gets a concrete fix, a cost, and a measurable claim.
> Written 2026-09-04. Sources listed at the end.

---

## 0. The one-paragraph summary

Your architecture has **one load-bearing assumption that current literature says is false as designed**, and everything else is fixable engineering. The false assumption: that you can distill the Inspector into a Sentry that still detects *local, per-host* deviation. Published distillation analysis shows local-outlier detection transfers at **20%** and neighborhood-based detection retains **76%**, while global/isolation-based detection transfers at 78–88%. Your Sentry is doing exactly the local kind. **Fix: stop distilling the detector. Distill the encoder, and make the local decision a non-neural statistical test.** That single change converts your biggest open research question into a measurable curve, removes GPU from steady state entirely, and is the thing you should build before the Grand Finale.

---

## Part B fixes

### B1 — Sentry sensitivity (the ballgame)

**The evidence against the current design.** A 2026 teacher–student distillation analysis on tabular anomaly detection found the student retains up to **98.5% of teacher AUC-ROC** (84.7% mean across datasets) at **26–181× inference speedup** — but with a sharp asymmetry in *what* transfers:

| Detection paradigm | Transfer / retention |
|---|---|
| Global outliers | 78% transfer |
| Isolation-based | 88% retention |
| **Neighborhood-based** | **76% retention** |
| **Local outliers** | **20% transfer** |

Your Sentry's job — "has *this* host deviated from *its own* baseline" — is textbook local-outlier detection. The literature says that is the one thing that does not survive compression. A reviewer who knows this will kill B1 on sight.

**The fix: split representation from decision.**

```
Teacher (GPU, commissioning + re-escalation only)
  E-GraphSAGE + masked-AE Transformer
        │
        ├── distill ENCODER only ──► Student encoder (CPU, small, always-on)
        │                                    │
        │                              per-window embedding z_t (d = 64–128)
        │                                    │
        └── commissioning ──► per-host baseline (μ_h, Σ_h) stored, NOT learned by student
                                             │
                        deviation = Mahalanobis(z_t ; μ_h, Σ_h)   ← exact, not distilled
                                             │
                                  > τ  ──► re-escalate to Teacher
```

Why this works: the encoder learns *global manifold structure*, which is the class that transfers at 78–88%. The local density decision — the part distillation destroys — is never distilled at all. It becomes an exact O(d²) statistic per host per window, computed on CPU from stored baseline moments.

**Three supporting changes:**

1. **Anomaly-weighted distillation loss.** Standard KD minimizes mean divergence, which is precisely why rare signals wash out. Weight by the teacher's own anomaly score:

   `L = E[(1 + λ·s_teacher(x)) · ‖f_student(x) − f_teacher(x)‖²]`

   Three-line change. Forces student capacity onto the examples the teacher found hardest.

2. **Robust baselining.** Fit (μ_h, Σ_h) with the top *q*% highest-teacher-error windows **trimmed**. This directly attacks *attacker-in-the-baseline* (Part D): a slow attacker present during commissioning contributes less to "normal". Use a trimmed / MCD covariance estimator, not the plain sample covariance.

3. **Cohort fallback for cold start.** A host with no baseline yet is scored against the **cohort** of same-role hosts, not against itself. Removes the day-1 blind spot the CRITIQUE flags.

**The measurable claim this unlocks — build this chart, it is your Grand Finale deliverable:**

> **Sentry recall vs. escalation budget.** X-axis: fraction of host-windows escalated. Y-axis: fraction of teacher-flagged windows recovered. Target to state: *"escalating ≤5% of host-windows recovers ≥95% of everything the Inspector would have flagged."*

Note what this measures: **student-vs-teacher agreement**, not student-vs-ground-truth. That means **you can prove it with the data you already have** — the teacher is the reference oracle. This is exactly the "prove ONE claim rigorously" that CRITIQUE §E3 asks for, and it sidesteps B2 entirely.

The Sentry is **not a detector. It is a router.** Its target metric is recall at a fixed escalation budget. Precision is irrelevant — the Inspector supplies precision. Say this explicitly; it reframes the whole objection.

---

### B2 — No dataset, can't prove the core claim

You will not have a real LSA chain corpus by the Finale. Stop trying. Four moves instead:

**1. Change the claim to one that needs no adversary-realistic data.** Cost recovery at fixed coverage (the B1 chart above) is provable with the teacher as oracle. Lead with it.

**2. Use the real multi-stage data that does exist.** DARPA OpTC and DARPA Transparent Computing carry labeled red-team engagements with genuine multi-stage chains. Recent work (StageFinder, 2026) uses OpTC for self-supervised pretraining and TC for labeled fine-tuning, reporting macro-F1 0.96 on stage estimation. They are host-provenance-heavy, not LOTS-specific — but their network components are *real red-team sequences, not your generator*. That kills the circularity objection for the sequence hypothesis even though the services differ.

**3. Get the asymmetry right: benign real, malicious emulated.** The dominant error is unrealistic *benign* data, not unrealistic attacks. If your benign side is `traffic_gen.py`, every false-positive number you report is meaningless. Capture real consented benign traffic — your own lab/campus: `git pull`, CI runs, Slack, Drive sync, browsing. That is days of work, not months. Then layer Mythic-emulated chains on top. Report FP on real benign, detection on emulated malicious, and **state the asymmetry out loud** before anyone asks.

**4. Adopt a defensible evaluation protocol.** A 2026 study of provenance-IDS benchmarks found that published conclusions are routinely distorted by three specific errors. Fixing them is free and puts you above most of the literature:

| Error | Fix |
|---|---|
| Random train/test splits leak future behavior | **Strictly monotonic train → validate → test in time** |
| Thresholds tuned on the test period | **Calibrate on validation only**, never test |
| Single-seed results mistaken for architecture effects | **Multi-seed, report mean ± variance** |

Also pair your headline metric with average precision / ranking metrics — "detected at least one true positive per scenario" credits a system that dumps an unusable alert on the analyst.

---

### B3 — Category transitions may be too weak (the strongest critique)

Honest read: **category sequence alone is too weak.** DevOps genuinely produces Recon→Repo→Messaging→Cloud all day. Fix by making the signal *conditional and conjunctive*, never marginal.

**1. Condition on the host's own history, never a global grammar.** `P(transition | this host)`, not `P(transition)`. GitHub→Slack→Drive is unremarkable for a dev box and extraordinary for a receptionist's laptop. Your reconstruction-error-vs-own-baseline formulation already gives you this — just never fall back to a global allow-list, which is where the FP flood comes from.

**2. Make automation a necessary condition, not a co-equal feature.** Fire only on:

```
off-path category transition
        AND automation score > θ_auto      (machine timing)
        AND egress asymmetry > θ_egress     (upload-heavy terminal hop)
```

A legitimate DevOps chain has human-initiated segments; a scripted chain does not. Conjunction of three weak-but-independent signals is far stronger than any one, and it is how the FP rate gets to SOC-viable.

**3. Encode direction and volume per category edge, not edge existence.** The byte-direction profile differs even when the category sequence is identical:

| Hop | Legit dev | LSA chain |
|---|---|---|
| Code repo | download-heavy | download-heavy *(identical)* |
| Messaging | bursty, human-sized, irregular | tiny up / tiny down, perfectly regular |
| Cloud storage | bidirectional sync | **large one-shot upload** |

The sequence collides; the shape does not.

**4. Publish the number even if it's bad.** "On N host-days of real benign dev traffic, X% contain the full category sequence; adding the automation gate reduces it to Y%." Reporting a disappointing Y is worth more to a panel than claiming the sequence works.

---

### B4 — Features are known and evadable

There is a genuinely good counter here, and it inverts the objection.

**Randomization is itself a signature.** A beacon configured with 60s sleep and 20% jitter produces inter-arrival times that are **uniformly distributed on [48, 72]**. Uniform IAT distributions are *rare* in legitimate traffic — human traffic is bursty and heavy-tailed, machine polling is near-constant. So don't test for low CoV. Test for **distribution family**:

| IAT distribution | Interpretation |
|---|---|
| Near-constant | naive beacon |
| **Uniform** | **jittered beacon — the evasion itself** |
| Heavy-tailed / Poisson-ish | human |
| Bursty / clustered | app sync, batch |

Use KS and chi-square tests against each family. Two of the four are machine signatures. Add the endpoint-entropy ratio: distinct-endpoints ÷ requests → 1.0 is a domain/URL randomizer fingerprint, a ratio benign traffic almost never shows.

**Then state the residual honestly, as an imposed cost.** Against an adversary who fully shapes timing to mimic human heavy-tailed behavior, you lose the timing channel. But they have now had to accept IAT variance ≥ X, which caps effective polling rate — quantify it: *"evading the automation gate forces the adversary below Y polls/hour, extending their operation by a factor of Z."* You don't stop evasion; you price it. That is the correct shape for a defensive claim.

---

### B5 — Tier model contradicts the security model

Clean fix. Make coverage invariant and sell latency instead.

| Invariant for **every** tier | What tiers may buy |
|---|---|
| Full commissioning window | Re-escalation turnaround speed |
| Minimum sampling rate r_min | Raw-evidence retention period |
| Retention rule (held = held) | Concurrent Inspector slots |
| Full detection ceiling | Historical replay depth, richer narratives |

Then scope by **asset criticality, not plan**: hosts touching crown-jewel data get longer commissioning and higher sampling regardless of what the customer paid. Implement as a criticality multiplier on sampling rate, never a plan multiplier.

Public statement: *"No tier changes what we can detect. Tiers change how fast you hear about it and how much history you keep."* That resolves both the security hole and the liability exposure.

---

### B6 — Activation → detection latency (dwell time)

Cannot be eliminated. **Can be bounded — which converts a weakness into a specification.**

Two-speed detection:

- **Visible deviation** → anomaly trigger fires within one window (5–15 min).
- **Invisible deviation** → bounded by random sampling. With per-host-day sampling probability *r*, expected time to escalation is **1/r days**.

| r (per host-day) | Expected worst-case detection | Inspector cost |
|---|---|---|
| 1/30 | 30 days | lowest |
| 1/7 | 7 days | low |
| 1/1 | 1 day | high |

Publish this curve. The claim becomes: *"detection latency ≤ 1 window for anything the Sentry can see; ≤ 1/r in expectation for anything it cannot."* An honest bound beats a vague reassurance, and it is the kind of statement a buyer can actually put in a risk register.

---

### B7 — LLM verdict is an audit risk

The LLM must be a **presentation layer over a deterministic verdict.** Concretely:

- **Decision, score, and MITRE mapping are all deterministic code.** Threshold on reconstruction error; technique mapping is a lookup from the category-transition pattern:
  `Recon_API → T1590` · `Code_Repo_Paste → T1105` · `Messaging_API → T1102 / T1071.001` · `Cloud_Storage egress → T1567.002`
- The LLM **receives** the finished structured verdict and writes prose about it. It is forbidden from changing severity or confidence. Enforce structurally — severity/confidence fields are not in its output schema.
- Every alert stores a **replay bundle**: flow window, embedding, threshold, model hash, prompt, LLM output hash. Any analyst can recompute the verdict offline and get the identical number. That is your chain-of-custody answer.

---

### B8 — Poisoning defense economics

State it as math, never as "poison-proof."

- Probability of surviving *n* days unsampled: **(1 − r)ⁿ**. Expected undetected dwell: **1/r days**.
- Cost is linear in *r*. The security/cost curve is explicit and defensible.

**Improvement — importance-weighted sampling.** Sample with probability proportional to
`asset_criticality × time_since_last_inspection × sentry_score_percentile`.
Still stochastic (unpredictable, cannot be timed), but concentrates budget where compromise hurts most. Strictly better expected loss for identical compute.

**Keep a pure-uniform floor** so an attacker cannot game the weighting by suppressing their Sentry score.

---

## Part C — The meta-flaw, and why your problem statement already answers it

The CRITIQUE says: network-only LSA detection lives in EDR's shadow; reframe as EDR-complementary and agentless-first. Correct — but go further.

**Your SIH problem statement is a data-diode-protected critical-infrastructure network.** In that environment:

1. **EDR is not a competitor. It is absent.** You cannot install an endpoint agent on a PLC, an HMI, a protection relay, or a legacy historian. The agentless gap isn't a niche you're arguing into — it's the entire deployment surface.
2. **Bidirectional tools are structurally disqualified.** Snort/Suricata/Zeek assume they can see both directions. A diode makes that impossible. Your passive, unidirectional, metadata-only design isn't a limitation you're apologizing for — it's the only shape that fits.
3. **Your architecture is *better* suited to OT than to enterprise IT.** OT hosts have extremely narrow, stable, machine-generated communication profiles. An HMI that suddenly talks to a historian it has never contacted is a far cleaner signal than a laptop hitting GitHub. **The DevOps-noise objection (B3) largely evaporates in OT** because the baselines are near-deterministic.

This is the single most valuable reframe available to you. Lead with it. The trusted-sites narrative (Telegram, Drive, GitHub) becomes your *IT-enterprise* generalization story — demoed second, not first.

---

## Part D — remaining objections

**Encrypted DNS / ECH.** Real erosion, but not fatal. RFC 9849 ECH removes SNI; what survives is destination IP + ASN, server certificate (where obtainable), client TLS fingerprint (JA3/JA4), and traffic shape. Design the resolver to emit a **category + confidence**, and when confidence is low, emit `unknown_external` as its own category — an unknown-category transition is itself informative. And note: **in a diode/OT deployment you control DNS and there is no ECH**, so the erosion applies to your secondary market, not your primary one.

**CDN / cloud IP churn.** Never map IP → category directly. Map on (ASN + SNI/cert + reverse-DNS + provider-published ranges) with a TTL and a confidence score. Accept staleness; measure it and report resolver hit-rate as a system metric.

**Privacy / DPDP Act 2023.** You are metadata-only already (no DPI) — say so loudly. Profile the **device**, not the person. Retain embeddings and moments, not raw flows. Write a one-page DPIA. Indian judges will care about this, and it costs you a day.

**Cold start / attacker-in-the-baseline.** Three mitigations, all cheap: cohort baselining for new hosts (B1.3), trimmed robust baseline estimation (B1.2), and the retention rule you already have — anything the teacher flags during commissioning is HELD, never demoted.

**Single-tenant, no transfer.** The **encoder transfers; the baselines do not.** Pretrain the encoder once on pooled/public data, fine-tune unsupervised per tenant. Standard foundation-model play, and it turns your go-to-market cold-start from "retrain everything" into "collect two weeks of traffic."

---

## Part A — v1 prototype, briefly

- **A2 (base-rate / 8.4% FPR).** Move from per-flow to per-host-window decisions and require *k*-of-*n* consecutive windows. FP compounds down geometrically while true beacons — which are persistent by definition — survive. Then report **precision at a fixed alert budget** ("top 50 alerts/day"), which is the number a SOC actually buys.
- **A4 (42.5 flows/sec).** This is a Python/Scapy parsing bottleneck, not an algorithmic one. Honest framing: *"single-node prototype at 42.5 fps; the architecture shards per-host, and the steady-state Sentry path is O(d²) per host-window."* Do not claim enterprise line rate.
- **A5 (circular validation).** Covered by B2.3 — real benign, emulated malicious, asymmetry stated.

---

## The GPU / compute argument (do this properly, it's your second-best chart)

**Steady state should be zero GPU.** With the B1 redesign — distilled CPU encoder + Mahalanobis test — no GPU is required for always-on monitoring. The claim upgrades from "90% less GPU" to **"GPU is used only during commissioning and re-escalation; steady state is CPU-only."** That is a much stronger and much more defensible statement.

**Cost model — memorize this formula, you will be asked:**

```
GPU-host-days = H·D            (one-time commissioning)
              + H·(r + e)·365   (ongoing: sampling + anomaly re-escalation)

vs. inspect-all = H·365
```

Worked example — H = 1000 hosts, D = 14 days, r = 1/30/day, e = 0.02/day:

| | GPU-host-days |
|---|---|
| Inspect-all | 365,000 / yr |
| NetSentinel one-time | 14,000 |
| NetSentinel ongoing | ≈ 19,400 / yr |
| **Reduction (steady state)** | **≈ 95%** |

**VRAM.** `NeighborLoader` mini-batching bounds the computational graph by fanout × batch size rather than by graph size — so VRAM is constant in the number of hosts. This is correct and worth stating explicitly; it is the answer to "your graph won't fit in memory."

**Distillation speedup.** Cite the measured range from the literature (26–181×) rather than inventing a number.

---

## Build order for the Grand Finale

Ranked by (panel impact ÷ effort):

1. **Sentry-as-router: distilled encoder + Mahalanobis baseline.** The B1 fix. Highest research value, and it produces #2.
2. **The recall-vs-escalation-budget chart.** One plot. This is the deliverable that wins the room.
3. **GPU cost model + measured cost recovery on your own run.** Second chart.
4. **Automation gate — IAT distribution-family test replacing raw CoV.** Cheap, counters B4 directly.
5. **Deterministic verdict + LLM demoted to presentation.** Half a day. Kills B7.
6. **Real benign capture (consented campus/lab traffic).** Days, not months. Kills half of B2 and B3.

**Do not build:** full E-GraphSAGE at enterprise scale, blockchain anchoring, SHAP, the meta-classifier ensemble. None of them move a panel and all of them eat the week.

---

## What to say when asked "so what's still broken?"

Say it first, before they ask:

1. *"We have no real LSA chain corpus. Nobody does. We prove cost-recovery against the teacher as oracle, and we validate sequence detection on real red-team data from DARPA TC — not on our own generator."*
2. *"Against an adversary who fully shapes timing to human distributions, we lose the automation gate. We measured what that costs them: it caps their polling rate."*
3. *"We are network-only. On a managed Windows endpoint, EDR beats us and we'd tell you to buy EDR. We're for the machines EDR cannot be installed on — which, behind a data diode, is all of them."*

Panels reward teams that know exactly where the idea breaks far more than teams claiming to have solved it.

---

## Part F — Prior art check: what here has already been built

Checked 2026-09-04. Verdict: **exactly one thing in the whole V2 design is unclaimed ground.**

| Component | Status | Evidence |
|---|---|---|
| **Cross-service category-transition sequence detection for LOTS** | **GAP — genuinely open** | Systematic review of **91 studies** on cloud/public legitimate-service abuse as C2 found only **7 addressed detection at all**, and **no sequence-based, multi-service, or graph-based detection across multiple legitimate platforms**. Review explicitly calls for it. |
| Inspector (E-GraphSAGE + masked-AE + Transformer reconstruction) | **Already published** | This *is* GraphIDS (NeurIPS 2025), 99.98% PR-AUC. Your Inspector is a reimplementation, not a design. |
| Distilled lightweight student IDS | Heavily studied | Many 2024–2026 papers: IoT, UAV, CAN-bus, consumer devices, self-distillation, adaptive KD. |
| Cascade / escalation to an expensive model | Whole ML subfield | "Learning to defer", cascade deferral, online cascade learning. |
| Per-entity baseline + deviation scoring | Shipping product | Microsoft Sentinel UEBA, Exabeam. |
| Mahalanobis distance on deep embeddings | Classic method | Standard OOD detection since 2018; extensively critiqued since. |
| Uniform-IAT / jitter-as-signature | Published | Varonis "Jitter-Trap". |
| Beacon CoV detection | Commercial | RITA / AC-Hunter and every UEBA product. |

**What this means.** Do not present the cascade, the distillation, the retention rule, or the Inspector as novel — all four have prior art and a judge may know it. The defensible claim narrows to: *cross-service category-transition sequence semantics for LOTS chains, plus the provenance chain dataset.* The review above is your citation that this specific gap is real — use it, it is the strongest external validation you have.

---

## Part G — Flaws in *this* document

Written against my own recommendations. Ordered by severity.

### G1. The B1 fix may fail for the same reason the original does

I argued: distillation destroys local-outlier detection, so move the local decision out of the network into a Mahalanobis test. **But the distilled encoder still has to preserve local geometry for that test to mean anything.** Compression is precisely what destroys fine-grained local structure. I relocated the problem into the encoder rather than solving it.

**This must be measured, not assumed.** The check is not "do student and teacher outputs agree" — it is **kNN-neighborhood overlap between teacher and student embedding spaces**. If a host's nearest neighbours differ between the two encoders, the Mahalanobis test is being computed in a geometry the teacher would not recognise, and B1 is unfixed. Run this before building anything else.

### G2. Mahalanobis is documented to fail in exactly your regime

A critical analysis of Mahalanobis for high-dimensional OOD finds that model-estimation error means **"near OoD samples are not distinguishable from known data"**, and that with insufficient samples relative to dimension, even genuine in-distribution samples score as outliers. LSA detection is *definitionally near-OOD* — a subtle deviation, not a wild one.

Worse: that paper's recommended alternative is **Local Outlier Factor** — a *local* method, which is exactly the family the distillation literature says does not survive compression. That is a closed loop, and I did not acknowledge it. There may be no cheap local detector that both survives distillation and resolves near-OOD.

### G3. The covariance estimate is statistically infeasible at the sizes I quoted

d = 64–128 requires ≫ d² samples for a stable Σ. Fourteen days of 5-minute windows is 4,032 samples; at d = 64, Σ has 4,096 parameters — roughly one sample per parameter, before trimming. Σ will be ill-conditioned or singular. Mandatory: Ledoit–Wolf shrinkage, or a diagonal covariance — but diagonal discards the correlation structure that was the reason to use Mahalanobis at all.

### G4. Host behaviour is multimodal; a single Gaussian is the wrong model

Workday vs. night, in-office vs. VPN, build day vs. meeting day. One (μ, Σ) is either wide enough to detect nothing or tight enough to fire constantly. The fix is a mixture or an exemplar set — which adds cost and reintroduces exactly the locality problem G1 flags.

### G5. There is a better construction than the one I proposed

"Sentry escalates when it detects an anomaly" is **confidence-based deferral**, and there is a theory result on when that suffices. The Bayes-optimal deferral rule compares *both* models' correctness probabilities; thresholding the cheap model's own confidence is provably suboptimal under **specialist downstream models, label noise, and distribution shift**. All three describe an IDS exactly — the Inspector is a specialist (only it sees chain structure), labels are noisy, and drift is the permanent operating condition.

**Better design:** train a small **deferral head** that predicts *"would the Inspector change the verdict on this window?"* rather than *"am I unsure?"* You get that training signal for free during commissioning — you have both models' outputs on every window. Same cost, strictly better targeting. **This supersedes the plain-threshold Sentry in Part B1; build this instead.**

### G6. I oversold "prove it against the teacher as oracle"

That construction proves **cost recovery, not detection.** If the teacher is wrong, the student faithfully reproduces the error. I wrote that it "sidesteps B2 entirely" — it does not; it sidesteps one proof burden. The correct framing, and expect this question: *"you have shown your cheap model agrees with your expensive model. Neither has been shown to detect real LSA."* Answer it by pairing the agreement curve with the DARPA-TC sequence result, and never present the agreement curve alone.

### G7. The OT reframe contradicts the novelty claim

In a diode-protected OT network there is no Telegram, GitHub, or Drive — so the LOTS threat model, **the only genuinely novel part**, does not apply there. What you would actually detect in OT is east-west lateral movement between internal assets: a different problem with much heavier prior art. I wrote "the mechanism generalizes"; that was hand-waving.

The real tension: **lead with OT and you abandon your novelty; lead with LOTS and you are back in EDR's shadow.** Pick deliberately, or bridge explicitly — redefine "service category" as *internal asset class* (HMI, historian, engineering workstation, PLC) and say plainly that the taxonomy, not the mechanism, is what transfers. Do not let a judge find this seam first.

### G8. Smaller ones

- **Conjunctive gate is brittle.** AND of three conditions means breaking any one evades. Low-and-slow exfil never trips egress asymmetry. A weighted score is more robust, less crisp.
- **k-of-n windows multiplies detection latency by k.** I presented it as a free FP reduction. It is not free.
- **ETTE = 1/r is optimistic.** True value is 1/(r · P(detect | inspected)). If the attacker is quiet in most windows, an Inspector visit sees nothing.
- **Trimmed baselining cuts both ways.** It removes attacker traces during commissioning, but also removes legitimate rare behaviour — which is then flagged forever after.
- **Importance-weighted sampling leaks.** If sampling probability depends on the Sentry score, an attacker who can observe inspections learns about their score. Not "strictly better"; keep the uniform floor meaningful.

---

## Sources

- Guerra et al., *Self-Supervised Learning of Graph Representations for Network Intrusion Detection* (GraphIDS), arXiv:2509.16625 / NeurIPS 2025 — https://arxiv.org/abs/2509.16625
- Lo et al., *E-GraphSAGE: A GNN-based Intrusion Detection System for IoT*, arXiv:2103.16329 — https://arxiv.org/pdf/2103.16329
- *What Knowledge Transfers in Tabular Anomaly Detection? A Teacher–Student Distillation Analysis*, MDPI Machine Learning & Knowledge Extraction 8(3):60 — https://www.mdpi.com/2504-4990/8/3/60
- *How Benchmarks and Evaluation Protocols Shape Conclusions in Provenance-Based Intrusion Detection*, arXiv:2608.01454 — https://arxiv.org/html/2608.01454
- *Learning the APT Kill Chain: Temporal Reasoning over Provenance Data for Attack Stage Estimation* (StageFinder), arXiv:2603.07560 — https://arxiv.org/html/2603.07560v1
- Varonis, *The Jitter-Trap: How Randomness Betrays the Evasive* — https://www.varonis.com/blog/jitter-trap
- IETF, *Encrypted Client Hello Deployment Considerations*, draft-campling-ech-deployment-considerations-12 — https://datatracker.ietf.org/doc/html/draft-campling-ech-deployment-considerations-12
- LOTS Project — https://lots-project.com/
- *Analyzing the Usefulness of the DARPA OpTC Dataset in Cyber Threat Detection Research*, arXiv:2103.03080 — https://ar5iv.labs.arxiv.org/html/2103.03080

### Added for Parts F & G

- *Abuse of Cloud-Based and Public Legitimate Services as Command-and-Control Infrastructure: A Systematic Literature Review*, MDPI JCP 3(3):27 — https://www.mdpi.com/2624-800X/3/3/27 — **the 91-study review; your novelty citation**
- Jitkrittum et al., *When Does Confidence-Based Cascade Deferral Suffice?*, NeurIPS 2023, arXiv:2307.02764 — https://arxiv.org/html/2307.02764v1
- *Out-of-Distribution Detection in High-Dimensional Data Using Mahalanobis Distance — Critical Analysis*, ICCS 2022 — https://link.springer.com/chapter/10.1007/978-3-031-08751-6_19
- *Learning to Defer: A Survey* — https://www.researchgate.net/publication/398417243_Learning_to_Defer_A_Survey
- Microsoft Sentinel UEBA reference — https://learn.microsoft.com/en-us/azure/sentinel/ueba-reference
