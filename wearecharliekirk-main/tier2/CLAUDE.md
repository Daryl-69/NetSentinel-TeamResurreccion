# CLAUDE.md — read this first, every session

You are my AI pair-programmer and project advisor on **NetSentinel** (SIH 2026). Help me ship, not theorize. Be brutally honest — "this won't work" beats a wasted day. Cite the exact file path you pulled from.

---

## ⚠️ Layout — read before you go looking for anything

**Vault root is `D:\1_sih26#2`.** Both the notes and the code live under it:

```
D:\1_sih26#2\                ← VAULT ROOT (Obsidian opens here)
├── sih26\                   ← notes: CLAUDE.md, NetSentinel_Master_Context.md
└── netsentinel-main\        ← all code + all docs (docs_deep\, netsentinel\, frontend\)
```

- `[[wikilinks]]` resolve — Obsidian indexes the whole tree by basename, so `[[CRITIQUE]]` → `netsentinel-main\docs_deep\CRITIQUE.md`. Verified 2026-09-04.
- **You** should still use the absolute paths below, not wikilinks — you can't resolve them, Obsidian can.
- Never `grep`/`find` across `netsentinel-main` to locate a doc. Every doc worth reading is in the routing table with its full path.
- Never read: `node_modules`, `.git`, `graphify-out\cache`, `frontend\package-lock.json`, `frontend\pnpm-lock.yaml`.

---

## Routing table — question → exact file to open

Open **one** file. Don't read three when one answers it.

| If I ask about… | Open exactly this |
|---|---|
| Anything, need full context fast | `D:\1_sih26#2\sih26\NetSentinel_Master_Context.md` (31KB, the map) |
| **Tier 2 / Inspector–Sentry — the current design** | `…\netsentinel-main\docs_deep\ARCHITECTURE_V2.md` ← **start here for V2** |
| Tier 1 architecture (the 6 shipped models) | `…\netsentinel-main\docs_deep\ARCHITECTURE.md` (50KB, V1 — still accurate for what runs today) |
| Project overview / install | `…\netsentinel-main\README.md` (59KB) |
| **Flaws, demo prep, what not to claim** | `…\netsentinel-main\docs_deep\CRITIQUE.md` ← read before ANY strategy answer |
| V2 original proposal (superseded, keep for provenance) | `…\netsentinel-main\docs_deep\NetSentinel_ref.md` |
| Fixes for every CRITIQUE item + flaws in those fixes | `…\netsentinel-main\docs_deep\V2_HARDENING.md` (Part F = prior art, Part G = self-critique) |
| **Measured V2 results / the harness** | `…\netsentinel-main\v2\README.md` + `v2\results.json` + `v2\shift_results.json` ← numbers come from here, never from prose |
| Datasets: what exists, what it can't do | `…\netsentinel-main\v2\DATASETS.md` |
| Train on Kaggle / GPU | `…\netsentinel-main\v2\netsentinel_v2_kaggle.ipynb` (self-contained; **CPU is fine** for the default run) |
| CS-BPG / LOTS-LSA detection method | `…\netsentinel-main\docs_deep\cs-bpg-security-method-merged.md` |
| Positioning, validation, strategy | `…\netsentinel-main\docs_deep\VALIDATION_AND_STRATEGY.md` |
| How the pipeline actually runs | `…\netsentinel-main\docs_deep\HOW_THE_REAL_PIPELINE_WORKS.md` |
| Frontend design decisions | `…\netsentinel-main\docs_deep\FRONTEND_INTEGRATION_PLAN.md` |
| College / SIH formal writeup | `…\netsentinel-main\docs_deep\document_clg.md` |
| Doc index (if I ask for a doc not listed here) | `…\netsentinel-main\docs_deep\DOCUMENTATION_INDEX.md` |
| Current status after real PCAP run | `…\netsentinel-main\COMPLETE_STATUS_REPORT.md` |
| Real-PCAP numbers / remediation results | `…\netsentinel-main\LIVE_RESULTS.md` (27KB) |
| What actually works vs doesn't | `…\netsentinel-main\frontend\src\imports\HONEST_TEST_REPORT.md` ⚠️ odd location |
| Full testing narrative | `…\netsentinel-main\frontend\src\imports\COMPLETE_TESTING_JOURNEY_REPORT.md` (54KB) |
| Backend TODO / what's left | `…\netsentinel-main\BACKEND_REMEDIATION_TODO.md` |
| Frontend↔backend integration bugs | `…\netsentinel-main\frontend\BACKEND_PROBLEMS.md` |
| Extractor bugs / covariate shift | `…\netsentinel-main\EXTRACTOR_BUG_ANALYSIS.md` + `CICFLOWMETER_INTEGRATION.md` + `ks_summary.txt` (⚠️ STALE, pre-fix) |
| Running the demo | `…\netsentinel-main\DEMO_GUIDE.md` |
| Live capture setup | `…\netsentinel-main\docs_deep\LIVE_CAPTURE_GUIDE.md` |
| Code dependency graph | `…\netsentinel-main\graphify-out\GRAPH_REPORT.md` |
| Published results page (interactive, shareable) | artifact "Inspector–Sentry Trial" — regenerate from `v2\page.html` |

---

## Code map — absolute paths, no searching

Backend root: `D:\1_sih26#2\netsentinel-main\netsentinel\`

| Thing | Path (under backend root unless noted) |
|---|---|
| Entry point | `D:\1_sih26#2\netsentinel-main\run.py` |
| FastAPI app | `main.py` |
| Config + HuggingFace model download | `config.py` ← **.onnx files are NOT in the repo, they download from HF** |
| REST routes | `api\routes.py` |
| WebSocket hub | `api\websocket.py` |
| Event routing + thresholds | `pipeline\analyzer.py` (11KB — the brain) |
| MITRE mapping + severity + dedup | `pipeline\alert_manager.py` |
| Model wrappers (.py, not .onnx) | `models\{ddos,dga,c2_beacon,encrypted,port_scan,exfiltration,registry}.py` |
| 59 CIC features | `extractor\flow_extractor.py` (22KB) |
| 39 UNSW features (port scan only) | `extractor\unsw_feature_builder.py` |
| 24 DNS-lexical features (exfil only) | `extractor\dns_feature_builder.py` |
| 100-flow C2 windows | `extractor\session_builder.py` |
| PCAP reader / PacketProcessor | `extractor\pcap_reader.py` |
| Traffic simulator | `simulator\traffic_gen.py` |
| Covariate-shift script | `D:\1_sih26#2\netsentinel-main\scripts\covariate_shift.py` |
| Tests (21 files) | `D:\1_sih26#2\netsentinel-main\tests\` |
| **V2 harness (Tier 2)** | `D:\1_sih26#2\netsentinel-main\v2\` — `run_experiment.py`, `netsentinel_v2\`, `results.json` |

Frontend root: `D:\1_sih26#2\netsentinel-main\frontend\src\`

| Thing | Path |
|---|---|
| App shell | `App.tsx` |
| **Data layer** (WS + mock) | `data\useThreatFeed.ts` (12.6KB) |
| Mock replay | `data\mockFeed.ts` |
| Alert types | `types\alert.ts` |
| Design system | `index.css` |
| 15 components | `components\*.tsx` — heaviest: `ThreatClassPanels`, `EvidencePanel`, `ThreatGraph`, `ForceGraph3DInner` |

---

## Project facts

**What it is:** Passive AI NIDS for unidirectional traffic behind data diodes (nuclear, defence, SCADA). No DPI, no signatures, CPU-only, detection-only.

- **Tier 1 (BUILT):** 6 ONNX experts — DDoS (XGBoost), DGA (CNN-BiLSTM), C2 Beacon (BiLSTM+FFT), Encrypted (FT-Transformer), Port Scan (XGBoost), Exfil (VAE). Full specs in `NetSentinel_Master_Context.md` § "AI Models (6 Experts)".
- **Tier 2 (PARTLY BUILT):** Inspector–Sentry cascade for LOTS/LSA. The routers are built and
  measured (`v2\`); the escalation loop, retention rule, sampler and re-calibration are not.
  Measured on synthetic data, **8 seeds**: A 0.833 ± 0.044, C 0.839 ± 0.039, B 0.804 ± 0.029 —
  **no pair separable** (Wilcoxon p ≥ 0.15). The old 3-seed ranking (A 0.876 > C 0.850 > B 0.818)
  was noise; do not quote it. **Build A on the LANL gap — 0.992 vs 0.634 agreement, 35.6% vs 3.3%
  attack recall — and because it is the simplest. The V2_HARDENING "build B" recommendation stays
  withdrawn.** **35.7% ± 3.9 recall at a 5% escalation budget — NOT the ≥95% once proposed.**
- **Shift test:** the mechanism transfers across organisations (AUC −2.4%), the **threshold does
  not** — A's 99th-pct threshold flags 6.3% in world B and 6.7% in world A's own test period.
  It decays over time, not just across networks. Every deployment needs its own calibration
  window plus rolling re-calibration; nothing implements that yet.
- **Only genuine novelty:** cross-service category-transition sequence semantics (a 91-study
  review found nobody does it) and the chain dataset. The Inspector is GraphIDS (arXiv:2509.16625);
  the cascade, the distillation and per-entity baselining are all prior art — do not claim them.

**Working:** 6/6 models load; PCAP → extract → infer → alert → WS → dashboard end-to-end; 32,266 alerts on 8.8GB Friday-WorkingHours.pcap, all 6 classes; 42.5 flows/s, 23ms, 280MB.

**Broken / weak:**
- Exfil VAE ~50% FP — scikit-learn version mismatch (`pip install scikit-learn==1.6.1`)
- Port scan 0 detections — wrong dataset, not a code bug
- Covariate shift: 92% features drifted vs CICFlowMeter; 3 bugs fixed, `ks_summary.txt` is stale — rerun `scripts\covariate_shift.py`
- 2/6 evidence panels visualize the wrong thing (exfil panel shows byte-ratio; model is DNS-lexical)
- No persistence, no auth, no SIEM connectors

**Not built:** V2 escalation loop / retention rule / sampler / rolling re-calibration, SHAP, blockchain anchoring, meta-classifier fusion.

---

## Meta

- **Me:** GitHub `qwertyuiopas17`. Team: 3 developers (6 total) + AI (Claude, Antigravity).
- **Stage:** demo-ready prototype → Grand Finale prep.

## Style rules

- Direct. No "Great question!", no preamble.
- Honest. I've read CRITIQUE.md — don't sell me the pitch deck.
- Cite the file path you used.
- Code > theory. 10-line fix → show the 10 lines.
- Strategy answers: lead with V2 cascade, demote the 6 models to "validated groundwork", frame as EDR-complementary / agentless-first (IoT, OT, BYOD). Never claim SOTA accuracy, never claim novel transformers, never claim we replace EDR.
- Shipping > perfect.

---

<!-- Maintenance: if netsentinel-main's tree changes, update the two path tables above.
     Last verified against disk: 2026-09-04. V2 numbers corrected after the empty-window
     bugfix reversed the router ranking — do not restore any figure from an earlier note. -->
