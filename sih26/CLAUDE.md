# CLAUDE.md — read this first, every session

You are my AI pair-programmer and project advisor on **NetSentinel** (SIH 2026). Help me ship, not theorize. Be brutally honest — "this won't work" beats a wasted day. Cite the exact file path you pulled from.

---

## ⚠️ Layout — read before you go looking for anything

**Vault root is `D:\1_sih26#2`.** It is also the git repo (remote `Daryl-69/sih26-2`, branch `main`).

```
D:\1_sih26#2\                   ← VAULT ROOT + git repo (Obsidian opens here)
├── sih26\                      ← notes: CLAUDE.md, NetSentinel_Master_Context.md
├── wearecharliekirk-main\      ← ★ THE CURRENT PROJECT. Tier 1 + Tier 2 combined.
└── netsentinel-main\           ← SUPERSEDED. Old split layout, kept for provenance.
```

**`wearecharliekirk-main` is the live tree.** It contains the full Tier-1 pipeline
*and* the whole Tier-2 track under `tier2\`. `netsentinel-main\` is the older
separate copy — do not edit it, do not quote its numbers. Where a doc exists in
both, the `wearecharliekirk-main` one wins.

- `[[wikilinks]]` resolve — Obsidian indexes the whole tree by basename. Verified 2026-09-04.
- **You** should use the absolute paths below, not wikilinks — you can't resolve them, Obsidian can.
- Never `grep`/`find` across the tree to locate a doc. Every doc worth reading is in the routing table.
- Never read: `node_modules`, `.git`, `graphify-out\cache`, `frontend\package-lock.json`, `frontend\pnpm-lock.yaml`.
- **`D:\capture\` is private.** Raw pcaps at snaplen 0 contain application payload.
  Never commit a pcap, never paste browsing hostnames into a doc, never stage one
  to the cloud. Analyse captures on the machine that holds them.

---

## Routing table — question → exact file to open

Open **one** file. Don't read three when one answers it.
Paths below are relative to `D:\1_sih26#2\wearecharliekirk-main\` unless stated.

| If I ask about… | Open exactly this |
|---|---|
| Anything, need full context fast | `D:\1_sih26#2\sih26\NetSentinel_Master_Context.md` |
| **What the project is / submission overview** | `README.md` ← the combined submission README |
| **Latest test state, what's fixed, what's open** | `PIPELINE_TEST_PART3.md` ← **start here** |
| Alert-volume + exfil fixes, real-capture behaviour | `PIPELINE_TEST_PART2.md` |
| First full-pipeline run, throughput, integrity bug | `PIPELINE_TEST_20SEP.md` |
| Port-scan model + SPSD design | `PORT_SCAN_COMPLETE.md` (⚠️ its 99.03% is CIDDS validation, NOT a NetSentinel rate) |
| **Tier 2 / Inspector–Sentry spec** | `tier2\INSPECTOR_SENTRY_SPEC.md` |
| How Tier 2 relates to Tier 1 | `tier2\HOW_THIS_FITS.md` |
| Claim-by-claim evidence register | `tier2\AUDIT.md` |
| Telegram-C2 / living-off-trusted-services bound | `tier2\telegram_c2.py` + `tier2\test_telegram.py` |
| **Flaws, demo prep, what not to claim** | `docs\CRITIQUE.md` ← read before ANY strategy answer |
| Tier 1 architecture (the 6 shipped models) | `docs\ARCHITECTURE.md` |
| Datasets: what exists, what it can't do | `tier2\DATASETS.md` |
| Old split-layout docs (provenance only) | `D:\1_sih26#2\netsentinel-main\docs_deep\` |

---

## Code map — absolute paths, no searching

Backend root: `D:\1_sih26#2\wearecharliekirk-main\netsentinel\`

| Thing | Path (under backend root unless noted) |
|---|---|
| Entry point | `..\run.py` |
| FastAPI app | `main.py` |
| Config, thresholds, model resolution | `config.py` ← `SEVERITY_MAP`, `MITRE_MAP`, `THRESHOLDS`, `ETT_ALERT_ON_VPN` |
| REST routes / WebSocket | `api\routes.py`, `api\websocket.py` |
| **Event routing + gating** | `pipeline\analyzer.py` ← the brain |
| MITRE mapping + severity + dedup | `pipeline\alert_manager.py` ← reads `model_result["threat"]` |
| Port-scan aggregation glue | `pipeline\portscan_integration.py` |
| Network-event aggregation / `Flow` | `extractor\network_event_builder.py` |
| Model wrappers | `models\{ddos,dga,c2_beacon,encrypted,port_scan,portscan_detector,exfiltration,registry}.py` |
| Extractors | `extractor\{flow_extractor,unsw_feature_builder,dns_feature_builder,session_builder,pcap_reader}.py` |
| Traffic simulator | `simulator\traffic_gen.py` |
| Integrity (Merkle, ledger, receipts) | `integrity\` |
| **Evaluation harness** | `..\scripts\evaluate_detection.py` |
| Tests + pytest config | `..\tests\`, `..\tests\conftest.py` |
| **Tier 2** | `..\tier2\` — `netsentinel_v2\`, `telegram_c2.py`, `verify_all.py` |

Frontend root: `D:\1_sih26#2\wearecharliekirk-main\frontend\src\`
(App shell `App.tsx`; data layer `data\useThreatFeed.ts`; 15 components in `components\*.tsx`.)

---

## Project facts

**What it is:** Passive AI NIDS for unidirectional traffic behind data diodes (nuclear, defence, SCADA). No DPI, no signatures, CPU-only, detection-only.

- **Tier 1:** 6 ONNX experts — DDoS (XGBoost), DGA (CNN-BiLSTM), C2 Beacon (BiLSTM+FFT), Encrypted (FT-Transformer), Port Scan (XGBoost + SPSD aggregation), Exfil (VAE). All 6 load in ~1.5 s from `models\`, no network needed.
- **Tier 2:** Inspector–Sentry cascade for LOTS/LSA, plus the Telegram-C2 bound. Runs as its own verified track alongside Tier 1; not yet wired into the Tier-1 analyzer.

### Verified state (2026-09-20, all re-measured — see `PIPELINE_TEST_PART3.md`)

| | |
|---|---|
| `pytest tests/` | **62 passed, 11 skipped, 0 errors** (no flags, no PYTHONPATH) |
| Integrity (inclusion, append-only, signed ledger) | **42/42** |
| Tier-2 Telegram-C2 | **17/17** (`tier2\test_telegram.py`) |
| Real 200 MB capture | 2,113 flow events → **34 alerts (1.61%), 4 actionable** |
| Throughput | ~49× real time single-core, 244 MB RSS |

**Fixed 2026-09-20 (don't re-report these as broken):**

- Exfil VAE confidence was saturating at exactly `1.000` (`min(mse/threshold,1)` always clamps). Now graded — 14 distinct values, 0.712–1.000. `dest_ip` now populated 27/27.
- "VPN Traffic" was a *classifier label* emitted as an alert — 103 of 144 alerts. Now telemetry behind `ETT_ALERT_ON_VPN=False`. Alert volume 144 → 34, CRITICAL 30 → 2.
- **Port scan was 0%** — four defects, none in the model: the aggregation buffer dropped `Src IP`/`Dst IP`/`Dst Port`/`Timestamp` (they live at event level, not in `features`), so fan-out was permanently 1; `_alert_to_dict` emitted `threat_type` where `create_alert` reads `threat`; **SPSD `predict_proba` returned raw leaf counts** (`[0., 15.]`) because a 1.3.2 pickle runs under sklearn 1.7.2; and the harness scored a per-source detector per-flow. Now **5/5 sources, 0 new FP**.
- Merkle `build_tree` used duplicate-leaf padding while `_hash_range` used the RFC 6962 split → no consistency proof could verify. Both fixed.
- Simulator events had no `timestamp`, so dedup suppressed every DNS alert.
- `pytest tests/` aborted entirely (`test_advanced.py` calls `sys.exit(1)` at import). Fixed with `tests\conftest.py`.
- `test_model_loading` called methods that don't exist, caught the error and `return False` — pytest counts that as a **pass**. It could not fail. Rewritten to assert.

**Still open:**

- **C2 beacon is throttled.** `c2_beacon.py:197-198` hard-codes `prob > 0.90`, overriding the configured `THRESHOLDS["c2_beacon"]=0.80` (which is dead code). On clean beacons the model tops out at **0.941**, median 0.838, with 255/500 stranded in 0.80–0.90 → only ~12% fire. Lowering the gate to 0.80 would recover ~63% on the simulator, but needs benign-session FP validation first.
- **sklearn pin not enforced** — `requirements.txt` pins 1.3.2, runtime is 1.7.2. Already caused two real defects; a `RobustScaler` in the same position is unaudited. Enforce at startup or re-serialise the pickles.
- DDoS also fires on port-scan flows (449/500) — labelling precision, not a miss.
- Tier-2 escalation loop, retention rule, sampler, rolling re-calibration: not built.
- No persistence, no auth, no SIEM connectors.

### Tier-2 measured results (do not inflate these)

- 8 seeds: A 0.833 ± 0.044, C 0.839 ± 0.039, B 0.804 ± 0.029 — **no pair separable** (Wilcoxon p ≥ 0.15). The old 3-seed ranking was noise.
- **35.7% ± 3.9 recall at a 5% escalation budget** — NOT the ≥95% once proposed.
- Shift test: mechanism transfers across organisations (AUC −2.4%), **the threshold does not**. Every deployment needs its own calibration window plus rolling re-calibration; nothing implements that yet.
- Weakest number, state it plainly when asked: **within-host AUC 0.557 ± 0.013**.
- Telegram-C2 bound: operational floor **~10.03 KB/day**; commodity rung near-perfectly detectable per-window, full-mimicry rung falls toward chance per-window but stays CUSUM-bounded in finite time.

---

## ⛔ Never claim

- **No accuracy, recall, or false-positive rate.** Not measured, because it needs labelled data and our capture has none. Recall figures from `scripts\evaluate_detection.py` are **circular** — our generator, our detectors — and are a wiring smoke test, never a product claim. Say "behaviour verified on real traffic", never "X% accurate".
- The simulator is unseeded: recall moves run to run (ddos 43.6–50.4%, c2 12.0–13.8%). Quote a range or nothing.
- Port scan's **99.03%** is the SPSD model on a CIDDS-001 validation set, **not** a NetSentinel detection rate.
- The real-capture 34 alerts is an **upper bound** on false positives (no ground truth), not an FP rate.
- Never: "state of the art", "novel transformer", "we replace EDR", "95%/96.9% recall", "94.7% GPU reduction", "55% of DNS hidden by DoH".
- "13.7×" is a **parameter ratio**, not a speedup.
- **"We detect the sequence" is withdrawn** → say "we detect the combination and the shape".
- The Inspector architecture is **not ours** — it is GraphIDS (arXiv:2509.16625). The cascade, distillation and per-entity baselining are all prior art. Only the cross-service category semantics, the chain dataset, and the bandwidth/time bound are ours.

---

## Meta

- **Me:** GitHub `qwertyuiopas17`. Repo remote is `Daryl-69/sih26-2` (team). Team: 3 developers (6 total) + AI.
- **Stage:** demo-ready prototype → Grand Finale prep.
- **Do not edit** the `.pptx` or `.docx` files.

## Style rules

- Direct. No "Great question!", no preamble.
- Honest. I've read CRITIQUE.md — don't sell me the pitch deck.
- Cite the file path you used.
- Code > theory. 10-line fix → show the 10 lines.
- Verify before reporting. If a harness disagrees with the product, suspect the harness first — and say so when that's what it was.
- Strategy answers: lead with the Tier-2 cascade, demote the 6 models to "validated groundwork", frame as EDR-complementary / agentless-first (IoT, OT, BYOD).
- Shipping > perfect.
