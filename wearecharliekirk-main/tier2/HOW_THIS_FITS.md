# Tier‑2 (this folder) and how it fits the NetSentinel pipeline

*Merged into this repo on 2026‑09‑20. This folder is the Tier‑2 track — the
Inspector–Sentry cascade and the Telegram‑C2 bound — brought in from the
`netsentinel-main/v2` working tree. Nothing in `../netsentinel/` was changed.*

## The two tiers, honestly

| | Tier‑1 (`../netsentinel/`) | Tier‑2 (`tier2/`, here) |
|---|---|---|
| what it is | the **live pipeline** — 5 experts (DDoS, DGA, C2‑beacon, encrypted, port‑scan) + exfil | the **anomaly / analysis track** for LOTS‑style abuse and the Telegram‑C2 bound |
| runtime | streaming: pcap → extract → infer → alert → WebSocket → dashboard | offline / batch: tensors, CUSUM, paired tests, benchmarks |
| status | shipped, demo‑ready | **runs and is verified standalone; NOT yet wired into the live analyzer** |

They share the idea, not yet the runtime. Wiring the Tier‑2 CUSUM detector into
`../netsentinel/pipeline/analyzer.py` as a 6th/7th module is the next step and is
**not done** — do not claim it is.

## What's in here

- **`telegram_c2.py`** — the Telegram‑C2 case, *bounded not solved*. Per‑window
  detection collapses under perfect mimicry (reported); CUSUM converts exfil
  bandwidth into a bounded detection delay. `test_telegram.py` (17 checks).
- **`bench_evasion.py`** — the evasion ladder + a second, independent angle:
  cross‑category correlation stays AUC ≈ 0.99 even at full *marginal* mimicry,
  because matching the marginal doesn't match the joint. Writes `bench_evasion.json`.
- **`netsentinel_v2/`** — the Inspector–Sentry cascade, cohort, host‑norm,
  calibration, QUIC, loaders, synthetic generator.
- **experiments** — `escalate.py`, `run_experiment.py`, `ablation_order.py`,
  `paired_synth.py`, `sweep_threshold.py`, `shift_test.py`, `lanl_*`, `confound_test.py`.
- **`verify_all.py`** — one command that runs every suite, re‑derives every
  headline number from its source `.json`, and fails if a withdrawn claim
  reappears. Exit 0 only if everything passes.
- **docs** — `AUDIT.md`, `INSPECTOR_SENTRY_SPEC.md`, `TIER2_BRIEF.md`,
  `PPT_NUMBERS.md`, `ARCHITECTURE_V2.md`.

## Run it

```bash
cd tier2
pip install -r requirements.txt        # torch (CPU), numpy, scipy, scikit-learn, cryptography
python verify_all.py                   # full suite: 8 suites, numbers re-derived
```

**Verified 2026‑09‑20.** Full `verify_all.py` — **8 suites pass**, 25 numbers
re‑derived, 0 retired claims live. On a machine without PyTorch, the three
torch‑free suites (`test_determinism`, `test_telegram`, `test_quic`) run in
place and pass; the torch suites (`test_contracts`, `test_tiers`,
`test_lanl_loader`, `test_calibration`, `test_lifecycle`) need `torch` installed.

## The one‑line claim you can defend

> Against a Telegram‑C2 implant that perfectly mimics the host's own traffic,
> per‑window detection is impossible and we show it collapses to chance — but we
> **prove a bound**: any nonzero exfil rate is caught within a delay its own
> bandwidth sets, and the only guaranteed‑invisible channel carries ~no data.

Not "we detect Telegram‑level malware." That one does not survive a hostile judge.
