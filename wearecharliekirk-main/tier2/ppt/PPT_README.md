# NetSentinel — SIH 2026 decks

Two files, same content, same visuals.

| File | Slides | Use it when |
|---|---|---|
| `NetSentinel_SIH2026.pptx` | 10 | The structure you specified: Title, Problem, Solution, Architecture, Innovation, Feasibility, Impact, Prototype, Timeline, Team & References. |
| `NetSentinel_SIH2026_6slide.pptx` | 6 | The **official SIH Idea Submission template** headings, exactly as in the reference PDF: Title Page, Proposed Solution, Technical Approach, Feasibility and Viability, Impact and Benefits, Research and References. Submit this one if the portal validates slide count or headings. |

## Before you submit — fill the placeholders

Everything to replace is in **«angle brackets»**, coloured yellow/amber so it is
impossible to miss. 24 in the 10-slide deck, 9 in the 6-slide deck:

- Problem Statement ID, Problem Statement Title, Theme, Team ID, Team Name
- Institution name
- Mentor name and department
- Six member names and departments (10-slide deck, slide 10)

Roles are already written against each member slot — reassign them to match who
actually did what.

## Two yellow SLOT boxes on slide 08 (10-slide deck only)

1. **Screenshot slots.** Paste the React dashboard mid-replay and the
   `demo_scenario.py` kill-chain terminal output, then delete the yellow boxes.
2. **RESULT SLOT.** Fill from `inject_demo.py` output on ~19 Sep, *and only if
   condition B (the benign-surge control) comes back clean*. If it has not, delete
   the box and say the experiment is pending. Do not put a number there you have
   not run — the whole deck's credibility rests on every other figure being real.

## Every figure traces to a file

Verified by script against the sources:

| Claim | Source |
|---|---|
| 0.992 ± 0.003 Sentry–Inspector AUC | `v2/lanl_novelty.json` |
| 96.9% ± 1.1 flags recovered @ 5% | `v2/lanl_novelty.json` |
| 18.4% (Router B, rejected) | `v2/lanl_novelty.json` |
| 0.745 ± 0.002 global AUC | `v2/lanl_novelty.json` |
| 0.557 ± 0.013 within-host AUC | `v2/lanl_novelty.json` |
| 13.7× · 205,546 → 14,992 params | `v2/results.json` |
| 94.7% GPU reduction | `v2/results.json` (cost model) |
| 612 hosts × 13 days × 749 events | `v2/lanl_novelty.json` |
| 0.811 vs 0.530 activity density | `v2/lanl_novelty.json` |
| 61% QUIC · 2.07 M packets · 73.8% unresolvable | `v2/capture_audit.json` |

Nothing in either deck is a number I could not trace. If a judge asks where a
figure comes from, the answer is a filename.

## Rebuilding

```bash
node build.js     # 10-slide
node build6.js    # 6-slide
python3 assets/mkcharts.py   # regenerate charts from the JSON
```

Assets are in `assets/` — four Eraser.io architecture diagrams, four charts
generated from the result files, and three HTML-rendered graphics (pipeline,
kill chain, 36-hour timeline).

## Design note

One visual motif, used consistently: **anything that came off a machine sits on
a dark panel.** Diagrams, charts, terminal output. Everything the team wrote sits
on light cards. It makes "measured" and "claimed" visually separable at a glance,
which is exactly the distinction this project needs to keep making.
