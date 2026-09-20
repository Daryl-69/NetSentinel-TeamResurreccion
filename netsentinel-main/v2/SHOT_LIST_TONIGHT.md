# Technical video — shot list for tonight

The brief is **the prototype and its development**. That is a different video
from a sales pitch: the panel wants to see that you built something, that you
tested it, and that you know where it breaks. You have all three. Nothing below
is fabricated and every command runs.

Two PowerShell windows, both already:

```powershell
cd D:\1_sih26#2\netsentinel-main\v2
```

---

## SHOT 1 — the cascade, running (≈50 s of screen, talk over it)

```powershell
.\.venv\Scripts\python.exe demo_scenario.py --quiet
```

**Launch it first and keep talking.** It commissions the Inspector unsupervised,
distils the Sentry, routes on CPU, escalates the top 5% back to the Inspector,
and reconstructs the kill chain hour by hour.

Land on the last block when it finishes:

```
Sentry agreement with the Inspector (AUC)   0.81-0.85
Inspector flags recovered at 5% budget       38-41%
Host-days the Inspector never had to see       ~61%
Model size            205,546 -> 14,992  (13.7x)

KILL-CHAIN RECONSTRUCTION -- host 051 (developer), day 22
 09:00  Recon_API, Browse, Sync, CI_CD      1.18  ESCALATED  <-- chain step 1/4
 10:00  Code_Repo_Paste, Messaging_API      0.88  ESCALATED  <-- chain step 2/4
 ...
```

**Say:** *"Synthetic environment — the mechanism is real, the adversary is ours.
It includes forty legitimate developer hosts walking the same four categories,
because without those hard negatives the result would be worthless."*

Do **not** quote the attack-recall line. The script tells you not to.

## SHOT 2 — the test built to fail (≈30 s, launch in window 2 during shot 1)

```powershell
.\.venv\Scripts\python.exe test_lanl_loader.py
```

53 assertions. Point at the lateral-movement one: an attack day with **identical**
flow counts, bytes, durations and timing — only the peers are new. Volume-and-
timing scores 0.520; novelty scores 0.888.

## SHOT 3 — the capture, running (≈10 s on camera)

```powershell
.\install_capture_task.ps1 -Status
```

File count climbing, hourly rotation in the log. Show the folder filling.

**Say:** *"The hard part isn't the model, it's the data. No public dataset has
multi-day egress traffic with attack labels — LANL has a real red team but zero
external traffic. So we're building our own: six machines, twelve days, running
right now. And we don't just trust it — we wrote a tool that audits whether our
own capture can actually feed the model. It caught a configuration problem on
day one, we fixed it, and it's collecting clean data now."*

That last sentence is the whole point and it takes six seconds. **Do not open
the audit output on camera.** One line about it lands better than a screen of
zeros, and the detail is there if a judge asks.

### Q&A only — if someone asks how you know the capture is any good

```powershell
.\.venv\Scripts\python.exe capture_audit.py --dir D:\capture
```

Needs `pip install dpkt` once. **Run this on camera only after the snaplen fix
has been live for an hour** — then it shows hostnames resolving and categories
populating, which is the version you want on screen. Before that it shows the
defect, which is a fine answer to a question but a bad thing to volunteer.

## SHOT 4 — nothing is hand-typed (≈5 s, closing beat)

```powershell
.\.venv\Scripts\python.exe make_card.py --open
```

Rebuilds the results page from `lanl_novelty.json` on camera.

## SHOT 5 — the number that argues against us (say it, don't skip it)

Slide 06 of the deck.

**Say:** *"Global AUC against the LANL red team was 0.745. Then we scored each
host against its own baseline: 0.557. Chance. The model was ranking which host
was busy, not when it was attacked. We built that check ourselves and it argued
against us. What we claim today is the cascade — measured, three seeds. The
detection claim comes from our own capture."*

---

## What NOT to show tonight

**`inject_demo.py`.** It is the right experiment — real captured background,
injected kill chain, plus a benign-surge control — and it is the centrepiece for
the 20th. Tonight it fails its own control: 5/5 benign-surge hours flagged and
2/5 untouched hours, because it has 11 commissioning hours instead of 14 days.
It is detecting difference, not attack. Ship it when the multi-host capture is
in and condition B comes back clean.

## Things not to say, in any form

- any Tier-2 **detection** rate, including "detected a C2 breach on our network"
- "95% recall"
- "state of the art", "novel transformer", "replaces EDR"
- that the Inspector architecture is ours (it is GraphIDS-shaped, arXiv:2509.16625)

If asked what is weakest: **0.557 ± 0.013**, plainly, then what you are doing
about it.

---

## Why this beats a fabricated detection

A claimed C2 detection on your own laptop invites four questions you cannot
answer: which family, what was the C2 domain, show me the flow, why did nothing
else catch it. At the Grand Finale those get asked out loud. What you have
instead is a working cascade, a test designed to fail, a confound check you built
against yourself, and a capture defect you caught on day one — and every one of
them survives being poked at.
