# Capture runbook — the 12-day benign capture

**Start it on 5 Sep. It must still be running on 17 Sep.** This is the only task on the
critical path that is gated on wall-clock rather than effort, so it starts before anything else
and runs in the background while you build.

## Why

ARCHITECTURE_V2 §5c: LANL cyber1 gave a clean negative (within-host AUC 0.557 ± 0.013) and, more
importantly, **could never have tested the actual claim** — it is an all-internal network with
zero egress, so there are no trusted-SaaS destinations to sequence. Every public dataset we
checked has the same problem or worse (`DATASETS.md`). The cross-service category-transition
hypothesis — the one thing a 91-study review says nobody else does — can only be tested on
traffic from machines that browse the real internet.

That traffic is yours. Nobody is going to hand it to you.

## Day 0 — today, about an hour

On each machine that will contribute (your own laptops are ideal — no permission needed):

```powershell
winget install WiresharkFoundation.Wireshark    # tick "Install Npcap"
cd D:\1_sih26#2\netsentinel-main\v2
.\start_capture.ps1                              # lists interfaces
.\start_capture.ps1 -Interface <n> -OutDir D:\capture -MaxGB 40
```

Leave the window open. Headers only by default (snaplen 512) — enough for TLS SNI and DNS query
names, no payload on disk. One file per hour, ring buffer, ~40 GB cap.

**Permission.** Capture your own machines and you need nobody's approval. If you want the
college or lab network, ask the network admin first and get it in writing. Do not skip this.

## Day 1 — prove the pipeline before you trust the capture

The failure that would cost you everything is discovering on the 18th that Zeek produced no
`ssl.log`, so every destination is `Unknown_External` and the resolver is blind. Check on day 1.

In WSL (Ubuntu), where `D:\capture` is `/mnt/d/capture`:

```bash
./zeekify.sh /mnt/d/capture /mnt/d/capture-zeek
```

It is incremental — safe to re-run nightly while the capture continues. It prints:

```
logs: conn=N  ssl=N  dns=N
distinct SNI hostnames so far: N
```

**If `ssl=0` and `dns=0`, stop and fix it now.** Wrong interface, or a snaplen too small. A
capture with no hostnames cannot test the hypothesis and you will have burned twelve days.

Then, on Windows:

```powershell
.\.venv\Scripts\python.exe train_real.py --data D:\capture-zeek --seeds 3
```

Look at the **resolver hit rate** line. WRCCDC gave 77.3%. If you are in that neighbourhood, the
capture is good and you can leave it alone until the 17th.

## Daily — 30 seconds

Confirm the dumpcap window is still running and files are still appearing. A capture nobody
checked is a capture that died on day 2. Put it on one person.

## Day 12 — 17 Sep

Stop the capture, run `zeekify.sh` a final time, then the real run. By then the chain-injection
work (see the plan) should be ready to overlay emulated LOTS sequences onto this benign base,
which is what finally produces a detection number with ground truth you control.

## What this buys you

| | LANL cyber1 | your capture |
|---|---|---|
| egress to trusted SaaS | none | yes |
| resolvable hostnames (SNI/DNS) | none | yes |
| multi-day per-host baselines | yes | yes (12 days) |
| attack ground truth | real red team | only what you inject |
| tests the V2 hypothesis | **no** | **yes** |

LANL had the labels and the wrong network. This has the right network, and you supply the labels.
