# Video, 8 Sep — do exactly this and nothing else

**Rule for these three days: no new science.** Every hour goes into making what already works
look solid on camera. Anything that needs a new measurement is post-8th (see `POST_8SEP.md`).

---

## Fri 5 Sep

### 1. Start the capture (1 hour, then it runs itself)
Nothing else on the list is gated on the calendar. This is. See `CAPTURE_RUNBOOK.md`.

```powershell
winget install WiresharkFoundation.Wireshark      # tick "Install Npcap"
cd D:\1_sih26#2\netsentinel-main\v2
.\install_capture_task.ps1                        # lists interfaces
# then, in an ADMIN PowerShell:
.\install_capture_task.ps1 -Interface <n> -OutDir D:\capture -MaxGB 40
```

Registers a scheduled task: starts at boot, restarts if it dies, survives reboots and closed
windows. **You never start or stop anything again.** Verify with `-Status`.

### 2. Fix the one flaw that shows on camera (15 min)
The exfil VAE fires ~50% false positives because of a scikit-learn version mismatch. A dashboard
spraying false alerts is the single most damaging thing a judge can see.

```powershell
cd D:\1_sih26#2\netsentinel-main
.\.venv\Scripts\python.exe -m pip install scikit-learn==1.6.1
.\.venv\Scripts\python.exe run.py            # re-run the demo PCAP, watch the exfil panel
```

If the false-positive rate does not visibly drop, **cut the exfil model from the demo** rather
than spending Saturday on it. Five working models beat six where one is visibly wrong.

### 3. Decide what is NOT in the video (10 min)
- **Port scan model — cut it.** Zero detections, wrong training dataset, not fixable by Monday.
- **The 2 evidence panels that visualise the wrong thing** (exfil panel shows byte-ratio; the
  model is DNS-lexical). Either don't open them on camera, or fix the label. Do not re-architect.
- **Any detection percentage for Tier 2.** See the script below.

---

## Sat 6 Sep

### 4. Generate the results page (2 min)
```powershell
cd D:\1_sih26#2\netsentinel-main\v2
.\.venv\Scripts\python.exe make_card.py --open
```

`results_card.html` — every figure read from `lanl_novelty.json` and `shift_results.json`, nothing
typed by hand. This is your data slide. Screen-record it; don't rebuild it in PowerPoint, because
that is exactly how a superseded number gets back onto a slide.

### 5. Dry-run the demo end to end, twice (2 hours)
PCAP in &rarr; extract &rarr; infer &rarr; alert &rarr; WebSocket &rarr; dashboard. Time it. Write
down every place it stalls. The known-good run is 8.8 GB Friday-WorkingHours, 32,266 alerts,
42.5 flows/s, 23 ms, 280 MB — if you are far off that, something regressed.

**Record the screen capture of the working run now, on Saturday.** Then if Sunday breaks, you
still have footage. This is the single highest-value hour of the three days.

---

## Sun 7 Sep — record

### 6. The script (keep to these beats)

1. **Problem.** Kill chains riding trusted services — GitHub, Telegram, Drive — behind a data
   diode where there is no agent, no DPI, no signature.
2. **Tier 1, live.** Real PCAP through six ONNX experts to the dashboard. Show it running.
   *"Validated groundwork."* Do not oversell it.
3. **Tier 2, the actual idea.** Expensive Inspector at commissioning, cheap Sentry always-on.
   Show `results_card.html`.
4. **The honest beat — one sentence, then move on:**
   > "We validated against a real red team in 13 days of enterprise traffic. We also built a
   > confound check that told us our detection signal was a between-host artifact, so what we're
   > reporting today is the efficiency result — 96.9% teacher agreement at 13.7× compression —
   > and we're fixing the detector."
5. **What's next.** The 12-day capture is running right now; chain injection and rolling
   re-calibration land before the 20th.

### 7. Things to never say on camera
- Any Tier-2 **detection** rate. The 96.9% is *agreement with the teacher*.
- "95% recall" in any form.
- "State of the art", "novel transformer", "replaces EDR".
- That the Inspector architecture is ours — it is GraphIDS (arXiv:2509.16625). Ours is the
  cross-service category-sequence framing and the chain dataset.

---

## Mon 8 Sep
Submit. Then open `POST_8SEP.md`.
