# Inspector–Sentry — 35-second walkthrough script

**Setup before you hit record**

1. Terminal A (backend, leave running):
   ```
   cd "D:\1_sih26#2\wearecharliekirk-main"
   python run.py
   ```
2. Browser, full-screen: **http://localhost:8000/sentinel/**
   Wait ~15–20 s until the phase track reads **3 · Watch & escalate** and the host
   grid is lit and moving. The left side is now the live cascade.
3. Terminal B, sized so a strip of it is visible over the browser, ready at:
   ```
   cd "D:\1_sih26#2\wearecharliekirk-main"
   ```
   (don't run it yet)

---

## The beats (~35 s)

**0:00–0:05 — the page, already watching** *(camera on the left panel)*
> "This is our Inspector–Sentry engine. Every host on the network is scored every
> hour by the small **Sentry** model running at the edge."

**0:05–0:10 — start the traffic** *(cut to Terminal B, type it live)*
```
python traffic_feed.py
```
> "I'll put real threat traffic onto the sensor."
*(Let the terminal show the `[1/7] Reconnaissance … <- flagged` lines scrolling.
Leave it visible for the rest — attacks are visibly arriving.)*

**0:10–0:17 — the cascade does its job** *(camera back on the left)*
> "The Sentry can't run the heavy model on everyone, so it escalates only the
> **top five percent** of host-hours to the **Inspector**, which re-checks each one
> against its own learned normal. Fourteen-thousand parameters guarding two-hundred-
> thousand — about **thirteen times smaller**."

**0:17–0:23 — the flag** *(point at the grid + the red verdict / banner)*
> "When one workstation reaches recon, code, messaging and cloud storage the way an
> intruder would, the Inspector flags it — that's **dev-011** turning red. It's the
> **combination and shape** of the services it touches, not any single request."

**0:23–0:30 — the right side, live** *(pan to C2 panel, then family tiles)*
> "A host calling home on a fixed timer gives itself away by its rhythm — you can see
> the beacon here. And every family in the problem statement — floods, beaconing, DGA
> and tunnelling, malware in encrypted sessions, recon, exfiltration — is scored as it
> arrives, from **handshake metadata and volume only. No payload is read.**"

**0:30–0:35 — the criteria strip** *(pan along the bottom)*
> "Read-only ingest, no decryption, bounded latency, one alert schema — the strip
> along the bottom is the PS 26145 checklist, ticking live. That's the whole engine,
> running."

---

## Delivery notes

- The feed runs ~30 s at normal speed, so start narrating the cascade the moment you
  launch it; the flag on dev-011 lands within the first pass and the banner shows
  **"Inspector flagged dev-011"**.
- If you want a slower run for a longer take: `python traffic_feed.py --speed 0.7`.
  For a quick rehearsal: `--speed 3`.
- Nothing on screen says "demo" or "simulation" — it reads as an operations view.

## Say it truthfully (so an alert judge can't catch you out)
- **13.7× is a size / parameter ratio**, not a speed or accuracy number. "About
  thirteen times smaller" is the safe phrasing.
- The Inspector's line is **"re-checks against its own normal"** — the threshold is the
  99th percentile of its *own* reconstruction error, not a labelled detector.
- Left panel = the **real Tier 2 models** (Inspector 205,546 params, Sentry 14,992)
  scoring a **modelled organisation**, streamed hour by hour. Right panel + the tiles =
  the **live sensor** scoring the traffic you pushed. They are two honest halves of the
  same story; don't imply the cascade is reading the same packets as the sensor — it
  isn't wired into the live pipeline yet, and you don't need to claim it is.
- Other hosts sometimes flag too — that's the model being honest, not a bug. If a judge
  asks, "unsupervised, so it has a false-positive budget; that's why the Sentry caps
  escalation at five percent" is the true answer.
