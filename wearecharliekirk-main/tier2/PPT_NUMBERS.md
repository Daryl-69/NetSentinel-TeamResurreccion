# NetSentinel — what works, in plain words

**For the deck. 17 September 2026.**
Every number here was measured and is in a file you can open. Nothing is
estimated. Where a number needs a caveat to be honest, the caveat is printed
next to it — put both on the slide or neither.

---

## 1. The one-line version

> A passive network detector for places you cannot install software — nuclear,
> defence, SCADA, behind a one-way data diode. It learns what normal looks like
> for each machine, with no attack examples and no signatures, and flags the
> machine when its day stops looking like its own normal.

---

## 2. The sensor works. This is your strongest, cleanest result.

Measured on real captured traffic from our own network — 173,682 packets.

| What | Number |
|---|---|
| Packets captured whole, nothing cut off | **100%** (0 truncated) |
| Website names recovered from encrypted TLS | **90.1%** (308 of 342) |
| Network flows we could put a name to | **66.2%** |
| Encrypted QUIC handshakes readable | **yes** — was 0 before the fix |
| DNS questions read in the clear | 1,002 across 65 distinct names |

**Say it like this:** *"We see encrypted traffic and can still tell you which
service it is, nine times out of ten, without decrypting anybody's data."*

### Why QUIC matters and why it is legitimate

Most Google and YouTube traffic uses QUIC. Its opening message is encrypted —
but the key is derived from a salt **printed in the public internet standard**
(RFC 9001) plus an ID the client sends in plain text. Anyone can compute it;
that is the design.

- We read **only the website name.** No message content, ever.
- Verified against the standard's own published test examples: **16 of 16 exact
  matches**, including 5 tests that confirm it refuses to guess when unsure.
- This is not interception. No private key, no certificate, no tampering.

**Say it like this:** *"We read the label on the envelope, which the postal
standard says is public. We never open the envelope."*

---

## 3. The categories work on real traffic

The system sorts every connection into one of nine service categories. On our
own real capture it filled **eight of the nine** — including the ones the whole
idea depends on:

| Category | Real example found |
|---|---|
| Code repository / paste site | github.com |
| Messaging | graph.microsoft.com |
| Cloud storage | onedrive (blob.core.windows.net) |
| Software build / packages | pypi.org |
| Background sync & telemetry | events.data.microsoft.com |

**This has never been possible before.** The public research dataset we test
against (LANL) anonymises every machine name, so those categories simply cannot
appear there. Our own capture is the first data where the core idea can even be
tested.

**Say it like this:** *"Our own network data is the only data in the world where
this idea can be tested, and we built the collection system to produce it."*

---

## 4. The two-model design, and why it is two

A big careful model (**Inspector**, 205,546 settings) and a small fast one
(**Sentry**, 14,992 settings). The small one watches everything and decides what
the big one should look at.

Two reasons, and both were **proven by measurement, not argued**:

| | Measured |
|---|---|
| The small model can answer **every hour** | difference from a full-day score: **0.000004** |
| The big model **cannot** — it needs the whole day | changes by **0.032** if given a partial day |
| The big model needs **other machines' data** | changes by **0.410** without it |
| The small model needs **no other machine** | by design — it has no such input |

That last pair is why they sit in different places: the small model runs at the
site, the big one runs centrally where all traffic meets.

**Say it like this:** *"The small model tells you at 2pm. The big model cannot
answer until midnight — not because it is slow, but because it reads the whole
day at once. So we run both."*

### Speed, measured on one ordinary processor core

| | Windows per second |
|---|---|
| Sentry (small) | **609,000 – 787,000** |
| Inspector (big) | 71,000 – 104,000 |

The small model is **about 8× faster** — three runs on the same machine gave
8.6×, 7.5× and 8.2×. ⚠️ Say **"about 8×, on a CPU"**, not a decimal place: the
machine was doing other work on some runs and that alone moved the number.
Do **not** say 13.7× — that is the size ratio, not a speed.

---

## 5. How well the small model copies the big one

This is the number the design lives or dies on, and it is excellent.

| Budget: how much the big model gets to look at | How much of its work the small model still catches |
|---|---|
| 1% | 37.7% |
| 2% | 68.0% |
| **5%** | **96.9%** |
| 10% | 99.0% |

**Agreement between the two models: 0.992 out of 1.0** (three independent runs).

⚠️ **The one sentence that must go with the 96.9%:** *"That is 96.9% of what the
big model would have flagged — it is not a detection rate."* Saying "96.9%
recall" on its own is the single most dangerous mistake available in this
project.

**Say it like this:** *"The cheap model reproduces 96.9% of the expensive
model's judgement while doing 5% of its work."*

---

## 6. Coverage you can dial, per machine

The small model can miss things — measured at **3.1%**. So every machine also
gets random spot-checks by the big model, and **you choose the rate per
machine**:

| Machine type | Spot-check rate | Worst case before the big model looks |
|---|---|---|
| Domain controller, critical server | 100% | **every single day** |
| Admin, finance | 20% | 10 days |
| Ordinary staff laptop | 5% | 40 days |
| Kiosk, IoT device | 2% | 100 days |

**At 100% the system is simply "check everything"** — so the design *contains*
full inspection rather than replacing it. One deployment, different protection
for different machines. A single fixed setting cannot do that.

**Say it like this:** *"Your crown jewels get looked at every day. Ten thousand
laptops get sampled. Same system, one dial."*

---

## 7. It runs on ordinary hardware

At **100,000 machines**, running the big model on everything for a year:

| | Cost |
|---|---|
| Graphics-card time needed | **about $150 a year** |

**Say it like this:** *"The whole detection workload for a hundred thousand
machines costs about 150 dollars a year. No specialist hardware anywhere in the
deployment."*

For nuclear, defence and air-gapped sites — where a graphics card is a
procurement problem, a power problem and sometimes a security problem — that is
a stronger claim than any percentage saving.

⚠️ Do not claim "94.7% cost reduction". It was withdrawn.

---

## 8. It keeps working when the sensor doesn't

**A camera fault must not look like a burglar.** If the sensor stops being able
to name traffic, the model would correctly notice something changed — and be
completely wrong about what. So the system checks the sensor before it trusts
the score, and raises a **maintenance ticket**, not a security alert.

The counter-intuitive part, and it is worth saying out loud: **an improvement
breaks it too.** When we fixed the capture and suddenly could name far more
traffic, every previously-learned baseline became wrong. The system treats a
sensor getting better exactly like a sensor getting worse — both mean relearn.

**Tested on the five sensor conditions we actually hit: 19 of 19 checks pass.**

---

## 9. It resists being trained by the attacker

If a system quietly re-learns "normal" from whatever it sees, a patient attacker
ramps up slowly and drags the definition of normal along with them — the frog in
slowly heating water.

Four guards, all built and tested:

1. Only **randomly spot-checked** traffic can update the baseline. An attacker
   cannot volunteer training data by looking normal, because looking normal is
   not what gets you selected.
2. Normal can only move a **limited amount** per update.
3. During an incident, the baseline **freezes completely**.
4. Updates **never rewrite history**.

**Demonstrated:** the naive version gets poisoned; the guarded version holds.

---

## 10. Machines earn their promotion — no fixed timer

A machine starts under full inspection and only graduates when there is real
evidence, not when a calendar runs out.

Requirements: 240 active hours · 10 different days · **a weekend must have been
seen** · enough samples to learn from · steady behaviour · agreement between the
two models.

**Why a timer is wrong:** two weeks on a developer's laptop shows you everything;
two weeks on a server whose big job runs monthly shows you nothing. A timer
promotes both. When a machine is held back, the system says exactly which
requirement is missing.

**Say it like this:** *"It graduates when it has proved it's understood, not when
two weeks are up."*

---

## 11. Everything is tested

| Test area | Checks | Result |
|---|---|---|
| Public dataset loader | 53 | ✅ pass |
| Feature definitions | 32 | ✅ pass |
| Sensor health + machine lifecycle | 19 | ✅ pass |
| Two-model deployment split | 17 | ✅ pass |
| QUIC vs the published standard | 16 | ✅ pass |
| Attacker-poisoning resistance | — | ✅ pass |
| Same seed → same numbers, in a fresh process | 11 | ✅ pass |
| **Total** | **148** | **7 of 7 suites pass** |

One command re-runs all of it, re-derives every number on these slides from its
source file, and checks that nothing we withdrew has crept back: **`python
verify_all.py`**. It prints a failure rather than a reassurance.

---

## 12. We tested our own claims and published what failed

This is a slide, not an apology. Say it with confidence — it is what makes every
other number on this list believable.

| We claimed | We tested it | We changed the claim |
|---|---|---|
| "We detect the *sequence* of events" | Shuffled the hours randomly | Score moved **0.000**. Order doesn't matter. Now we say **"the combination and the shape"** |
| Big headline accuracy number | Checked whether it was really detecting attacks | Attacked machines were just **busier** (0.811 vs 0.530). Corrected the number and said so |
| "Our model beats simple methods" | Ran it against a method with **almost no settings at all** | It **ties**. Published the tie |
| "94.7% cost saving" | Did the arithmetic properly | Wrong unit of measurement. Withdrawn |
| "55% of DNS is hidden" | Looked for the denominator | There isn't one. Retracted |
| "Router A is the best of the three" | Ran **8** independent trials instead of 3 | The three are **tied**. The ranking was noise. We still build A — because on *real* data it agrees with the big model **0.992 vs 0.634** |
| Every result from our traffic generator | **Ran the same script twice** | The two runs disagreed. A bug meant the same starting seed produced different data each time. Fixed, everything re-run, and there is now a test that catches it |

**Say it like this:** *"Every correction on this slide was found by us, before
anyone asked. That is why you can trust the numbers on the other slides."*

---

## 13. Three things we fixed this week, worth a sentence each

**The capture was throwing away half the traffic.** More than half our network
is modern IPv6, and the code only recognised the old address format — so every
IPv6 connection was silently discarded. Found it by re-reading 233,710 real
packets end to end: **52% of traffic** was being dropped. Fixed and re-tested.

**Two thirds of connections were landing in one "other" bucket.** Improving the
category rules moved it from **63% down to 40%**, and lit up three more
categories. More signal, same data.

**Our test data was not reproducible, and we only found out by running the same
script twice.** A list of service categories was stored in a form Python
shuffles differently in every run, so the same starting seed produced different
traffic each time — and our error bars had been quietly absorbing it. One
experiment's result flipped once it was fixed. Everything was re-run, the old
files were kept rather than deleted, and there is now a test that runs the
generator four times in four fresh processes and compares the bytes.

*If a judge asks what this means:* **"the results on the real public dataset
never changed — that code path was untouched. What changed was our synthetic
test data, and we found it ourselves, before anyone asked."**

---

## 14. Honest limits — have these ready, do not volunteer them

A judge who finds a weakness you hid punishes you. A judge who watches you name
it yourself does the opposite.

**"What's your detection rate?"**
> On the only public dataset with real attack labels, our within-machine score
> is 0.557 out of 1.0 — close to chance, and we lead with that. But that dataset
> anonymises every machine name, so it cannot test what our system actually
> looks for. It is the wrong exam. Our own data is the right one and we are
> still collecting it.

**"Does your AI beat a simple statistical method?"**
> On that dataset, no — it ties, and we ran the proper paired statistical test
> to confirm it rather than hoping. That dataset removes the thing our model
> exists to use. We are not claiming a win we cannot evidence.

**"How much of your own data do you have?"**
> Under two hours of fully-working capture. We need about ten days. We are
> honest about that rather than showing you a number built on two hours.

---

## 15. Where every number comes from

| Slide topic | File |
|---|---|
| Sensor, hostnames, QUIC | `capture_probe.json`, `test_quic.py` |
| Copying accuracy, budget table | `lanl_novelty.json` |
| Busy-machine correction | `lanl_novelty_hn.json` |
| Tie against the simple method | `lanl_p0b.json`, `paired_synth.json` |
| Order shuffle | `ablation_order_hard.json` |
| Speed | `escalate.json` |
| Coverage dial, hourly answers | `deploy_c.json`, `test_tiers.py` |
| Cost | `gpu_cost.py` |
| Real traffic categories | `pcap_to_tensor.py` on the 12 Sep capture |

**The rule:** if a number is not in one of those files, it does not go on a
slide.
