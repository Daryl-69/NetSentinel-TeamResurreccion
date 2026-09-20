# Review of the Astra advice, and what measuring it turned up

**Date:** 11 Sep 2026 · **Submission:** 20 Sep 2026 (8.5 days)

You asked whether the Astra document is useful and to implement what is. Short
answer: **most of it is right, two items are corrections to my own earlier work
that I got wrong, and one recommendation is right in direction but wrong in the
specific.** Acting on it also turned up three things neither document predicted,
and one of them changes a claim on slide 3 of the deck.

Everything below is measured on your own files with tools committed alongside
this note. No number here is estimated.

---

## 1. Scorecard on Astra's advice

| # | Astra said | Verdict | Evidence |
|---|---|---|---|
| 1 | snaplen 512 still truncates ClientHellos | **Right** | 512 captures the whole ClientHello in 26.7% of cases; median needs 654 B |
| 2 | "512 = headers only, no payload" is false | **Right, and it was my wording** | 512 B holds application bytes at any header size. Removed from 3 files |
| 3 | Use `-s 0` | **Right conclusion, weak reason** | The real reason is QUIC, not TLS — see §2 |
| 4 | Files are pcapng despite `.pcap` | **Right** | All 91 files are pcapng. Our readers cope; anything dispatching on extension will not |
| 5 | "55% of DNS is DoH" is unsupported | **Right, and it was my number** | It counted bootstrap lookups *of the resolver's own hostname*. Retracted — see §3 |
| 6 | QUIC is parseable, don't disable it | **Right, and important** | Implemented. 16/16 RFC 9001 vectors pass — see §2 |
| 7 | Ring buffer ≠ 12 days retained | **Right in principle, not the live risk** | Ring is 312 files and only 91 exist. The real loss is gaps — see §4 |
| 8 | Prove sequence order matters (shuffle test) | **Right, and the most valuable item in the document** | Ran it. The claim does not survive — see §5 |
| 9 | Guarded rolling recalibration | **Right** | Implemented + a test where the unguarded version fails — see §6 |
| 10 | Separate "unknown" from "suspicious" | **Right** | Partly done; see §8 for what is left |
| 11 | Reverse-direction features vs a one-way diode | **Right to raise** | Measured: costs 0.002 AUC. Good news — see §5 |
| 12 | Promote hosts on evidence, not a 14-day timer | **Right** | Agreed, not yet built — see §8 |
| 13 | Rename the taxonomy (`Recon_API` etc.) | **Right but do not do it now** | A rename before 20 Sep invalidates every measured number for a cosmetic gain |
| 14 | Two capture conditions (controlled + realistic) | **Superseded** | Parsing QUIC removes the reason to have a "controlled" condition at all |

Two things Astra got wrong or overstated:

- **"12 days can't validate a 14-day commissioning policy."** True, but it
  understates the problem. You do not have 12 days. You have 2.9 (§4).
- **Full capture as a privacy problem.** Real, but at ~1 GB/day on your own
  machines with consent it is a retention-policy question, not a blocker.

---

## 2. The snaplen question, settled by measurement

`capture_probe.py` reads the *original on-wire length* that pcapng records for
every packet, so a capture that truncated a handshake still tells us how big
that handshake was.

| snaplen | packets truncated | TLS hostnames recovered | QUIC hostnames |
|---|---|---|---|
| 160 (5–10 Sep) | 50.8% | **0 of 442** | 0 |
| 512 (10–11 Sep) | 25.1% | **365 of 415 (88.0%)** | **0 of 805** |
| 0 (recommended) | 0% | — | unlocked |

The TLS story is the one we already knew, and 512 largely fixed it. **The QUIC
story is the one that matters and it is new.** RFC 9000 §14.1 *requires* a
client Initial packet to be padded to at least 1200 bytes. Measured in your
capture: median 1,230 B of UDP payload, max 1,280, **90.2% larger than 512**.
So at snaplen 512 not one QUIC handshake can ever be decrypted — and QUIC is
about 61% of your encrypted traffic. That is the argument for `-s 0`, and it is
much stronger than "512 might be tight for TLS".

Cost, measured rather than guessed: **×1.84 bytes on disk, ≈1.01 GB/day, so 12
days ≈ 12.1 GB** against a 40 GB budget with 67 GB free. Affordable.

Two things no snaplen fixes, both now measured:

- **46.3% of ClientHellos span more than one TCP segment.** A per-packet parser
  misses those at any snaplen. Only TCP reassembly (Zeek) recovers them. This
  is a loader problem, not a capture flag.
- **43 ClientHellos in a 2-file sample carry Encrypted Client Hello**, where the
  visible name is a cover name. Small today, growing. We now detect and report
  it rather than recording the cover name as truth.

**Changed:** `start_capture.ps1`, `capture_service.ps1` → snaplen 0, with the
measurements written into the comments so nobody "optimises" it back.

## 3. Parsing QUIC instead of switching it off

The old plan was a registry policy disabling QUIC and DoH in Chrome and Edge.
That produces a capture no real network resembles, and invites the question
*"so it doesn't work on real traffic?"*

QUIC Initial packets are protected with keys derived from a **salt published in
RFC 9001 §5.2** plus the client's own Connection ID, which travels in cleartext
in the same packet. Reading them is the documented design, not an attack, and
not TLS interception — we get the handshake and nothing else, exactly as with
TLS over TCP.

`netsentinel_v2/quic.py` implements it. `test_quic.py` checks the derivation
against the RFC's published vectors: **16/16 pass**, including negative controls
that make sure a truncated packet reports itself rather than returning a
hostname. So the parser is correct and the only thing between us and QUIC
hostnames is the snaplen.

**Recommendation: drop the QUIC/DoH registry policies.** They are no longer
needed, and not applying them makes the capture more representative, not less.

## 4. The capture is much thinner than we thought

`capture.log` and the file listing, read together:

- **5.70 days** wall clock, 91 files, 3.56 GB
- **70 of 137 hours have data — 51%.** 67 hours are missing
- **14 files are empty** (380 bytes: an hour where nothing was captured)
- Gaps: **21 h** (7–8 Sep), **23 h** (8–9 Sep), 8 h, 6 h, and three of 2 h
- snaplen 512 only started **10 Sep 00:41**, not 6 Sep

Split by what the data can actually be used for:

| | live hours | days |
|---|---|---|
| snaplen 160 — cannot name anything | 55 | 2.3 |
| snaplen 512 — TLS yes, QUIC no | 15 | 0.6 |
| snaplen 0 — both | 0 | 0 |

The day-long gaps line up with a laptop sleeping. **Do not claim a 12-day
capture.** After restarting at snaplen 0 today, by 20 Sep you can have at most
~8.5 days on one host, and only if sleep is disabled.

Two concrete actions, in order of urgency:

1. **Restart the capture at snaplen 0 today.** Every hour not restarted is an
   hour of data that cannot name QUIC.
2. **Stop the machine sleeping** (`powercfg /change standby-timeout-ac 0`, and
   disable hibernate). This is what cost you the two day-long holes.

The ring buffer is *not* the live risk: it holds 312 files and only 91 exist.
Astra's concern is valid for later, not now.

---

## 5. The one that changes the deck: order does not carry the signal

Slide 3 ends on *"we detect the SEQUENCE, not the destination."* That is the
project's central claim and it had never been tested. `ablation_order.py` tests
it. The model can only see order through the positional embedding and the
transformer over the hour axis, so permuting the hour axis is a complete
ablation — it preserves every feature, category, mask and volume, and destroys
only the arrangement in time.

**3 seeds, 120 hosts, 16 days, 45/960 attack days, fully-shaped adversary,
with hard negatives enabled:**

| condition | ROC-AUC |
|---|---|
| A full model (order-aware) | 0.998 ± 0.001 |
| B hours permuted **at scoring** | 0.998 ± 0.001 |
| C hours permuted **at training and scoring** | 0.997 ± 0.001 |
| D bag of categories (**order-free**) | **1.000 ± 0.000** |
| E first-order Markov transitions | 0.444 ± 0.055 |
| F no reverse-direction features | 0.996 ± 0.002 |

Read it plainly:

- **A − B = 0.000.** Shuffling the hours changes the model's score by nothing.
  It is order-blind.
- **A − C = 0.000.** There is no order information in the data for any model
  to use.
- **A − D = −0.002.** An order-free Mahalanobis distance does *marginally
  better* than the transformer.

**The sequence claim is not supported.** What the detector is actually doing is
cross-service co-occurrence plus per-category traffic shape. That is still a
real and defensible thing — it is just not what the deck says.

**Good news in the same table: F.** Dropping `log_bytes_down` and
`egress_asymmetry` — the two features a sensor behind a genuine one-way tap
cannot compute — costs **0.002 AUC**. So the diode deployment story and the
feature list are consistent. That defuses a question that could have been
awkward, and it is worth a line in the deck.

### 5b. Why the old numbers could not have shown this

Testing the above exposed something worse. On the generator as it was, this
single rule:

> longest consecutive run of hours in which `Messaging_API` is present

scores **ROC-AUC 1.000** at every stealth level. One counter, no model, no
features. The attacker was the only host that ever chatted for nine hours
straight. **Any detection result measured on the old synthetic generator was
measuring that, and nothing else.**

I added the hard negatives Astra called for — benign hosts that chat all day,
and legitimate integrations that poll on a schedule (which produce the same
low-jitter timing the Jitter-Trap keys on). Opt-in via
`synth.generate(..., hard_negatives=True)`, so prior results stay reproducible.

| rule | old generator | with hard negatives |
|---|---|---|
| longest `Messaging_API` run | 1.000 | 0.797 |
| hours with `Messaging_API` | 0.999 | 0.661 |

Even hardened, the benchmark is still over-determined — `distinct_endpoint_ratio`
alone scores 1.000, as does volume alone (0.999) and timing alone (0.999).
**The honest position: the synthetic benchmark demonstrates that the pipeline
runs end to end. It cannot support any comparative claim about the
architecture.** The LANL numbers are unaffected — those measure router
agreement with the teacher on real data, which is a different question.

---

## 6. Guarded recalibration (Astra's point 7A)

`netsentinel_v2/calibration.py` plus `test_calibration.py`. The failure mode is
real and the test demonstrates it rather than asserting it: a slow-ramp attacker
feeds their own scores into a naive rolling quantile until the threshold rises
above them.

Drift in the test is sized to what our own shift test measured (a fixed
threshold flagging 6.8% instead of 1%), not to a number that flatters us.

| policy | attack windows caught | false alerts | final threshold |
|---|---|---|---|
| FIXED (what we ship today) | 9.6% | 4.21% | 2.85 |
| UNGUARDED rolling quantile | **0.1%** | 1.92% | **4.29–4.53** |
| GUARDED | **8.8%** | 4.14% | 2.89 |

The attacker walks the unguarded threshold from 2.85 to ~4.4 and detection
collapses to 0.1%. The guards that prevent it: admission by **provenance** (blind
random audit) never by score, movement bounded in MAD units, and adaptation
frozen while an incident is open.

The test also surfaces the cost, which the deck currently hides:

| audit budget | detection | false alerts |
|---|---|---|
| 2% | 8.8% | 4.14% |
| 5% | 7.4% | 3.93% |
| 10% | 4.9% | 3.67% |
| 20% | 1.6% | 2.88% |

Tracking drift needs blindly-sampled recent windows, and every one is an
Inspector run. **Calibration comes out of the same budget as escalation.** The
deck shows 5% for escalation and implies calibration is free; it is not.

(The falling detection column is inflated — that stream is 12% attack, which no
real network is. At realistic prevalence the poisoning term nearly vanishes and
only the budget cost remains. Quote the shape, not the numbers.)

---

## 7. What must change in the deck and PPT before 20 Sep

1. **Slide 3 closing line.** "We detect the SEQUENCE, not the destination" →
   *"we detect the cross-service pattern and the machine-like shape of the
   traffic — not the destination."* Back it with the §5 table.
2. **Delete the 55% DoH figure everywhere.** It did not mean what it said.
   Replace with: 906 readable plaintext DNS queries, 106 distinct names, 1
   connection to a known DoH endpoint in the sampled window.
3. **Reframe the QUIC slide.** Not "61% invisible, we disabled it" but "61% is
   QUIC, we parse the Initial packets per RFC 9001, 16/16 vectors pass."
4. **Remove "headers only, no payload"** in all forms. Correct wording: *"the
   sensor keeps whole packets so it can read handshakes; the detector consumes
   only flow records and handshake metadata and never application payload."*
   Two statements, only the second is about the model.
5. **Capture slide:** say 2.9 usable days across 5.7 wall-clock days at 51%
   hour coverage, and that the restart at snaplen 0 begins the real corpus.
   Do not say "12-day capture".
6. **Add the diode ablation** (F: 0.002) — it is a strong answer to an obvious
   question and it costs one line.
7. **Escalation budget:** say calibration draws from the same budget.

The story is *better* this way, not worse. "We built the check that argued
against our own headline claim, and here is the table" beats a claim that
survives only until someone runs one line of numpy.

---

## 8. Not done — ranked by value per remaining day

1. **Per-host commissioning state machine** (Astra §12). COMMISSIONING /
   SENTRY_PRIMARY / ESCALATED / INCIDENT_HOLD / RECOMMISSIONING, promotion on
   evidence rather than a 14-day timer. Design agreed, not built. ~half a day,
   and it answers "what happens when a new machine joins?"
2. **TCP reassembly in the loader**, to recover the 46.3% of ClientHellos that
   span segments. Zeek already does this — the gap is that `capture_probe.py`
   and `real_probe.py` read packets directly. Route naming through Zeek output.
3. **Visibility flags separated from anomaly** (Astra §10). Partly there: the
   probe reports naming coverage. What is missing is the *gate* — refusing to
   score, and raising a data-quality warning instead of a security alert, when
   naming coverage drops below what the model was fitted on.
4. **Feature/schema contract tests.** Astra's port-scan 39-vs-59 mismatch and
   the VAE scaler mismatch are both Tier 1 and both still open. A test that
   asserts feature name, order and count between training and runtime for every
   model would have caught both.
5. **Re-run `real_probe.py` / `inject_demo.py`** once there is a corpus at
   snaplen 0. Unchanged advice: show it only if the benign-surge control comes
   back clean.

---

## Files added or changed

| File | What |
|---|---|
| `netsentinel_v2/quic.py` | **new** — QUIC Initial decryption, SNI + ECH detection |
| `test_quic.py` | **new** — 16 checks vs RFC 9001 Appendix A.1 vectors |
| `capture_probe.py` | **new** — snaplen/truncation/naming/DNS measurement |
| `ablation_order.py` | **new** — the order ablation and the diode ablation |
| `netsentinel_v2/calibration.py` | **new** — guarded rolling recalibration |
| `test_calibration.py` | **new** — poisoning demo + audit-budget sweep |
| `netsentinel_v2/synth.py` | hard negatives (`hard_negatives=True`), opt-in |
| `start_capture.ps1` | snaplen 0; removed the false "headers only" line |
| `capture_service.ps1` | snaplen 0, with the measurements in the comments |
| `ablation_order_hard.json` | the §5 result |

Run order to reproduce: `test_quic.py` → `capture_probe.py --dir D:\capture` →
`ablation_order.py --hard-negatives --stealth-lo 0.9` → `test_calibration.py`.
