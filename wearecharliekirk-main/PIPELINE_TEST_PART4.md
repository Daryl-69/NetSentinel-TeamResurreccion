# Full-pipeline test, Part 4 — the controlled beacon test, and an IPv6 blind spot

*21 September 2026. The first test of C2 detection against real, labelled beacon
traffic on a live network. The beacon was not detected, and the reason turned
out to be bigger than C2.*

## The experiment

Part 3 closed by saying a publishable detection figure needs real traffic with
ground truth. `scripts/beacon_harness.py` produces exactly that, without
malware: an ordinary HTTPS client polling `api.telegram.org` on a fixed
interval, opening a new TCP connection per check-in, logging every one.

| | |
|---|---|
| target | `api.telegram.org` — the same endpoint 4 of the 5 malware samples used |
| interval | 60 s, ±5% jitter |
| duration | 4 hours (19:12 → 23:11 UTC, 20 Sep) |
| check-ins | **231 logged, 231 succeeded** |
| ground truth | `beacon_truth.jsonl` — timestamp, destination, port, status per check-in |
| capture | 5 consecutive hourly captures, fed through **one** `PacketProcessor` |

Replayed with `scripts/verify_beacon_detection.py`.

## Result: NOT DETECTED

```
flow events to beacon   41
threshold needed        100
--> NO. no session was built and the C2 model was NEVER INVOKED.

C2 Beacon alerts: 0
```

231 real, labelled beacons on a live network produced **zero** C2 alerts. Three
independent causes, in the order they bite.

---

## Cause 1 — the pipeline cannot see IPv6. This is the important one.

**206 of the 231 check-ins (89%) went over IPv6**, to
`2001:67c:4e8:f004::9`. Only 25 used the IPv4 address
(`149.154.166.110`) that the malware samples used.

The extractor has **no IPv6 handling at all** — there is not one IPv6 reference
in `netsentinel/extractor/`, and the default capture filter is `bpf_filter="ip"`
(`pcap_reader.py:243`), which in BPF means IPv4 only; IPv6 is `ip6`.

**The traffic is not missing from the capture — it is being ignored.** In one
capture from the beacon window there are **1,115 packets to and from the
beacon's IPv6 address**, sitting in the pcap, invisible to every detector.

This is not a corner case on this network:

| capture | IPv6 | IPv4 | IPv6 share |
|---|---:|---:|---:|
| `ns_00016_20260921005211` | 36,219 | 43,474 | **45%** |
| `ns_00018_20260921025212` | 7,504 | 4,291 | **64%** |
| `ns_00001_20260918083538` | 38,633 | 81,306 | **32%** |

That last row matters most: it is the 200 MB capture **every figure in Parts 2
and 3 was measured on**. Roughly a third of it was never examined.

**Consequences, stated plainly:**

- This affects **every detector**, not just C2. DDoS, DGA, exfiltration, port
  scan and the encrypted-traffic classifier all sit behind the same extractor.
- Alert counts reported earlier (144 → 34, 4 actionable) are alerts **per IPv4
  subset**, not per capture. They are not wrong, but their denominator is
  smaller than it appeared.
- The false-positive upper bound from Part 3 is unchanged in direction — fewer
  observed flows cannot create false positives — but the *rate* is computed
  against the wrong denominator.
- For the target deployment this is serious. Defence, OT and modern enterprise
  segments increasingly run dual-stack; a sensor that silently drops a third to
  two-thirds of traffic is not a passive monitor, it is a partial one.

Nothing in the product says "IPv4 only". It should, until this is fixed.

---

## Cause 2 — the IPv4 remainder never reaches the session threshold

Even ignoring IPv6: 41 flow events reached the beacon destination, against the
**100-flow** minimum `SessionBuilder` needs before emitting a session
(`extractor/session_builder.py:36`). No session, no C2 scoring — the same
structural failure as the malware sandbox captures in Part 3's addendum.

25 IPv4 check-ins cannot produce 100 flows. The 41 counted includes
return-direction and ordinary Telegram-client traffic from the host.

## Cause 3 — real-world jitter exceeds the low-jitter gate

Measured inter-check-in spacing over the 4 hours:

```
mean 62.4s   stdev 5.0s   cv = 0.0802
```

The `low_jitter_beacon` path requires **cv < 0.05**. At 0.0802 it would have
been rejected even with 100+ flows, leaving only the FFT path.

Worth noting *why* cv is higher than the 5% configured: the real gap is
`interval + RTT + scheduling overhead`, and observed RTT reached 877 ms. **Real
beacons are noisier than their nominal interval.** A gate tuned on synthetic
constant-interval traffic is tuned too tight for the real thing — consistent
with Part 3's finding that the model tops out at 0.941 on clean synthetic
beacons.

---

## False positives in the same window

The 4-hour window, one host, IPv4 only:

| | |
|---|---|
| total alerts | **117** |
| by class | Data Exfiltration 113, DGA 4 |
| by severity | 107 INFO, 8 CRITICAL, 2 HIGH |
| C2 Beacon | **0** |

117 alerts in 4 hours with 10 actionable, and the one thing we *know* was
happening — a beacon every 60 seconds for 4 hours — is not among them. This is
consistent with the exfiltration precision problem recorded in Part 3's malware
addendum, where 5 of 5 alerts fired on benign infrastructure domains.

---

## What this does and does not change

**Does not change:** no accuracy, recall or false-positive rate is claimed.
This adds a *measured negative*, which is evidence, not an accuracy figure.

**Does change:**

- C2 beacon detection must be described as **unverified on real traffic**. It
  has now been tested once, against labelled real traffic, and did not fire.
- Every coverage statement needs "IPv4 only" attached until Cause 1 is fixed.
- Prior alert-rate figures should be quoted as "alerts per IPv4 flow events",
  not "per capture".

**Honest framing of this test:** we chose the interval, so a detection would
have proven the detector works on real Telegram-shaped traffic — not that it
survives an adversary choosing their own timing. A *non*-detection is the
stronger signal, because it fails on the easy case: fixed interval, known
destination, four hours, perfect labels.

## Fix order

1. **IPv6 in the extractor.** Biggest single gap; unblocks every detector and
   is a prerequisite for re-measuring anything. Until then, set the capture
   filter explicitly and say IPv4-only in the docs.
2. **Re-run Parts 2–4** once IPv6 lands. Every number moves.
3. **Then** revisit the C2 gates (`cv < 0.05` is too tight for real jitter; the
   `prob > 0.90` gate overrides the configured 0.80 — Part 3 §C2).
4. **Exfiltration precision** — 113 alerts in 4 hours, and 5/5 on the malware
   captures were benign infrastructure domains.

## Reproducing

```bash
python scripts/beacon_harness.py --interval 60 --duration 4h
# ... capture in parallel, then:
python scripts/verify_beacon_detection.py \
    --pcap "D:/capture/ns_*.pcap" --truth beacon_truth.jsonl
```

The verifier reports in stages — flows reached, session built, model verdict,
which gate rejected it — so a negative result still says where it stopped.
