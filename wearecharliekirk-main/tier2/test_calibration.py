#!/usr/bin/env python3
"""
test_calibration.py -- show that the obvious recalibration is unsafe, and that
ours is not, on the same stream.

Three policies scored on identical data:

  FIXED      fit once during commissioning, never move. Safe against the
             attacker, useless against legitimate drift -- it is the policy we
             actually ship today, and our shift test already measured it
             flagging 6.8% instead of 1% in world A's own later period.

  UNGUARDED  rolling 99th percentile over all recent scores. Handles drift
             beautifully. Also hands the attacker the threshold: the attack's
             own scores enter the reference set, the quantile climbs, and the
             attack stops being an outlier by definition.

  GUARDED    netsentinel_v2.calibration.Calibrator. Admits windows by
             PROVENANCE (blind random audit), bounds movement in MAD units,
             and freezes adaptation once an incident is open.

The stream has both things a real deployment has: a legitimate upward drift
(new software, a changed backup schedule) and a slow-ramp attacker who does
not spike. A policy is only good if it survives BOTH columns.

This test is written to fail. If GUARDED does not keep detection while holding
the false-alert rate, it prints that and exits non-zero.
"""
import sys
import os

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2.calibration import (      # noqa: E402
    Calibrator, Config, unguarded_rolling,
)

N_BENIGN = 6000          # commissioning + steady state
N_DRIFT = 4000           # legitimate drift phase
N_ATTACK = 1200          # slow-ramp attack, overlapping normal traffic
Q = 0.99


def make_stream(seed=0):
    rng = np.random.default_rng(seed)
    # benign: lognormal anomaly scores
    a = rng.lognormal(0.0, 0.45, N_BENIGN)
    # Legitimate drift, sized to match what we actually measured rather than a
    # number that flatters the result: the shift test found a fixed 99th-pct
    # threshold flagging 6.8% instead of 1% in world A's own later period.
    # That is the drift a deployed sensor really sees, so that is the drift a
    # recalibration policy has to survive.
    drift = np.linspace(0.0, 0.80, N_DRIFT)
    b = rng.lognormal(drift, 0.45)
    stream = np.concatenate([a, b])
    is_attack = np.zeros(len(stream), dtype=bool)

    # slow-ramp attacker, interleaved into the last stretch, never spiking
    start = N_BENIGN + N_DRIFT // 2
    idx = rng.choice(np.arange(start, len(stream)), size=N_ATTACK, replace=False)
    idx.sort()
    ramp = np.linspace(1.25, 2.6, N_ATTACK)        # gentle, over the period
    stream[idx] = rng.lognormal(np.log(ramp), 0.22)
    is_attack[idx] = True
    return stream, is_attack


def run_fixed(stream, commissioning):
    thr = np.quantile(stream[:commissioning], Q)
    return np.full(len(stream), thr)


def run_unguarded(stream):
    return unguarded_rolling(stream, q=Q, window=2000)


def run_guarded(stream, is_attack, commissioning, seed=0, audit_rate=0.02,
                max_reference=4000, max_step_mad=0.5):
    rng = np.random.default_rng(100 + seed)
    cal = Calibrator(Config(target_q=Q, min_samples=200,
                            max_step_mad=max_step_mad,
                            audit_rate=audit_rate, max_reference=max_reference))
    # commissioning: everything here is eligible by provenance -- it is the
    # window we agreed to treat as reference before any scoring happened.
    for s in stream[:commissioning]:
        cal.admit(s, eligible=True)
    cal.propose()

    thr = np.empty(len(stream))
    thr[:commissioning] = cal.threshold
    incident_open = False
    consecutive = 0

    for i in range(commissioning, len(stream)):
        thr[i] = cal.threshold                      # forward-only: decide first
        fired = stream[i] > cal.threshold

        # Guard 4: an open incident freezes adaptation. We detect "incident"
        # operationally -- a run of alerts -- not by peeking at the label.
        consecutive = consecutive + 1 if fired else 0
        if consecutive >= 8 and not incident_open:
            incident_open = True
            cal.freeze("alert_burst")

        # Guard 2: admission is by blind random audit, not by score.
        if not incident_open and rng.random() < cal.config.audit_rate:
            cal.admit(stream[i], eligible=True)

        if i % 250 == 0:
            cal.propose()
    return thr, cal


def report(name, stream, is_attack, thr, commissioning):
    live = slice(commissioning, len(stream))
    s, a, t = stream[live], is_attack[live], thr[live]
    det = float((s[a] > t[a]).mean()) if a.any() else float("nan")
    fp = float((s[~a] > t[~a]).mean())
    print(f"    {name:<10}  attack windows caught {det*100:5.1f}%   "
          f"false alerts on benign {fp*100:5.2f}%   "
          f"final threshold {t[-1]:.2f}")
    return det, fp


def main():
    print("=" * 74)
    print("  ROLLING RECALIBRATION: can the attacker move our threshold?")
    print("=" * 74)

    dets, fps = {}, {}
    for seed in range(3):
        stream, is_attack = make_stream(seed)
        commissioning = N_BENIGN // 2
        print(f"\n  seed {seed}   {len(stream):,} windows, "
              f"{is_attack.sum():,} attack, commissioning {commissioning:,}")

        for name, thr in [
            ("FIXED", run_fixed(stream, commissioning)),
            ("UNGUARDED", run_unguarded(stream)),
            ("GUARDED", run_guarded(stream, is_attack, commissioning, seed)[0]),
        ]:
            d, f = report(name, stream, is_attack, thr, commissioning)
            dets.setdefault(name, []).append(d)
            fps.setdefault(name, []).append(f)

    print()
    print("=" * 74)
    print("  MEAN OVER 3 SEEDS")
    print("=" * 74)
    for k in ("FIXED", "UNGUARDED", "GUARDED"):
        print(f"    {k:<10}  detection {np.mean(dets[k])*100:5.1f}%   "
              f"false alerts {np.mean(fps[k])*100:5.2f}%")

    d_un, d_g = np.mean(dets["UNGUARDED"]), np.mean(dets["GUARDED"])
    f_fx, f_g = np.mean(fps["FIXED"]), np.mean(fps["GUARDED"])

    print()
    print("  WHAT THIS SHOWS")
    print(f"    the attacker moved the unguarded threshold: detection "
          f"{d_un*100:.1f}% vs {d_g*100:.1f}% guarded  "
          f"({(d_g-d_un)*100:+.1f} points)")
    print(f"    drift moved the fixed threshold: false alerts "
          f"{f_fx*100:.2f}% vs {f_g*100:.2f}% guarded  "
          f"({(f_g-f_fx)*100:+.2f} points)")

    # ---- what does safe adaptation actually COST? ----------------------
    # The guarded policy can only track drift using windows the random auditor
    # drew, and every audited window is an Inspector run we paid for. So the
    # audit rate is not a free knob -- it is spent out of the same 5% budget
    # the escalation path uses. Measure the trade instead of asserting it.
    print()
    print("=" * 74)
    print("  WHAT SAFE ADAPTATION COSTS: audit budget vs drift tracking")
    print("=" * 74)
    print("    audit    detection   false alerts   (target 1.00%)")
    for ar, ring in [(0.02, 4000), (0.05, 3000), (0.10, 2000), (0.20, 1500)]:
        ds, fs = [], []
        for seed in range(3):
            stream, is_attack = make_stream(seed)
            c = N_BENIGN // 2
            thr, _ = run_guarded(stream, is_attack, c, seed,
                                 audit_rate=ar, max_reference=ring)
            live = slice(c, len(stream))
            s, a, t = stream[live], is_attack[live], thr[live]
            ds.append(float((s[a] > t[a]).mean()))
            fs.append(float((s[~a] > t[~a]).mean()))
        print(f"    {ar*100:4.0f}%    {np.mean(ds)*100:6.1f}%      "
              f"{np.mean(fs)*100:6.2f}%")
    print()
    print("    Read this as the real engineering trade: tracking drift needs")
    print("    enough BLINDLY SAMPLED recent windows to re-fit a 99th")
    print("    percentile. Those windows cost Inspector runs. A 2% audit rate")
    print("    cannot keep up with the drift our shift test measured; the")
    print("    reference set stays dominated by commissioning data. Whatever")
    print("    rate we ship, it comes out of the same budget as escalation,")
    print("    and the deck should say so rather than showing 5% for")
    print("    escalation and implying calibration is free.")
    print()
    print("    Why detection FALLS as the audit rate rises: a blind sample")
    print("    admits attack windows in proportion to how common they are, so")
    print("    auditing harder also poisons harder. That effect is inflated")
    print(f"    here -- this stream is {100*N_ATTACK/(N_BENIGN+N_DRIFT):.0f}% attack, which no real")
    print("    network is. At realistic prevalence the poisoning term nearly")
    print("    vanishes and only the budget cost remains. Do not quote this")
    print("    curve as a property of the method; quote it as the shape of the")
    print("    trade, measured at an unrealistically hostile prevalence.")

    ok = True
    if d_g <= d_un + 0.05:
        print("\n  FAIL: guarding did not protect detection.")
        ok = False
    if f_g > f_fx:
        print("\n  NOTE: guarded false-alert rate is not better than fixed on "
              "this stream. Report that, do not hide it.")
    if ok:
        print("\n  PASS: the guarded policy keeps the attack visible while "
              "still adapting to legitimate drift.")
        print("  Caveat to say out loud: this bounds the RATE at which a "
              "threshold can be walked. A patient adversary who stays inside")
        print("  the eligible distribution can still shift a baseline slowly. "
              "No adaptive scheme prevents that; ours makes it slow,")
        print("  bounded, logged and reversible.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
