#!/usr/bin/env python3
"""
test_lifecycle.py -- P2 + P3. The visibility gate and the per-host state
machine, exercised on the cases that actually happened to us.

The scenarios are not invented. Each one is something this project has already
walked into:
  1. the 5-10 Sep snaplen-160 capture, which could name nothing
  2. the 11 Sep snaplen-0 fix, which improved the sensor and thereby
     invalidated every baseline fitted before it
  3. a quiet server that a 14-day timer would have promoted on no evidence
  4. an incident, and the fact that a hold must be releasable
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2.visibility import VisibilityProfile, VisibilityGate  # noqa: E402
from netsentinel_v2.lifecycle import Lifecycle, State, PromotionPolicy   # noqa: E402

fails, n = [], 0


def check(name, cond, detail=""):
    global n
    n += 1
    print(("  ok    " if cond else "  FAIL  ") + name + ("" if cond else f"   {detail}"))
    if not cond:
        fails.append(name)


print("=" * 72)
print("  P2 -- the visibility gate")
print("=" * 72)

# what we were fitted under, post-fix
good = VisibilityProfile(named_flow_ratio=0.78, unknown_category_ratio=0.18,
                         snaplen=0, quic_readable=True, tls_sni_ratio=0.95,
                         hours_observed=200, label="commissioning (snaplen 0)")
gate = VisibilityGate(good, tolerance=0.15)

print("\n  1. conditions unchanged")
r = gate.check(good)
print(gate.explain(good))
check("scores normally when visibility matches", r["action"] == "score")

print("\n  2. the 5-10 Sep capture: snaplen 160, nothing nameable")
old = VisibilityProfile(named_flow_ratio=0.26, unknown_category_ratio=0.74,
                        snaplen=160, quic_readable=False, tls_sni_ratio=0.0,
                        hours_observed=55, label="snaplen 160")
r = gate.check(old)
print(gate.explain(old))
check("a regime change is caught before anything is scored",
      r["action"] == "recommission")
check("it is a DATA QUALITY finding, not a security one",
      r["severity"] == "data_quality")

print("\n  3. the 11 Sep fix: the sensor got BETTER, baseline is now stale")
stale_base = VisibilityProfile(named_flow_ratio=0.26, unknown_category_ratio=0.74,
                               snaplen=512, quic_readable=False,
                               tls_sni_ratio=0.88, hours_observed=15,
                               label="commissioning (snaplen 512)")
g2 = VisibilityGate(stale_base, tolerance=0.15)
r = g2.check(good)
print(g2.explain(good))
check("an IMPROVEMENT also invalidates the baseline",
      r["action"] == "recommission")
check("and it does not silently score across the change", r["ok"] is False)

print("\n  4. mid-run degradation: QUIC stops being readable")
degraded = VisibilityProfile(named_flow_ratio=0.40, unknown_category_ratio=0.60,
                             snaplen=0, quic_readable=False,
                             tls_sni_ratio=0.90, hours_observed=20)
r = gate.check(degraded)
print(gate.explain(degraded))
check("refuses to score when 61% of traffic goes dark",
      r["action"] == "refuse")

print("\n  5. mild degradation, still usable")
mild = VisibilityProfile(named_flow_ratio=0.70, unknown_category_ratio=0.26,
                         snaplen=0, quic_readable=True, tls_sni_ratio=0.80,
                         hours_observed=20)
r = gate.check(mild)
print(gate.explain(mild))
check("a mild fall warns but still scores",
      r["action"] in ("score", "warn_and_score"))

print()
print("=" * 72)
print("  P3 -- promotion on evidence, not on a calendar")
print("=" * 72)

lc = Lifecycle()

print("\n  1. a busy laptop, two weeks in -- has the evidence")
r = lc.get(1)
r.live_windows, r.distinct_days, r.saw_weekend = 300, 14, True
r.reference_samples, r.named_flow_ratio = 260, 0.78
r.score_drift, r.teacher_disagreement = 0.10, 0.08
check("promoted", lc.step(1) is State.SENTRY_PRIMARY)

print("\n  2. a quiet server, ALSO two weeks in -- a timer would promote it")
r = lc.get(2)
r.live_windows, r.distinct_days, r.saw_weekend = 60, 14, True
r.reference_samples, r.named_flow_ratio = 55, 0.80
r.score_drift, r.teacher_disagreement = 0.10, 0.09
st = lc.step(2)
blockers = lc.promotion_blockers(lc.get(2))
for b in blockers:
    print(f"      blocked: {b}")
check("NOT promoted -- 14 days is not evidence", st is State.COMMISSIONING)
check("and it says exactly why", len(blockers) >= 2)

print("\n  3. a host that has never seen a weekend")
r = lc.get(3)
r.live_windows, r.distinct_days, r.saw_weekend = 300, 12, False
r.reference_samples, r.named_flow_ratio = 260, 0.78
r.score_drift, r.teacher_disagreement = 0.10, 0.08
check("held back until the weekly cycle is observed",
      lc.step(3) is State.COMMISSIONING)
check("the reason names the weekly cycle",
      any("weekend" in b for b in lc.promotion_blockers(lc.get(3))))

print("\n  4. degraded visibility blocks promotion independently of state")
r = lc.get(4)
r.live_windows, r.distinct_days, r.saw_weekend = 300, 14, True
r.reference_samples, r.named_flow_ratio = 260, 0.78
r.score_drift, r.teacher_disagreement = 0.10, 0.08
r.visibility_ok = False
check("not promoted while the sensor is degraded",
      lc.step(4) is State.COMMISSIONING)

print("\n  5. incident: hold, then an EXPLICIT release")
lc.get(5).state = State.SENTRY_PRIMARY
check("an incident freezes the host",
      lc.open_incident(5, "confirmed chain") is State.INCIDENT_HOLD)
check("stepping does not quietly release it", lc.step(5) is State.INCIDENT_HOLD)
check("release is explicit and sends it to RECOMMISSIONING",
      lc.release_incident(5, "reviewed by analyst") is State.RECOMMISSIONING)
check("recommissioning resets the reference set",
      lc.get(5).reference_samples == 0)

print("\n  6. the 11 Sep snaplen change marks every baseline stale")
lc.get(6).state = State.SENTRY_PRIMARY
check("gate -> lifecycle: baseline stale",
      lc.mark_baseline_stale(6, "snaplen 512 -> 0") is State.RECOMMISSIONING)

print("\n  7. who is costing the Inspector anything")
load = lc.inspector_load()
for s, c in load["by_state"].items():
    if c:
        print(f"      {s:<18} {c}")
print(f"      -> {load['hosts_costing_inspector']} of {load['hosts_total']} hosts "
      f"({load['fraction']*100:.0f}%) are on the expensive path")
check("load accounting counts every non-SENTRY_PRIMARY state",
      load["hosts_costing_inspector"] == sum(
          c for s, c in load["by_state"].items() if s != "SENTRY_PRIMARY"))

print()
print("=" * 72)
if fails:
    print(f"  {len(fails)} of {n} checks FAILED")
    for f in fails:
        print("   -", f)
    sys.exit(1)
print(f"  all {n} checks passed")
print()
print("  Note the thresholds in PromotionPolicy are starting settings, not")
print("  tuned constants. Say that when presenting them.")
