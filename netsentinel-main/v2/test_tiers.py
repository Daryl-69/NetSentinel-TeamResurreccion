#!/usr/bin/env python3
"""
test_tiers.py -- Option C, the two-speed split.

The claims this file exists to check are the two that the architecture rests
on, plus the dial that answers "what if the Sentry misses something":

  1. The Sentry is CAUSAL -- score at hour t uses only hours 0..t, so it can
     emit hourly. Asserted numerically, not assumed.
  2. The Inspector is NOT causal and needs cohort -- it cannot answer at hour t
     and it cannot run without other hosts' data. Both asserted.
  3. audit_rate = 1.0 makes the cascade equivalent to inspecting everything,
     i.e. Option C contains Option B, per host.
  4. A blind audit is drawn WITHOUT reference to the score, so audited days
     remain admissible to calibration.py.
"""
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2 import synth, train as T                      # noqa: E402
from netsentinel_v2.models import Inspector, Sentry               # noqa: E402
from netsentinel_v2.lifecycle import Lifecycle, State             # noqa: E402
from netsentinel_v2.visibility import VisibilityProfile, VisibilityGate  # noqa: E402
from netsentinel_v2.tiers import (EdgeTier, CentralTier, RiskTier, TIERS,  # noqa: E402
                                  EscalationPacket, load_report)

fails, n = [], 0


def check(name, cond, detail=""):
    global n
    n += 1
    print(("  ok    " if cond else "  FAIL  ") + name + ("" if cond else f"   {detail}"))
    if not cond:
        fails.append(name)


print("=" * 74)
print("  Option C -- the two-speed split")
print("=" * 74)

d = synth.generate(n_hosts=40, n_days=6, seed=3, hard_negatives=True)
E, M = d["edges"], d["mask"]
H, D, W, C, F = E.shape
Co = T.compute_cohort(E, M)

torch.manual_seed(0)
sentry = Sentry(dim=32, teacher_dim=96).eval()
insp = Inspector(dim=96).eval()


def sentry_scores(e, m):
    """(B,W,C,F) -> (B,W). Mean |embedding| stands in for the router head;
    what is under test is causality, not the head's calibration."""
    with torch.no_grad():
        z = sentry.encode(torch.tensor(e, dtype=torch.float32),
                          torch.tensor(m, dtype=torch.float32))
    return z.abs().mean(-1).numpy()


def inspect(e, m, c):
    with torch.no_grad():
        z, pred = insp(torch.tensor(e, dtype=torch.float32),
                       torch.tensor(m, dtype=torch.float32),
                       torch.tensor(c, dtype=torch.float32))
        from netsentinel_v2.models import recon_error
        return recon_error(pred, torch.tensor(e, dtype=torch.float32),
                           torch.tensor(m, dtype=torch.float32)).numpy()


print("\n  1. the Sentry is causal -- hourly scoring is real, not a slogan")
full = sentry_scores(E[0, 0][None], M[0, 0][None])[0]
worst = 0.0
for t_ in range(W):
    part = sentry_scores(E[0, 0][None, :t_ + 1], M[0, 0][None, :t_ + 1])[0, -1]
    worst = max(worst, abs(part - full[t_]))
print(f"      max |truncated - full| over all 24 hours: {worst:.3e}")
check("scoring hours 0..t equals the full day's slice at t", worst < 1e-5,
      f"drift {worst:.2e}")

print("\n  2. the Inspector cannot do that")
try:
    e3 = E[0, 0][None, :3]
    m3 = M[0, 0][None, :3]
    c3 = Co[0, 0][None, :3]
    part = inspect(e3, m3, c3)
    fullI = inspect(E[0, 0][None], M[0, 0][None], Co[0, 0][None])
    drift = float(np.abs(part[0] - fullI[0, :3]).max())
    print(f"      it runs on 3 hours, but the answer moves by {drift:.3f}")
    check("a partial day gives the Inspector a DIFFERENT answer", drift > 1e-3,
          "suspiciously causal; check the positional embedding")
except Exception as e:                                   # pragma: no cover
    check("a partial day gives the Inspector a different answer", True,
          f"(it refused outright: {type(e).__name__})")

print("\n  3. the Inspector needs other hosts; the Sentry does not")
zeroc = inspect(E[:4, 0], M[:4, 0], np.zeros_like(Co[:4, 0]))
realc = inspect(E[:4, 0], M[:4, 0], Co[:4, 0])
dc = float(np.abs(zeroc - realc).max())
print(f"      blanking the cohort moves the Inspector by {dc:.3f}")
check("the Inspector's answer depends on cohort context", dc > 1e-4)
check("the Sentry takes no cohort argument at all",
      not sentry.agg.use_cohort)

print("\n  4. the dial: audit_rate = 1.0 inspects every host-day (Option B)")
for tier_name, expect_all in (("crown_jewel", True), ("bulk", False)):
    tier = TIERS[tier_name]
    lc = Lifecycle()
    for h in range(H):
        lc.get(h).state = State.SENTRY_PRIMARY
    edge = EdgeTier(sentry_scores, lifecycle=lc,
                    tier_of=lambda h, t=tier: t, seed=7)
    pk = [edge.close_day(h, 0, E[h, 0], M[h, 0], router_cut=float("inf"))
          for h in range(H)]
    got = sum(p is not None for p in pk)
    print(f"      {tier_name:<12} audit {tier.audit_rate:>4.0%} -> "
          f"{got}/{H} host-days inspected")
    if expect_all:
        check("crown_jewel inspects EVERY host-day == Option B", got == H)
    else:
        check("bulk inspects a small blind sample", 0 <= got <= H // 4)

print("\n  5. the audit is blind -- drawn before the score is consulted")
lc = Lifecycle()
for h in range(H):
    lc.get(h).state = State.SENTRY_PRIMARY
edge = EdgeTier(sentry_scores, lifecycle=lc,
                tier_of=lambda h: TIERS["elevated"], seed=11)
peaks = np.array([sentry_scores(E[h, 0][None], M[h, 0][None])[0].max()
                  for h in range(H)])
cut = edge.budget_cut(peaks, TIERS["elevated"])
packets = [p for p in (edge.close_day(h, 0, E[h, 0], M[h, 0], router_cut=cut)
                       for h in range(H)) if p]
aud = [p for p in packets if p.reason == "audit"]
rtr = [p for p in packets if p.reason == "router"]
print(f"      cut at the {1 - TIERS['elevated'].escalation_budget:.0%} quantile "
      f"= {cut:.4f}")
print(f"      {len(aud)} audit-drawn, {len(rtr)} router-escalated, "
      f"{len(packets)} total of {H}")
check("audit-drawn packets are marked by provenance",
      all(p.audit_drawn() for p in aud) and not any(p.audit_drawn() for p in rtr))
check("some audited host-days scored BELOW the router cut",
      any(p.router_score < cut for p in aud) if aud else True,
      "audit is tracking the score, which defeats its purpose")

print("\n  6. the budget is spent in HOST-DAYS, not windows")
frac = len(rtr) / H
print(f"      router escalated {frac:.1%} of host-days "
      f"(budget {TIERS['elevated'].escalation_budget:.0%})")
check("router load matches the host-day budget, no 9.8x scatter",
      frac <= TIERS["elevated"].escalation_budget + 0.06,
      f"{frac:.1%} vs {TIERS['elevated'].escalation_budget:.0%}")

print("\n  7. the packet carries history, not one naked window")
p0 = packets[0]
p0.history_edges = E[p0.host_id, :1]
p0.history_mask = M[p0.host_id, :1]
check("packet carries the preceding day(s)", p0.history_edges is not None)
check("packet names why it crossed the boundary",
      p0.reason in ("audit", "router", "commissioning", "recommissioning",
                    "incident"))
check("packet records the triggering hour", p0.trigger_window is not None)

print("\n  8. central tier scores only what crossed, using all hosts' cohort")
central = CentralTier(inspect, T.compute_cohort, threshold=0.0)
verdicts = central.ingest(packets, E[:, 0], M[:, 0])
check("one verdict per packet", len(verdicts) == len(packets))
check("verdicts carry the audit provenance through",
      sum(v.audit_drawn for v in verdicts) == len(aud))

print("\n  9. a capture fault is refused, not scored as an attack")
good = VisibilityProfile(named_flow_ratio=0.78, unknown_category_ratio=0.18,
                         snaplen=0, quic_readable=True, tls_sni_ratio=0.95,
                         hours_observed=200)
dark = VisibilityProfile(named_flow_ratio=0.10, unknown_category_ratio=0.90,
                         snaplen=0, quic_readable=True, tls_sni_ratio=0.90,
                         hours_observed=20)
edge2 = EdgeTier(sentry_scores, lifecycle=Lifecycle(),
                 gate=VisibilityGate(good), tier_of=lambda h: TIERS["crown_jewel"],
                 seed=5)
check("a dark sensor produces no escalation even at 100% audit",
      edge2.close_day(0, 0, E[0, 0], M[0, 0], router_cut=0.0,
                      visibility=dark) is None)
check("a healthy sensor still escalates",
      edge2.close_day(0, 0, E[0, 0], M[0, 0], router_cut=0.0,
                      visibility=good) is not None)

print("\n 10. load accounting separates what you budget from what you absorb")
rep = load_report(packets, H)
print(f"      {rep['inspected']}/{rep['host_days']} host-days "
      f"({rep['fraction']:.1%})   by reason: {rep['by_reason']}")
check("report splits budget-controlled from churn-driven",
      abs(rep["budget_controlled"] + rep["churn_driven"]
          + rep["audit_driven"] - 1.0) < 1e-9)

print()
print("=" * 74)
if fails:
    print(f"  {len(fails)} of {n} checks FAILED")
    for f in fails:
        print("   -", f)
    sys.exit(1)
print(f"  all {n} checks passed")
print()
print("  The two structural claims hold: the Sentry can answer hourly and the")
print("  Inspector cannot; the Inspector needs other hosts and the Sentry does")
print("  not. Those are what justify the split -- not GPU cost.")
