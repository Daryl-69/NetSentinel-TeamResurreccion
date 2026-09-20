"""
netsentinel_v2.tiers -- Option C. The two-speed split, implemented.

    EDGE (one site, local traffic only)      |   CENTRAL (all hosts converge)
    ----------------------------------------+--------------------------------
    Sentry, 14,992 params, CPU               |   Inspector, 205,546 params, GPU
    scores EVERY HOUR                        |   consumes a WHOLE host-day
    no hop-2 cohort -> needs no other host   |   needs hop-2 cohort
    decides what crosses the boundary        |   returns the verdict

WHY THE SPLIT IS STRUCTURAL AND NOT A PREFERENCE
------------------------------------------------
Two properties of the models, not of the hardware:

1. The Sentry is CAUSAL. Its aggregator is per-window and its GRU is
   unidirectional, so the score at hour t depends only on hours 0..t. It can
   emit after every hour. `test_tiers.py` proves this by asserting that
   scoring a truncated day equals the corresponding slice of scoring the whole
   day, to float tolerance.

2. The Inspector is NOT causal. A Transformer with a 24-slot positional
   embedding attends across the whole sequence, so hour 3's representation
   depends on hour 20. It cannot emit before the day closes. No amount of
   compute changes that.

And one property of the inputs: the Inspector's hop-2 cohort is the mean of
OTHER hosts' edges in the same (day, window, category). That does not exist at
a single diode-separated site. The Sentry never asks for it.

THE AUDIT RATE IS THE DIAL, AND IT MATTERS MORE THAN IT LOOKS
-------------------------------------------------------------
A router that misses something never escalates it, and the Inspector never
gets a chance. Measured miss rate against the teacher at a 5% budget: 3.1%
(96.9% of the teacher's flags are recovered -- lanl_novelty.json).

The blind audit is the only thing that finds the other 3.1%, so its rate sets
the worst-case detection time:

    ETTE = 1 / (audit_rate * P(detect | inspected))     -- cost_model.ette_days

    2% audit  ->  ~50 days if P=1.0
   20% audit  ->   ~5 days
  100% audit  ->  every host-day inspected

At audit_rate = 1.0 this module IS "run the Inspector on everything", with the
hourly Sentry score kept on top. So the cascade is not an alternative to full
inspection -- it CONTAINS it, and the dial is per host, which is the thing a
single global mode cannot express. A domain controller sits at 1.0; ten
thousand laptops sit at 0.02.

What actually caps the dial is analyst capacity, not compute: every audited
host-day the Inspector flags becomes an alert someone must triage. Compute is
not the constraint -- see gpu_cost.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

import numpy as np

from .lifecycle import Lifecycle, State
from .visibility import VisibilityProfile, VisibilityGate


# --------------------------------------------------------------- risk tiers

@dataclass(frozen=True)
class RiskTier:
    """Per-host coverage policy. This is the dial.

    `audit_rate` is blind: drawn without reference to any score, which is what
    makes audited windows admissible to calibration.py (provenance, not score).
    `escalation_budget` is the fraction of host-days the router may send up on
    its own judgement.
    """
    name: str
    audit_rate: float
    escalation_budget: float
    note: str = ""

    def inspector_load(self, recommission_rate: float = 1 / 30) -> float:
        """Fraction of this host's days that reach the Inspector."""
        return min(1.0, self.audit_rate + self.escalation_budget
                   + recommission_rate)


TIERS = {
    # audit_rate 1.0 == inspect every host-day == Option B, per host.
    "crown_jewel": RiskTier("crown_jewel", 1.00, 1.00,
                            "domain controllers, prod credentials. Full "
                            "inspection; the router cannot cost a detection."),
    "elevated":    RiskTier("elevated", 0.20, 0.10,
                            "admins, finance, anyone with data access. ~5-day "
                            "worst case on a router blind spot."),
    "standard":    RiskTier("standard", 0.05, 0.05,
                            "ordinary staff endpoints. ~20-day worst case."),
    "bulk":        RiskTier("bulk", 0.02, 0.05,
                            "kiosks, IoT, low-value. ~50-day worst case -- "
                            "state this explicitly, do not let it be assumed."),
}


# ------------------------------------------------------- boundary objects

@dataclass
class EscalationPacket:
    """What crosses the edge/central boundary.

    Carries HISTORY, not just the flagged window. Handing the Inspector one
    isolated hour removes the very thing the hypothesis is about -- a
    combination of categories over a day. `history_days` is the preceding
    context the Inspector re-scores against.
    """
    host_id: int
    day: int
    reason: str                     # router | audit | commissioning |
                                    # recommission | incident
    trigger_window: Optional[int]
    router_score: float
    edges: np.ndarray               # (W, C, F) the closing day
    mask: np.ndarray                # (W, C)
    history_edges: Optional[np.ndarray] = None   # (k, W, C, F)
    history_mask: Optional[np.ndarray] = None
    visibility: dict = field(default_factory=dict)
    host_state: str = ""

    def audit_drawn(self) -> bool:
        """Provenance flag calibration.py needs. Only blind-drawn windows may
        update a baseline; score-selected ones must never."""
        return self.reason == "audit"


@dataclass
class Verdict:
    host_id: int
    day: int
    reason: str
    inspector_score: float
    threshold: float
    confirmed: bool
    audit_drawn: bool


# ------------------------------------------------------------- edge tier

class EdgeTier:
    """Runs at the site. Sentry only. Never touches another host's data."""

    def __init__(self, score_hours: Callable[[np.ndarray, np.ndarray], np.ndarray],
                 lifecycle: Optional[Lifecycle] = None,
                 gate: Optional[VisibilityGate] = None,
                 tier_of: Optional[Callable[[int], RiskTier]] = None,
                 seed: int = 0):
        """`score_hours(edges, mask)` takes (B, W, C, F) / (B, W, C) and returns
        (B, W) router scores. Causality is a property of the model passed in,
        and test_tiers.py asserts it rather than assuming it."""
        self._score = score_hours
        self.lifecycle = lifecycle or Lifecycle()
        self.gate = gate
        self.tier_of = tier_of or (lambda h: TIERS["standard"])
        self.rng = np.random.default_rng(seed)
        self.hourly: dict[tuple[int, int], list[float]] = {}

    # -- hourly path: the reason the Sentry exists ------------------------
    def score_hour(self, host_id: int, day: int,
                   edges_day: np.ndarray, mask_day: np.ndarray,
                   upto_hour: int) -> float:
        """Score with hours 0..upto_hour only. Emits same-hour, not next-day.

        The Inspector cannot answer this call at all -- it needs all 24.
        """
        e = edges_day[None, :upto_hour + 1]
        m = mask_day[None, :upto_hour + 1]
        s = float(self._score(e, m)[0, -1])
        self.hourly.setdefault((host_id, day), []).append(s)
        return s

    # -- day close: decide what crosses -----------------------------------
    def close_day(self, host_id: int, day: int,
                  edges_day: np.ndarray, mask_day: np.ndarray,
                  router_cut: Optional[float] = None,
                  history_edges: Optional[np.ndarray] = None,
                  history_mask: Optional[np.ndarray] = None,
                  visibility: Optional[VisibilityProfile] = None
                  ) -> Optional[EscalationPacket]:
        """Return a packet if this host-day should reach the Inspector.

        Order matters. The blind audit is drawn FIRST and independently of the
        score, so that an audited day stays admissible to calibration even when
        the router would also have escalated it.
        """
        tier = self.tier_of(host_id)
        rec = self.lifecycle.get(host_id)
        scores = self.hourly.get((host_id, day))
        if scores is None:
            scores = list(self._score(edges_day[None], mask_day[None])[0])
        peak = float(np.max(scores)) if len(scores) else 0.0
        arg = int(np.argmax(scores)) if len(scores) else None

        vis = {}
        if visibility is not None and self.gate is not None:
            g = self.gate.check(visibility)
            vis = {"action": g["action"], "reasons": g["reasons"]}
            if g["action"] == "refuse":
                # A capture fault is not an attack. Do not spend the Inspector
                # on it, and do not let it look like a detection.
                return None
            if g["action"] == "recommission":
                self.lifecycle.mark_baseline_stale(host_id, "visibility gate")

        # 1. blind audit -- drawn without looking at the score
        if self.rng.random() < tier.audit_rate:
            reason = "audit"
        # 2. states that always cost the Inspector
        elif rec.state in (State.COMMISSIONING, State.RECOMMISSIONING):
            reason = rec.state.value.lower()
        elif rec.state is State.INCIDENT_HOLD:
            reason = "incident"
        # 3. the router's own judgement, against the budget cut
        elif router_cut is not None and peak >= router_cut:
            reason = "router"
            self.lifecycle.escalate(host_id, f"router score {peak:.3f}")
        else:
            return None

        return EscalationPacket(
            host_id=host_id, day=day, reason=reason,
            trigger_window=arg, router_score=peak,
            edges=edges_day, mask=mask_day,
            history_edges=history_edges, history_mask=history_mask,
            visibility=vis, host_state=rec.state.value)

    def budget_cut(self, all_peaks: np.ndarray, tier: RiskTier) -> float:
        """The router score above which a host-day is escalated, set so the
        budget is spent in HOST-DAYS. Budgeting in windows is what produced the
        9.8x scatter (escalate.json): 5% of windows touched 49% of host-days."""
        if len(all_peaks) == 0:
            return float("inf")
        q = 1.0 - min(1.0, tier.escalation_budget)
        return float(np.quantile(all_peaks, q))


# ---------------------------------------------------------- central tier

class CentralTier:
    """Runs where every host's tensor is available. Inspector + cohort."""

    def __init__(self, inspect: Callable[[np.ndarray, np.ndarray, np.ndarray], np.ndarray],
                 cohort_fn: Callable[[np.ndarray, np.ndarray], np.ndarray],
                 threshold: float):
        """`inspect(edges, mask, cohort)` -> (B, W) reconstruction error."""
        self._inspect = inspect
        self._cohort = cohort_fn
        self.threshold = threshold

    def ingest(self, packets: list[EscalationPacket],
               day_edges: np.ndarray, day_mask: np.ndarray) -> list[Verdict]:
        """Score the escalated host-days.

        `day_edges` / `day_mask` are (H, W, C, F) / (H, W, C) for EVERY host on
        that day -- not because we score all of them, but because the cohort
        term is defined over the others. That requirement is the whole reason
        this tier is central.
        """
        if not packets:
            return []
        co_all = self._cohort(day_edges[:, None], day_mask[:, None])[:, 0]
        idx = np.array([p.host_id for p in packets])
        e = np.stack([p.edges for p in packets])
        m = np.stack([p.mask for p in packets])
        c = co_all[idx]
        err = self._inspect(e, m, c)                       # (B, W)
        live = m.sum(-1) > 0
        peak = np.where(live.any(1),
                        np.max(np.where(live, err, -np.inf), axis=1), 0.0)
        return [Verdict(host_id=p.host_id, day=p.day, reason=p.reason,
                        inspector_score=float(peak[i]),
                        threshold=self.threshold,
                        confirmed=bool(peak[i] >= self.threshold),
                        audit_drawn=p.audit_drawn())
                for i, p in enumerate(packets)]


# ------------------------------------------------------------- accounting

def load_report(packets: list[EscalationPacket], host_days: int) -> dict:
    """What actually reached the Inspector, and why. The 'why' is the part
    that gets forgotten: escalation is budgeted, churn is absorbed."""
    by = {}
    for p in packets:
        by[p.reason] = by.get(p.reason, 0) + 1
    n = len(packets)
    return dict(host_days=host_days, inspected=n,
                fraction=n / max(host_days, 1),
                by_reason=by,
                budget_controlled=by.get("router", 0) / max(n, 1) if n else 0.0,
                churn_driven=(by.get("commissioning", 0)
                              + by.get("recommissioning", 0)
                              + by.get("incident", 0)) / max(n, 1) if n else 0.0,
                audit_driven=by.get("audit", 0) / max(n, 1) if n else 0.0)
