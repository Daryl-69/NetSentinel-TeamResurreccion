"""
netsentinel_v2.lifecycle -- P3. Per-host commissioning, on evidence not on a
calendar.

The design this replaces
------------------------
"Run the Inspector on every host for 14 days, then hand the host to the
Sentry." Two weeks is a reasonable planning figure and a bad promotion rule:

  * a developer laptop generates plenty of evidence in two weeks
  * a server whose backup runs monthly shows you none of its interesting
    behaviour in that window
  * a mostly-offline machine gives you almost nothing at all

Promote on whether you have actually SEEN enough, not on whether the clock ran
out. And run the Sentry from day one even while the Inspector is still
commissioning, because that is the only period where you get free labels for
"would the teacher have flagged this" -- which is exactly what the router is
trained on.

States
------
  COMMISSIONING    Sentry runs; the Inspector covers this host heavily
  SENTRY_PRIMARY   the Sentry routes; the Inspector sees escalations + audits
  ESCALATED        the Inspector is looking at this host's recent history now
  INCIDENT_HOLD    elevated monitoring; baseline adaptation FROZEN
  RECOMMISSIONING  a legitimate change invalidated the baseline; refit it

`INCIDENT_HOLD` is deliberately not terminal. "Suspicious hosts stay on the
Inspector forever" sounds safe and is not survivable: false positives,
legitimate change and deliberately noisy traffic would consume the whole
budget within weeks. A confirmed incident stays under elevated monitoring
until reviewed and explicitly released.

Visibility is tracked SEPARATELY from state, because a host can be in incident
hold and have degraded capture at the same time, and those need different
people to do different things.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class State(str, Enum):
    COMMISSIONING = "COMMISSIONING"
    SENTRY_PRIMARY = "SENTRY_PRIMARY"
    ESCALATED = "ESCALATED"
    INCIDENT_HOLD = "INCIDENT_HOLD"
    RECOMMISSIONING = "RECOMMISSIONING"


@dataclass
class PromotionPolicy:
    """Every threshold here is a starting setting, not a validated constant.
    Say that out loud rather than presenting them as tuned."""
    min_live_windows: int = 240        # ~10 active days' worth of hours
    min_distinct_days: int = 10
    require_weekend: bool = True       # a weekly cycle must have been seen
    min_reference_samples: int = 200   # what calibration.py needs to fit
    min_named_flow_ratio: float = 0.50
    max_score_drift: float = 0.35      # |median shift| in robust sigma
    max_teacher_disagreement: float = 0.20


@dataclass
class HostRecord:
    host_id: int
    state: State = State.COMMISSIONING
    live_windows: int = 0
    distinct_days: int = 0
    saw_weekend: bool = False
    reference_samples: int = 0
    named_flow_ratio: float = 0.0
    score_drift: float = 0.0
    teacher_disagreement: float = 1.0
    incident_open: bool = False
    visibility_ok: bool = True         # tracked separately from state
    history: list = field(default_factory=list)

    def log(self, msg: str):
        self.history.append(msg)


class Lifecycle:
    def __init__(self, policy: Optional[PromotionPolicy] = None):
        self.policy = policy or PromotionPolicy()
        self.hosts: dict[int, HostRecord] = {}

    def get(self, host_id: int) -> HostRecord:
        if host_id not in self.hosts:
            self.hosts[host_id] = HostRecord(host_id=host_id)
        return self.hosts[host_id]

    # ------------------------------------------------------------ evidence
    def promotion_blockers(self, r: HostRecord) -> list[str]:
        """Everything standing between this host and SENTRY_PRIMARY."""
        p, out = self.policy, []
        if r.live_windows < p.min_live_windows:
            out.append(f"live windows {r.live_windows} < {p.min_live_windows}")
        if r.distinct_days < p.min_distinct_days:
            out.append(f"distinct days {r.distinct_days} < {p.min_distinct_days}")
        if p.require_weekend and not r.saw_weekend:
            out.append("no weekend observed -- the weekly cycle is unseen")
        if r.reference_samples < p.min_reference_samples:
            out.append(f"reference samples {r.reference_samples} < "
                       f"{p.min_reference_samples} (calibration cannot fit)")
        if r.named_flow_ratio < p.min_named_flow_ratio:
            out.append(f"named-flow ratio {r.named_flow_ratio:.2f} < "
                       f"{p.min_named_flow_ratio:.2f}")
        if abs(r.score_drift) > p.max_score_drift:
            out.append(f"score distribution still moving "
                       f"({r.score_drift:+.2f} sigma)")
        if r.teacher_disagreement > p.max_teacher_disagreement:
            out.append(f"Sentry disagrees with the Inspector "
                       f"{r.teacher_disagreement:.2f} > "
                       f"{p.max_teacher_disagreement:.2f}")
        if r.incident_open:
            out.append("an incident is open")
        if not r.visibility_ok:
            out.append("visibility is degraded (see visibility.py)")
        return out

    # ----------------------------------------------------------- the moves
    def step(self, host_id: int) -> State:
        """Advance one host. Returns its state after the move."""
        r = self.get(host_id)

        if r.incident_open and r.state is not State.INCIDENT_HOLD:
            r.state = State.INCIDENT_HOLD
            r.log("incident opened -> INCIDENT_HOLD, adaptation frozen")
            return r.state

        if r.state is State.COMMISSIONING:
            blockers = self.promotion_blockers(r)
            if not blockers:
                r.state = State.SENTRY_PRIMARY
                r.log("promoted on evidence -> SENTRY_PRIMARY")
            else:
                r.log(f"still commissioning: {len(blockers)} blocker(s)")

        elif r.state is State.RECOMMISSIONING:
            blockers = self.promotion_blockers(r)
            if not blockers:
                r.state = State.SENTRY_PRIMARY
                r.log("recommissioned -> SENTRY_PRIMARY")

        elif r.state is State.ESCALATED:
            r.state = State.SENTRY_PRIMARY
            r.log("escalation resolved benign -> SENTRY_PRIMARY")

        return r.state

    def escalate(self, host_id: int, reason: str) -> State:
        r = self.get(host_id)
        if r.state is State.INCIDENT_HOLD:
            r.log(f"escalation while on hold: {reason}")
            return r.state
        r.state = State.ESCALATED
        r.log(f"escalated: {reason}")
        return r.state

    def open_incident(self, host_id: int, reason: str) -> State:
        r = self.get(host_id)
        r.incident_open = True
        r.state = State.INCIDENT_HOLD
        r.log(f"INCIDENT: {reason} -- baseline adaptation frozen")
        return r.state

    def release_incident(self, host_id: int, note: str,
                         recommission: bool = True) -> State:
        """Explicit human release. Never automatic -- that is the whole point
        of the hold."""
        r = self.get(host_id)
        r.incident_open = False
        if recommission:
            r.state = State.RECOMMISSIONING
            r.reference_samples = 0
            r.score_drift = 0.0
            r.log(f"incident released ({note}) -> RECOMMISSIONING")
        else:
            r.state = State.SENTRY_PRIMARY
            r.log(f"incident released ({note}) -> SENTRY_PRIMARY")
        return r.state

    def mark_baseline_stale(self, host_id: int, reason: str) -> State:
        """Called when visibility.py returns 'recommission' -- e.g. the
        11 Sep snaplen change, which made the sensor BETTER and thereby
        invalidated every baseline fitted before it."""
        r = self.get(host_id)
        r.state = State.RECOMMISSIONING
        r.reference_samples = 0
        r.log(f"baseline stale: {reason} -> RECOMMISSIONING")
        return r.state

    # -------------------------------------------------------------- budget
    def inspector_load(self) -> dict:
        """Who is costing the Inspector anything right now."""
        n = {s: 0 for s in State}
        for r in self.hosts.values():
            n[r.state] += 1
        heavy = n[State.COMMISSIONING] + n[State.RECOMMISSIONING] \
            + n[State.ESCALATED] + n[State.INCIDENT_HOLD]
        return {"by_state": {s.value: c for s, c in n.items()},
                "hosts_costing_inspector": heavy,
                "hosts_total": len(self.hosts),
                "fraction": heavy / max(len(self.hosts), 1)}
