"""
netsentinel_v2.visibility -- P2. A capture fault must not look like an attack.

The failure this prevents
-------------------------
The Inspector is an anomaly detector over category-resolved traffic. If the
sensor stops being able to NAME flows, every destination falls into
`Unknown_External`, the feature distribution shifts hard, and the model
faithfully reports a large anomaly. It is right that something changed. It is
wrong about what.

We have already lived through both directions of this:

  * 5-10 Sep, snaplen 160: 0 of 442 TLS ClientHellos yielded a hostname. Six of
    nine categories were empty. Every external flow was Unknown_External.
  * 11 Sep, snaplen 0: QUIC Initials became readable, so roughly 61% of
    encrypted traffic moved OUT of Unknown_External and into real categories.

That second one is a **baseline reset**, and it is the dangerous one, because
it is an improvement. A baseline fitted before 11 Sep describes a world where
most traffic was unnameable. Score the post-fix corpus against it and the model
will flag the whole estate as anomalous on the day the sensor got better.

So: visibility is not a feature. It is a PRECONDITION. This module records the
conditions a baseline was fitted under, and refuses to score when the current
conditions are not the ones the model was trained for -- raising a
DATA_QUALITY warning, which is an operations ticket, not a security alert.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Optional

# Anything below this and the resolver is not really working.
ABSOLUTE_FLOOR = 0.25


@dataclass
class VisibilityProfile:
    """What the sensor could actually see over some period."""
    named_flow_ratio: float          # flows resolvable to a hostname
    unknown_category_ratio: float    # share landing in Unknown_External
    snaplen: int                     # 0 means whole packets
    quic_readable: bool              # can we decrypt QUIC Initials?
    tls_sni_ratio: float             # ClientHellos yielding a hostname
    hours_observed: int = 0
    label: str = ""

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_probe(probe: dict, label: str = "") -> "VisibilityProfile":
        """Build from a capture_probe.py JSON blob."""
        ch = max(probe.get("tls_clienthello", 0), 1)
        named = probe.get("named_destinations", 0)
        snap = 0
        snaps = probe.get("snaplens_in_files", {})
        if snaps:
            snap = min(int(k) for k in snaps)
        return VisibilityProfile(
            named_flow_ratio=probe.get("named_flow_ratio",
                                       min(1.0, named / max(ch, 1))),
            unknown_category_ratio=probe.get("unknown_category_ratio", 0.0),
            snaplen=snap,
            quic_readable=probe.get("quic_sni_ok", 0) > 0,
            tls_sni_ratio=probe.get("tls_sni_ok", 0) / ch,
            hours_observed=probe.get("hours_observed", 0),
            label=label,
        )


class VisibilityGate:
    """Compare live visibility against what the baseline was fitted under."""

    def __init__(self, commissioning: VisibilityProfile,
                 tolerance: float = 0.15):
        """`tolerance` is the RELATIVE drop in named-flow ratio we accept
        before refusing to score. 0.15 means a 15% relative fall."""
        self.commissioning = commissioning
        self.tolerance = tolerance

    def check(self, current: VisibilityProfile) -> dict:
        """Returns {'ok', 'action', 'severity', 'reasons'}.

        action is one of:
          score            conditions match, proceed
          warn_and_score   degraded but usable, attach the caveat to alerts
          refuse           do not score; raise a DATA_QUALITY ticket
          recommission     the sensor changed for the BETTER; the baseline is
                           stale and must be refitted, not worked around
        """
        c, reasons = self.commissioning, []
        action, severity = "score", "none"

        # --- the improvement case, which is the one people get wrong ------
        if current.snaplen != c.snaplen or (current.quic_readable
                                            and not c.quic_readable):
            reasons.append(
                f"capture regime changed (snaplen {c.snaplen} -> "
                f"{current.snaplen}, QUIC readable {c.quic_readable} -> "
                f"{current.quic_readable}). The baseline describes a different "
                "sensor. Refit it; do not score across the change.")
            return {"ok": False, "action": "recommission",
                    "severity": "data_quality", "reasons": reasons}

        if current.named_flow_ratio > c.named_flow_ratio * (1 + self.tolerance):
            reasons.append(
                f"naming coverage IMPROVED materially "
                f"({c.named_flow_ratio:.2f} -> {current.named_flow_ratio:.2f}). "
                "That shifts the feature distribution just as much as a "
                "degradation. Recommission.")
            return {"ok": False, "action": "recommission",
                    "severity": "data_quality", "reasons": reasons}

        # --- degradation --------------------------------------------------
        floor = c.named_flow_ratio * (1 - self.tolerance)
        if current.named_flow_ratio < ABSOLUTE_FLOOR:
            reasons.append(
                f"named-flow ratio {current.named_flow_ratio:.2f} is below the "
                f"absolute floor {ABSOLUTE_FLOOR:.2f}; the resolver is not "
                "working. Any anomaly reported now is about the sensor.")
            action, severity = "refuse", "data_quality"
        elif current.named_flow_ratio < floor:
            reasons.append(
                f"named-flow ratio {current.named_flow_ratio:.2f} is below the "
                f"commissioning floor {floor:.2f} "
                f"(fitted at {c.named_flow_ratio:.2f}).")
            action, severity = "refuse", "data_quality"

        if current.tls_sni_ratio < c.tls_sni_ratio * (1 - self.tolerance):
            reasons.append(
                f"TLS SNI recovery fell {c.tls_sni_ratio:.2f} -> "
                f"{current.tls_sni_ratio:.2f}; check snaplen and reassembly.")
            if action == "score":
                action, severity = "warn_and_score", "data_quality"

        if c.quic_readable and not current.quic_readable:
            reasons.append(
                "QUIC Initials stopped being readable; ~61% of encrypted "
                "traffic just became unnameable.")
            action, severity = "refuse", "data_quality"

        if not reasons:
            reasons.append("visibility matches commissioning conditions")
        return {"ok": action in ("score", "warn_and_score"), "action": action,
                "severity": severity, "reasons": reasons}

    def explain(self, current: VisibilityProfile) -> str:
        r = self.check(current)
        head = {"score": "SCORE", "warn_and_score": "SCORE WITH CAVEAT",
                "refuse": "REFUSE TO SCORE -- DATA QUALITY",
                "recommission": "RECOMMISSION -- BASELINE IS STALE"}[r["action"]]
        body = "\n".join(f"    - {x}" for x in r["reasons"])
        return f"  {head}\n{body}"
