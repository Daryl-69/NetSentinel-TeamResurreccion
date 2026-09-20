"""
netsentinel_v2.calibration -- rolling threshold recalibration that cannot be
talked into ignoring an attack.

The problem this solves
-----------------------
Our own shift test found the threshold does not transfer: the Inspector's
99th-percentile threshold fitted in world A flags 6.3% in world B and 6.8% in
world A's OWN later test period. It decays over time, not just across networks.
So a deployed NetSentinel needs to re-fit its threshold as it runs.

The obvious implementation is a rolling quantile over recent scores. That
implementation is dangerous, and the danger is not theoretical:

    attack begins -> scores rise -> the rolling quantile rises with them
    -> the threshold moves above the attack -> the attack reads as normal
    -> alerts return to the target rate and the system reports itself healthy

A slow attacker who ramps up over days gets this for free. Any adaptive
threshold that admits all recent traffic into its own reference set can be
walked upward by the thing it is supposed to catch.

The guards
----------
1. ELIGIBILITY. A window enters the reference set only if it is eligible:
   reviewed-benign, or matured with no incident association, or drawn by the
   random auditor. Never "admitted because its score was low" -- that selects
   for exactly the distribution that makes the threshold meaningless.

2. RANDOM AUDIT. Once the Sentry routes only unusual traffic, the Inspector
   sees a biased sample. Calibrating on what the Inspector happened to look at
   calibrates to already-suspicious traffic. So a fixed fraction of ordinary
   windows is sampled blind, and the reference set is built from those.

3. BOUNDED MOVEMENT, SCALE-AWARE. A candidate threshold may move at most
   `max_step` robust scale units (MAD) per update. "10% change" is meaningless
   when scores can sit near zero; MAD units are not.

4. FREEZE ON INCIDENT AND ON DEGRADED CAPTURE. While an incident is open, or
   while the capture is not delivering the visibility the model was fitted on,
   adaptation stops. A threshold must not drift during the event it exists to
   catch, and must not adapt to a sensor fault.

5. FORWARD ONLY. An update computed from data up to time t applies to windows
   after t. Never re-score history with a threshold derived from it.

What this does NOT do
---------------------
It does not prevent a patient adversary who stays inside the eligible
distribution from shifting the baseline slowly. Nothing that adapts can fully
prevent that. It bounds the rate, makes every change auditable and reversible,
and refuses to move at all when the evidence is thin -- which is the honest
claim, and the one we should make.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import numpy as np


@dataclass
class Config:
    target_q: float = 0.99          # quantile the threshold aims at
    min_samples: int = 200          # below this, refuse to move
    max_step_mad: float = 0.5       # max movement per update, in MAD units
    audit_rate: float = 0.02        # fraction of ordinary windows sampled blind
    max_reference: int = 5000       # ring size of the reference buffer


@dataclass
class Decision:
    threshold: float
    changed: bool
    reason: str
    n_reference: int
    candidate: Optional[float] = None


@dataclass
class Calibrator:
    """One calibrator per (model_version, feature_schema, host_group,
    visibility_regime). Mixing those is how a threshold becomes nonsense."""
    config: Config = field(default_factory=Config)
    threshold: float = float("nan")
    reference: List[float] = field(default_factory=list)
    history: List[Decision] = field(default_factory=list)
    frozen: bool = False
    freeze_reason: str = ""

    # ---------------------------------------------------------------- intake
    def admit(self, score: float, *, eligible: bool) -> bool:
        """Offer a scored window to the reference set.

        `eligible` must be decided by PROVENANCE -- reviewed benign, matured
        with no incident, or drawn by the random auditor -- and never by the
        score itself. Passing `eligible=score < threshold` reintroduces exactly
        the self-selection this class exists to prevent.
        """
        if not eligible:
            return False
        self.reference.append(float(score))
        if len(self.reference) > self.config.max_reference:
            self.reference.pop(0)
        return True

    def audit_mask(self, n: int, rng: np.random.Generator) -> np.ndarray:
        """Pick the blind random-audit sample for a batch of n windows."""
        return rng.random(n) < self.config.audit_rate

    # ------------------------------------------------------------- lifecycle
    def freeze(self, reason: str) -> None:
        self.frozen, self.freeze_reason = True, reason

    def unfreeze(self) -> None:
        self.frozen, self.freeze_reason = False, ""

    # ----------------------------------------------------------- the update
    def propose(self) -> Decision:
        c = self.config
        n = len(self.reference)

        if self.frozen:
            return self._keep(f"frozen:{self.freeze_reason}", n)
        if n < c.min_samples:
            return self._keep("insufficient_reference", n)

        ref = np.asarray(self.reference, dtype=float)
        candidate = float(np.quantile(ref, c.target_q))

        if not np.isfinite(self.threshold):
            self.threshold = candidate                 # first fit, unbounded
            d = Decision(self.threshold, True, "initial_fit", n, candidate)
            self.history.append(d)
            return d

        # robust scale of the reference distribution
        med = float(np.median(ref))
        mad = float(np.median(np.abs(ref - med))) * 1.4826 + 1e-12
        step = candidate - self.threshold
        cap = c.max_step_mad * mad
        if abs(step) > cap:
            candidate_bounded = self.threshold + np.sign(step) * cap
            reason = "accepted_bounded"
        else:
            candidate_bounded = candidate
            reason = "accepted"

        self.threshold = float(candidate_bounded)
        d = Decision(self.threshold, True, reason, n, candidate)
        self.history.append(d)
        return d

    def _keep(self, reason: str, n: int) -> Decision:
        d = Decision(self.threshold, False, reason, n)
        self.history.append(d)
        return d


# --------------------------------------------------------------- baselines
def unguarded_rolling(scores: np.ndarray, q: float = 0.99,
                      window: int = 2000) -> np.ndarray:
    """The implementation we are arguing against, for comparison only.

    Admits everything recent, including the attack, and re-fits every step.
    Returns the threshold in force at each index (forward-only, so index i
    uses only data strictly before i).
    """
    out = np.empty(len(scores))
    for i in range(len(scores)):
        lo = max(0, i - window)
        hist = scores[lo:i]
        out[i] = np.quantile(hist, q) if len(hist) >= 50 else np.inf
    return out
