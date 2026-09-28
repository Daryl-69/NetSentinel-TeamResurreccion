"""Deterministic inference replay — the flagship novelty.

"This exact approved model, with this exact pipeline and this exact
evidence-derived input, under this exact policy, produced this alert."

If an operator swaps the ONNX file, edits a wrapper, bumps a threshold,
or hand-edits the stored vector, claim 5 (prediction reproducible) fails.

All replay runs with pinned ORT determinism settings:
  intra_op_num_threads=1, inter_op_num_threads=1

If a future op proves non-deterministic on a platform, replay downgrades
that claim to UNVERIFIABLE with the reason surfaced — honesty over a
green check.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import numpy as np

from netsentinel.integrity.encoding import confidence_to_ppm


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ReplayResult:
    """Outcome of a replay attempt."""
    status: str              # "PASS" | "FAIL" | "UNVERIFIABLE"
    class_match: bool | None  # None if UNVERIFIABLE
    score_match: bool | None
    replayed_class: str
    replayed_score_ppm: int
    committed_class: str
    committed_score_ppm: int
    detail: str
    model_digest_match: bool | None = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "class_match": self.class_match,
            "score_match": self.score_match,
            "replayed_class": self.replayed_class,
            "replayed_score_ppm": self.replayed_score_ppm,
            "committed_class": self.committed_class,
            "committed_score_ppm": self.committed_score_ppm,
            "model_digest_match": self.model_digest_match,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Replay engine
# ---------------------------------------------------------------------------

class ReplayEngine:
    """Deterministic inference replay for all 6 model classes."""

    def __init__(self, registry):
        """
        Args:
            registry: ``ModelRegistry`` instance with loaded models.
        """
        self.registry = registry

    def replay(
        self,
        alert_id: str,
        feature_blob: dict,
        committed_class: str,
        committed_score_ppm: int,
        model_digest: str,
    ) -> ReplayResult:
        """Replay inference from stored feature blob.

        Args:
            alert_id: for logging/tracing.
            feature_blob: dict with ``names`` (list[str]) and ``values``
                (list[float|int|str]) — the exact vector the model consumed.
            committed_class: threat class from the receipt.
            committed_score_ppm: score_ppm from the receipt.
            model_digest: ``sha256:...`` of the ONNX file from the receipt.

        Returns:
            ReplayResult with status PASS, FAIL, or UNVERIFIABLE.
        """
        # Rule-based / statistical detectors commit their decision inputs
        # and a digest of their parameters instead of an ONNX file digest.
        if feature_blob.get("rule_key"):
            return self._replay_rule(feature_blob, committed_class,
                                     committed_score_ppm, model_digest)

        # Determine which model class to replay
        model_key = self._class_to_model_key(committed_class)
        if model_key is None:
            return ReplayResult(
                status="UNVERIFIABLE",
                class_match=None,
                score_match=None,
                replayed_class="",
                replayed_score_ppm=0,
                committed_class=committed_class,
                committed_score_ppm=committed_score_ppm,
                detail=f"Unknown threat class: {committed_class}",
            )

        # Check model digest
        model = getattr(self.registry, model_key, None)
        if model is None:
            return ReplayResult(
                status="UNVERIFIABLE",
                class_match=None,
                score_match=None,
                replayed_class="",
                replayed_score_ppm=0,
                committed_class=committed_class,
                committed_score_ppm=committed_score_ppm,
                detail=f"Model '{model_key}' not loaded",
            )

        # Check digest match
        current_digest = self.registry.model_digest(model_key)
        digest_match = current_digest == model_digest

        if not digest_match:
            return ReplayResult(
                status="FAIL",
                class_match=None,
                score_match=None,
                replayed_class="",
                replayed_score_ppm=0,
                committed_class=committed_class,
                committed_score_ppm=committed_score_ppm,
                model_digest_match=False,
                detail=(
                    f"Model digest mismatch: receipt={model_digest}, "
                    f"loaded={current_digest}"
                ),
            )

        # Reconstruct feature dict from blob
        names = feature_blob.get("names", [])
        values = feature_blob.get("values", [])
        features = dict(zip(names, values))

        # Run replay
        try:
            result = self._replay_model(model_key, model, features, feature_blob)
        except Exception as e:
            return ReplayResult(
                status="UNVERIFIABLE",
                class_match=None,
                score_match=None,
                replayed_class="",
                replayed_score_ppm=0,
                committed_class=committed_class,
                committed_score_ppm=committed_score_ppm,
                model_digest_match=True,
                detail=f"Replay execution error: {e}",
            )

        replayed_class = result["class"]
        replayed_score_ppm = result["score_ppm"]

        class_match = replayed_class == committed_class
        score_match = replayed_score_ppm == committed_score_ppm

        if class_match and score_match:
            status = "PASS"
            detail = "Prediction reproduced bit-for-bit"
        else:
            status = "FAIL"
            parts = []
            if not class_match:
                parts.append(
                    f"class: replayed={replayed_class}, "
                    f"committed={committed_class}"
                )
            if not score_match:
                parts.append(
                    f"score_ppm: replayed={replayed_score_ppm}, "
                    f"committed={committed_score_ppm}"
                )
            detail = "Prediction mismatch: " + "; ".join(parts)

        return ReplayResult(
            status=status,
            class_match=class_match,
            score_match=score_match,
            replayed_class=replayed_class,
            replayed_score_ppm=replayed_score_ppm,
            committed_class=committed_class,
            committed_score_ppm=committed_score_ppm,
            model_digest_match=True,
            detail=detail,
        )

    def _replay_rule(self, feature_blob: dict, committed_class: str,
                     committed_score_ppm: int, model_digest: str) -> ReplayResult:
        key = feature_blob.get("rule_key")
        rules = getattr(self.registry, "rule_detectors", {}) or {}
        det = rules.get(key)

        def unverifiable(detail, digest_match=None):
            return ReplayResult(status="UNVERIFIABLE", class_match=None, score_match=None,
                                replayed_class="", replayed_score_ppm=0,
                                committed_class=committed_class,
                                committed_score_ppm=committed_score_ppm,
                                model_digest_match=digest_match, detail=detail)

        if det is None:
            return unverifiable(f"Rule detector '{key}' is not running on this sensor")
        if det.digest != model_digest:
            return ReplayResult(
                status="FAIL", class_match=None, score_match=None, replayed_class="",
                replayed_score_ppm=0, committed_class=committed_class,
                committed_score_ppm=committed_score_ppm, model_digest_match=False,
                detail=(f"Detector parameters changed since the alert: "
                        f"receipt={model_digest}, running={det.digest}"))
        try:
            inputs = json.loads((feature_blob.get("values") or ["{}"])[0])
            out = det.replay(inputs)
        except Exception as e:
            return unverifiable(f"Replay execution error: {e}", True)
        if out is None:
            return unverifiable("This detector's decision depends on running state "
                                "that one alert's inputs cannot reproduce", True)
        replayed_class = out.get("threat", "Benign")
        replayed_ppm = confidence_to_ppm(round(float(out.get("confidence", 0.0)), 4))
        class_match = replayed_class == committed_class
        score_match = replayed_ppm == committed_score_ppm
        ok = class_match and score_match
        return ReplayResult(
            status="PASS" if ok else "FAIL", class_match=class_match, score_match=score_match,
            replayed_class=replayed_class, replayed_score_ppm=replayed_ppm,
            committed_class=committed_class, committed_score_ppm=committed_score_ppm,
            model_digest_match=True,
            detail=("Decision recomputed from the committed inputs"
                    if ok else "Recomputed decision differs from the receipt"))

    # -- Per-model replay adapters ------------------------------------

    def _replay_model(
        self,
        model_key: str,
        model: Any,
        features: dict,
        feature_blob: dict,
    ) -> dict:
        """Run a single model inference for replay.

        Returns dict with ``class`` and ``score_ppm``.
        """
        if model_key == "ddos":
            result = model.predict(features)
            threat = result.get("threat", "Benign")
            conf = result.get("confidence", 0.0)
            return {"class": threat, "score_ppm": confidence_to_ppm(conf)}

        elif model_key == "c2":
            # C2 expects a flows list — reconstruct from feature blob
            flows = feature_blob.get("flows", [])
            if not flows:
                # Fallback: construct minimal flows from stored values
                return {"class": "Unknown", "score_ppm": 0}
            result = model.predict(flows)
            threat = result.get("threat", "Benign")
            conf = result.get("confidence", 0.0)
            return {"class": threat, "score_ppm": confidence_to_ppm(conf)}

        elif model_key == "dga":
            domain = feature_blob.get("domain", "")
            if not domain:
                return {"class": "Unknown", "score_ppm": 0}
            result = model.predict(domain)
            threat = result.get("threat", "Benign")
            conf = result.get("confidence", 0.0)
            return {"class": threat, "score_ppm": confidence_to_ppm(conf)}

        elif model_key == "ett":
            result = model.predict(features)
            threat = result.get("threat", "Benign")
            conf = result.get("confidence", 0.0)
            return {"class": threat, "score_ppm": confidence_to_ppm(conf)}

        elif model_key == "port_scan":
            result = model.predict(features)
            threat = result.get("threat", "Benign")
            conf = result.get("confidence", 0.0)
            return {"class": threat, "score_ppm": confidence_to_ppm(conf)}

        elif model_key == "exfiltration":
            result = model.predict(features)
            threat = result.get("threat", "Benign")
            conf = result.get("confidence", 0.0)
            return {"class": threat, "score_ppm": confidence_to_ppm(conf)}

        return {"class": "Unknown", "score_ppm": 0}

    # -- Mapping helpers -----------------------------------------------

    @staticmethod
    def _class_to_model_key(threat_class: str) -> str | None:
        """Map threat class name to registry attribute."""
        _MAP = {
            "DDoS": "ddos",
            "C2 Beacon": "c2",
            "DGA": "dga",
            "DNS Tunnel": "dga",
            "Encrypted Malware": "ett",
            "VPN Traffic": "ett",
            "Port Scan": "port_scan",
            "Data Exfiltration": "exfiltration",
        }
        return _MAP.get(threat_class)
