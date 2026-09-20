"""Proof-Carrying Alert receipt builder.

Builds an **in-toto Statement v1** with a NetSentinel predicate and wraps
it in a DSSE envelope.  This is the single forensic artifact that the
anchor service batches, the CLI verifies, and the dashboard renders.

Includes integrated sealing logic: monotonic ``event_sequence`` and
``previous_receipt_digest`` form a per-sensor receipt chain that makes
omission attacks visible (Correction 7).

Replaces middle.md §B.8 (Chainpoint-like format) with standards-aligned
in-toto/DSSE (Correction 3).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from netsentinel.integrity.encoding import (
    jcs_canonicalize,
    digest_prefixed,
    canonical_digest,
    confidence_to_ppm,
)


# ---------------------------------------------------------------------------
# Provenance result (returned by model wrappers)
# ---------------------------------------------------------------------------

class ProvenanceResult(NamedTuple):
    """Provenance data captured alongside a prediction."""
    prediction_class: str
    score_ppm: int               # 0–1_000_000
    feature_names: list[str]     # ordered, exactly as passed to model
    feature_values: list         # parallel to feature_names
    preprocessor_ref: str | None  # digest of scaler/encoder, or None


# ---------------------------------------------------------------------------
# Sensor context
# ---------------------------------------------------------------------------

@dataclass
class SensorContext:
    """Per-sensor state for receipt assembly."""
    sensor_id: str
    signing_key: object  # nacl.signing.SigningKey
    codehash: str         # extractor_code_digest
    policy_digest: str    # JCS digest of thresholds + guards
    runtime_digest: str   # JCS digest of runtime env

    # Sealing state (monotonic counter + previous receipt digest)
    _sequence: int = 0
    _prev_receipt_digest: str = ""
    _seq_path: Path | None = None

    def __post_init__(self):
        # Load persisted sequence if available
        if self._seq_path and self._seq_path.exists():
            try:
                data = json.loads(self._seq_path.read_text())
                self._sequence = data.get("sequence", 0)
                self._prev_receipt_digest = data.get("prev_digest", "")
            except (json.JSONDecodeError, OSError):
                pass

    def next_sequence(self) -> int:
        """Increment and return the next monotonic sequence number."""
        self._sequence += 1
        self._persist_seq()
        return self._sequence

    def update_prev_digest(self, digest: str) -> None:
        self._prev_receipt_digest = digest
        self._persist_seq()

    def _persist_seq(self) -> None:
        if self._seq_path:
            self._seq_path.parent.mkdir(parents=True, exist_ok=True)
            self._seq_path.write_text(json.dumps({
                "sequence": self._sequence,
                "prev_digest": self._prev_receipt_digest,
            }))


# ---------------------------------------------------------------------------
# Receipt builder
# ---------------------------------------------------------------------------

PREDICATE_TYPE = "https://netsentinel.dev/attestation/ml-alert/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


class ReceiptBuilder:
    """Builds Proof-Carrying Alert receipts (in-toto Statement v1)."""

    def build(
        self,
        alert: dict,
        provenance: ProvenanceResult,
        model_digest: str,
        model_version: str,
        sensor_ctx: SensorContext,
    ) -> dict:
        """Build an in-toto statement for a single alert.

        Args:
            alert: the complete alert dict from alert_manager.
            provenance: ``ProvenanceResult`` from the model wrapper.
            model_digest: ``sha256:...`` of the ONNX file.
            model_version: human-readable model version string.
            sensor_ctx: sensor state (id, keys, digests, sequence).

        Returns:
            in-toto Statement v1 dict (ready for DSSE signing).
        """
        alert_id = alert.get("id", "unknown")
        seq = sensor_ctx.next_sequence()

        # Compute evidence digest (whole alert record)
        evidence_for_hash = {
            k: v for k, v in alert.get("evidence", {}).items()
            if isinstance(v, (str, int, bool, list, dict, type(None)))
        }
        # Sanitize: remove any float values for canonicalization
        evidence_clean = _sanitize_for_canon(evidence_for_hash)
        evidence_digest = canonical_digest(evidence_clean)

        # Feature vector digest
        feature_obj = {
            "names": provenance.feature_names,
            "values": [
                _float_to_repr(v) if isinstance(v, float) else v
                for v in provenance.feature_values
            ],
        }
        feature_vector_digest = canonical_digest(feature_obj)

        # Feature schema digest (just the ordered names)
        feature_schema_digest = canonical_digest(provenance.feature_names)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        statement = {
            "_type": STATEMENT_TYPE,
            "subject": [
                {
                    "name": f"netsentinel-alert:{alert_id}",
                    "digest": {
                        "sha256": digest_prefixed(
                            jcs_canonicalize(_sanitize_for_canon(alert))
                        ).split(":", 1)[1]
                    },
                }
            ],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "schema_version": "1.0",
                "canonicalization": "rfc8785-jcs-v1",
                "sensor": {
                    "id": sensor_ctx.sensor_id,
                    "event_sequence": seq,
                    "capture_window": {
                        "start": now,
                        "end": now,
                    },
                },
                "evidence": {
                    "digest": evidence_digest,
                    "storage_reference": f"local://evidence/{alert_id}.enc",
                },
                "feature_pipeline": {
                    "feature_vector_digest": feature_vector_digest,
                    "feature_schema_digest": feature_schema_digest,
                    "extractor_code_digest": sensor_ctx.codehash,
                    "preprocessor_digest": provenance.preprocessor_ref or "",
                },
                "model": {
                    "model_digest": model_digest,
                    "version": model_version,
                },
                "decision": {
                    "class": provenance.prediction_class,
                    "score_ppm": provenance.score_ppm,
                    "threshold_ppm": _get_threshold_ppm(
                        provenance.prediction_class
                    ),
                    "policy_digest": sensor_ctx.policy_digest,
                    "explanation_digest": "",  # Phase 2
                },
                "completeness": {
                    "previous_receipt_digest": sensor_ctx._prev_receipt_digest,
                    "checkpoint_root": "",  # filled post-anchor
                    "checkpoint_sequence": 0,  # filled post-anchor
                },
                "runtime": {
                    "environment_digest": sensor_ctx.runtime_digest,
                },
            },
        }

        # Update sealing chain
        receipt_digest = canonical_digest(statement)
        sensor_ctx.update_prev_digest(receipt_digest)

        return statement


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_for_canon(obj):
    """Recursively convert floats to repr strings for canonicalization.

    Floats are banned from signed payloads.  This function converts them
    at the boundary so evidence dicts (which contain model-output floats)
    can still be committed.
    """
    if isinstance(obj, float):
        return _float_to_repr(obj)
    if isinstance(obj, dict):
        return {k: _sanitize_for_canon(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_canon(v) for v in obj]
    if isinstance(obj, (str, int, bool, type(None))):
        return obj
    # Fallback: convert to string
    return str(obj)


def _float_to_repr(f: float) -> str:
    """Convert a float to its shortest round-trip repr string."""
    return repr(f)


def _get_threshold_ppm(threat_class: str) -> int:
    """Look up the configured threshold for a threat class (as PPM)."""
    from netsentinel.config import THRESHOLDS

    # Map threat class names to threshold keys
    _CLASS_TO_KEY = {
        "DDoS": "ddos",
        "C2 Beacon": "c2_beacon",
        "DGA": "dga",
        "DNS Tunnel": "dga",
        "Encrypted Malware": "encrypted_malware",
        "VPN Traffic": "encrypted_malware",
        "Port Scan": "port_scan",
        "Data Exfiltration": "exfiltration",
    }
    key = _CLASS_TO_KEY.get(threat_class, "")
    threshold = THRESHOLDS.get(key, 0.5)
    return confidence_to_ppm(threshold)
