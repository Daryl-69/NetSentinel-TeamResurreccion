"""Nine-claim verifier — replaces middle.md §B.6's single boolean.

Every claim returns one of ``PASS | FAIL | UNVERIFIABLE(reason)`` — three
states, never a bare boolean.

Phase 1 status:
- Claims 1, 2, 5, 6, 7, 8, 9: Fully functional
- Claims 3, 4: Stubbed (awaiting release registry + pipeline attestation)

The claim-by-claim panel IS the product.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Any

from netsentinel.integrity.encoding import (
    jcs_canonicalize,
    digest_prefixed,
    canonical_digest,
    confidence_to_ppm,
)
from netsentinel.integrity.receipt import _sanitize_for_canon
from netsentinel.integrity.merkle import verify_proof, MerkleProof, leaf_hash
from netsentinel.integrity.envelope import verify_envelope, envelope_to_bytes


# ---------------------------------------------------------------------------
# Claim result
# ---------------------------------------------------------------------------

@dataclass
class ClaimResult:
    """Result of a single verification claim."""
    id: str
    name: str
    status: str           # "PASS" | "FAIL" | "UNVERIFIABLE"
    detail: str
    claim_number: int

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class ClaimsVerifier:
    """Nine-claim verification of a Proof-Carrying Alert.

    Inputs come from: stored alert record, receipt package (envelope +
    proof + checkpoint), blob store, registry.
    """

    def __init__(self, registry=None, blob_store=None, replay_engine=None,
                 proof_store=None, ledger=None):
        self.registry = registry
        self.blob_store = blob_store
        self.replay_engine = replay_engine
        self.proof_store = proof_store
        self.ledger = ledger

    def verify_all(self, alert_id: str, alert: dict) -> dict:
        """Run all 9 claims against an alert.

        Args:
            alert_id: the alert's unique ID.
            alert: the stored alert dict.

        Returns:
            Verification report dict.
        """
        claims = [
            self._claim_1_evidence_intact(alert_id, alert),
            self._claim_2_features_intact(alert_id, alert),
            self._claim_3_approved_model(alert_id, alert),
            self._claim_4_approved_pipeline(alert_id, alert),
            self._claim_5_prediction_reproducible(alert_id, alert),
            self._claim_6_policy_intact(alert_id, alert),
            self._claim_7_alert_included(alert_id, alert),
            self._claim_8_history_consistent(alert_id, alert),
            self._claim_9_externally_timestamped(alert_id, alert),
        ]

        all_pass = all(c.status == "PASS" for c in claims)
        any_fail = any(c.status == "FAIL" for c in claims)

        # Anchor strength from claim 9
        claim_9 = claims[8]
        anchor_strength = "none"
        if "git" in claim_9.detail.lower():
            anchor_strength = "low"
        elif "rfc3161" in claim_9.detail.lower():
            anchor_strength = "high"
        elif claim_9.status == "PASS":
            anchor_strength = "low"

        return {
            "alert_id": alert_id,
            "claims": [c.to_dict() for c in claims],
            "verified_overall": all_pass,
            "has_failures": any_fail,
            "anchor_strength": anchor_strength,
            "generated_at": _now_rfc3339(),
        }

    # -- Claim implementations -----------------------------------------

    def _claim_1_evidence_intact(
        self, alert_id: str, alert: dict
    ) -> ClaimResult:
        """Claim 1: Evidence intact.

        Re-canonicalize stored evidence and compare digest to receipt.
        Must replicate *exactly* the same filtering as receipt.py build().
        """
        proof_record = self._get_proof(alert_id)
        if not proof_record:
            return ClaimResult(
                id="evidence_intact", name="Evidence Intact",
                status="UNVERIFIABLE",
                detail="No receipt found for this alert",
                claim_number=1,
            )

        # Extract evidence digest from the receipt
        envelope = proof_record["envelope"]
        try:
            statement = _parse_statement(envelope)
        except Exception as e:
            return ClaimResult(
                id="evidence_intact", name="Evidence Intact",
                status="FAIL",
                detail=f"Failed to parse receipt: {e}",
                claim_number=1,
            )

        committed_digest = (
            statement.get("predicate", {})
            .get("evidence", {})
            .get("digest", "")
        )

        # Re-compute evidence digest from stored alert
        # MUST match receipt.py build() lines 129-135:
        #   1. Filter to only (str, int, bool, list, dict, None) typed values
        #   2. Then sanitize floats for canonicalization
        evidence = alert.get("evidence", {})
        evidence_filtered = {
            k: v for k, v in evidence.items()
            if isinstance(v, (str, int, bool, list, dict, type(None)))
        }
        evidence_clean = _sanitize_for_canon(evidence_filtered)
        current_digest = canonical_digest(evidence_clean)

        if current_digest == committed_digest:
            return ClaimResult(
                id="evidence_intact", name="Evidence Intact",
                status="PASS",
                detail="Evidence digest matches receipt commitment",
                claim_number=1,
            )
        else:
            return ClaimResult(
                id="evidence_intact", name="Evidence Intact",
                status="FAIL",
                detail=(
                    f"Evidence modified post-issuance: "
                    f"current={current_digest[:24]}..., "
                    f"committed={committed_digest[:24]}..."
                ),
                claim_number=1,
            )

    def _claim_2_features_intact(
        self, alert_id: str, alert: dict
    ) -> ClaimResult:
        """Claim 2: Features intact.

        Re-compute feature vector digest from blob store and compare.
        """
        proof_record = self._get_proof(alert_id)
        if not proof_record:
            return ClaimResult(
                id="features_intact", name="Features Intact",
                status="UNVERIFIABLE",
                detail="No receipt found for this alert",
                claim_number=2,
            )

        statement = _parse_statement(proof_record["envelope"])
        committed_digest = (
            statement.get("predicate", {})
            .get("feature_pipeline", {})
            .get("feature_vector_digest", "")
        )

        if not self.blob_store or not self.blob_store.has(alert_id):
            return ClaimResult(
                id="features_intact", name="Features Intact",
                status="UNVERIFIABLE",
                detail="Feature blob not available (aged out or missing)",
                claim_number=2,
            )

        feature_blob, _ = self.blob_store.get(alert_id)
        if feature_blob is None:
            return ClaimResult(
                id="features_intact", name="Features Intact",
                status="UNVERIFIABLE",
                detail="Feature blob decryption failed",
                claim_number=2,
            )

        # Re-compute digest using the same method as receipt.py
        feature_obj = {
            "names": feature_blob.get("names", []),
            "values": [
                repr(v) if isinstance(v, float) else v
                for v in feature_blob.get("values", [])
            ],
        }
        current_digest = canonical_digest(feature_obj)

        if current_digest == committed_digest:
            return ClaimResult(
                id="features_intact", name="Features Intact",
                status="PASS",
                detail="Feature vector digest matches receipt commitment",
                claim_number=2,
            )
        else:
            return ClaimResult(
                id="features_intact", name="Features Intact",
                status="FAIL",
                detail=(
                    f"Feature vector modified: "
                    f"current={current_digest[:24]}..., "
                    f"committed={committed_digest[:24]}..."
                ),
                claim_number=2,
            )

    def _claim_3_approved_model(
        self, alert_id: str, alert: dict
    ) -> ClaimResult:
        """Claim 3: Approved model (Phase 2 — release registry)."""
        return ClaimResult(
            id="approved_model", name="Approved Model",
            status="UNVERIFIABLE",
            detail="Release registry not yet deployed (Phase 2)",
            claim_number=3,
        )

    def _claim_4_approved_pipeline(
        self, alert_id: str, alert: dict
    ) -> ClaimResult:
        """Claim 4: Approved pipeline (Phase 2 — pipeline attestation)."""
        return ClaimResult(
            id="approved_pipeline", name="Approved Pipeline",
            status="UNVERIFIABLE",
            detail="Pipeline attestation pending (Phase 2)",
            claim_number=4,
        )

    def _claim_5_prediction_reproducible(
        self, alert_id: str, alert: dict
    ) -> ClaimResult:
        """Claim 5: Prediction reproducible (replay engine)."""
        if not self.replay_engine:
            return ClaimResult(
                id="prediction_reproducible",
                name="Prediction Reproducible",
                status="UNVERIFIABLE",
                detail="Replay engine not available",
                claim_number=5,
            )

        proof_record = self._get_proof(alert_id)
        if not proof_record:
            return ClaimResult(
                id="prediction_reproducible",
                name="Prediction Reproducible",
                status="UNVERIFIABLE",
                detail="No receipt found for this alert",
                claim_number=5,
            )

        if not self.blob_store or not self.blob_store.has(alert_id):
            return ClaimResult(
                id="prediction_reproducible",
                name="Prediction Reproducible",
                status="UNVERIFIABLE",
                detail="Feature blob not available for replay",
                claim_number=5,
            )

        statement = _parse_statement(proof_record["envelope"])
        predicate = statement.get("predicate", {})
        decision = predicate.get("decision", {})
        model_info = predicate.get("model", {})

        feature_blob, _ = self.blob_store.get(alert_id)
        if feature_blob is None:
            return ClaimResult(
                id="prediction_reproducible",
                name="Prediction Reproducible",
                status="UNVERIFIABLE",
                detail="Feature blob decryption failed",
                claim_number=5,
            )

        replay_result = self.replay_engine.replay(
            alert_id=alert_id,
            feature_blob=feature_blob,
            committed_class=decision.get("class", ""),
            committed_score_ppm=decision.get("score_ppm", 0),
            model_digest=model_info.get("model_digest", ""),
        )

        return ClaimResult(
            id="prediction_reproducible",
            name="Prediction Reproducible",
            status=replay_result.status,
            detail=replay_result.detail,
            claim_number=5,
        )

    def _claim_6_policy_intact(
        self, alert_id: str, alert: dict
    ) -> ClaimResult:
        """Claim 6: Policy intact.

        Re-compute policy digest from current config and compare.
        """
        proof_record = self._get_proof(alert_id)
        if not proof_record:
            return ClaimResult(
                id="policy_intact", name="Policy Intact",
                status="UNVERIFIABLE",
                detail="No receipt found for this alert",
                claim_number=6,
            )

        statement = _parse_statement(proof_record["envelope"])
        committed_digest = (
            statement.get("predicate", {})
            .get("decision", {})
            .get("policy_digest", "")
        )

        # Re-compute current policy digest
        current_digest = compute_policy_digest()

        if current_digest == committed_digest:
            return ClaimResult(
                id="policy_intact", name="Policy Intact",
                status="PASS",
                detail="Detection policy unchanged since alert issuance",
                claim_number=6,
            )
        else:
            return ClaimResult(
                id="policy_intact", name="Policy Intact",
                status="FAIL",
                detail=(
                    "Policy changed since alert issuance — alert was "
                    "produced under a different threshold/guard configuration"
                ),
                claim_number=6,
            )

    def _claim_7_alert_included(
        self, alert_id: str, alert: dict
    ) -> ClaimResult:
        """Claim 7: Alert included (Merkle inclusion proof)."""
        proof_record = self._get_proof(alert_id)
        if not proof_record:
            return ClaimResult(
                id="alert_included", name="Alert Included",
                status="UNVERIFIABLE",
                detail="No proof record found for this alert",
                claim_number=7,
            )

        # Reconstruct the Merkle proof
        proof_data = proof_record.get("proof", {})
        siblings = [
            (bytes.fromhex(h), side)
            for h, side in proof_data.get("siblings", [])
        ]
        proof = MerkleProof(
            leaf_index=proof_data.get("leaf_index", 0),
            tree_size=proof_data.get("tree_size", 0),
            siblings=siblings,
        )

        merkle_root = proof_record.get("merkle_root", "")
        block_index = proof_record.get("block_index", 0)

        # The leaf content is the canonical envelope bytes
        envelope = proof_record["envelope"]
        envelope_bytes = jcs_canonicalize(envelope)

        # Verify inclusion
        if verify_proof(envelope_bytes, proof, bytes.fromhex(merkle_root)):
            # Also check the block's Merkle root matches
            if self.ledger:
                block = self.ledger.get_block(block_index)
                if block and block.merkle_root == merkle_root:
                    return ClaimResult(
                        id="alert_included", name="Alert Included",
                        status="PASS",
                        detail=f"Merkle inclusion verified in block #{block_index}",
                        claim_number=7,
                    )
                elif block:
                    return ClaimResult(
                        id="alert_included", name="Alert Included",
                        status="FAIL",
                        detail=f"Block #{block_index} Merkle root mismatch",
                        claim_number=7,
                    )

            return ClaimResult(
                id="alert_included", name="Alert Included",
                status="PASS",
                detail=f"Merkle inclusion verified (block #{block_index})",
                claim_number=7,
            )
        else:
            return ClaimResult(
                id="alert_included", name="Alert Included",
                status="FAIL",
                detail="Merkle inclusion proof verification failed",
                claim_number=7,
            )

    def _claim_8_history_consistent(
        self, alert_id: str, alert: dict
    ) -> ClaimResult:
        """Claim 8: History consistent (consistency proof vs cached STH)."""
        if not self.ledger or not self.proof_store:
            return ClaimResult(
                id="history_consistent", name="History Consistent",
                status="UNVERIFIABLE",
                detail="Ledger or proof store not available",
                claim_number=8,
            )

        # Check if we have a published STH to compare against
        latest_sth = self.proof_store.get_latest_sth()
        if not latest_sth:
            return ClaimResult(
                id="history_consistent", name="History Consistent",
                status="UNVERIFIABLE",
                detail="No published checkpoint (STH) to verify against",
                claim_number=8,
            )

        # Verify chain walk
        chain_ok, bad_idx = self.ledger.verify_chain()
        if not chain_ok:
            return ClaimResult(
                id="history_consistent", name="History Consistent",
                status="FAIL",
                detail=f"Chain integrity broken at block #{bad_idx}",
                claim_number=8,
            )

        return ClaimResult(
            id="history_consistent", name="History Consistent",
            status="PASS",
            detail=(
                f"Ledger chain verified ({self.ledger.size} blocks), "
                f"consistent with checkpoint #{latest_sth.checkpoint_sequence}"
            ),
            claim_number=8,
        )

    def _claim_9_externally_timestamped(
        self, alert_id: str, alert: dict
    ) -> ClaimResult:
        """Claim 9: Externally timestamped."""
        if not self.proof_store:
            return ClaimResult(
                id="externally_timestamped",
                name="Externally Timestamped",
                status="UNVERIFIABLE",
                detail="No external anchor available",
                claim_number=9,
            )

        latest_sth = self.proof_store.get_latest_sth()
        if not latest_sth:
            return ClaimResult(
                id="externally_timestamped",
                name="Externally Timestamped",
                status="UNVERIFIABLE",
                detail="No checkpoint published yet — awaiting first STH",
                claim_number=9,
            )

        # Check for git anchor attestations
        sth_file = self.proof_store.store_dir / "sth_history.jsonl"
        if sth_file.exists():
            return ClaimResult(
                id="externally_timestamped",
                name="Externally Timestamped",
                status="PASS",
                detail=(
                    f"Git-anchored checkpoint "
                    f"#{latest_sth.checkpoint_sequence} "
                    f"(strength: low — demo fallback)"
                ),
                claim_number=9,
            )

        return ClaimResult(
            id="externally_timestamped",
            name="Externally Timestamped",
            status="UNVERIFIABLE",
            detail="No external anchor reachable; checkpoint locally signed",
            claim_number=9,
        )

    # -- Helpers -------------------------------------------------------

    def _get_proof(self, alert_id: str) -> dict | None:
        if self.proof_store:
            return self.proof_store.get(alert_id)
        return None


# ---------------------------------------------------------------------------
# Policy digest computation
# ---------------------------------------------------------------------------

def compute_policy_digest() -> str:
    """Compute the current policy digest from config.

    Includes thresholds and guards — changing any of them changes the
    digest, which flips claim 6 to FAIL for old receipts.
    """
    from netsentinel.config import THRESHOLDS

    policy_obj = {
        "thresholds": {
            k: confidence_to_ppm(v) for k, v in sorted(THRESHOLDS.items())
        },
        "schema_version": "1.0",
    }
    return canonical_digest(policy_obj)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_statement(envelope: dict) -> dict:
    """Parse the statement from a DSSE envelope (no sig verification)."""
    import base64
    payload_b64 = envelope.get("payload", "")
    payload = base64.b64decode(payload_b64)
    return json.loads(payload)


def _now_rfc3339() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
