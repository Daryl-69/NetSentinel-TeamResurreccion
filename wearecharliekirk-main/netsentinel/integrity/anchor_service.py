"""Anchor service — windowed batching, proof store, and external anchoring.

Extends middle.md §B.5 with:
- DSSE envelope digests as leaves (not raw alert hashes) — Correction 3
- Empty-window commitments (every window produces a block) — Correction 7
- Pluggable ``AnchorBackend`` interface for external anchoring
- Integrated proof store (per-alert: envelope, Merkle proof, block ref)

Integration: wherever alerts are emitted, call ``add_envelope()``.
A background timer calls ``flush()`` every ``window_seconds``.
A daily timer calls ``publish_sth()``.
"""

from __future__ import annotations

import abc
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netsentinel.integrity.merkle import build_tree, MerkleProof, EMPTY_ROOT
from netsentinel.integrity.ledger import IntegrityLedger, SignedTreeHead
from netsentinel.integrity.encoding import (
    jcs_canonicalize,
    digest_prefixed,
)


# ---------------------------------------------------------------------------
# Proof store (integrated — per-alert proof records)
# ---------------------------------------------------------------------------

class ProofStore:
    """File-backed store for per-alert integrity proofs."""

    def __init__(self, store_dir: str):
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._index: dict[str, dict] = {}
        self._load_index()

    def save_proof(
        self,
        alert_id: str,
        envelope: dict,
        merkle_root: str,
        proof: MerkleProof,
        block_index: int,
    ) -> None:
        """Save a per-alert integrity proof."""
        record = {
            "alert_id": alert_id,
            "envelope": envelope,
            "merkle_root": merkle_root,
            "proof": {
                "leaf_index": proof.leaf_index,
                "tree_size": proof.tree_size,
                "siblings": [
                    (sib.hex(), side) for sib, side in proof.siblings
                ],
            },
            "block_index": block_index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._index[alert_id] = record
        self._persist_index()

    def get(self, alert_id: str) -> dict | None:
        return self._index.get(alert_id)

    def save_sth(self, sth: SignedTreeHead) -> None:
        """Persist a signed tree head."""
        sth_path = self.store_dir / "sth_history.jsonl"
        with open(sth_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(sth.to_dict()) + "\n")

    def get_latest_sth(self) -> SignedTreeHead | None:
        """Load the most recent STH."""
        sth_path = self.store_dir / "sth_history.jsonl"
        if not sth_path.exists():
            return None
        last = None
        with open(sth_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = SignedTreeHead.from_dict(json.loads(line))
        return last

    def _load_index(self) -> None:
        idx_path = self.store_dir / "proof_index.json"
        if idx_path.exists():
            try:
                self._index = json.loads(idx_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._index = {}

    def _persist_index(self) -> None:
        idx_path = self.store_dir / "proof_index.json"
        idx_path.write_text(
            json.dumps(self._index, indent=2), encoding="utf-8"
        )


# ---------------------------------------------------------------------------
# Anchor backend interface
# ---------------------------------------------------------------------------

class AnchorBackend(abc.ABC):
    """Abstract base for external anchoring backends."""

    @abc.abstractmethod
    def submit(self, checkpoint_digest: str, sth: SignedTreeHead) -> dict:
        """Submit a checkpoint for external anchoring.

        Returns:
            Attestation dict with at minimum ``{"type": ..., "ref": ...}``.
        """

    @property
    @abc.abstractmethod
    def strength(self) -> str:
        """Anchor strength label: ``"low"``, ``"medium"``, ``"high"``."""


class GitAnchorBackend(AnchorBackend):
    """Commit STH to a local git repo — demo fallback, low-strength.

    The git commit history becomes an external timestamped witness.
    Labeled low-strength because the repo owner can rewrite history.
    """

    def __init__(self, repo_dir: str):
        self.repo_dir = Path(repo_dir)

    @property
    def strength(self) -> str:
        return "low"

    def submit(self, checkpoint_digest: str, sth: SignedTreeHead) -> dict:
        sth_file = self.repo_dir / "integrity" / "latest_sth.json"
        sth_file.parent.mkdir(parents=True, exist_ok=True)
        sth_file.write_text(
            json.dumps(sth.to_dict(), indent=2), encoding="utf-8"
        )

        # Also write to a history file
        history = self.repo_dir / "integrity" / "sth_history.jsonl"
        with open(history, "a", encoding="utf-8") as f:
            f.write(json.dumps(sth.to_dict()) + "\n")

        # Try to git-add and commit (best-effort — won't fail if no git)
        ref = "local-file"
        try:
            subprocess.run(
                ["git", "add", str(sth_file), str(history)],
                cwd=str(self.repo_dir),
                capture_output=True,
                timeout=10,
            )
            result = subprocess.run(
                [
                    "git", "commit", "-m",
                    f"integrity: checkpoint #{sth.checkpoint_sequence} "
                    f"(tree_size={sth.tree_size})",
                ],
                cwd=str(self.repo_dir),
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Get commit hash
                sha_result = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(self.repo_dir),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                ref = f"git:{sha_result.stdout.strip()}"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass  # No git available — file-only fallback

        return {
            "type": "git-commit",
            "strength": "low",
            "ref": ref,
            "checkpoint_sequence": sth.checkpoint_sequence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Anchor service
# ---------------------------------------------------------------------------

class AnchorService:
    """Batches DSSE envelopes into Merkle windows and drives the ledger.

    The leaf hashed into each checkpoint is the digest of the DSSE
    envelope bytes (not the raw alert), per Correction 3.
    """

    def __init__(
        self,
        ledger: IntegrityLedger,
        proof_store: ProofStore,
        window_seconds: int = 60,
        anchor_backends: list[AnchorBackend] | None = None,
    ):
        self.ledger = ledger
        self.proof_store = proof_store
        self.window_seconds = window_seconds
        self.anchor_backends = anchor_backends or []
        self._buffer: list[tuple[str, dict, bytes]] = []
        # (alert_id, envelope_dict, envelope_canonical_bytes)

    def add_envelope(self, alert_id: str, envelope: dict) -> None:
        """Add a signed DSSE envelope to the current window's buffer."""
        canonical = jcs_canonicalize(envelope)
        self._buffer.append((alert_id, envelope, canonical))

    def flush(self) -> dict | None:
        """Flush the current window into a ledger block.

        **Always produces a block** — even for empty windows (Correction 7).
        An empty-window block has ``alert_count=0`` and the CT-convention
        empty-tree root.

        Returns:
            Block dict, or None only if the ledger itself errors.
        """
        if not self._buffer:
            # Empty-window commitment
            block = self.ledger.append(EMPTY_ROOT.hex(), 0)
            return block.to_dict()

        ids = [a for a, _, _ in self._buffer]
        envelopes = [e for _, e, _ in self._buffer]
        canonical_bytes = [c for _, _, c in self._buffer]

        # Build Merkle tree — raw content is the canonical envelope bytes
        root, proofs = build_tree(canonical_bytes)

        # Append block to ledger
        block = self.ledger.append(root.hex(), len(ids))

        # Store per-alert proofs
        for i, (aid, env, _) in enumerate(self._buffer):
            self.proof_store.save_proof(
                alert_id=aid,
                envelope=env,
                merkle_root=root.hex(),
                proof=proofs[i],
                block_index=block.index,
            )

        self._buffer.clear()
        return block.to_dict()

    def publish_sth(self) -> dict:
        """Build an STH and submit it to all anchor backends.

        Returns:
            Dict with STH and anchor attestations.
        """
        sth = self.ledger.build_sth()
        self.proof_store.save_sth(sth)

        checkpoint_digest = digest_prefixed(sth.signing_payload())
        attestations = []
        for backend in self.anchor_backends:
            try:
                att = backend.submit(checkpoint_digest, sth)
                attestations.append(att)
            except Exception as e:
                attestations.append({
                    "type": type(backend).__name__,
                    "error": str(e),
                    "queued": True,
                })

        return {
            "sth": sth.to_dict(),
            "attestations": attestations,
            "strongest": max(
                (a.get("strength", "none") for a in attestations
                 if "error" not in a),
                default="none",
            ),
        }

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)
