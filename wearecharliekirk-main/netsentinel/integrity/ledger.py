"""Append-only integrity ledger with Ed25519 signing and CT-style STH.

Extends middle.md §B.4 with:
- RFC 3339 timestamps (not floats) per Correction 4
- Monotonic ``checkpoint_sequence`` per Correction 7
- Empty-window commitments (every window produces a block)
- ``SignedTreeHead`` + consistency proofs for external auditing

Key management: Ed25519 via PyNaCl.  The private key is loaded from a file
whose path comes from ``INTEGRITY_KEY_PATH`` (env var or config); the file
is auto-generated on first run with 0600 permissions.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

from netsentinel.integrity.merkle import (
    build_tree,
    consistency_proof as merkle_consistency_proof,
    verify_consistency as merkle_verify_consistency,
    EMPTY_ROOT,
)
from netsentinel.integrity.encoding import (
    jcs_canonicalize,
    digest_prefixed,
    digest_bytes,
)


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def load_or_generate_key(key_path: str) -> SigningKey:
    """Load an Ed25519 signing key from *key_path*, or generate one.

    On generation the file is created with 0600 permissions (on POSIX).
    """
    p = Path(key_path)
    if p.exists():
        raw = p.read_bytes()
        # Support both raw 32-byte seed and hex-encoded seed
        if len(raw) == 32:
            return SigningKey(raw)
        return SigningKey(raw.strip(), encoder=HexEncoder)

    # Auto-generate
    p.parent.mkdir(parents=True, exist_ok=True)
    sk = SigningKey.generate()
    p.write_bytes(sk.encode())
    try:
        os.chmod(str(p), 0o600)
    except OSError:
        pass  # Windows doesn't support POSIX permissions — acceptable for demo
    print(f"  [KEY] Generated Ed25519 signing key: {p}")
    return sk


def public_key_hex(sk: SigningKey) -> str:
    """Return the verify (public) key as a hex string."""
    return sk.verify_key.encode(encoder=HexEncoder).decode("ascii")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

def _now_rfc3339() -> str:
    """UTC timestamp in RFC 3339 format, integer second resolution."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_unix() -> int:
    """Integer Unix epoch seconds."""
    return int(time.time())


GENESIS_PREV = "0" * 64  # 32 zero bytes in hex


@dataclass
class Block:
    """One block in the append-only ledger."""

    index: int
    timestamp_rfc3339: str        # RFC 3339 UTC
    unix_seconds: int             # integer epoch for sorting
    merkle_root: str              # hex of the per-window Merkle root
    prev_block_hash: str          # hex
    alert_count: int
    nid_pubkey: str               # hex verify key
    signature: str = ""           # hex Ed25519 signature over block_hash

    def block_hash(self) -> str:
        """Deterministic hash of this block's content (no signature)."""
        payload = (
            f"{self.index}|{self.timestamp_rfc3339}|{self.unix_seconds}|"
            f"{self.merkle_root}|{self.prev_block_hash}|{self.alert_count}"
        ).encode("utf-8")
        return digest_bytes(payload).hex()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(**d)


@dataclass
class SignedTreeHead:
    """A checkpoint over the whole block chain."""

    tree_size: int                # number of blocks covered
    root_hash: str                # hex Merkle root over block_hash()es
    timestamp_rfc3339: str
    unix_seconds: int
    checkpoint_sequence: int      # monotonically increasing checkpoint counter
    nid_pubkey: str
    signature: str = ""

    def signing_payload(self) -> bytes:
        return (
            f"{self.tree_size}|{self.root_hash}|"
            f"{self.timestamp_rfc3339}|{self.unix_seconds}|"
            f"{self.checkpoint_sequence}"
        ).encode("utf-8")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "SignedTreeHead":
        return cls(**d)


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class IntegrityLedger:
    """Append-only Ed25519-signed block chain with STH support.

    Storage: one JSON object per line in an append-only JSONL file.
    """

    def __init__(self, db_path: str, signing_key: SigningKey):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.sk = signing_key
        self.vk_hex = public_key_hex(signing_key)
        self._head: Block | None = self._load_head()
        self._checkpoint_seq: int = self._load_checkpoint_seq()

    # -- Append --------------------------------------------------------

    def append(self, merkle_root_hex: str, alert_count: int) -> Block:
        """Append a new block and return it."""
        prev = self._head.block_hash() if self._head else GENESIS_PREV
        idx = (self._head.index + 1) if self._head else 0

        blk = Block(
            index=idx,
            timestamp_rfc3339=_now_rfc3339(),
            unix_seconds=_now_unix(),
            merkle_root=merkle_root_hex,
            prev_block_hash=prev,
            alert_count=alert_count,
            nid_pubkey=self.vk_hex,
        )
        # Sign the block hash
        sig = self.sk.sign(bytes.fromhex(blk.block_hash()))
        blk.signature = sig.signature.hex()

        self._persist(blk)
        self._head = blk
        return blk

    # -- Verification --------------------------------------------------

    def verify_chain(self) -> tuple[bool, int | None]:
        """Re-walk the whole ledger.  Return ``(ok, first_bad_index)``."""
        prev = GENESIS_PREV
        for blk in self._iter_blocks():
            # Check chain linkage
            if blk.prev_block_hash != prev:
                return False, blk.index
            # Check signature
            try:
                vk = VerifyKey(bytes.fromhex(blk.nid_pubkey))
                vk.verify(
                    bytes.fromhex(blk.block_hash()),
                    bytes.fromhex(blk.signature),
                )
            except Exception:
                return False, blk.index
            prev = blk.block_hash()
        return True, None

    # -- STH (Signed Tree Head) ----------------------------------------

    def build_sth(self) -> SignedTreeHead:
        """Build a top-level Merkle tree over all block hashes and sign it."""
        blocks = list(self._iter_blocks())
        if not blocks:
            root = EMPTY_ROOT
        else:
            leaves = [bytes.fromhex(b.block_hash()) for b in blocks]
            root, _ = build_tree(leaves)

        self._checkpoint_seq += 1
        sth = SignedTreeHead(
            tree_size=len(blocks),
            root_hash=root.hex(),
            timestamp_rfc3339=_now_rfc3339(),
            unix_seconds=_now_unix(),
            checkpoint_sequence=self._checkpoint_seq,
            nid_pubkey=self.vk_hex,
        )
        payload = sth.signing_payload()
        sig = self.sk.sign(payload)
        sth.signature = sig.signature.hex()

        self._persist_checkpoint_seq()
        return sth

    # -- Consistency proofs --------------------------------------------

    def consistency_proof(
        self, old_size: int, new_size: int
    ) -> list[str]:
        """Compute a consistency proof between two tree sizes.

        Returns list of hex-encoded proof hashes.
        """
        blocks = list(self._iter_blocks())
        if new_size > len(blocks):
            new_size = len(blocks)
        leaves = [bytes.fromhex(b.block_hash()) for b in blocks[:new_size]]
        raw_proof = merkle_consistency_proof(leaves, old_size, new_size)
        return [h.hex() for h in raw_proof]

    # -- Block access --------------------------------------------------

    def get_block(self, index: int) -> Block | None:
        for blk in self._iter_blocks():
            if blk.index == index:
                return blk
        return None

    @property
    def head(self) -> Block | None:
        return self._head

    @property
    def size(self) -> int:
        return (self._head.index + 1) if self._head else 0

    # -- Persistence ---------------------------------------------------

    def _persist(self, blk: Block) -> None:
        with open(self.db_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(blk.to_dict()) + "\n")

    def _iter_blocks(self) -> Iterator[Block]:
        if not self.db_path.exists():
            return
        with open(self.db_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield Block.from_dict(json.loads(line))

    def _load_head(self) -> Block | None:
        last = None
        for blk in self._iter_blocks():
            last = blk
        return last

    def _load_checkpoint_seq(self) -> int:
        """Load the last checkpoint sequence number."""
        seq_path = self.db_path.with_suffix(".seq")
        if seq_path.exists():
            try:
                return int(seq_path.read_text().strip())
            except (ValueError, OSError):
                pass
        return 0

    def _persist_checkpoint_seq(self) -> None:
        seq_path = self.db_path.with_suffix(".seq")
        seq_path.write_text(str(self._checkpoint_seq))


# ---------------------------------------------------------------------------
# Standalone verification (no signing key needed)
# ---------------------------------------------------------------------------

def verify_sth_signature(sth: SignedTreeHead) -> bool:
    """Verify an STH's signature without the signing key."""
    try:
        vk = VerifyKey(bytes.fromhex(sth.nid_pubkey))
        vk.verify(sth.signing_payload(), bytes.fromhex(sth.signature))
        return True
    except Exception:
        return False


def verify_ledger_consistency(
    old_root: str,
    old_size: int,
    new_root: str,
    new_size: int,
    proof: list[str],
) -> bool:
    """Relying-party-side consistency check (no ledger access needed)."""
    return merkle_verify_consistency(
        bytes.fromhex(old_root),
        old_size,
        bytes.fromhex(new_root),
        new_size,
        [bytes.fromhex(h) for h in proof],
    )
