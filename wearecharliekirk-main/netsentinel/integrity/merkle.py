"""Domain-separated Merkle tree with CT-style consistency proofs.

Implements RFC 6962 §2.1 algorithms:
- Leaf hashing with 0x00 domain separator (second-preimage resistant)
- Internal node hashing with 0x01 domain separator
- Inclusion proofs (membership of a leaf in a tree)
- Consistency proofs (one tree is an append-only extension of another)

Kept from middle.md §B.2 — the algorithms are exactly what witnesses and
consistency proofs need.  The only design decision enforced here is the
**leaf-input contract**: ``build_tree`` receives raw content and applies
``leaf_hash`` internally, so callers never pre-hash.
"""

from __future__ import annotations

import hashlib
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Domain-separated hashing
# ---------------------------------------------------------------------------

def _h(b: bytes) -> bytes:
    """SHA-256."""
    return hashlib.sha256(b).digest()


def leaf_hash(data: bytes) -> bytes:
    """Hash a leaf value with 0x00 domain separator."""
    return _h(b"\x00" + data)


def _node(left: bytes, right: bytes) -> bytes:
    """Hash two children with 0x01 domain separator."""
    return _h(b"\x01" + left + right)


# Empty tree sentinel (SHA-256 of empty bytes — CT convention).
EMPTY_ROOT = _h(b"")


# ---------------------------------------------------------------------------
# Proof structures
# ---------------------------------------------------------------------------

class MerkleProof(NamedTuple):
    """Inclusion proof for a single leaf."""
    leaf_index: int
    tree_size: int
    siblings: list[tuple[bytes, str]]   # (hash, "L"|"R")


# ---------------------------------------------------------------------------
# Tree construction
# ---------------------------------------------------------------------------

def build_tree(
    raw_leaves: list[bytes],
) -> tuple[bytes, list[MerkleProof]]:
    """Build an RFC 6962 Merkle tree from raw leaf content.

    Args:
        raw_leaves: unhashed leaf content.  ``leaf_hash`` is applied
            internally — callers must NOT pre-hash.

    Returns:
        (root_hash, list-of-per-leaf-inclusion-proofs).
        For an empty list, returns ``(EMPTY_ROOT, [])``.

    NOTE (fixed 2026-09-20): this previously padded the leaf count up to the
    next power of two by DUPLICATING the last leaf.  That produced a different
    tree from ``_hash_range`` / ``consistency_proof``, which implement the
    RFC 6962 split at the largest power of two strictly less than n — so for
    any non-power-of-two size the two disagreed and no consistency proof could
    ever verify.  Duplicate-leaf padding is also unsound for a tamper-evident
    log: two different leaf sets can yield the same root.  The tree is now
    RFC 6962 throughout, which is what the rest of this module already assumed.
    """
    if not raw_leaves:
        return EMPTY_ROOT, []

    n = len(raw_leaves)
    hashes = [leaf_hash(d) for d in raw_leaves]
    siblings: list[list[tuple[bytes, str]]] = [[] for _ in range(n)]

    root = _build_subtree(hashes, 0, n, siblings)
    proofs = [
        MerkleProof(leaf_index=i, tree_size=n, siblings=siblings[i])
        for i in range(n)
    ]
    return root, proofs


def _build_subtree(
    hashes: list[bytes],
    start: int,
    end: int,
    siblings: list[list[tuple[bytes, str]]],
) -> bytes:
    """Root of hashes[start:end], recording each leaf's sibling path bottom-up."""
    n = end - start
    if n == 1:
        return hashes[start]

    k = _largest_power_of_two_less_than(n)
    left = _build_subtree(hashes, start, start + k, siblings)
    right = _build_subtree(hashes, start + k, end, siblings)

    # Deeper siblings were appended by the recursion above, so appending the
    # sibling at THIS level last keeps every path ordered leaf -> root, which
    # is the order verify_proof folds them in.
    for i in range(start, start + k):
        siblings[i].append((right, "R"))
    for i in range(start + k, end):
        siblings[i].append((left, "L"))

    return _node(left, right)


def verify_proof(raw_leaf: bytes, proof: MerkleProof, root: bytes) -> bool:
    """Verify a Merkle inclusion proof against a known root.

    Args:
        raw_leaf: the unhashed leaf content (``leaf_hash`` applied internally).
        proof: the ``MerkleProof`` returned by ``build_tree``.
        root: the expected Merkle root.

    Returns:
        True if the proof verifies.
    """
    h = leaf_hash(raw_leaf)
    for sib, side in proof.siblings:
        if side == "L":
            h = _node(sib, h)
        else:
            h = _node(h, sib)
    return h == root


# ---------------------------------------------------------------------------
# Consistency proofs  (RFC 6962 §2.1.2)
# ---------------------------------------------------------------------------

def consistency_proof(
    raw_leaves: list[bytes],
    old_size: int,
    new_size: int,
) -> list[bytes]:
    """Compute a consistency proof between tree sizes.

    Proves that the tree at *new_size* is a strict append-only extension
    of the tree at *old_size*.  The proof is a list of intermediate hashes
    that a verifier can use to reconstruct both roots without access to
    the full leaf set.

    Args:
        raw_leaves: all leaf content (unhashed) up to *new_size*.
        old_size: the earlier tree size.
        new_size: the current tree size (``len(raw_leaves)``).

    Returns:
        List of proof hashes.
    """
    if old_size < 1 or old_size > new_size or new_size > len(raw_leaves):
        return []

    hashes = [leaf_hash(d) for d in raw_leaves[:new_size]]
    proof_hashes: list[bytes] = []
    _consistency_proof_inner(hashes, old_size, new_size, proof_hashes, True)
    return proof_hashes


def _consistency_proof_inner(
    hashes: list[bytes],
    m: int,
    n: int,
    proof: list[bytes],
    start: bool,
) -> None:
    """Recursive consistency proof builder (RFC 6962 §2.1.2 algorithm)."""
    if m == n:
        if not start:
            proof.append(_hash_range(hashes, 0, n))
        return

    k = _largest_power_of_two_less_than(n)

    if m <= k:
        # m is entirely in the left subtree
        _consistency_proof_inner(hashes[:k], m, k, proof, start)
        proof.append(_hash_range(hashes, k, n))
    else:
        # m spans across subtrees
        _consistency_proof_inner(hashes[k:], m - k, n - k, proof, False)
        proof.append(_hash_range(hashes, 0, k))


def verify_consistency(
    old_root: bytes,
    old_size: int,
    new_root: bytes,
    new_size: int,
    proof: list[bytes],
) -> bool:
    """Verify an RFC 6962 §2.1.2 consistency proof.

    Checks that *new_root* at *new_size* is a strict append-only extension of
    *old_root* at *old_size* — i.e. that the log was only appended to, never
    rewritten.

    NOTE (fixed 2026-09-20): the previous implementation overwrote ``fr`` (the
    reconstructed old root) with ``proof[0]`` whenever ``old_size`` was a power
    of two, and mutated it with sibling hashes otherwise, then asserted
    ``fr == old_root``.  That check could not pass for a genuine append, so
    every consistency proof was rejected.  When the old tree is already a
    complete subtree the verifier consumes NO proof node for it; the old root
    itself is prepended to the proof instead.  This is the standard CT
    algorithm.

    Returns:
        True if the proof verifies both roots.
    """
    if old_size < 1 or old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and len(proof) == 0
    if not proof:
        return False

    # A complete (power-of-two) old tree contributes its own root, which the
    # prover therefore omits from the proof.
    path = list(proof)
    if _is_power_of_two(old_size):
        path.insert(0, old_root)

    # Walk up past the leaf's right-hand ancestors.
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    for node in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = _node(node, fr)
            sr = _node(node, sr)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = _node(sr, node)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr == old_root and sr == new_root


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_range(hashes: list[bytes], start: int, end: int) -> bytes:
    """Compute the Merkle root of hashes[start:end]."""
    n = end - start
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return hashes[start]

    k = _largest_power_of_two_less_than(n)
    left = _hash_range(hashes, start, start + k)
    right = _hash_range(hashes, start + k, end)
    return _node(left, right)


def _largest_power_of_two_less_than(n: int) -> int:
    """Return the largest power of 2 that is strictly less than n."""
    if n <= 1:
        return 0
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _log2(n: int) -> int:
    """Integer log base 2 (for powers of two)."""
    r = 0
    while n > 1:
        n >>= 1
        r += 1
    return r
