"""Regression tests for the Merkle transparency log (netsentinel.integrity.merkle).

These exist because two real defects shipped here and neither was caught by the
rest of the suite:

  1. `build_tree` padded the leaf count to a power of two by DUPLICATING the
     last leaf, while `consistency_proof`/`_hash_range` used the RFC 6962 split.
     For every non-power-of-two size the two produced different roots, so no
     consistency proof could verify. Duplicate-leaf padding is also unsound for
     a tamper-evident log (two leaf sets can share a root).

  2. `verify_consistency` overwrote the reconstructed old root with `proof[0]`
     and then asserted it equalled `old_root`, so it rejected every proof.

The consequence was that the ledger could prove "this alert is in the log" but
NOT "the log was only appended to" — which is the property an audit trail
exists for. Keep these tests green.
"""
from __future__ import annotations

import pytest

from netsentinel.integrity import merkle


def leaves(n: int) -> list[bytes]:
    return [f"alert-{i}".encode() for i in range(n)]


# --------------------------------------------------------------------------
# Inclusion
# --------------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33])
def test_every_leaf_has_a_valid_inclusion_proof(n):
    data = leaves(n)
    root, proofs = merkle.build_tree(data)
    for i in range(n):
        assert merkle.verify_proof(data[i], proofs[i], root), f"leaf {i} of {n}"


def test_tampered_leaf_is_rejected():
    data = leaves(8)
    root, proofs = merkle.build_tree(data)
    assert not merkle.verify_proof(b"TAMPERED", proofs[3], root)


def test_wrong_root_is_rejected():
    data = leaves(8)
    root, proofs = merkle.build_tree(data)
    assert not merkle.verify_proof(data[3], proofs[3], b"\x00" * 32)


# --------------------------------------------------------------------------
# The two-trees regression: build_tree and _hash_range must agree
# --------------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17])
def test_build_tree_matches_hash_range(n):
    """build_tree and the range-hash used by consistency_proof are the SAME tree.

    If this fails, consistency proofs are computed over a different tree than
    the roots they are checked against, and nothing will verify.
    """
    data = leaves(n)
    root, _ = merkle.build_tree(data)
    hashes = [merkle.leaf_hash(d) for d in data]
    assert root == merkle._hash_range(hashes, 0, n)


def test_no_duplicate_leaf_padding():
    """A log of 3 entries must not hash as if the last entry appeared twice."""
    three = merkle.build_tree(leaves(3))[0]
    padded = merkle.build_tree(leaves(3) + [b"alert-2"])[0]
    assert three != padded


# --------------------------------------------------------------------------
# Consistency (append-only)
# --------------------------------------------------------------------------

def test_consistency_verifies_for_every_size_pair():
    """Exhaustive: every (old_size, new_size) pair up to 33 must verify."""
    failures = []
    for n in range(1, 34):
        data = leaves(n)
        new_root, _ = merkle.build_tree(data)
        for m in range(1, n + 1):
            old_root, _ = merkle.build_tree(data[:m])
            proof = merkle.consistency_proof(data, m, n)
            if not merkle.verify_consistency(old_root, m, new_root, n, proof):
                failures.append((m, n))
    assert not failures, f"consistency failed for {len(failures)} pairs: {failures[:10]}"


@pytest.mark.parametrize("m,n", [(1, 2), (2, 4), (4, 8), (8, 16), (3, 4), (5, 8), (7, 9), (8, 9)])
def test_consistency_named_cases(m, n):
    data = leaves(n)
    old_root, _ = merkle.build_tree(data[:m])
    new_root, _ = merkle.build_tree(data)
    assert merkle.verify_consistency(
        old_root, m, new_root, n, merkle.consistency_proof(data, m, n)
    )


# --------------------------------------------------------------------------
# Consistency must REJECT tampering — this is the security property
# --------------------------------------------------------------------------

def _pair(old_n=8, new_n=9):
    data = leaves(new_n)
    old_root, _ = merkle.build_tree(data[:old_n])
    new_root, _ = merkle.build_tree(data)
    return data, old_root, new_root, merkle.consistency_proof(data, old_n, new_n)


def test_forged_old_root_rejected():
    _, _, new_root, proof = _pair()
    assert not merkle.verify_consistency(b"\x11" * 32, 8, new_root, 9, proof)


def test_forged_new_root_rejected():
    _, old_root, _, proof = _pair()
    assert not merkle.verify_consistency(old_root, 8, b"\x22" * 32, 9, proof)


def test_tampered_proof_rejected():
    _, old_root, new_root, proof = _pair()
    assert not merkle.verify_consistency(old_root, 8, new_root, 9, [b"\x33" * 32] * len(proof))


def test_empty_proof_rejected():
    _, old_root, new_root, _ = _pair()
    assert not merkle.verify_consistency(old_root, 8, new_root, 9, [])


def test_shrinking_log_rejected():
    _, old_root, new_root, proof = _pair()
    assert not merkle.verify_consistency(new_root, 9, old_root, 8, proof)


def test_rewritten_history_rejected():
    """The whole point: an entry changed after the fact must not verify."""
    old_root, _ = merkle.build_tree(leaves(8))
    rewritten = [b"REWRITTEN"] + leaves(9)[1:]
    new_root, _ = merkle.build_tree(rewritten)
    proof = merkle.consistency_proof(rewritten, 8, 9)
    assert not merkle.verify_consistency(old_root, 8, new_root, 9, proof)


def test_same_size_requires_identical_root_and_empty_proof():
    root, _ = merkle.build_tree(leaves(8))
    assert merkle.verify_consistency(root, 8, root, 8, [])
    assert not merkle.verify_consistency(root, 8, b"\x44" * 32, 8, [])
    assert not merkle.verify_consistency(root, 8, root, 8, [b"\x55" * 32])
