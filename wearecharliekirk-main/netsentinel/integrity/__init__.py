# NetSentinel Integrity Layer — Proof-Carrying Alerts
"""netsentinel.integrity — cryptographic provenance for ML predictions.

Modules:
    encoding        JCS canonicalization, SHA-256 digests, float→PPM
    merkle          RFC 6962 Merkle tree + inclusion/consistency proofs
    ledger          Append-only signed block ledger
    envelope        DSSE (Dead Simple Signing Envelope) v1
    receipt         in-toto Statement v1 builder for alert receipts
    anchor_service  Windowed batching, proof store, anchor backends
    blobstore       AES-GCM encrypted evidence storage
    replay          Deterministic inference replay engine
    claims          Nine-claim verifier
"""

